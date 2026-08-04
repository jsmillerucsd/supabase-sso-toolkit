-- ==============================================================================
-- @jsmillerucsd/supabase-sso — 0002_identity_projection        (depends on: 0001)
-- ==============================================================================
-- The trust boundary: SAML attributes are copied from `auth.identities` into
-- `private.user_attributes` on every sign-in. Everything downstream reads only
-- from `private.*`.
--
-- Read from `auth.identities`, never `auth.users.raw_user_meta_data`: the
-- latter is merged key-by-key (so revoked attributes never disappear) and is
-- client-writable.
--
-- These triggers run inside the sign-in transaction, so every projection is
-- wrapped: on error, log and continue. A projection bug must degrade a user to
-- zero privileges, never lock everyone out.
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- Tables
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS private.user_attributes (
  user_id            uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,

  eppn               text,
  ad_username        text,
  ucnet_id           text,
  email              text,
  -- Resolved by private.derive_display_identifier(); survives eppn going opaque.
  display_identifier text,

  full_name          text,
  first_name         text,
  last_name          text,
  title              text,

  home_dept_code     text,
  home_dept_desc     text,
  dept_codes         text[] NOT NULL DEFAULT '{}',

  ad_group_cns       text[] NOT NULL DEFAULT '{}',
  member_of_status   text NOT NULL DEFAULT 'absent'
    CHECK (member_of_status IN ('absent', 'empty', 'parsed', 'suspect_truncated')),

  ucpath_emplid      text,

  raw                jsonb NOT NULL DEFAULT '{}',
  synced_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_user_attributes_home_dept
  ON private.user_attributes (home_dept_code);
CREATE INDEX IF NOT EXISTS idx_user_attributes_emplid
  ON private.user_attributes (ucpath_emplid);
CREATE INDEX IF NOT EXISTS idx_user_attributes_display
  ON private.user_attributes (display_identifier);

REVOKE ALL ON private.user_attributes FROM public, anon, authenticated;

-- The auth hook reads this table.
GRANT SELECT ON private.user_attributes TO supabase_auth_admin;

-- Pre-materialized claims. The auth hook reads exactly one row from this table
-- and nothing else.
CREATE TABLE IF NOT EXISTS private.user_effective_claims (
  user_id      uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  app_roles    text[] NOT NULL DEFAULT '{}',
  dept_codes   text[] NOT NULL DEFAULT '{}',
  computed_at  timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON private.user_effective_claims FROM public, anon, authenticated;
GRANT SELECT ON private.user_effective_claims TO supabase_auth_admin;

-- ------------------------------------------------------------------------------
-- private.derive_display_identifier
-- ------------------------------------------------------------------------------
-- The campus IdP is switching to a 32-char opaque unique identifier. This chain
-- is correct whether that replaces the NameID only or the eppn attribute too:
--   NameID only  -> eppn stays scoped (user@domain) -> chain picks eppn
--   eppn too     -> regex rejects the opaque value  -> chain picks ad_username
CREATE OR REPLACE FUNCTION private.derive_display_identifier(
  p_eppn        text,
  p_ad_username text,
  p_ucnet_id    text,
  p_email       text
)
RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path = ''
AS $$
  SELECT COALESCE(
    CASE WHEN p_eppn ~ '^[^@[:space:]]+@[^@[:space:]]+$' THEN p_eppn END,
    NULLIF(p_ad_username, ''),
    NULLIF(p_ucnet_id, ''),
    NULLIF(p_email, '')
  );
$$;

-- ------------------------------------------------------------------------------
-- private.classify_member_of
-- ------------------------------------------------------------------------------
-- Supabase captures only the FIRST value of a multi-valued SAML attribute
-- unless the provider's attribute_mapping sets "array": true
-- (supabase/auth#2332). We classify what we got:
--   absent            key not present at all
--   empty             present but empty
--   parsed            >= 2 values (JSON array, or ';'-delimited): trustworthy
--   suspect_truncated exactly one value, no delimiter: probably truncated
--
-- The extracted CN is still used either way: a truncated group list can only
-- under-grant, never over-grant, because role derivation is additive.
CREATE OR REPLACE FUNCTION private.classify_member_of(v jsonb)
RETURNS TABLE (cns text[], status text)
LANGUAGE plpgsql
IMMUTABLE
SET search_path = ''
AS $$
DECLARE
  v_raw   text;
  v_parts text[];
  v_cns   text[] := '{}';
  v_dn    text;
  v_cn    text;
BEGIN
  IF v IS NULL OR v = 'null'::jsonb THEN
    RETURN QUERY SELECT '{}'::text[], 'absent'::text;
    RETURN;
  END IF;

  IF jsonb_typeof(v) = 'array' THEN
    SELECT string_agg(e, ';'), array_agg(e)
      INTO v_raw, v_parts
      FROM jsonb_array_elements_text(v) AS e
      WHERE e <> '';
    IF v_parts IS NULL THEN
      RETURN QUERY SELECT '{}'::text[], 'empty'::text;
      RETURN;
    END IF;
  ELSE
    v_raw := v #>> '{}';
    IF v_raw IS NULL OR v_raw = '' THEN
      RETURN QUERY SELECT '{}'::text[], 'empty'::text;
      RETURN;
    END IF;
    v_parts := string_to_array(v_raw, ';');
  END IF;

  FOREACH v_dn IN ARRAY v_parts LOOP
    v_cn := substring(v_dn FROM 'CN=([^,]+)');
    IF v_cn IS NOT NULL THEN
      v_cns := array_append(v_cns, v_cn);
    END IF;
  END LOOP;

  RETURN QUERY SELECT
    v_cns,
    CASE
      WHEN jsonb_typeof(v) = 'array' AND jsonb_array_length(v) > 1 THEN 'parsed'
      WHEN v_raw LIKE '%;%'                                        THEN 'parsed'
      ELSE 'suspect_truncated'
    END::text;
END;
$$;

-- ------------------------------------------------------------------------------
-- private.parse_multi
-- ------------------------------------------------------------------------------
-- Tolerates both delimited-string and JSON array shapes so that enabling
-- "array": true on the SSO provider later requires no migration.
CREATE OR REPLACE FUNCTION private.parse_multi(
  v            jsonb,
  delim        text,
  strip_zeros  boolean DEFAULT false
)
RETURNS text[]
LANGUAGE plpgsql
IMMUTABLE
SET search_path = ''
AS $$
DECLARE
  parts  text[];
  result text[] := '{}';
  e      text;
  norm   text;
BEGIN
  IF v IS NULL OR v = 'null'::jsonb THEN
    RETURN '{}';
  END IF;

  IF jsonb_typeof(v) = 'array' THEN
    SELECT array_agg(x) INTO parts FROM jsonb_array_elements_text(v) AS x;
  ELSE
    parts := string_to_array(v #>> '{}', delim);
  END IF;

  IF parts IS NULL THEN
    RETURN '{}';
  END IF;

  FOREACH e IN ARRAY parts LOOP
    norm := btrim(COALESCE(e, ''));
    IF strip_zeros THEN
      norm := NULLIF(ltrim(norm, '0'), '');
    END IF;
    IF norm IS NOT NULL AND norm <> '' THEN
      result := array_append(result, norm);
    END IF;
  END LOOP;

  RETURN result;
END;
$$;

-- ------------------------------------------------------------------------------
-- private.extract_attributes — the campus-adapter seam
-- ------------------------------------------------------------------------------
-- Generic version: standard OIDC-ish keys only. A campus adapter module (e.g.
-- 0006_ucsd_adapter) CREATE OR REPLACEs this with institution-specific mapping.
CREATE OR REPLACE FUNCTION private.extract_attributes(p_payload jsonb)
RETURNS private.user_attributes
LANGUAGE plpgsql
STABLE
SET search_path = ''
AS $$
DECLARE
  r  private.user_attributes;
  cc jsonb;
BEGIN
  cc := COALESCE(p_payload -> 'custom_claims', '{}'::jsonb);

  r.email      := NULLIF(p_payload ->> 'email', '');
  r.full_name  := COALESCE(NULLIF(p_payload ->> 'name', ''), NULLIF(p_payload ->> 'full_name', ''));
  r.first_name := NULLIF(p_payload ->> 'given_name', '');
  r.last_name  := NULLIF(p_payload ->> 'family_name', '');

  r.dept_codes := '{}';

  SELECT c.cns, c.status
    INTO r.ad_group_cns, r.member_of_status
    FROM private.classify_member_of(cc -> 'member_of') c;

  r.display_identifier := private.derive_display_identifier(NULL, NULL, NULL, r.email);
  r.raw := p_payload;

  RETURN r;
END;
$$;

-- ------------------------------------------------------------------------------
-- private.project_user_attributes — wholesale replace, then recompute
-- ------------------------------------------------------------------------------
-- Mirrors identity_data's replace semantics: every column is overwritten from
-- the fresh payload. No key-wise merging.
CREATE OR REPLACE FUNCTION private.project_user_attributes(
  p_user_id uuid,
  p_payload jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  a private.user_attributes;
BEGIN
  a := private.extract_attributes(p_payload);

  INSERT INTO private.user_attributes (
    user_id,
    eppn, ad_username, ucnet_id, email, display_identifier,
    full_name, first_name, last_name, title,
    home_dept_code, home_dept_desc, dept_codes,
    ad_group_cns, member_of_status,
    ucpath_emplid,
    raw, synced_at
  )
  VALUES (
    p_user_id,
    a.eppn, a.ad_username, a.ucnet_id, a.email, a.display_identifier,
    a.full_name, a.first_name, a.last_name, a.title,
    a.home_dept_code, a.home_dept_desc, COALESCE(a.dept_codes, '{}'),
    COALESCE(a.ad_group_cns, '{}'), COALESCE(a.member_of_status, 'absent'),
    a.ucpath_emplid,
    COALESCE(a.raw, '{}'::jsonb), now()
  )
  ON CONFLICT (user_id) DO UPDATE SET
    eppn               = EXCLUDED.eppn,
    ad_username        = EXCLUDED.ad_username,
    ucnet_id           = EXCLUDED.ucnet_id,
    email              = EXCLUDED.email,
    display_identifier = EXCLUDED.display_identifier,
    full_name          = EXCLUDED.full_name,
    first_name         = EXCLUDED.first_name,
    last_name          = EXCLUDED.last_name,
    title              = EXCLUDED.title,
    home_dept_code     = EXCLUDED.home_dept_code,
    home_dept_desc     = EXCLUDED.home_dept_desc,
    dept_codes         = EXCLUDED.dept_codes,
    ad_group_cns       = EXCLUDED.ad_group_cns,
    member_of_status   = EXCLUDED.member_of_status,
    ucpath_emplid      = EXCLUDED.ucpath_emplid,
    raw                = EXCLUDED.raw,
    synced_at          = now();

  PERFORM private.recompute_user_claims(p_user_id);
END;
$$;

-- ------------------------------------------------------------------------------
-- private.recompute_user_claims — THE COMPOSITION SEAM
-- ------------------------------------------------------------------------------
-- Trivial stub: no role sources exist yet, so app_roles is always empty.
-- Module 0004_roles CREATE OR REPLACEs this with the real multi-source union.
CREATE OR REPLACE FUNCTION private.recompute_user_claims(p_user_id uuid)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
  INSERT INTO private.user_effective_claims (user_id, app_roles, dept_codes, computed_at)
  SELECT ua.user_id, '{}'::text[], ua.dept_codes, now()
  FROM private.user_attributes ua
  WHERE ua.user_id = p_user_id
  ON CONFLICT (user_id) DO UPDATE SET
    app_roles   = EXCLUDED.app_roles,
    dept_codes  = EXCLUDED.dept_codes,
    computed_at = now();
$$;

CREATE OR REPLACE FUNCTION private.recompute_all_user_claims()
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  r   record;
  n   integer := 0;
BEGIN
  FOR r IN SELECT user_id FROM private.user_attributes LOOP
    BEGIN
      PERFORM private.recompute_user_claims(r.user_id);
      n := n + 1;
    EXCEPTION WHEN OTHERS THEN
      INSERT INTO private.sync_errors (user_id, source, detail)
      VALUES (r.user_id, 'recompute', SQLERRM);
    END;
  END LOOP;
  RETURN n;
END;
$$;

-- ------------------------------------------------------------------------------
-- Trigger: project SAML attributes on sign-in
-- ------------------------------------------------------------------------------
-- Fail-open: never let a projection defect break authentication.
CREATE OR REPLACE FUNCTION private.on_identity_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF NEW.provider LIKE 'sso:%' THEN
    BEGIN
      PERFORM private.project_user_attributes(NEW.user_id, NEW.identity_data);
    EXCEPTION WHEN OTHERS THEN
      INSERT INTO private.sync_errors (user_id, source, detail, payload)
      VALUES (NEW.user_id, 'projection_trigger', SQLERRM, NEW.identity_data);
      UPDATE private.user_attributes SET synced_at = now() WHERE user_id = NEW.user_id;
    END;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_sso_identity_projected ON auth.identities;
CREATE TRIGGER on_sso_identity_projected
  AFTER INSERT OR UPDATE OF identity_data ON auth.identities
  FOR EACH ROW
  EXECUTE FUNCTION private.on_identity_change();

-- ------------------------------------------------------------------------------
-- Backfill — safe on a fresh schema, safe to re-run
-- ------------------------------------------------------------------------------
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT i.user_id, i.identity_data
    FROM auth.identities i
    WHERE i.provider LIKE 'sso:%'
  LOOP
    BEGIN
      PERFORM private.project_user_attributes(r.user_id, r.identity_data);
    EXCEPTION WHEN OTHERS THEN
      INSERT INTO private.sync_errors (user_id, source, detail, payload)
      VALUES (r.user_id, 'projection_trigger', 'backfill: ' || SQLERRM, r.identity_data);
    END;
  END LOOP;
END;
$$;

SELECT private.register_module('0002_identity_projection', '1.0.0');
