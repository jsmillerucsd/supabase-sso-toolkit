-- ==============================================================================
-- @jsmillerucsd/supabase-sso v1.0.2 — install
-- ==============================================================================
-- GENERATED FILE. Edit the modules in sql/ and run `npm run build:sql`.
--
-- Run this once against your Supabase project. It is idempotent: re-running it
-- is how you upgrade, and re-running the same version is a no-op.
--
-- Modules included:
--   0001_core.sql
--   0002_identity_projection.sql
--   0003_rls_helpers.sql
--   0004_roles.sql
--   0005_auth_hook.sql
--   0006_ucsd_adapter.sql
--
-- After running, enable the auth hook:
--   Dashboard > Authentication > Hooks > Customize Access Token
--   pg-functions://postgres/private/custom_access_token_hook
--
-- Check what is installed at any time:
--   SELECT * FROM public.toolkit_version();
-- ==============================================================================

-- ==============================================================================
-- @jsmillerucsd/supabase-sso — 0001_core
-- ==============================================================================
-- Private schema, baseline grants, module registry, error log.
--
-- Every other module depends on this one. Idempotent: safe to re-apply.
--
-- Design notes:
--   * `private` is NEVER added to PostgREST's exposed schemas. All client access
--     goes through `public.*` RPC wrappers with explicit grants.
--   * `private.sync_errors` deliberately has NO foreign key on user_id. It is
--     written from inside auth triggers on the sign-in path; a constraint
--     violation there would defeat the fail-open policy and break sign-in.
-- ==============================================================================

CREATE SCHEMA IF NOT EXISTS private;

-- New functions in `private` must not be executable by the world by default.
ALTER DEFAULT PRIVILEGES IN SCHEMA private REVOKE EXECUTE ON FUNCTIONS FROM public;

REVOKE ALL ON SCHEMA private FROM public;
REVOKE ALL ON SCHEMA private FROM anon;

-- USAGE only. No table grants — helper functions are SECURITY DEFINER and are
-- the sole entry point for `authenticated`.
GRANT USAGE ON SCHEMA private TO authenticated;
GRANT USAGE ON SCHEMA private TO supabase_auth_admin;

-- ------------------------------------------------------------------------------
-- Module registry — lets support ask "what version is this app on?" in one query.
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS private.toolkit_modules (
  module       text PRIMARY KEY,
  version      text NOT NULL,
  installed_at timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON private.toolkit_modules FROM public, anon, authenticated;

CREATE OR REPLACE FUNCTION private.register_module(p_module text, p_version text)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
  INSERT INTO private.toolkit_modules (module, version)
  VALUES (p_module, p_version)
  ON CONFLICT (module) DO UPDATE
    SET version = EXCLUDED.version,
        installed_at = now();
$$;

CREATE OR REPLACE FUNCTION public.toolkit_version()
RETURNS TABLE (module text, version text, installed_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT m.module, m.version, m.installed_at
  FROM private.toolkit_modules m
  ORDER BY m.module;
$$;

REVOKE EXECUTE ON FUNCTION public.toolkit_version() FROM public, anon;
GRANT EXECUTE ON FUNCTION public.toolkit_version() TO authenticated;

-- ------------------------------------------------------------------------------
-- Error log — the fail-open policy's evidence trail.
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS private.sync_errors (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id     uuid,          -- intentionally no FK; see header
  source      text NOT NULL, -- projection_trigger | legacy_trigger | recompute | admin_rpc
  detail      text NOT NULL,
  payload     jsonb,
  occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sync_errors_user
  ON private.sync_errors (user_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_sync_errors_occurred
  ON private.sync_errors (occurred_at DESC);

REVOKE ALL ON private.sync_errors FROM public, anon, authenticated;

-- ------------------------------------------------------------------------------
-- Generic updated_at trigger utility.
-- ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION private.update_timestamp()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

SELECT private.register_module('0001_core', '1.0.0');


-- ==============================================================================
-- @jsmillerucsd/supabase-sso — 0002_identity_projection        (depends on: 0001)
-- ==============================================================================
-- The trust boundary: SAML attributes are copied from `auth.identities` into
-- `private.user_attributes` on every sign-in. Everything downstream reads only
-- from `private.*`.
--
-- Read from `auth.identities`, never `auth.users.raw_user_meta_data` — the
-- latter is merged key-by-key (so revoked attributes never disappear) and is
-- client-writable. See README, "Why attributes are read from auth.identities".
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
  source_kind        text NOT NULL CHECK (source_kind IN ('saml', 'legacy_oauth')),

  -- identity_data.sub verbatim (the SAML NameID). Stored for correlation and
  -- audit only. NEVER a join key, uniqueness constraint, or display value — the
  -- campus IdP is moving from email to a 32-char opaque value and this column
  -- must be allowed to change shape without consequence.
  subject_id         text,

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
  dept_names         text[] NOT NULL DEFAULT '{}',

  -- NULL means the attribute was not released by the IdP at all. '{}' means it
  -- was released and empty. Keep the distinction: it is how you tell
  -- "the IdP stopped sending this" from "this user genuinely has none".
  affiliations       text[],

  member_of_raw      text,
  ad_group_cns       text[] NOT NULL DEFAULT '{}',
  member_of_status   text NOT NULL DEFAULT 'absent'
    CHECK (member_of_status IN ('absent', 'empty', 'parsed', 'suspect_truncated')),

  ucpath_emplid      text,
  pid                text,
  employee_status    text,

  raw                jsonb NOT NULL DEFAULT '{}',
  synced_at          timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_user_attributes_home_dept
  ON private.user_attributes (home_dept_code);
CREATE INDEX IF NOT EXISTS idx_user_attributes_emplid
  ON private.user_attributes (ucpath_emplid);
CREATE INDEX IF NOT EXISTS idx_user_attributes_adgroups
  ON private.user_attributes USING gin (ad_group_cns);
CREATE INDEX IF NOT EXISTS idx_user_attributes_display
  ON private.user_attributes (display_identifier);

REVOKE ALL ON private.user_attributes FROM public, anon, authenticated;

-- The auth hook's slimming block reads this table.
GRANT SELECT ON private.user_attributes TO supabase_auth_admin;

-- Pre-materialized claims. The auth hook reads exactly one row from this table
-- and nothing else — see 0005.
CREATE TABLE IF NOT EXISTS private.user_effective_claims (
  user_id      uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  app_roles    text[] NOT NULL DEFAULT '{}',
  dept_codes   text[] NOT NULL DEFAULT '{}',
  -- Adapter-extensible. Merged into the JWT's top level by the hook, so a campus
  -- adapter can add claims without editing the hook.
  extra_claims jsonb NOT NULL DEFAULT '{}',
  computed_at  timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON private.user_effective_claims FROM public, anon, authenticated;
GRANT SELECT ON private.user_effective_claims TO supabase_auth_admin;

-- ------------------------------------------------------------------------------
-- private.derive_display_identifier — human-readable handle, IdP-change-proof
-- ------------------------------------------------------------------------------
-- The campus IdP is switching to a 32-char opaque unique identifier. It is
-- unresolved whether that replaces the NameID only or the eppn attribute too.
-- This chain is correct under both readings with no code change:
--   * NameID only  -> eppn stays scoped (user@domain) -> chain picks eppn
--   * eppn too     -> regex rejects the opaque value  -> chain picks ad_username
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
-- private.classify_member_of — honest handling of a known-truncated attribute
-- ------------------------------------------------------------------------------
-- Supabase currently captures only the FIRST value of a multi-valued SAML
-- attribute unless the provider's attribute_mapping sets "array": true
-- (supabase/auth#2332). Against the live campus IdP, `member_of` arrives as a
-- single delimiter-free DN for every user — the signature of that truncation.
--
-- We cannot fix it from here, so we classify it and make it visible:
--   absent            key not present at all
--   empty             present but empty
--   parsed            >= 2 values (JSON array, or ';'-delimited) — trustworthy
--   suspect_truncated exactly one value, no delimiter — probably truncated
--
-- The extracted CN is still used either way: a truncated group list can only
-- ever UNDER-grant, never over-grant, because role derivation is additive.
CREATE OR REPLACE FUNCTION private.classify_member_of(v jsonb)
RETURNS TABLE (raw text, cns text[], status text)
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
    RETURN QUERY SELECT NULL::text, '{}'::text[], 'absent'::text;
    RETURN;
  END IF;

  IF jsonb_typeof(v) = 'array' THEN
    SELECT string_agg(e, ';'), array_agg(e)
      INTO v_raw, v_parts
      FROM jsonb_array_elements_text(v) AS e
      WHERE e <> '';
    IF v_parts IS NULL THEN
      RETURN QUERY SELECT ''::text, '{}'::text[], 'empty'::text;
      RETURN;
    END IF;
  ELSE
    v_raw := v #>> '{}';
    IF v_raw IS NULL OR v_raw = '' THEN
      RETURN QUERY SELECT v_raw, '{}'::text[], 'empty'::text;
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
    v_raw,
    v_cns,
    CASE
      WHEN jsonb_typeof(v) = 'array' AND jsonb_array_length(v) > 1 THEN 'parsed'
      WHEN v_raw LIKE '%;%'                                        THEN 'parsed'
      ELSE 'suspect_truncated'
    END::text;
END;
$$;

-- ------------------------------------------------------------------------------
-- private.parse_multi — delimited-string-or-array to text[]
-- ------------------------------------------------------------------------------
-- Tolerates both shapes so that enabling "array": true on the SSO provider later
-- requires no migration.
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
-- Modules compose by replacing this function — never by cross-referencing each
-- other's tables.
CREATE OR REPLACE FUNCTION private.extract_attributes(
  p_source_kind text,
  p_payload     jsonb
)
RETURNS private.user_attributes
LANGUAGE plpgsql
STABLE
SET search_path = ''
AS $$
DECLARE
  r  private.user_attributes;
  cc jsonb;
BEGIN
  IF p_source_kind NOT IN ('saml', 'legacy_oauth') THEN
    RAISE EXCEPTION 'unknown source_kind %', p_source_kind;
  END IF;

  cc := COALESCE(p_payload -> 'custom_claims', '{}'::jsonb);

  r.subject_id := p_payload ->> 'sub';
  r.email      := NULLIF(p_payload ->> 'email', '');
  r.full_name  := COALESCE(NULLIF(p_payload ->> 'name', ''), NULLIF(p_payload ->> 'full_name', ''));
  r.first_name := NULLIF(p_payload ->> 'given_name', '');
  r.last_name  := NULLIF(p_payload ->> 'family_name', '');

  r.dept_codes := '{}';
  r.dept_names := '{}';
  r.affiliations := NULL;

  SELECT c.raw, c.cns, c.status
    INTO r.member_of_raw, r.ad_group_cns, r.member_of_status
    FROM private.classify_member_of(cc -> 'member_of') c;

  r.display_identifier := private.derive_display_identifier(NULL, NULL, NULL, r.email);
  r.raw := p_payload;

  RETURN r;
END;
$$;

-- ------------------------------------------------------------------------------
-- private.project_user_attributes — wholesale replace, then recompute
-- ------------------------------------------------------------------------------
-- Mirrors identity_data's replace semantics deliberately: every column is
-- overwritten from the fresh payload. No key-wise merging, ever — that is the
-- ratchet this whole module exists to avoid.
CREATE OR REPLACE FUNCTION private.project_user_attributes(
  p_user_id     uuid,
  p_source_kind text,
  p_payload     jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  a private.user_attributes;
BEGIN
  a := private.extract_attributes(p_source_kind, p_payload);

  INSERT INTO private.user_attributes (
    user_id, source_kind, subject_id,
    eppn, ad_username, ucnet_id, email, display_identifier,
    full_name, first_name, last_name, title,
    home_dept_code, home_dept_desc, dept_codes, dept_names,
    affiliations, member_of_raw, ad_group_cns, member_of_status,
    ucpath_emplid, pid, employee_status,
    raw, synced_at, updated_at
  )
  VALUES (
    p_user_id, p_source_kind, a.subject_id,
    a.eppn, a.ad_username, a.ucnet_id, a.email, a.display_identifier,
    a.full_name, a.first_name, a.last_name, a.title,
    a.home_dept_code, a.home_dept_desc, COALESCE(a.dept_codes, '{}'), COALESCE(a.dept_names, '{}'),
    a.affiliations, a.member_of_raw, COALESCE(a.ad_group_cns, '{}'),
    COALESCE(a.member_of_status, 'absent'),
    a.ucpath_emplid, a.pid, a.employee_status,
    COALESCE(a.raw, '{}'::jsonb), now(), now()
  )
  ON CONFLICT (user_id) DO UPDATE SET
    source_kind        = EXCLUDED.source_kind,
    subject_id         = EXCLUDED.subject_id,
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
    dept_names         = EXCLUDED.dept_names,
    affiliations       = EXCLUDED.affiliations,
    member_of_raw      = EXCLUDED.member_of_raw,
    ad_group_cns       = EXCLUDED.ad_group_cns,
    member_of_status   = EXCLUDED.member_of_status,
    ucpath_emplid      = EXCLUDED.ucpath_emplid,
    pid                = EXCLUDED.pid,
    employee_status    = EXCLUDED.employee_status,
    raw                = EXCLUDED.raw,
    synced_at          = now(),
    updated_at         = now();

  PERFORM private.recompute_user_claims(p_user_id);
END;
$$;

-- ------------------------------------------------------------------------------
-- private.recompute_user_claims — THE COMPOSITION SEAM
-- ------------------------------------------------------------------------------
-- Trivial version: no role sources exist yet, so app_roles is always empty.
-- Module 0004_roles CREATE OR REPLACEs this with the real multi-source union.
-- Nothing else in the toolkit may reference 0004's tables directly; replacing
-- this one function is how role support is added. That is what makes 0004
-- genuinely optional.
CREATE OR REPLACE FUNCTION private.recompute_user_claims(p_user_id uuid)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
  INSERT INTO private.user_effective_claims (user_id, app_roles, dept_codes, extra_claims, computed_at)
  SELECT ua.user_id, '{}'::text[], ua.dept_codes, '{}'::jsonb, now()
  FROM private.user_attributes ua
  WHERE ua.user_id = p_user_id
  ON CONFLICT (user_id) DO UPDATE SET
    app_roles    = EXCLUDED.app_roles,
    dept_codes   = EXCLUDED.dept_codes,
    extra_claims = EXCLUDED.extra_claims,
    computed_at  = now();
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
-- Triggers — SAML branch on auth.identities
-- ------------------------------------------------------------------------------
-- Fires on the sign-in path. Fail-open: never let a projection defect break
-- authentication. See header.
CREATE OR REPLACE FUNCTION private.on_identity_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF NEW.provider LIKE 'sso:%' THEN
    BEGIN
      PERFORM private.project_user_attributes(NEW.user_id, 'saml', NEW.identity_data);
    EXCEPTION WHEN OTHERS THEN
      INSERT INTO private.sync_errors (user_id, source, detail, payload)
      VALUES (NEW.user_id, 'projection_trigger', SQLERRM, NEW.identity_data);
      -- Stamp synced_at even on failure so staleness stays observable.
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
-- Triggers — legacy OAuth branch on auth.users
-- ------------------------------------------------------------------------------
-- Transition support only. Users provisioned by the retired central-auth OAuth
-- server carry their attributes in raw_app_meta_data (admin-written, NOT
-- client-writable — unlike raw_user_meta_data, which we never read).
--
-- Branch on provider; do NOT COALESCE the two shapes into one expression. A
-- COALESCE would let a legacy user's leftover app_metadata keys shadow fresh
-- SAML values after they migrate.
CREATE OR REPLACE FUNCTION private.on_legacy_user_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF COALESCE(NEW.is_sso_user, false) = false
     AND NEW.raw_app_meta_data ->> 'provider' = 'custom:ucsd-sso' THEN
    BEGIN
      -- Never downgrade a user who has already migrated to SAML.
      IF NOT EXISTS (
        SELECT 1 FROM private.user_attributes ua
        WHERE ua.user_id = NEW.id AND ua.source_kind = 'saml'
      ) THEN
        PERFORM private.project_user_attributes(NEW.id, 'legacy_oauth', NEW.raw_app_meta_data);
      END IF;
    EXCEPTION WHEN OTHERS THEN
      INSERT INTO private.sync_errors (user_id, source, detail, payload)
      VALUES (NEW.id, 'legacy_trigger', SQLERRM, NEW.raw_app_meta_data);
      UPDATE private.user_attributes SET synced_at = now() WHERE user_id = NEW.id;
    END;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_legacy_user_projected ON auth.users;
CREATE TRIGGER on_legacy_user_projected
  AFTER INSERT OR UPDATE OF raw_app_meta_data ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION private.on_legacy_user_change();

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
      PERFORM private.project_user_attributes(r.user_id, 'saml', r.identity_data);
    EXCEPTION WHEN OTHERS THEN
      INSERT INTO private.sync_errors (user_id, source, detail, payload)
      VALUES (r.user_id, 'projection_trigger', 'backfill: ' || SQLERRM, r.identity_data);
    END;
  END LOOP;

  FOR r IN
    SELECT u.id AS user_id, u.raw_app_meta_data
    FROM auth.users u
    WHERE COALESCE(u.is_sso_user, false) = false
      AND u.raw_app_meta_data ->> 'provider' = 'custom:ucsd-sso'
      AND NOT EXISTS (
        SELECT 1 FROM private.user_attributes ua
        WHERE ua.user_id = u.id AND ua.source_kind = 'saml'
      )
  LOOP
    BEGIN
      PERFORM private.project_user_attributes(r.user_id, 'legacy_oauth', r.raw_app_meta_data);
    EXCEPTION WHEN OTHERS THEN
      INSERT INTO private.sync_errors (user_id, source, detail, payload)
      VALUES (r.user_id, 'legacy_trigger', 'backfill: ' || SQLERRM, r.raw_app_meta_data);
    END;
  END LOOP;
END;
$$;

SELECT private.register_module('0002_identity_projection', '1.0.0');


-- ==============================================================================
-- @jsmillerucsd/supabase-sso — 0003_rls_helpers
-- ==============================================================================
-- Helper functions for RLS policies and application code.
--
-- READ-SOURCE RULE (this has regressed twice in the predecessor project):
--   * Role and department checks read TOP-LEVEL JWT claims injected by the auth
--     hook (`app_roles`, `dept_codes_array`) — never `app_metadata`, never
--     `user_metadata`. `user_metadata` is client-writable; trusting it is a
--     privilege-escalation vector.
--   * Attribute checks that are not in the JWT (AD groups, affiliations) read
--     `private.user_attributes` directly.
-- Test 16_helper_sources.sql locks both rules.
--
-- Depends on: 0002
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- JWT-sourced helpers (fast, stale up to one token lifetime)
-- ------------------------------------------------------------------------------

-- Role check against the hook-injected top-level `app_roles` claim.
CREATE OR REPLACE FUNCTION private.user_has_role(role_name text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT COALESCE((SELECT auth.jwt()) -> 'app_roles', '[]'::jsonb) ? role_name;
$$;

-- Department codes from the hook-injected top-level `dept_codes_array` claim.
-- No app_metadata fallback: if the claim is missing the answer is "none".
CREATE OR REPLACE FUNCTION private.user_dept_codes()
RETURNS text[]
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT COALESCE(
    (SELECT array_agg(e)
     FROM jsonb_array_elements_text(
       COALESCE((SELECT auth.jwt()) -> 'dept_codes_array', '[]'::jsonb)
     ) AS e),
    '{}'::text[]
  );
$$;

-- True when the hook could not materialize claims for this user. Apps should
-- surface this rather than silently showing an empty UI.
CREATE OR REPLACE FUNCTION private.claims_degraded()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT COALESCE(((SELECT auth.jwt()) ->> 'app_claims_degraded')::boolean, false);
$$;

-- ------------------------------------------------------------------------------
-- DB-sourced helpers (always current; AD groups never ride in the JWT)
-- ------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION private.user_ad_groups()
RETURNS text[]
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT COALESCE(
    (SELECT ua.ad_group_cns
     FROM private.user_attributes ua
     WHERE ua.user_id = (SELECT auth.uid())),
    '{}'::text[]
  );
$$;

CREATE OR REPLACE FUNCTION private.user_in_ad_group(group_cn text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT group_cn = ANY (private.user_ad_groups());
$$;

-- NOTE: the campus IdP does not currently release eduPersonAffiliation, so
-- `affiliations` is NULL for every user and this returns false for everyone.
-- It ships for forward-compatibility. Confirm the attribute is actually
-- arriving before gating any access on it:
--   SELECT count(*) FILTER (WHERE affiliations IS NOT NULL), count(*)
--     FROM private.user_attributes;
CREATE OR REPLACE FUNCTION private.user_has_affiliation(target text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT COALESCE(
    (SELECT target = ANY (ua.affiliations)
     FROM private.user_attributes ua
     WHERE ua.user_id = (SELECT auth.uid())),
    false
  );
$$;

-- Live role check that bypasses JWT staleness. Use in write paths so a
-- revocation takes effect immediately instead of at next token refresh.
-- Reads the materialized claims table, which is recomputed at write time.
CREATE OR REPLACE FUNCTION private.user_has_role_in_db(p_role text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT COALESCE(
    (SELECT p_role = ANY (ec.app_roles)
     FROM private.user_effective_claims ec
     WHERE ec.user_id = (SELECT auth.uid())),
    false
  );
$$;

-- ------------------------------------------------------------------------------
-- Authorization guards for SECURITY DEFINER RPCs
-- ------------------------------------------------------------------------------
-- Shipped because any RPC that reads the SSO layer needs them, and getting the
-- JWT-vs-live-DB distinction right is exactly the kind of thing this toolkit
-- exists to stop each app from re-deriving.
--
--   require_admin_read  — JWT only. Fast; stale up to one token lifetime.
--   require_admin_write — JWT AND live DB. A revoked admin loses write access
--                         immediately rather than at next token refresh.
CREATE OR REPLACE FUNCTION private.require_admin_read()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF NOT private.user_has_role('admin_role') THEN
    RAISE EXCEPTION 'insufficient_privilege: admin_role required'
      USING ERRCODE = '42501';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION private.require_admin_write()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF NOT (private.user_has_role('admin_role') AND private.user_has_role_in_db('admin_role')) THEN
    RAISE EXCEPTION 'insufficient_privilege: admin_role required (live check)'
      USING ERRCODE = '42501';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION private.actor()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT COALESCE((SELECT auth.jwt()) ->> 'email', (SELECT auth.uid())::text, 'unknown');
$$;

REVOKE EXECUTE ON FUNCTION private.require_admin_read()  FROM public, anon, authenticated;
REVOKE EXECUTE ON FUNCTION private.require_admin_write() FROM public, anon, authenticated;
REVOKE EXECUTE ON FUNCTION private.actor()               FROM public, anon, authenticated;

-- ------------------------------------------------------------------------------
-- Public RPC wrappers (private schema is never exposed to PostgREST)
-- ------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.get_my_ad_groups()
RETURNS text[]
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT private.user_ad_groups();
$$;

CREATE OR REPLACE FUNCTION public.get_my_attribute_summary()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT COALESCE(
    (SELECT jsonb_build_object(
       'display_identifier', ua.display_identifier,
       'full_name',          ua.full_name,
       'first_name',         ua.first_name,
       'last_name',          ua.last_name,
       'email',              ua.email,
       'title',              ua.title,
       'home_dept_code',     ua.home_dept_code,
       'home_dept_desc',     ua.home_dept_desc,
       'dept_codes',         to_jsonb(ua.dept_codes),
       'ad_group_cns',       to_jsonb(ua.ad_group_cns),
       'member_of_status',   ua.member_of_status,
       'affiliations',       to_jsonb(ua.affiliations),
       'source_kind',        ua.source_kind,
       'synced_at',          ua.synced_at
     )
     FROM private.user_attributes ua
     WHERE ua.user_id = (SELECT auth.uid())),
    '{}'::jsonb
  );
$$;

-- ------------------------------------------------------------------------------
-- Grants
-- ------------------------------------------------------------------------------
DO $$
DECLARE
  fn text;
BEGIN
  FOREACH fn IN ARRAY ARRAY[
    'private.user_has_role(text)',
    'private.user_dept_codes()',
    'private.claims_degraded()',
    'private.user_ad_groups()',
    'private.user_in_ad_group(text)',
    'private.user_has_affiliation(text)',
    'private.user_has_role_in_db(text)',
    'public.get_my_ad_groups()',
    'public.get_my_attribute_summary()'
  ] LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM public, anon', fn);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO authenticated', fn);
  END LOOP;
END;
$$;

SELECT private.register_module('0003_rls_helpers', '1.0.0');


-- ==============================================================================
-- @jsmillerucsd/supabase-sso — 0004_roles  [OPTIONAL MODULE]
-- ==============================================================================
-- Role definitions and the four grant sources that feed `app_roles`:
--   1. manual grants           private.user_roles
--   2. AD group membership     private.ad_group_role_mappings  x user_attributes.ad_group_cns
--   3. UCPath employee ID      private.emplid_role_mappings    x user_attributes.ucpath_emplid
--   4. home department code    private.dept_code_role_mappings x user_attributes.home_dept_code
--
-- This module is genuinely optional. It adds role support by CREATE OR REPLACEing
-- exactly one function — private.recompute_user_claims() — which 0002 ships as a
-- stub. Nothing outside this file references these tables, and the auth hook
-- (0005) reads only private.user_effective_claims. Skip this module and roles
-- are simply always empty; nothing breaks.
--
-- DEGRADED SIGNAL: AD-group-derived roles are best-effort. The campus IdP's
-- memberOf attribute is truncated to a single group for most users
-- (supabase/auth#2332). Derivation is additive, so a truncated list can only
-- under-grant. Never use absence of a group as a permission signal.
--
-- Depends on: 0002, 0003
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- Tables
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS private.app_roles (
  role        text PRIMARY KEY,
  description text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS private.user_roles (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id    uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role       text NOT NULL REFERENCES private.app_roles(role) ON DELETE CASCADE,
  granted_by text,
  granted_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  UNIQUE (user_id, role)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON private.user_roles (user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role    ON private.user_roles (role);
CREATE INDEX IF NOT EXISTS idx_user_roles_active  ON private.user_roles (user_id, role)
  WHERE expires_at IS NULL;

CREATE TABLE IF NOT EXISTS private.ad_group_role_mappings (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ad_group_cn text NOT NULL,
  role        text NOT NULL REFERENCES private.app_roles(role) ON DELETE CASCADE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (ad_group_cn, role)
);
CREATE INDEX IF NOT EXISTS idx_ad_group_mappings_role ON private.ad_group_role_mappings (role);

CREATE TABLE IF NOT EXISTS private.emplid_role_mappings (
  id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ucpath_emplid text NOT NULL,
  role          text NOT NULL REFERENCES private.app_roles(role) ON DELETE CASCADE,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (ucpath_emplid, role)
);
CREATE INDEX IF NOT EXISTS idx_emplid_mappings_role ON private.emplid_role_mappings (role);

CREATE TABLE IF NOT EXISTS private.dept_code_role_mappings (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  dept_code  text NOT NULL,
  role       text NOT NULL REFERENCES private.app_roles(role) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (dept_code, role)
);
CREATE INDEX IF NOT EXISTS idx_dept_mappings_role ON private.dept_code_role_mappings (role);

REVOKE ALL ON private.app_roles              FROM public, anon, authenticated;
REVOKE ALL ON private.user_roles             FROM public, anon, authenticated;
REVOKE ALL ON private.ad_group_role_mappings FROM public, anon, authenticated;
REVOKE ALL ON private.emplid_role_mappings   FROM public, anon, authenticated;
REVOKE ALL ON private.dept_code_role_mappings FROM public, anon, authenticated;

DROP TRIGGER IF EXISTS set_app_roles_timestamp ON private.app_roles;
CREATE TRIGGER set_app_roles_timestamp
  BEFORE UPDATE ON private.app_roles
  FOR EACH ROW EXECUTE FUNCTION private.update_timestamp();

-- Baseline role. Apps add their own via public.create_app_role().
INSERT INTO private.app_roles (role, description)
VALUES ('admin_role', 'Full administrative access to this application')
ON CONFLICT (role) DO NOTHING;

-- ------------------------------------------------------------------------------
-- The real recompute — replaces 0002's stub (THE COMPOSITION SEAM)
-- ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION private.recompute_user_claims(p_user_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  ua        private.user_attributes;
  manual    text[];
  ad        text[];
  emp       text[];
  dept      text[];
  all_roles text[];
BEGIN
  SELECT * INTO ua FROM private.user_attributes WHERE user_id = p_user_id;

  IF NOT FOUND THEN
    -- Deprivilege, but still materialize a row so the hook finds one and does
    -- not have to distinguish "missing" from "no roles".
    INSERT INTO private.user_effective_claims (user_id)
    VALUES (p_user_id)
    ON CONFLICT (user_id) DO UPDATE SET
      app_roles   = '{}',
      dept_codes  = '{}',
      computed_at = now();
    RETURN;
  END IF;

  SELECT array_agg(ur.role) INTO manual
  FROM private.user_roles ur
  WHERE ur.user_id = p_user_id
    AND (ur.expires_at IS NULL OR ur.expires_at > now());

  -- Additive only. A truncated ad_group_cns can under-grant, never over-grant.
  SELECT array_agg(DISTINCT m.role) INTO ad
  FROM private.ad_group_role_mappings m
  WHERE m.ad_group_cn = ANY (ua.ad_group_cns);

  SELECT array_agg(DISTINCT m.role) INTO emp
  FROM private.emplid_role_mappings m
  WHERE ua.ucpath_emplid IS NOT NULL
    AND m.ucpath_emplid = ua.ucpath_emplid;

  SELECT array_agg(DISTINCT m.role) INTO dept
  FROM private.dept_code_role_mappings m
  WHERE m.dept_code = NULLIF(ltrim(COALESCE(ua.home_dept_code, ''), '0'), '');

  SELECT array_agg(DISTINCT r) INTO all_roles
  FROM unnest(
    COALESCE(manual, '{}')
    || COALESCE(ad,   '{}')
    || COALESCE(emp,  '{}')
    || COALESCE(dept, '{}')
  ) AS r;

  INSERT INTO private.user_effective_claims (user_id, app_roles, dept_codes, extra_claims, computed_at)
  VALUES (p_user_id, COALESCE(all_roles, '{}'), ua.dept_codes, '{}'::jsonb, now())
  ON CONFLICT (user_id) DO UPDATE SET
    app_roles    = EXCLUDED.app_roles,
    dept_codes   = EXCLUDED.dept_codes,
    extra_claims = EXCLUDED.extra_claims,
    computed_at  = now();
END;
$$;

-- ------------------------------------------------------------------------------
-- Keep materialized claims current when role configuration changes
-- ------------------------------------------------------------------------------
-- Statement-level: mapping edits are admin-scale and rare. Correctness over
-- cleverness — a full recompute is cheap relative to how often this fires.
CREATE OR REPLACE FUNCTION private.on_role_config_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  PERFORM private.recompute_all_user_claims();
  RETURN NULL;
END;
$$;

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'user_roles', 'ad_group_role_mappings', 'emplid_role_mappings', 'dept_code_role_mappings'
  ] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS on_%s_changed ON private.%I', t, t);
    EXECUTE format(
      'CREATE TRIGGER on_%s_changed AFTER INSERT OR UPDATE OR DELETE ON private.%I
         FOR EACH STATEMENT EXECUTE FUNCTION private.on_role_config_change()',
      t, t
    );
  END LOOP;
END;
$$;

-- ------------------------------------------------------------------------------
-- Loud warning when mapping against a degraded attribute
-- ------------------------------------------------------------------------------
-- Fires however the row arrives — seed script, migration, psql — because the
-- toolkit ships no admin RPC to hang this off. A WARNING, not an error: the
-- mapping still works, it just under-grants.
CREATE OR REPLACE FUNCTION private.warn_if_member_of_unreliable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  n_suspect int;
  n_total   int;
BEGIN
  SELECT count(*) FILTER (WHERE member_of_status = 'suspect_truncated'), count(*)
    INTO n_suspect, n_total
    FROM private.user_attributes;

  IF n_total > 0 AND n_suspect > 0 THEN
    RAISE WARNING 'member_of is unreliable (% of % users look truncated to a single AD group, supabase/auth#2332); AD-group role mappings will under-grant',
      n_suspect, n_total;
  END IF;
  RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS warn_ad_group_mapping_quality ON private.ad_group_role_mappings;
CREATE TRIGGER warn_ad_group_mapping_quality
  AFTER INSERT ON private.ad_group_role_mappings
  FOR EACH STATEMENT EXECUTE FUNCTION private.warn_if_member_of_unreliable();

-- Pick up roles for users projected before this module was installed.
SELECT private.recompute_all_user_claims();

SELECT private.register_module('0004_roles', '1.0.0');


-- ==============================================================================
-- @jsmillerucsd/supabase-sso — 0005_auth_hook
-- ==============================================================================
-- Custom access token hook. Runs on every token mint and refresh.
--
-- Two rules, both enforced below:
--   * These claims must survive untouched or authentication breaks:
--     iss, aud, exp, iat, sub, role, aal, session_id, email, phone, is_anonymous.
--   * The hook must never raise. It has a ~2s budget and errors are not retried,
--     so an exception here fails the sign-in. Degrade to zero roles instead.
--
-- The incoming user_metadata is client-writable, so it is discarded and rebuilt
-- from private.user_attributes. That also keeps the JWT small enough for the
-- session cookie.
--
-- Cost: two primary-key lookups. Roles are derived at write time, not here.
--
-- ENABLEMENT (not executable from a migration):
--   Hosted:  Dashboard > Authentication > Hooks > Customize Access Token
--            pg-functions://postgres/private/custom_access_token_hook
--   Local:   supabase/config.toml
--            [auth.hook.custom_access_token]
--            enabled = true
--            uri = "pg-functions://postgres/private/custom_access_token_hook"
--
-- Depends on: 0002 (0004 optional — without it app_roles is always empty)
-- ==============================================================================

CREATE OR REPLACE FUNCTION private.custom_access_token_hook(event jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  claims    jsonb;
  v_user_id uuid;
  v_roles   text[];
  v_depts   text[];
  v_extra   jsonb;
  v_found   boolean := false;
  src_app   jsonb;
  slim_user jsonb;
BEGIN
  claims    := event -> 'claims';
  v_user_id := (event ->> 'user_id')::uuid;

  -- ---- app_roles / dept_codes_array -----------------------------------------
  BEGIN
    SELECT ec.app_roles, ec.dept_codes, ec.extra_claims
      INTO v_roles, v_depts, v_extra
      FROM private.user_effective_claims ec
     WHERE ec.user_id = v_user_id;

    v_found := FOUND;

    IF v_found THEN
      claims := jsonb_set(claims, '{app_roles}',        to_jsonb(COALESCE(v_roles, '{}'::text[])));
      claims := jsonb_set(claims, '{dept_codes_array}', to_jsonb(COALESCE(v_depts, '{}'::text[])));
      IF v_extra IS NOT NULL AND v_extra <> '{}'::jsonb THEN
        claims := claims || v_extra;
      END IF;
    ELSE
      claims := jsonb_set(claims, '{app_roles}',           '[]'::jsonb);
      claims := jsonb_set(claims, '{dept_codes_array}',    '[]'::jsonb);
      claims := jsonb_set(claims, '{app_claims_degraded}', 'true'::jsonb);
    END IF;
  EXCEPTION WHEN OTHERS THEN
    -- Deprivilege, never deny. See header.
    claims := jsonb_set(claims, '{app_roles}',           '[]'::jsonb);
    claims := jsonb_set(claims, '{dept_codes_array}',    '[]'::jsonb);
    claims := jsonb_set(claims, '{app_claims_degraded}', 'true'::jsonb);
  END;

  -- ---- user_metadata: rebuild from the trusted projection --------------------
  BEGIN
    SELECT jsonb_strip_nulls(jsonb_build_object(
             'email',              ua.email,
             'full_name',          ua.full_name,
             'first_name',         ua.first_name,
             'last_name',          ua.last_name,
             'display_identifier', ua.display_identifier,
             'home_dept_code',     ua.home_dept_code,
             'home_dept_desc',     ua.home_dept_desc,
             'title',              ua.title
           ))
      INTO slim_user
      FROM private.user_attributes ua
     WHERE ua.user_id = v_user_id;
  EXCEPTION WHEN OTHERS THEN
    slim_user := NULL;
  END;

  claims := jsonb_set(claims, '{user_metadata}', COALESCE(slim_user, '{}'::jsonb));

  -- ---- app_metadata: provider info only --------------------------------------
  src_app := COALESCE(claims -> 'app_metadata', '{}'::jsonb);
  claims  := jsonb_set(claims, '{app_metadata}', jsonb_build_object(
    'provider',  src_app ->> 'provider',
    'providers', COALESCE(src_app -> 'providers', '[]'::jsonb)
  ));

  RETURN jsonb_set(event, '{claims}', claims);
END;
$$;

-- ------------------------------------------------------------------------------
-- Grants — supabase_auth_admin is the only caller
-- ------------------------------------------------------------------------------
REVOKE EXECUTE ON FUNCTION private.custom_access_token_hook(jsonb) FROM public, anon, authenticated;
GRANT  EXECUTE ON FUNCTION private.custom_access_token_hook(jsonb) TO supabase_auth_admin;

GRANT USAGE  ON SCHEMA private                     TO supabase_auth_admin;
GRANT SELECT ON private.user_effective_claims      TO supabase_auth_admin;
GRANT SELECT ON private.user_attributes            TO supabase_auth_admin;

SELECT private.register_module('0005_auth_hook', '1.0.0');


-- ==============================================================================
-- @jsmillerucsd/supabase-sso — 0006_ucsd_adapter  [OPTIONAL CAMPUS ADAPTER]
-- ==============================================================================
-- UCSD Shibboleth attribute extraction. This is the ONLY file in the toolkit
-- that knows about UCSD-specific attributes (dept codes, UCPath emplids, AD
-- groups, UCnetID). Everything else is campus-agnostic.
--
-- It works by CREATE OR REPLACEing private.extract_attributes() — the seam that
-- 0002 defines. Another campus writes its own adapter module and skips this one.
--
-- WHERE THE ATTRIBUTES LIVE:
--   SAML branch:   standard keys at the top level of identity_data
--                  (sub, email, name, ...); every UCSD attribute nests under
--                  identity_data.custom_claims. Confirmed against live data.
--   Legacy branch: the retired attribute-sync flattened custom_claims to the top
--                  level of raw_app_meta_data, so there is no nesting to unwrap.
--
-- Depends on: 0002 (0004 optional)
-- ==============================================================================

CREATE OR REPLACE FUNCTION private.extract_attributes(
  p_source_kind text,
  p_payload     jsonb
)
RETURNS private.user_attributes
LANGUAGE plpgsql
STABLE
SET search_path = ''
AS $$
DECLARE
  r   private.user_attributes;
  cc  jsonb;   -- where UCSD attributes live
  src jsonb;   -- where standard keys live
BEGIN
  IF p_source_kind = 'saml' THEN
    cc  := COALESCE(p_payload -> 'custom_claims', '{}'::jsonb);
    src := COALESCE(p_payload, '{}'::jsonb);
  ELSIF p_source_kind = 'legacy_oauth' THEN
    cc  := COALESCE(p_payload, '{}'::jsonb);
    src := COALESCE(p_payload, '{}'::jsonb);
  ELSE
    RAISE EXCEPTION 'unknown source_kind %', p_source_kind;
  END IF;

  r.subject_id  := src ->> 'sub';
  r.eppn        := NULLIF(cc ->> 'eppn', '');
  r.ad_username := NULLIF(cc ->> 'ad_username', '');
  r.ucnet_id    := NULLIF(cc ->> 'ucnet_id', '');
  r.email       := COALESCE(NULLIF(src ->> 'email', ''), NULLIF(cc ->> 'mail', ''));

  r.full_name   := COALESCE(NULLIF(cc ->> 'full_name', ''),  NULLIF(src ->> 'name', ''));
  r.first_name  := COALESCE(NULLIF(cc ->> 'first_name', ''), NULLIF(src ->> 'given_name', ''));
  r.last_name   := COALESCE(NULLIF(cc ->> 'last_name', ''),  NULLIF(src ->> 'family_name', ''));
  r.title       := NULLIF(cc ->> 'title', '');

  -- Department codes are stored canonically un-padded. The IdP sends them
  -- zero-padded ("0578"); downstream lookup tables use "578". Normalizing here,
  -- once, is what keeps every consumer from having to remember to do it.
  r.home_dept_code := NULLIF(ltrim(COALESCE(cc ->> 'home_dept_code', ''), '0'), '');
  r.home_dept_desc := NULLIF(cc ->> 'home_dept_desc', '');
  r.dept_codes     := private.parse_multi(cc -> 'dept_codes', ',', true);
  r.dept_names     := private.parse_multi(cc -> 'dept_names', ',', false);

  -- NULL (not released) vs '{}' (released and empty) is a meaningful distinction
  -- here: the campus IdP does not currently release eduPersonAffiliation at all,
  -- so this column is NULL for every user until that changes.
  r.affiliations := CASE
    WHEN cc ? 'affiliation' THEN private.parse_multi(cc -> 'affiliation', ';', false)
    ELSE NULL
  END;

  SELECT c.raw, c.cns, c.status
    INTO r.member_of_raw, r.ad_group_cns, r.member_of_status
    FROM private.classify_member_of(cc -> 'member_of') c;

  r.ucpath_emplid   := NULLIF(cc ->> 'ucpath_emplid', '');
  r.pid             := NULLIF(cc ->> 'pid', '');
  r.employee_status := NULLIF(cc ->> 'employee_status', '');

  r.display_identifier := private.derive_display_identifier(
    r.eppn, r.ad_username, r.ucnet_id, r.email
  );

  r.raw := p_payload;
  RETURN r;
END;
$$;

-- ------------------------------------------------------------------------------
-- Re-project everything so existing rows pick up UCSD extraction
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
      PERFORM private.project_user_attributes(r.user_id, 'saml', r.identity_data);
    EXCEPTION WHEN OTHERS THEN
      INSERT INTO private.sync_errors (user_id, source, detail, payload)
      VALUES (r.user_id, 'projection_trigger', 'ucsd adapter reproject: ' || SQLERRM, r.identity_data);
    END;
  END LOOP;

  FOR r IN
    SELECT u.id AS user_id, u.raw_app_meta_data
    FROM auth.users u
    WHERE COALESCE(u.is_sso_user, false) = false
      AND u.raw_app_meta_data ->> 'provider' = 'custom:ucsd-sso'
      AND NOT EXISTS (
        SELECT 1 FROM private.user_attributes ua
        WHERE ua.user_id = u.id AND ua.source_kind = 'saml'
      )
  LOOP
    BEGIN
      PERFORM private.project_user_attributes(r.user_id, 'legacy_oauth', r.raw_app_meta_data);
    EXCEPTION WHEN OTHERS THEN
      INSERT INTO private.sync_errors (user_id, source, detail, payload)
      VALUES (r.user_id, 'legacy_trigger', 'ucsd adapter reproject: ' || SQLERRM, r.raw_app_meta_data);
    END;
  END LOOP;
END;
$$;

SELECT private.recompute_all_user_claims();

SELECT private.register_module('0006_ucsd_adapter', '1.0.0');
