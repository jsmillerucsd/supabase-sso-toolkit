-- ==============================================================================
-- @jsmillerucsd/supabase-sso v1.1.0 — install
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
  source      text NOT NULL, -- projection_trigger | recompute | admin_rpc
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

SELECT private.register_module('0001_core', '1.1.0');


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
      -- Log only. synced_at is NOT bumped: it must keep reflecting the last
      -- SUCCESSFUL projection, or staleness monitoring cannot see the failure.
      INSERT INTO private.sync_errors (user_id, source, detail, payload)
      VALUES (NEW.user_id, 'projection_trigger', SQLERRM, NEW.identity_data);
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
-- private.reproject_all_sso_identities — backfill / adapter re-projection
-- ------------------------------------------------------------------------------
-- Fail-open per user: one bad payload logs (prefixed with p_label) and moves on.
-- Called at install time here and by campus adapter modules after they replace
-- private.extract_attributes.
CREATE OR REPLACE FUNCTION private.reproject_all_sso_identities(p_label text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
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
      VALUES (r.user_id, 'projection_trigger', p_label || ': ' || SQLERRM, r.identity_data);
    END;
  END LOOP;
END;
$$;

-- Backfill — safe on a fresh schema, safe to re-run.
SELECT private.reproject_all_sso_identities('backfill');

SELECT private.register_module('0002_identity_projection', '1.1.0');


-- ==============================================================================
-- @jsmillerucsd/supabase-sso — 0003_rls_helpers
-- ==============================================================================
-- Helper functions for RLS policies and application code.
--
-- READ-SOURCE RULE:
--   * Role and department checks read TOP-LEVEL JWT claims injected by the auth
--     hook (`app_roles`, `dept_codes_array`): never `app_metadata`, never
--     `user_metadata`. `user_metadata` is client-writable; trusting it is a
--     privilege-escalation vector.
--   * Attribute checks that are not in the JWT (AD groups) read
--     `private.user_attributes` directly.
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

-- Live role check that bypasses JWT staleness. Use in write paths so a
-- revocation takes effect immediately instead of at next token refresh.
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
--   require_admin_read  : JWT only. Fast; stale up to one token lifetime.
--   require_admin_write : JWT AND live DB. A revoked admin loses write access
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

REVOKE EXECUTE ON FUNCTION private.require_admin_read()  FROM public, anon, authenticated;
REVOKE EXECUTE ON FUNCTION private.require_admin_write() FROM public, anon, authenticated;

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
    'private.user_has_role_in_db(text)',
    'public.get_my_ad_groups()',
    'public.get_my_attribute_summary()'
  ] LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM public, anon', fn);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO authenticated', fn);
  END LOOP;
END;
$$;

SELECT private.register_module('0003_rls_helpers', '1.1.0');


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

-- UNIQUE (user_id, role) above already serves the per-user lookup, and a partial
-- index on `expires_at IS NULL` can never match the expiry-aware recompute
-- filter. Both shipped in earlier versions; drop them on upgrade.
DROP INDEX IF EXISTS private.idx_user_roles_user_id;
DROP INDEX IF EXISTS private.idx_user_roles_active;
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON private.user_roles (role);

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

  INSERT INTO private.user_effective_claims (user_id, app_roles, dept_codes, computed_at)
  VALUES (p_user_id, COALESCE(all_roles, '{}'), ua.dept_codes, now())
  ON CONFLICT (user_id) DO UPDATE SET
    app_roles   = EXCLUDED.app_roles,
    dept_codes  = EXCLUDED.dept_codes,
    computed_at = now();
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
-- Expiry sweep — a grant whose expires_at passes must actually go away
-- ------------------------------------------------------------------------------
-- Claims are materialized, so an expiry only takes effect at the next recompute,
-- and pure time passage triggers none: without this sweep an expired grant keeps
-- riding in every freshly minted JWT (and in user_has_role_in_db) until some
-- unrelated role-config write happens to fire a recompute.
--
-- Targets exactly the stale rows: claims computed while the grant was still
-- valid (computed_at < expires_at) on a grant that has since expired. A swept
-- user's computed_at moves past expires_at, so the row self-clears from the scan.
CREATE OR REPLACE FUNCTION private.recompute_stale_expiries()
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  r record;
  n integer := 0;
BEGIN
  FOR r IN
    SELECT DISTINCT ur.user_id
    FROM private.user_roles ur
    JOIN private.user_effective_claims ec ON ec.user_id = ur.user_id
    WHERE ur.expires_at IS NOT NULL
      AND ur.expires_at <= now()
      AND ec.computed_at < ur.expires_at
  LOOP
    BEGIN
      PERFORM private.recompute_user_claims(r.user_id);
      n := n + 1;
    EXCEPTION WHEN OTHERS THEN
      INSERT INTO private.sync_errors (user_id, source, detail)
      VALUES (r.user_id, 'recompute', 'expiry sweep: ' || SQLERRM);
    END;
  END LOOP;
  RETURN n;
END;
$$;

-- Hourly schedule via pg_cron (hosted Supabase and the local stack both ship
-- it). cron.schedule upserts by job name, so re-running the installer is safe.
-- Without pg_cron, call private.recompute_stale_expiries() from your own
-- scheduler — otherwise expiry does not take effect on its own.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_cron') THEN
    CREATE EXTENSION IF NOT EXISTS pg_cron;
    PERFORM cron.schedule('sso_toolkit_expiry_sweep', '7 * * * *',
                          'SELECT private.recompute_stale_expiries()');
  ELSE
    RAISE WARNING 'pg_cron unavailable: schedule private.recompute_stale_expiries() externally, or expired role grants persist until the next recompute';
  END IF;
EXCEPTION WHEN OTHERS THEN
  RAISE WARNING 'could not schedule expiry sweep (%); schedule private.recompute_stale_expiries() externally', SQLERRM;
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

SELECT private.register_module('0004_roles', '1.1.0');


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
-- Depends on: 0002 (0004 optional: without it app_roles is always empty)
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
  v_found   boolean := false;
  src_app   jsonb;
  slim_user jsonb;
BEGIN
  claims    := event -> 'claims';
  v_user_id := (event ->> 'user_id')::uuid;

  -- ---- app_roles / dept_codes_array -----------------------------------------
  BEGIN
    SELECT ec.app_roles, ec.dept_codes
      INTO v_roles, v_depts
      FROM private.user_effective_claims ec
     WHERE ec.user_id = v_user_id;

    v_found := FOUND;

    IF v_found THEN
      claims := jsonb_set(claims, '{app_roles}',        to_jsonb(COALESCE(v_roles, '{}'::text[])));
      claims := jsonb_set(claims, '{dept_codes_array}', to_jsonb(COALESCE(v_depts, '{}'::text[])));
    ELSE
      claims := jsonb_set(claims, '{app_roles}',           '[]'::jsonb);
      claims := jsonb_set(claims, '{dept_codes_array}',    '[]'::jsonb);
      claims := jsonb_set(claims, '{app_claims_degraded}', 'true'::jsonb);
    END IF;
  EXCEPTION WHEN OTHERS THEN
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
-- Grants: supabase_auth_admin is the only caller
-- ------------------------------------------------------------------------------
REVOKE EXECUTE ON FUNCTION private.custom_access_token_hook(jsonb) FROM public, anon, authenticated;
GRANT  EXECUTE ON FUNCTION private.custom_access_token_hook(jsonb) TO supabase_auth_admin;

GRANT USAGE  ON SCHEMA private                TO supabase_auth_admin;
GRANT SELECT ON private.user_effective_claims TO supabase_auth_admin;
GRANT SELECT ON private.user_attributes       TO supabase_auth_admin;

SELECT private.register_module('0005_auth_hook', '1.1.0');


-- ==============================================================================
-- @jsmillerucsd/supabase-sso — 0006_ucsd_adapter  [OPTIONAL CAMPUS ADAPTER]
-- ==============================================================================
-- UCSD Shibboleth attribute extraction. This is the ONLY file in the toolkit
-- that knows about UCSD-specific attributes (dept codes, UCPath emplids, AD
-- groups, UCnetID). Everything else is campus-agnostic.
--
-- It works by CREATE OR REPLACEing private.extract_attributes(): the seam that
-- 0002 defines. Another campus writes its own adapter module and skips this one.
--
-- Standard keys live at the top level of identity_data (sub, email, name, ...);
-- every UCSD attribute nests under identity_data.custom_claims.
--
-- CONTRACT: the custom_claims key names read here are produced by the provider
-- attribute mapping in sql/assets/ucsd-attribute-mapping.json (passed to
-- `supabase sso add --attribute-mapping-file`). Renaming a key in either place
-- without the other silently yields NULL attributes — keep them in sync.
--
-- Depends on: 0002 (0004 optional)
-- ==============================================================================

CREATE OR REPLACE FUNCTION private.extract_attributes(p_payload jsonb)
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
  cc  := COALESCE(p_payload -> 'custom_claims', '{}'::jsonb);
  src := COALESCE(p_payload, '{}'::jsonb);

  r.eppn        := NULLIF(cc ->> 'eppn', '');
  r.ad_username := NULLIF(cc ->> 'ad_username', '');
  r.ucnet_id    := NULLIF(cc ->> 'ucnet_id', '');
  r.email       := COALESCE(NULLIF(src ->> 'email', ''), NULLIF(cc ->> 'mail', ''));

  r.full_name   := COALESCE(NULLIF(cc ->> 'full_name', ''),  NULLIF(src ->> 'name', ''));
  r.first_name  := COALESCE(NULLIF(cc ->> 'first_name', ''), NULLIF(src ->> 'given_name', ''));
  r.last_name   := COALESCE(NULLIF(cc ->> 'last_name', ''),  NULLIF(src ->> 'family_name', ''));
  r.title       := NULLIF(cc ->> 'title', '');

  -- Department codes are stored un-padded. The IdP sends them zero-padded
  -- ("0578"); downstream lookup tables use "578".
  r.home_dept_code := NULLIF(ltrim(COALESCE(cc ->> 'home_dept_code', ''), '0'), '');
  r.home_dept_desc := NULLIF(cc ->> 'home_dept_desc', '');
  r.dept_codes     := private.parse_multi(cc -> 'dept_codes', ',', true);

  SELECT c.cns, c.status
    INTO r.ad_group_cns, r.member_of_status
    FROM private.classify_member_of(cc -> 'member_of') c;

  r.ucpath_emplid := NULLIF(cc ->> 'ucpath_emplid', '');

  r.display_identifier := private.derive_display_identifier(
    r.eppn, r.ad_username, r.ucnet_id, r.email
  );

  r.raw := p_payload;
  RETURN r;
END;
$$;

-- Re-project everything so existing rows pick up UCSD extraction.
SELECT private.reproject_all_sso_identities('ucsd adapter reproject');

SELECT private.recompute_all_user_claims();

SELECT private.register_module('0006_ucsd_adapter', '1.1.0');
