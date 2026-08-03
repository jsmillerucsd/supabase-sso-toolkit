-- ==============================================================================
-- @ucsd/supabase-sso — 0001_core
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
