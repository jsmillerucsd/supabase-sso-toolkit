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
