-- ==============================================================================
-- @ucsd/supabase-sso — 0003_rls_helpers
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
