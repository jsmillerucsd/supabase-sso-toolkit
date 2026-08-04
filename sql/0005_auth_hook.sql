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

SELECT private.register_module('0005_auth_hook', '1.0.0');
