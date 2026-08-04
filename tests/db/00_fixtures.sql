-- ==============================================================================
-- Test fixtures — shared helpers for the @jsmillerucsd/supabase-sso pgTAP suite.
-- ==============================================================================
-- Applied as a migration in the toolkit's own dev project (and copied into
-- consuming apps by `install-sql --with-tests`). Creates nothing outside the
-- `sso_test` schema.
-- ==============================================================================

CREATE SCHEMA IF NOT EXISTS sso_test;

-- A SAML identity shaped like real campus data.
CREATE OR REPLACE FUNCTION sso_test.make_saml_user(
  p_user_id  uuid,
  p_email    text DEFAULT 'user@ucsd.edu',
  p_claims   jsonb DEFAULT NULL,
  p_poisoned jsonb DEFAULT '{}'::jsonb
)
RETURNS uuid
LANGUAGE plpgsql
AS $$
DECLARE
  cc jsonb;
BEGIN
  cc := COALESCE(p_claims, jsonb_build_object(
    'eppn', p_email, 'ad_username', split_part(p_email, '@', 1),
    'ucnet_id', split_part(p_email, '@', 1) || '-uc', 'mail', p_email,
    'full_name', 'TEST, USER', 'first_name', 'User', 'last_name', 'Test',
    'title', 'Analyst', 'home_dept_code', '0578', 'dept_codes', '0578,0580',
    'dept_names', 'Dept A,Dept B', 'ucpath_emplid', '10012345',
    'member_of', 'CN=App-Admins,OU=Groups,DC=ad,DC=ucsd,DC=edu'
  ));

  INSERT INTO auth.users (
    id, instance_id, aud, role, email, is_sso_user,
    raw_app_meta_data, raw_user_meta_data, created_at, updated_at
  )
  VALUES (
    p_user_id, '00000000-0000-0000-0000-000000000000',
    'authenticated', 'authenticated', p_email, true,
    jsonb_build_object('provider', 'sso:test', 'providers', jsonb_build_array('sso:test')),
    p_poisoned, now(), now()
  );

  INSERT INTO auth.identities (
    id, user_id, provider_id, provider, identity_data, created_at, updated_at, last_sign_in_at
  )
  VALUES (
    gen_random_uuid(), p_user_id, p_email,
    'sso:f063d234-1eac-425c-846c-833176a050c7',
    jsonb_build_object('sub', p_email, 'email', p_email, 'email_verified', true,
                       'custom_claims', cc),
    now(), now(), now()
  );

  RETURN p_user_id;
END;
$$;

-- Build a hook event with every required claim present.
CREATE OR REPLACE FUNCTION sso_test.hook_event(
  p_user_id       uuid,
  p_user_metadata jsonb DEFAULT '{}'::jsonb,
  p_app_metadata  jsonb DEFAULT '{}'::jsonb,
  p_session_id    uuid  DEFAULT '22222222-2222-2222-2222-222222222222'
)
RETURNS jsonb
LANGUAGE sql
AS $$
  SELECT jsonb_build_object(
    'user_id', p_user_id,
    'claims', jsonb_build_object(
      'iss', 'https://example.test/auth/v1',
      'aud', 'authenticated',
      'exp', 2000000000,
      'iat', 1000000000,
      'sub', p_user_id::text,
      'role', 'authenticated',
      'aal', 'aal1',
      'session_id', p_session_id::text,
      'email', 'user@ucsd.edu',
      'phone', '',
      'is_anonymous', false,
      'user_metadata', p_user_metadata,
      'app_metadata', p_app_metadata
    )
  );
$$;

-- Impersonate an authenticated caller with the given claims.
CREATE OR REPLACE FUNCTION sso_test.set_jwt(p_claims jsonb)
RETURNS void
LANGUAGE sql
AS $$
  SELECT set_config('request.jwt.claims', p_claims::text, true);
$$;
