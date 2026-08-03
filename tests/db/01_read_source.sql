-- ==============================================================================
-- 01_read_source — THE MANDATORY REGRESSION LOCKS
-- ==============================================================================
-- The predecessor project regressed twice on where auth-critical attributes are
-- read from (user_metadata vs app_metadata). These tests exist so it cannot
-- happen a third time.
--
-- Covers spec tests 01 (hook ignores user_metadata), 02 (projection ignores
-- raw_user_meta_data merge-ratchet), and 16 (RLS helper read sources).
-- ==============================================================================
BEGIN;
CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA extensions;
SELECT plan(14);

-- ------------------------------------------------------------------------------
-- Spec 01: the hook must ignore poisoned metadata on the incoming event
-- ------------------------------------------------------------------------------
SELECT sso_test.make_saml_user(
  '11111111-1111-1111-1111-111111111111',
  'poison@ucsd.edu',
  jsonb_build_object('eppn', 'poison@ucsd.edu', 'ad_username', 'poison',
                     'home_dept_code', '0578', 'dept_codes', '0578'),
  -- raw_user_meta_data, client-writable via updateUser(): pure poison
  jsonb_build_object(
    'app_roles', jsonb_build_array('admin_role'),
    'custom_claims', jsonb_build_object(
      'dept_codes', '999999',
      'member_of', 'CN=Evil-Admins,OU=x,DC=ad',
      'home_dept_code', '999999'
    )
  )
);

CREATE TEMP TABLE hook_out AS
SELECT private.custom_access_token_hook(
  sso_test.hook_event(
    '11111111-1111-1111-1111-111111111111',
    jsonb_build_object('app_roles', jsonb_build_array('admin_role'),
                       'member_of', 'CN=Evil-Admins',
                       'dept_codes', '999999'),
    jsonb_build_object('provider', 'sso:test',
                       'providers', jsonb_build_array('sso:test'),
                       'app_roles', jsonb_build_array('admin_role'),
                       'dept_codes', '999999')
  )
) -> 'claims' AS claims;

SELECT is(
  (SELECT claims -> 'app_roles' FROM hook_out),
  '[]'::jsonb,
  'hook: poisoned user_metadata/app_metadata app_roles is NOT honored'
);

SELECT is(
  (SELECT claims -> 'dept_codes_array' FROM hook_out),
  '["578"]'::jsonb,
  'hook: dept_codes_array comes from the projection, not poisoned metadata'
);

SELECT ok(
  (SELECT NOT (claims -> 'user_metadata' ? 'app_roles') FROM hook_out),
  'hook: app_roles never appears inside user_metadata'
);

SELECT ok(
  (SELECT NOT (claims -> 'user_metadata' ? 'member_of') FROM hook_out),
  'hook: member_of never rides in user_metadata'
);

SELECT ok(
  (SELECT NOT (claims -> 'user_metadata' ? 'dept_codes') FROM hook_out),
  'hook: raw dept_codes string never rides in user_metadata'
);

SELECT is(
  (SELECT (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(claims -> 'app_metadata') k)
   FROM hook_out),
  ARRAY['provider', 'providers'],
  'hook: app_metadata is slimmed to provider/providers only'
);

-- ------------------------------------------------------------------------------
-- Spec 02: the projection must never read raw_user_meta_data
-- ------------------------------------------------------------------------------
-- raw_user_meta_data is updated by a key-wise MERGE, so stale keys survive
-- forever. identity_data is replaced wholesale. Reading the former would mean a
-- group removed upstream is never revoked here.
SELECT is(
  (SELECT member_of_status FROM private.user_attributes
   WHERE user_id = '11111111-1111-1111-1111-111111111111'),
  'absent',
  'projection: member_of absent from identity_data => absent, despite poisoned raw_user_meta_data'
);

SELECT is(
  (SELECT ad_group_cns FROM private.user_attributes
   WHERE user_id = '11111111-1111-1111-1111-111111111111'),
  '{}'::text[],
  'projection: no AD groups leak in from raw_user_meta_data'
);

SELECT is(
  (SELECT home_dept_code FROM private.user_attributes
   WHERE user_id = '11111111-1111-1111-1111-111111111111'),
  '578',
  'projection: home_dept_code comes from identity_data, not the poisoned 999999'
);

-- ------------------------------------------------------------------------------
-- Spec 16: RLS helpers read top-level claims only
-- ------------------------------------------------------------------------------
SELECT sso_test.set_jwt(jsonb_build_object(
  'sub', '11111111-1111-1111-1111-111111111111',
  'app_roles', jsonb_build_array('reader_role'),
  'dept_codes_array', jsonb_build_array('578'),
  -- poison in both metadata containers
  'app_metadata',  jsonb_build_object('app_roles', jsonb_build_array('admin_role')),
  'user_metadata', jsonb_build_object('app_roles', jsonb_build_array('admin_role'),
                                      'dept_codes_array', jsonb_build_array('999999'))
));

SELECT ok(private.user_has_role('reader_role'),
          'user_has_role: reads the top-level app_roles claim');

SELECT ok(NOT private.user_has_role('admin_role'),
          'user_has_role: ignores app_roles planted in app_metadata/user_metadata');

SELECT is(private.user_dept_codes(), ARRAY['578'],
          'user_dept_codes: reads top-level dept_codes_array only');

SELECT ok(NOT private.user_has_affiliation('staff'),
          'user_has_affiliation: false when the IdP released no affiliation');

SELECT ok(NOT private.claims_degraded(),
          'claims_degraded: false when the hook materialized claims normally');

SELECT * FROM finish();
ROLLBACK;
