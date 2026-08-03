-- ==============================================================================
-- 05_guards — authorization guards for app-owned RPCs
-- ==============================================================================
-- The toolkit ships no admin API, but it does ship the two guards, because the
-- JWT-vs-live-DB distinction is subtle and getting it wrong is how a revoked
-- admin keeps write access until their token expires.
-- ==============================================================================
BEGIN;
CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA extensions;
SELECT plan(8);

SELECT sso_test.make_saml_user('11111111-1111-1111-1111-111111111111', 'admin@ucsd.edu');
SELECT sso_test.make_saml_user('22222222-2222-2222-2222-222222222222', 'plain@ucsd.edu');

-- ------------------------------------------------------------------------------
-- A caller with no roles is refused by both guards
-- ------------------------------------------------------------------------------
SELECT sso_test.set_jwt(jsonb_build_object(
  'sub', '22222222-2222-2222-2222-222222222222',
  'app_roles', jsonb_build_array()
));

SELECT throws_ok($$ SELECT private.require_admin_read() $$,  '42501', NULL,
                 'guard: require_admin_read refuses a caller with no roles');
SELECT throws_ok($$ SELECT private.require_admin_write() $$, '42501', NULL,
                 'guard: require_admin_write refuses a caller with no roles');

-- Self-service RPCs stay open to any signed-in user.
SELECT lives_ok($$ SELECT public.get_my_attribute_summary() $$,
                'guard: get_my_attribute_summary is open to any signed-in user');
SELECT lives_ok($$ SELECT public.get_my_ad_groups() $$,
                'guard: get_my_ad_groups is open to any signed-in user');

-- ------------------------------------------------------------------------------
-- A stale token claiming admin can read but must not write
-- ------------------------------------------------------------------------------
-- This is the whole point of the split: the JWT says admin, the database does
-- not. Reads tolerate that staleness; writes must not.
SELECT sso_test.set_jwt(jsonb_build_object(
  'sub', '11111111-1111-1111-1111-111111111111',
  'app_roles', jsonb_build_array('admin_role')
));

SELECT lives_ok($$ SELECT private.require_admin_read() $$,
                'guard: read guard accepts a JWT-only admin');
SELECT throws_ok($$ SELECT private.require_admin_write() $$, '42501', NULL,
                 'guard: write guard rejects a JWT-only admin (revocation is immediate)');

-- Grant it for real and the write path opens.
INSERT INTO private.user_roles (user_id, role, granted_by)
VALUES ('11111111-1111-1111-1111-111111111111', 'admin_role', 'test');

SELECT lives_ok($$ SELECT private.require_admin_write() $$,
                'guard: write guard accepts an admin whose grant exists in the DB');

-- ------------------------------------------------------------------------------
-- The guards themselves are not reachable from the client
-- ------------------------------------------------------------------------------
SELECT ok(
  NOT has_function_privilege('authenticated', 'private.require_admin_write()', 'EXECUTE'),
  'guard: authenticated cannot call the guards directly'
);

SELECT * FROM finish();
ROLLBACK;
