-- ==============================================================================
-- 02_hook_contract — the auth hook must never break authentication
-- ==============================================================================
-- Covers spec tests 03 (required claims preserved), 04 (never raises),
-- 05 (single materialized read), 06 (JWT size), 07 (grants).
-- ==============================================================================
BEGIN;
CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA extensions;
SELECT plan(23);

SELECT sso_test.make_saml_user('11111111-1111-1111-1111-111111111111', 'hook@ucsd.edu');

-- ------------------------------------------------------------------------------
-- Spec 03: every required claim survives untouched
-- ------------------------------------------------------------------------------
-- Losing any of these fails authentication outright.
CREATE TEMP TABLE ev AS
SELECT sso_test.hook_event('11111111-1111-1111-1111-111111111111') AS event;

CREATE TEMP TABLE out AS
SELECT (SELECT event FROM ev) -> 'claims' AS before,
       private.custom_access_token_hook((SELECT event FROM ev)) -> 'claims' AS after;

SELECT is(
  (SELECT after -> k FROM out),
  (SELECT before -> k FROM out),
  format('hook preserves required claim: %s', k)
)
FROM unnest(ARRAY[
  'iss', 'aud', 'exp', 'iat', 'sub', 'role', 'aal', 'session_id',
  'email', 'phone', 'is_anonymous'
]) AS k;

-- ------------------------------------------------------------------------------
-- Spec 04: the hook never raises
-- ------------------------------------------------------------------------------
-- An exception here fails the auth request for that user. Degrade, never deny.
SELECT lives_ok(
  $$ SELECT private.custom_access_token_hook(
       sso_test.hook_event('99999999-9999-9999-9999-999999999999')) $$,
  'hook: lives when the user has no rows at all'
);

SELECT is(
  private.custom_access_token_hook(
    sso_test.hook_event('99999999-9999-9999-9999-999999999999')
  ) #> '{claims,app_roles}',
  '[]'::jsonb,
  'hook: unknown user gets an empty role set'
);

SELECT is(
  private.custom_access_token_hook(
    sso_test.hook_event('99999999-9999-9999-9999-999999999999')
  ) #> '{claims,app_claims_degraded}',
  'true'::jsonb,
  'hook: unknown user is flagged degraded so the app can surface it'
);

-- ------------------------------------------------------------------------------
-- Spec 05: the hook reads ONLY the materialized row
-- ------------------------------------------------------------------------------
-- Stops the hook quietly re-growing multi-query role logic inside the 2s budget.
INSERT INTO private.ad_group_role_mappings (ad_group_cn, role) VALUES ('App-Admins', 'admin_role');
UPDATE private.user_effective_claims
   SET app_roles = '{}'
 WHERE user_id = '11111111-1111-1111-1111-111111111111';

SELECT is(
  private.custom_access_token_hook(
    sso_test.hook_event('11111111-1111-1111-1111-111111111111')
  ) #> '{claims,app_roles}',
  '[]'::jsonb,
  'hook: mapping rows that WOULD grant a role are ignored until recomputed'
);

SELECT private.recompute_user_claims('11111111-1111-1111-1111-111111111111');

SELECT is(
  private.custom_access_token_hook(
    sso_test.hook_event('11111111-1111-1111-1111-111111111111')
  ) #> '{claims,app_roles}',
  '["admin_role"]'::jsonb,
  'hook: role appears once claims are recomputed'
);

-- ------------------------------------------------------------------------------
-- Spec 06: JWT payload stays small
-- ------------------------------------------------------------------------------
-- @supabase/ssr persists the session into cookies; an unbounded payload
-- overruns proxy header limits (the "431" failure in the predecessor project).
SELECT cmp_ok(
  octet_length(
    (private.custom_access_token_hook(
      sso_test.hook_event('11111111-1111-1111-1111-111111111111')
    ) -> 'claims')::text
  ),
  '<', 4096,
  'hook: emitted claims stay under a 4 KB budget'
);

-- ------------------------------------------------------------------------------
-- Spec 07: grants
-- ------------------------------------------------------------------------------
SELECT ok(
  has_function_privilege('supabase_auth_admin', 'private.custom_access_token_hook(jsonb)', 'EXECUTE'),
  'grants: supabase_auth_admin may execute the hook'
);
SELECT ok(
  has_table_privilege('supabase_auth_admin', 'private.user_effective_claims', 'SELECT'),
  'grants: supabase_auth_admin may read user_effective_claims'
);
SELECT ok(
  has_table_privilege('supabase_auth_admin', 'private.user_attributes', 'SELECT'),
  'grants: supabase_auth_admin may read user_attributes'
);
SELECT ok(
  NOT has_function_privilege('authenticated', 'private.custom_access_token_hook(jsonb)', 'EXECUTE'),
  'grants: authenticated may NOT execute the hook'
);
SELECT ok(
  NOT has_table_privilege('authenticated', 'private.user_attributes', 'SELECT'),
  'grants: authenticated has no direct read on user_attributes'
);
SELECT ok(
  NOT has_table_privilege('anon', 'private.user_effective_claims', 'SELECT'),
  'grants: anon has no direct read on user_effective_claims'
);

SELECT * FROM finish();
ROLLBACK;
