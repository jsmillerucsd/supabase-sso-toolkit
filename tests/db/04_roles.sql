-- ==============================================================================
-- 04_roles — role derivation
-- ==============================================================================
-- Covers spec tests 13 (four-source union), 14 (mapping change recomputes),
-- 15 (AD groups additive-only under truncation).
-- ==============================================================================
BEGIN;
CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA extensions;
SELECT plan(7);

INSERT INTO private.app_roles (role, description) VALUES
  ('reader_role', 'test'), ('dept_role', 'test'), ('emplid_role', 'test')
ON CONFLICT (role) DO NOTHING;

-- ------------------------------------------------------------------------------
-- Spec 13: app_roles is the union of all four grant sources
-- ------------------------------------------------------------------------------
SELECT sso_test.make_saml_user('11111111-1111-1111-1111-111111111111', 'union@ucsd.edu');

INSERT INTO private.user_roles (user_id, role, granted_by)
VALUES ('11111111-1111-1111-1111-111111111111', 'reader_role', 'test');
INSERT INTO private.ad_group_role_mappings (ad_group_cn, role) VALUES ('App-Admins', 'admin_role');
INSERT INTO private.emplid_role_mappings (ucpath_emplid, role) VALUES ('10012345', 'emplid_role');
INSERT INTO private.dept_code_role_mappings (dept_code, role) VALUES ('578', 'dept_role');

SELECT private.recompute_user_claims('11111111-1111-1111-1111-111111111111');

SELECT set_eq(
  $$ SELECT unnest(app_roles) FROM private.user_effective_claims
     WHERE user_id = '11111111-1111-1111-1111-111111111111' $$,
  ARRAY['reader_role', 'admin_role', 'emplid_role', 'dept_role'],
  'roles: union of manual + AD group + emplid + dept sources'
);

-- Expiry is honored.
UPDATE private.user_roles SET expires_at = now() - interval '1 day'
 WHERE user_id = '11111111-1111-1111-1111-111111111111' AND role = 'reader_role';
SELECT private.recompute_user_claims('11111111-1111-1111-1111-111111111111');

SELECT ok(
  NOT (COALESCE((SELECT 'reader_role' = ANY (ec.app_roles)
            FROM private.user_effective_claims ec
           WHERE ec.user_id = '11111111-1111-1111-1111-111111111111'), false)),
  'roles: an expired manual grant is dropped on recompute'
);

-- ------------------------------------------------------------------------------
-- Spec 14: editing a mapping recomputes affected users automatically
-- ------------------------------------------------------------------------------
SELECT sso_test.make_saml_user('22222222-2222-2222-2222-222222222222', 'auto@ucsd.edu');

INSERT INTO private.app_roles (role, description) VALUES ('auto_role', 'test')
ON CONFLICT (role) DO NOTHING;

SELECT ok(
  NOT (COALESCE((SELECT 'auto_role' = ANY (ec.app_roles)
            FROM private.user_effective_claims ec
           WHERE ec.user_id = '22222222-2222-2222-2222-222222222222'), false)),
  'roles: role absent before the mapping exists'
);

INSERT INTO private.ad_group_role_mappings (ad_group_cn, role) VALUES ('App-Admins', 'auto_role');

SELECT ok(
  COALESCE((SELECT 'auto_role' = ANY (ec.app_roles)
            FROM private.user_effective_claims ec
           WHERE ec.user_id = '22222222-2222-2222-2222-222222222222'), false),
  'roles: inserting a mapping recomputes without a manual call'
);

DELETE FROM private.ad_group_role_mappings WHERE ad_group_cn = 'App-Admins' AND role = 'auto_role';

SELECT ok(
  NOT (COALESCE((SELECT 'auto_role' = ANY (ec.app_roles)
            FROM private.user_effective_claims ec
           WHERE ec.user_id = '22222222-2222-2222-2222-222222222222'), false)),
  'roles: deleting a mapping revokes on recompute'
);

-- ------------------------------------------------------------------------------
-- Spec 15: truncated AD group data still grants what it can (additive-only)
-- ------------------------------------------------------------------------------
-- The policy decision: a truncated list under-grants, so applying it is safe.
-- Disabling AD mapping entirely would be a bigger behavior change than the bug.
SELECT is(
  (SELECT member_of_status FROM private.user_attributes
    WHERE user_id = '22222222-2222-2222-2222-222222222222'),
  'suspect_truncated',
  'degraded: single-group member_of is flagged suspect_truncated'
);

SELECT ok(
  COALESCE((SELECT 'admin_role' = ANY (ec.app_roles)
            FROM private.user_effective_claims ec
           WHERE ec.user_id = '22222222-2222-2222-2222-222222222222'), false),
  'degraded: the one CN we did receive still grants its role'
);

SELECT * FROM finish();
ROLLBACK;
