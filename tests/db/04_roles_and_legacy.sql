-- ==============================================================================
-- 04_roles_and_legacy — role derivation and the transition branch
-- ==============================================================================
-- Covers spec tests 12 (legacy branch), 13 (four-source union), 14 (mapping
-- change recomputes), 15 (AD groups additive-only under truncation).
-- ==============================================================================
BEGIN;
CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA extensions;
SELECT plan(13);

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

-- ------------------------------------------------------------------------------
-- Spec 12: legacy OAuth branch, and the flip to SAML on migration
-- ------------------------------------------------------------------------------
SELECT sso_test.make_legacy_user('44444444-4444-4444-4444-444444444444', 'legacy@ucsd.edu');

SELECT is(
  (SELECT source_kind FROM private.user_attributes
    WHERE user_id = '44444444-4444-4444-4444-444444444444'),
  'legacy_oauth',
  'legacy: user provisioned by the old OAuth server is projected'
);

SELECT is(
  (SELECT home_dept_code FROM private.user_attributes
    WHERE user_id = '44444444-4444-4444-4444-444444444444'),
  '578',
  'legacy: attributes read from raw_app_meta_data (flat, no custom_claims nesting)'
);

SELECT is(
  (SELECT ucpath_emplid FROM private.user_attributes
    WHERE user_id = '44444444-4444-4444-4444-444444444444'),
  '10099999',
  'legacy: emplid extracted from the legacy shape'
);

-- Same human signs in through direct SAML for the first time.
INSERT INTO auth.identities (id, user_id, provider_id, provider, identity_data, created_at, updated_at, last_sign_in_at)
VALUES (gen_random_uuid(), '44444444-4444-4444-4444-444444444444', 'legacy@ucsd.edu',
        'sso:f063d234-1eac-425c-846c-833176a050c7',
        jsonb_build_object('sub', 'opaque-32-char-id', 'email', 'legacy@ucsd.edu',
          'custom_claims', jsonb_build_object(
            'eppn', 'legacy@ucsd.edu', 'ad_username', 'legacy',
            'home_dept_code', '0111', 'ucpath_emplid', '10099999')),
        now(), now(), now());

SELECT is(
  (SELECT source_kind FROM private.user_attributes
    WHERE user_id = '44444444-4444-4444-4444-444444444444'),
  'saml',
  'legacy: source_kind flips to saml once a SAML identity exists'
);

SELECT is(
  (SELECT home_dept_code FROM private.user_attributes
    WHERE user_id = '44444444-4444-4444-4444-444444444444'),
  '111',
  'legacy: SAML values win outright — no COALESCE shadowing from the old shape'
);

SELECT is(
  (SELECT subject_id FROM private.user_attributes
    WHERE user_id = '44444444-4444-4444-4444-444444444444'),
  'opaque-32-char-id',
  'legacy: an opaque NameID is stored verbatim and changes nothing else'
);

SELECT * FROM finish();
ROLLBACK;
