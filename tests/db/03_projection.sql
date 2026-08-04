-- ==============================================================================
-- 03_projection — attribute extraction and the fail-open policy
-- ==============================================================================
-- Covers spec tests 08 (wholesale replace), 09 (fail-open), 10 (member_of
-- classification), 11 (display identifier chain).
-- ==============================================================================
BEGIN;
CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA extensions;
SELECT plan(17);

-- ------------------------------------------------------------------------------
-- Spec 08: projection REPLACES, it does not merge
-- ------------------------------------------------------------------------------
-- Mirrors identity_data's own replace semantics. Merging is the ratchet that
-- makes revocation impossible.
SELECT sso_test.make_saml_user('11111111-1111-1111-1111-111111111111', 'a@ucsd.edu');

SELECT is(
  (SELECT title FROM private.user_attributes WHERE user_id = '11111111-1111-1111-1111-111111111111'),
  'Analyst',
  'projection: title populated on first sign-in'
);

UPDATE auth.identities
   SET identity_data = jsonb_build_object(
     'sub', 'a@ucsd.edu', 'email', 'a@ucsd.edu',
     'custom_claims', jsonb_build_object(
       'eppn', 'a@ucsd.edu', 'ad_username', 'a',
       'home_dept_code', '0999', 'dept_codes', '0999'
     ))
 WHERE user_id = '11111111-1111-1111-1111-111111111111';

SELECT is(
  (SELECT title FROM private.user_attributes WHERE user_id = '11111111-1111-1111-1111-111111111111'),
  NULL,
  'projection: attribute dropped by the IdP is cleared, not retained'
);
SELECT is(
  (SELECT home_dept_code FROM private.user_attributes WHERE user_id = '11111111-1111-1111-1111-111111111111'),
  '999',
  'projection: changed attribute is updated'
);
SELECT is(
  (SELECT ucpath_emplid FROM private.user_attributes WHERE user_id = '11111111-1111-1111-1111-111111111111'),
  NULL,
  'projection: removed emplid is cleared (no key-wise retention)'
);

-- ------------------------------------------------------------------------------
-- Spec 09: fail-open — a projection defect must not break sign-in
-- ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION private.extract_attributes(p_source_kind text, p_payload jsonb)
RETURNS private.user_attributes
LANGUAGE plpgsql STABLE SET search_path = ''
AS $$ BEGIN RAISE EXCEPTION 'simulated extraction defect'; END; $$;

SELECT lives_ok(
  $$ SELECT sso_test.make_saml_user('33333333-3333-3333-3333-333333333333', 'failopen@ucsd.edu') $$,
  'fail-open: sign-in survives an extraction defect'
);

SELECT cmp_ok(
  (SELECT count(*)::int FROM private.sync_errors
    WHERE user_id = '33333333-3333-3333-3333-333333333333'
      AND source = 'projection_trigger'),
  '>=', 1,
  'fail-open: the defect is recorded in sync_errors'
);

-- The hook must then deprivilege this user rather than deny them.
SELECT is(
  private.custom_access_token_hook(
    sso_test.hook_event('33333333-3333-3333-3333-333333333333')
  ) #> '{claims,app_roles}',
  '[]'::jsonb,
  'fail-open: a user with no projection gets zero roles, not an error'
);

-- ------------------------------------------------------------------------------
-- Spec 10: member_of classification
-- ------------------------------------------------------------------------------
SELECT is((SELECT status FROM private.classify_member_of(NULL)), 'absent',
          'classify: missing key => absent');
SELECT is((SELECT status FROM private.classify_member_of('""'::jsonb)), 'empty',
          'classify: empty string => empty');
SELECT is((SELECT status FROM private.classify_member_of('"CN=A,OU=x;CN=B,OU=y"'::jsonb)), 'parsed',
          'classify: semicolon-delimited => parsed');
SELECT is((SELECT cns FROM private.classify_member_of('"CN=A,OU=x;CN=B,OU=y"'::jsonb)), ARRAY['A','B'],
          'classify: both CNs extracted from a delimited string');
SELECT is((SELECT status FROM private.classify_member_of('["CN=A,OU=x","CN=B,OU=y","CN=C,OU=z"]'::jsonb)), 'parsed',
          'classify: JSON array of 3 => parsed (array:true mapping worked)');
SELECT is((SELECT cns FROM private.classify_member_of('["CN=A,OU=x","CN=B,OU=y","CN=C,OU=z"]'::jsonb)), ARRAY['A','B','C'],
          'classify: all CNs extracted from an array');
SELECT is((SELECT status FROM private.classify_member_of('"CN=OnlyOne,OU=x"'::jsonb)), 'suspect_truncated',
          'classify: single value with no delimiter => suspect_truncated');
SELECT is((SELECT cns FROM private.classify_member_of('"CN=OnlyOne,OU=x"'::jsonb)), ARRAY['OnlyOne'],
          'classify: the one CN is still usable when truncation is suspected');

-- ------------------------------------------------------------------------------
-- Spec 11: display identifier survives the IdP going opaque
-- ------------------------------------------------------------------------------
SELECT is(private.derive_display_identifier('jdoe@ucsd.edu', 'jdoe', 'jdoe-uc', 'jdoe@ucsd.edu'),
          'jdoe@ucsd.edu', 'display: scoped eppn wins');
SELECT is(private.derive_display_identifier('abcdef0123456789abcdef0123456789', 'jdoe', 'jdoe-uc', 'j@ucsd.edu'),
          'jdoe', 'display: 32-char opaque eppn falls through to ad_username');
SELECT is(private.derive_display_identifier(NULL, NULL, 'jdoe-uc', 'j@ucsd.edu'),
          'jdoe-uc', 'display: falls through to ucnet_id');
SELECT is(private.derive_display_identifier(NULL, NULL, NULL, 'j@ucsd.edu'),
          'j@ucsd.edu', 'display: falls through to email as last resort');

SELECT * FROM finish();
ROLLBACK;
