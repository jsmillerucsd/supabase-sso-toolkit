-- ==============================================================================
-- @jsmillerucsd/supabase-sso — 0006_ucsd_adapter  [OPTIONAL CAMPUS ADAPTER]
-- ==============================================================================
-- UCSD Shibboleth attribute extraction. This is the ONLY file in the toolkit
-- that knows about UCSD-specific attributes (dept codes, UCPath emplids, AD
-- groups, UCnetID). Everything else is campus-agnostic.
--
-- It works by CREATE OR REPLACEing private.extract_attributes(): the seam that
-- 0002 defines. Another campus writes its own adapter module and skips this one.
--
-- Standard keys live at the top level of identity_data (sub, email, name, ...);
-- every UCSD attribute nests under identity_data.custom_claims.
--
-- Depends on: 0002 (0004 optional)
-- ==============================================================================

CREATE OR REPLACE FUNCTION private.extract_attributes(p_payload jsonb)
RETURNS private.user_attributes
LANGUAGE plpgsql
STABLE
SET search_path = ''
AS $$
DECLARE
  r   private.user_attributes;
  cc  jsonb;   -- where UCSD attributes live
  src jsonb;   -- where standard keys live
BEGIN
  cc  := COALESCE(p_payload -> 'custom_claims', '{}'::jsonb);
  src := COALESCE(p_payload, '{}'::jsonb);

  r.eppn        := NULLIF(cc ->> 'eppn', '');
  r.ad_username := NULLIF(cc ->> 'ad_username', '');
  r.ucnet_id    := NULLIF(cc ->> 'ucnet_id', '');
  r.email       := COALESCE(NULLIF(src ->> 'email', ''), NULLIF(cc ->> 'mail', ''));

  r.full_name   := COALESCE(NULLIF(cc ->> 'full_name', ''),  NULLIF(src ->> 'name', ''));
  r.first_name  := COALESCE(NULLIF(cc ->> 'first_name', ''), NULLIF(src ->> 'given_name', ''));
  r.last_name   := COALESCE(NULLIF(cc ->> 'last_name', ''),  NULLIF(src ->> 'family_name', ''));
  r.title       := NULLIF(cc ->> 'title', '');

  -- Department codes are stored un-padded. The IdP sends them zero-padded
  -- ("0578"); downstream lookup tables use "578".
  r.home_dept_code := NULLIF(ltrim(COALESCE(cc ->> 'home_dept_code', ''), '0'), '');
  r.home_dept_desc := NULLIF(cc ->> 'home_dept_desc', '');
  r.dept_codes     := private.parse_multi(cc -> 'dept_codes', ',', true);

  SELECT c.cns, c.status
    INTO r.ad_group_cns, r.member_of_status
    FROM private.classify_member_of(cc -> 'member_of') c;

  r.ucpath_emplid := NULLIF(cc ->> 'ucpath_emplid', '');

  r.display_identifier := private.derive_display_identifier(
    r.eppn, r.ad_username, r.ucnet_id, r.email
  );

  r.raw := p_payload;
  RETURN r;
END;
$$;

-- ------------------------------------------------------------------------------
-- Re-project everything so existing rows pick up UCSD extraction
-- ------------------------------------------------------------------------------
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT i.user_id, i.identity_data
    FROM auth.identities i
    WHERE i.provider LIKE 'sso:%'
  LOOP
    BEGIN
      PERFORM private.project_user_attributes(r.user_id, r.identity_data);
    EXCEPTION WHEN OTHERS THEN
      INSERT INTO private.sync_errors (user_id, source, detail, payload)
      VALUES (r.user_id, 'projection_trigger', 'ucsd adapter reproject: ' || SQLERRM, r.identity_data);
    END;
  END LOOP;
END;
$$;

SELECT private.recompute_all_user_claims();

SELECT private.register_module('0006_ucsd_adapter', '1.0.0');
