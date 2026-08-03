-- ==============================================================================
-- @ucsd/supabase-sso — 0006_ucsd_adapter  [OPTIONAL CAMPUS ADAPTER]
-- ==============================================================================
-- UCSD Shibboleth attribute extraction. This is the ONLY file in the toolkit
-- that knows about UCSD-specific attributes (dept codes, UCPath emplids, AD
-- groups, UCnetID). Everything else is campus-agnostic.
--
-- It works by CREATE OR REPLACEing private.extract_attributes() — the seam that
-- 0002 defines. Another campus writes its own adapter module and skips this one.
--
-- WHERE THE ATTRIBUTES LIVE:
--   SAML branch:   standard keys at the top level of identity_data
--                  (sub, email, name, ...); every UCSD attribute nests under
--                  identity_data.custom_claims. Confirmed against live data.
--   Legacy branch: the retired attribute-sync flattened custom_claims to the top
--                  level of raw_app_meta_data, so there is no nesting to unwrap.
--
-- Depends on: 0002 (0004 optional)
-- ==============================================================================

CREATE OR REPLACE FUNCTION private.extract_attributes(
  p_source_kind text,
  p_payload     jsonb
)
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
  IF p_source_kind = 'saml' THEN
    cc  := COALESCE(p_payload -> 'custom_claims', '{}'::jsonb);
    src := COALESCE(p_payload, '{}'::jsonb);
  ELSIF p_source_kind = 'legacy_oauth' THEN
    cc  := COALESCE(p_payload, '{}'::jsonb);
    src := COALESCE(p_payload, '{}'::jsonb);
  ELSE
    RAISE EXCEPTION 'unknown source_kind %', p_source_kind;
  END IF;

  r.subject_id  := src ->> 'sub';
  r.eppn        := NULLIF(cc ->> 'eppn', '');
  r.ad_username := NULLIF(cc ->> 'ad_username', '');
  r.ucnet_id    := NULLIF(cc ->> 'ucnet_id', '');
  r.email       := COALESCE(NULLIF(src ->> 'email', ''), NULLIF(cc ->> 'mail', ''));

  r.full_name   := COALESCE(NULLIF(cc ->> 'full_name', ''),  NULLIF(src ->> 'name', ''));
  r.first_name  := COALESCE(NULLIF(cc ->> 'first_name', ''), NULLIF(src ->> 'given_name', ''));
  r.last_name   := COALESCE(NULLIF(cc ->> 'last_name', ''),  NULLIF(src ->> 'family_name', ''));
  r.title       := NULLIF(cc ->> 'title', '');

  -- Department codes are stored canonically un-padded. The IdP sends them
  -- zero-padded ("0578"); downstream lookup tables use "578". Normalizing here,
  -- once, is what keeps every consumer from having to remember to do it.
  r.home_dept_code := NULLIF(ltrim(COALESCE(cc ->> 'home_dept_code', ''), '0'), '');
  r.home_dept_desc := NULLIF(cc ->> 'home_dept_desc', '');
  r.dept_codes     := private.parse_multi(cc -> 'dept_codes', ',', true);
  r.dept_names     := private.parse_multi(cc -> 'dept_names', ',', false);

  -- NULL (not released) vs '{}' (released and empty) is a meaningful distinction
  -- here: the campus IdP does not currently release eduPersonAffiliation at all,
  -- so this column is NULL for every user until that changes.
  r.affiliations := CASE
    WHEN cc ? 'affiliation' THEN private.parse_multi(cc -> 'affiliation', ';', false)
    ELSE NULL
  END;

  SELECT c.raw, c.cns, c.status
    INTO r.member_of_raw, r.ad_group_cns, r.member_of_status
    FROM private.classify_member_of(cc -> 'member_of') c;

  r.ucpath_emplid   := NULLIF(cc ->> 'ucpath_emplid', '');
  r.pid             := NULLIF(cc ->> 'pid', '');
  r.employee_status := NULLIF(cc ->> 'employee_status', '');

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
      PERFORM private.project_user_attributes(r.user_id, 'saml', r.identity_data);
    EXCEPTION WHEN OTHERS THEN
      INSERT INTO private.sync_errors (user_id, source, detail, payload)
      VALUES (r.user_id, 'projection_trigger', 'ucsd adapter reproject: ' || SQLERRM, r.identity_data);
    END;
  END LOOP;

  FOR r IN
    SELECT u.id AS user_id, u.raw_app_meta_data
    FROM auth.users u
    WHERE COALESCE(u.is_sso_user, false) = false
      AND u.raw_app_meta_data ->> 'provider' = 'custom:ucsd-sso'
      AND NOT EXISTS (
        SELECT 1 FROM private.user_attributes ua
        WHERE ua.user_id = u.id AND ua.source_kind = 'saml'
      )
  LOOP
    BEGIN
      PERFORM private.project_user_attributes(r.user_id, 'legacy_oauth', r.raw_app_meta_data);
    EXCEPTION WHEN OTHERS THEN
      INSERT INTO private.sync_errors (user_id, source, detail, payload)
      VALUES (r.user_id, 'legacy_trigger', 'ucsd adapter reproject: ' || SQLERRM, r.raw_app_meta_data);
    END;
  END LOOP;
END;
$$;

SELECT private.recompute_all_user_claims();

SELECT private.register_module('0006_ucsd_adapter', '1.0.0');
