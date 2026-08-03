import type { SupabaseClient } from "@supabase/supabase-js";

/**
 * How much to trust `ad_group_cns`.
 *
 * `suspect_truncated` is the signature of supabase/auth#2332: a single AD group
 * with no delimiter, which is what a truncated multi-valued SAML attribute looks
 * like. The group we did receive is still valid — role derivation is additive,
 * so truncation can only under-grant.
 */
export type MemberOfStatus = "absent" | "empty" | "parsed" | "suspect_truncated";

/** The caller's own projected SSO attributes. */
export interface AttributeSummary {
  display_identifier: string | null;
  full_name: string | null;
  first_name: string | null;
  last_name: string | null;
  email: string | null;
  title: string | null;
  home_dept_code: string | null;
  home_dept_desc: string | null;
  dept_codes: string[];
  ad_group_cns: string[];
  member_of_status: MemberOfStatus;
  /** null means the IdP released no affiliation at all, not "none". */
  affiliations: string[] | null;
  source_kind: "saml" | "legacy_oauth";
  synced_at: string;
}

/**
 * Reads the caller's projected attributes — the trusted copy, taken from
 * `auth.identities` at sign-in, not from client-writable `user_metadata`.
 */
export async function getMyAttributes(
  supabase: SupabaseClient,
): Promise<AttributeSummary | null> {
  const { data, error } = await supabase.rpc("get_my_attribute_summary");
  if (error) throw error;
  if (!data || Object.keys(data as object).length === 0) return null;
  return data as AttributeSummary;
}

/**
 * AD group CNs for the caller.
 *
 * These deliberately never ride in the JWT — the list can be large and the
 * session cookie has a hard size ceiling. This is a live database read.
 */
export async function getMyAdGroups(supabase: SupabaseClient): Promise<string[]> {
  const { data, error } = await supabase.rpc("get_my_ad_groups");
  if (error) throw error;
  return (data as string[] | null) ?? [];
}
