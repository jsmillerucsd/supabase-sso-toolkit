import type { SupabaseClient } from "@supabase/supabase-js";

/**
 * The claims this toolkit's auth hook injects at the JWT's top level.
 *
 * Read roles from here and nowhere else. `user_metadata` is client-writable via
 * `updateUser()`, so anything found there is an assertion by the user about
 * themselves, not by the server.
 */
export interface AppClaims {
  /** Effective roles, union of every configured grant source. */
  app_roles: string[];
  /** Department codes, leading zeros already stripped. */
  dept_codes_array: string[];
  /**
   * True when the hook could not materialize claims for this user and
   * deliberately emitted an empty role set rather than failing the sign-in.
   * Treat as "no privileges" and surface it — the user is not simply unprivileged,
   * something is broken.
   */
  app_claims_degraded: boolean;
}

export class SsoAuthError extends Error {
  constructor(
    message: string,
    public readonly code: "forbidden" | "unauthenticated" | "callback_failed",
  ) {
    super(message);
    this.name = "SsoAuthError";
  }
}

const asStringArray = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

/**
 * Pure extraction. Use when you already hold the claims, to avoid a redundant
 * `getClaims()` round trip.
 */
export function extractAppClaims(
  claims: Record<string, unknown> | null | undefined,
): AppClaims {
  return {
    app_roles: asStringArray(claims?.app_roles),
    dept_codes_array: asStringArray(claims?.dept_codes_array),
    app_claims_degraded: claims?.app_claims_degraded === true,
  };
}

/** Validates the JWT locally against the project's JWKS — no network round trip. */
export async function getAppClaims(supabase: SupabaseClient): Promise<AppClaims> {
  const { data } = await supabase.auth.getClaims();
  return extractAppClaims(data?.claims as Record<string, unknown> | undefined);
}

/** Every claim, for debug screens. */
export async function getAllClaims(
  supabase: SupabaseClient,
): Promise<Record<string, unknown>> {
  const { data } = await supabase.auth.getClaims();
  return (data?.claims as Record<string, unknown>) ?? {};
}

export function hasRole(claims: AppClaims | null | undefined, role: string): boolean {
  return claims?.app_roles.includes(role) ?? false;
}

export function hasAnyRole(
  claims: AppClaims | null | undefined,
  roles: readonly string[],
): boolean {
  return roles.some((r) => hasRole(claims, r));
}

export function hasDeptCode(claims: AppClaims | null | undefined, code: string): boolean {
  return claims?.dept_codes_array.includes(code.replace(/^0+/, "")) ?? false;
}

/**
 * Throws when the role is missing. For route handlers and server actions.
 *
 * This is a UI-level convenience, not a security boundary — the enforceable
 * check is the RLS policy in the database. A client that ignores this still
 * cannot read rows it has no policy for.
 */
export function requireRole(claims: AppClaims | null | undefined, role: string): void {
  if (!claims) throw new SsoAuthError("Not authenticated", "unauthenticated");
  if (!hasRole(claims, role)) {
    throw new SsoAuthError(`Missing required role: ${role}`, "forbidden");
  }
}
