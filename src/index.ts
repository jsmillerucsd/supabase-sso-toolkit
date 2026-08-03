/**
 * @ucsd/supabase-sso — SAML SSO attribute + RLS wiring for Supabase projects.
 *
 * Isomorphic core. Framework entry points live at `/nextjs` and `/react`.
 */

export {
  DEFAULT_CONFIG,
  resolveConfig,
  safeRedirectPath,
  type ResolvedSsoConfig,
  type SsoConfig,
} from "./core/config.js";

export {
  SsoAuthError,
  extractAppClaims,
  getAllClaims,
  getAppClaims,
  hasAnyRole,
  hasDeptCode,
  hasRole,
  requireRole,
  type AppClaims,
} from "./core/claims.js";

export {
  buildLogoutUrl,
  handleAuthCallback,
  performLogout,
  signInWithSSO,
  type SignInOptions,
} from "./core/auth.js";

export {
  getMyAdGroups,
  getMyAttributes,
  type AttributeSummary,
  type MemberOfStatus,
} from "./core/attributes.js";
