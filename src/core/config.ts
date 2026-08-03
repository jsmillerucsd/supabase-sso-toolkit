/**
 * Configuration for the SSO wiring. Everything has a default except the
 * provider identity itself.
 */
export interface SsoConfig {
  /**
   * SSO provider UUID from `supabase sso list` or the Management API.
   * Preferred over `domain` — it is unambiguous and survives domain changes.
   */
  providerId?: string;
  /** Email-domain routing, e.g. "ucsd.edu". Used when `providerId` is absent. */
  domain?: string;
  /** Path that receives the ACS redirect. Default "/auth/callback". */
  callbackPath?: string;
  /** Post-login destination. Default "/". */
  homePath?: string;
  /** Login page. Default "/login". */
  loginPath?: string;
  /**
   * IdP logout endpoint. SAML Single Logout is not supported by Supabase, so
   * signing out locally leaves the IdP session alive and the next sign-in is
   * silent. Redirecting here after `signOut()` is the closest available thing.
   */
  idpLogoutUrl?: string;
  /** Skip the SSO redirect entirely (local development). Default false. */
  localAuthMode?: boolean;
}

export interface ResolvedSsoConfig extends SsoConfig {
  callbackPath: string;
  homePath: string;
  loginPath: string;
  idpLogoutUrl: string;
  localAuthMode: boolean;
}

export const DEFAULT_CONFIG = {
  callbackPath: "/auth/callback",
  homePath: "/",
  loginPath: "/login",
  idpLogoutUrl: "https://a5.ucsd.edu/tritON/profile/Logout",
  localAuthMode: false,
} as const;

/**
 * Applies defaults and fails fast on a config that cannot produce a sign-in.
 * `localAuthMode` skips that check so local dev does not need a provider.
 */
export function resolveConfig(config: SsoConfig): ResolvedSsoConfig {
  const resolved: ResolvedSsoConfig = { ...DEFAULT_CONFIG, ...config };

  if (!resolved.localAuthMode && !resolved.providerId && !resolved.domain) {
    throw new Error(
      "[supabase-sso] SsoConfig requires either `providerId` or `domain`. " +
        "Get the provider UUID from `supabase sso list --project-ref <ref>`.",
    );
  }

  return resolved;
}

/**
 * Guards against open redirects on the `next` query parameter. Only same-origin
 * absolute paths pass; "//evil.example" is rejected because browsers treat it
 * as protocol-relative.
 */
export function safeRedirectPath(next: string | null | undefined, fallback: string): string {
  if (!next) return fallback;
  if (!next.startsWith("/")) return fallback;
  if (next.startsWith("//")) return fallback;
  return next;
}
