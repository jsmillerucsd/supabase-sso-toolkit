import type { AuthError, Session, SupabaseClient } from "@supabase/supabase-js";
import { resolveConfig, safeRedirectPath, type SsoConfig } from "./config.js";

export interface SignInOptions {
  /** Absolute URL the IdP should return to. Defaults to origin + callbackPath. */
  redirectTo?: string;
  /** Return the URL instead of navigating. No effect outside a browser. */
  skipBrowserRedirect?: boolean;
}

/**
 * Starts a SAML sign-in.
 *
 * Thin wrapper over `signInWithSSO` that applies the resolved config and
 * performs the navigation, so callers do not each reimplement the
 * "returns a URL you must redirect to" contract.
 */
export async function signInWithSSO(
  supabase: SupabaseClient,
  config: SsoConfig,
  opts: SignInOptions = {},
): Promise<{ url: string | null; error: AuthError | null }> {
  const cfg = resolveConfig(config);

  if (!cfg.providerId && !cfg.domain) {
    // Only reachable in localAuthMode (resolveConfig enforces it otherwise).
    throw new Error(
      "[supabase-sso] signInWithSSO needs `providerId` or `domain`; " +
        "in localAuthMode use your local sign-in path instead.",
    );
  }

  const redirectTo =
    opts.redirectTo ??
    (typeof window !== "undefined"
      ? `${window.location.origin}${cfg.callbackPath}`
      : undefined);

  const params = cfg.providerId
    ? { providerId: cfg.providerId, options: { redirectTo } }
    : { domain: cfg.domain as string, options: { redirectTo } };

  const { data, error } = await supabase.auth.signInWithSSO(params);
  if (error) return { url: null, error };

  const url = data?.url ?? null;
  if (url && !opts.skipBrowserRedirect && typeof window !== "undefined") {
    window.location.assign(url);
  }
  return { url, error: null };
}

/**
 * Browser-side callback handler for SPAs.
 *
 * Handles both redirect shapes, because which one arrives depends on the
 * client's configured flow type: `?code=` (PKCE, exchanged explicitly) and
 * `#access_token=` (implicit, picked up by supabase-js `detectSessionInUrl`).
 * Keeping both means the same code works either way.
 *
 * Never throws — on failure it signs out and returns to the login page with an
 * error flag, because an exception here strands the user on a blank callback route.
 */
export async function handleAuthCallback(
  supabase: SupabaseClient,
  config: SsoConfig,
): Promise<void> {
  const cfg = resolveConfig(config);

  const goto = (path: string) => {
    if (typeof window !== "undefined") window.location.replace(path);
  };

  try {
    const url = new URL(window.location.href);
    const errorDescription =
      url.searchParams.get("error_description") ?? url.searchParams.get("error");
    if (errorDescription) {
      goto(`${cfg.loginPath}?error=${encodeURIComponent(errorDescription)}`);
      return;
    }

    const code = url.searchParams.get("code");
    if (code) {
      const { error } = await supabase.auth.exchangeCodeForSession(code);
      if (error) throw error;
    } else {
      // Implicit flow: supabase-js parses the fragment asynchronously on load.
      // Wait for the auth event rather than racing it with a fixed delay.
      const session = await waitForSession(supabase, 5000);
      if (!session) throw new Error("No session established from callback");
    }

    goto(safeRedirectPath(url.searchParams.get("next"), cfg.homePath));
  } catch (err) {
    await supabase.auth.signOut({ scope: "local" }).catch(() => undefined);
    const message = err instanceof Error ? err.message : "callback_failed";
    goto(`${cfg.loginPath}?error=${encodeURIComponent(message)}`);
  }
}

/** Resolves with the session as soon as supabase-js emits one, or null on timeout. */
async function waitForSession(
  supabase: SupabaseClient,
  timeoutMs: number,
): Promise<Session | null> {
  const { data } = await supabase.auth.getSession();
  if (data.session) return data.session;

  return new Promise<Session | null>((resolve) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (session: Session | null) => {
      clearTimeout(timer);
      sub.subscription.unsubscribe();
      resolve(session);
    };
    const { data: sub } = supabase.auth.onAuthStateChange((_event, session) => {
      if (session) finish(session);
    });
    timer = setTimeout(() => finish(null), timeoutMs);
  });
}

/**
 * Builds the IdP logout URL.
 *
 * Supabase does not support SAML Single Logout, so `signOut()` alone leaves the
 * campus session intact and the next sign-in completes silently — which looks
 * like logout being broken. Redirecting through the IdP is the mitigation.
 */
export function buildLogoutUrl(config: SsoConfig, returnUrl: string): string {
  const cfg = resolveConfig(config);
  const sep = cfg.idpLogoutUrl.includes("?") ? "&" : "?";
  return `${cfg.idpLogoutUrl}${sep}return=${encodeURIComponent(returnUrl)}`;
}

/**
 * Signs out locally, then returns the IdP logout URL to navigate to
 * (or null in localAuthMode). Never rejects — a failed local sign-out must not
 * prevent the IdP hop.
 */
export async function performLogout(
  supabase: SupabaseClient,
  config: SsoConfig,
  returnUrl: string,
): Promise<string | null> {
  const cfg = resolveConfig(config);
  await supabase.auth.signOut({ scope: "local" }).catch(() => undefined);
  return cfg.localAuthMode ? null : buildLogoutUrl(cfg, returnUrl);
}
