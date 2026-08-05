/**
 * Next.js App Router entry point.
 *
 * Server-only: imports `next/server` and `@supabase/ssr`. Do not import this
 * from a client component.
 */
import { createServerClient, parseCookieHeader } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";
import { extractAppClaims, type AppClaims } from "../core/claims.js";
import { performLogout } from "../core/auth.js";
import { resolveConfig, safeRedirectPath, type SsoConfig } from "../core/config.js";

/** What @supabase/ssr hands back when it wants cookies written. */
type CookiesToSet = {
  name: string;
  value: string;
  options?: Record<string, unknown>;
}[];

export interface NextSsoEnv {
  supabaseUrl: string;
  /** Publishable (or legacy anon) key. Never the secret key — this reaches the browser. */
  supabasePublishableKey: string;
  /**
   * Canonical public origin, e.g. "https://myapp.ucsd.edu". Strongly
   * recommended: when set, post-auth redirects use it instead of trusting the
   * request's x-forwarded-host header, which is client-controllable on
   * deployments without a normalizing proxy (open-redirect vector).
   */
  siteUrl?: string;
}

/**
 * Middleware body: refreshes the session cookie and redirects signed-out users
 * to the login page.
 *
 * Cookie mutations must be written onto whichever response is actually returned,
 * including redirects — otherwise a refreshed token is silently dropped and the
 * user bounces on the next request.
 */
export async function updateSession(
  request: NextRequest,
  env: NextSsoEnv,
  config: SsoConfig,
): Promise<NextResponse> {
  const path = request.nextUrl.pathname;

  // Static assets never need a session refresh; skip the client + JWT work.
  if (path.startsWith("/_next") || path === "/favicon.ico") {
    return NextResponse.next({ request });
  }

  const cfg = resolveConfig(config);
  let response = NextResponse.next({ request });

  const supabase = createServerClient(env.supabaseUrl, env.supabasePublishableKey, {
    cookies: {
      getAll: () => request.cookies.getAll(),
      setAll: (cookiesToSet: CookiesToSet) => {
        for (const { name, value } of cookiesToSet) request.cookies.set(name, value);
        response = NextResponse.next({ request });
        for (const { name, value, options } of cookiesToSet) {
          response.cookies.set(name, value, options);
        }
      },
    },
  });

  const { data } = await supabase.auth.getClaims();
  const claims = data?.claims as Record<string, unknown> | undefined;

  // Segment-exact matching: "/authors" or "/login-admin" must NOT be public.
  const isPublic =
    path === "/auth" ||
    path.startsWith("/auth/") ||
    path === cfg.loginPath ||
    path.startsWith(`${cfg.loginPath}/`);

  if (!claims && !isPublic && !cfg.localAuthMode) {
    const url = request.nextUrl.clone();
    url.pathname = cfg.loginPath;
    url.search = "";
    url.searchParams.set("next", `${path}${request.nextUrl.search}`);
    const redirect = NextResponse.redirect(url);
    for (const cookie of response.cookies.getAll()) redirect.cookies.set(cookie);
    return redirect;
  }

  return response;
}

/**
 * Factory for `app/auth/callback/route.ts`.
 *
 * Exchanges the PKCE code server-side. No attribute sync step: with direct SAML
 * the attributes are already in `auth.identities` by the time this runs, and the
 * database trigger has projected them.
 */
export function createSsoCallbackHandler(env: NextSsoEnv, config: SsoConfig) {
  const cfg = resolveConfig(config);

  return async function GET(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const forwardedHost = request.headers.get("x-forwarded-host");
    const origin =
      env.siteUrl?.replace(/\/$/, "") ??
      (forwardedHost ? `https://${forwardedHost}` : url.origin);

    const fail = (reason: string) =>
      NextResponse.redirect(`${origin}${cfg.loginPath}?error=${encodeURIComponent(reason)}`);

    const errorDescription =
      url.searchParams.get("error_description") ?? url.searchParams.get("error");
    if (errorDescription) return fail(errorDescription);

    const code = url.searchParams.get("code");
    if (!code) return fail("missing_code");

    const next = safeRedirectPath(url.searchParams.get("next"), cfg.homePath);
    const response = NextResponse.redirect(`${origin}${next}`);

    const supabase = supabaseForRequest(request, response, env);

    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (error) return fail(error.message);

    return response;
  };
}

/** Server-side claims for Server Components and route handlers. */
export async function getServerAppClaims(
  cookieStore: { getAll: () => { name: string; value: string }[] },
  env: NextSsoEnv,
): Promise<AppClaims> {
  const supabase = createServerClient(env.supabaseUrl, env.supabasePublishableKey, {
    cookies: {
      getAll: () => cookieStore.getAll(),
      // Server Components cannot set cookies; middleware owns refresh.
      setAll: () => undefined,
    },
  });
  const { data } = await supabase.auth.getClaims();
  return extractAppClaims(data?.claims as Record<string, unknown> | undefined);
}

/** Route-handler logout: clears the session, then hops through the IdP. */
export function createLogoutHandler(env: NextSsoEnv, config: SsoConfig) {
  const cfg = resolveConfig(config);

  return async function POST(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const origin = env.siteUrl?.replace(/\/$/, "") ?? url.origin;
    const response = NextResponse.redirect(`${origin}${cfg.loginPath}`, { status: 303 });

    const supabase = supabaseForRequest(request, response, env);

    const idpUrl = await performLogout(supabase, cfg, `${origin}${cfg.loginPath}`);
    if (!idpUrl) return response;

    const redirect = NextResponse.redirect(idpUrl, { status: 303 });
    for (const cookie of response.cookies.getAll()) redirect.cookies.set(cookie);
    return redirect;
  };
}

/** Client for a plain Request whose cookie writes land on `response`. */
function supabaseForRequest(request: Request, response: NextResponse, env: NextSsoEnv) {
  return createServerClient(env.supabaseUrl, env.supabasePublishableKey, {
    cookies: {
      getAll: () => {
        const header = request.headers.get("cookie");
        if (!header) return [];
        return parseCookieHeader(header).map(({ name, value }) => ({
          name,
          value: value ?? "",
        }));
      },
      setAll: (cookiesToSet: CookiesToSet) => {
        for (const { name, value, options } of cookiesToSet) {
          response.cookies.set(name, value, options);
        }
      },
    },
  });
}
