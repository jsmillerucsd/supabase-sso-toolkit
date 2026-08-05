/**
 * React entry point. Works in a browser SPA and in Next.js client components.
 */
"use client";

import type { Session, SupabaseClient } from "@supabase/supabase-js";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { handleAuthCallback, performLogout, signInWithSSO, type SignInOptions } from "../core/auth.js";
import { extractAppClaims, hasRole, type AppClaims } from "../core/claims.js";
import { resolveConfig, type ResolvedSsoConfig, type SsoConfig } from "../core/config.js";

export interface SsoContextValue {
  supabase: SupabaseClient;
  config: ResolvedSsoConfig;
  session: Session | null;
  /** null while loading or signed out. */
  claims: AppClaims | null;
  loading: boolean;
  /** The hook could not materialize claims; treat as no privileges and say so. */
  degraded: boolean;
  signIn(opts?: SignInOptions): Promise<void>;
  signOut(): Promise<void>;
}

const SsoContext = createContext<SsoContextValue | null>(null);

/**
 * Decodes claims from the access token locally.
 *
 * The session already carries the signed token, so re-deriving claims costs
 * nothing. Signature verification is the database's job on every request — this
 * value drives UI only.
 */
function claimsFromSession(session: Session | null): AppClaims | null {
  if (!session?.access_token) return null;
  try {
    const payload = session.access_token.split(".")[1];
    if (!payload) return null;
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    return extractAppClaims(JSON.parse(json) as Record<string, unknown>);
  } catch {
    return null;
  }
}

export function SsoProvider(props: {
  supabase: SupabaseClient;
  config: SsoConfig;
  children: ReactNode;
}): ReactNode {
  const { supabase, config, children } = props;
  const cfg = useMemo(() => resolveConfig(config), [config]);

  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;

    supabase.auth.getSession().then(({ data }) => {
      if (!active) return;
      setSession(data.session);
      setLoading(false);
    });

    const { data: sub } = supabase.auth.onAuthStateChange((_event, next) => {
      if (!active) return;
      setSession(next);
      setLoading(false);
    });

    return () => {
      active = false;
      sub.subscription.unsubscribe();
    };
  }, [supabase]);

  const claims = useMemo(() => claimsFromSession(session), [session]);

  const signIn = useCallback(
    async (opts?: SignInOptions) => {
      const { error } = await signInWithSSO(supabase, cfg, opts);
      if (error) throw error;
    },
    [supabase, cfg],
  );

  const signOut = useCallback(async () => {
    const returnUrl =
      typeof window !== "undefined"
        ? `${window.location.origin}${cfg.loginPath}`
        : cfg.loginPath;
    const idpUrl = await performLogout(supabase, cfg, returnUrl);
    if (typeof window !== "undefined") {
      window.location.assign(idpUrl ?? cfg.loginPath);
    }
  }, [supabase, cfg]);

  const value = useMemo<SsoContextValue>(
    () => ({
      supabase,
      config: cfg,
      session,
      claims,
      loading,
      degraded: claims?.app_claims_degraded ?? false,
      signIn,
      signOut,
    }),
    [supabase, cfg, session, claims, loading, signIn, signOut],
  );

  return <SsoContext.Provider value={value}>{children}</SsoContext.Provider>;
}

export function useSso(): SsoContextValue {
  const ctx = useContext(SsoContext);
  if (!ctx) throw new Error("useSso must be used inside <SsoProvider>");
  return ctx;
}

export function useAppClaims(): AppClaims | null {
  return useSso().claims;
}

/** False while loading — callers should not flash privileged UI before claims land. */
export function useHasRole(role: string): boolean {
  const { claims, loading } = useSso();
  return loading ? false : hasRole(claims, role);
}

/** Drop-in for the callback route in a SPA. */
export function AuthCallback(props: { children?: ReactNode }): ReactNode {
  const { supabase, config } = useSso();

  // Run-once guard: StrictMode double-invokes effects, and a second
  // exchangeCodeForSession burns the single-use PKCE code and fails the flow.
  const ran = useRef(false);
  useEffect(() => {
    if (ran.current) return;
    ran.current = true;
    void handleAuthCallback(supabase, config);
  }, [supabase, config]);

  return props.children ?? null;
}
