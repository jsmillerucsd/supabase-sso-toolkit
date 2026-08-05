# @jsmillerucsd/supabase-sso — agent guide

Read this before writing code that uses this package. It states the facts an
agent tends to guess wrong. This file describes **using** the package in an
app; if you are modifying the package itself, see CLAUDE.md in the repo.

## What this package is

SAML SSO wiring for Supabase projects at UCSD (campus Shibboleth IdP):

1. `signInWithSSO()` redirects the browser to the campus IdP.
2. Supabase writes the SAML assertion into `auth.identities.identity_data`.
3. A database trigger projects the attributes into `private.user_attributes`
   and precomputes roles into `private.user_effective_claims`.
4. A custom access token hook injects `app_roles` and `dept_codes_array` as
   TOP-LEVEL JWT claims on every token mint.
5. App RLS policies call `private.user_has_role(...)` / `private.user_dept_codes()`.

It is wiring only: **no admin UI, no user management, no profile tables**.

## Invariants — do not violate these

- **Roles come from top-level JWT claims (`app_roles`), never from
  `user_metadata` or `app_metadata`.** `user_metadata` is client-writable via
  `supabase.auth.updateUser()`; reading roles from it is a privilege-escalation
  vulnerability. The SQL helpers and `extractAppClaims()` already read the
  right place — use them instead of decoding claims yourself.
- **The `private` schema is never exposed to PostgREST.** Do not add it to the
  exposed schemas, and do not create views over `private.*` in `public`. All
  client access goes through the shipped `public.*` RPCs or through
  `SECURITY DEFINER` functions you write (see docs/admin-rpcs.md).
- **Do not write to `private.user_attributes` or `private.user_effective_claims`.**
  Both are derived state, replaced automatically. To change someone's roles,
  write to `private.user_roles` or the mapping tables — triggers recompute
  claims automatically; never call recompute functions from app code.
- **Client-side role checks are UI conveniences, not security.** `hasRole()`,
  `useHasRole()`, `requireRole()` gate rendering only. The enforceable check is
  the RLS policy in the database.
- **JWT claims are stale up to one token lifetime.** For write-path
  authorization use `private.require_admin_write()` (JWT + live DB) or
  `private.user_has_role_in_db(...)`; the read guard tolerates staleness.
- **AD group data may be truncated to one group** (supabase/auth#2332,
  surfaced as `member_of_status = 'suspect_truncated'`). Role derivation is
  additive, so truncation can only under-grant. Never treat the *absence* of an
  AD group as a permission signal.

## What is automatic vs. what the app owns

| Automatic (never touch) | App-owned (you populate / build) |
|---|---|
| `private.user_attributes` | `private.app_roles` (role definitions) |
| `private.user_effective_claims` | `private.user_roles` (manual grants, optional expiry) |
| Claim recompute on any role-config write | `private.*_role_mappings` (AD group / emplid / dept code) |
| Expired-grant sweep (hourly pg_cron) | Admin RPCs + UI, if the app wants them |

Populate app-owned tables via SQL migrations/seeds, or build guarded
`SECURITY DEFINER` RPCs — a complete worked example (including first-admin
bootstrap) is in **docs/admin-rpcs.md**. Follow its four hygiene rules.

## Client entry points

- `@jsmillerucsd/supabase-sso` — isomorphic core: `signInWithSSO`,
  `handleAuthCallback`, `performLogout`, `getAppClaims`, `extractAppClaims`,
  `hasRole`, `getMyAttributes`, `getMyAdGroups`, `resolveConfig`.
- `@jsmillerucsd/supabase-sso/nextjs` — server-only (App Router):
  `updateSession` (middleware), `createSsoCallbackHandler`,
  `createLogoutHandler`, `getServerAppClaims`. Set `NextSsoEnv.siteUrl` in
  production so redirects never trust `x-forwarded-host`.
- `@jsmillerucsd/supabase-sso/react` — client components: `SsoProvider`,
  `useSso`, `useAppClaims`, `useHasRole`, `AuthCallback`.

Config needs `providerId` (preferred) or `domain`; everything else defaults.
`localAuthMode: true` disables SSO enforcement for local development.

## RLS policy patterns

```sql
create policy "admins read all" on public.documents for select
  using ( private.user_has_role('admin_role') );

create policy "own department" on public.documents for select
  using ( dept_code = any (private.user_dept_codes()) );
```

Dept codes are stored with leading zeros stripped ("578", not "0578");
`hasDeptCode()` normalizes its argument the same way.

## Operational facts

- Install/upgrade = run `sql/install.sql` (idempotent) as a migration, then
  enable the auth hook: `pg-functions://postgres/private/custom_access_token_hook`.
  Without the hook, every role-based policy denies.
- `SELECT * FROM public.toolkit_version()` shows installed module versions.
- Projection is fail-open: a projection defect degrades the user to zero roles
  and logs to `private.sync_errors`; it never blocks sign-in. The JWT then
  carries `app_claims_degraded: true` — surface it, don't render a silently
  empty UI.
- Supabase has no SAML Single Logout: `performLogout` signs out locally, then
  redirects through the campus IdP logout URL.
- Full docs (on GitHub and shipped in `docs/`): setup.md, reference.md,
  admin-rpcs.md, idp-registration.md.

## Recommended agent skills

Beyond this guide, install Supabase's official agent skills in the app repo —
they cover general Supabase development and Postgres best practices that this
package assumes (RLS policy patterns, migration hygiene, query performance):

```bash
npx skills add supabase/agent-skills
```

Docs: https://supabase.com/docs/guides/getting-started/ai-skills.md

When writing SQL for the app (policies, admin RPCs from docs/admin-rpcs.md,
indexes), follow the `supabase-postgres-best-practices` skill in that set. The
rules in this file are stricter where they overlap — this package's invariants
win inside its wiring.
