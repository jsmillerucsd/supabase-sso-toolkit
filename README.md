# @jsmillerucsd/supabase-sso

SAML SSO attribute projection and RLS wiring for Supabase projects at UCSD.
Connects your app to the campus Shibboleth IdP, copies SAML attributes into a
trusted `private` schema on every sign-in, and exposes role/department helpers
for RLS policies. Ships a Next.js/SPA client for sign-in, callback, and claims.

Not an app template. No admin UI, no user management, no profile tables.

## How it works

```
1.  signInWithSSO()      browser redirects to the UCSD IdP
2.  IdP posts assertion  Supabase writes auth.identities.identity_data
3.  trigger fires        → private.user_attributes        (trusted copy)
                          → private.user_effective_claims  (roles precomputed)
4.  token minted         auth hook reads one row, adds app_roles + dept_codes_array
5.  app queries          RLS policies call private.user_has_role(...)
```

Attributes are copied from `auth.identities`, not `raw_user_meta_data` (which is
merged key-by-key and client-writable). Roles are computed at write time so the
hook stays a single row read.

## What gets installed

All objects live in a `private` schema that is never exposed to PostgREST. Client
access is through the `public.*` RPCs listed below. Nothing in your `public`
schema is touched.

**Tables**

| Table | Purpose |
|---|---|
| `private.user_attributes` | SAML attributes, replaced wholesale on every sign-in |
| `private.user_effective_claims` | Precomputed `app_roles` + `dept_codes`, read by the auth hook |
| `private.app_roles` | Role definitions |
| `private.user_roles` | Manual role grants (with optional expiry) |
| `private.ad_group_role_mappings` | AD group to role mapping |
| `private.emplid_role_mappings` | UCPath emplid to role mapping |
| `private.dept_code_role_mappings` | Department code to role mapping |
| `private.toolkit_modules` | Installed module versions |
| `private.sync_errors` | Fail-open error log for projection defects |

**Triggers**

| Trigger | On | Does |
|---|---|---|
| `on_sso_identity_projected` | `auth.identities` | Projects SAML attributes into `private.user_attributes` |
| `on_*_changed` (4) | `private.*_role_mappings`, `private.user_roles` | Recomputes affected users' claims |

**Functions**

| Function | Use |
|---|---|
| `private.custom_access_token_hook(jsonb)` | Access token hook. Injects `app_roles`, `dept_codes_array` into the JWT |
| `private.user_has_role(text)` | RLS policy role check (reads JWT) |
| `private.user_dept_codes()` | RLS policy department check (reads JWT) |
| `private.user_has_role_in_db(text)` | Live role check, bypasses JWT staleness |
| `private.user_in_ad_group(text)` | AD group membership check |
| `private.require_admin_read()` | Guard for your read RPCs (JWT only) |
| `private.require_admin_write()` | Guard for your write RPCs (JWT + live DB) |
| `public.get_my_attribute_summary()` | Caller's own attributes (RPC) |
| `public.get_my_ad_groups()` | Caller's AD groups (RPC) |
| `public.toolkit_version()` | Installed versions (RPC) |

Full signatures and granting roles: **[reference](docs/reference.md)**.

## Install

Add one line to your app's `.npmrc`:

```
@jsmillerucsd:registry=https://npm.pkg.github.com
```

```bash
npm i @jsmillerucsd/supabase-sso
supabase migration new sso_install
```

Paste in [`sql/install.sql`](sql/install.sql) and apply with `supabase db push`.
Then enable SAML, turn on the auth hook, register with the IdP, and allow-list
your callback URLs. See **[full setup](docs/setup.md)**. The SQL is idempotent;
re-running a newer `install.sql` is how you upgrade.

## RLS policies

```sql
create policy "admins read all" on public.documents for select
  using ( private.user_has_role('admin_role') );

create policy "own department" on public.documents for select
  using ( dept_code = any (private.user_dept_codes()) );
```

## Client integration

| Framework | Import | You write |
|---|---|---|
| Vue, Svelte, Angular, vanilla | `@jsmillerucsd/supabase-sso` | login button, callback page |
| React SPA | `+ /react` | same, wrapped in `<SsoProvider>` |
| Next.js App Router | `+ /nextjs` | `middleware.ts`, callback route |

### Any SPA

```ts
// login
import { signInWithSSO } from "@jsmillerucsd/supabase-sso";
await signInWithSSO(supabase, config);

// /auth/callback
import { handleAuthCallback } from "@jsmillerucsd/supabase-sso";
await handleAuthCallback(supabase, config);

// read claims
import { getAppClaims, hasRole } from "@jsmillerucsd/supabase-sso";
const claims = await getAppClaims(supabase);
hasRole(claims, "admin_role");
```

### React

```tsx
import { SsoProvider, useSso, useHasRole, AuthCallback } from "@jsmillerucsd/supabase-sso/react";

<SsoProvider supabase={supabase} config={config}>
  <App />
</SsoProvider>

const { signIn, signOut, claims } = useSso();
const isAdmin = useHasRole("admin_role");
```

Mount `<AuthCallback />` at your callback route.

### Next.js App Router

```ts
// middleware.ts
import { updateSession } from "@jsmillerucsd/supabase-sso/nextjs";
export const middleware = (req: NextRequest) =>
  updateSession(req, {
    supabaseUrl: process.env.NEXT_PUBLIC_SUPABASE_URL!,
    supabasePublishableKey: process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY!,
  }, { providerId: process.env.SUPABASE_SSO_PROVIDER_ID! });

// app/auth/callback/route.ts
import { createSsoCallbackHandler } from "@jsmillerucsd/supabase-sso/nextjs";
export const GET = createSsoCallbackHandler(
  {
    supabaseUrl: process.env.NEXT_PUBLIC_SUPABASE_URL!,
    supabasePublishableKey: process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY!,
  },
  { providerId: process.env.SUPABASE_SSO_PROVIDER_ID! },
);

// app/page.tsx (server components)
import { getServerAppClaims } from "@jsmillerucsd/supabase-sso/nextjs";
import { cookies } from "next/headers";
const claims = await getServerAppClaims(await cookies(), {
  supabaseUrl: process.env.NEXT_PUBLIC_SUPABASE_URL!,
  supabasePublishableKey: process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY!,
});
```

### Config

```ts
const config = { providerId: "..." };   // from `supabase sso list`
```

Everything else has a default. See [reference](docs/reference.md#config).

## Docs

- **[Setup](docs/setup.md)**: the six steps, and troubleshooting
- **[Reference](docs/reference.md)**: SQL and TypeScript API, granting roles
- **[IdP registration](docs/idp-registration.md)**: ServiceNow ticket routing
- **[Intake form](docs/saml-intake-form.md)**: answers, and the blank .docx

## Limitations

**AD groups are unreliable.** Supabase truncates `memberOf` to a single group
for most users ([supabase/auth#2332](https://github.com/supabase/auth/issues/2332)).
Group-to-role mapping still works (a short list can only under-grant), but never
treat *absence* of a group as a permission signal. Check `member_of_status` on
[`private.user_attributes`](sql/0002_identity_projection.sql).

**No Single Logout.** Supabase does not support SAML SLO. Logout clears the
local session and redirects through the IdP, but already-issued JWTs live until
they expire.

## Develop

```bash
npm run build   # regenerate install.sql, compile TS
npm test        # pgTAP suite against a local Supabase stack
```

### Release

Bump `version` in `package.json`, then:

```bash
npm run release   # build + publish to npm.pkg.github.com
git tag v1.x.y && git push --tags
```

Publishing requires a PAT with `write:packages` in `~/.npmrc`.
