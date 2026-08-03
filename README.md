# @ucsd/supabase-sso

SAML SSO attributes and RLS wiring for Supabase projects.

Your app registers directly with the UCSD Shibboleth IdP. This package takes the
attributes that arrive and makes them safe to use in RLS policies.

Not an app template — no admin UI, no user management, no profile tables. It installs
one auth hook, two triggers, and a `private` schema. No edge functions.

## How it works

```
1.  signInWithSSO()      browser redirects to the UCSD IdP
2.  IdP posts assertion  Supabase writes auth.identities.identity_data
3.  trigger fires        → private.user_attributes        (trusted copy)
                         → private.user_effective_claims  (roles precomputed)
4.  token minted         auth hook reads one row, adds app_roles + dept_codes_array
5.  app queries          RLS policies call private.user_has_role(...)
```

Steps 3 and 4 are the reason this package exists. Attributes are copied out of
`auth.identities` — not `raw_user_meta_data`, which is merged key-by-key and writable by
the user — and roles are computed at write time so the hook stays a single row read.

## Install

```bash
npm i github:jsmillerucsd/supabase-sso-toolkit#v1.0.0
supabase migration new sso_install
```

Paste in [`sql/install.sql`](sql/install.sql) and apply.

Then enable SAML, turn on the auth hook, register with the IdP, and allow-list your
callback URLs — **[full setup](docs/setup.md)**.

## Quick start

RLS policies are the same everywhere:

```sql
create policy "admins read all" on public.documents for select
  using ( private.user_has_role('admin_role') );

create policy "own department" on public.documents for select
  using ( dept_code = any (private.user_dept_codes()) );
```

The client differs by framework. SPAs exchange the auth code in the browser; Next.js
does it server-side and needs middleware to keep the session cookie fresh.

| Framework | Import | You write |
|---|---|---|
| Vue, Svelte, Angular, vanilla | `@ucsd/supabase-sso` | login button, callback page |
| React SPA | `+ /react` | same, wrapped in `<SsoProvider>` |
| Next.js App Router | `+ /nextjs` | `middleware.ts`, callback route |

### Vue, Svelte, or any SPA

Core exports are framework-agnostic. Two pieces:

```ts
// login
import { signInWithSSO } from "@ucsd/supabase-sso";
await signInWithSSO(supabase, config);

// /auth/callback — completes sign-in, then redirects home
import { handleAuthCallback } from "@ucsd/supabase-sso";
await handleAuthCallback(supabase, config);
```

Read claims anywhere:

```ts
import { getAppClaims, hasRole } from "@ucsd/supabase-sso";

const claims = await getAppClaims(supabase);
hasRole(claims, "admin_role");
```

### React SPA

Same as above, plus a provider and hooks:

```tsx
import { SsoProvider, useSso, useHasRole, AuthCallback } from "@ucsd/supabase-sso/react";

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
import { updateSession } from "@ucsd/supabase-sso/nextjs";
export const middleware = (req: NextRequest) => updateSession(req, env, config);

// app/auth/callback/route.ts
import { createSsoCallbackHandler } from "@ucsd/supabase-sso/nextjs";
export const GET = createSsoCallbackHandler(env, config);

// app/page.tsx — server components
import { getServerAppClaims } from "@ucsd/supabase-sso/nextjs";
const claims = await getServerAppClaims(await cookies(), env);
```

`/react` also works in client components if you want the hooks.

### Config

```ts
const config = { providerId: "..." };   // from `supabase sso list`
```

Everything else has a default — see [reference](docs/reference.md#config).

## Docs

- **[Setup](docs/setup.md)** — the six steps, and troubleshooting
- **[Reference](docs/reference.md)** — SQL and TypeScript API, granting roles
- **[IdP registration](docs/idp-registration.md)** — ServiceNow ticket routing
- **[Intake form](docs/saml-intake-form.md)** — answers, and the blank .docx

## Limitations

**AD groups are unreliable.** Supabase truncates `memberOf` to a single group for most
users ([supabase/auth#2332](https://github.com/supabase/auth/issues/2332)). Group→role
mapping still works — a short list can only under-grant — but never treat *absence* of
a group as a permission signal. Check `member_of_status` on
[`private.user_attributes`](sql/0002_identity_projection.sql).

**`eduPersonAffiliation` is not released.** `user_has_affiliation()` returns false for
everyone until that changes.

**No Single Logout.** Supabase does not support SAML SLO. Logout clears the local
session and redirects through the IdP, but already-issued JWTs live until they expire.

## Develop

```bash
npm run build   # regenerate install.sql, compile TS
npm test        # pgTAP suite against a local Supabase stack
```
