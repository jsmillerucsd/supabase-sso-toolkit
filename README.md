# @ucsd/supabase-sso

SAML SSO attributes and RLS wiring for Supabase projects.

Your app registers directly with the UCSD Shibboleth IdP. This package takes the
attributes that arrive and makes them safe to use in RLS policies.

Not an app template — no admin UI, no user management, no profile tables. It installs
one auth hook, two triggers, and a `private` schema. No edge functions.

## Install

```bash
npm i github:jsmillerucsd/supabase-sso-toolkit#v1.0.0
supabase migration new sso_install
```

Paste in `node_modules/@ucsd/supabase-sso/sql/install.sql` and apply.

Then enable SAML, turn on the auth hook, register with the IdP, and allow-list your
callback URLs — **[full setup](docs/setup.md)**.

## Use

```sql
-- RLS policies
create policy "admins read all" on public.documents for select
  using ( private.user_has_role('admin_role') );

create policy "own department" on public.documents for select
  using ( dept_code = any (private.user_dept_codes()) );
```

```ts
import { signInWithSSO, getAppClaims, hasRole } from "@ucsd/supabase-sso";

await signInWithSSO(supabase, { providerId: "..." });

const claims = await getAppClaims(supabase);
hasRole(claims, "admin_role");
```

```tsx
import { SsoProvider, useHasRole } from "@ucsd/supabase-sso/react";

<SsoProvider supabase={supabase} config={{ providerId: "..." }}>
  <App />
</SsoProvider>
```

```ts
// middleware.ts
import { updateSession } from "@ucsd/supabase-sso/nextjs";
export const middleware = (req: NextRequest) =>
  updateSession(req, env, { providerId: "..." });

// app/auth/callback/route.ts
import { createSsoCallbackHandler } from "@ucsd/supabase-sso/nextjs";
export const GET = createSsoCallbackHandler(env, { providerId: "..." });
```

## Docs

- **[Setup](docs/setup.md)** — the six steps, and troubleshooting
- **[Reference](docs/reference.md)** — SQL and TypeScript API, granting roles
- **[IdP registration](docs/idp-registration.md)** — ServiceNow ticket routing
- **[Intake form](docs/saml-intake-form.md)** — pre-filled, attach to the ticket

## Limitations

**AD groups are unreliable.** Supabase truncates `memberOf` to a single group for most
users ([supabase/auth#2332](https://github.com/supabase/auth/issues/2332)). Group→role
mapping still works — a short list can only under-grant — but never treat *absence* of
a group as a permission signal. Check `member_of_status` on `private.user_attributes`.

**`eduPersonAffiliation` is not released.** `user_has_affiliation()` returns false for
everyone until that changes.

**No Single Logout.** Supabase does not support SAML SLO. Logout clears the local
session and redirects through the IdP, but already-issued JWTs live until they expire.

## Develop

```bash
npm run build   # regenerate install.sql, compile TS
npm test        # pgTAP suite against a local Supabase stack
```
