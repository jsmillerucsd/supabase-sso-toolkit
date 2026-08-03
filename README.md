# @ucsd/supabase-sso

SAML SSO attributes and RLS wiring for Supabase projects.

Your app registers directly with the campus Shibboleth IdP. This package takes the
attributes that arrive and makes them safe to use in RLS policies.

It is **not** an app template — no admin UI, no user management, no profile tables.
Your schema and screens stay yours.

---

## Setup

**1. Install**

```bash
npm i github:UCSD/supabase-sso-toolkit#v1.0.0
```

**2. Run the SQL**

Copy `node_modules/@ucsd/supabase-sso/sql/install.sql` into a new migration and apply it:

```bash
supabase migration new sso_install
```

Re-running it later is how you upgrade — it is idempotent.

**3. Enable the auth hook**

Dashboard → Authentication → Hooks → Customize Access Token:

```
pg-functions://postgres/private/custom_access_token_hook
```

**4. Register the IdP**

```bash
supabase sso add --project-ref <ref> --type saml \
  --metadata-url <idp-metadata-url> \
  --domains ucsd.edu \
  --attribute-mapping-file node_modules/@ucsd/supabase-sso/sql/assets/ucsd-attribute-mapping.json
```

Note the provider UUID it prints — that is your `providerId`.

---

## Use it

**Sign in**

```ts
import { signInWithSSO } from "@ucsd/supabase-sso";

await signInWithSSO(supabase, { providerId: "..." });
```

**In RLS policies**

```sql
create policy "admins read all"
  on public.documents for select
  using ( private.user_has_role('admin_role') );

create policy "own department"
  on public.documents for select
  using ( dept_code = any (private.user_dept_codes()) );
```

**In app code**

```ts
import { getAppClaims, hasRole } from "@ucsd/supabase-sso";

const claims = await getAppClaims(supabase);
if (hasRole(claims, "admin_role")) { ... }
```

**React**

```tsx
import { SsoProvider, useAppClaims, useHasRole } from "@ucsd/supabase-sso/react";

<SsoProvider supabase={supabase} config={{ providerId: "..." }}>
  <App />
</SsoProvider>
```

**Next.js** — `middleware.ts`:

```ts
import { updateSession } from "@ucsd/supabase-sso/nextjs";

export async function middleware(request: NextRequest) {
  return updateSession(request, env, { providerId: "..." });
}
```

...and `app/auth/callback/route.ts`:

```ts
import { createSsoCallbackHandler } from "@ucsd/supabase-sso/nextjs";

export const GET = createSsoCallbackHandler(env, { providerId: "..." });
```

---

## Granting roles

Roles come from four sources, unioned into the `app_roles` JWT claim. Seed them in
your own migration:

```sql
insert into private.app_roles (role, description) values ('editor_role', 'Can edit');

insert into private.user_roles (user_id, role) values ('<uuid>', 'editor_role');
insert into private.ad_group_role_mappings (ad_group_cn, role) values ('App-Admins', 'admin_role');
insert into private.emplid_role_mappings (ucpath_emplid, role) values ('10012345', 'editor_role');
insert into private.dept_code_role_mappings (dept_code, role) values ('578', 'editor_role');
```

Claims recompute automatically when these change. Users pick up the new roles on their
next token refresh.

---

## What you get

| | |
|---|---|
| `private.user_attributes` | SSO attributes, refreshed on every sign-in |
| `private.user_has_role(text)` | Role check for RLS policies |
| `private.user_dept_codes()` | Department codes for RLS policies |
| `private.user_in_ad_group(text)` | AD group check |
| `private.user_has_role_in_db(text)` | Live role check, ignores JWT staleness |
| `public.get_my_attribute_summary()` | The caller's own attributes |
| `public.toolkit_version()` | What is installed |

The auth hook adds `app_roles` and `dept_codes_array` to every JWT.

---

## Known limitations

**AD group data is unreliable.** The IdP releases `memberOf` in a form Supabase
truncates to a single group for most users ([supabase/auth#2332](https://github.com/supabase/auth/issues/2332)).
Group→role mapping still works — a truncated list can only under-grant, never
over-grant — but never treat *absence* of a group as a permission signal. Check
`member_of_status` on `private.user_attributes`; `suspect_truncated` means what it says.

**`eduPersonAffiliation` is not released.** `user_has_affiliation()` ships but returns
false for everyone until that changes.

**No Single Logout.** Supabase does not support SAML SLO. `performLogout()` redirects
through the IdP, which is the closest available thing — but signing out does not
invalidate already-issued JWTs before they expire.

---

## Why attributes are read from `auth.identities`

Worth knowing before you change anything in `0002_identity_projection.sql`:

`auth.users.raw_user_meta_data` looks like the obvious source. It isn't. Supabase
merges it key-by-key, so an attribute the IdP stops sending keeps its old value
forever — a group removed upstream would never be revoked here. It is also writable
by the user via `updateUser()`.

`auth.identities.identity_data` is replaced wholesale on every sign-in and is not
client-writable. That is why the projection reads it, and why nothing downstream
reads JWT metadata.

---

## Development

```bash
npm run build      # regenerate install.sql, compile TS
npm test           # pgTAP suite against a local Supabase stack
```

`sql/install.sql` is generated from the numbered modules in `sql/`. Edit the modules,
not the generated file.
