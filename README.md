# @ucsd/supabase-sso

SAML SSO attributes and RLS wiring for Supabase projects.

Your app registers directly with the UCSD Shibboleth IdP. This package takes the
attributes that arrive and makes them safe to use in RLS policies.

It is **not** an app template — no admin UI, no user management, no profile tables.
Your schema and screens stay yours.

**What it installs:** one auth hook, two triggers on the auth schema, and a `private`
schema. No edge functions.

---

## Setup

Six steps. Four are in Supabase, one is with the IdP team, one is in your code.

### 1. Enable SAML on the project

SAML 2.0 requires the **Pro plan or above** and is **off by default**.

Dashboard → Authentication → Providers → SAML 2.0 → enable.

→ [Enterprise SSO with SAML](https://supabase.com/docs/guides/auth/enterprise-sso/auth-sso-saml)

### 2. Install the package and run the SQL

```bash
npm i github:jsmillerucsd/supabase-sso-toolkit#v1.0.0
supabase migration new sso_install
```

Paste `node_modules/@ucsd/supabase-sso/sql/install.sql` into the generated file and
apply it. Re-running a newer version is how you upgrade — it is idempotent.

### 3. Enable the auth hook

Dashboard → Authentication → Hooks → Customize Access Token:

```
pg-functions://postgres/private/custom_access_token_hook
```

Without this, `app_roles` and `dept_codes_array` never reach the JWT and every RLS
policy using them denies.

→ [Custom Access Token Hook](https://supabase.com/docs/guides/auth/auth-hooks/custom-access-token-hook)

### 4. Register the UCSD IdP

Requires Supabase CLI v1.46.4+.

```bash
supabase sso add --type saml --project-ref <ref> \
  --metadata-url 'https://a5.ucsd.edu/a5-stage-metadata-sscert3072.xml' \
  --domains ucsd.edu \
  --attribute-mapping-file node_modules/@ucsd/supabase-sso/sql/assets/ucsd-attribute-mapping.json
```

> The URL above is the **staging** IdP. Get the production metadata URL from the
> identity team before going live.

Note the provider UUID it prints — that is your `providerId`.

```bash
supabase sso list --project-ref <ref>     # look it up again later
```

### 5. Register your app with the UCSD IdP

Every app is its own service provider and needs its own ServiceNow ticket with a
completed SAML intake form.

→ **[How to register](docs/idp-registration.md)** — ticket routing, and the three
answers that will otherwise cost you a round trip
→ **[Pre-filled intake form](docs/saml-intake-form.md)** — attach to the ticket

They need these to register your app:

| Field | Value |
|---|---|
| Entity ID | `https://<project-ref>.supabase.co/auth/v1/sso/saml/metadata` |
| ACS URL | `https://<project-ref>.supabase.co/auth/v1/sso/saml/acs` |

**If you use a custom domain**, substitute it. For example with
`auth.supabase.ucsd.edu`:

```
Entity ID:  https://auth.supabase.ucsd.edu/auth/v1/sso/saml/metadata
ACS URL:    https://auth.supabase.ucsd.edu/auth/v1/sso/saml/acs
Metadata:   https://auth.supabase.ucsd.edu/auth/v1/sso/saml/metadata
```

Set the custom domain *before* registering with the IdP — changing it afterward means
re-registering, because the Entity ID changes.

→ [Custom Domains](https://supabase.com/docs/guides/platform/custom-domains)

### 6. Allow-list your callback URLs

Dashboard → Authentication → URL Configuration.

- **Site URL** — your production origin. The default is `http://localhost:3000`; leaving
  it there breaks production redirects.
- **Redirect URLs** — add every origin that completes sign-in. A `redirectTo` that
  isn't on this list is rejected.

```
http://localhost:3000/auth/callback
https://your-app.ucsd.edu/auth/callback
https://your-app-*.vercel.app/auth/callback
```

→ [Redirect URLs](https://supabase.com/docs/guides/auth/redirect-urls)

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

Claims recompute automatically when these change. Users pick up new roles on their
next token refresh.

---

## What you get

| Object | Purpose |
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

## Troubleshooting

**Roles are always empty.** The auth hook is not enabled (step 3). Check with
`select * from public.toolkit_version()` that the SQL ran, then confirm the hook URI
in the dashboard. If the JWT has `app_claims_degraded: true`, the hook ran but found
no attributes for that user — look at `private.sync_errors`.

**Sign-in redirects to an error page.** The callback URL is not in the Redirect URLs
allow-list (step 6).

**Attributes are missing or stale.** Check `private.user_attributes` for the user.
`synced_at` shows the last successful projection; `source_kind` shows which branch
wrote it.

---

## Known limitations

**AD group data is unreliable.** The IdP releases `memberOf` in a form Supabase
truncates to a single group for most users
([supabase/auth#2332](https://github.com/supabase/auth/issues/2332)). Group→role
mapping still works — a truncated list can only under-grant, never over-grant — but
never treat *absence* of a group as a permission signal. Check `member_of_status` on
`private.user_attributes`; `suspect_truncated` means what it says.

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
