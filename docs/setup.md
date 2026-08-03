# Setup

Six steps. Four in Supabase, one with the IdP team, one in your code.

---

## 1. Enable SAML

SAML 2.0 requires the **Pro plan or above** and is **off by default**.

Dashboard → Authentication → Providers → SAML 2.0.

→ [Enterprise SSO with SAML](https://supabase.com/docs/guides/auth/enterprise-sso/auth-sso-saml)

## 2. Run the SQL

```bash
npm i github:jsmillerucsd/supabase-sso-toolkit#v1.0.0
supabase migration new sso_install
```

Paste in [`sql/install.sql`](../sql/install.sql) — shipped at
`node_modules/@ucsd/supabase-sso/sql/install.sql` — and apply.

The file is idempotent — re-running a newer version is how you upgrade.

## 3. Enable the auth hook

Dashboard → Authentication → Hooks → Customize Access Token:

```
pg-functions://postgres/private/custom_access_token_hook
```

Without this, `app_roles` and `dept_codes_array` never reach the JWT and every policy
using them denies. Source: [`sql/0005_auth_hook.sql`](../sql/0005_auth_hook.sql).

→ [Custom Access Token Hook](https://supabase.com/docs/guides/auth/auth-hooks/custom-access-token-hook)

## 4. Set a custom domain

A custom domain changes your Entity ID. Setting one up after registering with the IdP
means registering again.

→ [Custom Domains](https://supabase.com/docs/guides/platform/custom-domains)

## 5. Register with the UCSD IdP

Each app is its own service provider and needs its own ServiceNow ticket.

→ [How to register](./idp-registration.md) · [Pre-filled intake form](./saml-intake-form.md)

Once they confirm, add the connection:

```bash
supabase sso add --type saml --project-ref <ref> \
  --metadata-url '<idp-metadata-url>' \
  --domains ucsd.edu \
  --attribute-mapping-file node_modules/@ucsd/supabase-sso/sql/assets/ucsd-attribute-mapping.json
```

The staging IdP metadata is `https://a5.ucsd.edu/a5-stage-metadata-sscert3072.xml`.
Get the production URL from the identity team.

Requires Supabase CLI v1.46.4+. The command prints your `providerId`; `supabase sso
list` looks it up later.

## 6. Allow-list your callback URLs

Dashboard → Authentication → URL Configuration.

- **Site URL** — your production origin. The default is `http://localhost:3000` and
  will break production redirects if left.
- **Redirect URLs** — every origin that completes sign-in. A `redirectTo` that is not
  listed is rejected.

```
http://localhost:3000/auth/callback
https://your-app.ucsd.edu/auth/callback
```

→ [Redirect URLs](https://supabase.com/docs/guides/auth/redirect-urls)

---

## Troubleshooting

**Roles are always empty.** The auth hook is not enabled (step 3). Confirm the SQL ran
with `select * from public.toolkit_version()`, then check the hook URI. If the JWT has
`app_claims_degraded: true`, the hook ran but found no attributes — see
`private.sync_errors` ([`sql/0001_core.sql`](../sql/0001_core.sql)).

**Sign-in redirects to an error page.** The callback URL is not allow-listed (step 6).

**Attributes missing or stale.** Check `private.user_attributes`. `synced_at` is the
last successful projection; `source_kind` shows which branch wrote it. Source:
[`sql/0002_identity_projection.sql`](../sql/0002_identity_projection.sql).
