# Reference

## SQL

| Object | Purpose | Source |
|---|---|---|
| `private.user_attributes` | SSO attributes, refreshed on every sign-in | [0002](../sql/0002_identity_projection.sql) |
| `private.user_has_role(text)` | Role check for RLS policies | [0003](../sql/0003_rls_helpers.sql) |
| `private.user_dept_codes()` | Department codes for RLS policies | [0003](../sql/0003_rls_helpers.sql) |
| `private.user_in_ad_group(text)` | AD group check | [0003](../sql/0003_rls_helpers.sql) |
| `private.user_has_affiliation(text)` | Affiliation check — see limitations | [0003](../sql/0003_rls_helpers.sql) |
| `private.user_has_role_in_db(text)` | Live role check, ignores JWT staleness | [0003](../sql/0003_rls_helpers.sql) |
| `private.require_admin_read()` | Guard for your own read RPCs | [0003](../sql/0003_rls_helpers.sql) |
| `private.require_admin_write()` | Guard for your own write RPCs — checks the live DB | [0003](../sql/0003_rls_helpers.sql) |
| `public.get_my_attribute_summary()` | The caller's own attributes | [0003](../sql/0003_rls_helpers.sql) |
| `public.get_my_ad_groups()` | The caller's AD groups | [0003](../sql/0003_rls_helpers.sql) |
| `public.toolkit_version()` | What is installed | [0001](../sql/0001_core.sql) |

The auth hook adds `app_roles`, `dept_codes_array`, and — when it could not read
claims — `app_claims_degraded` to every JWT.

## TypeScript

[`src/index.ts`](../src/index.ts) · [`src/nextjs`](../src/nextjs/index.ts) · [`src/react`](../src/react/index.tsx)

```ts
import {
  signInWithSSO, handleAuthCallback, performLogout, buildLogoutUrl,
  getAppClaims, extractAppClaims, getAllClaims,
  hasRole, hasAnyRole, hasDeptCode, requireRole,
  getMyAttributes, getMyAdGroups,
  resolveConfig, SsoAuthError,
} from "@jsmillerucsd/supabase-sso";

import {
  updateSession, createSsoCallbackHandler,
  getServerAppClaims, createLogoutHandler,
} from "@jsmillerucsd/supabase-sso/nextjs";

import {
  SsoProvider, useSso, useAppClaims, useHasRole, AuthCallback,
} from "@jsmillerucsd/supabase-sso/react";
```

### Config

```ts
{
  providerId?: string;      // from `supabase sso list` — preferred
  domain?: string;          // e.g. "ucsd.edu" — used if providerId is absent
  callbackPath?: string;    // default "/auth/callback"
  homePath?: string;        // default "/"
  loginPath?: string;       // default "/login"
  idpLogoutUrl?: string;    // default UCSD tritON logout
  localAuthMode?: boolean;  // skip SSO for local dev
}
```

---

## Granting roles

Four sources, unioned into `app_roles`. Seed them in your own migration:

```sql
insert into private.app_roles (role, description) values ('editor_role', 'Can edit');

insert into private.user_roles (user_id, role)                values ('<uuid>', 'editor_role');
insert into private.ad_group_role_mappings (ad_group_cn, role) values ('App-Admins', 'admin_role');
insert into private.emplid_role_mappings (ucpath_emplid, role) values ('10012345', 'editor_role');
insert into private.dept_code_role_mappings (dept_code, role)  values ('578', 'editor_role');
```

Claims recompute automatically. Users pick up new roles on their next token refresh.

Department codes are stored un-padded — the IdP sends `0578`, this stores `578`.

---

## Why attributes come from `auth.identities`

Read this before changing [`sql/0002_identity_projection.sql`](../sql/0002_identity_projection.sql).

`auth.users.raw_user_meta_data` looks like the obvious source. It isn't. Supabase
merges it key-by-key, so an attribute the IdP stops sending keeps its old value
forever — a group removed upstream would never be revoked. It is also writable by the
user via `updateUser()`.

`auth.identities.identity_data` is replaced wholesale on every sign-in and is not
client-writable. That is why the projection reads it, and why nothing downstream trusts
JWT metadata.

---

## Modules

[`sql/install.sql`](../sql/install.sql) is generated from these. Edit the modules, not the generated file.

| Module | Contents |
|---|---|
| [`0001_core`](../sql/0001_core.sql) | `private` schema, grants, version registry, error log |
| [`0002_identity_projection`](../sql/0002_identity_projection.sql) | `user_attributes`, triggers, the trust boundary |
| [`0003_rls_helpers`](../sql/0003_rls_helpers.sql) | Policy helpers and admin guards |
| [`0004_roles`](../sql/0004_roles.sql) | Role tables and the four grant sources |
| [`0005_auth_hook`](../sql/0005_auth_hook.sql) | Custom access token hook |
| [`0006_ucsd_adapter`](../sql/0006_ucsd_adapter.sql) | UCSD attribute extraction |
