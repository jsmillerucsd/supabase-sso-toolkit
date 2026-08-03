# SAML Vendor Intake Form — Supabase

Pre-filled for a Supabase project using this toolkit. Answers marked **[FILL IN]** are
yours. Attach to a ServiceNow ticket — see [idp-registration.md](./idp-registration.md).

---

**Is the vendor an InCommon Federation member?**

No. Supabase is a commercial platform (supabase.com).

**If not — do you consume InCommon metadata?**

No. We consume UCSD IdP metadata directly.

**What SAML implementation do you use?**

Other: Supabase Auth (GoTrue), an open-source auth server with built-in SAML 2.0 SP
support.

**What is the primary user population?**

**[FILL IN]** — students / faculty & staff / non-employee affiliates.

**Do you support the standard eduPerson / "OID" style attribute names?**

Yes. We accept both OID-style and `urn:mace:ucsd.edu:sso:*` names. Attribute mapping is
configured on our side at registration time.

**What are your required / optional SAML attributes?**

The standard UCSD SSO attribute set, plus `memberOf`.

These values are consumed by the application and by Supabase Row Level Security
policies.

> Please release `memberOf` as a multi-valued attribute containing the user's complete
> group list. Our SP captures only the first value if the groups arrive as a single
> concatenated string.

**What do you use as the primary user identifier?**

ePPN (`urn:oid:1.3.6.1.4.1.5923.1.1.1.6`).

We understand the preference is to send this as a 32-character opaque value rather than
`user@ucsd.edu`. That works for us.

**Can you handle a primary user identifier of 32+ characters?**

Yes. Stored as unbounded text in Postgres.

**Do you have any special SAML NameID requirements?**

Yes. The NameID format must be **`persistent`** or **`emailAddress`**.

Please do not send `transient` — Supabase rejects it, and a NameID that changes each
login would create a new account on every sign-in.

**How are user accounts provisioned?**

On demand. Accounts are created automatically the first time a user authenticates.

**How are admin accounts provisioned?**

Same as regular users. Admin roles are assigned inside the application, not at
provisioning time.

**Who are your primary contacts for these areas?**

**[FILL IN]** — technical, support, administrative.

**How do you handle user logout?**

Local logout plus redirect to a configurable URL. The app clears its session, then
redirects to the UCSD IdP logout endpoint.

We do not implement SAML 2 Single Logout — Supabase Auth does not support it.

**Can you supply SAML metadata for your QA and production environments?**

Yes. Each application is a separate service provider with its own metadata endpoint.
This registration covers one application:

- **[FILL IN]** Application name:
- **[FILL IN]** Environment: staging / production
- **[FILL IN]** Entity ID: `https://<host>/auth/v1/sso/saml/metadata`
- **[FILL IN]** ACS URL: `https://<host>/auth/v1/sso/saml/acs`

Where `<host>` is `<project-ref>.supabase.co` or a custom domain such as
`auth.supabase.ucsd.edu`.

Additional applications will be registered under separate tickets.

**How do you handle guest accounts?**

None. All users authenticate via UCSD SSO. There is no anonymous access.
