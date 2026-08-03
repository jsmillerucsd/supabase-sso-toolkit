# SAML Vendor Intake Form — Supabase

Pre-filled for a Supabase project using this toolkit. Answers marked **[FILL IN]** are
yours; the rest are the same for every Supabase app and can be sent as-is.

Attach to a ServiceNow ticket — see [`idp-registration.md`](./idp-registration.md) for
routing.

---

**Is the vendor an InCommon Federation member?**

No. Supabase is a commercial platform (supabase.com) and is not an InCommon member.

**If not — do you consume InCommon metadata?**

No. We consume UCSD IdP metadata directly via bilateral trust.

**What SAML implementation do you use?**

Other: Supabase Auth (GoTrue), an open-source Go-based auth server with built-in
SAML 2.0 SP support.

**What is the primary user population?**

**[FILL IN]** — students / faculty & staff / non-employee affiliates.

**Do you support the standard eduPerson / "OID" style attribute names?**

Yes. We accept both standard eduPerson/OID-style URNs and UCSD-specific
`urn:mace:ucsd.edu:sso:*` URNs. Attribute mapping is configured via a JSON mapping file
at SP registration time.

**What are your required / optional SAML attributes?**

Please include the standard UCSD SSO attribute set. These values are consumed by the
application and by Supabase Row Level Security policies.

Required, and please confirm each is in the release set:

- `urn:oid:1.3.6.1.4.1.5923.1.1.1.6` — ePPN
- `urn:oid:0.9.2342.19200300.100.1.3` — mail
- `urn:oid:1.3.6.1.4.1.5923.1.1.1.1` — eduPersonAffiliation
- `urn:mace:ucsd.edu:sso:ad:username` — AD username
- `urn:mace:ucsd.edu:sso:actsso:ucnetid` — UCnetID
- `urn:mace:ucsd.edu:sso:pps:home_dept_code`
- `urn:mace:ucsd.edu:sso:pps:departmentcodes`
- `urn:mace:ucsd.edu:sso:ucpath:emplid`

Requires release approval:

- `memberOf` — AD group membership
- `urn:mace:ucsd.edu:sso:ad:upn`
- `urn:mace:ucsd.edu:sso:people:employee_email`
- `urn:mace:ucsd.edu:sso:people:stu_email`

> **`memberOf` must be released as a multi-valued attribute containing all groups.**
> Our SP captures only the first value unless the attribute is sent multi-valued and
> mapped as an array on our side. We have configured the array mapping; please confirm
> the IdP releases the complete group list rather than a single value.

To future-proof, please include these even if currently blank:

- `urn:mace:ucsd.edu:sso:tss:stuid`
- `urn:mace:ucsd.edu:sso:csid`
- `urn:mace:ucsd.edu:sso:aff_emp_id`

**What do you use as the primary user identifier?**

ePPN (`urn:oid:1.3.6.1.4.1.5923.1.1.1.6`). We understand the preference is to send this
as a 32-character opaque alphanumeric value rather than scoped `user@ucsd.edu` form —
that works for us.

Because an opaque identifier is not human-readable, please also include
`urn:mace:ucsd.edu:sso:ad:username` or `urn:mace:ucsd.edu:sso:actsso:ucnetid` in the
release set so support staff can identify accounts.

**Can you handle a primary user identifier of 32+ characters?**

Yes. Stored as unbounded text in Postgres.

**Do you have any special SAML NameID requirements?**

Yes. The NameID format must be **`persistent`** or **`emailAddress`**. Supabase Auth
rejects other formats.

Please do **not** send `transient` — a transient NameID changes on every login, which
would create a new user account each time a user signs in.

**How are user accounts provisioned?**

On demand. Accounts are created automatically (JIT provisioning) the first time a user
authenticates via SAML.

**How are admin accounts provisioned?**

On demand via SSO, same as regular users. Admin roles are assigned inside the
application via AD group membership or database role grants — no separate provisioning
path.

**Who are your primary contacts for these areas?**

**[FILL IN]** — technical (architecture/design), support (routine issues, outages),
administrative.

**How do you handle user logout?**

Local logout plus redirect to a configurable URL. The app clears its local session,
then redirects to the UCSD IdP logout endpoint.

We do not implement SAML 2 Single Logout — Supabase Auth does not support it.

**Can you supply SAML metadata for your QA and production environments?**

Yes.

Each application is a separate service provider with its own metadata endpoint. This
registration covers one application:

- **[FILL IN]** Application name:
- **[FILL IN]** Environment: staging / production
- **[FILL IN]** Entity ID: `https://<host>/auth/v1/sso/saml/metadata`
- **[FILL IN]** ACS URL: `https://<host>/auth/v1/sso/saml/acs`
- **[FILL IN]** Metadata: `https://<host>/auth/v1/sso/saml/metadata`

Where `<host>` is either `<project-ref>.supabase.co` or a custom domain such as
`auth.supabase.ucsd.edu`.

Additional applications will be registered under separate tickets.

**How do you handle guest accounts?**

We do not support guest accounts. All users authenticate via UCSD SSO. There is no
anonymous or unauthenticated access.
