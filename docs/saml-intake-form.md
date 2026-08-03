# SAML Vendor Intake Form — Supabase

Answers for a Supabase project using this toolkit. Copy into
[SAMLVendorIntakeForm.docx](./SAMLVendorIntakeForm.docx) and attach to the ticket.

**[FILL IN]** marks the per-app answers.

---

**Q. Is the vendor an InCommon Federation member?**

**A.** No. Supabase is a commercial platform (supabase.com).

**Q. If not — do you consume InCommon metadata?**

**A.** No. We consume UCSD IdP metadata directly.

**Q. What SAML implementation do you use?**

**A.** Other: Supabase Auth (GoTrue), an open-source auth server with built-in SAML 2.0
SP support.

**Q. What is the primary user population?**

**A. [FILL IN]** — students / faculty & staff / non-employee affiliates.

**Q. Do you support the standard eduPerson / "OID" style attribute names?**

**A.** Yes. We accept both OID-style and `urn:mace:ucsd.edu:sso:*` names. Attribute
mapping is configured on our side at registration time.

**Q. What are your required / optional SAML attributes?**

**A.** The standard UCSD SSO attribute set, plus `memberOf`.

Please release `memberOf` as a multi-valued attribute containing the user's complete
group list. We capture only the first value if the groups arrive as a single
concatenated string.

**Q. What do you use as the primary user identifier?**

**A.** ePPN (`urn:oid:1.3.6.1.4.1.5923.1.1.1.6`). Sending it as a 32-character opaque
value rather than `user@ucsd.edu` works for us.

**Q. Can you handle a primary user identifier of 32+ characters?**

**A.** Yes. Stored as unbounded text in Postgres.

**Q. Do you have any special SAML NameID requirements?**

**A.** Yes. The format must be `persistent` or `emailAddress`. Supabase rejects
`transient`, and a NameID that changes each login would create a new account on every
sign-in.

**Q. How are user accounts provisioned?**

**A.** On demand, the first time a user authenticates.

**Q. How are admin accounts provisioned?**

**A.** Same as regular users. Admin roles are assigned inside the application, not at
provisioning time.

**Q. Who are your primary contacts for these areas?**

**A. [FILL IN]** — technical, support, administrative.

**Q. How do you handle user logout?**

**A.** Local logout plus redirect to a configurable URL. The app clears its session,
then redirects to the UCSD IdP logout endpoint. We do not implement SAML 2 Single
Logout — Supabase Auth does not support it.

**Q. Can you supply SAML metadata for your QA and production environments?**

**A.** Yes. Each application is a separate service provider with its own metadata
endpoint. This registration covers one application:

- **[FILL IN]** Application name
- **[FILL IN]** Environment — staging / production
- **[FILL IN]** Entity ID — `https://<host>/auth/v1/sso/saml/metadata`
- **[FILL IN]** ACS URL — `https://<host>/auth/v1/sso/saml/acs`

`<host>` is `<project-ref>.supabase.co` or a custom domain such as
`auth.supabase.ucsd.edu`. Additional applications will be registered under separate
tickets.

**Q. How do you handle guest accounts?**

**A.** None. All users authenticate via UCSD SSO. There is no anonymous access.
