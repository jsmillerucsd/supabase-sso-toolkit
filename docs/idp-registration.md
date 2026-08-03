# Registering with the UCSD IdP

Each app is its own SAML service provider. One ticket per Supabase project.

## Before you file

| | |
|---|---|
| Supabase project ref | e.g. `abcdefghijklmnop` |
| Entity ID | `https://<host>/auth/v1/sso/saml/metadata` |
| ACS URL | `https://<host>/auth/v1/sso/saml/acs` |

`<host>` is `<project-ref>.supabase.co` or your custom domain.

Set up the custom domain first. Adding one later changes the Entity ID and means a
second ticket. → [Custom domains](https://supabase.com/docs/guides/platform/custom-domains)

## File the ticket

ServiceNow:

| | |
|---|---|
| Service | Access & Identity Management |
| Service offering | Single Sign-on |
| Assignment group | ITS-OIA-IAM-ShibSupport |

Attach [SAMLVendorIntakeForm.docx](./SAMLVendorIntakeForm.docx), filled in from
[saml-intake-form.md](./saml-intake-form.md).

Request staging first, then production once you have tested.

## Requirements to state explicitly

**NameID must be `persistent` or `emailAddress`.** Supabase rejects anything else.
`transient` is the usual Shibboleth default and changes on every login, which creates a
new account each time. Answering "no special requirements" tends to get you transient.

**`memberOf` must be multi-valued.** If groups arrive as one concatenated string we
capture a single group and AD-group role mapping silently under-grants
([supabase/auth#2332](https://github.com/supabase/auth/issues/2332)).

## Identifiers

Identity sends ePPN as a 32-character opaque value rather than `user@ucsd.edu`. The
toolkit never uses the subject as a display value or a join key, so this is fine.

Because the value is unreadable in a support screen,
[`derive_display_identifier()`](../sql/0002_identity_projection.sql) falls back:

```
eppn (if still user@domain) → ad_username → ucnet_id → email
```

`ad_username` and `ucnetid` are both in the standard release set.

## After they confirm

They send the IdP metadata URL. Continue at
[setup step 5](./setup.md#5-register-with-the-ucsd-idp).
