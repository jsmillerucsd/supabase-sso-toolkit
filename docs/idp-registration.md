# Registering your app with the UCSD IdP

Every app is its own SAML service provider and needs its own registration. There is no
shared endpoint to inherit — this is a ticket per Supabase project.

---

## 1. Before you file

Have these ready. The form asks for all of them.

| | |
|---|---|
| Supabase project ref | e.g. `abcdefghijklmnop` |
| Custom domain | optional, but set it up **first** — it changes your Entity ID |
| Entity ID | `https://<host>/auth/v1/sso/saml/metadata` |
| ACS URL | `https://<host>/auth/v1/sso/saml/acs` |

Where `<host>` is `<project-ref>.supabase.co` or your custom domain.

Set up the custom domain before filing. Adding one later changes the Entity ID and
means a second ticket.

→ [Supabase custom domains](https://supabase.com/docs/guides/platform/custom-domains)

---

## 2. File the ticket

ServiceNow:

| | |
|---|---|
| Service | Access & Identity Management |
| Service offering | Single Sign-on |
| Assignment group | ITS-OIA-IAM-ShibSupport |

Attach a completed intake form. Use [`saml-intake-form.md`](./saml-intake-form.md) —
it is pre-filled with everything that is the same for every Supabase app. You fill in
contacts, hostnames, and user population.

Ask for **staging first**, then a follow-up for production once you have tested.

---

## 3. What you get back

The IdP metadata URL for your environment, and confirmation that your SP is registered.
Then continue at [setup step 5](./setup.md#5-register-with-the-ucsd-idp).

---

## Two answers worth getting right

**NameID must be `persistent` or `emailAddress`.** Supabase rejects anything else, and
`transient` — the usual Shibboleth default — changes on every login, which would create
a new account each time. Answering "no special requirements" tends to get you transient.

**`memberOf` must be multi-valued.** If the groups arrive as one concatenated string we
capture a single group, and AD-group role mapping silently under-grants
([supabase/auth#2332](https://github.com/supabase/auth/issues/2332)).

---

## On the opaque uniqueID

Identity prefers to send ePPN as a 32-character opaque value rather than
`user@ucsd.edu`. That is fine — the toolkit never uses the subject as a display value
or a join key.

It does mean the identifier is unreadable in a support screen, so the toolkit falls
back automatically:

```
eppn (if still user@domain) → ad_username → ucnet_id → email
```

`ad_username` and `ucnetid` are both in the standard release set, so this works today.
