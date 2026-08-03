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
Then continue at step 4 of the [README](../README.md#4-register-the-ucsd-idp).

---

## Three answers that matter

The intake form has a few questions where a casual answer will cost you a round trip
or a broken integration.

**NameID format — must be `persistent` or `emailAddress`.** Supabase rejects anything
else. `transient` is the usual Shibboleth default, and it mints a *new user account on
every single login*, because the subject changes each time. If you answer "no special
requirements" you will likely get transient. Say so explicitly.

**`memberOf` must be released multi-valued, with all groups.** Supabase currently
captures only the first value of a multi-valued SAML attribute unless the mapping sets
`"array": true` ([supabase/auth#2332](https://github.com/supabase/auth/issues/2332)).
The shipped attribute mapping sets it. If the IdP sends groups as separate
`AttributeValue` elements and this is not configured on both ends, you get one group
per user and AD-group role mapping silently under-grants.

**`eduPersonAffiliation` has to be asked for by name.** It is not in the default
release set. Ask for `urn:oid:1.3.6.1.4.1.5923.1.1.1.1` explicitly or
`user_has_affiliation()` returns false for everyone, forever, with no error.

---

## Identity's preference on uniqueID

The identity team has said they prefer to send ePPN as a 32-character opaque
alphanumeric value rather than `user@ucsd.edu`. That is fine — the toolkit stores the
subject as unbounded text and never uses it as a display value or a join key.

But an opaque identifier is unreadable in an admin screen and cannot be matched to a
person by eye. The toolkit falls back automatically:

```
eppn (if it still looks like user@domain) → ad_username → ucnet_id → email
```

So make sure `ad_username` or `ucnetid` is in your release set. Both are in the default
UCSD attribute set today.
