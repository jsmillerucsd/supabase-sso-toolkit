# Building admin RPCs — worked example

The toolkit deliberately ships **no admin API**: which roles exist and who
grants them is an app decision. What it does ship is everything an admin API
needs to be safe — the `private.*` tables, the recompute triggers, and the two
authorization guards:

| Guard | Checks | Use for |
|---|---|---|
| `private.require_admin_read()` | JWT only (fast, stale ≤ one token lifetime) | List/read RPCs |
| `private.require_admin_write()` | JWT **and** live DB | Anything that mutates — a revoked admin loses write access immediately |

This page is a complete, copy-paste starting point. Adjust names, keep the
patterns. Every function below follows four rules — keep all four in yours:

1. `SECURITY DEFINER` — the caller has no direct access to `private.*`.
2. `SET search_path = ''` — mandatory hygiene for SECURITY DEFINER; forces
   fully-qualified names and blocks search-path hijacking.
3. First statement is a guard call. No guard, no function body.
4. Explicit grants: `REVOKE ... FROM public, anon`, `GRANT ... TO authenticated`.
   Authorization happens inside via the guard (it raises `42501` for
   non-admins), so `authenticated` is the correct outer grant.

You never call `recompute` yourself: the toolkit's statement triggers on
`user_roles` and the mapping tables recompute affected users' claims on every
write. Your RPC just writes the row.

## The RPCs

```sql
-- ==============================================================================
-- Example admin RPCs on top of @jsmillerucsd/supabase-sso. Copy and adapt.
-- ==============================================================================

-- Define a role this app knows about.
CREATE OR REPLACE FUNCTION public.admin_create_role(p_role text, p_description text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  PERFORM private.require_admin_write();
  INSERT INTO private.app_roles (role, description)
  VALUES (p_role, p_description)
  ON CONFLICT (role) DO UPDATE SET description = EXCLUDED.description;
END;
$$;

-- Grant a role to a user, optionally with an expiry. Claims recompute
-- automatically; the expiry sweep (private.recompute_stale_expiries) drops it
-- on time even if nothing else changes.
CREATE OR REPLACE FUNCTION public.admin_grant_role(
  p_user_id    uuid,
  p_role       text,
  p_expires_at timestamptz DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  PERFORM private.require_admin_write();
  INSERT INTO private.user_roles (user_id, role, granted_by, expires_at)
  VALUES (p_user_id, p_role, (SELECT auth.uid())::text, p_expires_at)
  ON CONFLICT (user_id, role) DO UPDATE SET
    expires_at = EXCLUDED.expires_at,
    granted_by = EXCLUDED.granted_by,
    granted_at = now();
END;
$$;

CREATE OR REPLACE FUNCTION public.admin_revoke_role(p_user_id uuid, p_role text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  PERFORM private.require_admin_write();
  DELETE FROM private.user_roles
  WHERE user_id = p_user_id AND role = p_role;
END;
$$;

-- Map an AD group CN to a role. Same shape works for
-- private.emplid_role_mappings and private.dept_code_role_mappings.
CREATE OR REPLACE FUNCTION public.admin_map_ad_group(p_ad_group_cn text, p_role text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  PERFORM private.require_admin_write();
  INSERT INTO private.ad_group_role_mappings (ad_group_cn, role)
  VALUES (p_ad_group_cn, p_role)
  ON CONFLICT (ad_group_cn, role) DO NOTHING;
END;
$$;

-- Everyone's effective roles, joined to who they are. Read guard: JWT only.
CREATE OR REPLACE FUNCTION public.admin_list_user_roles()
RETURNS TABLE (
  user_id            uuid,
  display_identifier text,
  full_name          text,
  app_roles          text[],
  dept_codes         text[],
  computed_at        timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  PERFORM private.require_admin_read();
  RETURN QUERY
  SELECT ec.user_id, ua.display_identifier, ua.full_name,
         ec.app_roles, ec.dept_codes, ec.computed_at
  FROM private.user_effective_claims ec
  LEFT JOIN private.user_attributes ua ON ua.user_id = ec.user_id
  ORDER BY ua.display_identifier;
END;
$$;

-- Recent projection/recompute failures — the fail-open evidence trail.
CREATE OR REPLACE FUNCTION public.admin_list_sync_errors(p_limit int DEFAULT 50)
RETURNS TABLE (id bigint, user_id uuid, source text, detail text, occurred_at timestamptz)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  PERFORM private.require_admin_read();
  RETURN QUERY
  SELECT e.id, e.user_id, e.source, e.detail, e.occurred_at
  FROM private.sync_errors e
  ORDER BY e.occurred_at DESC
  LIMIT p_limit;
END;
$$;

-- ------------------------------------------------------------------------------
-- Grants — same pattern for every RPC above
-- ------------------------------------------------------------------------------
DO $$
DECLARE
  fn text;
BEGIN
  FOREACH fn IN ARRAY ARRAY[
    'public.admin_create_role(text, text)',
    'public.admin_grant_role(uuid, text, timestamptz)',
    'public.admin_revoke_role(uuid, text)',
    'public.admin_map_ad_group(text, text)',
    'public.admin_list_user_roles()',
    'public.admin_list_sync_errors(int)'
  ] LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM public, anon', fn);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO authenticated', fn);
  END LOOP;
END;
$$;
```

## Bootstrapping the first admin

`require_admin_write()` needs an existing admin, so the very first grant cannot
go through the RPC. Seed it once, directly in SQL (migration or Studio SQL
editor), after that user has signed in at least once:

```sql
INSERT INTO private.user_roles (user_id, role, granted_by)
SELECT id, 'admin_role', 'bootstrap'
FROM auth.users
WHERE email = 'you@ucsd.edu'
ON CONFLICT (user_id, role) DO NOTHING;
```

The recompute trigger fires on that insert; the user gets `admin_role` in their
JWT at the next token refresh (sign out/in to force it).

## Calling from the client

```ts
const { error } = await supabase.rpc("admin_grant_role", {
  p_user_id: userId,
  p_role: "reviewer_role",
  p_expires_at: null,
});
// error.code === "42501" → caller is not an admin (or their grant was revoked:
// write RPCs check the live DB, not just the JWT).
```

## What NOT to do

- **Don't** expose the `private` schema to PostgREST to "make CRUD easier" —
  the whole trust model depends on RPCs being the only path in.
- **Don't** skip the guard in a "harmless" read RPC; attribute and role data is
  personal information.
- **Don't** gate writes with `require_admin_read()` — the read guard trusts the
  JWT, so a revoked admin would keep write access until their token expires.
- **Don't** write to `private.user_effective_claims` directly; it is derived
  state. Write to `user_roles`/mappings and let the triggers recompute.
