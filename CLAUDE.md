# CLAUDE.md — developing this package

This file is for agents working on the toolkit itself. For agents *using* the
package in an app, the shipped guide is AGENTS.md (also in the npm tarball).

## Commands

- `npm run build` — regenerates `sql/install.sql`, then tsup (ESM+CJS+dts).
- `npm run typecheck` — `tsc --noEmit`.
- `npm test` — stages `dev/supabase/` from the generated installer + `tests/db/`,
  then `supabase db reset && supabase test db` (pgTAP). Requires Docker and the
  Supabase CLI; the local stack lives in `dev/`. If `db reset` fails at
  "Restarting containers" because non-DB services are stopped, the migrations
  already applied — run `cd dev && supabase test db` directly.
- CI (`.github/workflows/test.yml`) runs typecheck, build, and the pgTAP suite
  on every push/PR.

## Hard rules

- **Never edit `sql/install.sql`** — it is generated from the `sql/000x_*.sql`
  modules by `scripts/build-install-sql.mjs` (which also stamps the package
  version into every `register_module` call). Edit modules, then rebuild.
- **Everything in `sql/` must stay idempotent.** Re-running a newer
  `install.sql` is the upgrade path. New objects need `IF NOT EXISTS` /
  `CREATE OR REPLACE` / guarded DO blocks; removed objects need explicit
  `DROP ... IF EXISTS` so upgrades clean them.
- **Keep the pgTAP plan counts in sync** — each `tests/db/*.sql` declares
  `plan(N)`; adding assertions without bumping N fails the file.
- **UCSD-specific knowledge lives only in `sql/0006_ucsd_adapter.sql`** (SQL)
  — everything else is campus-agnostic. The adapter's `custom_claims` key
  names are the counterpart of `sql/assets/ucsd-attribute-mapping.json` (fed
  to `supabase sso add`); change them together. Known exception: the default
  `idpLogoutUrl` in `src/core/config.ts` is UCSD's, accepted because the
  package is UCSD-scoped.
- **The auth hook must never raise and must stay cheap** — it runs on every
  token mint with a ~2s budget; roles are derived at write time
  (`recompute_user_claims`), never inside the hook.
- **Preserve the read-source rule**: attributes project from
  `auth.identities.identity_data` (server-written, replaced wholesale), never
  from `raw_user_meta_data` (client-writable, merge-ratchet). RLS helpers read
  top-level JWT claims, never `user_metadata`/`app_metadata`.
  `tests/db/01_read_source.sql` exists to make regressions here impossible —
  do not weaken it.
- **Fail-open on the sign-in path**: projection errors log to
  `private.sync_errors` and degrade the user to zero roles; they must never
  block authentication. Don't bump `synced_at` on failure — it means "last
  successful projection".

## Architecture seams

- `private.extract_attributes(jsonb)` — the campus-adapter seam. 0002 ships a
  generic version; 0006 `CREATE OR REPLACE`s it. Another campus writes its own
  0006-equivalent.
- `private.recompute_user_claims(uuid)` — the composition seam. 0002 ships a
  stub (roles always empty); 0004 replaces it with the four-source union
  (manual grants, AD groups, emplid, home dept). 0004 is genuinely optional.
- Role expiry is handled by `private.recompute_stale_expiries()` scheduled
  hourly via pg_cron (guarded; warns if pg_cron is absent). Claims are
  materialized, so nothing else makes an expiry take effect.

## TS packaging notes

- `src/nextjs` is server-only (imports `next/server`); `src/react` is client
  ("use client" is applied as a tsup banner in its own config entry — the
  rollup treeshake pass strips banners, hence `treeshake: false` there).
- Peer deps `@supabase/ssr`, `next`, `react` are optional; core must stay
  importable without them.
