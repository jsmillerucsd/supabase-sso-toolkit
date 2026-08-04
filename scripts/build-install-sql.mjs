/**
 * Concatenates the SQL modules into sql/install.sql — the single file apps run.
 *
 * The modules stay the source of truth so they can be reviewed and edited in
 * isolation; this keeps the shipped installer from drifting away from them.
 */
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const SQL_DIR = "sql";
const OUT = join(SQL_DIR, "install.sql");

const modules = readdirSync(SQL_DIR)
  .filter((f) => /^\d{4}_.+\.sql$/.test(f))
  .sort();

const version = JSON.parse(readFileSync("package.json", "utf8")).version;

const header = `-- ==============================================================================
-- @jsmillerucsd/supabase-sso v${version} — install
-- ==============================================================================
-- GENERATED FILE. Edit the modules in sql/ and run \`npm run build:sql\`.
--
-- Run this once against your Supabase project. It is idempotent: re-running it
-- is how you upgrade, and re-running the same version is a no-op.
--
-- Modules included:
${modules.map((m) => `--   ${m}`).join("\n")}
--
-- After running, enable the auth hook:
--   Dashboard > Authentication > Hooks > Customize Access Token
--   pg-functions://postgres/private/custom_access_token_hook
--
-- Check what is installed at any time:
--   SELECT * FROM public.toolkit_version();
-- ==============================================================================

`;

const body = modules
  .map((m) => readFileSync(join(SQL_DIR, m), "utf8").trimEnd())
  .join("\n\n\n");

writeFileSync(OUT, `${header}${body}\n`, "utf8");
console.log(`wrote ${OUT} (${modules.length} modules)`);
