/**
 * Stages the local verification stack: the generated installer plus the pgTAP
 * suite. Mirrors exactly what a consuming app does — one migration holding
 * install.sql — so the tests exercise the file that actually ships.
 */
import { copyFileSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

const MIGRATIONS = "dev/supabase/migrations";
const TESTS = "dev/supabase/tests";

for (const dir of [MIGRATIONS, TESTS]) {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
}

copyFileSync("sql/install.sql", join(MIGRATIONS, "20260101000000_sso_install.sql"));
copyFileSync("tests/db/00_fixtures.sql", join(MIGRATIONS, "20260101000001_sso_test_fixtures.sql"));

for (const f of readdirSync("tests/db").filter((f) => /^\d\d_/.test(f) && f !== "00_fixtures.sql")) {
  copyFileSync(join("tests/db", f), join(TESTS, f));
}

console.log("staged dev/supabase from sql/install.sql + tests/db");
