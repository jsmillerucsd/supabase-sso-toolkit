import { defineConfig } from "tsup";
import { readFileSync, writeFileSync } from "node:fs";

// Prepend `"use client"` to the react entry's runtime outputs. tsup strips the
// source-level directive when bundling, which would make Next.js App Router
// treat `@jsmillerucsd/supabase-sso/react` as a Server Component and fail on import.
function prependUseClient() {
  for (const f of ["dist/react.js", "dist/react.cjs"]) {
    const before = readFileSync(f, "utf8");
    if (!before.startsWith('"use client"')) {
      writeFileSync(f, `"use client";\n${before}`, "utf8");
    }
  }
}

export default defineConfig({
  entry: {
    index: "src/index.ts",
    nextjs: "src/nextjs/index.ts",
    react: "src/react/index.tsx",
  },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  target: "es2022",
  platform: "neutral",
  external: ["next", "next/server", "react", "react/jsx-runtime", "@supabase/ssr", "@supabase/supabase-js"],
  async onSuccess() {
    prependUseClient();
  },
});
