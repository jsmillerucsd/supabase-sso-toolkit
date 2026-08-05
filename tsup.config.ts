import { defineConfig, type Options } from "tsup";

const shared: Options = {
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  splitting: false,
  treeshake: true,
  target: "es2022",
  platform: "neutral",
  external: ["next", "next/server", "react", "react/jsx-runtime", "@supabase/ssr", "@supabase/supabase-js"],
};

// The react entry builds in its own config so it can carry a `"use client"`
// banner (tsup strips the source-level directive when bundling, and Next.js
// App Router would otherwise treat the entry as a Server Component). A banner,
// unlike a post-build prepend, is applied before sourcemap generation. The
// banner must not be global — the nextjs entry is server-only.
export default defineConfig([
  {
    ...shared,
    entry: {
      index: "src/index.ts",
      nextjs: "src/nextjs/index.ts",
    },
    clean: true,
  },
  {
    ...shared,
    entry: { react: "src/react/index.tsx" },
    clean: false,
    // The rollup treeshake pass drops esbuild banners; the entry is tiny and
    // tree-shaken by consumers anyway, so trade it for a reliable directive.
    treeshake: false,
    banner: { js: '"use client";' },
  },
]);
