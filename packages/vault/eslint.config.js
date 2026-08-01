import tseslint from "typescript-eslint";

// No `@keyhole/crypto` restriction here, deliberately. This is the layer that
// is *supposed* to import it; the ban belongs to apps/web/src/ui, which is
// where it remains.
export default tseslint.config(
  {
    files: ["src/**/*.ts"],
    extends: [tseslint.configs.recommended],
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
  {
    // This package must run inside an MV3 extension service worker, which
    // has no DOM and therefore no `localStorage`/`sessionStorage`. The
    // tsconfig "WebWorker" lib swap already rejects `document`/`window`, but
    // it cannot catch these two: `@types/node` declares both globally and
    // that declaration is pulled in transitively, so tsc sees them as valid
    // regardless of "lib". This rule is the only gate that actually catches
    // them.
    //
    // Scoped to production sources only: session.test.ts, unlock.test.ts,
    // recover.test.ts, and enroll.test.ts legitimately reference
    // localStorage/sessionStorage to prove the session persists nothing.
    files: ["src/**/*.ts"],
    ignores: ["src/**/*.test.ts"],
    rules: {
      "no-restricted-globals": [
        "error",
        {
          name: "localStorage",
          message:
            "This package must run in an MV3 service worker, which has no " +
            "DOM and no localStorage. Take a PreferenceStore (or equivalent) " +
            "as an argument instead.",
        },
        {
          name: "sessionStorage",
          message:
            "This package must run in an MV3 service worker, which has no " +
            "DOM and no sessionStorage. Take a PreferenceStore (or " +
            "equivalent) as an argument instead.",
        },
      ],
    },
  },
);
