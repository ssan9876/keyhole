import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    // The whole of src, not just the UI layer. `src/vault/` holds the parsing,
    // crypto-adjacent, and network code — the half of this app where a mistake
    // costs a password rather than a misaligned button — and until this object
    // existed `eslint .` applied *no rule at all* to any of it: the single
    // config below matched only `src/ui/**`, so `src/vault/**` and `main.tsx`
    // were linted by nothing. `src/vault/import/` is about to grow ten format
    // parsers whose only other gates are `tsc` and their own tests.
    files: ["src/**/*.{ts,tsx}"],
    // Without this, ESLint has no TypeScript/JSX-aware parser for these files:
    // it falls back to the default parser and every file fails with a parse
    // error before any rule — including no-restricted-imports below — ever
    // runs. That made the crypto-import gate this config exists for entirely
    // unenforced the moment src/ui gained real .tsx files.
    extends: [tseslint.configs.recommended],
    rules: {
      // A leading underscore is the standard "intentionally unused" convention
      // — without this, the recommended rule above would force every
      // not-yet-wired prop or deliberately-ignored binding to be referenced
      // just to satisfy the linter.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
  {
    // Deliberately *narrower* than the object above, and it must stay that way.
    // `src/vault/` is the layer that is supposed to import `@keyhole/crypto`;
    // widening this rule to all of src would ban the design rather than protect
    // it, and the only way to satisfy it would be to move key handling
    // somewhere worse.
    files: ["src/ui/**/*.{ts,tsx}"],
    rules: {
      // Design spec 6.3 calls the memory-only rule "a code-review gate, not a
      // guideline". This is that gate, mechanised: if the UI cannot reach the
      // crypto package, it cannot hold a key by accident, and a violation fails
      // the build instead of depending on a reviewer noticing.
      "no-restricted-imports": [
        "error",
        {
          paths: [
            {
              name: "@keyhole/crypto",
              message:
                "UI code must not touch crypto directly. Go through src/vault/, " +
                "which is the only layer allowed to hold key material.",
            },
          ],
        },
      ],
    },
  },
);
