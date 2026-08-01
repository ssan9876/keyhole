import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    // The whole of src, not just the UI layer. Until this object existed
    // `eslint .` applied *no rule at all* to `src/ui/**`'s neighbours: the
    // single config below matched only `src/ui/**`, so `src/sw/`, `src/platform/`,
    // and `main.tsx` were linted by nothing.
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
    // Narrower than the object above, and it must stay that way. The vault
    // layer now lives in packages/vault, which is the layer allowed to import
    // crypto; this ban applies to the UI only.
    files: ["src/ui/**/*.{ts,tsx}"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          paths: [
            {
              name: "@keyhole/crypto",
              message:
                "UI code must not touch crypto directly. Go through " +
                "@keyhole/vault, which is the only layer allowed to hold key " +
                "material.",
            },
          ],
        },
      ],
    },
  },
);
