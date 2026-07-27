import tseslint from "typescript-eslint";

export default tseslint.config({
  files: ["src/ui/**/*.{ts,tsx}"],
  // Without this, ESLint has no TypeScript/JSX-aware parser for these files:
  // it falls back to the default parser and every file in src/ui fails with a
  // parse error before any rule — including no-restricted-imports below — ever
  // runs. That made the crypto-import gate this config exists for entirely
  // unenforced the moment src/ui gained real .tsx files.
  extends: [tseslint.configs.recommended],
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
    // A leading underscore is the standard "intentionally unused" convention
    // (used by the VaultScreen placeholder's `_props`, which Task 8 replaces
    // wholesale) — without this, the recommended rule above would force every
    // not-yet-wired prop to be referenced just to satisfy the linter.
    "@typescript-eslint/no-unused-vars": [
      "error",
      { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
    ],
  },
});
