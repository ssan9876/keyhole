import tseslint from "typescript-eslint";

export default tseslint.config({
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
});
