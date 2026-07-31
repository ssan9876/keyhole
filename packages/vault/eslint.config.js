import tseslint from "typescript-eslint";

// No `@keyhole/crypto` restriction here, deliberately. This is the layer that
// is *supposed* to import it; the ban belongs to apps/web/src/ui, which is
// where it remains.
export default tseslint.config({
  files: ["src/**/*.ts"],
  extends: [tseslint.configs.recommended],
  rules: {
    "@typescript-eslint/no-unused-vars": [
      "error",
      { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
    ],
  },
});
