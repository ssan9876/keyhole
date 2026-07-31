import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    // Node, not jsdom: every module in this package is framework-free and
    // DOM-free by construction. If a test here ever needs jsdom, something
    // that belongs in apps/web has been moved in by mistake.
    environment: "node",
    include: ["src/**/*.test.ts"],
    // Argon2id at 64 MiB is deliberately slow; anything touching the crypto
    // package needs headroom.
    testTimeout: 30_000,
  },
});
