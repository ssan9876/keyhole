import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    // jsdom, not node: every module in this package is framework-free and
    // DOM-free by construction, and stays that way -- but several tests
    // moved from apps/web (session.test.ts, enroll.test.ts, unlock.test.ts,
    // recover.test.ts) assert the *absence* of any write to localStorage /
    // sessionStorage as their proof that key material never leaves memory,
    // and that proof needs a real Storage global to check. This is a test
    // environment choice only; it does not let production code depend on a
    // DOM global; there is no jsdom import anywhere under src/**/*.ts.
    environment: "jsdom",
    include: ["src/**/*.test.ts"],
    // Argon2id at 64 MiB is deliberately slow; anything touching the crypto
    // package needs headroom.
    testTimeout: 30_000,
  },
});
