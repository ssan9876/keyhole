import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["./src/test-setup.ts"],
    // Argon2id at 64 MiB is deliberately slow; anything touching the crypto
    // package needs headroom.
    testTimeout: 30_000,
  },
});
