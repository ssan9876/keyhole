import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  // Argon2id at 64 MiB is roughly half a second per derivation, and these
  // journeys do several. The cost is the feature; the timeout accommodates it.
  timeout: 120_000,
  expect: { timeout: 20_000 },
  // One worker: every journey drives the same server on the same port, and the
  // whole point is a real single-writer SQLite database.
  workers: 1,
  use: {
    baseURL: "http://127.0.0.1:5173",
    trace: "retain-on-failure",
  },
  webServer: {
    // --host 127.0.0.1 is required: Vite's default "localhost" host resolves
    // to the IPv6 loopback (::1) on this machine, so it never satisfies a
    // health check or baseURL pinned to the IPv4 127.0.0.1 used here and in
    // e2e/server.ts's proxy target. Without it, `webServer` times out after
    // 60s even though `vite` is running and reachable at http://localhost:5173.
    command: "pnpm dev --port 5173 --host 127.0.0.1",
    url: "http://127.0.0.1:5173",
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
