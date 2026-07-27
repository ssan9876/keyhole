import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const REPO_ROOT = resolve(import.meta.dirname, "../../..");
// Go is installed but not on this machine's PATH for tool shells.
const GO = process.platform === "win32" ? "C:\\Program Files\\Go\\bin\\go.exe" : "go";

export interface RunningServer {
  baseUrl: string;
  /** A working invite URL for a fresh admin account. */
  inviteUrl: string;
  email: string;
  stop(): void;
}

const READY_TIMEOUT_MS = 20_000;
const READY_POLL_INTERVAL_MS = 100;

/**
 * Polls /healthz until the server accepts connections and answers, or gives up.
 *
 * `spawn` returning is not the server being ready — it is the OS having
 * accepted the exec, with everything from Go runtime init to sqlite migration
 * checks still ahead of it. Nothing today waits for that gap to close before
 * the first `page.goto`, which makes an early request a race rather than a
 * guarantee. It has not flaked yet only because the gap has always been
 * smaller than the time it takes Playwright to get through `beforeAll` and
 * issue that first request.
 */
async function waitUntilReady(baseUrl: string): Promise<void> {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/healthz`);
      if (response.ok) return;
      lastError = new Error(`/healthz responded with status ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, READY_POLL_INTERVAL_MS));
  }
  throw new Error(
    `keyhole server at ${baseUrl} did not become ready within ${READY_TIMEOUT_MS}ms` +
      (lastError instanceof Error ? `: ${lastError.message}` : ""),
  );
}

/**
 * Boots a real keyhole server on a temporary database, bootstrapped exactly the
 * way an operator does it: build, migrate, admin create, then read the setup
 * link off stdout.
 *
 * The invite reaching the test as a printed URL is the point. A fixture that
 * injected a token straight into the database would skip the one step that
 * proves an operator can actually onboard someone.
 */
export async function startServer(port = 8477): Promise<RunningServer> {
  const dataDir = mkdtempSync(join(tmpdir(), "keyhole-e2e-"));
  const binary = join(dataDir, process.platform === "win32" ? "keyhole.exe" : "keyhole");
  const configPath = join(dataDir, "config.yml");

  writeFileSync(
    configPath,
    [
      `addr: 127.0.0.1:${port}`,
      `data_dir: ${dataDir}`,
      `base_url: http://127.0.0.1:5173`,
      `log_level: warn`,
      "",
    ].join("\n"),
  );

  execFileSync(GO, ["build", "-o", binary, "./cmd/keyhole"], { cwd: REPO_ROOT });
  execFileSync(binary, ["migrate", "--config", configPath]);

  const email = "e2e@example.com";
  const created = execFileSync(binary, [
    "admin",
    "create",
    "--email",
    email,
    "--config",
    configPath,
  ]).toString();

  const match = /(http:\/\/\S+\/enroll\/\S+)/.exec(created);
  if (match === null) {
    throw new Error(`No setup link in admin create output:\n${created}`);
  }

  const child: ChildProcess = spawn(binary, ["serve", "--config", configPath], {
    stdio: "ignore",
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  await waitUntilReady(baseUrl);

  return {
    baseUrl,
    inviteUrl: match[1] as string,
    email,
    stop: () => {
      child.kill();
    },
  };
}
