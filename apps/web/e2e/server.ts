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

/**
 * Boots a real keyhole server on a temporary database, bootstrapped exactly the
 * way an operator does it: build, migrate, admin create, then read the setup
 * link off stdout.
 *
 * The invite reaching the test as a printed URL is the point. A fixture that
 * injected a token straight into the database would skip the one step that
 * proves an operator can actually onboard someone.
 */
export function startServer(port = 8477): RunningServer {
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

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    inviteUrl: match[1] as string,
    email,
    stop: () => {
      child.kill();
    },
  };
}
