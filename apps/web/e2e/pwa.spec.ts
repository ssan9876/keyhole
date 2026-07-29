import { execSync } from "node:child_process";
import { resolve } from "node:path";
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { startServer, type RunningServer } from "./server.js";

// apps/web — where `pnpm build` (vite build) runs and writes the built app into
// internal/webui/dist, which the Go binary embeds.
const WEB_DIR = resolve(import.meta.dirname, "..");

const MASTER_PASSWORD = "correct horse battery staple";
const ITEM_NAME = "Example Service";
// An invented marker, never a real credential (global constraint). The entire
// leak assertion turns on searching cached bytes for this exact string, so it
// must be one that could not appear inside a shell asset by accident.
const ITEM_PASSWORD = "leak-canary-7Qv3ndalf-do-not-cache";

let server: RunningServer;
let context: BrowserContext;
let page: Page;

function url(path: string): string {
  return `${server.baseUrl}${path}`;
}

// Serial and sharing one browser context: the whole point is a single device on
// which a service worker installs, caches the shell, is used against a real
// vault, and is then inspected. A fresh per-test context (Playwright's default)
// would throw away the SW, the caches, and localStorage between steps, so the
// leak assertion would have nothing to inspect.
test.describe.serial("PWA: installable, loads offline, leaks nothing", () => {
  test.beforeAll(async ({ browser }) => {
    // THE service worker is production-only (registerServiceWorker guards on
    // import.meta.env.PROD), so the Vite dev server the other specs run against
    // never registers it. This spec therefore serves the BUILT app: `pnpm
    // build` writes internal/webui/dist, and startServer() compiles and runs
    // the Go binary that embeds that dist — the same binary an operator ships.
    // If the app were not built, the binary would serve a placeholder with no
    // service worker, and every assertion below would pass vacuously; building
    // here is what makes the SW real. We serve it on the Go origin
    // (http://127.0.0.1:8477) so the app, its /api, its manifest and its SW are
    // all one same-origin build — no dev proxy in the picture.
    execSync("pnpm build", { cwd: WEB_DIR, stdio: "inherit" });
    server = await startServer();
    context = await browser.newContext();
    page = await context.newPage();
  });

  test.afterAll(async () => {
    await context?.close();
    server?.stop();
  });

  test("serves a valid manifest and activates a service worker from the built app", async () => {
    // Use the app so there is real vault data on the device before the disk is
    // inspected: enrol, then create an item whose password is the leak canary.
    const invitePath = new URL(server.inviteUrl).pathname;
    await page.goto(url(invitePath));

    await page.getByLabel(/email/i).fill(server.email);
    await page.getByLabel(/^master password/i).fill(MASTER_PASSWORD);
    await page.getByLabel(/confirm/i).fill(MASTER_PASSWORD);
    await page.getByRole("button", { name: /set master password/i }).click();

    await expect(page.getByText(/save your recovery code/i)).toBeVisible();
    await page.getByLabel(/saved/i).check();
    await page.getByRole("button", { name: /continue/i }).click();

    await page.getByRole("button", { name: /add an item/i }).click();
    // Anchored /^name$/ so it does not also match "Username", per vault.spec.ts.
    await page.getByLabel(/^name$/i).fill(ITEM_NAME);
    await page.getByLabel(/username/i).fill("person@example.com");
    await page.getByLabel(/^password/i).fill(ITEM_PASSWORD);
    await page.getByRole("button", { name: /save/i }).click();
    await expect(page.getByText(ITEM_NAME)).toBeVisible();

    // The manifest the Go binary actually serves, parsed and shaped: an
    // unparseable or icon-less manifest is not installable, and nothing but a
    // check against the served bytes would catch a manifest the build dropped.
    const manifestRes = await page.request.get(url("/manifest.webmanifest"));
    expect(manifestRes.ok()).toBe(true);
    const manifest = JSON.parse(await manifestRes.text()) as {
      name?: string;
      start_url?: string;
      display?: string;
      icons?: unknown[];
    };
    expect(manifest.name).toBe("Keyhole");
    expect(manifest.start_url).toBe("/");
    expect(manifest.display).toBe("standalone");
    expect(Array.isArray(manifest.icons)).toBe(true);
    expect(manifest.icons?.length ?? 0).toBeGreaterThan(0);

    // The service worker must reach "activated". If it never does, this poll
    // times out and the test FAILS — a skip or a vacuous pass here would make
    // every offline and leak assertion below meaningless. Argon2id enrolment
    // already ran, so activation has had ample time; the timeout is generous
    // anyway.
    await expect
      .poll(
        () =>
          page.evaluate(async () => {
            const registration = await navigator.serviceWorker.getRegistration();
            return registration?.active?.state ?? null;
          }),
        { timeout: 30_000, message: "the service worker never reached 'activated'" },
      )
      .toBe("activated");
  });

  test("loads offline and reaches the unlock screen with the honest offline message", async () => {
    // Reload while online first: the page is now controlled by the SW from its
    // first byte, so the unlock that follows drives prelogin, login and sync —
    // every one an /api request routed through the SW's bypass rule. This is
    // what makes the "no /api entry" assertion in the next test a statement
    // about requests the SW actually handled, not requests it never saw.
    await page.reload();
    await page.getByLabel(/master password/i).fill(MASTER_PASSWORD);
    await page.getByRole("button", { name: /^unlock$/i }).click();
    await expect(page.getByText(ITEM_NAME)).toBeVisible();

    // Cut the network and reload. The shell must still load — served from the
    // SW cache — and reach the unlock screen, not a browser error page.
    await context.setOffline(true);
    await page.reload({ waitUntil: "domcontentloaded" });

    await expect(page.getByRole("heading", { name: /unlock your vault/i })).toBeVisible();
    // The vault is deliberately NOT populated offline, so nothing from the
    // last session is on screen — that is the design, not a bug.
    await expect(page.getByText(ITEM_NAME)).toHaveCount(0);

    // Attempt to unlock offline. prelogin cannot reach the server, so the vault
    // layer raises a NetworkError and the screen must say so honestly — the
    // offline message, not a wrong-password or a generic server error. (Playwright's
    // setOffline fails requests but does not flip navigator.onLine, so this
    // asserts the error path rather than the proactive navigator.onLine banner,
    // which has its own unit coverage.)
    await page.getByLabel(/master password/i).fill(MASTER_PASSWORD);
    await page.getByRole("button", { name: /^unlock$/i }).click();
    await expect(page.getByRole("alert")).toContainText(
      /you're offline\. connect to load your vault\./i,
    );
    await expect(page.getByText(ITEM_NAME)).toHaveCount(0);
  });

  test("leaves no vault on disk: IndexedDB empty, cache holds the shell but no /api entry or plaintext", async () => {
    const disk = await page.evaluate(async (marker) => {
      const databases = (await indexedDB.databases?.()) ?? [];
      const cacheNames = await caches.keys();
      const urls: string[] = [];
      let anyBodyHasMarker = false;
      for (const name of cacheNames) {
        const cache = await caches.open(name);
        for (const request of await cache.keys()) {
          urls.push(request.url);
          const response = await cache.match(request);
          if (response) {
            const body = await response.text();
            if (body.includes(marker)) anyBodyHasMarker = true;
          }
        }
      }
      return {
        indexedDbNames: databases.map((db) => db.name ?? ""),
        cacheNames,
        urls,
        anyBodyHasMarker,
      };
    }, ITEM_PASSWORD);

    // Nothing decryptable, and nothing about the vault at all, is written to
    // disk: the memory-only session is the device-theft defence, so IndexedDB
    // stays empty (design spec §6.3, and the plan's shell-only narrowing of
    // §6.5 that keeps even encrypted vault bytes off the disk).
    expect(disk.indexedDbNames).toEqual([]);

    // Non-vacuous guard: the SW must have precached the shell. Without this, the
    // "no /api entry" assertion below could be true simply because nothing was
    // cached — the exact way a SW that never activated would fake a pass.
    expect(disk.cacheNames.length).toBeGreaterThan(0);
    expect(disk.urls.some((entry) => new URL(entry).pathname.startsWith("/assets/"))).toBe(true);

    // THE rule this whole plan turns on, proved against a real browser: the SW
    // handled the unlock/sync /api requests above and cached none of them.
    const apiUrls = disk.urls.filter((entry) => new URL(entry).pathname.startsWith("/api"));
    expect(apiUrls).toEqual([]);

    // And no cached body carries the item password placed in the vault this run.
    expect(disk.anyBodyHasMarker).toBe(false);
  });
});
