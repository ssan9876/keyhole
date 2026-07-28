import { expect, test } from "@playwright/test";
import { startServer, type RunningServer } from "./server.js";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

const MASTER_PASSWORD = "correct horse battery staple";

// Serial, deliberately: all three tests share one server and one SQLite
// database (server.js starts it once in beforeAll above), and the third test
// below depends on the item the first one creates. Running them in parallel
// or out of order is not an option here -- test.describe.serial just makes
// that dependency explicit and turns a failure in an earlier test into a
// skip for the ones after it, instead of a second, confusing failure with a
// different symptom.
test.describe.serial("vault", () => {
  test("enrol, create an item, reload, and read it back decrypted", async ({ page }) => {
    // The one journey that can catch a broken crypto-server contract: byte-exact
    // KDF params, base64 handling, the revision cursor. A mocked test would pass
    // with every one of them wrong.
    const invitePath = new URL(server.inviteUrl).pathname;
    await page.goto(invitePath);

    await page.getByLabel(/email/i).fill(server.email);
    await page.getByLabel(/^master password/i).fill(MASTER_PASSWORD);
    await page.getByLabel(/confirm/i).fill(MASTER_PASSWORD);
    await page.getByRole("button", { name: /set master password/i }).click();

    // The recovery code is shown once and gated behind an acknowledgement.
    await expect(page.getByText(/save your recovery code/i)).toBeVisible();
    await page.getByLabel(/saved/i).check();
    await page.getByRole("button", { name: /continue/i }).click();

    await page.getByRole("button", { name: /add an item/i }).click();
    // Anchored: /name/i would also match "Username" and trip Playwright's strict
    // mode with two candidates.
    await page.getByLabel(/^name$/i).fill("Example Service");
    await page.getByLabel(/username/i).fill("person@example.com");
    await page.getByLabel(/^password/i).fill("s3cr3t-value");
    await page.getByRole("button", { name: /save/i }).click();
    await expect(page.getByText("Example Service")).toBeVisible();

    // A reload throws away every key: they were memory-only, by design.
    await page.reload();
    await expect(page.getByLabel(/master password/i)).toBeVisible();

    await page.getByLabel(/master password/i).fill(MASTER_PASSWORD);
    await page.getByRole("button", { name: /^unlock$/i }).click();

    await expect(page.getByText("Example Service")).toBeVisible();
    await page.getByText("Example Service").click();
    await page.getByRole("button", { name: /reveal|show/i }).click();
    // The round trip completed: encrypted here, stored opaque, decrypted here.
    await expect(page.getByLabel(/^password/i)).toHaveValue("s3cr3t-value");

    // keyhole.autolock is written lazily -- only when the user actually changes
    // the setting (src/vault/autolock.ts: readAutoLock falls back to a default
    // rather than the app ever writing one on boot). Touch Settings so both of
    // the app's only two persisted keys have had their chance to land before
    // the exact-set assertion below.
    await page.getByRole("button", { name: /^settings$/i }).click();
    await page.getByLabel(/auto-lock/i).selectOption("30");

    // Design spec §6.3: decrypted keys live in memory only, never in
    // localStorage, sessionStorage, or IndexedDB. This is a code-review gate in
    // the spec; asserting it here makes it a gate that actually runs on every
    // test, not just once by hand in a browser. The vault has been unlocked,
    // used, and an item saved and revealed by this point, so anything the app
    // would ever persist has had its chance to land.
    const storageState = await page.evaluate(async () => {
      const databases = (await indexedDB.databases?.()) ?? [];
      return {
        localStorageKeys: Object.keys(localStorage).sort(),
        sessionStorageKeys: Object.keys(sessionStorage),
        indexedDbNames: databases.map((db) => db.name),
      };
    });
    // Comparing the sorted array (not just checking absence of key material)
    // means an unexpected *added* key fails this assertion instead of being
    // silently ignored.
    expect(storageState.localStorageKeys).toEqual(["keyhole.autolock", "keyhole.email"]);
    expect(storageState.sessionStorageKeys).toEqual([]);
    expect(storageState.indexedDbNames).toEqual([]);
  });

  test("a wrong master password is reported honestly", async ({ page }) => {
    await page.goto("/");
    // Each Playwright test gets a fresh browser context, so localStorage is empty
    // and the email field is present. Filling only the password would fail the
    // form's own required check and never reach the server.
    await page.getByLabel(/email/i).fill(server.email);
    await page.getByLabel(/master password/i).fill("not the password");
    await page.getByRole("button", { name: /^unlock$/i }).click();

    // Design spec 9: a network blip must never read as a wrong password, and a
    // wrong password must not read as a server fault.
    await expect(page.getByRole("alert")).toContainText(/wrong master password/i);
  });

  test("the vault survives a locked and re-unlocked session", async ({ page }) => {
    await page.goto("/");
    await page.getByLabel(/email/i).fill(server.email);
    await page.getByLabel(/master password/i).fill(MASTER_PASSWORD);
    await page.getByRole("button", { name: /^unlock$/i }).click();
    await expect(page.getByText("Example Service")).toBeVisible();

    await page.getByRole("button", { name: /^lock$/i }).click();
    await expect(page.getByLabel(/master password/i)).toBeVisible();
    // Locking must clear the list, not merely navigate away from it.
    await expect(page.getByText("Example Service")).not.toBeVisible();

    await page.getByLabel(/master password/i).fill(MASTER_PASSWORD);
    await page.getByRole("button", { name: /^unlock$/i }).click();
    await expect(page.getByText("Example Service")).toBeVisible();
  });
});
