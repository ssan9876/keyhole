import { join } from "node:path";
import { expect, test } from "@playwright/test";
import { startServer, type RunningServer } from "./server.js";

let server: RunningServer;

test.beforeAll(async () => {
  // The default port, for the reason sharing.spec.ts spells out: vite.config's
  // /api proxy target is hardcoded to 127.0.0.1:8477.
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

const MASTER_PASSWORD = "correct horse battery staple";

// The generated Bitwarden export the parsers were built against. It carries two
// logins, a note, and a card Keyhole cannot store — so importing it exercises a
// per-row error in the same journey. No real credential appears in it (see the
// fixtures README).
const FIXTURE = join(import.meta.dirname, "../../../packages/vault/src/import/fixtures/bitwarden-export.json");

// The item whose password makes the whole trip. This exact string coming back
// out of a fresh unlock is the assertion this file exists for: it can only be
// there if the plaintext was encrypted in the browser, uploaded as ciphertext,
// synced back, and decrypted — the entire import pipeline in one value.
const ITEM_NAME = "Example Mail";
const ITEM_PASSWORD = "fixture-pw-8Hq2vN";

// The second readback, chosen because its password contains commas — the exact
// value a naive CSV split or an over-eager trim destroys. If any layer of the
// pipeline corrupted a password, this is the one it would corrupt.
const COMMA_ITEM_NAME = "Example Forum";
const COMMA_ITEM_PASSWORD = "fixture,pw,with,commas";

/**
 * The whole point of the import feature, proven end to end rather than mocked.
 *
 * A single journey: enrol, import a real Bitwarden export against a real server,
 * lock and reload so nothing is left in memory, unlock, and read one item's
 * password back out. Plus the storage invariant — an import is the largest
 * volume of plaintext this app ever handles, so it is the flow most likely to
 * leak something to disk, and the assertion is the exact key set, not merely
 * the absence of a known password.
 */
test("import a Bitwarden export against a real server, then read a password back after a fresh unlock", async ({
  page,
}) => {
  // Enrolment plus a later unlock: two Argon2id derivations at 64 MiB before
  // this test is done, each roughly half a second by design.
  test.setTimeout(180_000);

  await test.step("1. enrol and save the recovery code", async () => {
    await page.goto(new URL(server.inviteUrl).pathname);
    await page.getByLabel(/email/i).fill(server.email);
    await page.getByLabel(/^master password/i).fill(MASTER_PASSWORD);
    await page.getByLabel(/confirm/i).fill(MASTER_PASSWORD);
    await page.getByRole("button", { name: /set master password/i }).click();

    await expect(page.getByText(/save your recovery code/i)).toBeVisible();
    await page.getByLabel(/saved/i).check();
    await page.getByRole("button", { name: /continue/i }).click();
  });

  await test.step("2. upload the export and confirm the detected format", async () => {
    await page.getByRole("button", { name: "Import", exact: true }).click();
    await page.getByLabel("Choose an export file").setInputFiles(FIXTURE);
    await page.getByRole("button", { name: "Continue" }).click();
    // Detection ran on the file's own bytes and named it a Bitwarden JSON.
    await expect(page.getByLabel("Export format")).toHaveValue("bitwarden-json");
  });

  await test.step("3. preview: the counts reconcile and the card is named, not dropped", async () => {
    await page.getByRole("button", { name: "Preview the import" }).click();
    // Two logins and a note import; the card cannot, and is reported. Four rows
    // read, three to import, one unreadable — a total that adds up.
    await expect(page.getByText(/4 rows read from your file/i)).toBeVisible();
    await expect(page.getByText(/3 will be imported/i)).toBeVisible();
    await expect(page.getByText(/1 could not be read/i)).toBeVisible();
    await expect(page.getByText(/is a Bitwarden card, which Keyhole cannot import/i)).toBeVisible();
  });

  await test.step("4. import, and be told to delete the export file", async () => {
    await page.getByRole("button", { name: "Import 3 items" }).click();
    await page
      .getByRole("alertdialog")
      .getByRole("button", { name: "Import 3 items" })
      .click();
    await expect(
      page.getByRole("heading", { name: /imported 3 items into personal/i }),
    ).toBeVisible();
    await expect(page.getByText(/now delete the export file/i)).toBeVisible();
  });

  await test.step("4b. the imported items appear in the vault without a reload", async () => {
    // The hook resyncs after uploading, so switching to the vault should show
    // the new items straight away — no reload, no manual refresh. This is the
    // one path the lock-and-reload below would otherwise paper over.
    await page.getByRole("button", { name: "Vault", exact: true }).click();
    await expect(page.getByText(ITEM_NAME)).toBeVisible();
    await expect(page.getByText(COMMA_ITEM_NAME)).toBeVisible();
  });

  await test.step("5. nothing was written to disk by the import", async () => {
    // Design spec §6.3: decrypted keys and plaintext live in memory only, never
    // localStorage, sessionStorage, or IndexedDB. Asserted at the point the
    // import has just handled every password in the file, which is where a leak
    // would show. The exact key set, so a plaintext written under some new key
    // fails here rather than slipping past an absence check. keyhole.autolock is
    // absent because this journey never opens Settings, which is the only thing
    // that writes it (src/vault/autolock.ts).
    const storageState = await page.evaluate(async () => {
      const databases = (await indexedDB.databases?.()) ?? [];
      return {
        localStorageKeys: Object.keys(localStorage).sort(),
        sessionStorageKeys: Object.keys(sessionStorage),
        indexedDbNames: databases.map((db) => db.name),
      };
    });
    expect(storageState.localStorageKeys).toEqual(["keyhole.email"]);
    expect(storageState.sessionStorageKeys).toEqual([]);
    expect(storageState.indexedDbNames).toEqual([]);
  });

  await test.step("6. lock and reload, so nothing is left in memory", async () => {
    await page.getByRole("button", { name: /^lock$/i }).click();
    await page.reload();
    await expect(page.getByLabel(/master password/i)).toBeVisible();
  });

  await test.step("7. the imported password is readable from a fresh unlock", async () => {
    await page.getByLabel(/master password/i).fill(MASTER_PASSWORD);
    await page.getByRole("button", { name: /^unlock$/i }).click();

    // The item is there because it was synced from the server, decrypted with a
    // key derived fresh from the master password just typed.
    await expect(page.getByText(ITEM_NAME)).toBeVisible();
    await page.getByText(ITEM_NAME).click();
    await page.getByRole("button", { name: /reveal|show/i }).click();
    // The assertion this file exists for: the plaintext made the whole trip.
    await expect(page.getByLabel(/^password/i)).toHaveValue(ITEM_PASSWORD);
    await page.getByRole("button", { name: /^cancel$/i }).click();
  });

  await test.step("8. a password full of commas survived byte for byte", async () => {
    // The plan's stated risk is a password silently truncated or mangled, and a
    // comma is where that happens. Reading this one back intact proves no layer
    // between the export and the decrypt split it.
    await page.getByText(COMMA_ITEM_NAME).click();
    await page.getByRole("button", { name: /reveal|show/i }).click();
    await expect(page.getByLabel(/^password/i)).toHaveValue(COMMA_ITEM_PASSWORD);
    await page.getByRole("button", { name: /^cancel$/i }).click();
  });

  await test.step("9. re-importing the same file now reports both logins as duplicates", async () => {
    // Duplicate detection runs against the vault, not only within the file, so
    // the two logins just imported must come back flagged — proving
    // existingFromRecords reached the decrypted vault and matched on host and
    // username. Left at the preview; completing it would only make the point
    // twice.
    await page.getByRole("button", { name: "Import", exact: true }).click();
    await page.getByLabel("Choose an export file").setInputFiles(FIXTURE);
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "Preview the import" }).click();

    await expect(page.getByText(/possible duplicates \(2\)/i)).toBeVisible();
    // Both default to skip, because both are already in the vault.
    const toggles = page.getByRole("checkbox");
    await expect(toggles).toHaveCount(2);
    await expect(toggles.nth(0)).toBeChecked();
    await expect(toggles.nth(1)).toBeChecked();
  });
});
