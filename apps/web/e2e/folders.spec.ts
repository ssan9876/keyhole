import { expect, test } from "@playwright/test";
import { startServer, type RunningServer } from "./server.js";

let server: RunningServer;

test.beforeAll(async () => {
  // The default port, for the reason sharing.spec.ts spells out at length:
  // vite.config's /api proxy target is hardcoded to 127.0.0.1:8477, and one
  // Vite instance serves the whole Playwright run.
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

const MASTER_PASSWORD = "correct horse battery staple";

// The encrypted-name round trip is the whole point of this file. This exact
// string is written on the way out as ciphertext the server never reads, and it
// coming back — legibly — out of a fresh unlock is the only thing that proves
// encryptString/decryptString carried it there and back. Chosen so it collides
// with nothing else on screen: it is not a substring of the item name, the item
// username, or any control's label.
const FOLDER_NAME = "Work Accounts";

// The item that lives in that folder. Its password makes the same trip the
// folder name does; reading it back after the reload is a second, independent
// witness that the item's own body survived.
const ITEM_NAME = "Payroll Portal";
const ITEM_USERNAME = "person@example.com";
const ITEM_PASSWORD = "quokka-lantern-drizzle-77";

/**
 * The folder feature proven end to end against a real Go server and a real
 * browser, not a mock.
 *
 * One journey: enrol, create a folder, put an item in it, filter to it, then
 * reload so every key is thrown away, unlock, and confirm the folder's
 * encrypted name decrypted and its item is still inside it. That reload step is
 * the load-bearing one — the server only ever held ciphertext for the name, so
 * a legible folder here can only mean the round trip closed. Then delete the
 * folder and confirm the item is not deleted with it: the server tombstones the
 * folder and never touches items (internal/store/folders.go:169), so the client
 * must reconcile the orphan and show it under Personal. Plus the storage
 * invariant, because folders are a new flow and a new flow is where a stray
 * write to disk appears.
 */
test("create a folder, assign an item, filter to it, reload and decrypt it, then delete it and keep the item", async ({
  page,
}) => {
  // Enrolment plus a later unlock: two Argon2id derivations at 64 MiB, each
  // roughly half a second by design. The KDF cost is the feature, not a thing
  // to trim; the timeout accommodates it.
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

  await test.step("2. create a folder", async () => {
    // Anchored to the exact label. A loose getByLabel(/folder/i) would also
    // match the "Rename folder" field a folder row reveals, and getByLabel(
    // /name/i) would match the item editor's "Name"/"Username" — exact keeps
    // this pinned to the create field alone.
    await page.getByLabel("New folder name", { exact: true }).fill(FOLDER_NAME);
    await page.getByRole("button", { name: "Add folder" }).click();
    // The sidebar renders the created folder as a filter button. Its presence is
    // proof the create POST succeeded and the follow-up resync brought the
    // folder back into state — decrypted, since createFolder already had the
    // name in hand.
    await expect(page.getByRole("button", { name: FOLDER_NAME, exact: true })).toBeVisible();
  });

  await test.step("3. add an item assigned to that folder", async () => {
    await page.getByRole("button", { name: /add an item/i }).click();
    // Anchored: /name/i would also match "Username", and the editor now also
    // carries "Folder" and "Collection" selects, so a loose match trips
    // Playwright's strict mode.
    await page.getByLabel(/^name$/i).fill(ITEM_NAME);
    await page.getByLabel(/username/i).fill(ITEM_USERNAME);
    await page.getByLabel(/^password/i).fill(ITEM_PASSWORD);
    // The label trap in full: "Folder" must not match "New folder name" (the
    // sidebar is unmounted while the editor is open, but exact is correct
    // regardless) nor "Collection". Selecting by the folder's decrypted name is
    // exactly what a user does.
    await page.getByLabel("Folder", { exact: true }).selectOption({ label: FOLDER_NAME });
    await page.getByRole("button", { name: /^save$/i }).click();
    await expect(page.getByText(ITEM_NAME)).toBeVisible();
  });

  await test.step("4. filter to the folder and see the item", async () => {
    await page.getByRole("button", { name: FOLDER_NAME, exact: true }).click();
    await expect(page.getByText(ITEM_NAME)).toBeVisible();
    // And it is genuinely filed under the folder, not merely surviving an
    // all-items view: Personal — the no-folder bucket — must not show it.
    await page.getByRole("button", { name: "Personal", exact: true }).click();
    await expect(page.getByText(ITEM_NAME)).not.toBeVisible();
  });

  await test.step("5. reload, unlock, and confirm the folder name decrypted with the item still in it", async () => {
    // A reload throws away every key: they were memory-only, by design. Nothing
    // decryptable survives in the page — the folder name and the item both have
    // to be fetched as ciphertext and reopened with a key derived fresh from the
    // password typed below.
    await page.reload();
    await expect(page.getByLabel(/master password/i)).toBeVisible();
    await page.getByLabel(/master password/i).fill(MASTER_PASSWORD);
    await page.getByRole("button", { name: /^unlock$/i }).click();

    // The assertion this whole file exists for: the encrypted folder name made
    // the round trip through a server that only ever saw ciphertext, and came
    // back legible. A broken encrypt/decrypt contract would surface here as
    // "Couldn't decrypt this folder" instead of the real name.
    await expect(page.getByRole("button", { name: FOLDER_NAME, exact: true })).toBeVisible();
    await page.getByRole("button", { name: FOLDER_NAME, exact: true }).click();
    await expect(page.getByText(ITEM_NAME)).toBeVisible();

    // The item's own body survived too: reveal its password and read it back.
    await page.getByText(ITEM_NAME).click();
    await page.getByRole("button", { name: /reveal|show/i }).click();
    await expect(page.getByLabel(/^password/i)).toHaveValue(ITEM_PASSWORD);
    await page.getByRole("button", { name: /^cancel$/i }).click();
  });

  await test.step("6. delete the folder and confirm the item survives with no folder", async () => {
    // Scope the Delete to the folder's own row: the row is the one <li>
    // containing the folder name, and it carries both a Rename and a Delete
    // button. (The item editor's "Delete this item" is not on screen here.)
    const folderRow = page.getByRole("listitem").filter({ hasText: FOLDER_NAME });
    await folderRow.getByRole("button", { name: "Delete" }).click();

    // The confirmation must state the load-bearing rule out loud, because it is
    // the one thing a user would not otherwise expect: the items are kept.
    const dialog = page.getByRole("alertdialog");
    await expect(dialog).toContainText(/does not delete the items/i);
    await dialog.getByRole("button", { name: "Delete folder" }).click();

    // The folder is gone from the sidebar once the delete's resync brings back
    // its tombstone.
    await expect(page.getByRole("button", { name: FOLDER_NAME, exact: true })).not.toBeVisible();

    // The item is not gone with it. The server never touched it; the client
    // reconciles its now-dangling folderId to Personal. First: it is still in
    // the vault at all (All items).
    await page.getByRole("button", { name: "All items", exact: true }).click();
    await expect(page.getByText(ITEM_NAME)).toBeVisible();

    // And precisely: it has fallen to Personal, the orphan bucket — not stranded
    // under a folder filter the sidebar no longer even offers. This is the whole
    // plan's most important rule, exercised against the real server.
    await page.getByRole("button", { name: "Personal", exact: true }).click();
    await expect(page.getByText(ITEM_NAME)).toBeVisible();
  });

  await test.step("7. nothing was written to disk by using folders", async () => {
    // Design spec §6.3: decrypted keys and plaintext live in memory only, never
    // localStorage, sessionStorage, or IndexedDB. Folders are a new flow — a new
    // create/rename/delete path plus a new decrypt on every sync — so this is
    // where a stray persist would first show. The exact key set, not a mere
    // absence check, so a value written under some new key fails here instead of
    // slipping past. keyhole.autolock is absent because this journey never opens
    // Settings, the only thing that writes it (src/vault/autolock.ts).
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
});
