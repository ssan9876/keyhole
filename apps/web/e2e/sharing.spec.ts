import { expect, test } from "@playwright/test";
import { createUser, startServer, type RunningServer } from "./server.js";

let server: RunningServer;

test.beforeAll(async () => {
  // The default port, deliberately: vite.config.ts's dev-server proxy target
  // for /api is hardcoded to 127.0.0.1:8477, not derived from whatever port
  // a given spec file's Go process happens to use. A different port here
  // would make every request the browser sends 404 against nothing, since
  // the one Vite instance (started once for the whole Playwright run) would
  // still be aiming at 8477.
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

const ADMIN_MASTER_PASSWORD = "correct horse battery staple";
const BEE_MASTER_PASSWORD = "a different horse, a different battery";
// 16 crockford-base32 characters grouped by 4 (packages/crypto/src/fingerprint.ts).
const FINGERPRINT_PATTERN = /^[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/;

test("an admin shares a collection and the second user reads the item", async ({ browser }) => {
  // Two full unlocks (admin, Bee) plus an enrolment apiece: four Argon2id
  // derivations at 64 MiB before this test does anything else.
  test.setTimeout(180_000);

  const adminContext = await browser.newContext();
  const adminPage = await adminContext.newPage();
  const beeContext = await browser.newContext();
  const beePage = await beeContext.newPage();

  try {
    // 1. Admin enrols from the CLI invite URL, sets a master password.
    await test.step("1. admin enrols", async () => {
      await adminPage.goto(new URL(server.inviteUrl).pathname);
      await adminPage.getByLabel(/email/i).fill(server.email);
      await adminPage.getByLabel(/^master password/i).fill(ADMIN_MASTER_PASSWORD);
      await adminPage.getByLabel(/confirm/i).fill(ADMIN_MASTER_PASSWORD);
      await adminPage.getByRole("button", { name: /set master password/i }).click();
      await expect(adminPage.getByText(/save your recovery code/i)).toBeVisible();
      await adminPage.getByLabel(/saved/i).check();
      await adminPage.getByRole("button", { name: /continue/i }).click();
      await expect(adminPage.getByRole("button", { name: "Admin", exact: true })).toBeVisible();
    });

    // 2. Admin > Users > creates "bee@example.com", copies the invite URL.
    const beeEmail = "bee@example.com";
    const beeInviteUrl = await test.step("2. admin creates Bee's account", () =>
      createUser(adminPage, { email: beeEmail, name: "Bee" }));

    // 3. Second context opens that URL, enrols, saves its recovery code.
    await test.step("3. Bee enrols", async () => {
      await beePage.goto(new URL(beeInviteUrl).pathname);
      await beePage.getByLabel(/email/i).fill(beeEmail);
      await beePage.getByLabel(/^master password/i).fill(BEE_MASTER_PASSWORD);
      await beePage.getByLabel(/confirm/i).fill(BEE_MASTER_PASSWORD);
      await beePage.getByRole("button", { name: /set master password/i }).click();
      await expect(beePage.getByText(/save your recovery code/i)).toBeVisible();
      await beePage.getByLabel(/saved/i).check();
      await beePage.getByRole("button", { name: /continue/i }).click();
      // Bee has no admin tab, but landing on the vault list is proof enough
      // that enrolment finished and logged her straight in.
      await expect(beePage.getByRole("button", { name: /add an item/i })).toBeVisible();
    });

    // 4. Admin > Collections > creates "Household".
    const householdRow = adminPage.getByRole("button", { name: /household/i });
    await test.step("4. admin creates Household", async () => {
      await adminPage.getByRole("button", { name: "Collections", exact: true }).click();
      await adminPage.getByRole("button", { name: "Create collection" }).click();
      await adminPage.getByLabel("Name", { exact: true }).fill("Household");
      await adminPage.getByRole("button", { name: "Save collection" }).click();
      await expect(householdRow).toBeVisible();
    });

    // 5. Admin adds Bee as a member -- the fingerprint is on screen before
    // confirming -- and the result reads "granted", not "pending", because
    // the admin created the collection and holds its key.
    await test.step("5. admin adds Bee, granted immediately", async () => {
      await householdRow.click(); // expand the row, loading its member list
      await adminPage.getByRole("button", { name: "Add member" }).click();
      await adminPage
        .getByLabel(/new member/i)
        .selectOption({ label: `Bee <${beeEmail}>` });
      // Design spec 3.9.1's mitigation for a substituted key is two people
      // reading this fingerprint aloud -- it must render before the seal
      // happens, not only in a confirmation after the fact. Scoped to a <p>
      // because every *existing* member (including the admin's own row)
      // also renders its fingerprint, but as a <span>; only the
      // about-to-be-sealed recipient's preview is a <p>.
      await expect(adminPage.locator("p", { hasText: FINGERPRINT_PATTERN })).toBeVisible();

      const [addResponse] = await Promise.all([
        adminPage.waitForResponse(
          (res) =>
            /\/api\/collections\/[^/]+\/members$/.test(res.url()) &&
            res.request().method() === "POST",
          { timeout: 20_000 },
        ),
        adminPage.getByRole("button", { name: "Add", exact: true }).click(),
      ]);
      // The server's own answer, not a UI label: handleAddMember
      // (internal/httpapi/collections.go) returns 201 + {"status":"granted"}
      // only when the request carried a sealed key, which only a member
      // (the admin, here) can produce. A 202 {"status":"pending"} would
      // mean nothing was actually granted -- see addMember's own comment in
      // vault/collections.ts.
      expect((await addResponse.json()).status).toBe("granted");
    });

    // 6. Admin creates an item in Household with a distinctive password.
    await test.step("6. admin creates a shared item", async () => {
      await adminPage.getByRole("button", { name: "Vault", exact: true }).click();
      await adminPage.getByRole("button", { name: /add an item/i }).click();
      await adminPage.getByLabel(/^name$/i).fill("Shared Router");
      await adminPage.getByLabel(/^username$/i).fill("admin@household.example");
      await adminPage.getByLabel(/^password/i).fill("wombat-castle-ferocious-19");
      await adminPage.getByLabel("Collection", { exact: true }).selectOption({ label: "Household" });
      await adminPage.getByRole("button", { name: /^save$/i }).click();
      await expect(adminPage.getByText("Shared Router")).toBeVisible();
    });

    // 7. Bee reloads, unlocks, and sees the item with the correct password.
    // This is the assertion the whole feature exists for: a value that
    // travelled through the server as ciphertext only, opened by a key the
    // server never held.
    await test.step("7. Bee reads the shared item", async () => {
      await beePage.reload();
      // The email field is gone on reload: enrolling remembered it
      // (keyhole.email in this context's own localStorage), matching
      // vault.spec.ts's "locked and re-unlocked" journey.
      await beePage.getByLabel(/master password/i).fill(BEE_MASTER_PASSWORD);
      await beePage.getByRole("button", { name: /^unlock$/i }).click();
      await expect(beePage.getByText("Shared Router")).toBeVisible();
      await beePage.getByText("Shared Router").click();
      await beePage.getByRole("button", { name: /reveal|show/i }).click();
      await expect(beePage.getByLabel(/^password/i)).toHaveValue("wombat-castle-ferocious-19");
      await beePage.getByRole("button", { name: /^cancel$/i }).click();
    });

    // 8. Admin removes Bee, and is shown the not-retroactive warning.
    await test.step("8. admin removes Bee", async () => {
      // Step 6 left this page on the Vault tab. The Collections tab (and the
      // Household row's expanded member list) is still holding client-side
      // state from step 5, but it has to be the active tab again for any of
      // its buttons to be clickable.
      await adminPage.getByRole("button", { name: "Collections", exact: true }).click();
      // Scoped to the <li> containing "Bee", not just getByRole("button", {
      // name: "Remove" }): the admin is also a member of a collection they
      // created, so their own row renders a "Remove" button too, and an
      // unscoped locator would match both. locator("li", { hasText: "Bee" })
      // alone is still ambiguous: the member list's <li> rows nest inside
      // the collection row's own <li>, so that outer <li> contains "Bee" too
      // (and, transitively, its own copy of the Remove button). Document
      // order puts the outer row first and the nested member row last, so
      // .last() is the actual member row.
      const beeRow = adminPage.locator("li", { hasText: "Bee" }).last();
      await beeRow.getByRole("button", { name: "Remove" }).click();
      await expect(adminPage.getByRole("alertdialog")).toContainText(
        /does not rotate the collection key/i,
      );
      await adminPage.getByRole("button", { name: "Remove member" }).click();
    });

    // 9. Bee reloads and unlocks: the item is gone from her list.
    await test.step("9. Bee no longer sees the item", async () => {
      await beePage.reload();
      await beePage.getByLabel(/master password/i).fill(BEE_MASTER_PASSWORD);
      await beePage.getByRole("button", { name: /^unlock$/i }).click();
      await expect(beePage.getByText(/add an item/i)).toBeVisible();
      await expect(beePage.getByText("Shared Router")).not.toBeVisible();
    });
  } finally {
    await adminContext.close();
    await beeContext.close();
  }
});

test("the server rejects a params object with reordered keys", async ({ request, browser }) => {
  test.setTimeout(60_000);

  // A fresh, unused invite token to submit the reordered payload against.
  // Reusing the admin from the first test (same server, same database) is
  // simpler than re-deriving a login server-side, and the admin's account
  // already exists there once that test has run.
  const adminContext = await browser.newContext();
  const adminPage = await adminContext.newPage();
  let token: string;
  try {
    await adminPage.goto("/");
    await adminPage.getByLabel(/email/i).fill(server.email);
    await adminPage.getByLabel(/master password/i).fill(ADMIN_MASTER_PASSWORD);
    await adminPage.getByRole("button", { name: /^unlock$/i }).click();
    await expect(adminPage.getByRole("button", { name: "Admin", exact: true })).toBeVisible();

    const inviteUrl = await createUser(adminPage, { email: "carol@example.com", name: "Carol" });
    const path = new URL(inviteUrl).pathname; // "/enroll/<token>"
    token = path.slice(path.lastIndexOf("/") + 1);
  } finally {
    await adminContext.close();
  }

  // Plan 3 proved this: JSON.stringify of a params object typed in the
  // server's own key order passes by luck, because V8 preserves an object
  // literal's insertion order and the two strings end up byte-identical.
  // Typing the keys in a different order here is what actually exercises
  // the comparison in internal/store/enroll.go's validate() -- a mocked
  // test cannot express this at all, because there is no server-side byte
  // comparison to bypass.
  const reorderedParams = JSON.stringify({
    iterations: 3,
    algorithm: "argon2id",
    parallelism: 4,
    memoryKiB: 65536,
  });

  const response = await request.post(`${server.baseUrl}/api/enroll/${token}`, {
    data: {
      kdfSalt: "salt",
      params: reorderedParams,
      authHash: "authhash",
      protectedUserKey: "protected",
      publicKey: "public",
      encryptedPrivateKey: "encrypted",
      recoverySalt: "recovery-salt",
      recoveryProtectedUserKey: "recovery-protected",
      recoveryKdfParams: "{}",
    },
  });

  expect(response.status()).toBe(400);
  const body = await response.json();
  expect(body.error.code).toBe("bad_request");
  expect(body.error.message).toBe(
    'field "params": must match the server\'s current KDF parameters exactly',
  );
});
