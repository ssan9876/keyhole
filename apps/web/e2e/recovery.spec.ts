import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
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

const ORIGINAL_MASTER_PASSWORD = "correct horse battery staple";
const NEW_MASTER_PASSWORD = "a different horse, a different battery";
const ITEM_NAME = "Recovered Service";
// Distinctive on purpose: this exact string coming back out at the end is the
// only thing that proves the userKey survived the rotation.
const ITEM_PASSWORD = "pangolin-trapeze-thunder-42";

// 25 Crockford-base32 characters in five groups of five
// (packages/crypto/src/recovery.ts).
const RECOVERY_CODE = /^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{5}(-[0-9ABCDEFGHJKMNPQRSTVWXYZ]{5}){4}$/;

/**
 * The recovery salt POST /api/auth/recover/prelogin returned for the real
 * account *before* the redemption rotated it, captured from the browser's own
 * request in the first test.
 *
 * The second test needs it to prove it is not comparing two decoys — see the
 * comment there.
 */
let saltBeforeRotation = "";

/** The one-time code, read off whichever screen is showing it. */
async function readRecoveryCode(page: Page): Promise<string> {
  // Anchored, so none of the surrounding prose paragraphs can match: only the
  // panel whose entire contents are the code.
  const panel = page.locator("p").filter({ hasText: RECOVERY_CODE });
  await expect(panel).toBeVisible();
  return ((await panel.textContent()) ?? "").trim();
}

interface PreloginAnswer {
  status: number;
  contentType: string | undefined;
  raw: string;
  json: { recoverySalt: string; recoveryKdfParams: string };
}

async function recoverPrelogin(
  request: APIRequestContext,
  email: string,
): Promise<PreloginAnswer> {
  const response = await request.post(`${server.baseUrl}/api/auth/recover/prelogin`, {
    data: { email },
  });
  // The raw bytes, not the parsed object: field order, whitespace and escaping
  // are exactly what this endpoint has to keep identical, and JSON.parse throws
  // all three away.
  const raw = (await response.body()).toString("utf8");
  return {
    status: response.status(),
    contentType: response.headers()["content-type"],
    raw,
    json: JSON.parse(raw) as PreloginAnswer["json"],
  };
}

// Serial, and for the same reasons vault.spec.ts is: one server, one SQLite
// database, and the second test below depends on the account the first one
// enrols and then recovers.
test.describe.serial("recovery", () => {
  test("a forgotten master password, redeemed with the code, still opens the same items", async ({
    page,
  }) => {
    // Eight Argon2id derivations at 64 MiB before this test is done: enrolment,
    // the redemption, the two inside completeRecovery, the sign-in after it, a
    // deliberately wrong password, a deliberately stale code, and the final
    // unlock.
    test.setTimeout(240_000);

    const originalCode = await test.step("1. enrol and save the code", async () => {
      await page.goto(new URL(server.inviteUrl).pathname);
      await page.getByLabel(/email/i).fill(server.email);
      await page.getByLabel(/^master password/i).fill(ORIGINAL_MASTER_PASSWORD);
      await page.getByLabel(/confirm/i).fill(ORIGINAL_MASTER_PASSWORD);
      await page.getByRole("button", { name: /set master password/i }).click();

      await expect(page.getByText(/save your recovery code/i)).toBeVisible();
      const code = await readRecoveryCode(page);
      expect(code).toMatch(RECOVERY_CODE);
      await page.getByLabel(/saved/i).check();
      await page.getByRole("button", { name: /continue/i }).click();
      return code;
    });

    await test.step("2. store an item with a distinctive password", async () => {
      await page.getByRole("button", { name: /add an item/i }).click();
      await page.getByLabel(/^name$/i).fill(ITEM_NAME);
      await page.getByLabel(/^username$/i).fill("someone@example.com");
      await page.getByLabel(/^password/i).fill(ITEM_PASSWORD);
      await page.getByRole("button", { name: /^save$/i }).click();
      await expect(page.getByText(ITEM_NAME)).toBeVisible();
    });

    await test.step("3. lock and reload, so nothing is left in memory", async () => {
      await page.getByRole("button", { name: /^lock$/i }).click();
      await page.reload();
      await expect(page.getByLabel(/master password/i)).toBeVisible();
    });

    await test.step("4. redeem the code", async () => {
      await page.getByRole("button", { name: /forgot your master password/i }).click();
      await page.getByLabel("Email", { exact: true }).fill(server.email);
      await page.getByLabel("Recovery code", { exact: true }).fill(originalCode);

      const [prelogin] = await Promise.all([
        page.waitForResponse(
          (res) =>
            res.url().endsWith("/api/auth/recover/prelogin") && res.request().method() === "POST",
          { timeout: 20_000 },
        ),
        page.getByRole("button", { name: "Continue", exact: true }).click(),
      ]);
      // Captured here because the redemption that follows succeeds, which is
      // what makes this salt provably the real account's rather than a decoy.
      saltBeforeRotation = ((await prelogin.json()) as { recoverySalt: string }).recoverySalt;
      expect(saltBeforeRotation.length).toBeGreaterThan(0);
    });

    const newCode = await test.step("5. set a new master password, save the new code", async () => {
      await page.getByLabel("New master password", { exact: true }).fill(NEW_MASTER_PASSWORD);
      await page
        .getByLabel("Confirm new master password", { exact: true })
        .fill(NEW_MASTER_PASSWORD);
      await page.getByRole("button", { name: "Set new master password" }).click();

      await expect(page.getByText(/save your new recovery code/i)).toBeVisible();
      const code = await readRecoveryCode(page);
      expect(code).toMatch(RECOVERY_CODE);
      // A rotation that handed back the same code would mean the recovery blob
      // was never replaced, leaving a code someone else may have read still
      // live.
      expect(code).not.toBe(originalCode);
      await page.getByLabel(/saved/i).check();
      await page.getByRole("button", { name: "Continue to my vault" }).click();
      return code;
    });

    await test.step("6. the item's password is still readable", async () => {
      // The assertion this whole file exists for. The recovery rotated the
      // password and the recovery blob but re-wrapped the *same* userKey; a
      // rotation that generated a fresh one would look identical from the
      // outside and would have orphaned every item this account owns. Only
      // this value coming back out can tell the two apart.
      await expect(page.getByText(ITEM_NAME)).toBeVisible();
      await page.getByText(ITEM_NAME).click();
      await page.getByRole("button", { name: /reveal|show/i }).click();
      await expect(page.getByLabel(/^password/i)).toHaveValue(ITEM_PASSWORD);
      await page.getByRole("button", { name: /^cancel$/i }).click();
    });

    await test.step("7. the old master password no longer works", async () => {
      await page.getByRole("button", { name: /^lock$/i }).click();
      await page.getByLabel(/master password/i).fill(ORIGINAL_MASTER_PASSWORD);
      await page.getByRole("button", { name: /^unlock$/i }).click();
      // "Replaces your master password" is a promise this screen makes on the
      // way in; nothing else in the suite checks that the old one actually
      // stopped opening the vault.
      await expect(page.getByRole("alert")).toContainText(/wrong master password/i);
    });

    await test.step("8. and neither does the old recovery code", async () => {
      await page.getByRole("button", { name: /forgot your master password/i }).click();
      await page.getByLabel("Email", { exact: true }).fill(server.email);
      await page.getByLabel("Recovery code", { exact: true }).fill(originalCode);
      await page.getByRole("button", { name: "Continue", exact: true }).click();
      // A real 401 from a real server, turned into the wrong-code sentence
      // rather than a server fault: the branch RecoverScreen's unit tests can
      // only exercise against a rejected promise.
      await expect(page.getByRole("alert")).toContainText(/did not match an account/i);
      await page.getByRole("button", { name: "Back to unlocking" }).click();
    });

    await test.step("9. the new password opens it again", async () => {
      await page.getByLabel(/master password/i).fill(NEW_MASTER_PASSWORD);
      await page.getByRole("button", { name: /^unlock$/i }).click();
      await expect(page.getByText(ITEM_NAME)).toBeVisible();
      // Held only so the compiler agrees this step needs the value: the code
      // itself was asserted in step 5.
      expect(newCode).toMatch(RECOVERY_CODE);
    });
  });

  test("answers an address with no account exactly as it answers a real one", async ({
    request,
  }) => {
    const real = await recoverPrelogin(request, server.email);
    const unknown = await recoverPrelogin(request, "nobody-at-all@example.com");

    // Non-vacuity, and it is not optional: if the account were missing or not
    // redeemable, `real` would be a decoy too and every assertion below would
    // pass while proving nothing. A decoy is a deterministic function of
    // (server secret, address) -- auth.DecoyRecoverySalt -- so a decoy for this
    // address would be byte-identical to what the browser saw in the previous
    // test. The redemption in between rotated the stored salt, so a *different*
    // value here can only have come from the account's own column.
    expect(saltBeforeRotation.length).toBeGreaterThan(0);
    expect(real.json.recoverySalt).not.toBe(saltBeforeRotation);

    expect(real.status).toBe(200);
    expect(unknown.status).toBe(real.status);
    expect(unknown.contentType).toBe(real.contentType);
    expect(Object.keys(unknown.json).sort()).toEqual(Object.keys(real.json).sort());
    // The parameters have to match byte for byte, not merely parse the same:
    // this is the field that was an enumeration oracle until the three write
    // sites were pinned to auth.DefaultKDFParamsJSON.
    expect(unknown.json.recoveryKdfParams).toBe(real.json.recoveryKdfParams);
    // The salt cannot be equal -- one is the account's, the other is a decoy --
    // so every measurable property of it has to be.
    expect(unknown.json.recoverySalt.length).toBe(real.json.recoverySalt.length);
    expect(Buffer.from(unknown.json.recoverySalt, "base64").byteLength).toBe(
      Buffer.from(real.json.recoverySalt, "base64").byteLength,
    );
    expect(Buffer.byteLength(unknown.raw)).toBe(Buffer.byteLength(real.raw));
    // And with that one unequal-by-definition value masked out, the two bodies
    // are byte-identical: same fields, same order, same separators, same
    // escaping. An added field, a reordered one, or a differently shaped decoy
    // fails here.
    expect(unknown.raw.replace(unknown.json.recoverySalt, "<salt>")).toBe(
      real.raw.replace(real.json.recoverySalt, "<salt>"),
    );

    // Stability, which is a separate property from parity and just as
    // load-bearing: a decoy regenerated per call would differ between these two
    // requests while a real account's salt stayed put, and that difference
    // alone would tell an attacker which addresses exist.
    const realAgain = await recoverPrelogin(request, server.email);
    const unknownAgain = await recoverPrelogin(request, "nobody-at-all@example.com");
    expect(realAgain.raw).toBe(real.raw);
    expect(unknownAgain.raw).toBe(unknown.raw);
  });
});
