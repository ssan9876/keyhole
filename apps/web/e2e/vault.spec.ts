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
