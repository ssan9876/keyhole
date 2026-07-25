import { describe, expect, it } from "vitest";
import {
  decryptItem,
  encryptItem,
  generateItemKey,
  rewrapItem,
  type LoginItem,
  type NoteItem,
} from "./item.js";
import { generateCollectionKey, generateUserKey } from "./keys.js";
import { DecryptionError } from "./errors.js";

const login: LoginItem = {
  type: "login",
  name: "GitHub",
  username: "seth@gmail.com",
  password: "hunter2-but-better",
  urls: ["https://github.com"],
  notes: "personal account",
  favorite: true,
  folderId: null,
  passwordHistory: [{ password: "old-one", changedAt: "2026-01-01T00:00:00.000Z" }],
};

const note: NoteItem = {
  type: "note",
  name: "Wifi recovery codes",
  notes: "1234-5678\n9012-3456",
  favorite: false,
  folderId: "folder-1",
};

describe("generateItemKey", () => {
  it("produces a distinct 32-byte key each call", () => {
    expect(generateItemKey()).toHaveLength(32);
    expect(generateItemKey().join()).not.toBe(generateItemKey().join());
  });
});

describe("encryptItem / decryptItem", () => {
  it("round-trips a login", async () => {
    const userKey = generateUserKey();
    expect(await decryptItem(await encryptItem(login, userKey), userKey)).toEqual(login);
  });

  it("round-trips a note", async () => {
    const userKey = generateUserKey();
    expect(await decryptItem(await encryptItem(note, userKey), userKey)).toEqual(note);
  });

  it("leaks no plaintext field into the ciphertext", async () => {
    const encrypted = await encryptItem(login, generateUserKey());
    const blob = encrypted.ciphertext + encrypted.wrappedItemKey;
    for (const secret of ["GitHub", "seth@gmail.com", "hunter2-but-better", "github.com", "old-one"]) {
      expect(blob).not.toContain(secret);
    }
  });

  it("gives every item its own key, so two identical items differ", async () => {
    const userKey = generateUserKey();
    const a = await encryptItem(login, userKey);
    const b = await encryptItem(login, userKey);
    expect(a.wrappedItemKey).not.toBe(b.wrappedItemKey);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });

  it("cannot be decrypted with the wrong parent key", async () => {
    const encrypted = await encryptItem(login, generateUserKey());
    await expect(decryptItem(encrypted, generateUserKey())).rejects.toThrow(DecryptionError);
  });
});

describe("rewrapItem", () => {
  // Moving a personal item into a shared collection must not re-encrypt the
  // item body — only the wrapped item key changes.
  it("moves an item between parent keys without touching the ciphertext", async () => {
    const userKey = generateUserKey();
    const collectionKey = generateCollectionKey();
    const personal = await encryptItem(login, userKey);
    const shared = await rewrapItem(personal, userKey, collectionKey);

    expect(shared.ciphertext).toBe(personal.ciphertext);
    expect(shared.wrappedItemKey).not.toBe(personal.wrappedItemKey);
    expect(await decryptItem(shared, collectionKey)).toEqual(login);
    await expect(decryptItem(shared, userKey)).rejects.toThrow(DecryptionError);
  });
});
