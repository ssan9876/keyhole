import { describe, expect, it } from "vitest";
import {
  decryptItem,
  encryptItem,
  generateItemKey,
  rewrapItem,
  type EncryptedItem,
  type LoginItem,
  type NoteItem,
} from "./item.js";
import { generateCollectionKey, generateUserKey, wrapKey } from "./keys.js";
import { encryptString } from "./symmetric.js";
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

// The AEAD tag does not make the plaintext trustworthy, because parentKey can
// be attacker-chosen: a compromised server can seal arbitrary bytes to a user
// as a "collection key" and serve a ciphertext that verifies under it. Without
// a runtime check, fully attacker-controlled JSON reaches the web app typed as
// ItemPlaintext.
describe("decryptItem shape validation", () => {
  async function sealForged(body: unknown): Promise<[EncryptedItem, Uint8Array]> {
    const parentKey = generateUserKey();
    const itemKey = generateItemKey();
    return [
      {
        ciphertext: await encryptString(JSON.stringify(body), itemKey),
        wrappedItemKey: await wrapKey(itemKey, parentKey),
      },
      parentKey,
    ];
  }

  it("rejects an unknown type", async () => {
    const [forged, key] = await sealForged({ ...note, type: "card" });
    await expect(decryptItem(forged, key)).rejects.toThrow(DecryptionError);
  });

  it("rejects a missing required field", async () => {
    const { urls: _dropped, ...withoutUrls } = login;
    const [forged, key] = await sealForged(withoutUrls);
    await expect(decryptItem(forged, key)).rejects.toThrow(DecryptionError);
  });

  it("rejects a field of the wrong type", async () => {
    const [forged, key] = await sealForged({ ...login, favorite: "yes" });
    await expect(decryptItem(forged, key)).rejects.toThrow(DecryptionError);
  });

  it("rejects urls that is not an array of strings", async () => {
    const [forged, key] = await sealForged({ ...login, urls: ["https://ok", 7] });
    await expect(decryptItem(forged, key)).rejects.toThrow(DecryptionError);
  });

  it("rejects a malformed passwordHistory entry", async () => {
    const [forged, key] = await sealForged({
      ...login,
      passwordHistory: [{ password: "x" }],
    });
    await expect(decryptItem(forged, key)).rejects.toThrow(DecryptionError);
  });

  it("rejects a plaintext that is not an object at all", async () => {
    const [forged, key] = await sealForged("just a string");
    await expect(decryptItem(forged, key)).rejects.toThrow(DecryptionError);
  });

  it("still accepts both well-formed variants", async () => {
    const [validLogin, loginKey] = await sealForged(login);
    const [validNote, noteKey] = await sealForged(note);
    expect(await decryptItem(validLogin, loginKey)).toEqual(login);
    expect(await decryptItem(validNote, noteKey)).toEqual(note);
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
