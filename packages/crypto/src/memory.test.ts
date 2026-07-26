import { describe, expect, it } from "vitest";
import { zeroize } from "./memory.js";
import { randomBytes } from "./random.js";
import {
  enrollUser,
  generateCollectionKey,
  generateKeyPair,
  generateUserKey,
} from "./keys.js";
import { decryptItem, encryptItem, type NoteItem } from "./item.js";
import { openSealed, sealToUser } from "./seal.js";
import { createRecoveryBlob, generateRecoveryCode, recoverUserKey } from "./recovery.js";
import { DEFAULT_KDF_PARAMS } from "./kdf.js";

describe("zeroize", () => {
  it("overwrites the buffer in place", () => {
    const secret = randomBytes(32);
    zeroize(secret);
    expect(Array.from(secret)).toEqual(new Array(32).fill(0));
  });

  it("clears several buffers at once", () => {
    const a = randomBytes(8);
    const b = randomBytes(16);
    zeroize(a, b);
    expect(Array.from(a)).toEqual(new Array(8).fill(0));
    expect(Array.from(b)).toEqual(new Array(16).fill(0));
  });

  it("ignores null and undefined so callers need no guards", () => {
    expect(() => zeroize(null, undefined, randomBytes(4))).not.toThrow();
  });
});

// The package zeroizes its own intermediates. The failure mode that would
// introduce is clearing a buffer that belongs to the caller, which would strand
// a vault mid-session; every one of these keys is still live after the call.
describe("internal zeroization leaves the caller's buffers alone", () => {
  const zeroed = (bytes: Uint8Array): boolean => bytes.every((byte) => byte === 0);

  it("does not clear the keys passed to or returned from enrollment", async () => {
    const enrolled = await enrollUser("a master password");
    expect(zeroed(enrolled.userKey)).toBe(false);
    expect(zeroed(enrolled.keyPair.privateKey)).toBe(false);
    expect(zeroed(enrolled.authHash)).toBe(false);
  });

  it("does not clear a parentKey handed to encryptItem or decryptItem", async () => {
    const userKey = generateUserKey();
    const item: NoteItem = {
      type: "note",
      name: "n",
      notes: "x",
      favorite: false,
      folderId: null,
    };
    const encrypted = await encryptItem(item, userKey);
    expect(zeroed(userKey)).toBe(false);
    expect(await decryptItem(encrypted, userKey)).toEqual(item);
    expect(zeroed(userKey)).toBe(false);
  });

  it("does not clear the secret or recipient key handed to sealToUser", async () => {
    const recipient = generateKeyPair();
    const secret = generateCollectionKey();
    const sealed = await sealToUser(secret, recipient.publicKey);
    expect(zeroed(secret)).toBe(false);
    expect(zeroed(recipient.publicKey)).toBe(false);
    const opened = await openSealed(sealed, recipient.privateKey);
    expect(zeroed(recipient.privateKey)).toBe(false);
    expect(Array.from(opened)).toEqual(Array.from(secret));
  });

  it("does not clear the userKey handed to recovery", async () => {
    const userKey = generateUserKey();
    const code = generateRecoveryCode();
    const blob = await createRecoveryBlob(userKey, code, DEFAULT_KDF_PARAMS);
    expect(zeroed(userKey)).toBe(false);
    const recovered = await recoverUserKey(
      blob.recoveryProtectedUserKey,
      code,
      blob.recoverySalt,
      blob.params,
    );
    expect(Array.from(recovered)).toEqual(Array.from(userKey));
  });
});
