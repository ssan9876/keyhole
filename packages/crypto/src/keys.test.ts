import { describe, expect, it } from "vitest";
import { createPrivateKey, createPublicKey, diffieHellman } from "node:crypto";
import { x25519 } from "@noble/curves/ed25519";
import {
  enrollUser,
  generateCollectionKey,
  generateKeyPair,
  generateUserKey,
  publicKeyFor,
  rotateMasterPassword,
  unlockUser,
  unwrapKey,
  wrapKey,
} from "./keys.js";
import { DecryptionError } from "./errors.js";
import { toBase64 } from "./encoding.js";

const PASSWORD = "correct horse battery staple";

describe("key generation", () => {
  it("produces 32-byte symmetric keys", () => {
    expect(generateUserKey()).toHaveLength(32);
    expect(generateCollectionKey()).toHaveLength(32);
  });

  it("does not repeat", () => {
    expect(toBase64(generateUserKey())).not.toBe(toBase64(generateUserKey()));
  });

  it("produces 32-byte X25519 keypairs whose public key derives from the private key", () => {
    const pair = generateKeyPair();
    expect(pair.privateKey).toHaveLength(32);
    expect(pair.publicKey).toHaveLength(32);
    expect(toBase64(publicKeyFor(pair.privateKey))).toBe(toBase64(pair.publicKey));
  });

  // Independent implementation check: an X25519 shared secret computed by
  // @noble/curves must equal the one OpenSSL computes via Node.
  it("agrees with Node/OpenSSL on X25519 shared secrets", () => {
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const ours = x25519.getSharedSecret(alice.privateKey, bob.publicKey);

    const pkcs8Prefix = Buffer.from("302e020100300506032b656e04220420", "hex");
    const spkiPrefix = Buffer.from("302a300506032b656e032100", "hex");
    const alicePrivate = createPrivateKey({
      key: Buffer.concat([pkcs8Prefix, Buffer.from(alice.privateKey)]),
      format: "der",
      type: "pkcs8",
    });
    const bobPublic = createPublicKey({
      key: Buffer.concat([spkiPrefix, Buffer.from(bob.publicKey)]),
      format: "der",
      type: "spki",
    });
    const theirs = diffieHellman({ privateKey: alicePrivate, publicKey: bobPublic });

    expect(toBase64(ours)).toBe(toBase64(new Uint8Array(theirs)));
  });
});

describe("wrapKey / unwrapKey", () => {
  it("round-trips a key", async () => {
    const key = generateUserKey();
    const wrapping = generateUserKey();
    expect(toBase64(await unwrapKey(await wrapKey(key, wrapping), wrapping))).toBe(toBase64(key));
  });

  it("fails under the wrong wrapping key", async () => {
    const wrapped = await wrapKey(generateUserKey(), generateUserKey());
    await expect(unwrapKey(wrapped, generateUserKey())).rejects.toThrow(DecryptionError);
  });
});

describe("enrollUser", () => {
  it("returns everything the server needs and nothing it must not have", async () => {
    const result = await enrollUser(PASSWORD);
    expect(result.kdfSalt).toHaveLength(16);
    expect(result.authHash).toHaveLength(32);
    expect(result.publicKey).toHaveLength(32);
    expect(typeof result.protectedUserKey).toBe("string");
    expect(typeof result.encryptedPrivateKey).toBe("string");
    // The wrapped blobs must not contain the plaintext key material.
    expect(result.protectedUserKey).not.toContain(toBase64(result.userKey));
    expect(result.encryptedPrivateKey).not.toContain(toBase64(result.keyPair.privateKey));
  });

  it("produces different key material for two users with the same password", async () => {
    const a = await enrollUser(PASSWORD);
    const b = await enrollUser(PASSWORD);
    expect(toBase64(a.userKey)).not.toBe(toBase64(b.userKey));
    expect(toBase64(a.authHash)).not.toBe(toBase64(b.authHash));
  });
});

describe("unlockUser", () => {
  it("recovers the same userKey and private key", async () => {
    const enrolled = await enrollUser(PASSWORD);
    const unlocked = await unlockUser(
      PASSWORD,
      enrolled.kdfSalt,
      enrolled.protectedUserKey,
      enrolled.encryptedPrivateKey,
    );
    expect(toBase64(unlocked.userKey)).toBe(toBase64(enrolled.userKey));
    expect(toBase64(unlocked.privateKey)).toBe(toBase64(enrolled.keyPair.privateKey));
  });

  it("throws DecryptionError under the wrong master password", async () => {
    const enrolled = await enrollUser(PASSWORD);
    await expect(
      unlockUser("wrong password", enrolled.kdfSalt, enrolled.protectedUserKey, enrolled.encryptedPrivateKey),
    ).rejects.toThrow(DecryptionError);
  });
});

describe("rotateMasterPassword", () => {
  it("keeps the same userKey and private key under the new password", async () => {
    const enrolled = await enrollUser(PASSWORD);
    const rotated = await rotateMasterPassword("a brand new password", enrolled.userKey);

    const unlocked = await unlockUser(
      "a brand new password",
      rotated.kdfSalt,
      rotated.protectedUserKey,
      enrolled.encryptedPrivateKey,
    );
    expect(toBase64(unlocked.userKey)).toBe(toBase64(enrolled.userKey));
    expect(toBase64(unlocked.privateKey)).toBe(toBase64(enrolled.keyPair.privateKey));
  });

  it("issues a fresh salt and auth hash so the old password stops working", async () => {
    const enrolled = await enrollUser(PASSWORD);
    const rotated = await rotateMasterPassword("a brand new password", enrolled.userKey);

    expect(toBase64(rotated.kdfSalt)).not.toBe(toBase64(enrolled.kdfSalt));
    expect(toBase64(rotated.authHash)).not.toBe(toBase64(enrolled.authHash));
    await expect(
      unlockUser(PASSWORD, rotated.kdfSalt, rotated.protectedUserKey, enrolled.encryptedPrivateKey),
    ).rejects.toThrow(DecryptionError);
  });
});
