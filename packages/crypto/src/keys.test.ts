import { describe, expect, it } from "vitest";
import { createPrivateKey, createPublicKey, diffieHellman } from "node:crypto";
import { x25519 } from "@noble/curves/ed25519";
import {
  beginUnlock,
  enrollUser,
  generateCollectionKey,
  generateKeyPair,
  generateUserKey,
  publicKeyFor,
  rotateMasterPassword,
  unwrapKey,
  wrapKey,
} from "./keys.js";
import { DecryptionError, KeyholeCryptoError } from "./errors.js";
import { DEFAULT_KDF_PARAMS, type KdfParams } from "./kdf.js";
import { toBase64 } from "./encoding.js";

const PASSWORD = "correct horse battery staple";

const RAISED_PARAMS: Readonly<KdfParams> = Object.freeze({
  algorithm: "argon2id",
  memoryKiB: 131072,
  iterations: 4,
  parallelism: 4,
});

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

  // Without this, an app that raises a user's params has no way to learn from
  // the result which params the salt belongs to, and can persist the wrong ones.
  it("reports the params it actually used", async () => {
    expect((await enrollUser(PASSWORD)).params).toEqual(DEFAULT_KDF_PARAMS);
    expect((await enrollUser(PASSWORD, RAISED_PARAMS)).params).toEqual(RAISED_PARAMS);
  });

  it("produces different key material for two users with the same password", async () => {
    const a = await enrollUser(PASSWORD);
    const b = await enrollUser(PASSWORD);
    expect(toBase64(a.userKey)).not.toBe(toBase64(b.userKey));
    expect(toBase64(a.authHash)).not.toBe(toBase64(b.authHash));
  });
});

describe("beginUnlock", () => {
  // The login protocol is: derive -> POST authHash -> receive the wrapped keys
  // -> unwrap. The session exists so the Argon2id derivation happens once, not
  // once for the auth hash and again for the blobs.
  it("yields the authHash before the wrapped blobs are known", async () => {
    const enrolled = await enrollUser(PASSWORD);
    const session = await beginUnlock(PASSWORD, enrolled.kdfSalt);
    expect(toBase64(session.authHash)).toBe(toBase64(enrolled.authHash));
    session.destroy();
  });

  it("recovers the same userKey and private key", async () => {
    const enrolled = await enrollUser(PASSWORD);
    const session = await beginUnlock(PASSWORD, enrolled.kdfSalt);
    const unlocked = await session.finish(
      enrolled.protectedUserKey,
      enrolled.encryptedPrivateKey,
    );
    expect(toBase64(unlocked.userKey)).toBe(toBase64(enrolled.userKey));
    expect(toBase64(unlocked.privateKey)).toBe(toBase64(enrolled.keyPair.privateKey));
    session.destroy();
  });

  it("throws DecryptionError under the wrong master password", async () => {
    const enrolled = await enrollUser(PASSWORD);
    const session = await beginUnlock("wrong password", enrolled.kdfSalt);
    await expect(
      session.finish(enrolled.protectedUserKey, enrolled.encryptedPrivateKey),
    ).rejects.toThrow(DecryptionError);
    session.destroy();
  });

  it("produces a different authHash under the wrong master password", async () => {
    const enrolled = await enrollUser(PASSWORD);
    const session = await beginUnlock("wrong password", enrolled.kdfSalt);
    expect(toBase64(session.authHash)).not.toBe(toBase64(enrolled.authHash));
    session.destroy();
  });

  it("refuses to finish after destroy rather than deriving garbage", async () => {
    const enrolled = await enrollUser(PASSWORD);
    const session = await beginUnlock(PASSWORD, enrolled.kdfSalt);
    session.destroy();
    await expect(
      session.finish(enrolled.protectedUserKey, enrolled.encryptedPrivateKey),
    ).rejects.toThrow(KeyholeCryptoError);
    await expect(
      session.finish(enrolled.protectedUserKey, enrolled.encryptedPrivateKey),
    ).rejects.toThrow(/destroyed/u);
  });

  it("is safe to destroy twice", async () => {
    const enrolled = await enrollUser(PASSWORD);
    const session = await beginUnlock(PASSWORD, enrolled.kdfSalt);
    session.destroy();
    expect(() => session.destroy()).not.toThrow();
  });
});

describe("rotateMasterPassword", () => {
  it("keeps the same userKey and private key under the new password", async () => {
    const enrolled = await enrollUser(PASSWORD);
    const rotated = await rotateMasterPassword("a brand new password", enrolled.userKey);

    const session = await beginUnlock("a brand new password", rotated.kdfSalt);
    const unlocked = await session.finish(
      rotated.protectedUserKey,
      enrolled.encryptedPrivateKey,
    );
    session.destroy();
    expect(toBase64(unlocked.userKey)).toBe(toBase64(enrolled.userKey));
    expect(toBase64(unlocked.privateKey)).toBe(toBase64(enrolled.keyPair.privateKey));
  });

  it("reports the params it actually used", async () => {
    const userKey = generateUserKey();
    expect((await rotateMasterPassword("new", userKey)).params).toEqual(DEFAULT_KDF_PARAMS);
  });

  it("issues a fresh salt and auth hash so the old password stops working", async () => {
    const enrolled = await enrollUser(PASSWORD);
    const rotated = await rotateMasterPassword("a brand new password", enrolled.userKey);

    expect(toBase64(rotated.kdfSalt)).not.toBe(toBase64(enrolled.kdfSalt));
    expect(toBase64(rotated.authHash)).not.toBe(toBase64(enrolled.authHash));
    const session = await beginUnlock(PASSWORD, rotated.kdfSalt);
    await expect(
      session.finish(rotated.protectedUserKey, enrolled.encryptedPrivateKey),
    ).rejects.toThrow(DecryptionError);
    session.destroy();
  });
});
