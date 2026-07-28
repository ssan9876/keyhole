import { describe, expect, it } from "vitest";
import vectors from "../vectors/vectors.json" with { type: "json" };
import { DEFAULT_KDF_PARAMS, deriveAuthHash, deriveMasterKey, deriveWrapKey } from "./kdf.js";
import {
  decryptBytes,
  encryptBytesWithNonce,
  serializeEnvelope,
  type Envelope,
} from "./symmetric.js";
import { openSealed, sealToUserWithEphemeral } from "./seal.js";
import { publicKeyFor, unwrapKey } from "./keys.js";
import { decryptItem, encryptItem, type ItemPlaintext } from "./item.js";
import { publicKeyFingerprint } from "./fingerprint.js";
import { CROCKFORD_ALPHABET, encodeCrockford } from "./crockford.js";
import {
  deriveRecoveryAuthHash,
  deriveRecoveryKey,
  deriveRecoveryWrapKey,
  recoverUserKey,
} from "./recovery.js";
import { DecryptionError } from "./errors.js";
import { fromBase64, toBase64, utf8Decode, utf8Encode } from "./encoding.js";

// These assertions are the contract every Keyhole client must satisfy — the
// TypeScript one today, the Kotlin and Swift ones later. A failure here means
// the wire format changed and existing vaults will not open.
describe("frozen vectors", () => {
  it("reproduces the KDF chain", async () => {
    const masterKey = await deriveMasterKey(
      vectors.kdf.masterPassword,
      fromBase64(vectors.kdf.kdfSaltBase64),
    );
    expect(toBase64(masterKey)).toBe(vectors.kdf.masterKeyBase64);
    expect(toBase64(deriveWrapKey(masterKey))).toBe(vectors.kdf.wrapKeyBase64);
    expect(toBase64(deriveAuthHash(masterKey))).toBe(vectors.kdf.authHashBase64);
  });

  it("reproduces the AES-GCM envelope", async () => {
    const envelope = await encryptBytesWithNonce(
      new TextEncoder().encode(vectors.aesGcm.plaintextUtf8),
      fromBase64(vectors.aesGcm.keyBase64),
      fromBase64(vectors.aesGcm.nonceBase64),
    );
    expect(envelope).toEqual(vectors.aesGcm.envelope);
  });

  it("decrypts the frozen envelope back to the original plaintext", async () => {
    const plaintext = await decryptBytes(
      // JSON module imports widen literal types (`v: 1` -> `v: number`), so the
      // frozen envelope needs a cast back to the exact wire shape it was
      // generated from.
      vectors.aesGcm.envelope as Envelope,
      fromBase64(vectors.aesGcm.keyBase64),
    );
    expect(utf8Decode(plaintext)).toBe(vectors.aesGcm.plaintextUtf8);
  });

  it("reproduces the sealed key and opens it", async () => {
    const recipientPublic = publicKeyFor(fromBase64(vectors.seal.recipientPrivateKeyBase64));
    expect(toBase64(recipientPublic)).toBe(vectors.seal.recipientPublicKeyBase64);

    const sealed = await sealToUserWithEphemeral(
      fromBase64(vectors.seal.secretBase64),
      recipientPublic,
      fromBase64(vectors.seal.ephemeralPrivateKeyBase64),
      fromBase64(vectors.seal.nonceBase64),
    );
    expect(JSON.parse(sealed)).toEqual(vectors.seal.sealed);

    const opened = await openSealed(sealed, fromBase64(vectors.seal.recipientPrivateKeyBase64));
    expect(toBase64(opened)).toBe(vectors.seal.secretBase64);
  });

  it("reproduces the recovery key", async () => {
    const key = await deriveRecoveryKey(
      vectors.recovery.code,
      fromBase64(vectors.recovery.recoverySaltBase64),
      DEFAULT_KDF_PARAMS,
    );
    expect(toBase64(key)).toBe(vectors.recovery.recoveryKeyBase64);
  });

  it("reproduces the fingerprint", () => {
    expect(
      publicKeyFingerprint(fromBase64(vectors.fingerprint.publicKeyBase64), vectors.fingerprint.email),
    ).toBe(vectors.fingerprint.fingerprint);
  });
});

// The params block states the rules a porter cannot infer from the arithmetic.
// These assertions keep it honest: a rule that drifts from the code is worse
// than no rule, because a porter will trust it.
describe("frozen vectors: the documented parameters match the code", () => {
  it("states the Argon2id parameters this package actually uses", () => {
    expect(vectors.params.argon2id.memoryKiB).toBe(DEFAULT_KDF_PARAMS.memoryKiB);
    expect(vectors.params.argon2id.iterations).toBe(DEFAULT_KDF_PARAMS.iterations);
    expect(vectors.params.argon2id.parallelism).toBe(DEFAULT_KDF_PARAMS.parallelism);
    expect(vectors.params.argon2id.version).toBe(0x13);
    expect(vectors.params.argon2id.saltBytes).toBe(16);
    expect(vectors.params.argon2id.outputBytes).toBe(32);
  });

  it("states the HKDF info strings byte-for-byte, in both encodings", () => {
    const { wrap, auth, seal, recoveryWrap, recoveryAuth } = vectors.params.hkdf.info;
    expect(wrap.utf8).toBe("keyhole:wrap:v1");
    expect(auth.utf8).toBe("keyhole:auth:v1");
    expect(seal.utf8).toBe("keyhole:seal:v1");
    expect(recoveryWrap.utf8).toBe("keyhole:recovery-wrap:v1");
    expect(recoveryAuth.utf8).toBe("keyhole:recovery-auth:v1");
    expect(toBase64(utf8Encode(wrap.utf8))).toBe(wrap.base64);
    expect(toBase64(utf8Encode(auth.utf8))).toBe(auth.base64);
    expect(toBase64(utf8Encode(seal.utf8))).toBe(seal.base64);
    expect(toBase64(utf8Encode(recoveryWrap.utf8))).toBe(recoveryWrap.base64);
    expect(toBase64(utf8Encode(recoveryAuth.utf8))).toBe(recoveryAuth.base64);
    // Five labels, five domains. A recovery label that collided with a
    // master-key one would make the recovery key expand into a value already
    // in use elsewhere in the hierarchy.
    expect(
      new Set([wrap.utf8, auth.utf8, seal.utf8, recoveryWrap.utf8, recoveryAuth.utf8]).size,
    ).toBe(5);
    expect(vectors.params.hkdf.hash).toBe("SHA-256");
    expect(vectors.params.hkdf.outputBytes).toBe(32);
  });

  it("states the seal info concatenation order the implementation uses", () => {
    expect(vectors.params.seal.infoConcatenation).toBe(
      '"keyhole:seal:v1" || ephemeralPublicKey || recipientPublicKey',
    );
    expect(vectors.params.seal.secretBytes).toBe(32);
  });

  // A porter reaching for a Crockford Base32 library gets different output,
  // because this is a byte-to-character mapping, not a bit-packing base32.
  it("states the Crockford alphabet and the one-character-per-byte rule", () => {
    expect(vectors.params.crockford.alphabet).toBe(CROCKFORD_ALPHABET);
    expect(vectors.params.crockford.warning).toContain("NOT standard Base32");
    // 3 bytes are 3 characters here; real Base32 would give 5 (plus padding).
    expect(encodeCrockford(new Uint8Array([0x00, 0x1f, 0x20]))).toHaveLength(3);
    expect(encodeCrockford(new Uint8Array([0x00, 0x1f, 0x20]))).toBe("0Z0");
  });

  it("states the AES-GCM and key-length constraints", () => {
    expect(vectors.params.aesGcm.nonceBits).toBe(96);
    expect(vectors.params.aesGcm.tagBits).toBe(128);
    expect(vectors.params.aesGcm.keyBytes).toBe(32);
    expect(vectors.params.keyLengths.kdfSalt).toBe(16);
    expect(vectors.params.keyLengths.userKey).toBe(32);
    expect(vectors.params.keyLengths.x25519PublicKey).toBe(32);
  });
});

// The highest-value vectors: the arithmetic is easy to reproduce, the
// normalization is easy to forget, and forgetting it locks a real user out.
describe("frozen vectors: normalization", () => {
  it("derives one master key from both Unicode spellings of the password", async () => {
    const { precomposedUtf8, decomposedUtf8, saltBase64, masterKeyBase64 } =
      vectors.normalization.password;

    // Guard the vector itself: if a tool ever normalizes the JSON, these two
    // become the same string and the test below would pass while proving
    // nothing.
    expect(precomposedUtf8).not.toBe(decomposedUtf8);
    expect(Array.from(precomposedUtf8).map((c) => c.codePointAt(0))).toEqual([0x63, 0x61, 0x66, 0xe9]);
    expect(Array.from(decomposedUtf8).map((c) => c.codePointAt(0))).toEqual([
      0x63, 0x61, 0x66, 0x65, 0x301,
    ]);

    const salt = fromBase64(saltBase64);
    expect(toBase64(await deriveMasterKey(precomposedUtf8, salt))).toBe(masterKeyBase64);
    expect(toBase64(await deriveMasterKey(decomposedUtf8, salt))).toBe(masterKeyBase64);
  });

  it("fingerprints an untrimmed, mixed-case email the same as the canonical form", () => {
    const { canonical, asTyped, publicKeyBase64, fingerprint } = vectors.normalization.email;
    expect(asTyped).not.toBe(canonical);
    const publicKey = fromBase64(publicKeyBase64);
    expect(publicKeyFingerprint(publicKey, asTyped)).toBe(fingerprint);
    expect(publicKeyFingerprint(publicKey, canonical)).toBe(fingerprint);
  });

  it("derives one recovery key however the code was typed", async () => {
    const { canonical, asTyped, recoverySaltBase64, recoveryKeyBase64 } =
      vectors.normalization.recoveryCode;
    // Guard the vector itself: if canonical and asTyped were ever the same
    // string, deriving the same key from the same input would pass this test
    // while proving nothing about normalization.
    expect(asTyped).not.toBe(canonical);
    const salt = fromBase64(recoverySaltBase64);
    expect(toBase64(await deriveRecoveryKey(asTyped, salt, DEFAULT_KDF_PARAMS))).toBe(
      recoveryKeyBase64,
    );
    expect(toBase64(await deriveRecoveryKey(canonical, salt, DEFAULT_KDF_PARAMS))).toBe(
      recoveryKeyBase64,
    );
  });
});

describe("frozen vectors: item plaintext", () => {
  it("pins the exact JSON that gets encrypted, for both variants", () => {
    expect(JSON.stringify(vectors.itemPlaintext.login.object)).toBe(vectors.itemPlaintext.login.json);
    expect(JSON.stringify(vectors.itemPlaintext.note.object)).toBe(vectors.itemPlaintext.note.json);
  });

  // Item plaintext is a discriminated union, not one struct with optional
  // fields: a note carries no username, password, urls or passwordHistory.
  it("shows a note carrying none of the login-only fields", () => {
    expect(Object.keys(vectors.itemPlaintext.note.object).sort()).toEqual([
      "favorite",
      "folderId",
      "name",
      "notes",
      "type",
    ]);
    expect(Object.keys(vectors.itemPlaintext.login.object).sort()).toEqual([
      "favorite",
      "folderId",
      "name",
      "notes",
      "password",
      "passwordHistory",
      "type",
      "urls",
      "username",
    ]);
  });

  it("round-trips both variants through the real item path", async () => {
    const parentKey = new Uint8Array(32).fill(0x77);
    for (const variant of [vectors.itemPlaintext.login, vectors.itemPlaintext.note]) {
      const item = variant.object as ItemPlaintext;
      expect(await decryptItem(await encryptItem(item, parentKey), parentKey)).toEqual(item);
    }
  });
});

// One unbroken chain from the master password to an item key, so a porter
// whose end-to-end test fails can bisect in one step instead of five.
describe("frozen vectors: composed key hierarchy", () => {
  it("chains onto the KDF vector rather than inventing a wrapping key", () => {
    expect(vectors.composed.wrappingKeyBase64).toBe(vectors.kdf.wrapKeyBase64);
  });

  it("reproduces protectedUserKey byte-for-byte and unwraps it", async () => {
    const wrappingKey = fromBase64(vectors.composed.wrappingKeyBase64);
    const userKey = fromBase64(vectors.composed.userKeyBase64);
    const envelope = await encryptBytesWithNonce(
      userKey,
      wrappingKey,
      fromBase64(vectors.composed.protectedUserKeyNonceBase64),
    );
    expect(serializeEnvelope(envelope)).toBe(vectors.composed.protectedUserKey);
    expect(toBase64(await unwrapKey(vectors.composed.protectedUserKey, wrappingKey))).toBe(
      vectors.composed.userKeyBase64,
    );
  });

  it("reproduces wrappedItemKey byte-for-byte and unwraps it under the userKey", async () => {
    const userKey = fromBase64(vectors.composed.userKeyBase64);
    const itemKey = fromBase64(vectors.composed.itemKeyBase64);
    const envelope = await encryptBytesWithNonce(
      itemKey,
      userKey,
      fromBase64(vectors.composed.wrappedItemKeyNonceBase64),
    );
    expect(serializeEnvelope(envelope)).toBe(vectors.composed.wrappedItemKey);
    expect(toBase64(await unwrapKey(vectors.composed.wrappedItemKey, userKey))).toBe(
      vectors.composed.itemKeyBase64,
    );
  });

  it("walks the whole chain from the master password", async () => {
    const masterKey = await deriveMasterKey(
      vectors.kdf.masterPassword,
      fromBase64(vectors.kdf.kdfSaltBase64),
    );
    const wrappingKey = deriveWrapKey(masterKey);
    const userKey = await unwrapKey(vectors.composed.protectedUserKey, wrappingKey);
    const itemKey = await unwrapKey(vectors.composed.wrappedItemKey, userKey);
    expect(toBase64(itemKey)).toBe(vectors.composed.itemKeyBase64);
  });
});

// The second route to the same userKey. The recovery key is expanded twice —
// once into the half that opens the blob, once into the half uploaded as proof
// the caller holds the code — and nothing about a 32-byte value says which
// info string produced it. A port that copies the master-key labels, or types
// `v2`, derives two plausible keys and finds out at redemption: after the user
// has already lost their master password, with this as the last resort. That
// is why these are pinned as literals rather than recomputed here.
describe("frozen vectors: recovery key split", () => {
  const recoverySalt = fromBase64(vectors.recoverySplit.recoverySaltBase64);

  it("chains onto the recovery vector rather than deriving a second recovery key", () => {
    expect(vectors.recoverySplit.code).toBe(vectors.recovery.code);
    expect(vectors.recoverySplit.recoverySaltBase64).toBe(vectors.recovery.recoverySaltBase64);
    expect(vectors.recoverySplit.recoveryKeyBase64).toBe(vectors.recovery.recoveryKeyBase64);
  });

  // Recovery carries its own kdf params (spec 4.2 keeps recovery_kdf_params
  // separate), so the vector must say which ones its pinned key was derived
  // under rather than leaving a porter to assume the account's.
  it("states the KDF params the pinned recovery key was derived under", () => {
    expect(vectors.recoverySplit.params.memoryKiB).toBe(DEFAULT_KDF_PARAMS.memoryKiB);
    expect(vectors.recoverySplit.params.iterations).toBe(DEFAULT_KDF_PARAMS.iterations);
    expect(vectors.recoverySplit.params.parallelism).toBe(DEFAULT_KDF_PARAMS.parallelism);
  });

  it("reproduces both halves from the recovery code", async () => {
    const recoveryKey = await deriveRecoveryKey(
      vectors.recoverySplit.code,
      recoverySalt,
      DEFAULT_KDF_PARAMS,
    );
    expect(toBase64(recoveryKey)).toBe(vectors.recoverySplit.recoveryKeyBase64);
    expect(toBase64(deriveRecoveryWrapKey(recoveryKey))).toBe(vectors.recoverySplit.wrapKeyBase64);
    expect(toBase64(deriveRecoveryAuthHash(recoveryKey))).toBe(
      vectors.recoverySplit.authHashBase64,
    );
  });

  // Three distinct literals. If a future change made two of them equal, every
  // derivation assertion above would still pass — each would be a value equal
  // to itself — while the credential the server holds had become the one that
  // opens the vault.
  it("pins three distinct values, so the uploaded half is not the unwrapping half", () => {
    const { recoveryKeyBase64, wrapKeyBase64, authHashBase64 } = vectors.recoverySplit;
    expect(new Set([recoveryKeyBase64, wrapKeyBase64, authHashBase64]).size).toBe(3);
  });

  it("reproduces recoveryProtectedUserKey byte-for-byte and unwraps it under the wrap half", async () => {
    const wrapKey = fromBase64(vectors.recoverySplit.wrapKeyBase64);
    const envelope = await encryptBytesWithNonce(
      fromBase64(vectors.recoverySplit.userKeyBase64),
      wrapKey,
      fromBase64(vectors.recoverySplit.recoveryProtectedUserKeyNonceBase64),
    );
    expect(serializeEnvelope(envelope)).toBe(vectors.recoverySplit.recoveryProtectedUserKey);
    expect(toBase64(await unwrapKey(vectors.recoverySplit.recoveryProtectedUserKey, wrapKey))).toBe(
      vectors.recoverySplit.userKeyBase64,
    );
  });

  // The property the split exists for, frozen rather than merely round-tripped:
  // the credential the server stores must not open the blob the server stores.
  it("cannot be opened with the auth half the server holds, nor with the recovery key", async () => {
    await expect(
      unwrapKey(
        vectors.recoverySplit.recoveryProtectedUserKey,
        fromBase64(vectors.recoverySplit.authHashBase64),
      ),
    ).rejects.toThrow(DecryptionError);
    await expect(
      unwrapKey(
        vectors.recoverySplit.recoveryProtectedUserKey,
        fromBase64(vectors.recoverySplit.recoveryKeyBase64),
      ),
    ).rejects.toThrow(DecryptionError);
  });

  // One account has one userKey, wrapped twice. Recovery that returned some
  // other key would decrypt nothing in the vault it was supposed to restore.
  it("recovers, from the code alone, the same userKey the master-password chain unwraps", async () => {
    expect(vectors.recoverySplit.userKeyBase64).toBe(vectors.composed.userKeyBase64);
    const userKey = await recoverUserKey(
      vectors.recoverySplit.recoveryProtectedUserKey,
      vectors.recoverySplit.code,
      recoverySalt,
      DEFAULT_KDF_PARAMS,
    );
    expect(toBase64(userKey)).toBe(vectors.recoverySplit.userKeyBase64);
  });
});
