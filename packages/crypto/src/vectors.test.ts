import { describe, expect, it } from "vitest";
import vectors from "../vectors/vectors.json" with { type: "json" };
import { deriveAuthHash, deriveMasterKey, deriveWrapKey } from "./kdf.js";
import { decryptBytes, encryptBytesWithNonce, type Envelope } from "./symmetric.js";
import { openSealed, sealToUserWithEphemeral } from "./seal.js";
import { publicKeyFor } from "./keys.js";
import { publicKeyFingerprint } from "./fingerprint.js";
import { deriveRecoveryKey } from "./recovery.js";
import { fromBase64, toBase64, utf8Decode } from "./encoding.js";

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
    );
    expect(toBase64(key)).toBe(vectors.recovery.recoveryKeyBase64);
  });

  it("reproduces the fingerprint", () => {
    expect(
      publicKeyFingerprint(fromBase64(vectors.fingerprint.publicKeyBase64), vectors.fingerprint.email),
    ).toBe(vectors.fingerprint.fingerprint);
  });
});
