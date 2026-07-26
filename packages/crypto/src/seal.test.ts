import { describe, expect, it } from "vitest";
import {
  openSealed,
  sealToUser,
  sealToUserWithEphemeral,
} from "./seal.js";
import { generateCollectionKey, generateKeyPair } from "./keys.js";
import { DecryptionError, InvalidKeyError, MalformedEnvelopeError } from "./errors.js";
import { toBase64 } from "./encoding.js";

describe("sealToUser / openSealed", () => {
  it("lets only the holder of the private key recover the secret", async () => {
    const recipient = generateKeyPair();
    const secret = generateCollectionKey();
    const sealed = await sealToUser(secret, recipient.publicKey);
    expect(toBase64(await openSealed(sealed, recipient.privateKey))).toBe(toBase64(secret));
  });

  it("cannot be opened by a different private key", async () => {
    const recipient = generateKeyPair();
    const stranger = generateKeyPair();
    const sealed = await sealToUser(generateCollectionKey(), recipient.publicKey);
    await expect(openSealed(sealed, stranger.privateKey)).rejects.toThrow(DecryptionError);
  });

  it("produces a fresh ephemeral key every time, so sealing twice differs", async () => {
    const recipient = generateKeyPair();
    const secret = generateCollectionKey();
    const first = JSON.parse(await sealToUser(secret, recipient.publicKey));
    const second = JSON.parse(await sealToUser(secret, recipient.publicKey));
    expect(first.epk).not.toBe(second.epk);
    expect(first.ct).not.toBe(second.ct);
  });

  it("seals the same collection key to several members independently", async () => {
    const secret = generateCollectionKey();
    const members = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
    const sealedPerMember = await Promise.all(
      members.map((member) => sealToUser(secret, member.publicKey)),
    );
    for (const [index, member] of members.entries()) {
      const opened = await openSealed(sealedPerMember[index] as string, member.privateKey);
      expect(toBase64(opened)).toBe(toBase64(secret));
    }
  });

  it("is deterministic when the ephemeral key and nonce are fixed", async () => {
    const recipient = generateKeyPair();
    const ephemeral = generateKeyPair();
    const secret = new Uint8Array(32).fill(0x5a);
    const nonce = new Uint8Array(12).fill(0x01);
    const a = await sealToUserWithEphemeral(secret, recipient.publicKey, ephemeral.privateKey, nonce);
    const b = await sealToUserWithEphemeral(secret, recipient.publicKey, ephemeral.privateKey, nonce);
    expect(a).toBe(b);
  });

  it("rejects tampering with the ephemeral public key", async () => {
    const recipient = generateKeyPair();
    const sealed = JSON.parse(await sealToUser(generateCollectionKey(), recipient.publicKey));
    const other = generateKeyPair();
    const tampered = JSON.stringify({ ...sealed, epk: toBase64(other.publicKey) });
    await expect(openSealed(tampered, recipient.privateKey)).rejects.toThrow(DecryptionError);
  });

  it("rejects a malformed sealed blob", async () => {
    const recipient = generateKeyPair();
    await expect(openSealed("not json", recipient.privateKey)).rejects.toThrow(
      MalformedEnvelopeError,
    );
    await expect(
      openSealed('{"v":1,"alg":"wrong","epk":"AA","n":"AA","ct":"AA"}', recipient.privateKey),
    ).rejects.toThrow(MalformedEnvelopeError);
  });

  it("rejects a recipient public key that is not 32 bytes", async () => {
    await expect(sealToUser(generateCollectionKey(), new Uint8Array(16))).rejects.toThrow(
      InvalidKeyError,
    );
    await expect(sealToUser(generateCollectionKey(), new Uint8Array(16))).rejects.toThrow(
      /32 bytes/,
    );
  });

  // A compromised server can seal arbitrary bytes to a user as a "collection
  // key". Without this check the wrong-length result reaches decryptItem and
  // AES-GCM key import throws — outside the error taxonomy, so a caller
  // catching KeyholeCryptoError gets an unhandled rejection instead.
  it("refuses to return an opened secret that is not a 32-byte key", async () => {
    const recipient = generateKeyPair();
    const notAKey = new Uint8Array(16).fill(0xaa);
    const sealed = await sealToUser(notAKey, recipient.publicKey);
    await expect(openSealed(sealed, recipient.privateKey)).rejects.toThrow(DecryptionError);
  });

  it("rejects a sealed blob whose epk is the wrong length", async () => {
    const recipient = generateKeyPair();
    const sealed = JSON.parse(await sealToUser(generateCollectionKey(), recipient.publicKey));
    const tampered = JSON.stringify({ ...sealed, epk: toBase64(new Uint8Array(16)) });
    await expect(openSealed(tampered, recipient.privateKey)).rejects.toThrow(
      MalformedEnvelopeError,
    );
  });

  it("rejects a sealed blob whose epk is not valid base64", async () => {
    const recipient = generateKeyPair();
    const sealed = JSON.parse(await sealToUser(generateCollectionKey(), recipient.publicKey));
    const tampered = JSON.stringify({ ...sealed, epk: "not-valid-base64!!" });
    await expect(openSealed(tampered, recipient.privateKey)).rejects.toThrow(
      MalformedEnvelopeError,
    );
  });
});
