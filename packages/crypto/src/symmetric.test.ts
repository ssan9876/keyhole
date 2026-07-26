import { describe, expect, it } from "vitest";
import { createCipheriv } from "node:crypto";
import fc from "fast-check";
import {
  decryptBytes,
  decryptString,
  encryptBytes,
  encryptBytesWithNonce,
  encryptString,
  parseEnvelope,
  serializeEnvelope,
} from "./symmetric.js";
import {
  DecryptionError,
  InvalidKeyError,
  KeyholeCryptoError,
  MalformedEnvelopeError,
} from "./errors.js";
import { fromBase64, toBase64, utf8Encode } from "./encoding.js";

const KEY = new Uint8Array(32).fill(0x07);
const NONCE = new Uint8Array(12).fill(0x09);

describe("encryptBytes", () => {
  it("produces a v1 A256GCM envelope with a 12-byte nonce", async () => {
    const envelope = await encryptBytes(utf8Encode("hello"), KEY);
    expect(envelope.v).toBe(1);
    expect(envelope.alg).toBe("A256GCM");
    expect(fromBase64(envelope.n)).toHaveLength(12);
  });

  it("never reuses a nonce", async () => {
    const nonces = new Set<string>();
    for (let i = 0; i < 50; i += 1) {
      nonces.add((await encryptBytes(utf8Encode("same"), KEY)).n);
    }
    expect(nonces.size).toBe(50);
  });

  it("appends the 16-byte GCM tag to the ciphertext", async () => {
    const plaintext = utf8Encode("hello");
    const envelope = await encryptBytes(plaintext, KEY);
    expect(fromBase64(envelope.ct)).toHaveLength(plaintext.length + 16);
  });

  // A web app catching KeyholeCryptoError must catch every failure this
  // package can raise, or it gets an unhandled rejection where it wanted a
  // lock screen.
  it("rejects a key that is not 32 bytes with a typed error", async () => {
    await expect(encryptBytes(utf8Encode("x"), new Uint8Array(16))).rejects.toThrow(InvalidKeyError);
    await expect(encryptBytes(utf8Encode("x"), new Uint8Array(16))).rejects.toThrow(
      KeyholeCryptoError,
    );
    await expect(encryptBytes(utf8Encode("x"), new Uint8Array(16))).rejects.toThrow(/32 bytes/);
  });

  it("rejects a nonce that is not 12 bytes with a typed error", async () => {
    await expect(
      encryptBytesWithNonce(utf8Encode("x"), KEY, new Uint8Array(16)),
    ).rejects.toThrow(InvalidKeyError);
  });
});

describe("cross-implementation agreement", () => {
  // WebCrypto AES-GCM must match OpenSSL via Node's crypto for the same
  // key, nonce, and plaintext. Two independent implementations agreeing is
  // what makes the frozen vector worth anything.
  it("matches Node/OpenSSL AES-256-GCM", async () => {
    const plaintext = utf8Encode("attack at dawn");
    const ours = await encryptBytesWithNonce(plaintext, KEY, NONCE);

    const cipher = createCipheriv("aes-256-gcm", Buffer.from(KEY), Buffer.from(NONCE));
    const body = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
    const theirs = Buffer.concat([body, cipher.getAuthTag()]);

    expect(ours.ct).toBe(toBase64(new Uint8Array(theirs)));
  });
});

describe("decryptBytes", () => {
  it("round-trips", async () => {
    const plaintext = utf8Encode("round trip");
    const envelope = await encryptBytes(plaintext, KEY);
    expect(Array.from(await decryptBytes(envelope, KEY))).toEqual(Array.from(plaintext));
  });

  it("round-trips arbitrary byte lengths", async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 2048 }), async (bytes) => {
        const envelope = await encryptBytes(bytes, KEY);
        expect(Array.from(await decryptBytes(envelope, KEY))).toEqual(Array.from(bytes));
      }),
      { numRuns: 25 },
    );
  });

  it("throws DecryptionError under the wrong key", async () => {
    const envelope = await encryptBytes(utf8Encode("secret"), KEY);
    await expect(decryptBytes(envelope, new Uint8Array(32).fill(0x08))).rejects.toThrow(
      DecryptionError,
    );
  });

  it("throws DecryptionError when the ciphertext is tampered with", async () => {
    const envelope = await encryptBytes(utf8Encode("secret"), KEY);
    const bytes = fromBase64(envelope.ct);
    bytes[0]! ^= 0xff;
    await expect(decryptBytes({ ...envelope, ct: toBase64(bytes) }, KEY)).rejects.toThrow(
      DecryptionError,
    );
  });

  it("throws DecryptionError when the tag is tampered with", async () => {
    const envelope = await encryptBytes(utf8Encode("secret"), KEY);
    const bytes = fromBase64(envelope.ct);
    bytes[bytes.length - 1]! ^= 0xff;
    await expect(decryptBytes({ ...envelope, ct: toBase64(bytes) }, KEY)).rejects.toThrow(
      DecryptionError,
    );
  });

  it("reveals nothing about why decryption failed", async () => {
    const envelope = await encryptBytes(utf8Encode("secret"), KEY);
    await expect(decryptBytes(envelope, new Uint8Array(32).fill(0x08))).rejects.toThrow(
      "Decryption failed: wrong key or corrupted data",
    );
  });
});

describe("serializeEnvelope / parseEnvelope", () => {
  it("round-trips", async () => {
    const envelope = await encryptBytes(utf8Encode("x"), KEY);
    expect(parseEnvelope(serializeEnvelope(envelope))).toEqual(envelope);
  });

  it("rejects malformed JSON", () => {
    expect(() => parseEnvelope("not json")).toThrow(MalformedEnvelopeError);
  });

  it("rejects an unknown version", () => {
    expect(() => parseEnvelope('{"v":2,"alg":"A256GCM","n":"AA","ct":"AA"}')).toThrow(
      MalformedEnvelopeError,
    );
  });

  it("rejects an unknown algorithm", () => {
    expect(() => parseEnvelope('{"v":1,"alg":"AES-CBC","n":"AA","ct":"AA"}')).toThrow(
      MalformedEnvelopeError,
    );
  });

  it("rejects missing fields", () => {
    expect(() => parseEnvelope('{"v":1,"alg":"A256GCM"}')).toThrow(MalformedEnvelopeError);
  });
});

describe("string helpers", () => {
  it("round-trip non-ASCII text", async () => {
    const text = "pässwörd 🔑";
    expect(await decryptString(await encryptString(text, KEY), KEY)).toBe(text);
  });
});
