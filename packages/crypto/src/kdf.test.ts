import { describe, expect, it } from "vitest";
import * as argon2rs from "@node-rs/argon2";
const { hashRaw } = argon2rs;
import { hkdf as nobleHkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import {
  DEFAULT_KDF_PARAMS,
  deriveAuthHash,
  deriveMasterKey,
  deriveWrapKey,
  generateKdfSalt,
} from "./kdf.js";
import { toBase64, utf8Encode } from "./encoding.js";

const SALT = new Uint8Array(16).fill(0x42);
const PASSWORD = "correct horse battery staple";

describe("DEFAULT_KDF_PARAMS", () => {
  it("matches the values fixed in the spec", () => {
    expect(DEFAULT_KDF_PARAMS).toEqual({
      algorithm: "argon2id",
      memoryKiB: 65536,
      iterations: 3,
      parallelism: 4,
    });
  });
});

describe("deriveMasterKey", () => {
  it("produces 32 bytes", async () => {
    const key = await deriveMasterKey(PASSWORD, SALT);
    expect(key).toHaveLength(32);
  });

  it("is deterministic", async () => {
    const a = await deriveMasterKey(PASSWORD, SALT);
    const b = await deriveMasterKey(PASSWORD, SALT);
    expect(toBase64(a)).toBe(toBase64(b));
  });

  it("changes with the password and with the salt", async () => {
    const base = toBase64(await deriveMasterKey(PASSWORD, SALT));
    const otherPassword = toBase64(await deriveMasterKey(`${PASSWORD}!`, SALT));
    const otherSalt = toBase64(await deriveMasterKey(PASSWORD, new Uint8Array(16).fill(0x43)));
    expect(otherPassword).not.toBe(base);
    expect(otherSalt).not.toBe(base);
  });

  // The point of this test: our WASM Argon2id must agree byte-for-byte with a
  // completely independent native Rust implementation. That is what makes the
  // frozen vectors meaningful for a future Kotlin or Swift port.
  it("agrees with an independent native Argon2id implementation", async () => {
    const ours = await deriveMasterKey(PASSWORD, SALT);
    const theirs = await hashRaw(PASSWORD, {
      salt: Buffer.from(SALT),
      memoryCost: DEFAULT_KDF_PARAMS.memoryKiB,
      timeCost: DEFAULT_KDF_PARAMS.iterations,
      parallelism: DEFAULT_KDF_PARAMS.parallelism,
      outputLen: 32,
      algorithm: argon2rs.Algorithm.Argon2id,
      version: argon2rs.Version.V0x13,
    });
    expect(toBase64(ours)).toBe(toBase64(new Uint8Array(theirs)));
  });

  it("normalizes Unicode passwords to NFC so equivalent inputs agree", async () => {
    // "é" as a single code point vs. "e" + combining acute.
    const composed = await deriveMasterKey("café", SALT);
    const decomposed = await deriveMasterKey("café", SALT);
    expect(toBase64(composed)).toBe(toBase64(decomposed));
  });

  it("rejects a salt that is not 16 bytes", async () => {
    await expect(deriveMasterKey(PASSWORD, new Uint8Array(8))).rejects.toThrow(/16 bytes/);
  });

  it("rejects an empty password", async () => {
    await expect(deriveMasterKey("", SALT)).rejects.toThrow(/empty/);
  });
});

describe("HKDF derivation", () => {
  const masterKey = new Uint8Array(32).fill(0x11);

  it("produces 32-byte keys", () => {
    expect(deriveWrapKey(masterKey)).toHaveLength(32);
    expect(deriveAuthHash(masterKey)).toHaveLength(32);
  });

  it("separates the two domains", () => {
    expect(toBase64(deriveWrapKey(masterKey))).not.toBe(toBase64(deriveAuthHash(masterKey)));
  });

  it("uses exactly the info strings the spec fixes", () => {
    const expectedWrap = nobleHkdf(sha256, masterKey, undefined, utf8Encode("keyhole:wrap:v1"), 32);
    const expectedAuth = nobleHkdf(sha256, masterKey, undefined, utf8Encode("keyhole:auth:v1"), 32);
    expect(toBase64(deriveWrapKey(masterKey))).toBe(toBase64(expectedWrap));
    expect(toBase64(deriveAuthHash(masterKey))).toBe(toBase64(expectedAuth));
  });

  it("matches RFC 5869 test case 1, proving the HKDF construction itself", () => {
    const ikm = new Uint8Array(22).fill(0x0b);
    const salt = Uint8Array.from([
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ]);
    const info = Uint8Array.from([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]);
    const okm = nobleHkdf(sha256, ikm, salt, info, 42);
    const hex = Array.from(okm)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(hex).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
  });

  it("rejects a master key that is not 32 bytes", () => {
    expect(() => deriveWrapKey(new Uint8Array(16))).toThrow(/32 bytes/);
    expect(() => deriveAuthHash(new Uint8Array(16))).toThrow(/32 bytes/);
  });
});

describe("generateKdfSalt", () => {
  it("returns 16 unpredictable bytes", () => {
    expect(generateKdfSalt()).toHaveLength(16);
    expect(toBase64(generateKdfSalt())).not.toBe(toBase64(generateKdfSalt()));
  });
});
