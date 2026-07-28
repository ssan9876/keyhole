import { describe, expect, it } from "vitest";
import { hkdf as nobleHkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import {
  createRecoveryBlob,
  deriveRecoveryAuthHash,
  deriveRecoveryKey,
  deriveRecoveryWrapKey,
  generateRecoveryCode,
  normalizeRecoveryCode,
  recoverUserKey,
} from "./recovery.js";
import { generateUserKey, unwrapKey } from "./keys.js";
import { DecryptionError, InvalidKeyError, InvalidRecoveryCodeError } from "./errors.js";
import { DEFAULT_KDF_PARAMS } from "./kdf.js";
import { toBase64, utf8Encode } from "./encoding.js";

describe("generateRecoveryCode", () => {
  it("is five groups of five Crockford characters", () => {
    expect(generateRecoveryCode()).toMatch(/^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{5}(-[0-9ABCDEFGHJKMNPQRSTVWXYZ]{5}){4}$/u);
  });

  it("never contains the ambiguous letters I, L, O, or U", () => {
    for (let i = 0; i < 200; i += 1) {
      expect(generateRecoveryCode()).not.toMatch(/[ILOU]/u);
    }
  });

  it("does not repeat", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i += 1) seen.add(generateRecoveryCode());
    expect(seen.size).toBe(200);
  });
});

describe("normalizeRecoveryCode", () => {
  it("strips formatting and uppercases", () => {
    expect(normalizeRecoveryCode("abcde-fghjk-mnpqr-stvwx-yz234")).toBe("ABCDEFGHJKMNPQRSTVWXYZ234");
    expect(normalizeRecoveryCode("ABCDE FGHJK MNPQR STVWX YZ234")).toBe("ABCDEFGHJKMNPQRSTVWXYZ234");
  });

  // Crockford's whole purpose: a human transcribing by hand cannot tell these apart.
  it("maps the ambiguous characters the way Crockford specifies", () => {
    expect(normalizeRecoveryCode("IIIII-lllll-OOOOO-00000-11111")).toBe("1111111111000000000011111");
  });

  it("rejects a code of the wrong length", () => {
    expect(() => normalizeRecoveryCode("ABCDE")).toThrow(InvalidRecoveryCodeError);
  });

  it("rejects characters outside the alphabet", () => {
    expect(() => normalizeRecoveryCode("ABCDE-FGHJK-MNPQR-STVWX-YZ23!")).toThrow(
      InvalidRecoveryCodeError,
    );
  });
});

describe("deriveRecoveryKey", () => {
  it("is insensitive to how the user typed the code", async () => {
    const salt = new Uint8Array(16).fill(0x21);
    const formatted = await deriveRecoveryKey(
      "ABCDE-FGHJK-MNPQR-STVWX-YZ234",
      salt,
      DEFAULT_KDF_PARAMS,
    );
    const messy = await deriveRecoveryKey(
      "abcde fghjk mnpqr stvwx yz234",
      salt,
      DEFAULT_KDF_PARAMS,
    );
    expect(toBase64(formatted)).toBe(toBase64(messy));
  });

  // deriveRecoveryKey did not validate its salt at all: an 8-to-15-byte salt
  // was silently accepted, violating the fixed 16-byte constraint and
  // producing a key no other client would reproduce.
  it("rejects a salt that is not 16 bytes", async () => {
    await expect(
      deriveRecoveryKey("ABCDE-FGHJK-MNPQR-STVWX-YZ234", new Uint8Array(8), DEFAULT_KDF_PARAMS),
    ).rejects.toThrow(InvalidKeyError);
  });
});

describe("recovery key split", () => {
  const CODE = "ABCDE-FGHJK-MNPQR-STVWX-YZ234";
  const SALT = new Uint8Array(16).fill(0x21);
  const recoveryKey = new Uint8Array(32).fill(0x33);

  it("derives a wrap key and an auth hash that are different from each other and from the recovery key", async () => {
    const key = await deriveRecoveryKey(CODE, SALT, DEFAULT_KDF_PARAMS);
    const wrap = deriveRecoveryWrapKey(key);
    const auth = deriveRecoveryAuthHash(key);
    expect(toBase64(wrap)).not.toBe(toBase64(auth));
    expect(toBase64(wrap)).not.toBe(toBase64(key));
    expect(toBase64(auth)).not.toBe(toBase64(key));
    expect(wrap).toHaveLength(32);
    expect(auth).toHaveLength(32);
  });

  // The info strings are wire contract, not implementation detail: a Kotlin or
  // Swift client that expands under different labels derives different halves
  // and cannot redeem a code this client issued. They must also differ from
  // "keyhole:wrap:v1" and "keyhole:auth:v1", or the recovery domain collides
  // with the master-key domain.
  it("uses exactly the info strings the spec fixes", () => {
    const expectedWrap = nobleHkdf(
      sha256,
      recoveryKey,
      undefined,
      utf8Encode("keyhole:recovery-wrap:v1"),
      32,
    );
    const expectedAuth = nobleHkdf(
      sha256,
      recoveryKey,
      undefined,
      utf8Encode("keyhole:recovery-auth:v1"),
      32,
    );
    expect(toBase64(deriveRecoveryWrapKey(recoveryKey))).toBe(toBase64(expectedWrap));
    expect(toBase64(deriveRecoveryAuthHash(recoveryKey))).toBe(toBase64(expectedAuth));
  });

  it("rejects a recovery key that is not 32 bytes", () => {
    expect(() => deriveRecoveryWrapKey(new Uint8Array(16))).toThrow(InvalidKeyError);
    expect(() => deriveRecoveryAuthHash(new Uint8Array(16))).toThrow(InvalidKeyError);
    expect(() => deriveRecoveryWrapKey(new Uint8Array(16))).toThrow(/32 bytes/);
  });

  // Redemption happens on a different device from enrolment: the auth hash the
  // server compares against was computed months earlier. Anything nondeterministic
  // in the expansion — a salt, a counter — locks the user out of their own vault.
  it("derives the same wrap key and auth hash from the same code and salt, twice", async () => {
    const first = await deriveRecoveryKey(CODE, SALT, DEFAULT_KDF_PARAMS);
    const second = await deriveRecoveryKey(CODE, SALT, DEFAULT_KDF_PARAMS);
    expect(toBase64(deriveRecoveryWrapKey(first))).toBe(toBase64(deriveRecoveryWrapKey(second)));
    expect(toBase64(deriveRecoveryAuthHash(first))).toBe(toBase64(deriveRecoveryAuthHash(second)));
  });
});

describe("recovery round trip", () => {
  it("recovers the userKey from the code alone", async () => {
    const userKey = generateUserKey();
    const code = generateRecoveryCode();
    const blob = await createRecoveryBlob(userKey, code, DEFAULT_KDF_PARAMS);
    const recovered = await recoverUserKey(
      blob.recoveryProtectedUserKey,
      code,
      blob.recoverySalt,
      blob.params,
    );
    expect(toBase64(recovered)).toBe(toBase64(userKey));
  });

  // The blob's params must come back out, or the caller cannot persist the
  // recovery_kdf_params column that spec 4.2 keeps separate from kdf_params.
  it("returns the params the blob was wrapped under", async () => {
    const blob = await createRecoveryBlob(
      generateUserKey(),
      generateRecoveryCode(),
      DEFAULT_KDF_PARAMS,
    );
    expect(blob.params).toEqual(DEFAULT_KDF_PARAMS);
  });

  it("accepts the code typed in lower case without separators", async () => {
    const userKey = generateUserKey();
    const code = generateRecoveryCode();
    const blob = await createRecoveryBlob(userKey, code, DEFAULT_KDF_PARAMS);
    const messy = code.replace(/-/gu, "").toLowerCase();
    const recovered = await recoverUserKey(
      blob.recoveryProtectedUserKey,
      messy,
      blob.recoverySalt,
      blob.params,
    );
    expect(toBase64(recovered)).toBe(toBase64(userKey));
  });

  it("fails on the wrong code", async () => {
    const blob = await createRecoveryBlob(
      generateUserKey(),
      generateRecoveryCode(),
      DEFAULT_KDF_PARAMS,
    );
    await expect(
      recoverUserKey(
        blob.recoveryProtectedUserKey,
        generateRecoveryCode(),
        blob.recoverySalt,
        blob.params,
      ),
    ).rejects.toThrow(DecryptionError);
  });
});

describe("recovery blob and the value sent to the server", () => {
  // The whole point of the split: the value sent to the server must not be the
  // value that unwraps the key. If it were, the server could open every vault
  // whose owner ever redeemed a code.
  it("produces an auth hash the blob cannot be opened with", async () => {
    const blob = await createRecoveryBlob(
      generateUserKey(),
      generateRecoveryCode(),
      DEFAULT_KDF_PARAMS,
    );
    await expect(
      unwrapKey(blob.recoveryProtectedUserKey, blob.recoveryAuthHash),
    ).rejects.toThrow(DecryptionError);
  });

  // The negative half is the one that matters. Wrapping under the raw
  // recoveryKey round-trips just as happily and still keeps the auth hash from
  // opening the blob, so both other tests pass under that regression; only this
  // one pins that the blob is sealed to the wrap half specifically.
  it("wraps under the wrap half, not the raw recovery key", async () => {
    const userKey = generateUserKey();
    const code = generateRecoveryCode();
    const blob = await createRecoveryBlob(userKey, code, DEFAULT_KDF_PARAMS);
    const recoveryKey = await deriveRecoveryKey(code, blob.recoverySalt, blob.params);

    const opened = await unwrapKey(
      blob.recoveryProtectedUserKey,
      deriveRecoveryWrapKey(recoveryKey),
    );
    expect(toBase64(opened)).toBe(toBase64(userKey));
    await expect(unwrapKey(blob.recoveryProtectedUserKey, recoveryKey)).rejects.toThrow(
      DecryptionError,
    );
  });

  // What the server stores at enrolment must be what a redeeming client — a
  // different device, holding only the code — recomputes from the salt and
  // params the server hands back. Anything else and no correct code ever
  // redeems. This also catches the auth half being zeroized alongside the
  // wrap half, which would ship a buffer of zeros as the credential.
  it("returns the auth hash a redeeming client recomputes from the code and salt", async () => {
    const code = generateRecoveryCode();
    const blob = await createRecoveryBlob(generateUserKey(), code, DEFAULT_KDF_PARAMS);
    const recoveryKey = await deriveRecoveryKey(code, blob.recoverySalt, blob.params);
    expect(toBase64(blob.recoveryAuthHash)).toBe(toBase64(deriveRecoveryAuthHash(recoveryKey)));
  });
});
