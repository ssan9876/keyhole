import { describe, expect, it } from "vitest";
import {
  createRecoveryBlob,
  deriveRecoveryKey,
  generateRecoveryCode,
  normalizeRecoveryCode,
  recoverUserKey,
} from "./recovery.js";
import { generateUserKey } from "./keys.js";
import { DecryptionError, InvalidRecoveryCodeError } from "./errors.js";
import { toBase64 } from "./encoding.js";

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
    const formatted = await deriveRecoveryKey("ABCDE-FGHJK-MNPQR-STVWX-YZ234", salt);
    const messy = await deriveRecoveryKey("abcde fghjk mnpqr stvwx yz234", salt);
    expect(toBase64(formatted)).toBe(toBase64(messy));
  });
});

describe("recovery round trip", () => {
  it("recovers the userKey from the code alone", async () => {
    const userKey = generateUserKey();
    const code = generateRecoveryCode();
    const blob = await createRecoveryBlob(userKey, code);
    const recovered = await recoverUserKey(
      blob.recoveryProtectedUserKey,
      code,
      blob.recoverySalt,
    );
    expect(toBase64(recovered)).toBe(toBase64(userKey));
  });

  it("accepts the code typed in lower case without separators", async () => {
    const userKey = generateUserKey();
    const code = generateRecoveryCode();
    const blob = await createRecoveryBlob(userKey, code);
    const messy = code.replace(/-/gu, "").toLowerCase();
    const recovered = await recoverUserKey(blob.recoveryProtectedUserKey, messy, blob.recoverySalt);
    expect(toBase64(recovered)).toBe(toBase64(userKey));
  });

  it("fails on the wrong code", async () => {
    const blob = await createRecoveryBlob(generateUserKey(), generateRecoveryCode());
    await expect(
      recoverUserKey(blob.recoveryProtectedUserKey, generateRecoveryCode(), blob.recoverySalt),
    ).rejects.toThrow(DecryptionError);
  });
});
