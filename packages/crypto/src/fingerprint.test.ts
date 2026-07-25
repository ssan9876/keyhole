import { describe, expect, it } from "vitest";
import { publicKeyFingerprint } from "./fingerprint.js";
import { generateKeyPair } from "./keys.js";

const KEY = new Uint8Array(32).fill(0x33);

describe("publicKeyFingerprint", () => {
  it("is four groups of four Crockford characters", () => {
    expect(publicKeyFingerprint(KEY, "seth@gmail.com")).toMatch(
      /^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{4}(-[0-9ABCDEFGHJKMNPQRSTVWXYZ]{4}){3}$/u,
    );
  });

  it("is deterministic", () => {
    expect(publicKeyFingerprint(KEY, "seth@gmail.com")).toBe(
      publicKeyFingerprint(KEY, "seth@gmail.com"),
    );
  });

  // The email is bound in so an attacker cannot present a legitimate user's
  // key under a different identity and have the fingerprint still match.
  it("changes when the email changes", () => {
    expect(publicKeyFingerprint(KEY, "seth@gmail.com")).not.toBe(
      publicKeyFingerprint(KEY, "someone@else.com"),
    );
  });

  it("normalizes email case and surrounding whitespace", () => {
    expect(publicKeyFingerprint(KEY, "  Seth@Gmail.com ")).toBe(
      publicKeyFingerprint(KEY, "seth@gmail.com"),
    );
  });

  it("differs between distinct keys", () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    expect(publicKeyFingerprint(a.publicKey, "x@y.z")).not.toBe(
      publicKeyFingerprint(b.publicKey, "x@y.z"),
    );
  });
});
