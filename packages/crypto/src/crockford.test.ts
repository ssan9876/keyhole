import { describe, expect, it } from "vitest";
import {
  CROCKFORD_ALPHABET,
  encodeCrockford,
  groupChars,
  normalizeCrockford,
} from "./crockford.js";

describe("CROCKFORD_ALPHABET", () => {
  it("is 32 characters and excludes the ambiguous ones", () => {
    expect(CROCKFORD_ALPHABET).toHaveLength(32);
    expect(CROCKFORD_ALPHABET).not.toMatch(/[ILOU]/u);
  });
});

describe("encodeCrockford", () => {
  // Alphabet index 0 is "0", index 1 is "1", index 31 is "Z".
  it("emits one alphabet character per input byte", () => {
    expect(encodeCrockford(new Uint8Array([0, 1, 31]))).toBe("01Z");
  });

  it("uses only the low five bits, so 0 and 32 collide", () => {
    expect(encodeCrockford(new Uint8Array([0]))).toBe(encodeCrockford(new Uint8Array([32])));
  });
});

describe("groupChars", () => {
  it("splits into hyphenated groups", () => {
    expect(groupChars("ABCDEFGH", 4)).toBe("ABCD-EFGH");
    expect(groupChars("ABCDE", 5)).toBe("ABCDE");
  });
});

describe("normalizeCrockford", () => {
  it("uppercases and strips spaces and hyphens", () => {
    expect(normalizeCrockford("ab cd-ef")).toBe("ABCDEF");
  });

  it("maps the transcription-ambiguous characters", () => {
    expect(normalizeCrockford("ILOilo")).toBe("110110");
  });
});
