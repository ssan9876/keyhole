import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  concatBytes,
  constantTimeEqual,
  fromBase64,
  toBase64,
  utf8Decode,
  utf8Encode,
} from "./encoding.js";

describe("base64", () => {
  it("encodes known values", () => {
    expect(toBase64(new Uint8Array([0, 1, 2, 253, 254, 255]))).toBe("AAEC/f7/");
    expect(toBase64(new Uint8Array([]))).toBe("");
  });

  it("decodes known values", () => {
    expect(Array.from(fromBase64("AAEC/f7/"))).toEqual([0, 1, 2, 253, 254, 255]);
    expect(fromBase64("")).toHaveLength(0);
  });

  it("round-trips arbitrary bytes", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 512 }), (bytes) => {
        expect(Array.from(fromBase64(toBase64(bytes)))).toEqual(Array.from(bytes));
      }),
    );
  });
});

describe("utf8", () => {
  it("round-trips non-ASCII text", () => {
    const text = "pässwörd — 日本語 🔑";
    expect(utf8Decode(utf8Encode(text))).toBe(text);
  });
});

describe("concatBytes", () => {
  it("joins in order", () => {
    const joined = concatBytes(new Uint8Array([1, 2]), new Uint8Array([]), new Uint8Array([3]));
    expect(Array.from(joined)).toEqual([1, 2, 3]);
  });
});

describe("constantTimeEqual", () => {
  it("is true for identical arrays", () => {
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
  });

  it("is false for differing arrays of equal length", () => {
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
  });

  it("is false for differing lengths", () => {
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
  });
});
