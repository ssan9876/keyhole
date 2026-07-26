import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  concatBytes,
  fromBase64,
  toBase64,
  utf8Decode,
  utf8Encode,
} from "./encoding.js";
import { MalformedEnvelopeError } from "./errors.js";

describe("base64", () => {
  it("encodes known values", () => {
    expect(toBase64(new Uint8Array([0, 1, 2, 253, 254, 255]))).toBe("AAEC/f7/");
    expect(toBase64(new Uint8Array([]))).toBe("");
  });

  it("decodes known values", () => {
    expect(Array.from(fromBase64("AAEC/f7/"))).toEqual([0, 1, 2, 253, 254, 255]);
    expect(fromBase64("")).toHaveLength(0);
  });

  it("pads a single byte the way every other base64 encoder does", () => {
    expect(toBase64(new Uint8Array([0]))).toBe("AA==");
  });

  it("rejects an invalid character with a typed error", () => {
    expect(() => fromBase64("AA!A")).toThrow(MalformedEnvelopeError);
  });

  // Five stripped characters are four bytes plus six orphan bits. No encoder
  // emits that, and the decoder used to drop the tail silently rather than
  // reporting the corruption.
  it("rejects a stripped length of 1 mod 4 rather than dropping six bits", () => {
    expect(() => fromBase64("AAAAA")).toThrow(MalformedEnvelopeError);
    expect(() => fromBase64("A")).toThrow(MalformedEnvelopeError);
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
