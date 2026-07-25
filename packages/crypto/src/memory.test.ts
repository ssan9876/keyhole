import { describe, expect, it } from "vitest";
import { zeroize } from "./memory.js";
import { randomBytes } from "./random.js";

describe("zeroize", () => {
  it("overwrites the buffer in place", () => {
    const secret = randomBytes(32);
    zeroize(secret);
    expect(Array.from(secret)).toEqual(new Array(32).fill(0));
  });

  it("clears several buffers at once", () => {
    const a = randomBytes(8);
    const b = randomBytes(16);
    zeroize(a, b);
    expect(Array.from(a)).toEqual(new Array(8).fill(0));
    expect(Array.from(b)).toEqual(new Array(16).fill(0));
  });

  it("ignores null and undefined so callers need no guards", () => {
    expect(() => zeroize(null, undefined, randomBytes(4))).not.toThrow();
  });
});
