import { describe, expect, it } from "vitest";
import { randomBytes } from "./random.js";

describe("randomBytes", () => {
  it("returns the requested length", () => {
    expect(randomBytes(32)).toHaveLength(32);
    expect(randomBytes(1)).toHaveLength(1);
  });

  it("does not repeat across calls", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 100; i += 1) {
      seen.add(randomBytes(32).join(","));
    }
    expect(seen.size).toBe(100);
  });

  it("rejects non-positive and non-integer lengths", () => {
    expect(() => randomBytes(0)).toThrow(/positive integer/);
    expect(() => randomBytes(-1)).toThrow(/positive integer/);
    expect(() => randomBytes(1.5)).toThrow(/positive integer/);
  });
});
