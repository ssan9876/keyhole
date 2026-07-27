import { describe, expect, it } from "vitest";
import { DEFAULT_GENERATOR_OPTIONS, generatePassword } from "./generator.js";

describe("generatePassword", () => {
  it("honours the requested length", () => {
    for (const length of [8, 20, 64, 128]) {
      expect(generatePassword({ length })).toHaveLength(length);
    }
  });

  it("uses only the enabled character classes", () => {
    const digitsOnly = generatePassword({
      length: 200,
      lowercase: false,
      uppercase: false,
      digits: true,
      symbols: false,
    });
    expect(digitsOnly).toMatch(/^[0-9]+$/);
  });

  it("includes at least one character from every enabled class", () => {
    // A generator that merely samples the union will, often enough to matter,
    // emit a "symbols on" password with no symbol — which fails the site's own
    // policy check and reads to the user as the generator being broken.
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const password = generatePassword({ length: 8 });
      expect(password).toMatch(/[a-z]/);
      expect(password).toMatch(/[A-Z]/);
      expect(password).toMatch(/[0-9]/);
      expect(password).toMatch(/[^a-zA-Z0-9]/);
    }
  });

  it("does not repeat itself", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 100; i += 1) seen.add(generatePassword());
    // 100 collisions-free draws at the default length is not proof of entropy,
    // but a stuck or seeded generator fails it immediately.
    expect(seen.size).toBe(100);
  });

  it("refuses a length shorter than the number of enabled classes", () => {
    // Four classes cannot each appear in three characters. Silently returning
    // three would break the guarantee the test above depends on.
    expect(() => generatePassword({ length: 3 })).toThrow();
  });

  it("refuses when every class is disabled", () => {
    expect(() =>
      generatePassword({
        lowercase: false,
        uppercase: false,
        digits: false,
        symbols: false,
      }),
    ).toThrow();
  });

  it("defaults to a length and classes worth having", () => {
    expect(DEFAULT_GENERATOR_OPTIONS.length).toBeGreaterThanOrEqual(16);
    expect(DEFAULT_GENERATOR_OPTIONS.lowercase).toBe(true);
    expect(DEFAULT_GENERATOR_OPTIONS.uppercase).toBe(true);
    expect(DEFAULT_GENERATOR_OPTIONS.digits).toBe(true);
    expect(DEFAULT_GENERATOR_OPTIONS.symbols).toBe(true);
  });
});
