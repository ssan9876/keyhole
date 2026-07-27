import { describe, expect, it } from "vitest";
import { DEFAULT_GENERATOR_OPTIONS, generatePassword, randomIndex } from "./generator.js";

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

  it(
    "generates very long passwords without hanging",
    { timeout: 2000 },
    () => {
      // Regression for a real hang: randomIndex used to compute
      // `ceiling = Math.floor(256 / limit) * limit`, which is 0 for any
      // limit > 256, so the rejection loop's `byte < ceiling` was never true
      // and it spun forever. The Fisher-Yates shuffle calls randomIndex(i + 1)
      // up to settings.length, so any password longer than 256 characters hit
      // this and froze the tab. Assert on the return itself -- a synchronous
      // infinite loop starves vitest's own timer, so a hang would not
      // actually be caught by the timeout below; it's a second line of
      // defense, not the primary check.
      const password = generatePassword({ length: 300 });
      expect(password).toHaveLength(300);
    },
  );

  it("shuffles the guaranteed class characters instead of leaving them in fixed positions", () => {
    // The first characters() are built one-per-enabled-class, in class order:
    // lowercase, uppercase, digit, symbol. Without the Fisher-Yates shuffle,
    // every generated password would have that exact class order at
    // positions 0-3, every single time. Across many generations, that fixed
    // pattern should not hold for all of them.
    const matchesUnshuffledClassOrder = (password: string): boolean =>
      /^[a-z]/.test(password) &&
      /^.[A-Z]/.test(password) &&
      /^..[0-9]/.test(password) &&
      /^...[^a-zA-Z0-9]/.test(password);

    const trials = Array.from({ length: 60 }, () => generatePassword({ length: 8 }));
    expect(trials.every(matchesUnshuffledClassOrder)).toBe(false);
  });
});

describe("randomIndex", () => {
  it("draws indices without modulo bias, even when 256 does not divide the limit", () => {
    // 26 (the lowercase/uppercase alphabet size) does not divide 256, which is
    // exactly the case `byte % limit` gets wrong: it over-selects the low
    // indices because floor(256 / 26) * 26 = 234 of the 256 byte values are
    // "extra" full cycles and the remaining 22 (234..255) alias back onto
    // indices 0..21 under plain modulo instead of being rejected.
    //
    // Feed a byte source that counts up forever (0, 1, 2, ..., 255, 0, 1, ...).
    // Because the source is exactly periodic with period 256, and rejection
    // sampling only ever emits an accepted byte's value % limit while silently
    // skipping the rest, the *sequence of returned indices* -- regardless of
    // how many raw bytes get consumed doing it -- is exactly the periodic
    // sequence 0, 1, ..., 233 (mod 26) repeating forever. Over any multiple of
    // 234 draws, every index therefore comes out exactly the same number of
    // times. Plain `byte % limit` has no such periodicity in the *accepted*
    // stream (it never rejects), so it does not land on this exact count.
    const limit = 26;
    let cursor = 0;
    const byteSource = (length: number): Uint8Array => {
      const out = new Uint8Array(length);
      for (let i = 0; i < length; i += 1) {
        out[i] = cursor % 256;
        cursor += 1;
      }
      return out;
    };

    const drawsPerIndex = 90;
    const totalDraws = limit * drawsPerIndex;
    const counts = new Array(limit).fill(0) as number[];
    for (let i = 0; i < totalDraws; i += 1) {
      const index = randomIndex(limit, byteSource);
      counts[index] = (counts[index] ?? 0) + 1;
    }

    expect(counts).toEqual(new Array(limit).fill(drawsPerIndex));
  });
});
