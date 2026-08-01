import { randomBytes } from "@keyhole/crypto";

export interface GeneratorOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
}

export const DEFAULT_GENERATOR_OPTIONS: GeneratorOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
};

const CLASSES = {
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  // No quotes or backslashes: they are the characters most likely to be mangled
  // by a shell, a CSV export, or a site's own escaping.
  symbols: "!#$%&()*+,-.:;<=>?@[]^_{|}~",
} as const;

/** Supplies `length` random bytes. Swappable so tests can drive known values. */
type ByteSource = (length: number) => Uint8Array;

/**
 * Number of bytes needed so that a value built from them can reach at least
 * `limit` distinct values (256^width >= limit).
 */
function byteWidthFor(limit: number): number {
  let width = 1;
  let range = 256;
  while (range < limit) {
    width += 1;
    range *= 256;
  }
  return width;
}

/**
 * Draws an index below `limit` without modulo bias, for any integer limit >= 1.
 *
 * Taking `byte % limit` skews toward the low end whenever the byte range is
 * not an exact multiple of limit -- true for every alphabet here. A single
 * byte only has 256 possible values, so once `limit` exceeds 256 no single
 * byte can even represent every index; drawing from a wide-enough integer
 * (built from `byteWidthFor(limit)` bytes) fixes both problems at once: the
 * rejection ceiling is the largest exact multiple of `limit` that fits in
 * that width, which is always >= limit, so the loop always has a nonzero
 * chance of returning and rejection sampling still removes the skew.
 *
 * Exported for testing only: production code should go through
 * `secureRandomIndex`, which supplies the real CSPRNG byte source.
 */
export function randomIndex(limit: number, byteSource: ByteSource): number {
  if (limit < 1) {
    // limit <= 0 makes ceiling = Math.floor(range / limit) * limit either 0
    // (limit 0, via division by zero -> NaN, and NaN * limit is also NaN, so
    // `value < ceiling` is never true) or negative (limit < 0), and a
    // negative limit is nonsensical besides. Either way the rejection loop
    // below never returns -- it spins forever and, being synchronous, starves
    // even vitest's own timer, so a hang here does not get caught by a test
    // timeout. Fail fast instead.
    throw new Error(`limit must be at least 1, got ${limit}`);
  }
  const byteWidth = byteWidthFor(limit);
  const range = 256 ** byteWidth;
  const ceiling = Math.floor(range / limit) * limit;
  for (;;) {
    const bytes = byteSource(byteWidth);
    let value = 0;
    for (let i = 0; i < byteWidth; i += 1) {
      value = value * 256 + (bytes[i] as number);
    }
    if (value < ceiling) return value % limit;
  }
}

function secureRandomIndex(limit: number): number {
  return randomIndex(limit, randomBytes);
}

function pick(alphabet: string): string {
  return alphabet.charAt(secureRandomIndex(alphabet.length));
}

export function generatePassword(options: Partial<GeneratorOptions> = {}): string {
  const settings: GeneratorOptions = { ...DEFAULT_GENERATOR_OPTIONS, ...options };

  const enabled: string[] = [];
  if (settings.lowercase) enabled.push(CLASSES.lowercase);
  if (settings.uppercase) enabled.push(CLASSES.uppercase);
  if (settings.digits) enabled.push(CLASSES.digits);
  if (settings.symbols) enabled.push(CLASSES.symbols);

  if (enabled.length === 0) {
    throw new Error("At least one character class must be enabled");
  }
  if (settings.length < enabled.length) {
    // Returning a shorter password, or one missing a class, would quietly break
    // the guarantee callers rely on to satisfy a site's password policy.
    throw new Error(
      `Length must be at least ${enabled.length} to include every enabled class`,
    );
  }

  // One from each class first, so "symbols on" always means a symbol is present.
  const characters = enabled.map((alphabet) => pick(alphabet));
  const union = enabled.join("");
  while (characters.length < settings.length) {
    characters.push(pick(union));
  }

  // Fisher-Yates, or the guaranteed characters would always sit at the front in
  // a fixed class order — a pattern worth nothing to an attacker but obvious to
  // a user, and a real weakness if anyone ever truncated the output.
  for (let i = characters.length - 1; i > 0; i -= 1) {
    const j = secureRandomIndex(i + 1);
    const a = characters[i] as string;
    const b = characters[j] as string;
    characters[i] = b;
    characters[j] = a;
  }
  return characters.join("");
}
