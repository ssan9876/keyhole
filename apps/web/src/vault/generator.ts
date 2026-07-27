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

/**
 * Draws an index below `limit` without modulo bias.
 *
 * Taking `byte % limit` skews toward the low end whenever 256 is not a multiple
 * of limit, which is every alphabet here. Rejection sampling costs a handful of
 * extra bytes and removes the skew entirely.
 */
function randomIndex(limit: number): number {
  const ceiling = Math.floor(256 / limit) * limit;
  for (;;) {
    const byte = randomBytes(1)[0] as number;
    if (byte < ceiling) return byte % limit;
  }
}

function pick(alphabet: string): string {
  return alphabet.charAt(randomIndex(alphabet.length));
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
    const j = randomIndex(i + 1);
    const a = characters[i] as string;
    const b = characters[j] as string;
    characters[i] = b;
    characters[j] = a;
  }
  return characters.join("");
}
