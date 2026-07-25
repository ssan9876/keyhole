/**
 * Crockford Base32 — the alphabet omits I, L, O, and U so that a human reading
 * a code off a screen and typing it somewhere else cannot confuse characters.
 *
 * Internal module: shared by recovery codes and key fingerprints, and
 * deliberately not re-exported from index.ts. It is an implementation detail,
 * not part of the package's public surface.
 */
export const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** One character per byte, taken from the low five bits. 256 is divisible by
 *  32, so masking is uniform — there is no modulo bias to correct for. */
export function encodeCrockford(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) {
    // charAt, not [], because noUncheckedIndexedAccess types [] as possibly undefined.
    out += CROCKFORD_ALPHABET.charAt(byte & 0x1f);
  }
  return out;
}

export function groupChars(text: string, size: number): string {
  const groups: string[] = [];
  for (let i = 0; i < text.length; i += size) {
    groups.push(text.slice(i, i + size));
  }
  return groups.join("-");
}

/** Undoes formatting and the transcription substitutions Crockford anticipates. */
export function normalizeCrockford(input: string): string {
  return input
    .toUpperCase()
    .replace(/[\s-]/gu, "")
    .replace(/[IL]/gu, "1")
    .replace(/O/gu, "0");
}
