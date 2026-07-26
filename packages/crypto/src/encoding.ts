import { MalformedEnvelopeError } from "./errors.js";

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** `noUncheckedIndexedAccess` makes every string index `string | undefined`.
 *  These lookups are masked to 6 bits against a 64-character alphabet, so they
 *  cannot miss — this helper documents that rather than scattering `!`. */
function alphabetAt(alphabet: string, index: number): string {
  return alphabet.charAt(index);
}

/** Base64 without Node's Buffer, so the same code runs in a browser. */
export function toBase64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] as number;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += alphabetAt(BASE64_ALPHABET, b0 >> 2);
    out += alphabetAt(BASE64_ALPHABET, ((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4));
    out += b1 === undefined ? "=" : alphabetAt(BASE64_ALPHABET, ((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6));
    out += b2 === undefined ? "=" : alphabetAt(BASE64_ALPHABET, b2 & 0x3f);
  }
  return out;
}

export function fromBase64(text: string): Uint8Array {
  const clean = text.replace(/=+$/u, "");
  // A stripped length of 1 mod 4 is not producible by any encoder: it is six
  // orphan bits that this decoder would silently drop, turning corrupt input
  // into a short buffer instead of an error.
  if (clean.length % 4 === 1) {
    throw new MalformedEnvelopeError(`Invalid base64 length: ${clean.length} characters`);
  }
  const out = new Uint8Array(Math.floor((clean.length * 6) / 8));
  let bits = 0;
  let acc = 0;
  let index = 0;
  for (const char of clean) {
    const value = BASE64_ALPHABET.indexOf(char);
    if (value < 0) throw new MalformedEnvelopeError(`Invalid base64 character: ${char}`);
    acc = (acc << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[index] = (acc >> bits) & 0xff;
      index += 1;
    }
  }
  return out;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function utf8Encode(text: string): Uint8Array {
  return encoder.encode(text);
}

export function utf8Decode(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Comparison whose running time does not depend on where the first
 *  difference occurs. Length difference short-circuits, which is fine —
 *  the lengths of our tokens and hashes are public. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= (a[i] as number) ^ (b[i] as number);
  }
  return diff === 0;
}
