import { DecryptionError, MalformedEnvelopeError } from "./errors.js";
import { fromBase64, toBase64, utf8Decode, utf8Encode } from "./encoding.js";
import { randomBytes } from "./random.js";

export interface Envelope {
  v: 1;
  alg: "A256GCM";
  n: string;
  ct: string;
}

const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BITS = 128;

async function importKey(key: Uint8Array): Promise<CryptoKey> {
  if (key.length !== KEY_BYTES) {
    throw new Error(`Symmetric key must be ${KEY_BYTES} bytes, received ${key.length}`);
  }
  return globalThis.crypto.subtle.importKey("raw", key as BufferSource, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

/** Deterministic encryption. Exported only for tests and vector generation —
 *  production callers must use encryptBytes so the nonce is always fresh. */
export async function encryptBytesWithNonce(
  key: Uint8Array,
  plaintext: Uint8Array,
  nonce: Uint8Array,
): Promise<Envelope> {
  if (nonce.length !== NONCE_BYTES) {
    throw new Error(`Nonce must be ${NONCE_BYTES} bytes, received ${nonce.length}`);
  }
  const cryptoKey = await importKey(key);
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce as BufferSource, tagLength: TAG_BITS },
    cryptoKey,
    plaintext as BufferSource,
  );
  return { v: 1, alg: "A256GCM", n: toBase64(nonce), ct: toBase64(new Uint8Array(ciphertext)) };
}

export async function encryptBytes(key: Uint8Array, plaintext: Uint8Array): Promise<Envelope> {
  return encryptBytesWithNonce(key, plaintext, randomBytes(NONCE_BYTES));
}

export async function decryptBytes(key: Uint8Array, envelope: Envelope): Promise<Uint8Array> {
  const cryptoKey = await importKey(key);
  try {
    const plaintext = await globalThis.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64(envelope.n) as BufferSource, tagLength: TAG_BITS },
      cryptoKey,
      fromBase64(envelope.ct) as BufferSource,
    );
    return new Uint8Array(plaintext);
  } catch {
    // Swallow the underlying error deliberately: a GCM failure cannot tell a
    // wrong key from a corrupt blob, and inventing a distinction would mislead.
    throw new DecryptionError();
  }
}

export function serializeEnvelope(envelope: Envelope): string {
  return JSON.stringify(envelope);
}

export function parseEnvelope(serialized: string): Envelope {
  let raw: unknown;
  try {
    raw = JSON.parse(serialized);
  } catch {
    throw new MalformedEnvelopeError("Envelope is not valid JSON");
  }
  if (typeof raw !== "object" || raw === null) {
    throw new MalformedEnvelopeError("Envelope must be an object");
  }
  const { v, alg, n, ct } = raw as Record<string, unknown>;
  if (v !== 1) throw new MalformedEnvelopeError(`Unsupported envelope version: ${String(v)}`);
  if (alg !== "A256GCM") {
    throw new MalformedEnvelopeError(`Unsupported algorithm: ${String(alg)}`);
  }
  if (typeof n !== "string" || typeof ct !== "string") {
    throw new MalformedEnvelopeError("Envelope is missing 'n' or 'ct'");
  }
  return { v: 1, alg: "A256GCM", n, ct };
}

export async function encryptString(key: Uint8Array, plaintext: string): Promise<string> {
  return serializeEnvelope(await encryptBytes(key, utf8Encode(plaintext)));
}

export async function decryptString(key: Uint8Array, serialized: string): Promise<string> {
  return utf8Decode(await decryptBytes(key, parseEnvelope(serialized)));
}
