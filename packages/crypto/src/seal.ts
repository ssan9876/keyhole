import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { concatBytes, fromBase64, toBase64, utf8Encode } from "./encoding.js";
import { DecryptionError, InvalidKeyError, MalformedEnvelopeError } from "./errors.js";
import { decryptBytes, encryptBytesWithNonce } from "./symmetric.js";
import { generateKeyPair } from "./keys.js";
import { randomBytes } from "./random.js";

export interface SealedKey {
  v: 1;
  alg: "X25519-HKDF-SHA256-A256GCM";
  epk: string;
  n: string;
  ct: string;
}

const SEAL_ALG = "X25519-HKDF-SHA256-A256GCM";
const SEAL_INFO_PREFIX = utf8Encode("keyhole:seal:v1");
const PUBLIC_KEY_BYTES = 32;
const NONCE_BYTES = 12;
/** Sealing carries symmetric keys — collection keys today — and nothing else. */
const SEALED_SECRET_BYTES = 32;

/**
 * The HKDF info binds both public keys into the derived key. Without that
 * binding, a shared secret could be reinterpreted in a different context;
 * with it, a blob sealed for one recipient cannot be replayed at another.
 */
function deriveSealKey(sharedSecret: Uint8Array, ephemeralPublicKey: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array {
  const info = concatBytes(SEAL_INFO_PREFIX, ephemeralPublicKey, recipientPublicKey);
  return hkdf(sha256, sharedSecret, undefined, info, 32);
}

/** Deterministic sealing. Exported only for tests and vector generation —
 *  production callers must use sealToUser so the ephemeral key is always
 *  fresh. Reusing an ephemeral key across seals breaks the construction. */
export async function sealToUserWithEphemeral(
  secret: Uint8Array,
  recipientPublicKey: Uint8Array,
  ephemeralPrivateKey: Uint8Array,
  nonce: Uint8Array,
): Promise<string> {
  if (recipientPublicKey.length !== PUBLIC_KEY_BYTES) {
    throw new InvalidKeyError(
      `Recipient public key must be ${PUBLIC_KEY_BYTES} bytes, received ${recipientPublicKey.length}`,
    );
  }
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);
  const sharedSecret = x25519.getSharedSecret(ephemeralPrivateKey, recipientPublicKey);
  const sealKey = deriveSealKey(sharedSecret, ephemeralPublicKey, recipientPublicKey);
  const envelope = await encryptBytesWithNonce(secret, sealKey, nonce);
  const sealed: SealedKey = {
    v: 1,
    alg: SEAL_ALG,
    epk: toBase64(ephemeralPublicKey),
    n: envelope.n,
    ct: envelope.ct,
  };
  return JSON.stringify(sealed);
}

export async function sealToUser(
  secret: Uint8Array,
  recipientPublicKey: Uint8Array,
): Promise<string> {
  const ephemeral = generateKeyPair();
  return sealToUserWithEphemeral(
    secret,
    recipientPublicKey,
    ephemeral.privateKey,
    randomBytes(NONCE_BYTES),
  );
}

function parseSealed(serialized: string): SealedKey {
  let raw: unknown;
  try {
    raw = JSON.parse(serialized);
  } catch {
    throw new MalformedEnvelopeError("Sealed key is not valid JSON");
  }
  if (typeof raw !== "object" || raw === null) {
    throw new MalformedEnvelopeError("Sealed key must be an object");
  }
  const { v, alg, epk, n, ct } = raw as Record<string, unknown>;
  if (v !== 1) throw new MalformedEnvelopeError(`Unsupported sealed key version: ${String(v)}`);
  if (alg !== SEAL_ALG) {
    throw new MalformedEnvelopeError(`Unsupported sealed key algorithm: ${String(alg)}`);
  }
  if (typeof epk !== "string" || typeof n !== "string" || typeof ct !== "string") {
    throw new MalformedEnvelopeError("Sealed key is missing 'epk', 'n', or 'ct'");
  }
  let ephemeralPublicKey: Uint8Array;
  try {
    ephemeralPublicKey = fromBase64(epk);
  } catch {
    throw new MalformedEnvelopeError("Sealed key 'epk' is not valid base64");
  }
  if (ephemeralPublicKey.length !== PUBLIC_KEY_BYTES) {
    throw new MalformedEnvelopeError(
      `Sealed key 'epk' must be ${PUBLIC_KEY_BYTES} bytes, received ${ephemeralPublicKey.length}`,
    );
  }
  return { v: 1, alg: SEAL_ALG, epk, n, ct };
}

export async function openSealed(
  sealed: string,
  recipientPrivateKey: Uint8Array,
): Promise<Uint8Array> {
  const parsed = parseSealed(sealed);
  const ephemeralPublicKey = fromBase64(parsed.epk);
  let sealKey: Uint8Array;
  try {
    const recipientPublicKey = x25519.getPublicKey(recipientPrivateKey);
    const sharedSecret = x25519.getSharedSecret(recipientPrivateKey, ephemeralPublicKey);
    sealKey = deriveSealKey(sharedSecret, ephemeralPublicKey, recipientPublicKey);
  } catch {
    throw new DecryptionError();
  }
  const opened = await decryptBytes({ v: 1, alg: "A256GCM", n: parsed.n, ct: parsed.ct }, sealKey);
  // Everything this opens is a 32-byte symmetric key. Returning anything else
  // is how an attacker-chosen "collection key" of the wrong length reaches
  // decryptItem and surfaces as a bare Error from importKey instead of a typed
  // failure the caller can handle.
  if (opened.length !== SEALED_SECRET_BYTES) {
    throw new DecryptionError();
  }
  return opened;
}
