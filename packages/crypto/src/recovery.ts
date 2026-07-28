import { argon2id } from "hash-wasm";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { InvalidKeyError, InvalidRecoveryCodeError } from "./errors.js";
import { zeroize } from "./memory.js";
import { randomBytes } from "./random.js";
import { assertKdfSalt, generateKdfSalt, type KdfParams } from "./kdf.js";
import { unwrapKey, wrapKey } from "./keys.js";
import { utf8Encode } from "./encoding.js";
import {
  CROCKFORD_ALPHABET,
  encodeCrockford,
  groupChars,
  normalizeCrockford,
} from "./crockford.js";

const CODE_LENGTH = 25; // 25 chars x 5 bits = 125 bits of entropy
const GROUP_SIZE = 5;
const RECOVERY_KEY_BYTES = 32;

const RECOVERY_WRAP_INFO = utf8Encode("keyhole:recovery-wrap:v1");
const RECOVERY_AUTH_INFO = utf8Encode("keyhole:recovery-auth:v1");

export function generateRecoveryCode(): string {
  return groupChars(encodeCrockford(randomBytes(CODE_LENGTH)), GROUP_SIZE);
}

export function normalizeRecoveryCode(input: string): string {
  const cleaned = normalizeCrockford(input);
  if (cleaned.length !== CODE_LENGTH) {
    throw new InvalidRecoveryCodeError(
      `Recovery code must be ${CODE_LENGTH} characters, received ${cleaned.length}`,
    );
  }
  for (const char of cleaned) {
    if (!CROCKFORD_ALPHABET.includes(char)) {
      throw new InvalidRecoveryCodeError(`Invalid character in recovery code: ${char}`);
    }
  }
  return cleaned;
}

/**
 * `params` is required, not defaulted. The recovery blob may have been made
 * under different params from the account's current ones (spec §4.2 keeps
 * `recovery_kdf_params` separate for exactly this reason), and defaulting here
 * would silently derive a different key from a perfectly correct recovery code
 * — a failure discovered only when recovery was the user's last resort.
 */
export async function deriveRecoveryKey(
  code: string,
  salt: Uint8Array,
  params: Readonly<KdfParams>,
): Promise<Uint8Array> {
  assertKdfSalt(salt);
  const hash = await argon2id({
    password: normalizeRecoveryCode(code),
    salt,
    memorySize: params.memoryKiB,
    iterations: params.iterations,
    parallelism: params.parallelism,
    hashLength: RECOVERY_KEY_BYTES,
    outputType: "binary",
  });
  return new Uint8Array(hash);
}

function expandRecovery(recoveryKey: Uint8Array, info: Uint8Array): Uint8Array {
  if (recoveryKey.length !== RECOVERY_KEY_BYTES) {
    throw new InvalidKeyError(
      `Recovery key must be ${RECOVERY_KEY_BYTES} bytes, received ${recoveryKey.length}`,
    );
  }
  return hkdf(sha256, recoveryKey, undefined, info, RECOVERY_KEY_BYTES);
}

/** Unwraps the userKey. Never leaves the device. */
export function deriveRecoveryWrapKey(recoveryKey: Uint8Array): Uint8Array {
  return expandRecovery(recoveryKey, RECOVERY_WRAP_INFO);
}

/**
 * Sent to the server as proof the caller holds the code. Decrypts nothing.
 *
 * The split is what makes remote redemption safe: without it the only value
 * derivable from the code is the one that opens the blob, so proving
 * possession to the server would mean handing the server the key.
 */
export function deriveRecoveryAuthHash(recoveryKey: Uint8Array): Uint8Array {
  return expandRecovery(recoveryKey, RECOVERY_AUTH_INFO);
}

export interface RecoveryBlob {
  recoverySalt: Uint8Array;
  recoveryProtectedUserKey: string;
  /** Store as `recovery_auth_hash`. The server compares it to prove the caller
   *  holds the code before returning the blob. It opens nothing. */
  recoveryAuthHash: Uint8Array;
  /** Store as `recovery_kdf_params`. Recovery is impossible without it. */
  params: Readonly<KdfParams>;
}

/**
 * `params` is required so the caller must state which it used, and is
 * returned so the caller has no excuse for not persisting them.
 *
 * **Breaking change.** The blob is wrapped under `deriveRecoveryWrapKey`, not
 * under the raw recovery key. Every recovery blob created before this commit
 * becomes unopenable by `recoverUserKey`. That is intended: a
 * `recovery_auth_hash IS NULL` column marks those accounts, and their owners
 * must regenerate a code from Settings. There is no migration — the server
 * cannot re-wrap a blob it has no key for, which is the property this whole
 * design exists to preserve.
 */
export async function createRecoveryBlob(
  userKey: Uint8Array,
  code: string,
  params: Readonly<KdfParams>,
): Promise<RecoveryBlob> {
  const recoverySalt = generateKdfSalt();
  const recoveryKey = await deriveRecoveryKey(code, recoverySalt, params);
  const wrappingKey = deriveRecoveryWrapKey(recoveryKey);
  try {
    return {
      recoverySalt,
      recoveryProtectedUserKey: await wrapKey(userKey, wrappingKey),
      recoveryAuthHash: deriveRecoveryAuthHash(recoveryKey),
      params,
    };
  } finally {
    // recoveryAuthHash is returned, so clearing it is the caller's job once it
    // has been uploaded. userKey belongs to the caller and is untouched. These
    // two are created here and never leave.
    zeroize(recoveryKey, wrappingKey);
  }
}

/**
 * `params` must be the ones the blob was created under — see deriveRecoveryKey.
 *
 * **Breaking change.** Unwraps with `deriveRecoveryWrapKey`, so a blob created
 * before this commit throws `DecryptionError` here even given its correct code.
 * See `createRecoveryBlob`.
 */
export async function recoverUserKey(
  recoveryProtectedUserKey: string,
  code: string,
  recoverySalt: Uint8Array,
  params: Readonly<KdfParams>,
): Promise<Uint8Array> {
  const recoveryKey = await deriveRecoveryKey(code, recoverySalt, params);
  const wrappingKey = deriveRecoveryWrapKey(recoveryKey);
  try {
    return await unwrapKey(recoveryProtectedUserKey, wrappingKey);
  } finally {
    zeroize(recoveryKey, wrappingKey);
  }
}
