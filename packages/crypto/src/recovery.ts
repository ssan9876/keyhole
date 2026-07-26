import { argon2id } from "hash-wasm";
import { InvalidRecoveryCodeError } from "./errors.js";
import { randomBytes } from "./random.js";
import { DEFAULT_KDF_PARAMS, generateKdfSalt, type KdfParams } from "./kdf.js";
import { unwrapKey, wrapKey } from "./keys.js";
import {
  CROCKFORD_ALPHABET,
  encodeCrockford,
  groupChars,
  normalizeCrockford,
} from "./crockford.js";

const CODE_LENGTH = 25; // 25 chars x 5 bits = 125 bits of entropy
const GROUP_SIZE = 5;

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
  const hash = await argon2id({
    password: normalizeRecoveryCode(code),
    salt,
    memorySize: params.memoryKiB,
    iterations: params.iterations,
    parallelism: params.parallelism,
    hashLength: 32,
    outputType: "binary",
  });
  return new Uint8Array(hash);
}

export interface RecoveryBlob {
  recoverySalt: Uint8Array;
  recoveryProtectedUserKey: string;
  /** Store as `recovery_kdf_params`. Recovery is impossible without it. */
  params: Readonly<KdfParams>;
}

/** `params` is required so the caller must state which it used, and is
 *  returned so the caller has no excuse for not persisting them. */
export async function createRecoveryBlob(
  userKey: Uint8Array,
  code: string,
  params: Readonly<KdfParams>,
): Promise<RecoveryBlob> {
  const recoverySalt = generateKdfSalt();
  const recoveryKey = await deriveRecoveryKey(code, recoverySalt, params);
  return {
    recoverySalt,
    recoveryProtectedUserKey: await wrapKey(userKey, recoveryKey),
    params,
  };
}

/** `params` must be the ones the blob was created under — see deriveRecoveryKey. */
export async function recoverUserKey(
  recoveryProtectedUserKey: string,
  code: string,
  recoverySalt: Uint8Array,
  params: Readonly<KdfParams>,
): Promise<Uint8Array> {
  const recoveryKey = await deriveRecoveryKey(code, recoverySalt, params);
  return unwrapKey(recoveryProtectedUserKey, recoveryKey);
}
