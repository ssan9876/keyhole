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

export async function deriveRecoveryKey(
  code: string,
  salt: Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
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

export async function createRecoveryBlob(
  userKey: Uint8Array,
  code: string,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<{ recoverySalt: Uint8Array; recoveryProtectedUserKey: string }> {
  const recoverySalt = generateKdfSalt();
  const recoveryKey = await deriveRecoveryKey(code, recoverySalt, params);
  return {
    recoverySalt,
    recoveryProtectedUserKey: await wrapKey(userKey, recoveryKey),
  };
}

export async function recoverUserKey(
  recoveryProtectedUserKey: string,
  code: string,
  recoverySalt: Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<Uint8Array> {
  const recoveryKey = await deriveRecoveryKey(code, recoverySalt, params);
  return unwrapKey(recoveryProtectedUserKey, recoveryKey);
}
