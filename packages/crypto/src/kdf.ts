import { argon2id } from "hash-wasm";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "./random.js";
import { utf8Encode } from "./encoding.js";

export interface KdfParams {
  algorithm: "argon2id";
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

/** Fixed by the spec. Stored per user so they can be raised later without a flag day. */
export const DEFAULT_KDF_PARAMS: Readonly<KdfParams> = Object.freeze({
  algorithm: "argon2id",
  memoryKiB: 65536,
  iterations: 3,
  parallelism: 4,
});

const KDF_SALT_BYTES = 16;
const DERIVED_KEY_BYTES = 32;

const WRAP_INFO = utf8Encode("keyhole:wrap:v1");
const AUTH_INFO = utf8Encode("keyhole:auth:v1");

export function generateKdfSalt(): Uint8Array {
  return randomBytes(KDF_SALT_BYTES);
}

/**
 * Argon2id over the master password. The password is normalized to Unicode NFC
 * first: a user typing "é" on one platform and "e"+combining-acute on another
 * must derive the same key, or they are locked out of their own vault by an
 * invisible difference.
 */
export async function deriveMasterKey(
  masterPassword: string,
  salt: Uint8Array,
  params: Readonly<KdfParams> = DEFAULT_KDF_PARAMS,
): Promise<Uint8Array> {
  if (masterPassword.length === 0) {
    throw new Error("Master password must not be empty");
  }
  if (salt.length !== KDF_SALT_BYTES) {
    throw new Error(`KDF salt must be ${KDF_SALT_BYTES} bytes, received ${salt.length}`);
  }
  const hash = await argon2id({
    password: masterPassword.normalize("NFC"),
    salt,
    memorySize: params.memoryKiB,
    iterations: params.iterations,
    parallelism: params.parallelism,
    hashLength: DERIVED_KEY_BYTES,
    outputType: "binary",
  });
  return new Uint8Array(hash);
}

function expand(masterKey: Uint8Array, info: Uint8Array): Uint8Array {
  if (masterKey.length !== DERIVED_KEY_BYTES) {
    throw new Error(`Master key must be ${DERIVED_KEY_BYTES} bytes, received ${masterKey.length}`);
  }
  return hkdf(sha256, masterKey, undefined, info, DERIVED_KEY_BYTES);
}

/** Unwraps the userKey. Never leaves the device. */
export function deriveWrapKey(masterKey: Uint8Array): Uint8Array {
  return expand(masterKey, WRAP_INFO);
}

/** Sent to the server as the login credential. Decrypts nothing. */
export function deriveAuthHash(masterKey: Uint8Array): Uint8Array {
  return expand(masterKey, AUTH_INFO);
}
