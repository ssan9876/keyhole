import { x25519 } from "@noble/curves/ed25519";
import { randomBytes } from "./random.js";
import { decryptBytes, encryptBytes, parseEnvelope, serializeEnvelope } from "./symmetric.js";
import {
  DEFAULT_KDF_PARAMS,
  deriveAuthHash,
  deriveMasterKey,
  deriveWrapKey,
  generateKdfSalt,
  type KdfParams,
} from "./kdf.js";

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

const SYMMETRIC_KEY_BYTES = 32;

export function generateUserKey(): Uint8Array {
  return randomBytes(SYMMETRIC_KEY_BYTES);
}

export function generateCollectionKey(): Uint8Array {
  return randomBytes(SYMMETRIC_KEY_BYTES);
}

export function publicKeyFor(privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(privateKey);
}

export function generateKeyPair(): KeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  return { privateKey, publicKey: publicKeyFor(privateKey) };
}

export async function wrapKey(keyToWrap: Uint8Array, wrappingKey: Uint8Array): Promise<string> {
  return serializeEnvelope(await encryptBytes(keyToWrap, wrappingKey));
}

export async function unwrapKey(wrapped: string, wrappingKey: Uint8Array): Promise<Uint8Array> {
  return decryptBytes(parseEnvelope(wrapped), wrappingKey);
}

export interface EnrollmentResult {
  kdfSalt: Uint8Array;
  authHash: Uint8Array;
  protectedUserKey: string;
  publicKey: Uint8Array;
  encryptedPrivateKey: string;
  /** In-memory only. Never send to the server. */
  userKey: Uint8Array;
  /** In-memory only. Never send the private half to the server. */
  keyPair: KeyPair;
}

/**
 * Everything that happens when a user first sets a master password. Runs
 * entirely on the client; only the wrapped blobs and the auth hash are ever
 * uploaded.
 */
export async function enrollUser(
  masterPassword: string,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<EnrollmentResult> {
  const kdfSalt = generateKdfSalt();
  const masterKey = await deriveMasterKey(masterPassword, kdfSalt, params);
  const wrappingKey = deriveWrapKey(masterKey);
  const authHash = deriveAuthHash(masterKey);

  const userKey = generateUserKey();
  const keyPair = generateKeyPair();

  return {
    kdfSalt,
    authHash,
    protectedUserKey: await wrapKey(userKey, wrappingKey),
    publicKey: keyPair.publicKey,
    encryptedPrivateKey: await wrapKey(keyPair.privateKey, userKey),
    userKey,
    keyPair,
  };
}

export async function unlockUser(
  masterPassword: string,
  kdfSalt: Uint8Array,
  protectedUserKey: string,
  encryptedPrivateKey: string,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<{ userKey: Uint8Array; privateKey: Uint8Array }> {
  const masterKey = await deriveMasterKey(masterPassword, kdfSalt, params);
  const wrappingKey = deriveWrapKey(masterKey);
  const userKey = await unwrapKey(protectedUserKey, wrappingKey);
  const privateKey = await unwrapKey(encryptedPrivateKey, userKey);
  return { userKey, privateKey };
}

export interface RotationResult {
  kdfSalt: Uint8Array;
  authHash: Uint8Array;
  protectedUserKey: string;
}

/**
 * Changing the master password. The userKey is deliberately unchanged — only
 * its wrapping is redone — so no item, folder, or collection key is touched and
 * nothing needs re-encrypting. A fresh KDF salt is generated because the old one
 * belongs to the old password.
 *
 * The caller must already hold the userKey, which means the vault must be
 * unlocked. There is no way to rotate a password you cannot currently use.
 */
export async function rotateMasterPassword(
  newMasterPassword: string,
  userKey: Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<RotationResult> {
  const kdfSalt = generateKdfSalt();
  const masterKey = await deriveMasterKey(newMasterPassword, kdfSalt, params);
  return {
    kdfSalt,
    authHash: deriveAuthHash(masterKey),
    protectedUserKey: await wrapKey(userKey, deriveWrapKey(masterKey)),
  };
}
