import { x25519 } from "@noble/curves/ed25519";
import { KeyholeCryptoError } from "./errors.js";
import { zeroize } from "./memory.js";
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

export interface UnlockedKeys {
  userKey: Uint8Array;
  privateKey: Uint8Array;
}

/**
 * An in-progress login. Holds the derived masterKey and wrappingKey between the
 * two halves of the protocol, so Argon2id runs once per login rather than twice.
 */
export interface UnlockSession {
  /** Send this to POST /api/auth/login. It decrypts nothing. */
  readonly authHash: Uint8Array;
  /** Unwrap the blobs the login response carried back. */
  finish(protectedUserKey: string, encryptedPrivateKey: string): Promise<UnlockedKeys>;
  /** Zeroize the masterKey and wrappingKey held by this session. */
  destroy(): void;
}

/**
 * The first half of unlocking. Login is `authHash` out, wrapped keys back
 * (spec §4.3), so the client must produce the auth hash *before* it holds the
 * blobs. Deriving here and unwrapping in `finish` keeps that to one Argon2id
 * pass — a second one is an extra second or more on a phone, on the screen
 * where the user is already waiting.
 *
 * Call `destroy()` once unlocked, or on a failed login, to clear the derived
 * key material this session holds.
 */
export async function beginUnlock(
  masterPassword: string,
  kdfSalt: Uint8Array,
  params: Readonly<KdfParams> = DEFAULT_KDF_PARAMS,
): Promise<UnlockSession> {
  const masterKey = await deriveMasterKey(masterPassword, kdfSalt, params);
  const wrappingKey = deriveWrapKey(masterKey);
  const authHash = deriveAuthHash(masterKey);
  let destroyed = false;

  return {
    authHash,
    async finish(protectedUserKey: string, encryptedPrivateKey: string): Promise<UnlockedKeys> {
      if (destroyed) {
        // Without this the zeroed wrappingKey would be used as a real key and
        // fail as an ordinary DecryptionError, which reads as a wrong password.
        throw new KeyholeCryptoError(
          "Unlock session has been destroyed; call beginUnlock again to unlock",
        );
      }
      const userKey = await unwrapKey(protectedUserKey, wrappingKey);
      const privateKey = await unwrapKey(encryptedPrivateKey, userKey);
      return { userKey, privateKey };
    },
    destroy(): void {
      destroyed = true;
      zeroize(masterKey, wrappingKey);
    },
  };
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
