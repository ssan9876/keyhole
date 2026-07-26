/**
 * Regenerates the frozen cross-language test vectors.
 *
 * Run deliberately — `pnpm --filter @keyhole/crypto vectors` — and review the
 * resulting diff with care. A change here is a change to the wire format that
 * every client, present and future, must follow. All inputs are fixed so the
 * output is byte-for-byte reproducible.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_KDF_PARAMS, deriveAuthHash, deriveMasterKey, deriveWrapKey } from "../src/kdf.js";
import { encryptBytesWithNonce, serializeEnvelope } from "../src/symmetric.js";
import { sealToUserWithEphemeral } from "../src/seal.js";
import { publicKeyFor } from "../src/keys.js";
import { publicKeyFingerprint } from "../src/fingerprint.js";
import { deriveRecoveryKey } from "../src/recovery.js";
import type { LoginItem, NoteItem } from "../src/item.js";
import { toBase64, utf8Encode } from "../src/encoding.js";

const here = dirname(fileURLToPath(import.meta.url));

const MASTER_PASSWORD = "correct horse battery staple";
const KDF_SALT = new Uint8Array(16).fill(0x42);
const RECOVERY_CODE = "ABCDE-FGHJK-MNPQR-STVWX-YZ234";
const RECOVERY_SALT = new Uint8Array(16).fill(0x21);
const AES_KEY = new Uint8Array(32).fill(0x07);
const AES_NONCE = new Uint8Array(12).fill(0x09);
const AES_PLAINTEXT = utf8Encode("attack at dawn");
const RECIPIENT_PRIVATE = new Uint8Array(32).fill(0x0a);
const EPHEMERAL_PRIVATE = new Uint8Array(32).fill(0x0b);
const SEAL_SECRET = new Uint8Array(32).fill(0x5a);
const SEAL_NONCE = new Uint8Array(12).fill(0x01);

/** Deliberately a reserved example address. These vectors are frozen forever
 *  and shared across repositories; a real personal address does not belong in
 *  one. */
const FINGERPRINT_EMAIL = "user@example.com";
const FINGERPRINT_EMAIL_MESSY = "  User@EXAMPLE.com  ";

// Normalization inputs. Both Unicode forms MUST stay \u escapes here, and the
// generator writes the JSON with every non-ASCII character escaped, because a
// plain literal is silently normalized by editors and file writers — which is
// exactly how an earlier test in this project came to assert nothing.
const NFC_PASSWORD_PRECOMPOSED = "caf\u00e9";
const NFC_PASSWORD_DECOMPOSED = "cafe\u0301";
const NFC_SALT = new Uint8Array(16).fill(0x37);
const RECOVERY_CODE_MESSY = "abcde fghjk mnpqr stvwx yz234";

// Composed vectors. The wrapping key is the one derived from the KDF vector
// above, so a porter has one unbroken chain from the master password to an
// item key rather than five disconnected values.
const COMPOSED_USER_KEY = new Uint8Array(32).fill(0x31);
const COMPOSED_USER_KEY_NONCE = new Uint8Array(12).fill(0x33);
const COMPOSED_ITEM_KEY = new Uint8Array(32).fill(0x34);
const COMPOSED_ITEM_KEY_NONCE = new Uint8Array(12).fill(0x35);

const ITEM_LOGIN: LoginItem = {
  type: "login",
  name: "GitHub",
  username: "user@example.com",
  password: "s3cret",
  urls: ["https://github.com"],
  notes: "personal account",
  favorite: true,
  folderId: null,
  passwordHistory: [{ password: "old-one", changedAt: "2026-01-01T00:00:00.000Z" }],
};

const ITEM_NOTE: NoteItem = {
  type: "note",
  name: "Wifi",
  notes: "ssid: keyhole\npsk: hunter2",
  favorite: false,
  folderId: "folder-1",
};

/** Escapes every non-ASCII character as \uXXXX. JSON parsers decode this
 *  identically to the literal character, but the file on disk stays pure
 *  ASCII, so no editor, formatter or file writer can silently renormalize the
 *  Unicode vectors into the form they are meant to distinguish. */
function escapeNonAscii(json: string): string {
  let out = "";
  for (let i = 0; i < json.length; i += 1) {
    const code = json.charCodeAt(i);
    // Per UTF-16 code unit, and only above ASCII: the newlines and indentation
    // that make this file readable must survive as themselves.
    out += code > 127 ? `\\u${code.toString(16).padStart(4, "0")}` : json.charAt(i);
  }
  return out;
}

async function main(): Promise<void> {
  const masterKey = await deriveMasterKey(MASTER_PASSWORD, KDF_SALT);
  const wrapKey = deriveWrapKey(masterKey);
  const recipientPublic = publicKeyFor(RECIPIENT_PRIVATE);

  const nfcPrecomposed = await deriveMasterKey(NFC_PASSWORD_PRECOMPOSED, NFC_SALT);
  const nfcDecomposed = await deriveMasterKey(NFC_PASSWORD_DECOMPOSED, NFC_SALT);
  if (toBase64(nfcPrecomposed) !== toBase64(nfcDecomposed)) {
    throw new Error("NFC normalization vector is inconsistent; refusing to write it");
  }

  const recoveryKey = await deriveRecoveryKey(RECOVERY_CODE, RECOVERY_SALT, DEFAULT_KDF_PARAMS);
  const recoveryKeyMessy = await deriveRecoveryKey(
    RECOVERY_CODE_MESSY,
    RECOVERY_SALT,
    DEFAULT_KDF_PARAMS,
  );
  if (toBase64(recoveryKey) !== toBase64(recoveryKeyMessy)) {
    throw new Error("Recovery code normalization vector is inconsistent; refusing to write it");
  }

  const vectors = {
    _comment:
      "Frozen cross-language test vectors for Keyhole. Any client implementation " +
      "must reproduce these exactly. Regenerate only with a deliberate format change.",

    // The rules a porter cannot infer from the arithmetic. Reproducing every
    // value below and still getting one of these wrong locks a user out.
    params: {
      argon2id: {
        algorithm: "Argon2id",
        version: 19,
        versionHex: "0x13",
        note: "Version 0x13 (19). Argon2 0x10 produces different output for identical parameters.",
        memoryKiB: 65536,
        iterations: 3,
        parallelism: 4,
        outputBytes: 32,
        saltBytes: 16,
        passwordEncoding:
          "UTF-8 bytes of the password after Unicode NFC normalization. Normalize first, then encode.",
        secondaryUse:
          "The recovery key uses the same Argon2id parameters over the normalized recovery code.",
      },
      hkdf: {
        hash: "SHA-256",
        salt: "absent",
        saltNote:
          "No salt is supplied. RFC 5869 substitutes HashLen (32) zero bytes; passing a zero-length salt is equivalent, because HMAC zero-pads a short key to the block size.",
        outputBytes: 32,
        info: {
          wrap: { utf8: "keyhole:wrap:v1", base64: toBase64(utf8Encode("keyhole:wrap:v1")) },
          auth: { utf8: "keyhole:auth:v1", base64: toBase64(utf8Encode("keyhole:auth:v1")) },
          seal: { utf8: "keyhole:seal:v1", base64: toBase64(utf8Encode("keyhole:seal:v1")) },
        },
      },
      seal: {
        kem: "X25519",
        infoConcatenation: '"keyhole:seal:v1" || ephemeralPublicKey || recipientPublicKey',
        infoNote:
          "Raw 32-byte public keys, concatenated in that order with no separators and no length prefixes. Both keys are bound in so a blob sealed for one recipient cannot be replayed at another.",
        secretBytes: 32,
        secretNote: "Sealing carries 32-byte symmetric keys only; anything else must be rejected.",
      },
      aesGcm: {
        cipher: "AES-256-GCM",
        keyBytes: 32,
        nonceBits: 96,
        tagBits: 128,
        tagPlacement: "appended to the ciphertext, as WebCrypto does",
        envelope: '{"v":1,"alg":"A256GCM","n":"<base64 nonce>","ct":"<base64 ciphertext||tag>"}',
        nonceNote: "A fresh random nonce per operation. Never reuse a nonce with a key.",
      },
      keyLengths: {
        userKey: 32,
        collectionKey: 32,
        itemKey: 32,
        x25519PrivateKey: 32,
        x25519PublicKey: 32,
        kdfSalt: 16,
      },
      crockford: {
        alphabet: "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
        encoding: "one output character per input byte, from the low five bits (byte & 0x1f)",
        warning:
          "This is NOT standard Base32. It does not pack 5 bits per character across a byte stream, and it emits no padding. A Crockford Base32 library will produce different output for the same bytes. Implement the byte-to-character mapping literally.",
        inputNormalization:
          "On input, uppercase, strip whitespace and hyphens, then map I and L to 1 and O to 0.",
        usedBy: "recovery codes (25 characters, 5 groups of 5) and public key fingerprints",
      },
      fingerprint: {
        construction: "SHA-256(utf8(email.trim().toLowerCase()) || publicKey), first 16 bytes",
        rendering: "encodeCrockford over those 16 bytes, grouped 4-4-4-4 with hyphens",
      },
    },

    kdf: {
      masterPassword: MASTER_PASSWORD,
      kdfSaltBase64: toBase64(KDF_SALT),
      params: { algorithm: "argon2id", memoryKiB: 65536, iterations: 3, parallelism: 4 },
      masterKeyBase64: toBase64(masterKey),
      wrapKeyBase64: toBase64(wrapKey),
      authHashBase64: toBase64(deriveAuthHash(masterKey)),
    },

    // Inputs that differ byte-for-byte but must derive identical output. These
    // are the vectors most likely to catch a port: the arithmetic is easy to
    // reproduce, the normalization is easy to forget, and forgetting it locks
    // a real user out of a real vault.
    normalization: {
      _comment:
        "Unicode forms are written as \\u escapes on purpose. Decode them, do not retype them: an editor will silently normalize the literal characters and the vector will then verify nothing.",
      password: {
        note: "Argon2id runs over the NFC form. Both spellings of the same word must derive the same master key.",
        precomposedUtf8: NFC_PASSWORD_PRECOMPOSED,
        precomposedCodepoints: ["U+0063", "U+0061", "U+0066", "U+00E9"],
        decomposedUtf8: NFC_PASSWORD_DECOMPOSED,
        decomposedCodepoints: ["U+0063", "U+0061", "U+0066", "U+0065", "U+0301"],
        saltBase64: toBase64(NFC_SALT),
        masterKeyBase64: toBase64(nfcPrecomposed),
      },
      email: {
        note: "Fingerprints bind the email, trimmed and lowercased. Untrimmed input must not change the fingerprint.",
        canonical: FINGERPRINT_EMAIL,
        asTyped: FINGERPRINT_EMAIL_MESSY,
        publicKeyBase64: toBase64(recipientPublic),
        fingerprint: publicKeyFingerprint(recipientPublic, FINGERPRINT_EMAIL_MESSY),
      },
      recoveryCode: {
        note: "Recovery codes are normalized before Argon2id: uppercase, strip spaces and hyphens, map I/L to 1 and O to 0.",
        canonical: RECOVERY_CODE,
        asTyped: RECOVERY_CODE_MESSY,
        recoverySaltBase64: toBase64(RECOVERY_SALT),
        recoveryKeyBase64: toBase64(recoveryKeyMessy),
      },
    },

    aesGcm: {
      keyBase64: toBase64(AES_KEY),
      nonceBase64: toBase64(AES_NONCE),
      plaintextUtf8: "attack at dawn",
      envelope: await encryptBytesWithNonce(AES_PLAINTEXT, AES_KEY, AES_NONCE),
    },

    seal: {
      recipientPrivateKeyBase64: toBase64(RECIPIENT_PRIVATE),
      recipientPublicKeyBase64: toBase64(recipientPublic),
      ephemeralPrivateKeyBase64: toBase64(EPHEMERAL_PRIVATE),
      nonceBase64: toBase64(SEAL_NONCE),
      secretBase64: toBase64(SEAL_SECRET),
      sealed: JSON.parse(
        await sealToUserWithEphemeral(SEAL_SECRET, recipientPublic, EPHEMERAL_PRIVATE, SEAL_NONCE),
      ) as unknown,
    },

    recovery: {
      code: RECOVERY_CODE,
      recoverySaltBase64: toBase64(RECOVERY_SALT),
      recoveryKeyBase64: toBase64(recoveryKey),
    },

    fingerprint: {
      email: FINGERPRINT_EMAIL,
      publicKeyBase64: toBase64(recipientPublic),
      fingerprint: publicKeyFingerprint(recipientPublic, FINGERPRINT_EMAIL),
    },

    // The exact JSON that gets encrypted. Item plaintext is a discriminated
    // union, not one struct with optional fields: a `note` has no username,
    // password, urls or passwordHistory at all. A port that models it as one
    // struct should discover that here rather than after shipping.
    itemPlaintext: {
      login: { object: ITEM_LOGIN, json: JSON.stringify(ITEM_LOGIN) },
      note: { object: ITEM_NOTE, json: JSON.stringify(ITEM_NOTE) },
    },

    // The whole hierarchy in one place, so a porter whose end-to-end test fails
    // can bisect in one step instead of five. wrappingKey is kdf.wrapKeyBase64,
    // so this chains directly onto the KDF vector above.
    composed: {
      _comment:
        "masterPassword -> masterKey -> wrappingKey -> protectedUserKey -> userKey -> wrappedItemKey -> itemKey.",
      wrappingKeyBase64: toBase64(wrapKey),
      userKeyBase64: toBase64(COMPOSED_USER_KEY),
      protectedUserKeyNonceBase64: toBase64(COMPOSED_USER_KEY_NONCE),
      protectedUserKey: serializeEnvelope(
        await encryptBytesWithNonce(COMPOSED_USER_KEY, wrapKey, COMPOSED_USER_KEY_NONCE),
      ),
      itemKeyBase64: toBase64(COMPOSED_ITEM_KEY),
      wrappedItemKeyNonceBase64: toBase64(COMPOSED_ITEM_KEY_NONCE),
      wrappedItemKey: serializeEnvelope(
        await encryptBytesWithNonce(COMPOSED_ITEM_KEY, COMPOSED_USER_KEY, COMPOSED_ITEM_KEY_NONCE),
      ),
    },
  };

  const outDir = join(here, "..", "vectors");
  mkdirSync(outDir, { recursive: true });
  const json = escapeNonAscii(JSON.stringify(vectors, null, 2));
  writeFileSync(join(outDir, "vectors.json"), `${json}\n`, "utf8");
  console.log("Wrote vectors/vectors.json");
}

await main();
