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
import { deriveAuthHash, deriveMasterKey, deriveWrapKey } from "../src/kdf.js";
import { encryptBytesWithNonce } from "../src/symmetric.js";
import { sealToUserWithEphemeral } from "../src/seal.js";
import { publicKeyFor } from "../src/keys.js";
import { publicKeyFingerprint } from "../src/fingerprint.js";
import { deriveRecoveryKey } from "../src/recovery.js";
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
const FINGERPRINT_EMAIL = "seth@gmail.com";

async function main(): Promise<void> {
  const masterKey = await deriveMasterKey(MASTER_PASSWORD, KDF_SALT);
  const recipientPublic = publicKeyFor(RECIPIENT_PRIVATE);

  const vectors = {
    _comment:
      "Frozen cross-language test vectors for Keyhole. Any client implementation " +
      "must reproduce these exactly. Regenerate only with a deliberate format change.",
    kdf: {
      masterPassword: MASTER_PASSWORD,
      kdfSaltBase64: toBase64(KDF_SALT),
      params: { algorithm: "argon2id", memoryKiB: 65536, iterations: 3, parallelism: 4 },
      masterKeyBase64: toBase64(masterKey),
      wrapKeyBase64: toBase64(deriveWrapKey(masterKey)),
      authHashBase64: toBase64(deriveAuthHash(masterKey)),
    },
    aesGcm: {
      keyBase64: toBase64(AES_KEY),
      nonceBase64: toBase64(AES_NONCE),
      plaintextUtf8: "attack at dawn",
      envelope: await encryptBytesWithNonce(AES_KEY, AES_PLAINTEXT, AES_NONCE),
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
      recoveryKeyBase64: toBase64(await deriveRecoveryKey(RECOVERY_CODE, RECOVERY_SALT)),
    },
    fingerprint: {
      email: FINGERPRINT_EMAIL,
      publicKeyBase64: toBase64(recipientPublic),
      fingerprint: publicKeyFingerprint(recipientPublic, FINGERPRINT_EMAIL),
    },
  };

  const outDir = join(here, "..", "vectors");
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "vectors.json"), `${JSON.stringify(vectors, null, 2)}\n`, "utf8");
  console.log("Wrote vectors/vectors.json");
}

await main();
