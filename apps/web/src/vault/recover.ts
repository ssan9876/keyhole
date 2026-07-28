import {
  DEFAULT_KDF_PARAMS,
  DEFAULT_KDF_PARAMS_JSON,
  createRecoveryBlob,
  deriveRecoveryAuthHash,
  deriveRecoveryKey,
  deriveRecoveryWrapKey,
  fromBase64,
  generateRecoveryCode,
  rotateMasterPassword,
  toBase64,
  unwrapKey,
  zeroize,
  type KdfParams,
} from "@keyhole/crypto";
import { ApiError, type ApiClient } from "./api.js";

/**
 * The email and recovery code together did not open the account.
 *
 * Distinct from every other failure because design spec §9 requires honest
 * wording: a network blip must never read as a wrong code, and a wrong code
 * must not read as a server fault. It deliberately names both inputs, because
 * the server answers an unknown address, a wrong code, a disabled account and a
 * blob that predates the auth-hash split identically — by design, so that this
 * endpoint cannot be used to find out who has an account here.
 */
export class WrongRecoveryCodeError extends Error {
  constructor() {
    super("That email and recovery code did not match an account");
    this.name = "WrongRecoveryCodeError";
  }
}

/**
 * A redemption in progress: the keys the code opened, and the one-time token
 * that finishes it.
 *
 * The token is short-lived server-side (ten minutes), which is the window the
 * user has to type a new password twice. The keys are held here and nowhere
 * else — this object never reaches storage, and `completeRecovery` does not
 * take ownership of it.
 */
export interface RecoverySession {
  readonly email: string;
  /** In memory only. The key every item, folder and collection key hangs off. */
  readonly userKey: Uint8Array;
  /** In memory only. Opens collection keys sealed to this user. */
  readonly privateKey: Uint8Array;
  readonly recoveryToken: string;
  /** Seconds the token remains valid, as the server reported it. */
  readonly expiresIn: number;
  /**
   * Overwrite the recovered keys.
   *
   * Present because `src/ui/**` may not import `@keyhole/crypto` (ESLint
   * enforces it), so a screen that abandons or finishes a recovery has no other
   * way to clear what this object holds.
   */
  destroy(): void;
}

interface RecoverPreloginResponse {
  recoverySalt: string;
  recoveryKdfParams: string;
}

interface RecoverResponse {
  recoveryProtectedUserKey: string;
  encryptedPrivateKey: string;
  recoveryToken: string;
  expiresIn: number;
}

/**
 * The first half of redeeming a recovery code: prove possession, get the blobs
 * back, open them.
 *
 * One Argon2id pass, not two. The recovery key splits by HKDF into an auth half
 * that is sent to the server and a wrap half that opens the blob
 * (`packages/crypto/src/recovery.ts`), and both come from the same derivation —
 * so calling `recoverUserKey` here, which re-derives from the code, would spend
 * a second 64 MiB pass on a value already in hand. That is another half-second
 * or more on a phone, on a screen where the user is already waiting and has
 * already lost their password once today.
 *
 * The params come from prelogin rather than from the client's default: the blob
 * may have been wrapped under others (spec §4.2 records them per account), and
 * deriving under the wrong ones turns a correct code into a wrong one at the
 * moment recovery is the last resort.
 */
export async function recoverAccount(
  deps: { api: ApiClient },
  input: { email: string; recoveryCode: string },
): Promise<RecoverySession> {
  const prelogin = await deps.api.post<RecoverPreloginResponse>(
    "/api/auth/recover/prelogin",
    { email: input.email },
  );

  // An unknown address gets a deterministic decoy salt and the default params,
  // shaped exactly like a real answer. That is the enumeration defence, and it
  // means this path is identical either way right up to the 401 below.
  const params = JSON.parse(prelogin.recoveryKdfParams) as KdfParams;
  const recoveryKey = await deriveRecoveryKey(
    input.recoveryCode,
    fromBase64(prelogin.recoverySalt),
    params,
  );

  let wrappingKey: Uint8Array | null = null;
  try {
    // base64, because that is the encoding enrolment uploaded and the server
    // stores a hash of that exact string. Nothing pins this the way
    // DEFAULT_KDF_PARAMS_JSON pins the parameters — it is convention on both
    // sides — so hex here would make a correct code fail with a 401 that looks
    // exactly like a wrong one.
    const authHalf = deriveRecoveryAuthHash(recoveryKey);
    let recoveryAuthHash: string;
    try {
      recoveryAuthHash = toBase64(authHalf);
    } finally {
      // Encoded first, then cleared. It decrypts nothing — that is the point of
      // the split — but it is derived from the code and has no reason to stay
      // live once the string exists.
      zeroize(authHalf);
    }

    let redeemed: RecoverResponse;
    try {
      redeemed = await deps.api.post<RecoverResponse>("/api/auth/recover", {
        email: input.email,
        recoveryAuthHash,
      });
    } catch (error) {
      // Only a 401 means "wrong". A NetworkError, a 429 and a 500 all pass
      // through untouched, so none of them can be shown as a bad code.
      if (error instanceof ApiError && error.code === "unauthorized") {
        throw new WrongRecoveryCodeError();
      }
      throw error;
    }

    wrappingKey = deriveRecoveryWrapKey(recoveryKey);
    // A failure here is not a wrong code: the server already verified the auth
    // half, so the code is right and the blob is damaged. DecryptionError says
    // exactly that and is deliberately left to propagate.
    const userKey = await unwrapKey(redeemed.recoveryProtectedUserKey, wrappingKey);
    const privateKey = await unwrapKey(redeemed.encryptedPrivateKey, userKey);

    return {
      email: input.email,
      userKey,
      privateKey,
      recoveryToken: redeemed.recoveryToken,
      expiresIn: redeemed.expiresIn,
      destroy(): void {
        zeroize(userKey, privateKey);
      },
    };
  } finally {
    // Both halves of the recovery key, whichever way this went. The userKey and
    // privateKey belong to the caller from here; destroy() clears those.
    zeroize(recoveryKey, wrappingKey);
  }
}

/**
 * The second half: a new master password, a new recovery code, both uploaded
 * together.
 *
 * The userKey is deliberately unchanged — only its wrapping is redone — so no
 * item, folder or collection key is touched and nothing in the vault needs
 * rewriting. Generating a fresh one here would look identical from the outside
 * and would orphan every item the user owns.
 *
 * Both credentials move in one request because the server rotates them in one
 * transaction: replacing only the password would leave a recovery code that
 * still opens the vault, and replacing only the blob would leave the user
 * locked out exactly as they were. The request also ends every session,
 * including any the person who may have read the old code was holding.
 *
 * Returns the new recovery code, which is shown once and then gone. It is
 * returned only after the upload succeeds: unlike enrolment, where the account
 * already exists by the time the code is minted, a code whose blob never
 * reached the server opens nothing and showing it would be a lie.
 */
export async function completeRecovery(
  deps: { api: ApiClient },
  session: RecoverySession,
  newMasterPassword: string,
): Promise<string> {
  const rotation = await rotateMasterPassword(
    newMasterPassword,
    session.userKey,
    DEFAULT_KDF_PARAMS,
  );

  const recoveryCode = generateRecoveryCode();
  const blob = await createRecoveryBlob(session.userKey, recoveryCode, DEFAULT_KDF_PARAMS);
  // Encoded and cleared in the same breath, exactly as enrolment does it.
  // Order matters: clearing before toBase64 would upload a field of zeros and
  // leave the user holding a freshly issued code no server will ever accept.
  const recoveryAuthHash = toBase64(blob.recoveryAuthHash);
  zeroize(blob.recoveryAuthHash);

  await deps.api.post("/api/auth/recover/complete", {
    recoveryToken: session.recoveryToken,
    kdfSalt: toBase64(rotation.kdfSalt),
    // The pinned constants, verbatim, both of them. Never JSON.stringify an
    // object into either field: the server compares raw bytes, because its two
    // prelogin endpoints answer unknown addresses with these exact strings and
    // any divergence would make this account distinguishable from a decoy.
    params: DEFAULT_KDF_PARAMS_JSON,
    authHash: toBase64(rotation.authHash),
    protectedUserKey: rotation.protectedUserKey,
    recoverySalt: toBase64(blob.recoverySalt),
    recoveryKdfParams: DEFAULT_KDF_PARAMS_JSON,
    recoveryProtectedUserKey: blob.recoveryProtectedUserKey,
    recoveryAuthHash,
  });

  return recoveryCode;
}
