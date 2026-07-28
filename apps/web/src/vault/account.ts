import {
  DEFAULT_KDF_PARAMS,
  DEFAULT_KDF_PARAMS_JSON,
  createRecoveryBlob,
  deriveAuthHash,
  deriveMasterKey,
  fromBase64,
  generateRecoveryCode,
  publicKeyFingerprint,
  rotateMasterPassword,
  toBase64,
  zeroize,
  type KdfParams,
} from "@keyhole/crypto";
import type { ApiClient } from "./api.js";
import type { Session } from "./session.js";

type Deps = { api: ApiClient; session: Session };

export interface AccountProfile {
  id: string;
  email: string;
  name: string;
  role: string;
  publicKey: string;
  createdAt: string;
  /** The user's own fingerprint, so they can read it to someone comparing. */
  fingerprint: string;
}

export interface DeviceSession {
  id: string;
  deviceLabel: string;
  createdAt: string;
  lastSeenAt: string;
  current: boolean;
}

interface PreloginResponse {
  kdfSalt: string;
  params: string;
}

/**
 * Re-derives the current auth hash, which both write endpoints require.
 *
 * The session proves who the caller is; it does not prove they hold the master
 * password. Both endpoints overwrite key material, so without this a stolen
 * access token would be enough to write garbage over a wrapped key and destroy
 * a vault beyond recovery.
 *
 * The salt must come from prelogin — it is the salt this account's current
 * password was derived under, and a fresh one would produce a hash that
 * verifies against nothing.
 */
async function currentAuthHash(deps: Deps, email: string, currentPassword: string): Promise<string> {
  const prelogin = await deps.api.post<PreloginResponse>("/api/auth/prelogin", { email });
  const params = JSON.parse(prelogin.params) as KdfParams;
  const masterKey = await deriveMasterKey(currentPassword, fromBase64(prelogin.kdfSalt), params);
  try {
    return toBase64(deriveAuthHash(masterKey));
  } finally {
    zeroize(masterKey);
  }
}

export async function loadAccount(deps: Deps): Promise<AccountProfile> {
  const profile = await deps.api.get<Omit<AccountProfile, "fingerprint">>("/api/account");
  let fingerprint = "";
  try {
    fingerprint = publicKeyFingerprint(fromBase64(profile.publicKey), profile.email);
  } catch {
    // A pending account has no public key. Showing an empty fingerprint beats
    // failing the whole settings screen.
  }
  return { ...profile, fingerprint };
}

/**
 * Changes the master password without touching the userKey.
 *
 * Only the wrapping is redone, so no item, folder, or collection key is
 * re-encrypted and nothing in the vault needs rewriting. The server revokes
 * every other session but keeps this one, so the vault stays unlocked here.
 */
export async function changeMasterPassword(
  deps: Deps,
  input: { email: string; currentPassword: string; newPassword: string },
): Promise<void> {
  const current = await currentAuthHash(deps, input.email, input.currentPassword);
  const rotation = await rotateMasterPassword(
    input.newPassword,
    deps.session.getKeys().userKey,
    DEFAULT_KDF_PARAMS,
  );
  await deps.api.post("/api/account/password", {
    currentAuthHash: current,
    kdfSalt: toBase64(rotation.kdfSalt),
    // The pinned constant, verbatim. Never JSON.stringify an object here.
    params: DEFAULT_KDF_PARAMS_JSON,
    authHash: toBase64(rotation.authHash),
    protectedUserKey: rotation.protectedUserKey,
  });
}

/**
 * Issues a new recovery code and invalidates the old one.
 *
 * Returns the code, which is shown once and then gone: the server stores only
 * a blob the code opens, and cannot reproduce it.
 */
export async function regenerateRecoveryCode(
  deps: Deps,
  input: { email: string; currentPassword: string },
): Promise<string> {
  const current = await currentAuthHash(deps, input.email, input.currentPassword);
  const recoveryCode = generateRecoveryCode();
  const blob = await createRecoveryBlob(
    deps.session.getKeys().userKey,
    recoveryCode,
    DEFAULT_KDF_PARAMS,
  );
  // Encoded and cleared in the same breath. It decrypts nothing — that is the
  // point of the HKDF split — but it is derived from the recovery code, and
  // once the base64 string exists there is no reason to leave the bytes live.
  // Order matters: clearing before toBase64 would upload a field of zeros and
  // leave the user holding a code no server will ever accept.
  const recoveryAuthHash = toBase64(blob.recoveryAuthHash);
  zeroize(blob.recoveryAuthHash);
  await deps.api.post("/api/account/recovery", {
    currentAuthHash: current,
    recoverySalt: toBase64(blob.recoverySalt),
    // NOT pinned, deliberately: no endpoint returns this, so it leaks nothing,
    // and recording the params the blob was actually made under is what keeps
    // a correct code from failing later.
    recoveryKdfParams: JSON.stringify(blob.params),
    recoveryProtectedUserKey: blob.recoveryProtectedUserKey,
    // Proof of possession for the redeem endpoints, hashed again server-side
    // before storage. The endpoint rejects a rotation without it rather than
    // writing a recovery record no code can redeem.
    recoveryAuthHash,
  });
  return recoveryCode;
}

export async function listSessions(deps: Deps): Promise<DeviceSession[]> {
  const response = await deps.api.get<{ sessions: DeviceSession[] }>("/api/account/sessions");
  return response.sessions;
}

export async function revokeSession(deps: Deps, sessionId: string): Promise<void> {
  await deps.api.del(`/api/account/sessions/${sessionId}`);
}
