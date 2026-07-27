import {
  DEFAULT_KDF_PARAMS,
  DEFAULT_KDF_PARAMS_JSON,
  createRecoveryBlob,
  enrollUser,
  generateRecoveryCode,
  toBase64,
} from "@keyhole/crypto";
import type { ApiClient } from "./api.js";
import { rememberEmail, type Session, type SessionUser } from "./session.js";

export interface EnrolmentOutcome {
  /** Shown exactly once. It cannot be recovered afterwards — not by an admin,
   *  not by anyone holding the database. */
  recoveryCode: string;
}

interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  protectedUserKey: string;
  encryptedPrivateKey: string;
  user: SessionUser;
}

/**
 * Everything that happens when someone sets a master password for the first
 * time.
 *
 * POST /api/enroll/:token returns only {id, email, name, role} — deliberately,
 * per its own comment: "never echo key material, not even the caller's own". So
 * a login follows. But enrollUser already produced the authHash, so that login
 * needs no prelogin and no second Argon2id pass; the whole flow costs one
 * derivation.
 */
export async function enroll(
  deps: { api: ApiClient; session: Session },
  input: {
    inviteToken: string;
    email: string;
    masterPassword: string;
    deviceLabel: string;
  },
): Promise<EnrolmentOutcome> {
  const enrolled = await enrollUser(input.masterPassword, DEFAULT_KDF_PARAMS);
  const recoveryCode = generateRecoveryCode();
  const recovery = await createRecoveryBlob(
    enrolled.userKey,
    recoveryCode,
    DEFAULT_KDF_PARAMS,
  );

  await deps.api.post(`/api/enroll/${encodeURIComponent(input.inviteToken)}`, {
    kdfSalt: toBase64(enrolled.kdfSalt),
    // The pinned constant, verbatim. Never JSON.stringify an object into this
    // field: key order is part of the contract and the server compares bytes.
    params: DEFAULT_KDF_PARAMS_JSON,
    authHash: toBase64(enrolled.authHash),
    protectedUserKey: enrolled.protectedUserKey,
    publicKey: toBase64(enrolled.publicKey),
    encryptedPrivateKey: enrolled.encryptedPrivateKey,
    recoverySalt: toBase64(recovery.recoverySalt),
    recoveryProtectedUserKey: recovery.recoveryProtectedUserKey,
    // NOT pinned: no endpoint returns it, so it leaks nothing, and recording
    // the params the blob was actually made under is what keeps a correct
    // recovery code from failing later — at the moment it is the last resort.
    recoveryKdfParams: JSON.stringify(recovery.params),
  });

  const login = await deps.api.post<LoginResponse>("/api/auth/login", {
    email: input.email,
    authHash: toBase64(enrolled.authHash),
    deviceLabel: input.deviceLabel,
  });

  deps.session.open({
    tokens: {
      accessToken: login.accessToken,
      refreshToken: login.refreshToken,
    },
    user: login.user,
    // These are the objects enrollUser produced. The keys never left memory and
    // were never round-tripped through the server.
    userKey: enrolled.userKey,
    privateKey: enrolled.keyPair.privateKey,
  });
  rememberEmail(input.email);

  return { recoveryCode };
}
