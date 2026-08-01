import {
  DEFAULT_KDF_PARAMS,
  DEFAULT_KDF_PARAMS_JSON,
  createRecoveryBlob,
  enrollUser,
  generateRecoveryCode,
  toBase64,
  zeroize,
} from "@keyhole/crypto";
import type { ApiClient } from "./api.js";
import type { Session, SessionUser } from "./session.js";

export interface EnrolmentOutcome {
  /** Shown exactly once. It cannot be recovered afterwards — not by an admin,
   *  not by anyone holding the database. */
  recoveryCode: string;
  /**
   * True once the follow-up login succeeded and the session is open.
   *
   * False means POST /api/enroll/:token already returned 200 — the invite is
   * consumed and the account exists with the credentials just set — but the
   * login that normally follows it failed (a network blip, a 5xx). The
   * caller must still surface `recoveryCode`: it is gone forever otherwise,
   * and there is no second chance to show it. The user can unlock normally
   * afterwards, since the account already has everything it needs.
   */
  loggedIn: boolean;
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
  deps: { api: ApiClient; session: Session; rememberEmail: (email: string) => void },
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
  // Encoded and cleared in the same breath. It decrypts nothing — that is the
  // point of the HKDF split — but it is derived from the recovery code, and
  // once the base64 string exists there is no reason to leave the bytes live.
  // Order matters: clearing before toBase64 would upload a field of zeros and
  // leave the account with a recovery code no server will ever accept.
  const recoveryAuthHash = toBase64(recovery.recoveryAuthHash);
  zeroize(recovery.recoveryAuthHash);

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
    // Proof of possession for the redeem endpoints, hashed again server-side
    // before storage. Without it the server rejects the enrolment outright —
    // a NULL here is reserved for accounts that predate the split, and those
    // are unredeemable by design.
    recoveryAuthHash,
    // Pinned too, and sent as the same constant verbatim. This used to say the
    // field leaks nothing because no endpoint returns it; POST
    // /api/auth/recover/prelogin now does, and answers an unknown address with
    // this exact string — so an account recording anything else would be
    // distinguishable from a decoy, and the server rejects it with 400.
    //
    // The blob really is made under these parameters (createRecoveryBlob was
    // handed DEFAULT_KDF_PARAMS above), so spec §4.2's "record what it was
    // wrapped under" still holds; what is gone is the freedom to record
    // something else. A JSON.stringify here produced the right bytes only
    // because the object literal happens to be declared in this key order.
    recoveryKdfParams: DEFAULT_KDF_PARAMS_JSON,
  });

  // POST /api/enroll/:token has returned 200: the invite is consumed and the
  // account exists. From here on, nothing may destroy recoveryCode — it is
  // the only way back into the vault, and there is no second chance to show
  // it. Remembering the email is safe regardless of what happens next: it is
  // the one value this application persists, and the user typed it whether
  // or not the login below succeeds.
  deps.rememberEmail(input.email);

  try {
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
      // These are the objects enrollUser produced. The keys never left memory
      // and were never round-tripped through the server.
      userKey: enrolled.userKey,
      privateKey: enrolled.keyPair.privateKey,
    });

    return { recoveryCode, loggedIn: true };
  } catch {
    // The account exists and its credentials are already set server-side; a
    // normal unlock will succeed. What must not happen is losing the code
    // because this last, resumable step hiccupped.
    return { recoveryCode, loggedIn: false };
  }
}
