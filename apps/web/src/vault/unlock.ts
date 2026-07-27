import {
  beginUnlock,
  fromBase64,
  toBase64,
  type KdfParams,
} from "@keyhole/crypto";
import { ApiError, type ApiClient } from "./api.js";
import { rememberEmail, type Session, type SessionUser } from "./session.js";

/**
 * The password did not open the vault.
 *
 * Distinct from every other failure because design spec 9 requires unlock
 * failure to be honestly worded: a network blip must never read as a wrong
 * password, and a wrong password must not read as a server fault.
 */
export class WrongMasterPasswordError extends Error {
  constructor() {
    super("Wrong master password");
    this.name = "WrongMasterPasswordError";
  }
}

interface PreloginResponse {
  kdfSalt: string;
  params: string;
}

interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  protectedUserKey: string;
  encryptedPrivateKey: string;
  user: SessionUser;
}

/**
 * prelogin then login, with exactly one Argon2id pass between them.
 *
 * The order is forced by the protocol: login is authHash out and the wrapped
 * keys back, so the client must produce the hash before it holds the blobs.
 * beginUnlock exists precisely so that costs one derivation rather than two — a
 * second is another second on a phone, on the screen where the user is already
 * waiting.
 */
export async function unlock(
  deps: { api: ApiClient; session: Session },
  input: { email: string; masterPassword: string; deviceLabel: string },
): Promise<void> {
  const prelogin = await deps.api.post<PreloginResponse>("/api/auth/prelogin", {
    email: input.email,
  });

  // An unknown address gets a decoy salt and the default params, shaped exactly
  // like a real answer. That is the enumeration defence, and it means this path
  // is identical either way right up to the 401.
  const params = JSON.parse(prelogin.params) as KdfParams;
  const unlockSession = await beginUnlock(
    input.masterPassword,
    fromBase64(prelogin.kdfSalt),
    params,
  );

  try {
    let login: LoginResponse;
    try {
      login = await deps.api.post<LoginResponse>("/api/auth/login", {
        email: input.email,
        authHash: toBase64(unlockSession.authHash),
        deviceLabel: input.deviceLabel,
      });
    } catch (error) {
      if (error instanceof ApiError && error.code === "unauthorized") {
        throw new WrongMasterPasswordError();
      }
      throw error;
    }

    const keys = await unlockSession.finish(
      login.protectedUserKey,
      login.encryptedPrivateKey,
    );

    deps.session.open({
      tokens: {
        accessToken: login.accessToken,
        refreshToken: login.refreshToken,
      },
      user: login.user,
      userKey: keys.userKey,
      privateKey: keys.privateKey,
    });
    // Only after success: a failed attempt must not pin a typo into the screen.
    rememberEmail(input.email);
  } finally {
    // Zeroizes the derived master and wrapping keys whichever way this went.
    unlockSession.destroy();
  }
}
