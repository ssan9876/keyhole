import { beforeAll, describe, expect, it } from "vitest";
import {
  DEFAULT_KDF_PARAMS,
  DEFAULT_KDF_PARAMS_JSON,
  createRecoveryBlob,
  deriveMasterKey,
  deriveRecoveryAuthHash,
  deriveRecoveryKey,
  deriveWrapKey,
  fromBase64,
  generateKeyPair,
  generateRecoveryCode,
  generateUserKey,
  recoverUserKey,
  toBase64,
  unwrapKey,
  wrapKey,
  zeroize,
  type KdfParams,
} from "@keyhole/crypto";
import { ApiError, NetworkError, type ApiClient } from "./api.js";
import { fakeApi } from "./test-helpers.js";
import { WrongRecoveryCodeError, completeRecovery, recoverAccount } from "./recover.js";

/**
 * An account exactly as enrolment left it on the server.
 *
 * Built with the same calls `enroll.ts` makes, in the same order, because the
 * property under test is that a *different device months later* can redeem what
 * enrolment stored. A fixture that derived its values the way `recover.ts` does
 * would prove only that the file agrees with itself.
 */
interface Account {
  email: string;
  recoveryCode: string;
  userKey: Uint8Array;
  privateKey: Uint8Array;
  /** The columns POST /api/auth/recover/prelogin reads back out. */
  recoverySalt: string;
  recoveryKdfParams: string;
  /** The blobs POST /api/auth/recover hands back. */
  recoveryProtectedUserKey: string;
  encryptedPrivateKey: string;
  /**
   * The string enrolment uploaded, byte for byte. The server stores a hash of
   * it and compares a redeeming caller's value against that hash, so this is
   * the whole contract at the encoding seam: base64 in, base64 back.
   */
  storedRecoveryAuthHash: string;
}

async function enrolledAccount(): Promise<Account> {
  const userKey = generateUserKey();
  const keyPair = generateKeyPair();
  const recoveryCode = generateRecoveryCode();
  const blob = await createRecoveryBlob(userKey, recoveryCode, DEFAULT_KDF_PARAMS);
  // Encoded before anything clears it, exactly as enroll.ts does — reading it
  // after a zeroize would seed the fixture with 32 zero bytes and make every
  // assertion below meaningless.
  const storedRecoveryAuthHash = toBase64(blob.recoveryAuthHash);
  zeroize(blob.recoveryAuthHash);

  return {
    email: "person@example.com",
    recoveryCode,
    userKey,
    privateKey: keyPair.privateKey,
    recoverySalt: toBase64(blob.recoverySalt),
    recoveryKdfParams: DEFAULT_KDF_PARAMS_JSON,
    recoveryProtectedUserKey: blob.recoveryProtectedUserKey,
    encryptedPrivateKey: await wrapKey(keyPair.privateKey, userKey),
    storedRecoveryAuthHash,
  };
}

interface RecordedCall {
  path: string;
  body: Record<string, unknown>;
}

const RECOVERY_TOKEN = "recovery-token-abc";

/**
 * The three endpoints, answering as `internal/httpapi/recover.go` does.
 *
 * The redeem step compares the uploaded `recoveryAuthHash` against the string
 * enrolment stored and refuses with 401 otherwise, which is what
 * `auth.VerifyAuthHash` amounts to. That comparison is deliberately part of the
 * fixture rather than only of one assertion: it makes the encoding load-bearing
 * for every test in this file, so a client that sent hex, or the wrap half, or
 * a value derived under the wrong params, fails them all rather than passing
 * everything except one narrow check.
 */
function recoveringServer(account: Account): { api: ApiClient; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const api = fakeApi({
    post: async (path, body) => {
      const payload = (body ?? {}) as Record<string, unknown>;
      calls.push({ path, body: payload });
      if (path === "/api/auth/recover/prelogin") {
        return {
          recoverySalt: account.recoverySalt,
          recoveryKdfParams: account.recoveryKdfParams,
        };
      }
      if (path === "/api/auth/recover") {
        if (payload["recoveryAuthHash"] !== account.storedRecoveryAuthHash) {
          throw new ApiError("unauthorized", 401, "email or recovery code is incorrect", null);
        }
        return {
          recoveryProtectedUserKey: account.recoveryProtectedUserKey,
          encryptedPrivateKey: account.encryptedPrivateKey,
          recoveryToken: RECOVERY_TOKEN,
          expiresIn: 600,
        };
      }
      if (path === "/api/auth/recover/complete") {
        return null;
      }
      throw new Error(`unexpected POST ${path}`);
    },
  });
  return { api, calls };
}

function bodyFor(calls: RecordedCall[], path: string): Record<string, unknown> {
  const call = calls.find((c) => c.path === path);
  if (!call) throw new Error(`no request was made to ${path}`);
  return call.body;
}

const NEW_PASSWORD = "a new master password";

let account: Account;

// One Argon2id pass for the whole file rather than one per test. Nothing here
// mutates the fixture: createRecoveryBlob and rotateMasterPassword both leave
// the caller's userKey untouched by contract.
beforeAll(async () => {
  account = await enrolledAccount();
}, 30_000);

describe("recoverAccount", () => {
  it("recovers the userKey and privateKey the blobs were made from", async () => {
    const { api } = recoveringServer(account);

    const session = await recoverAccount(
      { api },
      { email: account.email, recoveryCode: account.recoveryCode },
    );

    // Byte equality, not "some 32 bytes came back". This is the single promise
    // the recovery code makes: the key that opens the vault, not a new one.
    expect(Array.from(session.userKey)).toEqual(Array.from(account.userKey));
    // And the private half, unwrapped with that recovered userKey — without it
    // the user is back in but cannot open a single shared collection.
    expect(Array.from(session.privateKey)).toEqual(Array.from(account.privateKey));
    expect(session.recoveryToken).toBe(RECOVERY_TOKEN);
  }, 30_000);

  it("sends the auth hash base64-encoded, the way enrolment stored it", async () => {
    const { api, calls } = recoveringServer(account);

    await recoverAccount({ api }, { email: account.email, recoveryCode: account.recoveryCode });

    const sent = bodyFor(calls, "/api/auth/recover")["recoveryAuthHash"];
    // The encoding at this seam is convention only. Nothing pins it the way
    // DEFAULT_KDF_PARAMS_JSON pins the KDF parameters: the server stores
    // whatever string enrolment uploaded and compares byte for byte, so a
    // client that encoded hex here would make a *correct* recovery code fail,
    // on the one day the code matters, with a 401 indistinguishable from a
    // wrong code.
    expect(sent).toBe(account.storedRecoveryAuthHash);
    // Recomputed from the code and the two values the server keeps, which is
    // all a redeeming device has. Comparing the field to itself would pass
    // against zeros, against the wrap half, or against the wrong encoding.
    const recoveryKey = await deriveRecoveryKey(
      account.recoveryCode,
      fromBase64(account.recoverySalt),
      JSON.parse(account.recoveryKdfParams) as KdfParams,
    );
    expect(sent).toBe(toBase64(deriveRecoveryAuthHash(recoveryKey)));
    // Base64 of 32 bytes, not hex and not a byte-array literal: those are the
    // two encodings a port would reach for by accident, and both round-trip
    // through fromBase64 as something else or not at all.
    expect(fromBase64(sent as string)).toHaveLength(32);
  }, 30_000);

  it("derives the recovery key under the params prelogin returned, not a default of its own", async () => {
    const { api, calls } = recoveringServer(account);

    await recoverAccount({ api }, { email: account.email, recoveryCode: account.recoveryCode });

    // The blob may have been wrapped under parameters other than today's
    // default (spec §4.2 keeps recovery_kdf_params per account for exactly
    // that), and prelogin answers with the ones it was actually made under.
    // Ignoring them derives a different key from a perfectly correct code.
    expect(calls.map((c) => c.path)).toEqual(["/api/auth/recover/prelogin", "/api/auth/recover"]);
    expect(bodyFor(calls, "/api/auth/recover/prelogin")["email"]).toBe(account.email);
  }, 30_000);

  it("reports a wrong code as a wrong code, not a server error", async () => {
    const { api } = recoveringServer(account);

    // A real, well-formed code that simply is not this account's. The stub
    // refuses it the way the server does — by comparing the derived auth hash
    // — rather than by being told to fail.
    const attempt = recoverAccount(
      { api },
      { email: account.email, recoveryCode: generateRecoveryCode() },
    );

    await expect(attempt).rejects.toBeInstanceOf(WrongRecoveryCodeError);
  }, 30_000);

  it("reports an unreachable server as a connection problem, never as a wrong code", async () => {
    const { api: reachable } = recoveringServer(account);
    const api: ApiClient = {
      ...reachable,
      async post<T>(path: string, body?: unknown): Promise<T> {
        if (path === "/api/auth/recover") {
          throw new NetworkError(new TypeError("Failed to fetch"));
        }
        return reachable.post<T>(path, body);
      },
    };

    const failure: unknown = await recoverAccount(
      { api },
      { email: account.email, recoveryCode: account.recoveryCode },
    ).catch((error: unknown) => error);

    // Design spec §9: a network blip must never read as a wrong code. This is
    // the failure that arrives at the same moment and through the same call as
    // a 401, so it is the one that gets conflated. A resolved recovery lands
    // here as a RecoverySession and fails the first assertion.
    expect(failure).toBeInstanceOf(NetworkError);
    expect(failure).not.toBeInstanceOf(WrongRecoveryCodeError);
    // Told to try again with a different code, or to check a password they
    // have already lost, the user does the one thing that cannot help.
    expect((failure as Error).message).not.toMatch(/code/iu);
    expect((failure as Error).message).not.toMatch(/password/iu);
  }, 30_000);

  it("clears the recovered keys when the session is destroyed", async () => {
    const { api } = recoveringServer(account);

    const session = await recoverAccount(
      { api },
      { email: account.email, recoveryCode: account.recoveryCode },
    );
    const length = session.userKey.length;
    session.destroy();

    // The UI cannot import @keyhole/crypto (ESLint forbids it), so without a
    // method here a cancelled or completed recovery would leave the userKey and
    // the private key live in the tab with nothing able to clear them.
    expect(Array.from(session.userKey)).toEqual(Array.from(new Uint8Array(length)));
    expect(Array.from(session.privateKey)).toEqual(
      Array.from(new Uint8Array(session.privateKey.length)),
    );
  }, 30_000);
});

describe("completeRecovery", () => {
  it("re-wraps the SAME userKey under the new master password", async () => {
    const { api, calls } = recoveringServer(account);
    const session = await recoverAccount(
      { api },
      { email: account.email, recoveryCode: account.recoveryCode },
    );

    await completeRecovery({ api }, session, NEW_PASSWORD);

    const body = bodyFor(calls, "/api/auth/recover/complete");
    // Derived from the new password and the *uploaded* salt — the two things a
    // future unlock will have — then used to open the uploaded blob. Anything
    // weaker (a shape check, a "not empty", a comparison against the value the
    // client kept) passes just as happily on a freshly generated userKey, and
    // that would orphan every item, folder and collection key in the vault
    // while looking like a successful recovery.
    const masterKey = await deriveMasterKey(
      NEW_PASSWORD,
      fromBase64(body["kdfSalt"] as string),
      DEFAULT_KDF_PARAMS,
    );
    const rewrapped = await unwrapKey(body["protectedUserKey"] as string, deriveWrapKey(masterKey));
    expect(Array.from(rewrapped)).toEqual(Array.from(account.userKey));
  }, 30_000);

  it("returns a new code that opens the new recovery blob", async () => {
    const { api, calls } = recoveringServer(account);
    const session = await recoverAccount(
      { api },
      { email: account.email, recoveryCode: account.recoveryCode },
    );

    const newCode = await completeRecovery({ api }, session, NEW_PASSWORD);

    expect(newCode).not.toBe(account.recoveryCode);
    const body = bodyFor(calls, "/api/auth/recover/complete");
    // End to end through the public helper, from the code the user is shown to
    // the userKey it must produce. Redeeming a code retires it, so this new one
    // is the only way back in after today — a blob it cannot open is a promise
    // broken at the moment it is needed, and nothing else would catch it.
    const recovered = await recoverUserKey(
      body["recoveryProtectedUserKey"] as string,
      newCode,
      fromBase64(body["recoverySalt"] as string),
      JSON.parse(body["recoveryKdfParams"] as string) as KdfParams,
    );
    expect(Array.from(recovered)).toEqual(Array.from(account.userKey));
  }, 30_000);

  it("uploads a recovery auth hash the server can check the new code against", async () => {
    const { api, calls } = recoveringServer(account);
    const session = await recoverAccount(
      { api },
      { email: account.email, recoveryCode: account.recoveryCode },
    );

    const newCode = await completeRecovery({ api }, session, NEW_PASSWORD);

    const body = bodyFor(calls, "/api/auth/recover/complete");
    const recoveryKey = await deriveRecoveryKey(
      newCode,
      fromBase64(body["recoverySalt"] as string),
      JSON.parse(body["recoveryKdfParams"] as string) as KdfParams,
    );
    // Recomputed from the new code, as the next redemption will. createRecoveryBlob
    // hands back live bytes and the caller clears them once encoded; encoding
    // after the clear would upload 32 zero bytes and leave the freshly issued
    // code unredeemable, which nothing else in this file would notice.
    expect(body["recoveryAuthHash"]).toBe(toBase64(deriveRecoveryAuthHash(recoveryKey)));
    expect(fromBase64(body["recoveryAuthHash"] as string).some((byte) => byte !== 0)).toBe(true);
  }, 30_000);

  it("sends both pinned params strings verbatim", async () => {
    const { api, calls } = recoveringServer(account);
    const session = await recoverAccount(
      { api },
      { email: account.email, recoveryCode: account.recoveryCode },
    );

    await completeRecovery({ api }, session, NEW_PASSWORD);

    const body = bodyFor(calls, "/api/auth/recover/complete");
    // Byte equality both times: the server compares raw strings and rejects
    // anything else with 400, because its prelogin decoys answer unknown
    // addresses with these exact strings. A JSON.stringify of an equivalent
    // object passes only for as long as nobody reorders the literal.
    expect(body["params"]).toBe(DEFAULT_KDF_PARAMS_JSON);
    expect(body["recoveryKdfParams"]).toBe(DEFAULT_KDF_PARAMS_JSON);
    expect(body["recoveryToken"]).toBe(RECOVERY_TOKEN);
  }, 30_000);

  it("never sends a recovery code, grouped or hyphen-stripped, and persists nothing", async () => {
    const { api, calls } = recoveringServer(account);
    const session = await recoverAccount(
      { api },
      { email: account.email, recoveryCode: account.recoveryCode },
    );

    const newCode = await completeRecovery({ api }, session, NEW_PASSWORD);

    const serialized = JSON.stringify(calls);
    // Proof the haystack is the real payload before asserting on absence.
    expect(serialized).toContain("recoveryAuthHash");
    expect(serialized).toContain("protectedUserKey");
    // The server never sees a code — that is the whole design (spec §3.6).
    // Both forms of both codes: grouped as generated, and hyphen-stripped as
    // normalizeCrockford produces, since a leak that split a code across fields
    // at a hyphen boundary would match one form and not the other.
    for (const code of [account.recoveryCode, newCode]) {
      expect(serialized).not.toContain(code);
      expect(serialized).not.toContain(code.replace(/-/gu, ""));
    }
    // Nor the new master password, nor the recovered keys.
    expect(serialized).not.toContain(NEW_PASSWORD);
    expect(serialized).not.toContain(toBase64(account.userKey));
    expect(serialized).not.toContain(toBase64(account.privateKey));
    // A recovery token or a code left in storage is a spare key on the device
    // of someone who has just declared they lost control of their credentials.
    expect(localStorage.length).toBe(0);
    session.destroy();
  }, 30_000);
});
