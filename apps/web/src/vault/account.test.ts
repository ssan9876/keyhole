import { describe, expect, it } from "vitest";
import {
  DEFAULT_KDF_PARAMS,
  DEFAULT_KDF_PARAMS_JSON,
  deriveAuthHash,
  deriveMasterKey,
  deriveWrapKey,
  fromBase64,
  generateKdfSalt,
  recoverUserKey,
  toBase64,
  unwrapKey,
} from "@keyhole/crypto";
import { NetworkError, type ApiClient } from "./api.js";
import { changeMasterPassword, regenerateRecoveryCode } from "./account.js";
import { fakeApi, openSession } from "./test-helpers.js";

interface RecordedCall {
  path: string;
  body: Record<string, unknown>;
}

/**
 * An ApiClient that answers `/api/auth/prelogin` with a real-shaped response
 * built from `preloginSalt` (as prelogin actually returns for a known
 * account), records every POST it sees, and answers every other POST with
 * `null` (a 204, as both write endpoints under test actually return).
 */
function recordingApi(preloginSalt: Uint8Array): { api: ApiClient; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const api = fakeApi({
    post: async (path, body) => {
      calls.push({ path, body: (body ?? {}) as Record<string, unknown> });
      if (path === "/api/auth/prelogin") {
        return { kdfSalt: toBase64(preloginSalt), params: DEFAULT_KDF_PARAMS_JSON };
      }
      return null;
    },
  });
  return { api, calls };
}

const CREDENTIALS = { email: "a@example.com", currentPassword: "old-password", newPassword: "new-password" };

describe("changeMasterPassword", () => {
  it("sends the pinned params string byte for byte", async () => {
    const salt = generateKdfSalt();
    const { api, calls } = recordingApi(salt);

    await changeMasterPassword({ api, session: openSession() }, CREDENTIALS);

    const rotate = calls.find((c) => c.path === "/api/account/password");
    // Byte equality against the constant, not a parsed comparison. The server
    // compares the raw string; a semantically identical object with reordered
    // keys is rejected with 400 (internal/httpapi/account.go:76).
    expect(rotate?.body["params"]).toBe(DEFAULT_KDF_PARAMS_JSON);
  }, 30_000);

  it("derives currentAuthHash from the salt prelogin returned, not from a fresh one", async () => {
    const salt = generateKdfSalt();
    const { api, calls } = recordingApi(salt);

    await changeMasterPassword({ api, session: openSession() }, CREDENTIALS);

    const rotate = calls.find((c) => c.path === "/api/account/password");
    const expected = toBase64(
      deriveAuthHash(await deriveMasterKey(CREDENTIALS.currentPassword, salt, DEFAULT_KDF_PARAMS)),
    );
    expect(rotate?.body["currentAuthHash"]).toBe(expected);
  }, 30_000);

  it("re-wraps the SAME userKey under the new password, so existing items still open", async () => {
    const salt = generateKdfSalt();
    const { api, calls } = recordingApi(salt);
    const session = openSession();
    const userKey = session.getKeys().userKey;

    await changeMasterPassword({ api, session }, CREDENTIALS);

    const rotate = calls.find((c) => c.path === "/api/account/password");
    const newMaster = await deriveMasterKey(
      CREDENTIALS.newPassword,
      fromBase64(rotate?.body["kdfSalt"] as string),
      DEFAULT_KDF_PARAMS,
    );
    // The proof: the blob the server will store unwraps to the key this
    // session is already using. A regenerated userKey would pass any
    // "something was sent" assertion and orphan every item in the vault.
    await expect(
      unwrapKey(rotate?.body["protectedUserKey"] as string, deriveWrapKey(newMaster)),
    ).resolves.toEqual(userKey);
  }, 30_000);

  it("never sends either password or the userKey", async () => {
    const salt = generateKdfSalt();
    const { api, calls } = recordingApi(salt);
    const session = openSession();
    const userKey = session.getKeys().userKey;

    await changeMasterPassword({ api, session }, CREDENTIALS);

    const serialized = JSON.stringify(calls);
    expect(serialized).not.toContain(CREDENTIALS.currentPassword);
    expect(serialized).not.toContain(CREDENTIALS.newPassword);
    expect(serialized).not.toContain(toBase64(userKey));
  }, 30_000);

  it("does not call the rotate endpoint when prelogin fails", async () => {
    const calls: { path: string }[] = [];
    const api = fakeApi({
      post: async (path) => {
        calls.push({ path });
        throw new NetworkError(new Error("down"));
      },
    });

    await expect(
      changeMasterPassword({ api, session: openSession() }, CREDENTIALS),
    ).rejects.toThrow(NetworkError);
    expect(calls.map((c) => c.path)).toEqual(["/api/auth/prelogin"]);
  }, 30_000);
});

const RECOVERY_INPUT = { email: "a@example.com", currentPassword: "old-password" };

describe("regenerateRecoveryCode", () => {
  it("returns a code that unwraps the current userKey from the blob it uploaded", async () => {
    const salt = generateKdfSalt();
    const { api, calls } = recordingApi(salt);
    const session = openSession();

    const code = await regenerateRecoveryCode({ api, session }, RECOVERY_INPUT);

    const rotate = calls.find((c) => c.path === "/api/account/recovery");
    const recovered = await recoverUserKey(
      rotate?.body["recoveryProtectedUserKey"] as string,
      code,
      fromBase64(rotate?.body["recoverySalt"] as string),
      JSON.parse(rotate?.body["recoveryKdfParams"] as string),
    );
    // End to end through the real crypto: this is what "the code works" means,
    // and nothing weaker distinguishes a correct blob from a well-shaped one.
    expect(recovered).toEqual(session.getKeys().userKey);
  }, 30_000);

  it("sends recoveryKdfParams as the params the blob was actually made under", async () => {
    const salt = generateKdfSalt();
    const { api, calls } = recordingApi(salt);
    const session = openSession();

    await regenerateRecoveryCode({ api, session }, RECOVERY_INPUT);

    const rotate = calls.find((c) => c.path === "/api/account/recovery");
    expect(JSON.parse(rotate?.body["recoveryKdfParams"] as string)).toEqual(DEFAULT_KDF_PARAMS);
  }, 30_000);

  it("never sends the recovery code itself", async () => {
    const salt = generateKdfSalt();
    const { api, calls } = recordingApi(salt);
    const session = openSession();

    const code = await regenerateRecoveryCode({ api, session }, RECOVERY_INPUT);

    // The server never sees it — that is the whole design (spec §3.6). Check
    // both the grouped form (with hyphens, as generated) and the ungrouped
    // form (hyphens stripped, as normalizeCrockford would produce) — a leak
    // that split the code across body fields at a hyphen boundary would still
    // read as a match for one form but not the other.
    const serialized = JSON.stringify(calls);
    expect(serialized).not.toContain(code);
    expect(serialized).not.toContain(code.replace(/-/g, ""));
  }, 30_000);
});
