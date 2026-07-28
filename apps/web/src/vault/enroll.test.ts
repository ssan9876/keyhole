import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_KDF_PARAMS_JSON,
  deriveRecoveryAuthHash,
  deriveRecoveryKey,
  fromBase64,
  recoverUserKey,
  toBase64,
  type KdfParams,
} from "@keyhole/crypto";
import type { ApiClient } from "./api.js";
import { createSession } from "./session.js";
import { enroll } from "./enroll.js";

/**
 * Every blob `enroll` made, in call order.
 *
 * `vi.hoisted` because `vi.mock`'s factory is hoisted above every `const` in
 * this file and runs during import, so a plain module-level array would still
 * be in its temporal dead zone when the factory closes over it.
 */
const { blobs } = vi.hoisted(() => ({ blobs: [] as { recoveryAuthHash: Uint8Array }[] }));

// Everything real except a wrapper that keeps a handle on the blob object
// `enroll` received. Nothing else can observe whether the auth hash buffer was
// cleared afterwards: it is a local that never leaves the function.
vi.mock("@keyhole/crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@keyhole/crypto")>();
  return {
    ...actual,
    createRecoveryBlob: async (...args: Parameters<typeof actual.createRecoveryBlob>) => {
      const blob = await actual.createRecoveryBlob(...args);
      blobs.push(blob);
      return blob;
    },
  };
});

interface EnrolBody {
  kdfSalt: string;
  params: string;
  authHash: string;
  protectedUserKey: string;
  publicKey: string;
  encryptedPrivateKey: string;
  recoverySalt: string;
  recoveryProtectedUserKey: string;
  recoveryKdfParams: string;
  recoveryAuthHash: string;
}

function recordingApi(): { api: ApiClient; bodies: Map<string, unknown> } {
  const bodies = new Map<string, unknown>();
  const api: ApiClient = {
    async get<T>(): Promise<T> {
      throw new Error("unexpected GET");
    },
    async post<T>(path: string, body?: unknown): Promise<T> {
      const key = path.startsWith("/api/enroll/") ? "/api/enroll" : path;
      bodies.set(key, body);
      if (key === "/api/enroll") {
        // Deliberately minimal, matching the server: no tokens, no key material.
        return { id: "u1", email: "a@b.c", name: "A", role: "user" } as T;
      }
      if (path === "/api/auth/login") {
        const enrolled = bodies.get("/api/enroll") as EnrolBody;
        return {
          accessToken: "access",
          refreshToken: "refresh",
          protectedUserKey: enrolled.protectedUserKey,
          encryptedPrivateKey: enrolled.encryptedPrivateKey,
          user: { id: "u1", email: "a@b.c", name: "A", role: "user" },
        } as T;
      }
      throw new Error(`unexpected POST ${path}`);
    },
    async put<T>(): Promise<T> {
      throw new Error("unexpected PUT");
    },
    async patch<T>(): Promise<T> {
      throw new Error("unexpected PATCH");
    },
    async del<T>(): Promise<T> {
      throw new Error("unexpected DELETE");
    },
  };
  return { api, bodies };
}

const INPUT = {
  inviteToken: "tok",
  email: "a@b.c",
  masterPassword: "pw",
  deviceLabel: "test",
};

beforeEach(() => {
  localStorage.clear();
  blobs.length = 0;
});

describe("enroll", () => {
  it("sends params as the pinned constant, byte for byte", async () => {
    const { api, bodies } = recordingApi();

    await enroll({ api, session: createSession() }, INPUT);

    const body = bodies.get("/api/enroll") as EnrolBody;
    // The server rejects anything not byte-equal (Plan 2b Task 6). A
    // JSON.stringify here happens to produce the right bytes today only because
    // the object literal is declared in that key order — one reordering away
    // from a 400 nobody can explain.
    expect(body.params).toBe(DEFAULT_KDF_PARAMS_JSON);
    // recoveryKdfParams is pinned the same way now: POST
    // /api/auth/recover/prelogin returns it and answers an unknown address with
    // this exact string, so an account recording anything else would be
    // distinguishable from a decoy. The server rejects a divergent value with
    // 400 (internal/store/enroll.go's validate).
    expect(body.recoveryKdfParams).toBe(DEFAULT_KDF_PARAMS_JSON);
  }, 60_000);

  it("produces a recovery code that actually opens the vault", async () => {
    const { api, bodies } = recordingApi();
    const session = createSession();

    const { recoveryCode } = await enroll({ api, session }, INPUT);
    const body = bodies.get("/api/enroll") as EnrolBody;

    // The recovery code matters on exactly one day: the day the master password
    // is gone. A blob that does not open is a promise this product cannot keep,
    // and nothing else would discover it until then.
    const recovered = await recoverUserKey(
      body.recoveryProtectedUserKey,
      recoveryCode,
      fromBase64(body.recoverySalt),
      JSON.parse(body.recoveryKdfParams) as never,
    );
    expect(Array.from(recovered)).toEqual(
      Array.from(session.getKeys().userKey),
    );
  }, 60_000);

  it("uploads the auth hash a redeeming client recomputes from the code and salt", async () => {
    const { api, bodies } = recordingApi();

    const { recoveryCode } = await enroll({ api, session: createSession() }, INPUT);
    const body = bodies.get("/api/enroll") as EnrolBody;

    // Recomputed here from the code and the two values the server keeps —
    // exactly what POST /api/recover/prelogin hands a different device months
    // later. Reading body.recoveryAuthHash back out and comparing it to itself
    // would pass against a field of zeros, a field of the wrong key half, or a
    // field derived under the wrong params: it asserts nothing at all.
    const recoveryKey = await deriveRecoveryKey(
      recoveryCode,
      fromBase64(body.recoverySalt),
      JSON.parse(body.recoveryKdfParams) as KdfParams,
    );
    expect(body.recoveryAuthHash).toBe(toBase64(deriveRecoveryAuthHash(recoveryKey)));
  }, 120_000);

  it("clears the auth hash buffer once it has been encoded, not before", async () => {
    const { api, bodies } = recordingApi();

    await enroll({ api, session: createSession() }, INPUT);
    const body = bodies.get("/api/enroll") as EnrolBody;

    // Order is the whole assertion. Zeroizing before toBase64 would upload a
    // field of zeros and lock the account out of recovery, and a test that
    // only checked the buffer was blank afterwards would call that a pass.
    const uploaded = fromBase64(body.recoveryAuthHash);
    expect(uploaded.some((byte) => byte !== 0)).toBe(true);
    expect(blobs.at(-1)?.recoveryAuthHash).toEqual(new Uint8Array(uploaded.length));
  }, 120_000);

  it("never sends the recovery code to any endpoint, grouped or stripped", async () => {
    const { api, bodies } = recordingApi();

    const { recoveryCode } = await enroll({ api, session: createSession() }, INPUT);

    // Array.from, not the Map: JSON.stringify of a Map is "{}", so the two
    // not.toContain assertions below would hold against literally anything.
    const serialized = JSON.stringify(Array.from(bodies.values()));
    // Proof the haystack is the real payload before asserting on absence.
    expect(serialized).toContain("recoveryAuthHash");
    // The server never sees the code — that is the whole design (spec §3.6).
    // Both forms: grouped as generated, and hyphen-stripped as
    // normalizeCrockford produces, since a leak that split the code across
    // fields at a hyphen boundary would read as a match for one and not the
    // other.
    expect(serialized).not.toContain(recoveryCode);
    expect(serialized).not.toContain(recoveryCode.replace(/-/gu, ""));
  }, 120_000);

  it("never uploads the user key or the private key", async () => {
    const { api, bodies } = recordingApi();
    const session = createSession();

    await enroll({ api, session }, INPUT);

    const dump = JSON.stringify(bodies.get("/api/enroll"));
    const keys = session.getKeys();
    // Uploading either would hand the server the ability to decrypt everything,
    // which is the one thing this whole design exists to prevent.
    expect(dump).not.toContain(Array.from(keys.userKey).join(","));
    expect(dump).not.toContain(Array.from(keys.privateKey).join(","));
    // The CSV form above is a raw decimal join that nothing in this codebase
    // actually produces. Every key-shaped field in this request body is base64
    // text (wrapKey/toBase64), and a plain JSON.stringify of a Uint8Array
    // serialises as an index-keyed object ({"0":12,"1":45,...}) — neither of
    // which the CSV check would catch. Check both realistic leak forms too.
    expect(dump).not.toContain(toBase64(keys.userKey));
    expect(dump).not.toContain(toBase64(keys.privateKey));
    expect(dump).not.toContain(JSON.stringify(keys.userKey));
    expect(dump).not.toContain(JSON.stringify(keys.privateKey));
  }, 60_000);

  it("leaves the vault unlocked without a second password prompt", async () => {
    const { api } = recordingApi();
    const session = createSession();

    await enroll({ api, session }, INPUT);

    // enrollUser already returned the authHash, so the follow-up login needs no
    // prelogin and no second Argon2id pass. Asking someone to log in again
    // moments after setting a password would be a self-inflicted wound.
    expect(session.isUnlocked).toBe(true);
    expect(session.getAccessToken()).toBe("access");
  }, 60_000);

  it("still returns the recovery code when the follow-up login fails", async () => {
    // Regression: POST /api/enroll/:token has already returned 200 here — the
    // invite is consumed and the account exists — but POST /api/auth/login
    // (a network blip, a 5xx) fails right after. The old code awaited that
    // login unconditionally and let its rejection propagate, destroying the
    // recovery code identically to the App.tsx-level bug one layer up: the
    // code is unrecoverable afterwards, by anyone, so losing it here is just
    // as fatal as losing it there.
    const { api: base } = recordingApi();
    const api: typeof base = {
      ...base,
      async post<T>(path: string, body?: unknown): Promise<T> {
        if (path === "/api/auth/login") {
          throw new Error("network blip");
        }
        return base.post<T>(path, body);
      },
    };
    const session = createSession();

    const outcome = await enroll({ api, session }, INPUT);

    expect(outcome.recoveryCode).toBeTruthy();
    expect(outcome.loggedIn).toBe(false);
    // The account exists but this session never opened — a real unlock is
    // still required, and must not be skipped silently.
    expect(session.isUnlocked).toBe(false);
  }, 60_000);
});
