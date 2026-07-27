import { beforeEach, describe, expect, it } from "vitest";
import {
  DEFAULT_KDF_PARAMS_JSON,
  fromBase64,
  recoverUserKey,
} from "@keyhole/crypto";
import type { ApiClient } from "./api.js";
import { createSession } from "./session.js";
import { enroll } from "./enroll.js";

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
});
