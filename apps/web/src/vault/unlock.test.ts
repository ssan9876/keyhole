import { beforeEach, describe, expect, it } from "vitest";
import {
  DEFAULT_KDF_PARAMS_JSON,
  enrollUser,
  toBase64,
  type KdfParams,
} from "@keyhole/crypto";
import { ApiError, type ApiClient } from "./api.js";
import { createSession, rememberedEmail } from "./session.js";
import { WrongMasterPasswordError, unlock } from "./unlock.js";

// 16 bytes, the length assertKdfSalt requires.
const SALT_B64 = toBase64(new Uint8Array(16).fill(7));

interface FakeOptions {
  loginThrows?: unknown;
  protectedUserKey?: string;
  encryptedPrivateKey?: string;
  kdfSalt?: string;
  kdfParams?: string;
  loginBodies?: unknown[];
}

function fakeApi(options: FakeOptions = {}): { api: ApiClient; calls: string[] } {
  const calls: string[] = [];
  const api: ApiClient = {
    async get<T>(path: string): Promise<T> {
      throw new Error(`unexpected GET ${path}`);
    },
    async post<T>(path: string, body?: unknown): Promise<T> {
      calls.push(`POST ${path}`);
      if (path === "/api/auth/prelogin") {
        return {
          kdfSalt: options.kdfSalt ?? SALT_B64,
          params: options.kdfParams ?? DEFAULT_KDF_PARAMS_JSON,
        } as T;
      }
      if (path === "/api/auth/login") {
        if (options.loginThrows !== undefined) throw options.loginThrows;
        options.loginBodies?.push(body);
        return {
          accessToken: "access",
          refreshToken: "refresh",
          protectedUserKey: options.protectedUserKey ?? "puk",
          encryptedPrivateKey: options.encryptedPrivateKey ?? "epk",
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
  return { api, calls };
}

beforeEach(() => {
  localStorage.clear();
});

describe("unlock", () => {
  it("prelogins, derives, logs in, and unwraps the enrolled keys", async () => {
    // A round trip against the real crypto. Stubbing it here would leave the
    // one thing worth testing untested: that the key which comes out is the
    // key that went in.
    const enrolled = await enrollUser("correct horse battery staple");
    const { api, calls } = fakeApi({
      protectedUserKey: enrolled.protectedUserKey,
      encryptedPrivateKey: enrolled.encryptedPrivateKey,
      kdfSalt: toBase64(enrolled.kdfSalt),
      kdfParams: JSON.stringify(enrolled.params),
    });
    const session = createSession();

    await unlock(
      { api, session },
      {
        email: "a@b.c",
        masterPassword: "correct horse battery staple",
        deviceLabel: "test",
      },
    );

    expect(calls).toEqual(["POST /api/auth/prelogin", "POST /api/auth/login"]);
    expect(session.isUnlocked).toBe(true);
    expect(session.getAccessToken()).toBe("access");
    expect(Array.from(session.getKeys().userKey)).toEqual(
      Array.from(enrolled.userKey),
    );
  }, 60_000);

  it("sends the auth hash base64-encoded, never as raw bytes", async () => {
    const enrolled = await enrollUser("pw");
    const loginBodies: unknown[] = [];
    const { api } = fakeApi({
      loginBodies,
      protectedUserKey: enrolled.protectedUserKey,
      encryptedPrivateKey: enrolled.encryptedPrivateKey,
      kdfSalt: toBase64(enrolled.kdfSalt),
      kdfParams: JSON.stringify(enrolled.params),
    });

    await unlock(
      { api, session: createSession() },
      { email: "a@b.c", masterPassword: "pw", deviceLabel: "test" },
    );

    // The server hashes whatever string arrives, so enrolment and login only
    // have to agree with each other. That is exactly why a wrong encoding is
    // invisible: a JSON-serialised Uint8Array would authenticate consistently
    // and never be noticed until another client tried to log in.
    const body = loginBodies[0] as { authHash: string };
    expect(typeof body.authHash).toBe("string");
    expect(body.authHash).toMatch(/^[A-Za-z0-9+/]+=*$/);
  }, 60_000);

  it("reports a 401 as a wrong master password", async () => {
    const { api } = fakeApi({
      loginThrows: new ApiError("unauthorized", 401, "invalid credentials", {}),
    });

    // Design spec 9: unlock failure is honestly worded. The server answers a
    // wrong password and an unknown account identically, which is correct —
    // both are the same thing to the person typing.
    await expect(
      unlock(
        { api, session: createSession() },
        { email: "a@b.c", masterPassword: "wrong", deviceLabel: "test" },
      ),
    ).rejects.toBeInstanceOf(WrongMasterPasswordError);
  }, 60_000);

  it("leaves the session locked and the email unremembered when login fails", async () => {
    const { api } = fakeApi({
      loginThrows: new ApiError("unauthorized", 401, "nope", {}),
    });
    const session = createSession();

    await unlock(
      { api, session },
      { email: "typo@example.com", masterPassword: "wrong", deviceLabel: "test" },
    ).catch(() => undefined);

    expect(session.isUnlocked).toBe(false);
    // A failed attempt must not pin a mistyped address into the unlock screen.
    expect(rememberedEmail()).toBeNull();
  }, 60_000);

  it("remembers the email after a successful unlock", async () => {
    const enrolled = await enrollUser("pw");
    const { api } = fakeApi({
      protectedUserKey: enrolled.protectedUserKey,
      encryptedPrivateKey: enrolled.encryptedPrivateKey,
      kdfSalt: toBase64(enrolled.kdfSalt),
      kdfParams: JSON.stringify(enrolled.params),
    });

    await unlock(
      { api, session: createSession() },
      { email: "a@b.c", masterPassword: "pw", deviceLabel: "test" },
    );

    expect(rememberedEmail()).toBe("a@b.c");
  }, 60_000);
});
