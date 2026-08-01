import type { ApiClient } from "../api.js";
import { createSession, type Session } from "../session.js";

/**
 * Shared test fixtures for src/vault/**.test.ts.
 *
 * Pulled out after the third near-identical `fakeApi`/`openSession` pair
 * turned up across these files — two of them shadowing an outer helper of
 * the same name with a different signature. A stub reused verbatim is
 * something a reader can trust at a glance; four almost-but-not-quite copies
 * is something they have to diff.
 */

interface FakeApiOptions {
  get?: (path: string) => Promise<unknown>;
  post?: (path: string, body?: unknown) => Promise<unknown>;
  put?: (path: string, body?: unknown) => Promise<unknown>;
  patch?: (path: string, body?: unknown) => Promise<unknown>;
  del?: (path: string) => Promise<unknown>;
}

/**
 * A stub `ApiClient` that answers only the HTTP methods a test wires up via
 * `options`; every other method throws with the path, so a call the test
 * didn't expect fails loudly at that call site instead of returning
 * `undefined` and failing confusingly somewhere downstream.
 */
export function fakeApi(options: FakeApiOptions = {}): ApiClient {
  return {
    async get<T>(path: string): Promise<T> {
      if (options.get) return (await options.get(path)) as T;
      throw new Error(`unexpected GET ${path}`);
    },
    async post<T>(path: string, body?: unknown): Promise<T> {
      if (options.post) return (await options.post(path, body)) as T;
      throw new Error(`unexpected POST ${path}`);
    },
    async put<T>(path: string, body?: unknown): Promise<T> {
      if (options.put) return (await options.put(path, body)) as T;
      throw new Error(`unexpected PUT ${path}`);
    },
    async patch<T>(path: string, body?: unknown): Promise<T> {
      if (options.patch) return (await options.patch(path, body)) as T;
      throw new Error(`unexpected PATCH ${path}`);
    },
    async del<T>(path: string): Promise<T> {
      if (options.del) return (await options.del(path)) as T;
      throw new Error(`unexpected DELETE ${path}`);
    },
  };
}

/**
 * An unlocked session with a real-sized (32-byte) key pair, for tests that
 * need a genuine X25519 private key so `sealToUser`/`adoptCollections` can
 * actually open something — most callers don't care what the private key is
 * and can omit it; collections.test.ts and store.test.ts pass a real
 * generated key so a collection key sealed to it will open.
 *
 * A fresh Uint8Array is created on every call (including for the default
 * private key): `session.lock()` zeroizes the arrays it was opened with in
 * place, so a helper that handed out a shared module-level array would let
 * one test's lock() blank the key out from under every other test that
 * called this helper.
 */
export function openSession(privateKey: Uint8Array = new Uint8Array(32).fill(2)): Session {
  const session = createSession();
  session.open({
    tokens: { accessToken: "a", refreshToken: "r" },
    user: { id: "u1", email: "a@example.com", name: "A", role: "user" },
    userKey: new Uint8Array(32).fill(1),
    privateKey,
  });
  return session;
}

/**
 * An unlocked session parameterised on the user key, with filler tokens/user
 * and a zeroed 32-byte private key — for tests exercising personal-item
 * encryption where the private key itself is never used.
 */
export function sessionWithUserKey(userKey: Uint8Array): Session {
  const session = createSession();
  session.open({
    tokens: { accessToken: "a", refreshToken: "r" },
    user: { id: "u1", email: "a@b.c", name: "A", role: "user" },
    userKey,
    privateKey: new Uint8Array(32),
  });
  return session;
}

/**
 * Like `openSession`, but with the collection keyring pre-populated — for
 * tests that only care about collection-item encryption/decryption, not
 * adoption of a sealed collection key.
 */
export function sessionWithCollectionKeys(collectionKeys: Map<string, Uint8Array>): Session {
  const session = openSession();
  session.setCollectionKeys(collectionKeys);
  return session;
}
