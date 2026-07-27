import { beforeEach, describe, expect, it } from "vitest";
import { toBase64 } from "@keyhole/crypto";
import {
  EMAIL_STORAGE_KEY,
  createSession,
  forgetEmail,
  rememberEmail,
  rememberedEmail,
} from "./session.js";
import { openSession } from "./test-helpers.js";

const USER = { id: "u1", email: "a@b.c", name: "A", role: "user" };
const TOKENS = { accessToken: "access", refreshToken: "refresh" };

/**
 * Trivial fixed keys, not the shared `openSession` helper's real-sized ones:
 * these tests exercise the session's own open/lock/subscribe/storage
 * behaviour, not anything that has to survive a real crypto operation.
 */
function openBasicSession() {
  const session = createSession();
  session.open({
    tokens: TOKENS,
    user: USER,
    userKey: new Uint8Array([1, 2, 3, 4]),
    privateKey: new Uint8Array([5, 6, 7, 8]),
  });
  return session;
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
});

describe("session", () => {
  it("is locked before open and unlocked after", () => {
    const session = createSession();
    expect(session.isUnlocked).toBe(false);
    expect(session.getAccessToken()).toBeNull();
    expect(() => session.getKeys()).toThrow();

    session.open({
      tokens: TOKENS,
      user: USER,
      userKey: new Uint8Array(4),
      privateKey: new Uint8Array(4),
    });
    expect(session.isUnlocked).toBe(true);
    expect(session.getAccessToken()).toBe("access");
    expect(session.user).toEqual(USER);
  });

  it("zeroizes the key material on lock", () => {
    const userKey = new Uint8Array([1, 2, 3, 4]);
    const privateKey = new Uint8Array([5, 6, 7, 8]);
    const session = createSession();
    session.open({ tokens: TOKENS, user: USER, userKey, privateKey });

    session.lock();

    // The caller's arrays are the same objects the session holds, so this
    // asserts the bytes are actually gone from memory rather than merely
    // dereferenced and left for the garbage collector to maybe reclaim.
    expect(Array.from(userKey)).toEqual([0, 0, 0, 0]);
    expect(Array.from(privateKey)).toEqual([0, 0, 0, 0]);
    expect(session.isUnlocked).toBe(false);
    expect(session.getAccessToken()).toBeNull();
    expect(() => session.getKeys()).toThrow();
  });

  it("writes nothing but the email to storage, ever", () => {
    const session = openBasicSession();
    rememberEmail("a@b.c");

    // Build the dump from the raw stored strings rather than re-encoding
    // them. localStorage/sessionStorage values are already strings, so
    // running the whole thing through JSON.stringify again would add a
    // second encoding layer: a leak written as `JSON.stringify(userKey)`
    // (producing the literal text `{"0":1,"1":2,...}`) would have its
    // quotes escaped by the outer JSON.stringify, so it would never match
    // an unescaped `JSON.stringify(...)` needle below. Concatenating the
    // raw key/value pairs keeps the dump byte-for-byte what is actually in
    // storage, so a substring check means something.
    //
    // The separators below are derived from numeric character codes rather
    // than typed as literal characters: this codebase's file-write path has
    // been seen to silently mangle literal characters that recur within a
    // file (see the keyhole-file-write-normalization note), which would make
    // this dump quietly stop reflecting the real stored bytes. Deriving them
    // at runtime from distinct numeric codes sidesteps that entirely.
    const fieldSep = String.fromCharCode(30); // ASCII record separator
    const entrySep = String.fromCharCode(31); // ASCII unit separator
    const dumpStorage = (storage: Storage): string => {
      const parts: string[] = [];
      for (let i = 0; i < storage.length; i++) {
        const key = storage.key(i);
        if (key === null) continue;
        parts.push(key + fieldSep + (storage.getItem(key) ?? ""));
      }
      return parts.join(entrySep);
    };
    const dump =
      dumpStorage(localStorage) + entrySep + dumpStorage(sessionStorage);

    // Design spec 6.3, stated as a code-review gate: no key material and no
    // plaintext outside memory. A stringified dump catches a value written
    // under any key, which an assertion on known keys would not.
    //
    // The raw decimal CSV forms ("1,2,3,4") are what a naive `.join(",")` would
    // produce, but nothing in this codebase serialises keys that way: they
    // would actually reach storage as base64 text, or as the index-keyed
    // object form a plain `JSON.stringify` of a Uint8Array produces
    // ({"0":1,"1":2,...}). Check both realistic leak forms alongside the CSV.
    for (const forbidden of [
      "access",
      "refresh",
      "1,2,3,4",
      "5,6,7,8",
      toBase64(new Uint8Array([1, 2, 3, 4])),
      toBase64(new Uint8Array([5, 6, 7, 8])),
      JSON.stringify(new Uint8Array([1, 2, 3, 4])),
      JSON.stringify(new Uint8Array([5, 6, 7, 8])),
    ]) {
      expect(dump).not.toContain(forbidden);
    }
    expect(Object.keys(localStorage)).toEqual([EMAIL_STORAGE_KEY]);
    expect(Object.keys(sessionStorage)).toHaveLength(0);
    session.lock();
  });

  it("survives a remembered email across a fresh session", () => {
    rememberEmail("person@example.com");
    expect(rememberedEmail()).toBe("person@example.com");
    forgetEmail();
    expect(rememberedEmail()).toBeNull();
  });

  it("notifies subscribers on open and lock, and stops after unsubscribe", () => {
    const session = createSession();
    let calls = 0;
    const unsubscribe = session.subscribe(() => {
      calls += 1;
    });

    session.open({
      tokens: TOKENS,
      user: USER,
      userKey: new Uint8Array(4),
      privateKey: new Uint8Array(4),
    });
    expect(calls).toBe(1);

    session.lock();
    expect(calls).toBe(2);

    unsubscribe();
    session.open({
      tokens: TOKENS,
      user: USER,
      userKey: new Uint8Array(4),
      privateKey: new Uint8Array(4),
    });
    expect(calls).toBe(2);
  });

  it("replaces tokens without disturbing the keys", () => {
    const session = openBasicSession();
    const before = session.getKeys();

    session.replaceTokens({ accessToken: "fresh", refreshToken: "fresh-r" });

    expect(session.getAccessToken()).toBe("fresh");
    // A token refresh must not cost the user their unlocked vault.
    expect(session.getKeys().userKey).toBe(before.userKey);
    expect(session.isUnlocked).toBe(true);
  });

  it("is safe to lock twice", () => {
    const session = openBasicSession();
    session.lock();
    expect(() => session.lock()).not.toThrow();
  });
});

describe("collection keyring", () => {
  it("returns a collection key that was set, and null for one that was not", () => {
    const session = openSession();
    const key = new Uint8Array(32).fill(7);
    session.setCollectionKeys(new Map([["c1", key]]));

    expect(session.getCollectionKey("c1")).toBe(key);
    expect(session.getCollectionKey("c2")).toBeNull();
  });

  it("zeroizes a collection key that the replacement map drops", () => {
    const session = openSession();
    const revoked = new Uint8Array(32).fill(7);
    const kept = new Uint8Array(32).fill(9);
    session.setCollectionKeys(new Map([["c1", revoked], ["c2", kept]]));

    // A membership revoked server-side simply stops appearing in /api/sync.
    session.setCollectionKeys(new Map([["c2", kept]]));

    expect(revoked.every((byte) => byte === 0)).toBe(true);
    expect(kept.every((byte) => byte === 9)).toBe(true);
    expect(session.getCollectionKey("c1")).toBeNull();
  });

  it("does not zeroize a key the replacement map carries over by identity", () => {
    const session = openSession();
    const key = new Uint8Array(32).fill(7);
    session.setCollectionKeys(new Map([["c1", key]]));
    session.setCollectionKeys(new Map([["c1", key]]));

    expect(key.every((byte) => byte === 7)).toBe(true);
  });

  it("zeroizes a superseded key when the same collection id gets a different buffer", () => {
    const session = openSession();
    const superseded = new Uint8Array(32).fill(7);
    session.setCollectionKeys(new Map([["c1", superseded]]));

    // What a re-grant looks like: the same collection, a freshly opened key.
    const replacement = new Uint8Array(32).fill(9);
    session.setCollectionKeys(new Map([["c1", replacement]]));

    expect(superseded.every((byte) => byte === 0)).toBe(true);
    expect(replacement.every((byte) => byte === 9)).toBe(true);
    expect(session.getCollectionKey("c1")).toBe(replacement);
  });

  it("zeroizes every collection key on lock", () => {
    const session = openSession();
    const first = new Uint8Array(32).fill(7);
    const second = new Uint8Array(32).fill(8);
    session.setCollectionKeys(new Map([["c1", first], ["c2", second]]));

    session.lock();

    expect(first.every((byte) => byte === 0)).toBe(true);
    expect(second.every((byte) => byte === 0)).toBe(true);
    expect(session.getCollectionKey("c1")).toBeNull();
  });

  it("zeroizes the keys of a previous session when open() is called again", () => {
    const session = openSession();
    const stale = new Uint8Array(32).fill(7);
    session.setCollectionKeys(new Map([["c1", stale]]));
    const staleUserKey = session.getKeys().userKey;

    session.open({
      tokens: { accessToken: "a2", refreshToken: "r2" },
      user: { id: "u2", email: "b@example.com", name: "B", role: "user" },
      userKey: new Uint8Array(32).fill(3),
      privateKey: new Uint8Array(32).fill(4),
    });

    expect(stale.every((byte) => byte === 0)).toBe(true);
    expect(staleUserKey.every((byte) => byte === 0)).toBe(true);
    expect(session.getCollectionKey("c1")).toBeNull();
  });
});
