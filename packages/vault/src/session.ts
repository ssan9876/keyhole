import { zeroize } from "@keyhole/crypto";

/**
 * The only module in this application that retains key material.
 *
 * Everything else receives what it needs as an argument and does not hold it.
 * That is deliberate and load-bearing: design spec 6.3 makes "decrypted keys in
 * memory only" a code-review gate, and a gate is only checkable if there is one
 * place to look. This module has no serializer, no storage call of any kind,
 * and nothing that could reach one.
 */

export interface SessionTokens {
  accessToken: string;
  refreshToken: string;
}

export interface SessionUser {
  id: string;
  email: string;
  name: string;
  role: string;
}

export interface Session {
  readonly isUnlocked: boolean;
  readonly user: SessionUser | null;
  getAccessToken(): string | null;
  getRefreshToken(): string | null;
  getKeys(): { userKey: Uint8Array; privateKey: Uint8Array };
  /** The key for one collection, or null when this client holds none — either
   *  because the user is not a member or because the sealed blob would not
   *  open. Callers must handle null; an item in that collection is simply
   *  unreadable here, which is not an error worth throwing over. */
  getCollectionKey(collectionId: string): Uint8Array | null;
  /** The ids of every collection this session currently holds a key for. Used
   *  by collection creation to preserve the rest of the keyring while adding
   *  the newly created one, without exposing the key material itself. */
  collectionIds(): string[];
  /**
   * Replaces the whole keyring, zeroizing every key the new map does not
   * carry over.
   *
   * Whole-map replacement rather than per-key insertion because that is the
   * shape of the truth: /api/sync sends the full collection list every time
   * (internal/store/sync.go:17), so a revoked membership is expressed by
   * absence. Merging would keep a revoked collection's key alive in memory
   * indefinitely with nothing to ever remove it.
   */
  setCollectionKeys(next: Map<string, Uint8Array>): void;
  open(input: {
    tokens: SessionTokens;
    user: SessionUser;
    userKey: Uint8Array;
    privateKey: Uint8Array;
  }): void;
  replaceTokens(tokens: SessionTokens): void;
  lock(): void;
  subscribe(listener: () => void): () => void;
}

export function createSession(): Session {
  let tokens: SessionTokens | null = null;
  let user: SessionUser | null = null;
  let userKey: Uint8Array | null = null;
  let privateKey: Uint8Array | null = null;
  let collectionKeys = new Map<string, Uint8Array>();
  const listeners = new Set<() => void>();

  const notify = (): void => {
    for (const listener of listeners) listener();
  };

  return {
    get isUnlocked() {
      return userKey !== null && privateKey !== null;
    },
    get user() {
      return user;
    },
    getAccessToken() {
      return tokens?.accessToken ?? null;
    },
    getRefreshToken() {
      return tokens?.refreshToken ?? null;
    },
    getKeys() {
      if (userKey === null || privateKey === null) {
        // Throwing beats returning null: a caller that forgot to check would
        // otherwise encrypt with `undefined` and produce a blob nothing can
        // ever open, which surfaces months later as an unreadable item.
        throw new Error("The vault is locked");
      }
      return { userKey, privateKey };
    },
    getCollectionKey(collectionId) {
      return collectionKeys.get(collectionId) ?? null;
    },
    collectionIds() {
      return [...collectionKeys.keys()];
    },
    setCollectionKeys(next) {
      // Identity, not equality: adoptCollections reuses the existing Uint8Array
      // for an unchanged collection, and zeroizing a buffer the new map still
      // points at would silently blank a live key.
      for (const [id, key] of collectionKeys) {
        if (next.get(id) !== key) zeroize(key);
      }
      collectionKeys = next;
    },
    open(input) {
      // Zeroize whatever this session already held. Reachable in ordinary use:
      // enrol-then-login opens twice, and any future re-authentication would
      // too. Without this, the first unlock's keys stay live in the heap for
      // the life of the tab with no reference left to clear them.
      zeroize(userKey, privateKey, ...collectionKeys.values());
      collectionKeys = new Map();

      tokens = input.tokens;
      user = input.user;
      userKey = input.userKey;
      privateKey = input.privateKey;
      notify();
    },
    replaceTokens(next) {
      tokens = next;
    },
    lock() {
      zeroize(userKey, privateKey, ...collectionKeys.values());
      collectionKeys = new Map();
      userKey = null;
      privateKey = null;
      tokens = null;
      user = null;
      notify();
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
}
