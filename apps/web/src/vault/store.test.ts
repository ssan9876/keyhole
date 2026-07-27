import { describe, expect, it } from "vitest";
import { encryptItem, generateUserKey, type LoginItem } from "@keyhole/crypto";
import type { ApiClient } from "./api.js";
import { createSession } from "./session.js";
import { createVaultStore } from "./store.js";
import type { WireItem } from "./items.js";

const LOGIN: LoginItem = {
  type: "login",
  name: "Example",
  username: "u",
  password: "p",
  urls: [],
  notes: "",
  favorite: false,
  folderId: null,
  passwordHistory: [],
};

function sessionWith(userKey: Uint8Array) {
  const session = createSession();
  session.open({
    tokens: { accessToken: "a", refreshToken: "r" },
    user: { id: "u1", email: "a@b.c", name: "A", role: "user" },
    userKey,
    privateKey: new Uint8Array(32),
  });
  return session;
}

function syncApi(pages: Record<string, unknown>): ApiClient {
  return {
    async get<T>(path: string): Promise<T> {
      const body = pages[path];
      if (body === undefined) throw new Error(`no stub for ${path}`);
      return body as T;
    },
    async post<T>(): Promise<T> {
      throw new Error("unexpected");
    },
    async put<T>(): Promise<T> {
      throw new Error("unexpected");
    },
    async del<T>(): Promise<T> {
      throw new Error("unexpected");
    },
  };
}

/**
 * Like `syncApi`, but each path serves a queue of bodies, one per call, so a
 * test can make the same path (e.g. `/api/sync`) answer differently on a
 * second `.load()` than it did on the first.
 */
function sequencedSyncApi(pages: Record<string, unknown[]>): ApiClient {
  return {
    async get<T>(path: string): Promise<T> {
      const queue = pages[path];
      if (queue === undefined || queue.length === 0) {
        throw new Error(`no stub for ${path}`);
      }
      return queue.shift() as T;
    },
    async post<T>(): Promise<T> {
      throw new Error("unexpected");
    },
    async put<T>(): Promise<T> {
      throw new Error("unexpected");
    },
    async del<T>(): Promise<T> {
      throw new Error("unexpected");
    },
  };
}

describe("vault store", () => {
  it("loads, decrypts, and records the cursor", async () => {
    const userKey = generateUserKey();
    const encrypted = await encryptItem(LOGIN, userKey);
    const item: WireItem = {
      id: "i1",
      collectionId: null,
      ownerUserId: "u1",
      ciphertext: encrypted.ciphertext,
      wrappedItemKey: encrypted.wrappedItemKey,
      revision: 4,
      createdAt: "2026-01-01T00:00:00Z",
      updatedAt: "2026-01-01T00:00:00Z",
      deletedAt: null,
    };
    const api = syncApi({ "/api/sync": { revision: 4, items: [item], folders: [], collections: [] } });
    const store = createVaultStore();

    await store.load({ api, session: sessionWith(userKey) });

    expect(store.getState().status).toBe("ready");
    expect(store.getState().revision).toBe(4);
    expect(store.getState().items[0]?.plaintext).toEqual(LOGIN);
  });

  it("re-syncs from the cursor and drops tombstoned rows", async () => {
    const userKey = generateUserKey();
    const encrypted = await encryptItem(LOGIN, userKey);
    const base: WireItem = {
      id: "i1",
      collectionId: null,
      ownerUserId: "u1",
      ciphertext: encrypted.ciphertext,
      wrappedItemKey: encrypted.wrappedItemKey,
      revision: 4,
      createdAt: "2026-01-01T00:00:00Z",
      updatedAt: "2026-01-01T00:00:00Z",
      deletedAt: null,
    };
    const api = syncApi({
      "/api/sync": { revision: 4, items: [base], folders: [], collections: [] },
      "/api/sync?since=4": {
        revision: 5,
        // The server blanks ciphertext on delete; the tombstone is an id and a
        // revision, which is exactly enough to remove the row here.
        items: [{ ...base, revision: 5, deletedAt: "2026-01-02T00:00:00Z", ciphertext: "", wrappedItemKey: "" }],
        folders: [],
        collections: [],
      },
    });
    const store = createVaultStore();
    const session = sessionWith(userKey);

    await store.load({ api, session });
    expect(store.getState().items).toHaveLength(1);

    await store.resync({ api, session });

    // A delete on another device has to reach this one, or the item lingers
    // forever on a screen its owner believes is empty.
    expect(store.getState().items).toHaveLength(0);
    expect(store.getState().revision).toBe(5);
  });

  it("a full load replaces state wholesale, dropping items absent from the snapshot without a tombstone", async () => {
    const userKey = generateUserKey();
    const encrypted = await encryptItem(LOGIN, userKey);
    const item1: WireItem = {
      id: "i1",
      collectionId: null,
      ownerUserId: "u1",
      ciphertext: encrypted.ciphertext,
      wrappedItemKey: encrypted.wrappedItemKey,
      revision: 4,
      createdAt: "2026-01-01T00:00:00Z",
      updatedAt: "2026-01-01T00:00:00Z",
      deletedAt: null,
    };
    const item2: WireItem = { ...item1, id: "i2" };
    const api = sequencedSyncApi({
      "/api/sync": [
        { revision: 4, items: [item1, item2], folders: [], collections: [] },
        // A second full snapshot that simply omits i2 — no tombstone, no
        // deletedAt. A full `/api/sync` response is authoritative: anything
        // it doesn't list no longer exists server-side. Merging this into the
        // existing state (instead of replacing it) would resurrect i2 forever,
        // since there is no tombstone to ever remove it.
        { revision: 6, items: [item1], folders: [], collections: [] },
      ],
    });
    const store = createVaultStore();
    const session = sessionWith(userKey);

    await store.load({ api, session });
    expect(store.getState().items).toHaveLength(2);

    await store.load({ api, session });

    expect(store.getState().items).toHaveLength(1);
    expect(store.getState().items[0]?.id).toBe("i1");
    expect(store.getState().items.some((item) => item.id === "i2")).toBe(false);
    expect(store.getState().revision).toBe(6);
  });

  it("notifies subscribers and clears on lock", async () => {
    const store = createVaultStore();
    let calls = 0;
    store.subscribe(() => {
      calls += 1;
    });

    store.upsert({ id: "x", revision: 1, collectionId: null, deletedAt: null, plaintext: LOGIN });
    expect(store.getState().items).toHaveLength(1);
    expect(calls).toBeGreaterThan(0);

    store.clear();
    // Plaintext must not outlive the unlocked session — this is the store half
    // of the memory-only rule.
    expect(store.getState().items).toHaveLength(0);
    expect(store.getState().status).toBe("empty");
  });
});
