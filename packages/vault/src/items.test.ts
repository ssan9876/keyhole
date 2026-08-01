import { describe, expect, it } from "vitest";
import {
  decryptItem,
  encryptItem,
  generateCollectionKey,
  generateUserKey,
  type LoginItem,
} from "@keyhole/crypto";
import { ApiError } from "./api.js";
import {
  ItemConflictError,
  createItem,
  decryptRecords,
  updateItem,
  type WireItem,
} from "./items.js";
import { fakeApi, sessionWithCollectionKeys, sessionWithUserKey } from "./testing/test-helpers.js";

const LOGIN: LoginItem = {
  type: "login",
  name: "Example",
  username: "person@example.com",
  password: "hunter2",
  urls: ["https://example.com"],
  notes: "",
  favorite: false,
  folderId: null,
  passwordHistory: [],
};

const BLANK: LoginItem = {
  type: "login",
  name: "",
  username: "",
  password: "",
  urls: [],
  notes: "",
  favorite: false,
  folderId: null,
  passwordHistory: [],
};

function wireItem(overrides: Partial<WireItem> = {}): WireItem {
  return {
    id: "i1",
    collectionId: null,
    ownerUserId: "u1",
    ciphertext: "",
    wrappedItemKey: "",
    revision: 1,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    deletedAt: null,
    ...overrides,
  };
}

describe("decryptRecords", () => {
  it("decrypts what it can", async () => {
    const userKey = generateUserKey();
    const encrypted = await encryptItem(LOGIN, userKey);
    const records = await decryptRecords(
      [wireItem({ ciphertext: encrypted.ciphertext, wrappedItemKey: encrypted.wrappedItemKey })],
      sessionWithUserKey(userKey),
    );

    expect(records).toHaveLength(1);
    expect(records[0]?.plaintext).toEqual(LOGIN);
  });

  it("survives one undecryptable row without failing the vault", async () => {
    const userKey = generateUserKey();
    const good = await encryptItem(LOGIN, userKey);

    const records = await decryptRecords(
      [
        wireItem({ id: "bad", ciphertext: "not-ciphertext", wrappedItemKey: "junk" }),
        wireItem({ id: "good", ciphertext: good.ciphertext, wrappedItemKey: good.wrappedItemKey }),
      ],
      sessionWithUserKey(userKey),
    );

    // One corrupt blob making every password unreachable is a far worse failure
    // than one visibly broken row. The UI renders plaintext === null as
    // "couldn't decrypt" and carries on.
    expect(records).toHaveLength(2);
    expect(records.find((r) => r.id === "bad")?.plaintext).toBeNull();
    expect(records.find((r) => r.id === "good")?.plaintext).toEqual(LOGIN);
  });

  it("skips tombstones rather than trying to decrypt an emptied row", async () => {
    // DeleteItem blanks ciphertext and wrapped_item_key, so a tombstone has
    // nothing to decrypt and must not be reported as a decryption failure.
    const records = await decryptRecords(
      [wireItem({ deletedAt: "2026-01-02T00:00:00Z" })],
      sessionWithUserKey(generateUserKey()),
    );
    expect(records[0]?.plaintext).toBeNull();
    expect(records[0]?.deletedAt).not.toBeNull();
  });
});

describe("createItem and updateItem", () => {
  it("uploads ciphertext and never plaintext", async () => {
    const userKey = generateUserKey();
    let sent: unknown = null;
    const api = fakeApi({
      post: async (_path, body) => {
        sent = body;
        const b = body as { ciphertext: string; wrappedItemKey: string };
        return wireItem({ ciphertext: b.ciphertext, wrappedItemKey: b.wrappedItemKey });
      },
    });

    await createItem({ api, session: sessionWithUserKey(userKey) }, LOGIN, null);

    const dump = JSON.stringify(sent);
    // The server stores an opaque string. If any of these appear, the vault is
    // not end-to-end encrypted and every other guarantee is decoration.
    expect(dump).not.toContain("hunter2");
    expect(dump).not.toContain("person@example.com");
    expect(dump).not.toContain("Example");
  });

  it("raises a typed conflict carrying the winning copy", async () => {
    const userKey = generateUserKey();
    const winner = wireItem({ revision: 9, ciphertext: "theirs" });
    const api = fakeApi({
      put: async () => {
        throw new ApiError("conflict", 409, "changed", {
          error: { code: "conflict", message: "changed" },
          item: winner,
        });
      },
    });

    const error = (await updateItem(
      { api, session: sessionWithUserKey(userKey) },
      { id: "i1", revision: 1, collectionId: null, plaintext: LOGIN },
    ).catch((e: unknown) => e)) as ItemConflictError;

    // Without the winning row the client has nothing to reconcile against and
    // its only option is to discard one of the two edits — the data loss design
    // spec 9 forbids.
    expect(error).toBeInstanceOf(ItemConflictError);
    expect(error.current.revision).toBe(9);
  });
});

describe("collection items", () => {
  const COLLECTION_KEY = generateCollectionKey();
  // Matches the fixed userKey `sessionWithCollectionKeys` opens with, so
  // tests below can encrypt/decrypt directly against it to prove which key a
  // ciphertext actually opens under.
  const USER_KEY = new Uint8Array(32).fill(1);

  it("decrypts a collection item with the collection key, not the user key", async () => {
    const plaintext: LoginItem = { ...BLANK, name: "Shared router" };
    const encrypted = await encryptItem(plaintext, COLLECTION_KEY);
    const session = sessionWithCollectionKeys(new Map([["c1", COLLECTION_KEY]]));

    const [record] = await decryptRecords(
      [wireItem({ id: "i1", collectionId: "c1", ...encrypted })],
      session,
    );

    expect(record?.plaintext?.name).toBe("Shared router");
  });

  it("leaves a collection item unreadable when the session holds no key for it", async () => {
    const encrypted = await encryptItem({ ...BLANK, name: "Shared router" }, COLLECTION_KEY);
    const session = sessionWithCollectionKeys(new Map());

    const [record] = await decryptRecords(
      [wireItem({ id: "i1", collectionId: "c1", ...encrypted })],
      session,
    );

    // Not an exception and not a dropped row: the list shows "couldn't
    // decrypt", which is the honest answer.
    expect(record?.plaintext).toBeNull();
    expect(record?.id).toBe("i1");
  });

  it("still decrypts a personal item with the user key when a keyring is present", async () => {
    const encrypted = await encryptItem({ ...BLANK, name: "Mine" }, USER_KEY);
    const session = sessionWithCollectionKeys(new Map([["c1", COLLECTION_KEY]]));

    const [record] = await decryptRecords(
      [wireItem({ id: "i1", collectionId: null, ...encrypted })],
      session,
    );

    expect(record?.plaintext?.name).toBe("Mine");
  });

  it("encrypts a new collection item under the collection key", async () => {
    const session = sessionWithCollectionKeys(new Map([["c1", COLLECTION_KEY]]));
    type Sent = { ciphertext: string; wrappedItemKey: string; collectionId: string | null };
    let sent: Sent | null = null;
    const api = fakeApi({
      post: async (_path, body) => {
        sent = body as Sent;
        return wireItem({ id: "i1", collectionId: "c1", ...(body as object) });
      },
    });

    await createItem({ api, session }, { ...BLANK, name: "Shared router" }, "c1");

    expect(sent!.collectionId).toBe("c1");
    // The proof that the right parent was used: only the collection key opens it.
    await expect(decryptItem(sent!, COLLECTION_KEY)).resolves.toMatchObject({
      name: "Shared router",
    });
    await expect(decryptItem(sent!, USER_KEY)).rejects.toThrow();
  });

  it("refuses to create an item in a collection this client cannot open", async () => {
    const session = sessionWithCollectionKeys(new Map());
    const api = fakeApi({ post: async () => { throw new Error("must not be called"); } });

    await expect(
      createItem({ api, session }, { ...BLANK, name: "Shared router" }, "c1"),
    ).rejects.toThrow(/cannot open/i);
  });

  it("always sends collectionId on update, so an unchanged shared item is never moved to personal", async () => {
    const session = sessionWithCollectionKeys(new Map([["c1", COLLECTION_KEY]]));
    let sent: Record<string, unknown> | null = null;
    const api = fakeApi({
      put: async (_path, body) => {
        sent = body as Record<string, unknown>;
        return wireItem({ id: "i1", collectionId: "c1" });
      },
    });

    await updateItem(
      { api, session },
      { id: "i1", revision: 4, collectionId: "c1", plaintext: { ...BLANK, name: "Edited" } },
    );

    // The field is present, not merely correct: an omitted collectionId means
    // "no change" to the server, and relying on that is the data-loss trap
    // this signature exists to remove.
    expect(Object.keys(sent!)).toContain("collectionId");
    expect(sent!["collectionId"]).toBe("c1");
  });

  it("re-encrypts under the user key when an item is moved out of a collection", async () => {
    const session = sessionWithCollectionKeys(new Map([["c1", COLLECTION_KEY]]));
    type Sent = { ciphertext: string; wrappedItemKey: string };
    let sent: Sent | null = null;
    const api = fakeApi({
      put: async (_path, body) => {
        sent = body as Sent;
        return wireItem({ id: "i1", collectionId: null });
      },
    });

    await updateItem(
      { api, session },
      { id: "i1", revision: 4, collectionId: null, plaintext: { ...BLANK, name: "Now mine" } },
    );

    await expect(decryptItem(sent!, USER_KEY)).resolves.toMatchObject({ name: "Now mine" });
    await expect(decryptItem(sent!, COLLECTION_KEY)).rejects.toThrow();
  });
});
