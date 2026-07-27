import { describe, expect, it } from "vitest";
import { encryptItem, generateUserKey, type LoginItem } from "@keyhole/crypto";
import { ApiError, type ApiClient } from "./api.js";
import { createSession } from "./session.js";
import {
  ItemConflictError,
  createItem,
  decryptRecords,
  updateItem,
  type WireItem,
} from "./items.js";

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

function wire(overrides: Partial<WireItem> = {}): WireItem {
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

describe("decryptRecords", () => {
  it("decrypts what it can", async () => {
    const userKey = generateUserKey();
    const encrypted = await encryptItem(LOGIN, userKey);
    const records = await decryptRecords(
      [wire({ ciphertext: encrypted.ciphertext, wrappedItemKey: encrypted.wrappedItemKey })],
      userKey,
    );

    expect(records).toHaveLength(1);
    expect(records[0]?.plaintext).toEqual(LOGIN);
  });

  it("survives one undecryptable row without failing the vault", async () => {
    const userKey = generateUserKey();
    const good = await encryptItem(LOGIN, userKey);

    const records = await decryptRecords(
      [
        wire({ id: "bad", ciphertext: "not-ciphertext", wrappedItemKey: "junk" }),
        wire({ id: "good", ciphertext: good.ciphertext, wrappedItemKey: good.wrappedItemKey }),
      ],
      userKey,
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
      [wire({ deletedAt: "2026-01-02T00:00:00Z" })],
      generateUserKey(),
    );
    expect(records[0]?.plaintext).toBeNull();
    expect(records[0]?.deletedAt).not.toBeNull();
  });
});

describe("createItem and updateItem", () => {
  it("uploads ciphertext and never plaintext", async () => {
    const userKey = generateUserKey();
    let sent: unknown = null;
    const api: ApiClient = {
      async get<T>(): Promise<T> {
        throw new Error("unexpected");
      },
      async post<T>(_path: string, body?: unknown): Promise<T> {
        sent = body;
        const b = body as { ciphertext: string; wrappedItemKey: string };
        return wire({ ciphertext: b.ciphertext, wrappedItemKey: b.wrappedItemKey }) as T;
      },
      async put<T>(): Promise<T> {
        throw new Error("unexpected");
      },
      async del<T>(): Promise<T> {
        throw new Error("unexpected");
      },
    };

    await createItem({ api, session: sessionWith(userKey) }, LOGIN);

    const dump = JSON.stringify(sent);
    // The server stores an opaque string. If any of these appear, the vault is
    // not end-to-end encrypted and every other guarantee is decoration.
    expect(dump).not.toContain("hunter2");
    expect(dump).not.toContain("person@example.com");
    expect(dump).not.toContain("Example");
  });

  it("raises a typed conflict carrying the winning copy", async () => {
    const userKey = generateUserKey();
    const winner = wire({ revision: 9, ciphertext: "theirs" });
    const api: ApiClient = {
      async get<T>(): Promise<T> {
        throw new Error("unexpected");
      },
      async post<T>(): Promise<T> {
        throw new Error("unexpected");
      },
      async put<T>(): Promise<T> {
        throw new ApiError("conflict", 409, "changed", {
          error: { code: "conflict", message: "changed" },
          item: winner,
        });
      },
      async del<T>(): Promise<T> {
        throw new Error("unexpected");
      },
    };

    const error = (await updateItem(
      { api, session: sessionWith(userKey) },
      "i1",
      1,
      LOGIN,
    ).catch((e: unknown) => e)) as ItemConflictError;

    // Without the winning row the client has nothing to reconcile against and
    // its only option is to discard one of the two edits — the data loss design
    // spec 9 forbids.
    expect(error).toBeInstanceOf(ItemConflictError);
    expect(error.current.revision).toBe(9);
  });
});
