import { describe, expect, it, vi } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";
import {
  createCollection,
  type ApiClient,
  type VaultState,
  type VaultStore,
  type PendingGrant,
  type DirectoryEntry,
} from "@keyhole/vault";
import { openSession } from "../../../../packages/vault/src/test-helpers.js";
import { useCollectionsPanel } from "./useCollectionsPanel.js";

// The round trip this test exists to prove: handleCreateCollection has no
// public key of its own, so it must fetch the caller's own profile via
// loadAccount first and hand *that* publicKey to createCollection. Before
// this hook existed, that wiring lived inline in VaultScreen and was
// untestable without mounting the whole screen (self-flagged in the task-10
// report's Concerns section). createCollection is mocked out entirely here
// -- this test is about the argument that reaches it, not about real sealing,
// which collections.test.ts already covers with a real key pair.
vi.mock("@keyhole/vault", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@keyhole/vault")>();
  return {
    ...actual,
    createCollection: vi
      .fn()
      .mockResolvedValue({ id: "c9", name: "Household", role: "manager", usable: true }),
  };
});

function fakeStore(): VaultStore {
  const state: VaultState = { revision: 0, items: [], folders: [], collections: [], status: "ready", error: null };
  return {
    getState: () => state,
    subscribe: () => () => undefined,
    async load() {},
    async resync() {},
    upsert() {},
    remove() {},
    clear() {},
  };
}

describe("useCollectionsPanel", () => {
  it("supplies the caller's own public key from loadAccount to createCollection", async () => {
    const session = openSession();
    const store = fakeStore();
    const api: ApiClient = {
      async get<T>(path: string): Promise<T> {
        if (path === "/api/account") {
          return {
            id: "u1",
            email: "a@example.com",
            name: "A",
            role: "user",
            publicKey: "own-public-key-b64",
            createdAt: "2026-01-01T00:00:00Z",
          } as T;
        }
        throw new Error(`unexpected GET ${path}`);
      },
      async post<T>(): Promise<T> {
        throw new Error("unexpected POST");
      },
      async put<T>(): Promise<T> {
        throw new Error("unexpected PUT");
      },
      async patch<T>(): Promise<T> {
        throw new Error("unexpected PATCH");
      },
      async del<T>(): Promise<T> {
        throw new Error("unexpected DEL");
      },
    };

    // active: false -- this test is only about handleCreateCollection, not
    // the lazy directory/pending-grants load, and a passive tab keeps the
    // fixture's api stub from also having to answer those two GETs.
    const { result } = renderHook(() =>
      useCollectionsPanel({ api, session, store, active: false }),
    );

    await act(async () => {
      await result.current.onCreateCollection("Household");
    });

    expect(createCollection).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ name: "Household", ownPublicKey: "own-public-key-b64" }),
    );
  });

  it("refreshes members after fulfilling a grant for the collection currently open", async () => {
    // Finding 3b: handleAddMember already refreshed members when the added
    // member's collection matched the one selected; handleFulfil did not,
    // so a manager who fulfilled a grant for the collection they were
    // looking at saw a stale Members panel until they collapsed and
    // reopened it.
    const session = openSession();
    session.setCollectionKeys(new Map([["c1", new Uint8Array(32).fill(9)]]));
    const store = fakeStore();

    let membersCalls = 0;
    const api: ApiClient = {
      async get<T>(path: string): Promise<T> {
        if (path === "/api/collections/c1/members") {
          membersCalls += 1;
          const members =
            membersCalls === 1
              ? []
              : [
                  {
                    userId: "u2",
                    name: "Bee",
                    email: "bee@example.com",
                    role: "member",
                    grantedAt: "2026-07-27T00:00:00Z",
                  },
                ];
          return { members } as T;
        }
        throw new Error(`unexpected GET ${path}`);
      },
      async post<T>(path: string): Promise<T> {
        if (path === "/api/collections/c1/grants") return {} as T;
        throw new Error(`unexpected POST ${path}`);
      },
      async put<T>(): Promise<T> {
        throw new Error("unexpected PUT");
      },
      async patch<T>(): Promise<T> {
        throw new Error("unexpected PATCH");
      },
      async del<T>(): Promise<T> {
        throw new Error("unexpected DEL");
      },
    };

    const { result } = renderHook(() =>
      useCollectionsPanel({ api, session, store, active: false }),
    );

    act(() => {
      result.current.onSelectCollection("c1");
    });
    await waitFor(() => expect(membersCalls).toBe(1));

    const grant: PendingGrant = {
      collectionId: "c1",
      collectionName: "Household",
      userId: "u2",
      role: "member",
      requestedBy: "u1",
      createdAt: "2026-07-27T00:00:00Z",
    };
    // A real (if arbitrary) 32-byte X25519 public key -- fulfilGrant is the
    // real vault-layer function here, not mocked, and it really seals to it.
    const recipient: DirectoryEntry = {
      id: "u2",
      name: "Bee",
      email: "bee@example.com",
      publicKey: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
      fingerprint: "x",
    };

    await act(async () => {
      await result.current.onFulfil(grant, recipient);
    });

    expect(result.current.members).toEqual([
      {
        userId: "u2",
        name: "Bee",
        email: "bee@example.com",
        role: "member",
        grantedAt: "2026-07-27T00:00:00Z",
      },
    ]);
  });
});
