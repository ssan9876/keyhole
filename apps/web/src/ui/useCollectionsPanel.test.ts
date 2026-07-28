import { describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";
import type { ApiClient } from "../vault/api.js";
import type { VaultState, VaultStore } from "../vault/store.js";
import { openSession } from "../vault/test-helpers.js";
import { createCollection } from "../vault/collections.js";
import { useCollectionsPanel } from "./useCollectionsPanel.js";

// The round trip this test exists to prove: handleCreateCollection has no
// public key of its own, so it must fetch the caller's own profile via
// loadAccount first and hand *that* publicKey to createCollection. Before
// this hook existed, that wiring lived inline in VaultScreen and was
// untestable without mounting the whole screen (self-flagged in the task-10
// report's Concerns section). createCollection is mocked out entirely here
// -- this test is about the argument that reaches it, not about real sealing,
// which collections.test.ts already covers with a real key pair.
vi.mock("../vault/collections.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../vault/collections.js")>();
  return {
    ...actual,
    createCollection: vi
      .fn()
      .mockResolvedValue({ id: "c9", name: "Household", role: "manager", usable: true }),
  };
});

function fakeStore(): VaultStore {
  const state: VaultState = { revision: 0, items: [], collections: [], status: "ready", error: null };
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
});
