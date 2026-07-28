import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
// Brief defect fix: the brief's example imports `LoginItem` straight from
// "@keyhole/crypto". eslint.config.js bans that import from anywhere under
// src/ui/** (no-restricted-imports, the mechanised form of design spec 6.3's
// "decrypted keys stay out of the UI layer" gate) and the rule fires on
// type-only imports too, so this test file would fail lint exactly like the
// implementation would. Routing through vault/types.js — a one-line
// re-export — satisfies the gate without weakening it.
import type { LoginItem } from "../../vault/types.js";
import { ApiError, type ApiClient } from "../../vault/api.js";
import { createSession, type Session } from "../../vault/session.js";
import { createVaultStore, type VaultState, type VaultStore } from "../../vault/store.js";
import { createItem, decryptRecords, type ItemRecord, type WireItem } from "../../vault/items.js";
import { fakeApi, openSession } from "../../vault/test-helpers.js";
import { VaultList, VaultScreen } from "./VaultScreen.js";

// Wraps the real createItem so "saves a new item into the collection chosen
// in the editor" can assert on the exact arguments VaultScreen passed it --
// the collectionId is the whole point of that test, and only a spy on the
// real function (not a hand-rolled fake api body inspection) matches the
// brief's own assertion shape. Every other test in this file still gets the
// real encryption behaviour: the mock delegates to it, it only adds
// observability.
vi.mock("../../vault/items.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../vault/items.js")>();
  return { ...actual, createItem: vi.fn(actual.createItem) };
});

const LOGIN: LoginItem = {
  type: "login",
  name: "Example",
  username: "person@example.com",
  password: "hunter2",
  urls: [],
  notes: "",
  favorite: false,
  folderId: null,
  passwordHistory: [],
};

function record(overrides: Partial<ItemRecord> = {}): ItemRecord {
  return {
    id: "i1",
    revision: 1,
    collectionId: null,
    deletedAt: null,
    plaintext: LOGIN,
    ...overrides,
  };
}

describe("VaultList", () => {
  it("lists item names and usernames", () => {
    render(<VaultList items={[record()]} onSelect={vi.fn()} onNew={vi.fn()} />);
    expect(screen.getByText("Example")).toBeInTheDocument();
    expect(screen.getByText("person@example.com")).toBeInTheDocument();
  });

  it("never renders a password in the list", () => {
    render(<VaultList items={[record()]} onSelect={vi.fn()} onNew={vi.fn()} />);
    // A shoulder-surfable list defeats the point of a vault. Passwords appear
    // only in the editor, behind a reveal.
    expect(screen.queryByText("hunter2")).not.toBeInTheDocument();
  });

  it("shows an undecryptable row as broken rather than hiding it", () => {
    render(
      <VaultList items={[record({ id: "bad", plaintext: null })]} onSelect={vi.fn()} onNew={vi.fn()} />,
    );
    // Hiding it would be worse: the user would believe an item they created is
    // gone, with nothing anywhere saying otherwise.
    expect(screen.getByText(/couldn.t decrypt/i)).toBeInTheDocument();
  });

  it("filters as the user types", async () => {
    render(
      <VaultList
        items={[record(), record({ id: "i2", plaintext: { ...LOGIN, name: "Bank" } })]}
        onSelect={vi.fn()}
        onNew={vi.fn()}
      />,
    );
    await userEvent.type(screen.getByLabelText(/search/i), "ban");
    expect(screen.getByText("Bank")).toBeInTheDocument();
    expect(screen.queryByText("Example")).not.toBeInTheDocument();
  });

  it("offers an empty state that explains what to do", () => {
    render(<VaultList items={[]} onSelect={vi.fn()} onNew={vi.fn()} />);
    expect(screen.getByRole("button", { name: /add.*item/i })).toBeInTheDocument();
  });
});

/**
 * Produces a real, decryptable WireItem under `session`'s own key, by driving
 * it through the vault layer's own createItem rather than importing
 * "@keyhole/crypto" here (banned under src/ui/**, per the comment above).
 * createItem's api.post is stubbed to simply echo back whatever ciphertext
 * and wrappedItemKey it just encrypted, plus the wire metadata this test
 * cares about.
 */
async function wireFor(
  session: Session,
  plaintext: LoginItem,
  meta: { id: string; revision: number },
  collectionId: string | null = null,
): Promise<WireItem> {
  const captured: { body?: { ciphertext: string; wrappedItemKey: string } } = {};
  const capture: ApiClient = {
    async get<T>(): Promise<T> {
      throw new Error("unexpected GET");
    },
    async post<T>(_path: string, body?: unknown): Promise<T> {
      captured.body = body as { ciphertext: string; wrappedItemKey: string };
      return { id: meta.id, revision: meta.revision } as T;
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
  await createItem({ api: capture, session }, plaintext, collectionId);
  const sent = captured.body;
  if (sent === undefined) throw new Error("createItem never posted a body");
  return {
    id: meta.id,
    collectionId,
    ownerUserId: "u1",
    ciphertext: sent.ciphertext,
    wrappedItemKey: sent.wrappedItemKey,
    revision: meta.revision,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    deletedAt: null,
  };
}

describe("VaultScreen", () => {
  it("lets a retried Save succeed after a conflict, by adopting the server's revision", async () => {
    // Regression for the finding: ItemEditor already rendered the conflict
    // message, but VaultScreen never updated `editing.revision`, so every
    // subsequent Save re-conflicted against the same stale revision forever.
    // Cancel (losing the edit) or a reload were the only exits. This drives
    // the real VaultScreen -- not just ItemEditor in isolation -- so it fails
    // if that revision is never adopted, even though the conflict message
    // alone would still look fine.
    const session = createSession();
    session.open({
      tokens: { accessToken: "a", refreshToken: "r" },
      user: { id: "u1", email: "a@b.c", name: "A", role: "user" },
      userKey: new Uint8Array(32),
      privateKey: new Uint8Array(32),
    });

    const original = await wireFor(session, LOGIN, { id: "i1", revision: 1 });
    const winner = await wireFor(
      session,
      { ...LOGIN, name: "Changed on another device" },
      { id: "i1", revision: 5 },
    );

    let putCalls = 0;
    const api: ApiClient = {
      async get<T>(path: string): Promise<T> {
        if (path === "/api/sync") {
          return { revision: 1, items: [original] } as T;
        }
        throw new Error(`unexpected GET ${path}`);
      },
      async post<T>(): Promise<T> {
        throw new Error("unexpected POST");
      },
      async put<T>(path: string, body: unknown): Promise<T> {
        putCalls += 1;
        if (putCalls === 1) {
          // The stale revision (1) still in flight: the server has already
          // moved on to revision 5.
          throw new ApiError("conflict", 409, "changed", {
            error: { code: "conflict", message: "changed" },
            item: winner,
          });
        }
        // A second Save must carry the revision VaultScreen adopted from the
        // conflict, not the original stale one -- this is the assertion the
        // whole test exists to make.
        const sent = body as { ciphertext: string; wrappedItemKey: string; revision: number };
        expect(sent.revision).toBe(winner.revision);
        return {
          ...winner,
          revision: winner.revision + 1,
          ciphertext: sent.ciphertext,
          wrappedItemKey: sent.wrappedItemKey,
        } as T;
      },
      async patch<T>(): Promise<T> {
        throw new Error("unexpected PATCH");
      },
      async del<T>(): Promise<T> {
        throw new Error("unexpected DEL");
      },
    };

    const store = createVaultStore();
    await store.load({ api, session });

    render(<VaultScreen api={api} session={session} store={store} />);

    await userEvent.click(screen.getByText("Example"));
    await userEvent.clear(screen.getByLabelText(/^name/i));
    await userEvent.type(screen.getByLabelText(/^name/i), "Renamed");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/changed on the server/i);
    });

    // The user's edit is still right there; Save again with no other action.
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    await waitFor(() => {
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    });
    expect(putCalls).toBe(2);
  });
});

/**
 * A `VaultStore` that serves a fixed, caller-supplied `VaultState` and treats
 * every mutating method as a no-op.
 *
 * The real store's `load`/`resync` route collection metadata through
 * `adoptCollections`, which opens each sealed key via `openSealed` -- real
 * X25519 sealing, which needs `@keyhole/crypto` to set up (banned under
 * src/ui/**). A `CollectionSummary` itself carries no ciphertext, so there is
 * nothing to open here: this fake lets a test hand VaultScreen collection
 * metadata directly, exactly as if a real sync had already resolved it.
 */
function fakeStore(state: VaultState): VaultStore {
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

describe("VaultScreen collections", () => {
  it("shows a shared badge on an item that belongs to a collection", async () => {
    const session = openSession();
    session.setCollectionKeys(new Map([["c1", new Uint8Array(32).fill(9)]]));

    const shared = await wireFor(session, { ...LOGIN, name: "Household login" }, { id: "i1", revision: 1 }, "c1");
    const personal = await wireFor(session, { ...LOGIN, name: "Personal login" }, { id: "i2", revision: 1 });
    const [sharedRecord, personalRecord] = await decryptRecords([shared, personal], session);

    const store = fakeStore({
      revision: 1,
      items: [sharedRecord as ItemRecord, personalRecord as ItemRecord],
      collections: [{ id: "c1", name: "Household", role: "member", usable: true }],
      status: "ready",
      error: null,
    });

    render(<VaultScreen api={fakeApi()} session={session} store={store} />);

    expect(await screen.findByText("Household login")).toBeInTheDocument();
    // Anchored to the start: the badge text is "Shared · Household", and
    // anchoring rules out a false match against the item's own name (which
    // also happens to contain "Household") or the personal item's row.
    const badge = screen.getByText(/^shared/i);
    expect(badge).toHaveTextContent("Household");
    // The personal item must never carry the badge.
    const personalRow = screen.getByText("Personal login").closest("button");
    expect(personalRow).not.toHaveTextContent(/^shared/i);
  });

  it("filters the list to one collection when that collection is selected", async () => {
    const session = openSession();
    session.setCollectionKeys(new Map([["c1", new Uint8Array(32).fill(9)]]));

    const shared = await wireFor(session, { ...LOGIN, name: "Household login" }, { id: "i1", revision: 1 }, "c1");
    const personal = await wireFor(session, { ...LOGIN, name: "Personal login" }, { id: "i2", revision: 1 });
    const [sharedRecord, personalRecord] = await decryptRecords([shared, personal], session);

    const store = fakeStore({
      revision: 1,
      items: [sharedRecord as ItemRecord, personalRecord as ItemRecord],
      collections: [{ id: "c1", name: "Household", role: "member", usable: true }],
      status: "ready",
      error: null,
    });

    render(<VaultScreen api={fakeApi()} session={session} store={store} />);

    expect(screen.getByText("Household login")).toBeInTheDocument();
    expect(screen.getByText("Personal login")).toBeInTheDocument();

    await userEvent.selectOptions(screen.getByLabelText(/filter by collection/i), "c1");

    expect(screen.getByText("Household login")).toBeInTheDocument();
    expect(screen.queryByText("Personal login")).not.toBeInTheDocument();
  });

  it("does not render the admin tab for a non-admin session", () => {
    const session = openSession(); // role "user", per test-helpers.ts
    const store = fakeStore({ revision: 0, items: [], collections: [], status: "ready", error: null });

    render(<VaultScreen api={fakeApi()} session={session} store={store} />);

    expect(screen.queryByRole("button", { name: "Admin" })).not.toBeInTheDocument();
  });

  it("saves a new item into the collection chosen in the editor", async () => {
    const session = openSession();
    session.setCollectionKeys(new Map([["c1", new Uint8Array(32).fill(9)]]));

    const store = fakeStore({
      revision: 1,
      items: [],
      collections: [{ id: "c1", name: "Household", role: "manager", usable: true }],
      status: "ready",
      error: null,
    });

    const api: ApiClient = {
      async get<T>(path: string): Promise<T> {
        throw new Error(`unexpected GET ${path}`);
      },
      async post<T>(_path: string, body?: unknown): Promise<T> {
        const sent = body as { collectionId: string | null; ciphertext: string; wrappedItemKey: string };
        return {
          id: "i9",
          collectionId: sent.collectionId,
          ownerUserId: "u1",
          ciphertext: sent.ciphertext,
          wrappedItemKey: sent.wrappedItemKey,
          revision: 1,
          createdAt: "2026-01-01T00:00:00Z",
          updatedAt: "2026-01-01T00:00:00Z",
          deletedAt: null,
        } as T;
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

    render(<VaultScreen api={api} session={session} store={store} />);

    await userEvent.click(screen.getByRole("button", { name: /add.*item/i }));
    await userEvent.type(screen.getByLabelText(/^name/i), "New login");
    await userEvent.selectOptions(screen.getByLabelText(/^collection$/i), "c1");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    // The assertion is on the collectionId reaching createItem, not on the
    // control's appearance: a picker that renders and passes null shares
    // nothing.
    await waitFor(() => {
      expect(createItem).toHaveBeenCalledWith(expect.anything(), expect.anything(), "c1");
    });
  });

  it("warns that moving a shared item out of its collection does not revoke access", async () => {
    const session = openSession();
    session.setCollectionKeys(new Map([["c1", new Uint8Array(32).fill(9)]]));

    const shared = await wireFor(session, LOGIN, { id: "i1", revision: 1 }, "c1");
    const [sharedRecord] = await decryptRecords([shared], session);

    const store = fakeStore({
      revision: 1,
      items: [sharedRecord as ItemRecord],
      collections: [{ id: "c1", name: "Household", role: "manager", usable: true }],
      status: "ready",
      error: null,
    });

    render(<VaultScreen api={fakeApi()} session={session} store={store} />);

    await userEvent.click(screen.getByText(LOGIN.name));
    // Nothing shown yet: the picker still matches the item's own collection.
    expect(screen.queryByText(/does not take back access/i)).not.toBeInTheDocument();

    await userEvent.selectOptions(screen.getByLabelText(/^collection$/i), "");

    // The exact copy from packages/crypto/src/item.ts:149, verbatim.
    expect(
      screen.getByText(
        "Moving this out does not take back access. A former member who kept the item key " +
          "can still read it, including future edits.",
      ),
    ).toBeInTheDocument();
  });
});
