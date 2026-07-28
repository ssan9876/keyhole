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
import { createVaultStore } from "../../vault/store.js";
import { createItem, type ItemRecord, type WireItem } from "../../vault/items.js";
import { VaultList, VaultScreen } from "./VaultScreen.js";

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
  await createItem({ api: capture, session }, plaintext, null);
  const sent = captured.body;
  if (sent === undefined) throw new Error("createItem never posted a body");
  return {
    id: meta.id,
    collectionId: null,
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
