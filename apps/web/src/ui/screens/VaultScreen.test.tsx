import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
// Brief defect fix: the brief's example imports `LoginItem` straight from
// "@keyhole/crypto". eslint.config.js bans that import from anywhere under
// src/ui/** (no-restricted-imports, the mechanised form of design spec 6.3's
// "decrypted keys stay out of the UI layer" gate) and the rule fires on
// type-only imports too, so this test file would fail lint exactly like the
// implementation would. Routing through vault/types.js — a one-line
// re-export — satisfies the gate without weakening it.
import type { LoginItem } from "../../vault/types.js";
import type { ItemRecord } from "../../vault/items.js";
import { VaultList } from "./VaultScreen.js";

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
