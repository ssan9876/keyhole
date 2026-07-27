import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
// Brief defect fix: routed through vault/types.js rather than @keyhole/crypto
// directly — see the comment in VaultScreen.test.tsx for why.
import type { LoginItem } from "../../vault/types.js";
import { ItemEditor } from "./ItemEditor.js";

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

describe("ItemEditor", () => {
  it("masks the password until it is revealed", async () => {
    render(<ItemEditor initial={LOGIN} onSave={vi.fn()} onCancel={vi.fn()} />);

    const field = screen.getByLabelText(/^password/i);
    expect(field).toHaveAttribute("type", "password");
    await userEvent.click(screen.getByRole("button", { name: /reveal|show/i }));
    expect(field).toHaveAttribute("type", "text");
  });

  it("fills the password field from the generator", async () => {
    render(<ItemEditor initial={LOGIN} onSave={vi.fn()} onCancel={vi.fn()} />);

    await userEvent.click(screen.getByRole("button", { name: /generate/i }));

    const field = screen.getByLabelText(/^password/i) as HTMLInputElement;
    expect(field.value).not.toBe("hunter2");
    expect(field.value.length).toBeGreaterThanOrEqual(16);
  });

  it("saves the edited plaintext", async () => {
    const onSave = vi.fn().mockResolvedValue(undefined);
    render(<ItemEditor initial={LOGIN} onSave={onSave} onCancel={vi.fn()} />);

    // Brief defect fix: the brief used `screen.getByLabelText(/name/i)`, which
    // also matches the "Username" field (it contains "name" as a substring)
    // and throws "Found multiple elements" instead of exercising the rename —
    // this is exactly the label-ambiguity trap called out for this task.
    // Anchoring to the start of the label disambiguates it from "Username".
    await userEvent.clear(screen.getByLabelText(/^name/i));
    await userEvent.type(screen.getByLabelText(/^name/i), "Renamed");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    await waitFor(() => {
      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({ type: "login", name: "Renamed" }),
      );
    });
  });

  it("surfaces a conflict with both versions rather than overwriting", async () => {
    const onSave = vi.fn().mockRejectedValue(
      Object.assign(new Error("This item changed on the server since you last synced"), {
        name: "ItemConflictError",
      }),
    );
    render(<ItemEditor initial={LOGIN} onSave={onSave} onCancel={vi.fn()} />);

    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    // Design spec 9: concurrent edits never silently lose data. The server
    // refuses the overwrite precisely so the client can put this choice in
    // front of the person who made the edit.
    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/changed on the server/i);
    });
  });
});
