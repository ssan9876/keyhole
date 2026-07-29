import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { FolderRecord } from "../../vault/folders.js";
import { FolderSidebar } from "./FolderSidebar.js";

function folder(overrides: Partial<FolderRecord> = {}): FolderRecord {
  return { id: "f1", revision: 1, deletedAt: null, name: "Work", ...overrides };
}

// Shared handler spies. Call history is cleared before each test; the resolved
// values set here survive clearAllMocks (which resets calls, not implementation).
const handlers = {
  onSelect: vi.fn(),
  onCreateFolder: vi.fn().mockResolvedValue(undefined),
  onRenameFolder: vi.fn().mockResolvedValue(undefined),
  onDeleteFolder: vi.fn().mockResolvedValue(undefined),
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("FolderSidebar", () => {
  it("creates a folder with the typed name", async () => {
    render(<FolderSidebar folders={[]} selected="" {...handlers} />);

    // Exact label string: "New folder name" must not be reachable by a query
    // meant for "Rename folder" or the vault's "Search" -- the collision that
    // has shipped here twice.
    await userEvent.type(screen.getByLabelText("New folder name"), "Travel");
    await userEvent.click(screen.getByRole("button", { name: "Add folder" }));

    expect(handlers.onCreateFolder).toHaveBeenCalledWith("Travel");
  });

  it("renames a folder to the typed name, with the rename field not colliding with create", async () => {
    render(<FolderSidebar folders={[folder()]} selected="" {...handlers} />);

    await userEvent.click(screen.getByRole("button", { name: "Rename" }));

    // Both labelled fields are in the DOM at once here; exact strings keep them
    // apart. A regex like /folder/i would match both and throw.
    expect(screen.getByLabelText("New folder name")).toBeInTheDocument();
    const field = screen.getByLabelText("Rename folder");
    await userEvent.clear(field);
    await userEvent.type(field, "Projects");
    await userEvent.click(screen.getByRole("button", { name: "Save name" }));

    expect(handlers.onRenameFolder).toHaveBeenCalledWith(
      expect.objectContaining({ id: "f1" }),
      "Projects",
    );
  });

  it("states in the delete confirmation that the folder's items are kept", async () => {
    render(<FolderSidebar folders={[folder()]} selected="" {...handlers} />);

    await userEvent.click(screen.getByRole("button", { name: "Delete" }));

    const dialog = screen.getByRole("alertdialog");
    // The load-bearing truth: the server tombstones the folder and never
    // touches its items (internal/store/folders.go:169).
    expect(within(dialog).getByText(/does not delete the items/i)).toBeInTheDocument();
  });

  it("deletes the folder once the deletion is confirmed", async () => {
    render(<FolderSidebar folders={[folder()]} selected="" {...handlers} />);

    await userEvent.click(screen.getByRole("button", { name: "Delete" }));
    await userEvent.click(screen.getByRole("button", { name: "Delete folder" }));

    expect(handlers.onDeleteFolder).toHaveBeenCalledWith(expect.objectContaining({ id: "f1" }));
  });

  it("shows an undecryptable folder, labelled, rather than hiding it", () => {
    render(<FolderSidebar folders={[folder({ id: "fUnd", name: null })]} selected="" {...handlers} />);

    expect(screen.getByText(/couldn.t decrypt this folder/i)).toBeInTheDocument();
  });
});
