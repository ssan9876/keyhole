import { useState } from "react";
import type { FormEvent } from "react";
import type { FolderRecord } from "../../vault/folders.js";
import { Button } from "../components/Button.js";
import { Confirm } from "../components/Confirm.js";
import { Field } from "../components/Field.js";
import { describeFailure } from "../errors.js";

export interface FolderSidebarProps {
  folders: FolderRecord[];
  /** The active filter: "" for All items, "personal" for the no-folder /
   *  orphaned bucket, or a folder id. Owned by VaultScreen so the item list
   *  and this sidebar agree on it. */
  selected: string;
  onSelect(value: string): void;
  onCreateFolder(name: string): Promise<void>;
  onRenameFolder(folder: FolderRecord, name: string): Promise<void>;
  onDeleteFolder(folder: FolderRecord): Promise<void>;
}

const UNDECRYPTABLE_LABEL = "Couldn't decrypt this folder";

/** One line: a filter button whose pressed state drives the vault list. */
function FilterButton({
  label,
  value,
  selected,
  onSelect,
}: {
  label: string;
  value: string;
  selected: string;
  onSelect(value: string): void;
}) {
  const isSelected = selected === value;
  return (
    <button
      type="button"
      aria-pressed={isSelected}
      onClick={() => onSelect(value)}
      style={{
        font: "inherit",
        background: "transparent",
        border: "none",
        color: isSelected ? "var(--ink)" : "var(--ink-muted)",
        fontWeight: isSelected ? 600 : 400,
        cursor: "pointer",
        textAlign: "left",
        padding: 0,
      }}
    >
      {label}
    </button>
  );
}

function FolderRow({
  folder,
  selected,
  onSelect,
  onRenameFolder,
  onDelete,
}: {
  folder: FolderRecord;
  selected: string;
  onSelect(value: string): void;
  onRenameFolder(folder: FolderRecord, name: string): Promise<void>;
  onDelete(folder: FolderRecord): void;
}) {
  const [renaming, setRenaming] = useState(false);
  // A folder whose name would not decrypt has no current name to seed the
  // field with -- the user types a fresh one. A decryptable folder starts from
  // its current name.
  const [name, setName] = useState(folder.name ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const label = folder.name ?? UNDECRYPTABLE_LABEL;

  async function submitRename(event: FormEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onRenameFolder(folder, name);
      setRenaming(false);
    } catch (failure) {
      setError(describeFailure(failure, "Could not rename that folder"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <li style={{ borderTop: "1px solid var(--rule)", padding: "var(--space-2) 0" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "var(--space-2)" }}>
        <FilterButton label={label} value={folder.id} selected={selected} onSelect={onSelect} />
        <div style={{ display: "flex", gap: "var(--space-2)" }}>
          <Button type="button" variant="quiet" onClick={() => setRenaming((open) => !open)}>
            Rename
          </Button>
          <Button type="button" variant="quiet" onClick={() => onDelete(folder)}>
            Delete
          </Button>
        </div>
      </div>
      {renaming && (
        <form onSubmit={submitRename} style={{ marginTop: "var(--space-2)" }}>
          <Field
            label="Rename folder"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
          {error !== null && (
            <p role="alert" style={{ color: "var(--danger)" }}>
              {error}
            </p>
          )}
          <Button type="submit" disabled={busy}>
            {busy ? "Saving…" : "Save name"}
          </Button>
        </form>
      )}
    </li>
  );
}

/**
 * The folder sidebar: a filter (All items · Personal · each folder), plus
 * create, rename, and delete.
 *
 * Purely presentational -- every action is a prop, so a test drives it with
 * spies and VaultScreen wires the real handlers from useFoldersPanel. An
 * undecryptable folder is shown, labelled, never hidden, for the same reason an
 * undecryptable item is: a silently missing folder reads as data loss.
 */
export function FolderSidebar({
  folders,
  selected,
  onSelect,
  onCreateFolder,
  onRenameFolder,
  onDeleteFolder,
}: FolderSidebarProps) {
  const [newName, setNewName] = useState("");
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<FolderRecord | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  async function submitCreate(event: FormEvent): Promise<void> {
    event.preventDefault();
    setCreateBusy(true);
    setCreateError(null);
    try {
      await onCreateFolder(newName);
      setNewName("");
    } catch (failure) {
      setCreateError(describeFailure(failure, "Could not create that folder"));
    } finally {
      setCreateBusy(false);
    }
  }

  return (
    <section style={{ marginBottom: "var(--space-4)" }}>
      <h2 style={{ fontSize: "1rem", fontWeight: 600, margin: "0 0 var(--space-2)" }}>Folders</h2>

      <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
        <li style={{ padding: "var(--space-2) 0" }}>
          <FilterButton label="All items" value="" selected={selected} onSelect={onSelect} />
        </li>
        <li style={{ borderTop: "1px solid var(--rule)", padding: "var(--space-2) 0" }}>
          <FilterButton label="Personal" value="personal" selected={selected} onSelect={onSelect} />
        </li>
        {folders.map((folder) => (
          <FolderRow
            key={folder.id}
            folder={folder}
            selected={selected}
            onSelect={onSelect}
            onRenameFolder={onRenameFolder}
            onDelete={(target) => {
              setDeleting(target);
              setDeleteError(null);
            }}
          />
        ))}
      </ul>

      <form onSubmit={submitCreate} style={{ marginTop: "var(--space-3)" }}>
        <Field
          label="New folder name"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          required
        />
        {createError !== null && (
          <p role="alert" style={{ color: "var(--danger)" }}>
            {createError}
          </p>
        )}
        <Button type="submit" disabled={createBusy}>
          {createBusy ? "Adding…" : "Add folder"}
        </Button>
      </form>

      {deleteError !== null && (
        <p role="alert" style={{ color: "var(--danger)" }}>
          {deleteError}
        </p>
      )}

      {deleting !== null && (
        <Confirm
          title={`Delete ${deleting.name ?? "this folder"}?`}
          // True, and the reason it is true: the server tombstones the folder
          // and never touches its items (internal/store/folders.go:169), so the
          // client shows them under Personal afterwards.
          body="Deleting this folder does not delete the items inside it. They stay in your vault and move to Personal."
          confirmLabel="Delete folder"
          onCancel={() => setDeleting(null)}
          onConfirm={() => {
            const target = deleting;
            setDeleting(null);
            setDeleteError(null);
            // The dialog closes at once; a failed request still needs to be
            // surfaced rather than silently swallowed.
            void (async () => {
              try {
                await onDeleteFolder(target);
                // The folder is gone; a filter still pointed at it would leave
                // the list stuck on a bucket the sidebar no longer offers.
                if (selected === target.id) onSelect("");
              } catch (failure) {
                setDeleteError(describeFailure(failure, "Could not delete that folder"));
              }
            })();
          }}
        />
      )}
    </section>
  );
}
