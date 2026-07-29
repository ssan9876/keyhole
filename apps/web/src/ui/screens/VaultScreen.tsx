import { useCallback, useEffect, useId, useMemo, useState } from "react";
// Brief defect fix: routed through vault/types.js rather than
// "@keyhole/crypto" directly — see the comment in ItemEditor.tsx for why.
import type { ItemPlaintext, LoginItem } from "../../vault/types.js";
import type { ApiClient } from "../../vault/api.js";
import type { Session } from "../../vault/session.js";
import type { VaultStore } from "../../vault/store.js";
import {
  ItemConflictError,
  createItem,
  decryptRecords,
  deleteItem,
  updateItem,
  type ItemRecord,
} from "../../vault/items.js";
import type { CollectionSummary } from "../../vault/collections.js";
import { DEFAULT_AUTO_LOCK, type AutoLockSetting } from "../../vault/autolock.js";
import { Button } from "../components/Button.js";
import { Field } from "../components/Field.js";
import { TabNav } from "../components/TabNav.js";
import { useVaultState } from "../useVault.js";
import { useCollectionsPanel } from "../useCollectionsPanel.js";
import { useSettingsPanel } from "../useSettingsPanel.js";
import { useAdminPanel } from "../useAdminPanel.js";
import { useImportPanel } from "../useImportPanel.js";
import { ItemEditor } from "./ItemEditor.js";
import { CollectionsScreen } from "./CollectionsScreen.js";
import { SettingsScreen } from "./SettingsScreen.js";
import { AdminScreen } from "./AdminScreen.js";
import { ImportScreen } from "./ImportScreen.js";

export type Tab = "vault" | "collections" | "import" | "settings" | "admin";

const BLANK_LOGIN: LoginItem = {
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

/**
 * The plaintext of an existing record, never a default.
 *
 * A record with `plaintext === null` must never reach `ItemEditor` -- see the
 * guard in `onSelect` below, which redirects it to the undecryptable-item
 * explanation instead of ever calling `setEditing` on it. `BLANK_LOGIN`
 * exists only for the `editing === "new"` case; sharing it here as a `??`
 * fallback is exactly the bug this function replaces: it used to hand a
 * member an empty form for an item they could not decrypt, and whatever they
 * saved into it silently replaced the real (still-encrypted, still
 * shared-with-everyone-else) ciphertext. If this is ever reached, that
 * invariant has already broken, so it throws instead of quietly reopening
 * the hole.
 */
function requirePlaintext(record: ItemRecord): ItemPlaintext {
  if (record.plaintext === null) {
    throw new Error("Cannot edit an item this device could not decrypt");
  }
  return record.plaintext;
}

interface VaultListProps {
  items: ItemRecord[];
  /** Used only to resolve a collectionId to a name for the "Shared" badge and
   *  to populate the filter dropdown -- an empty default keeps every existing
   *  caller (and test) that never mentions collections unaffected. */
  collections?: CollectionSummary[];
  onSelect(record: ItemRecord): void;
  onNew(): void;
}

export function VaultList({ items, collections = [], onSelect, onNew }: VaultListProps) {
  const [query, setQuery] = useState("");
  const [collectionFilter, setCollectionFilter] = useState("");
  const filterId = useId();

  const nameById = useMemo(
    () => new Map(collections.map((collection) => [collection.id, collection.name])),
    [collections],
  );

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return items.filter((item) => {
      if (collectionFilter === "personal" && item.collectionId !== null) return false;
      if (
        collectionFilter !== "" &&
        collectionFilter !== "personal" &&
        item.collectionId !== collectionFilter
      ) {
        return false;
      }
      if (needle.length === 0) return true;
      const name = item.plaintext?.name ?? "";
      const username =
        item.plaintext !== null && item.plaintext.type === "login"
          ? item.plaintext.username
          : "";
      return (
        name.toLowerCase().includes(needle) || username.toLowerCase().includes(needle)
      );
    });
  }, [items, query, collectionFilter]);

  return (
    <section>
      <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "end" }}>
        <div style={{ flex: 1 }}>
          <Field
            label="Search"
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <Button type="button" onClick={onNew}>
          Add an item
        </Button>
      </div>

      {collections.length > 0 && (
        <div style={{ display: "grid", gap: "var(--space-1)", marginBottom: "var(--space-4)" }}>
          <label htmlFor={filterId} style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
            Filter by collection
          </label>
          <select
            id={filterId}
            value={collectionFilter}
            onChange={(e) => setCollectionFilter(e.target.value)}
          >
            <option value="">All items</option>
            <option value="personal">Personal</option>
            {collections.map((collection) => (
              <option key={collection.id} value={collection.id}>
                {collection.name}
              </option>
            ))}
          </select>
        </div>
      )}

      {filtered.length === 0 ? (
        <p style={{ color: "var(--ink-muted)" }}>
          {items.length === 0 ? "Your vault is empty." : "Nothing matches that search."}
        </p>
      ) : (
        <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
          {filtered.map((item) => (
            <li key={item.id} style={{ borderTop: "1px solid var(--rule)" }}>
              <button
                type="button"
                onClick={() => onSelect(item)}
                style={{
                  font: "inherit",
                  width: "100%",
                  textAlign: "left",
                  background: "transparent",
                  border: "none",
                  color: "var(--ink)",
                  padding: "var(--space-3) 0",
                  cursor: "pointer",
                }}
              >
                {/* A row that failed to decrypt is shown, not hidden: the user
                    would otherwise believe an item they created is gone, with
                    nothing anywhere saying otherwise. */}
                {item.plaintext === null ? (
                  <span style={{ color: "var(--danger)" }}>
                    Couldn&rsquo;t decrypt this item
                  </span>
                ) : (
                  <>
                    <span style={{ display: "block" }}>{item.plaintext.name}</span>
                    {item.plaintext.type === "login" && (
                      <span style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
                        {item.plaintext.username}
                      </span>
                    )}
                    {item.collectionId !== null && (
                      <span style={{ color: "var(--ink-muted)", fontSize: "0.75rem", display: "block" }}>
                        Shared &middot; {nameById.get(item.collectionId) ?? "Unknown collection"}
                      </span>
                    )}
                  </>
                )}
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

const TABS: { id: Tab; label: string }[] = [
  { id: "vault", label: "Vault" },
  { id: "collections", label: "Collections" },
  { id: "import", label: "Import" },
  { id: "settings", label: "Settings" },
  { id: "admin", label: "Admin" },
];

export function VaultScreen({
  api,
  session,
  store,
  autoLock = DEFAULT_AUTO_LOCK,
  onAutoLockChange = () => undefined,
}: {
  api: ApiClient;
  session: Session;
  store: VaultStore;
  /** Optional so every existing caller (and test) that never mentions
   *  auto-lock is unaffected -- mirrors VaultList's `collections = []`
   *  default above. App.tsx is the only real caller that supplies these. */
  autoLock?: AutoLockSetting;
  onAutoLockChange?(setting: AutoLockSetting): void;
}) {
  const state = useVaultState(store);
  const [editing, setEditing] = useState<ItemRecord | "new" | null>(null);
  // Set instead of opening the editor when a clicked row's plaintext is
  // null: this device could not decrypt it (an unreadable collection key,
  // a corrupt blob), and ItemEditor must never open on nothing. Cleared
  // whenever the vault list is shown again.
  const [undecryptable, setUndecryptable] = useState<ItemRecord | null>(null);
  // The server's winning copy after a 409, decrypted for display. Cleared
  // whenever the editor is opened afresh, so a stale conflict from a
  // previous item can never bleed into the next one.
  const [conflict, setConflict] = useState<ItemPlaintext | null>(null);
  // The collection chosen in the editor's picker. Starts at the item's
  // current collection (null for a new item / a personal one) and only
  // diverges from it when the user actually changes the selection.
  const [editorCollectionId, setEditorCollectionId] = useState<string | null>(null);
  const collectionSelectId = useId();
  // The folder chosen in the editor's picker. Unlike the collection, this is
  // part of the item's own plaintext (`ItemPlaintext.folderId`), so `save`
  // writes it onto the body rather than passing it as a separate argument.
  // Starts at the item's current folderId -- which may name a folder that is
  // undecryptable, or one that was deleted and is no longer in state at all;
  // both are handled where the picker renders and where save normalises it.
  const [editorFolderId, setEditorFolderId] = useState<string | null>(null);
  const folderSelectId = useId();

  const [activeTab, setActiveTab] = useState<Tab>("vault");

  const isAdmin = session.user?.role === "admin";
  const tabs = TABS.filter((tab) => tab.id !== "admin" || isAdmin);

  const collectionsPanel = useCollectionsPanel({
    api,
    session,
    store,
    active: activeTab === "collections",
  });

  const settingsPanel = useSettingsPanel({
    api,
    session,
    store,
    active: activeTab === "settings",
    autoLock,
    onAutoLockChange,
  });

  // isAdmin folded into `active` itself, not just into whether the tab is
  // drawn: a stale activeTab === "admin" surviving a role change must not
  // keep this hook's lazy load armed for a session that is no longer an
  // admin's. Still only a UI courtesy -- requireAdmin on the server is the
  // real boundary, same note as the tab filter below.
  const adminPanel = useAdminPanel({
    api,
    active: activeTab === "admin" && isAdmin,
  });

  const importPanel = useImportPanel({ api, session, store });

  // Re-sync on focus rather than a timer: it catches the realistic case — you
  // edited on your phone, you come back to this tab — with no polling, no
  // battery cost, and no timer to leak.
  useEffect(() => {
    const onFocus = (): void => {
      void store.resync({ api, session }).catch(() => undefined);
    };
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [api, session, store]);

  const save = useCallback(
    async (next: ItemPlaintext): Promise<void> => {
      // The picker's selection wins over whatever folderId the plaintext
      // carried in. An id naming a folder no longer in state (its folder was
      // deleted) is reconciled to Personal here rather than persisted as a
      // dangling reference -- the orphan rule, applied on write. An
      // undecryptable folder is still in state, so its id is kept.
      const folderId =
        editorFolderId !== null && state.folders.some((folder) => folder.id === editorFolderId)
          ? editorFolderId
          : null;
      const withFolder: ItemPlaintext = { ...next, folderId };
      if (editing === "new") {
        store.upsert(await createItem({ api, session }, withFolder, editorCollectionId));
        setEditing(null);
        setConflict(null);
        return;
      }
      if (editing === null) return;
      try {
        const updated = await updateItem(
          { api, session },
          {
            id: editing.id,
            revision: editing.revision,
            collectionId: editorCollectionId,
            plaintext: withFolder,
          },
        );
        store.upsert(updated);
        setEditing(null);
        setConflict(null);
      } catch (error) {
        if (error instanceof ItemConflictError) {
          // Adopt the winning revision so a retried Save applies on top of
          // it instead of conflicting forever -- Cancel or a reload were
          // otherwise the only exits. ItemEditor's own form state (what the
          // user typed) is untouched by this, so their edit is still right
          // there to resubmit.
          const [serverRecord] = await decryptRecords([error.current], session);
          setEditing({ ...editing, revision: error.current.revision });
          setConflict(serverRecord?.plaintext ?? null);
        }
        throw error;
      }
    },
    [api, editing, editorCollectionId, editorFolderId, session, state.folders, store],
  );

  const remove = useCallback(async (): Promise<void> => {
    if (editing === null || editing === "new") return;
    await deleteItem({ api, session }, editing.id);
    store.remove(editing.id);
    setEditing(null);
    setConflict(null);
  }, [api, editing, session, store]);

  const usableCollections = state.collections.filter((c) => c.usable);
  // Only a decryptable folder is an assignable option -- an undecryptable one
  // has no name to show in a list you would pick from.
  const assignableFolders = state.folders.filter((folder) => folder.name !== null);
  // The item's current assignment, if that folder is still in state at all.
  // A deleted folder is absent from state (tombstoned out), so this is null
  // for the orphan case and the select falls back to Personal below.
  const currentFolder =
    editorFolderId === null
      ? null
      : (state.folders.find((folder) => folder.id === editorFolderId) ?? null);
  // The current assignment names a folder still on the server whose name would
  // not decrypt here. It is shown as a disabled option so the id is visibly
  // retained rather than silently reset to Personal.
  const currentFolderUndecryptable = currentFolder !== null && currentFolder.name === null;
  // A value with no matching option (a deleted folder's id) would leave the
  // select showing nothing; resolving it to "" shows Personal instead.
  const folderSelectValue = currentFolder !== null ? (editorFolderId ?? "") : "";
  // Moving a shared item is only a genuine "move out" when it started in a
  // collection and the picker's selection has actually diverged from that --
  // not on every render, and not for a brand-new item, which never had
  // members to lose access.
  const isMovingOut =
    editing !== null &&
    editing !== "new" &&
    editing.collectionId !== null &&
    editorCollectionId !== editing.collectionId;

  return (
    <main style={{ maxWidth: "40rem", margin: "0 auto", padding: "var(--space-4)" }}>
      <header
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "baseline",
          borderBottom: "1px solid var(--rule-strong)",
          paddingBottom: "var(--space-2)",
          marginBottom: "var(--space-4)",
        }}
      >
        <h1 style={{ fontSize: "1.125rem", fontWeight: 600, margin: 0 }}>Keyhole</h1>
        <Button
          type="button"
          variant="quiet"
          onClick={() => {
            store.clear();
            session.lock();
          }}
        >
          Lock
        </Button>
      </header>

      {/* Admin is folded into `tabs` via the .filter() above rather than
          special-cased here, so there is exactly one place a tab button is
          rendered. It is still a UI courtesy, not the security boundary:
          requireAdmin on the server is what actually protects admin-only
          endpoints. Hiding this button only spares a non-admin the dead end
          of clicking into a screen that would fail every request. */}
      <TabNav tabs={tabs} active={activeTab} onSelect={(id) => setActiveTab(id)} />

      {state.status === "error" && (
        <p role="alert" style={{ color: "var(--danger)" }}>
          {state.error}
        </p>
      )}

      {activeTab === "vault" &&
        (undecryptable !== null ? (
          <div>
            <p role="alert" style={{ color: "var(--danger)" }}>
              This item is in a collection this device can&rsquo;t open. Ask a member of that
              collection to grant you access again.
            </p>
            <Button type="button" variant="quiet" onClick={() => setUndecryptable(null)}>
              Back
            </Button>
          </div>
        ) : editing === null ? (
          <VaultList
            items={state.items}
            collections={state.collections}
            onSelect={(record) => {
              // An undecryptable record must never reach ItemEditor -- see
              // requirePlaintext's comment. This is the one place that
              // invariant is enforced: every other read of `editing` in this
              // component trusts it.
              if (record.plaintext === null) {
                setUndecryptable(record);
                return;
              }
              setEditing(record);
              setEditorCollectionId(record.collectionId);
              // record.plaintext is non-null here (the guard above returned
              // for the null case), so its folderId seeds the picker.
              setEditorFolderId(record.plaintext.folderId);
              setConflict(null);
            }}
            onNew={() => {
              setEditing("new");
              setEditorCollectionId(null);
              setEditorFolderId(null);
              setConflict(null);
            }}
          />
        ) : (
          <>
            <div style={{ display: "grid", gap: "var(--space-1)", marginBottom: "var(--space-4)" }}>
              <label htmlFor={collectionSelectId} style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
                Collection
              </label>
              <select
                id={collectionSelectId}
                value={editorCollectionId ?? ""}
                onChange={(e) => setEditorCollectionId(e.target.value === "" ? null : e.target.value)}
              >
                <option value="">Personal</option>
                {usableCollections.map((collection) => (
                  <option key={collection.id} value={collection.id}>
                    {collection.name}
                  </option>
                ))}
              </select>
            </div>
            <div style={{ display: "grid", gap: "var(--space-1)", marginBottom: "var(--space-4)" }}>
              <label htmlFor={folderSelectId} style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
                Folder
              </label>
              <select
                id={folderSelectId}
                value={folderSelectValue}
                onChange={(e) => setEditorFolderId(e.target.value === "" ? null : e.target.value)}
              >
                <option value="">Personal</option>
                {assignableFolders.map((folder) => (
                  <option key={folder.id} value={folder.id}>
                    {folder.name}
                  </option>
                ))}
                {/* The item is already in a folder whose name will not decrypt
                    here: shown, disabled, so the assignment is visible and kept
                    rather than silently reset. */}
                {currentFolderUndecryptable && (
                  <option value={editorFolderId ?? ""} disabled>
                    Couldn&rsquo;t decrypt this folder
                  </option>
                )}
              </select>
            </div>
            {isMovingOut && (
              <p style={{ color: "var(--danger)", marginBottom: "var(--space-4)" }}>
                Moving this out does not take back access. A former member who kept the item key
                can still read it, including future edits.
              </p>
            )}
            <ItemEditor
              initial={editing === "new" ? BLANK_LOGIN : requirePlaintext(editing)}
              conflict={conflict}
              onSave={save}
              onCancel={() => {
                setEditing(null);
                setConflict(null);
              }}
            />
            {editing !== "new" && (
              <Button type="button" variant="danger" onClick={() => void remove()}>
                Delete this item
              </Button>
            )}
          </>
        ))}

      {activeTab === "collections" && <CollectionsScreen {...collectionsPanel} />}

      {activeTab === "import" && <ImportScreen {...importPanel} />}

      {activeTab === "settings" && <SettingsScreen {...settingsPanel} />}

      {activeTab === "admin" && isAdmin && <AdminScreen {...adminPanel} />}
    </main>
  );
}
