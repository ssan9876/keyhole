import { useCallback, useEffect, useMemo, useState } from "react";
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
import { Button } from "../components/Button.js";
import { Field } from "../components/Field.js";
import { useVaultState } from "../useVault.js";
import { ItemEditor } from "./ItemEditor.js";

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

interface VaultListProps {
  items: ItemRecord[];
  onSelect(record: ItemRecord): void;
  onNew(): void;
}

export function VaultList({ items, onSelect, onNew }: VaultListProps) {
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (needle.length === 0) return items;
    return items.filter((item) => {
      const name = item.plaintext?.name ?? "";
      const username =
        item.plaintext !== null && item.plaintext.type === "login"
          ? item.plaintext.username
          : "";
      return (
        name.toLowerCase().includes(needle) || username.toLowerCase().includes(needle)
      );
    });
  }, [items, query]);

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

export function VaultScreen({
  api,
  session,
  store,
}: {
  api: ApiClient;
  session: Session;
  store: VaultStore;
}) {
  const state = useVaultState(store);
  const [editing, setEditing] = useState<ItemRecord | "new" | null>(null);
  // The server's winning copy after a 409, decrypted for display. Cleared
  // whenever the editor is opened afresh, so a stale conflict from a
  // previous item can never bleed into the next one.
  const [conflict, setConflict] = useState<ItemPlaintext | null>(null);

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
      if (editing === "new") {
        store.upsert(await createItem({ api, session }, next));
        setEditing(null);
        setConflict(null);
        return;
      }
      if (editing === null) return;
      try {
        const updated = await updateItem({ api, session }, editing.id, editing.revision, next);
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
          const [serverRecord] = await decryptRecords(
            [error.current],
            session.getKeys().userKey,
          );
          setEditing({ ...editing, revision: error.current.revision });
          setConflict(serverRecord?.plaintext ?? null);
        }
        throw error;
      }
    },
    [api, editing, session, store],
  );

  const remove = useCallback(async (): Promise<void> => {
    if (editing === null || editing === "new") return;
    await deleteItem({ api, session }, editing.id);
    store.remove(editing.id);
    setEditing(null);
    setConflict(null);
  }, [api, editing, session, store]);

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

      {state.status === "error" && (
        <p role="alert" style={{ color: "var(--danger)" }}>
          {state.error}
        </p>
      )}

      {editing === null ? (
        <VaultList
          items={state.items}
          onSelect={(record) => {
            setEditing(record);
            setConflict(null);
          }}
          onNew={() => {
            setEditing("new");
            setConflict(null);
          }}
        />
      ) : (
        <>
          <ItemEditor
            initial={editing === "new" ? BLANK_LOGIN : (editing.plaintext ?? BLANK_LOGIN)}
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
      )}
    </main>
  );
}
