import type { ApiClient } from "./api.js";
import type { Session } from "./session.js";
import { adoptCollections, type CollectionSummary, type WireCollection } from "./collections.js";
import { decryptFolders, type FolderRecord, type WireFolder } from "./folders.js";
import { decryptRecords, type ItemRecord, type WireItem } from "./items.js";

/**
 * The in-memory vault for one unlocked session.
 *
 * This is the one module that holds decrypted plaintext, which is a deliberate
 * and bounded concession: a vault list has to render names. Its lifetime is tied
 * to `clear()`, which the UI calls whenever the session locks.
 *
 * Deliberately hand-rolled rather than a state library. TanStack Query's
 * devtools serialise cache contents and its persist plugin writes to storage —
 * the two behaviours design spec 6.3 forbids, shipped as headline features.
 */
export interface VaultState {
  revision: number;
  items: ItemRecord[];
  /** Incremental with tombstones, exactly like `items` and unlike `collections`:
   *  an incremental `/api/sync` sends only the folders that changed since the
   *  cursor, so a wholesale replace would drop every folder it did not mention.
   *  Holds the live (non-tombstone) folders, decryptable or not — an
   *  undecryptable name is carried as `null` rather than hidden. */
  folders: FolderRecord[];
  /** Sent in full on every sync, so this is a replacement rather than a merge:
   *  a revoked membership is expressed by absence (internal/store/sync.go:17). */
  collections: CollectionSummary[];
  status: "empty" | "loading" | "ready" | "error";
  error: string | null;
}

interface SyncResponse {
  revision: number;
  items: WireItem[];
  // Optional, not just in practice but in the type: an older server may omit
  // these fields entirely (both predate the feature that added them), which is
  // exactly what the `?? []` guards in fetchInto exist to handle. Without
  // `| undefined` here, those guards are invisible to the type system and read
  // as dead code.
  folders: WireFolder[] | undefined;
  collections: WireCollection[] | undefined;
}

export interface VaultStore {
  getState(): VaultState;
  subscribe(listener: () => void): () => void;
  load(deps: { api: ApiClient; session: Session }): Promise<void>;
  resync(deps: { api: ApiClient; session: Session }): Promise<void>;
  upsert(record: ItemRecord): void;
  remove(id: string): void;
  clear(): void;
}

const EMPTY: VaultState = {
  revision: 0,
  items: [],
  folders: [],
  collections: [],
  status: "empty",
  error: null,
};

export function createVaultStore(): VaultStore {
  let state: VaultState = EMPTY;
  const listeners = new Set<() => void>();

  const set = (next: Partial<VaultState>): void => {
    // A new object every time: useSyncExternalStore compares by identity, and
    // mutating in place would render nothing.
    state = { ...state, ...next };
    for (const listener of listeners) listener();
  };

  // One merge for items and folders both: they share the same incremental
  // contract — an incremental sync carries only what changed, a tombstone
  // (`deletedAt !== null`) removes a row, and everything absent is left in
  // place. Collections do not go through here; they are replaced wholesale.
  const merge = <T extends { id: string; deletedAt: string | null }>(
    existing: T[],
    incoming: T[],
  ): T[] => {
    const byId = new Map(existing.map((record) => [record.id, record]));
    for (const record of incoming) {
      if (record.deletedAt !== null) {
        byId.delete(record.id);
      } else {
        byId.set(record.id, record);
      }
    }
    return [...byId.values()];
  };

  async function fetchInto(
    deps: { api: ApiClient; session: Session },
    since: number | null,
  ): Promise<void> {
    const path = since === null ? "/api/sync" : `/api/sync?since=${since}`;
    try {
      const response = await deps.api.get<SyncResponse>(path);
      // Before decryptRecords, not after: the items in a collection granted
      // since the last sync arrive in this same response, and they are
      // unreadable until their key is in the session.
      const collections = await adoptCollections(response.collections ?? [], deps.session);
      const records = await decryptRecords(response.items, deps.session);
      // A folder name is symmetric ciphertext under the userKey, just like a
      // personal item body. The store holds the decrypted names — the same
      // bounded plaintext concession it makes for items — but never the key:
      // it reads the userKey out of the session at the point of use and hands
      // it to decryptFolders, which retains nothing.
      const folders = await decryptFolders(response.folders ?? [], deps.session.getKeys().userKey);
      set({
        revision: response.revision,
        items: since === null ? merge([], records) : merge(state.items, records),
        // Merged like items, never replaced like collections: an incremental
        // response omits every unchanged folder, so a replace would drop them.
        folders: since === null ? merge([], folders) : merge(state.folders, folders),
        collections,
        status: "ready",
        error: null,
      });
    } catch (error) {
      set({
        status: "error",
        error: error instanceof Error ? error.message : "Could not sync",
      });
      throw error;
    }
  }

  return {
    getState: () => state,
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    async load(deps) {
      set({ status: "loading", error: null });
      await fetchInto(deps, null);
    },
    async resync(deps) {
      await fetchInto(deps, state.revision);
    },
    upsert(record) {
      set({ items: merge(state.items, [record]), status: "ready" });
    },
    remove(id) {
      set({ items: state.items.filter((item) => item.id !== id) });
    },
    clear() {
      state = EMPTY;
      for (const listener of listeners) listener();
    },
  };
}
