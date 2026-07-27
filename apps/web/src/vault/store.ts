import type { ApiClient } from "./api.js";
import type { Session } from "./session.js";
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
  status: "empty" | "loading" | "ready" | "error";
  error: string | null;
}

interface SyncResponse {
  revision: number;
  items: WireItem[];
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

const EMPTY: VaultState = { revision: 0, items: [], status: "empty", error: null };

export function createVaultStore(): VaultStore {
  let state: VaultState = EMPTY;
  const listeners = new Set<() => void>();

  const set = (next: Partial<VaultState>): void => {
    // A new object every time: useSyncExternalStore compares by identity, and
    // mutating in place would render nothing.
    state = { ...state, ...next };
    for (const listener of listeners) listener();
  };

  const merge = (existing: ItemRecord[], incoming: ItemRecord[]): ItemRecord[] => {
    const byId = new Map(existing.map((item) => [item.id, item]));
    for (const item of incoming) {
      if (item.deletedAt !== null) {
        byId.delete(item.id);
      } else {
        byId.set(item.id, item);
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
      const records = await decryptRecords(
        response.items,
        deps.session.getKeys().userKey,
      );
      set({
        revision: response.revision,
        items: since === null ? merge([], records) : merge(state.items, records),
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
