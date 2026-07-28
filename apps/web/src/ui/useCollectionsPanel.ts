import { useCallback, useEffect, useState } from "react";
import type { ApiClient } from "../vault/api.js";
import type { Session } from "../vault/session.js";
import type { VaultStore } from "../vault/store.js";
import { loadAccount } from "../vault/account.js";
import {
  addMember,
  createCollection,
  fulfilGrant,
  listMembers,
  loadPendingGrants,
  removeMember,
  type Member,
  type PendingGrant,
} from "../vault/collections.js";
import { loadDirectory, type DirectoryEntry } from "../vault/directory.js";
import type { CollectionsScreenProps } from "./screens/CollectionsScreen.js";
import { useVaultState } from "./useVault.js";

/**
 * The collections-management controller: state and handlers for the
 * Collections tab, extracted out of VaultScreen once that screen had grown
 * a full second responsibility alongside item CRUD and tab-strip rendering.
 *
 * Returns exactly the props `CollectionsScreen` needs, so a caller renders it
 * as `<CollectionsScreen {...useCollectionsPanel({ api, session, store,
 * active })} />` with nothing else to wire up.
 */
export function useCollectionsPanel({
  api,
  session,
  store,
  active,
}: {
  api: ApiClient;
  session: Session;
  store: VaultStore;
  /** Whether the Collections tab is the one currently showing. Gates the
   *  lazy directory/pending-grants load below. */
  active: boolean;
}): CollectionsScreenProps {
  const state = useVaultState(store);
  const [directory, setDirectory] = useState<DirectoryEntry[]>([]);
  const [pendingGrants, setPendingGrants] = useState<PendingGrant[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [selectedCollectionId, setSelectedCollectionId] = useState<string | null>(null);
  const [members, setMembers] = useState<Member[]>([]);

  // Loaded lazily on first visit to the Collections tab rather than on every
  // mount: a user who never opens it should not pay for a directory fetch
  // and a pending-grants request they will never see.
  useEffect(() => {
    if (!active || loaded) return;
    let cancelled = false;
    void (async () => {
      try {
        const [dir, grants] = await Promise.all([
          loadDirectory({ api }),
          loadPendingGrants({ api, session }),
        ]);
        if (!cancelled) {
          setDirectory(dir);
          setPendingGrants(grants);
          setLoaded(true);
        }
      } catch {
        // Best-effort: the collections list itself still comes from
        // state.collections regardless, so the tab is not empty even if this
        // secondary data fails to load.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [active, loaded, api, session]);

  const handleSelectCollection = useCallback(
    (collectionId: string | null) => {
      setSelectedCollectionId(collectionId);
      if (collectionId === null) {
        setMembers([]);
        return;
      }
      void listMembers({ api, session }, collectionId)
        .then(setMembers)
        .catch(() => setMembers([]));
    },
    [api, session],
  );

  const handleCreateCollection = useCallback(
    async (name: string): Promise<void> => {
      const profile = await loadAccount({ api, session });
      await createCollection({ api, session }, { name, ownPublicKey: profile.publicKey });
      await store.resync({ api, session });
    },
    [api, session, store],
  );

  const handleFulfil = useCallback(
    async (grant: PendingGrant, recipient: DirectoryEntry): Promise<void> => {
      await fulfilGrant({ api, session }, { grant, recipient });
      setPendingGrants((prev) =>
        prev.filter((g) => !(g.collectionId === grant.collectionId && g.userId === grant.userId)),
      );
      await store.resync({ api, session });
    },
    [api, session, store],
  );

  const handleAddMember = useCallback(
    async (input: {
      collectionId: string;
      recipient: DirectoryEntry;
      role: "manager" | "member";
    }): Promise<"granted" | "pending"> => {
      const outcome = await addMember({ api, session }, input);
      if (outcome === "granted" && selectedCollectionId === input.collectionId) {
        setMembers(await listMembers({ api, session }, input.collectionId));
      }
      return outcome;
    },
    [api, session, selectedCollectionId],
  );

  const handleRemoveMember = useCallback(
    async (input: { collectionId: string; userId: string }): Promise<void> => {
      await removeMember({ api, session }, input);
      setMembers((prev) => prev.filter((m) => m.userId !== input.userId));
    },
    [api, session],
  );

  return {
    role: session.user?.role ?? "user",
    collections: state.collections,
    pendingGrants,
    directory,
    members,
    selectedCollectionId,
    onSelectCollection: handleSelectCollection,
    onCreateCollection: handleCreateCollection,
    onFulfil: handleFulfil,
    onAddMember: handleAddMember,
    onRemoveMember: handleRemoveMember,
  };
}
