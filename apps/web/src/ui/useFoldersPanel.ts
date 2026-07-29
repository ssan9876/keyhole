import { useCallback } from "react";
import type { ApiClient } from "../vault/api.js";
import type { Session } from "../vault/session.js";
import type { VaultStore } from "../vault/store.js";
import {
  createFolder,
  deleteFolder,
  renameFolder,
  type FolderRecord,
} from "../vault/folders.js";
import { useVaultState } from "./useVault.js";

export interface FoldersPanel {
  folders: FolderRecord[];
  onCreateFolder(name: string): Promise<void>;
  onRenameFolder(folder: FolderRecord, name: string): Promise<void>;
  onDeleteFolder(folder: FolderRecord): Promise<void>;
}

/**
 * The folder-management controller: the create/rename/delete handlers for the
 * folder sidebar, extracted out of VaultScreen the same way useCollectionsPanel
 * was -- so the screen stays a thin presentational shell and does not triple in
 * size wiring folder CRUD inline.
 *
 * `folders` is read straight off the vault store; the handlers each act and then
 * resync so the new state (the created folder, the renamed name, the removed
 * row) shows up. Like handleCreateCollection, a resync that blips must not turn
 * an action that already succeeded on the server into a reported failure, so the
 * resync error is swallowed: the change simply will not appear until the next
 * successful sync.
 */
export function useFoldersPanel({
  api,
  session,
  store,
}: {
  api: ApiClient;
  session: Session;
  store: VaultStore;
}): FoldersPanel {
  const state = useVaultState(store);

  const onCreateFolder = useCallback(
    async (name: string): Promise<void> => {
      await createFolder({ api, session }, name);
      await store.resync({ api, session }).catch(() => undefined);
    },
    [api, session, store],
  );

  const onRenameFolder = useCallback(
    async (folder: FolderRecord, name: string): Promise<void> => {
      await renameFolder({ api, session }, folder.id, folder.revision, name);
      await store.resync({ api, session }).catch(() => undefined);
    },
    [api, session, store],
  );

  const onDeleteFolder = useCallback(
    async (folder: FolderRecord): Promise<void> => {
      await deleteFolder({ api, session }, folder.id);
      await store.resync({ api, session }).catch(() => undefined);
    },
    [api, session, store],
  );

  return { folders: state.folders, onCreateFolder, onRenameFolder, onDeleteFolder };
}
