import { decryptString, encryptString } from "@keyhole/crypto";
import { ApiError, type ApiClient } from "./api.js";
import type { Session } from "./session.js";

/** The server's wire shape for a folder. The name is opaque to it — it stores
 *  and echoes `encryptedName` and never sees the plaintext. */
export interface WireFolder {
  id: string;
  encryptedName: string;
  revision: number;
  deletedAt: string | null;
}

/** A wire folder after this client tried to open its name. */
export interface FolderRecord {
  id: string;
  revision: number;
  deletedAt: string | null;
  /** null when the row is a tombstone, or when the name would not decrypt. */
  name: string | null;
}

export class FolderConflictError extends Error {
  readonly current: WireFolder;
  constructor(current: WireFolder) {
    super("This folder changed on the server since you last synced");
    this.name = "FolderConflictError";
    this.current = current;
  }
}

function toRecord(folder: WireFolder, name: string | null): FolderRecord {
  return {
    id: folder.id,
    revision: folder.revision,
    deletedAt: folder.deletedAt,
    name,
  };
}

/**
 * Decrypts a batch of folder names, one at a time, and never lets one failure
 * sink the rest.
 *
 * A name that will not open is a broken folder, not a broken vault. Throwing
 * here would turn one corrupt name into a sidebar that shows nothing at all; a
 * folder whose name is null is instead rendered as "couldn't decrypt this
 * folder", which is the honest outcome and the one design spec calls for.
 */
export async function decryptFolders(
  wire: WireFolder[],
  userKey: Uint8Array,
): Promise<FolderRecord[]> {
  const records: FolderRecord[] = [];
  for (const folder of wire) {
    // A tombstone has had its name cleared server-side, so there is nothing to
    // open. Skip it rather than feed a blank string to decryption and catch the
    // throw — a deleted folder is not a decryption failure.
    if (folder.deletedAt !== null) {
      records.push(toRecord(folder, null));
      continue;
    }
    try {
      const name = await decryptString(folder.encryptedName, userKey);
      records.push(toRecord(folder, name));
    } catch {
      records.push(toRecord(folder, null));
    }
  }
  return records;
}

/**
 * Encrypts the name under the userKey and creates the folder.
 *
 * The userKey is read from the session at the point of use and never retained:
 * design spec keeps all key material in session.ts alone.
 */
export async function createFolder(
  deps: { api: ApiClient; session: Session },
  name: string,
): Promise<FolderRecord> {
  const encryptedName = await encryptString(name, deps.session.getKeys().userKey);
  const created = await deps.api.post<WireFolder>("/api/folders", { encryptedName });
  // The name is already in hand — decrypting the echo would be work to learn
  // something we just encrypted.
  return toRecord(created, name);
}

export async function renameFolder(
  deps: { api: ApiClient; session: Session },
  id: string,
  revision: number,
  name: string,
): Promise<FolderRecord> {
  const encryptedName = await encryptString(name, deps.session.getKeys().userKey);
  try {
    const updated = await deps.api.put<WireFolder>(`/api/folders/${id}`, {
      encryptedName,
      revision,
    });
    return toRecord(updated, name);
  } catch (error) {
    if (error instanceof ApiError && error.code === "conflict") {
      const body = error.body as { folder?: WireFolder };
      if (body.folder !== undefined) {
        throw new FolderConflictError(body.folder);
      }
    }
    throw error;
  }
}

export async function deleteFolder(
  deps: { api: ApiClient; session: Session },
  id: string,
): Promise<void> {
  await deps.api.del(`/api/folders/${id}`);
}
