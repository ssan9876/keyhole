import {
  decryptItem,
  encryptItem,
  type ItemPlaintext,
} from "@keyhole/crypto";
import { ApiError, type ApiClient } from "./api.js";
import type { Session } from "./session.js";

/** The server's wire shape for an item. Every field is opaque to it. */
export interface WireItem {
  id: string;
  collectionId: string | null;
  ownerUserId: string;
  ciphertext: string;
  wrappedItemKey: string;
  revision: number;
  createdAt: string;
  updatedAt: string;
  deletedAt: string | null;
}

/** A wire item after this client tried to open it. */
export interface ItemRecord {
  id: string;
  revision: number;
  collectionId: string | null;
  deletedAt: string | null;
  /** null when the row is a tombstone, or when decryption failed. */
  plaintext: ItemPlaintext | null;
}

export class ItemConflictError extends Error {
  readonly current: WireItem;
  constructor(current: WireItem) {
    super("This item changed on the server since you last synced");
    this.name = "ItemConflictError";
    this.current = current;
  }
}

function toRecord(item: WireItem, plaintext: ItemPlaintext | null): ItemRecord {
  return {
    id: item.id,
    revision: item.revision,
    collectionId: item.collectionId,
    deletedAt: item.deletedAt,
    plaintext,
  };
}

/**
 * Decrypts a batch, one row at a time, and never lets one failure sink the rest.
 *
 * A corrupt or unopenable blob is a bad row; it is not a bad vault. Throwing
 * here would turn one damaged item into a password manager that shows nothing
 * at all, which is the worse failure by a wide margin.
 */
export async function decryptRecords(
  wire: WireItem[],
  userKey: Uint8Array,
): Promise<ItemRecord[]> {
  const records: ItemRecord[] = [];
  for (const item of wire) {
    // A tombstone has had its ciphertext and wrapped key blanked by the server,
    // so there is nothing to open and nothing to report as a failure.
    if (item.deletedAt !== null) {
      records.push(toRecord(item, null));
      continue;
    }
    try {
      const plaintext = await decryptItem(
        { ciphertext: item.ciphertext, wrappedItemKey: item.wrappedItemKey },
        userKey,
      );
      records.push(toRecord(item, plaintext));
    } catch {
      records.push(toRecord(item, null));
    }
  }
  return records;
}

export async function createItem(
  deps: { api: ApiClient; session: Session },
  plaintext: ItemPlaintext,
): Promise<ItemRecord> {
  const { userKey } = deps.session.getKeys();
  const encrypted = await encryptItem(plaintext, userKey);
  const created = await deps.api.post<WireItem>("/api/items", {
    ciphertext: encrypted.ciphertext,
    wrappedItemKey: encrypted.wrappedItemKey,
  });
  // The plaintext is already in hand — decrypting the echo would be work to
  // learn something we just encrypted.
  return toRecord(created, plaintext);
}

export async function updateItem(
  deps: { api: ApiClient; session: Session },
  id: string,
  revision: number,
  plaintext: ItemPlaintext,
): Promise<ItemRecord> {
  const { userKey } = deps.session.getKeys();
  const encrypted = await encryptItem(plaintext, userKey);
  try {
    const updated = await deps.api.put<WireItem>(`/api/items/${id}`, {
      ciphertext: encrypted.ciphertext,
      wrappedItemKey: encrypted.wrappedItemKey,
      revision,
    });
    return toRecord(updated, plaintext);
  } catch (error) {
    if (error instanceof ApiError && error.code === "conflict") {
      const body = error.body as { item?: WireItem };
      if (body.item !== undefined) {
        throw new ItemConflictError(body.item);
      }
    }
    throw error;
  }
}

export async function deleteItem(
  deps: { api: ApiClient; session: Session },
  id: string,
): Promise<void> {
  await deps.api.del(`/api/items/${id}`);
}
