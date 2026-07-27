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
 * The key an item's body is encrypted under: the userKey for a personal item,
 * the collection key for a shared one.
 *
 * Returns null rather than throwing when the collection key is missing —
 * decryptRecords turns that into an unreadable row, which is the honest
 * outcome, while the write paths turn it into a thrown error, because writing
 * an item nobody can open is not something to do quietly.
 */
export function parentKeyFor(session: Session, collectionId: string | null): Uint8Array | null {
  if (collectionId === null) return session.getKeys().userKey;
  return session.getCollectionKey(collectionId);
}

function requireParentKey(session: Session, collectionId: string | null): Uint8Array {
  const key = parentKeyFor(session, collectionId);
  if (key === null) {
    throw new Error(
      `This device cannot open the key for that collection, so it cannot write to it`,
    );
  }
  return key;
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
  session: Session,
): Promise<ItemRecord[]> {
  const records: ItemRecord[] = [];
  for (const item of wire) {
    // A tombstone has had its ciphertext and wrapped key blanked by the server,
    // so there is nothing to open and nothing to report as a failure.
    if (item.deletedAt !== null) {
      records.push(toRecord(item, null));
      continue;
    }
    const parentKey = parentKeyFor(session, item.collectionId);
    if (parentKey === null) {
      // An item in a collection whose key this client does not hold. Shown as
      // undecryptable rather than dropped, for the same reason a corrupt blob
      // is: a silently missing row reads as data loss.
      records.push(toRecord(item, null));
      continue;
    }
    try {
      const plaintext = await decryptItem(
        { ciphertext: item.ciphertext, wrappedItemKey: item.wrappedItemKey },
        parentKey,
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
  collectionId: string | null,
): Promise<ItemRecord> {
  const encrypted = await encryptItem(plaintext, requireParentKey(deps.session, collectionId));
  const created = await deps.api.post<WireItem>("/api/items", {
    collectionId,
    ciphertext: encrypted.ciphertext,
    wrappedItemKey: encrypted.wrappedItemKey,
  });
  // The plaintext is already in hand — decrypting the echo would be work to
  // learn something we just encrypted.
  return toRecord(created, plaintext);
}

export interface ItemUpdate {
  id: string;
  revision: number;
  /** Always explicit. The server reads an omitted field as "no change", and a
   *  client that forgets to echo it moves a shared item to personal — which
   *  every other member's next sync sees as the item vanishing. */
  collectionId: string | null;
  plaintext: ItemPlaintext;
}

export async function updateItem(
  deps: { api: ApiClient; session: Session },
  input: ItemUpdate,
): Promise<ItemRecord> {
  // The parent is the *target* collection: a move re-encrypts the body under
  // the destination's key in the same write.
  const encrypted = await encryptItem(
    input.plaintext,
    requireParentKey(deps.session, input.collectionId),
  );
  try {
    const updated = await deps.api.put<WireItem>(`/api/items/${input.id}`, {
      collectionId: input.collectionId,
      ciphertext: encrypted.ciphertext,
      wrappedItemKey: encrypted.wrappedItemKey,
      revision: input.revision,
    });
    return toRecord(updated, input.plaintext);
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
