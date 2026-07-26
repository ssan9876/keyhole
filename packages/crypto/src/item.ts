import { randomBytes } from "./random.js";
import { decryptString, encryptString } from "./symmetric.js";
import { unwrapKey, wrapKey } from "./keys.js";

export interface PasswordHistoryEntry {
  password: string;
  changedAt: string;
}

export interface LoginItem {
  type: "login";
  name: string;
  username: string;
  password: string;
  urls: string[];
  notes: string;
  favorite: boolean;
  folderId: string | null;
  passwordHistory: PasswordHistoryEntry[];
}

export interface NoteItem {
  type: "note";
  name: string;
  notes: string;
  favorite: boolean;
  folderId: string | null;
}

export type ItemPlaintext = LoginItem | NoteItem;

export interface EncryptedItem {
  ciphertext: string;
  wrappedItemKey: string;
}

const ITEM_KEY_BYTES = 32;

export function generateItemKey(): Uint8Array {
  return randomBytes(ITEM_KEY_BYTES);
}

/**
 * `parentKey` is the userKey for a personal item, or the collectionKey for a
 * shared one. The item body is encrypted under its own key so that moving an
 * item between the two only re-wraps 32 bytes.
 */
export async function encryptItem(
  item: ItemPlaintext,
  parentKey: Uint8Array,
): Promise<EncryptedItem> {
  const itemKey = generateItemKey();
  return {
    ciphertext: await encryptString(JSON.stringify(item), itemKey),
    wrappedItemKey: await wrapKey(itemKey, parentKey),
  };
}

export async function decryptItem(
  encrypted: EncryptedItem,
  parentKey: Uint8Array,
): Promise<ItemPlaintext> {
  const itemKey = await unwrapKey(encrypted.wrappedItemKey, parentKey);
  return JSON.parse(await decryptString(encrypted.ciphertext, itemKey)) as ItemPlaintext;
}

export async function rewrapItem(
  encrypted: EncryptedItem,
  fromParentKey: Uint8Array,
  toParentKey: Uint8Array,
): Promise<EncryptedItem> {
  const itemKey = await unwrapKey(encrypted.wrappedItemKey, fromParentKey);
  return {
    ciphertext: encrypted.ciphertext,
    wrappedItemKey: await wrapKey(itemKey, toParentKey),
  };
}
