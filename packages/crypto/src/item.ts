import { DecryptionError, KeyholeCryptoError } from "./errors.js";
import { zeroize } from "./memory.js";
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
  try {
    return {
      ciphertext: await encryptString(JSON.stringify(item), itemKey),
      wrappedItemKey: await wrapKey(itemKey, parentKey),
    };
  } finally {
    // parentKey is the caller's; the itemKey exists only for this call.
    zeroize(itemKey);
  }
}

function isString(value: unknown): boolean {
  return typeof value === "string";
}

function isStringOrNull(value: unknown): boolean {
  return value === null || typeof value === "string";
}

function isStringArray(value: unknown): boolean {
  return Array.isArray(value) && value.every(isString);
}

function isPasswordHistory(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.every(
      (entry) =>
        typeof entry === "object" &&
        entry !== null &&
        isString((entry as Record<string, unknown>)["password"]) &&
        isString((entry as Record<string, unknown>)["changedAt"]),
    )
  );
}

/**
 * Checks the decrypted body really is an ItemPlaintext before the cast.
 *
 * The AEAD tag is not sufficient authority here: `parentKey` can be
 * attacker-chosen. A compromised server can seal arbitrary bytes to a user as a
 * "collection key" and serve a ciphertext that verifies under it, at which
 * point fully attacker-controlled JSON would reach the web app typed as
 * `ItemPlaintext`. This is the only thing standing between that and the UI.
 *
 * Failure raises DecryptionError rather than a new type: the caller's recovery
 * is identical to any other decryption failure — the item cannot be shown.
 */
function assertItemPlaintext(value: unknown): asserts value is ItemPlaintext {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new DecryptionError();
  }
  const item = value as Record<string, unknown>;

  const common =
    isString(item["name"]) &&
    isString(item["notes"]) &&
    typeof item["favorite"] === "boolean" &&
    isStringOrNull(item["folderId"]);

  const valid =
    item["type"] === "note"
      ? common
      : item["type"] === "login"
        ? common &&
          isString(item["username"]) &&
          isString(item["password"]) &&
          isStringArray(item["urls"]) &&
          isPasswordHistory(item["passwordHistory"])
        : false;

  if (!valid) throw new DecryptionError();
}

export async function decryptItem(
  encrypted: EncryptedItem,
  parentKey: Uint8Array,
): Promise<ItemPlaintext> {
  const itemKey = await unwrapKey(encrypted.wrappedItemKey, parentKey);
  let parsed: unknown;
  try {
    parsed = JSON.parse(await decryptString(encrypted.ciphertext, itemKey));
  } catch (error) {
    // A KeyholeCryptoError from decryptString is already the right answer;
    // only JSON.parse's SyntaxError needs translating.
    if (error instanceof KeyholeCryptoError) throw error;
    throw new DecryptionError();
  } finally {
    zeroize(itemKey);
  }
  assertItemPlaintext(parsed);
  return parsed;
}

/**
 * Moves an item between parents by re-wrapping 32 bytes; the body is never
 * re-encrypted.
 *
 * **Moving an item out of a collection does not revoke it.** The ciphertext and
 * the item key are unchanged, so an ex-member who cached the old wrapped item
 * key can still read the item as it stands today — and will keep reading every
 * future edit, because edits reuse the same item key. This mirrors spec §5.1:
 * removing a member is not retroactive. Revocation requires rotating the item
 * key, which means re-encrypting the body, and any UI offering "remove from
 * collection" as a security action must say so.
 */
export async function rewrapItem(
  encrypted: EncryptedItem,
  fromParentKey: Uint8Array,
  toParentKey: Uint8Array,
): Promise<EncryptedItem> {
  const itemKey = await unwrapKey(encrypted.wrappedItemKey, fromParentKey);
  try {
    return {
      ciphertext: encrypted.ciphertext,
      wrappedItemKey: await wrapKey(itemKey, toParentKey),
    };
  } finally {
    zeroize(itemKey);
  }
}
