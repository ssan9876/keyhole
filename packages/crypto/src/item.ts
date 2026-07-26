import { DecryptionError, KeyholeCryptoError } from "./errors.js";
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
  }
  assertItemPlaintext(parsed);
  return parsed;
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
