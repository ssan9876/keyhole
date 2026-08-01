import {
  blankImportItem,
  type ImportItem,
  type ImportItemType,
  type ImportResult,
  type ImportRowError,
} from "../types.js";
import { carry, isRowError, type RowOutcome } from "./shared.js";

/**
 * Proton Pass's JSON export.
 *
 * **Items are nested under vaults, and the vault is the folder.** The root's
 * `vaults` is an object keyed by vault id — not an array — and each vault
 * carries a `name` and an `items` array. Proton Pass has no folders at all: an
 * item belongs to exactly one vault, and the vault's name is the only grouping
 * the export carries, so it is what `folderPath` gets.
 *
 * A vault does not nest, so its name is one segment and is never split.
 * Choosing a separator anyway would turn a vault the user named `Home/Office`
 * into two folders that never existed.
 *
 * ## The contract (stated in full in the plan, Tasks 3-7)
 *
 * Returns the intermediate shape, never `ItemPlaintext`. **Never throws** — a
 * malformed item comes back as a per-row error beside the items that parsed, and
 * that includes a file that is not JSON at all. **Never guesses at a password.**
 * **Preserves the password byte for byte.**
 *
 * ## What `sourceRow` means here
 *
 * A JSON export has no rows, so it is the item's 1-based position counted across
 * every vault in the order the export lists them, and every message opens with
 * `Item N ("the item's name")` so the number is never presented as a line.
 */

/** What a user is told when they upload an export they chose to encrypt. */
const ENCRYPTED_EXPORT =
  "This is an encrypted Proton Pass export, which cannot be read without your " +
  "Proton Pass password. Export it again unencrypted and upload that file.";

/** Proton Pass's item types that map onto one of Keyhole's two kinds. */
const KINDS = new Map<string, ImportItemType>([
  ["login", "login"],
  ["note", "note"],
]);

/**
 * The types Keyhole has no home for, and what to call each one.
 *
 * Named rather than skipped, so the count the user reads adds up. A type not in
 * this map is reported using the export's own word for it, which is what lets
 * the user match the error to an item in their own file.
 */
const UNSUPPORTED = new Map<string, string>([
  ["creditCard", "credit card"],
  ["identity", "identity"],
  ["alias", "email alias"],
  ["sshKey", "SSH key"],
  ["wifi", "wifi network"],
]);

/**
 * The `state` of an item Proton Pass has moved to the trash.
 *
 * Only this exact value is treated as trashed. Anything else — including a
 * missing `state` — is read as active, so a wrong guess about this enum cannot
 * silently refuse a live item; at worst a trashed one is imported, which is what
 * would happen with no check at all.
 */
const TRASHED = 2;

function asObject(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * A JSON string as itself, and anything else as `""`.
 *
 * Deliberately not a stringifier: `note` is `null` on most items, and
 * `String(null)` would put the word "null" in the user's vault.
 */
function stringOf(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/**
 * The URLs of a login.
 *
 * **`content.urls` is an array of plain strings**, unlike Bitwarden's
 * `login.uris`, which is an array of objects with a `uri` field. Reading these
 * the way Bitwarden's are read gives `undefined` for every URL of every item and
 * drops the lot; reading Bitwarden's the way these are read gives
 * `[object Object]`. The two look interchangeable and are not.
 */
function urlsOf(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((url): url is string => typeof url === "string" && url !== "");
}

/**
 * Carries an item's `extraFields`, which are the fields the user made
 * themselves.
 *
 * The `kind` comes from the field's declared `type`, which is **Proton Pass's
 * own field-type discriminator set by the app** rather than a name the user
 * typed — so it is where the value sat, which is what `ImportFieldKind` requires
 * the kind to come from. A user's text field *named* `totp` stays `custom`,
 * which is the distinction that rule exists for.
 */
function carryExtraFields(item: ImportItem, value: unknown): void {
  if (!Array.isArray(value)) return;
  for (const entry of value) {
    const field = asObject(entry);
    if (field === null) continue;
    const name = stringOf(field["fieldName"]);
    const content = stringOf(asObject(field["data"])?.["content"]);
    carry(
      item,
      // A field Proton Pass let the user leave unnamed still holds a value, and
      // a hidden field's value is a secret. Naming it for what it is beats
      // keying it by a position nothing downstream can read.
      name === "" ? "(unnamed field)" : name,
      content,
      field["type"] === "totp" ? "totp" : "custom",
    );
  }
}

/** One item of a vault, as an item or as the reason it is not one. */
function vaultItem(raw: unknown, vaultName: string, position: number): RowOutcome {
  const source = asObject(raw);
  if (source === null) {
    return { row: position, message: `Item ${position} is not an object, so it could not be read` };
  }

  const data = asObject(source["data"]);
  const metadata = asObject(data?.["metadata"]);
  const name = stringOf(metadata?.["name"]);
  // The name is what the user will recognise; the position is what makes two
  // items of the same name distinguishable. Both, because either alone leaves a
  // report the user cannot act on.
  const label = name === "" ? `Item ${position}` : `Item ${position} ("${name}")`;

  if (source["state"] === TRASHED) {
    // Proton Pass exports the trash alongside the vault. Importing it silently
    // resurrects items the user chose to delete; dropping it silently loses
    // items they may not have meant to. Naming it lets them decide.
    return { row: position, message: `${label} is in the Proton Pass trash, so it was not imported` };
  }

  if (data === null) {
    return { row: position, message: `${label} carries no data, so it could not be read` };
  }

  const type = stringOf(data["type"]);
  const kind = KINDS.get(type);
  if (kind === undefined) {
    const described = UNSUPPORTED.get(type) ?? (type === "" ? "item of no stated type" : type);
    return {
      row: position,
      message:
        `${label} is a Proton Pass ${described}, which Keyhole cannot import yet, ` +
        "so it was not imported",
    };
  }

  const item = blankImportItem(position);
  item.type = kind;
  item.name = name;
  item.notes = stringOf(metadata?.["note"]);
  // A vault does not nest, so its name is one whole segment. An unnamed vault
  // leaves the item at the root rather than in a folder with no name.
  item.folderPath = vaultName === "" ? [] : [vaultName];

  if (kind === "login") {
    const content = asObject(data["content"]);
    if (content === null) {
      return {
        row: position,
        message: `${label} is a login with no login details, so it was not imported`,
      };
    }

    const password = content["password"];
    if (typeof password !== "string") {
      return { row: position, message: `${label} has no password, so it was not imported` };
    }
    if (password === "") {
      return { row: position, message: `${label} has an empty password, so it was not imported` };
    }

    // Proton Pass keeps a login's email and username in separate fields and an
    // item can carry both. Keyhole has one username, so the other is carried
    // rather than dropped — and only when it is not already the username, or
    // every ordinary login would report the same value twice.
    const email = stringOf(content["itemEmail"]);
    const username = stringOf(content["itemUsername"]);
    item.username = username === "" ? email : username;
    // Byte for byte: the string `JSON.parse` produced and nothing else.
    item.password = password;
    item.urls = urlsOf(content["urls"]);

    if (email !== "" && email !== item.username) {
      carry(item, "itemEmail", email, "custom");
    }
    // Keyhole has no TOTP field in v1 (spec section 1, non-goals), and `totp` is
    // the kind because of where this sits — the login's own `totpUri` — rather
    // than because of what it is called.
    carry(item, "totpUri", stringOf(content["totpUri"]), "totp");

    // A passkey cannot be imported and its material has no business being
    // appended to a note. How many there were is recorded so the user is not
    // left believing they moved: silence here is the failure they would find out
    // about at a sign-in page.
    const passkeys = content["passkeys"];
    if (Array.isArray(passkeys) && passkeys.length > 0) {
      carry(item, "passkeys", String(passkeys.length), "metadata");
    }
  }

  carryExtraFields(item, data["extraFields"]);

  return item;
}

/** Reads a Proton Pass JSON export. Never throws. */
export function parseProtonPassJson(text: string): ImportResult {
  let body: unknown;
  try {
    body = JSON.parse(text) as unknown;
  } catch {
    return {
      items: [],
      errors: [{ row: 1, message: "This file is not valid JSON, so nothing could be read from it" }],
    };
  }

  const root = asObject(body);

  // Before the vaults check: an encrypted export may well carry an empty
  // `vaults`, and answering "this is not a Proton Pass export" for a file that
  // plainly is one sends the user looking for the wrong problem.
  if (root?.["encrypted"] === true) {
    return { items: [], errors: [{ row: 1, message: ENCRYPTED_EXPORT }] };
  }

  const vaults = asObject(root?.["vaults"]);
  if (vaults === null) {
    return {
      items: [],
      errors: [
        { row: 1, message: "This file has no vaults object, so it is not a Proton Pass JSON export" },
      ],
    };
  }

  const items: ImportItem[] = [];
  const errors: ImportRowError[] = [];
  let position = 0;

  for (const raw of Object.values(vaults)) {
    const vault = asObject(raw);
    if (vault === null) continue;
    const name = stringOf(vault["name"]);
    const contents = vault["items"];
    if (!Array.isArray(contents)) continue;
    for (const entry of contents) {
      position += 1;
      const outcome = vaultItem(entry, name, position);
      if (isRowError(outcome)) {
        errors.push(outcome);
      } else {
        items.push(outcome);
      }
    }
  }

  return { items, errors };
}
