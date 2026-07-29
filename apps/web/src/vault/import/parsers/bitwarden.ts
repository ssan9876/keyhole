import { parseCsv, type CsvRow } from "../csv.js";
import {
  blankImportItem,
  folderSegments,
  type ImportFieldKind,
  type ImportItem,
  type ImportItemType,
  type ImportResult,
  type ImportRowError,
} from "../types.js";

/**
 * Bitwarden's two exports: the JSON one and the CSV one.
 *
 * One vendor, two parsers, because they are two genuinely different files. The
 * JSON export nests a login under `login`, names folders in a separate top-level
 * array and identifies an item's folder by id; the CSV export is flat, carries
 * the folder's *name* in a column, and writes the item type as a word rather
 * than a number. Nothing but the vendor is shared, so the mapping is written
 * twice rather than bent into one table.
 *
 * The JSON export is the richest format Keyhole reads and the one most likely to
 * be used by somebody migrating deliberately, which makes it the format where
 * dropping information silently costs most. Everything Bitwarden carries that
 * Keyhole has no field for goes into `extra` — TOTP seeds, custom fields, the
 * reprompt flag, an organisation export's collection names — rather than being
 * quietly discarded, because `types.ts` makes `extra` both the channel the
 * mapper appends to the note from *and* the channel the preview screen reads to
 * tell the user what will not survive.
 *
 * ## The contract (stated in full in the plan, Tasks 3-7)
 *
 * Returns the intermediate shape, never `ItemPlaintext`. **Never throws** — a
 * malformed item comes back as a per-row error beside the items that parsed, and
 * that includes a file that is not JSON at all. **Never guesses at a password**:
 * absent, empty, or from a row the CSV reader flagged as damaged is an error
 * row, never an item with a blank password, because a blank imported over a real
 * password has no undo and the user is about to be told to delete the export.
 * **Preserves the password byte for byte** — nothing here trims or normalizes a
 * password.
 *
 * ## What `sourceRow` means here, and why it differs between the two
 *
 * `types.ts` describes `sourceRow` as a 1-based line "the user can actually find
 * in their own file". For the CSV that is exactly what it is, straight from the
 * reader. **A JSON export has no rows**, so `sourceRow` is the item's 1-based
 * position in the `items` array, and every JSON error message opens with
 * `Item N ("the item's name")` so the number is never presented as a line. A
 * position with the name beside it is what a user can actually search a 40,000
 * line export for; a line number would need the file's byte offsets, which
 * `JSON.parse` does not report and a hand-rolled scanner would only estimate.
 */

/**
 * What a user is told when they upload an encrypted export.
 *
 * This is a realistic first attempt rather than an edge case: "Password
 * protected" and the account-encrypted `.json (Encrypted)` are choices in the
 * same Bitwarden export dialog as the plain one. The items in such a file are
 * ciphertext strings, so a parser that ploughed on would produce one unreadable
 * -password error per item — hundreds of rows saying nothing — in place of the
 * single sentence that tells the user what to do instead.
 */
const ENCRYPTED_EXPORT =
  "This is an encrypted Bitwarden export, which cannot be read without your " +
  "Bitwarden password. Export it again with the file format set to .json " +
  "rather than .json (Encrypted), and upload that file.";

/** Bitwarden's numeric item types that map onto one of Keyhole's two kinds. */
const JSON_KINDS = new Map<number, ImportItemType>([
  [1, "login"],
  [2, "note"],
]);

/**
 * The numeric types Keyhole has no home for, and what to call each one.
 *
 * Named rather than skipped. "Imported 200 of 214" with the other 14 explained
 * is a count the user can act on; "imported 200" from a 214-item file is a
 * number they have no way to check, and the difference is exactly the kind of
 * loss that is discovered months later.
 */
const JSON_UNSUPPORTED = new Map<number, string>([
  [3, "card"],
  [4, "identity"],
  [5, "SSH key"],
]);

/** The CSV export's type words, which are the same two kinds spelled out. */
const CSV_KINDS = new Map<string, ImportItemType>([
  ["login", "login"],
  ["note", "note"],
  ["securenote", "note"],
  ["secure note", "note"],
]);

/** The CSV export's column names, lowercased as the header index holds them. */
const CSV_COLUMNS = {
  folder: "folder",
  favorite: "favorite",
  type: "type",
  name: "name",
  notes: "notes",
  fields: "fields",
  reprompt: "reprompt",
  uri: "login_uri",
  username: "login_username",
  password: "login_password",
  totp: "login_totp",
} as const;

/**
 * Adds one entry to `item.extra`, in the order the export carried it.
 *
 * One entry each, never merged by name, because two things can legitimately
 * claim one name: Bitwarden allows two custom fields with the same name, and a
 * custom field may itself be named `totp`. Merging them into a single value —
 * which is what the record this used to be forced — leaves the user's two "PIN"
 * fields as one string that nothing downstream can take apart again.
 *
 * An empty value is not carried at all: otherwise every ordinary login would
 * arrive with an empty `totp` and the preview screen would warn about the loss
 * of nothing on every row of the import.
 */
function carry(item: ImportItem, name: string, value: string, kind: ImportFieldKind): void {
  if (value === "") return;
  item.extra.push({ name, value, kind });
}

/**
 * What Bitwarden nests folders with.
 *
 * Bitwarden has no folder tree in its data: a nested folder is one folder whose
 * *name* contains a `/`, which is the documented way to make one and how its own
 * clients render the tree. So `Work/Servers` is two segments, and a folder whose
 * name genuinely contains a slash is indistinguishable from a nested one in
 * Bitwarden's own model too — splitting here matches what Bitwarden itself shows
 * the user, which is the closest thing to a right answer available.
 */
const FOLDER_SEPARATOR = "/";

/**
 * The reprompt flag as text, or `""` for the ordinary case of it being off.
 *
 * Written once for both exports: the JSON writes the number `1`, the CSV writes
 * the string `"1"`, and both mean the same thing — Bitwarden asks for the master
 * password before revealing this item. Keyhole has no such setting in v1, so it
 * is carried rather than silently lost.
 */
function repromptText(value: unknown): string {
  const text = scalarText(value);
  return text === "" || text === "0" || text === "false" ? "" : text;
}

/* -------------------------------------------------------------------------- */
/*                                    JSON                                    */
/* -------------------------------------------------------------------------- */

function asObject(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * A JSON string as itself, and anything else as `""`.
 *
 * Deliberately not a stringifier: `notes` is `null` on most items and a number
 * where a name belongs is a broken export, and `String(null)` would put the word
 * "null" in the user's vault.
 */
function stringOf(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/** A JSON scalar as text, for the fields where Bitwarden writes several types. */
function scalarText(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return "";
}

/**
 * `id` → `name` for the export's `folders` (or an organisation export's
 * `collections`, which have the same two fields).
 *
 * The mapping is the whole reason this parser has a folder step at all: an item
 * names its folder by an id, and the intermediate shape carries the folder's
 * *name*, because an id from someone else's vault means nothing in this one.
 */
function namesById(value: unknown): Map<string, string> {
  const names = new Map<string, string>();
  if (!Array.isArray(value)) return names;
  for (const entry of value) {
    const folder = asObject(entry);
    if (folder === null) continue;
    const id = folder["id"];
    const name = folder["name"];
    // First occurrence wins for a repeated id, matching the rule `csv.ts`
    // applies to a repeated column name.
    if (typeof id === "string" && typeof name === "string" && !names.has(id)) {
      names.set(id, name);
    }
  }
  return names;
}

/**
 * The URLs of a login.
 *
 * **`login.uris` is an array of objects with a `uri` field, not an array of
 * strings.** Reading the elements themselves gives `[object Object]` for every
 * URL of every multi-site login — a value that looks like a string right up
 * until somebody tries to visit it.
 */
function urlsOf(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const urls: string[] = [];
  for (const entry of value) {
    const uri = asObject(entry)?.["uri"];
    // An entry with no `uri`, or a null one, is nothing to carry rather than an
    // empty string to carry: `[""]` downstream would make every URL-less item a
    // duplicate of every other, since duplicate detection compares hosts.
    if (typeof uri === "string" && uri !== "") urls.push(uri);
  }
  return urls;
}

/** Carries the user's custom fields, keyed by the name they gave each one. */
function carryFields(item: ImportItem, value: unknown): void {
  if (!Array.isArray(value)) return;
  for (const entry of value) {
    const field = asObject(entry);
    if (field === null) continue;
    const name = stringOf(field["name"]);
    // A field Bitwarden let the user leave unnamed still holds a value, and a
    // hidden field's value is a secret. Keying it by position in the item would
    // be meaningless to read, so it is named for what it is.
    //
    // `custom` whatever it is called — including a field the user named "totp",
    // which is not the login's TOTP seed and must not be reported as one. That
    // is the whole reason `kind` comes from the position in the file rather than
    // from the name.
    carry(item, name === "" ? "(unnamed field)" : name, scalarText(field["value"]), "custom");
  }
}

/**
 * Records the collections an organisation export puts an item in.
 *
 * Not treated as the folder. An item can be in several collections at once, so
 * no one of them is "the" folder, and picking the first would be a guess that
 * looked like a fact. Recording the names is what lets the preview screen say
 * the grouping is not coming across; an id that resolves to no collection is
 * kept as the id, which is at least something the user can search their export
 * for.
 */
function carryCollections(
  item: ImportItem,
  ids: unknown,
  collections: ReadonlyMap<string, string>,
): void {
  if (!Array.isArray(ids)) return;
  const named: string[] = [];
  for (const id of ids) {
    if (typeof id !== "string" || id === "") continue;
    named.push(collections.get(id) ?? id);
  }
  carry(item, "collections", named.join(", "), "metadata");
}

/** One item of the `items` array, as an item or as the reason it is not one. */
function jsonItem(
  raw: unknown,
  position: number,
  folders: ReadonlyMap<string, string>,
  collections: ReadonlyMap<string, string>,
): ImportItem | ImportRowError {
  const source = asObject(raw);
  if (source === null) {
    return { row: position, message: `Item ${position} is not an object, so it could not be read` };
  }

  const name = stringOf(source["name"]);
  // The name is what the user will recognise; the position is what makes two
  // items of the same name distinguishable. Both, because either alone leaves a
  // report the user cannot act on.
  const label = name === "" ? `Item ${position}` : `Item ${position} ("${name}")`;

  const type = source["type"];
  if (typeof type !== "number") {
    return {
      row: position,
      message: `${label} does not say what kind of item it is, so it was not imported`,
    };
  }

  const kind = JSON_KINDS.get(type);
  if (kind === undefined) {
    const described = JSON_UNSUPPORTED.get(type) ?? `item of type ${type}`;
    return {
      row: position,
      message:
        `${label} is a Bitwarden ${described}, which Keyhole cannot import yet, ` +
        "so it was not imported",
    };
  }

  const item = blankImportItem(position);
  item.type = kind;
  item.name = name;
  item.notes = stringOf(source["notes"]);
  item.favorite = source["favorite"] === true;

  if (kind === "login") {
    const login = asObject(source["login"]);
    if (login === null) {
      return {
        row: position,
        message: `${label} is a login with no login details, so it was not imported`,
      };
    }

    const password = login["password"];
    // Absent and empty are different answers and both are refusals: absent is a
    // damaged export, empty is Bitwarden saying there is no password here.
    // Neither is an item, because an item with a blank password imported over a
    // real one cannot be recovered from an export the user has been told to
    // delete.
    if (typeof password !== "string") {
      return { row: position, message: `${label} has no password, so it was not imported` };
    }
    if (password === "") {
      return { row: position, message: `${label} has an empty password, so it was not imported` };
    }

    item.username = stringOf(login["username"]);
    // Byte for byte: the string `JSON.parse` produced and nothing else. A
    // trailing space is part of the password.
    item.password = password;
    item.urls = urlsOf(login["uris"]);
    // Keyhole has no TOTP field in v1 (spec section 1, non-goals). Dropping the
    // seed silently would lose a second factor the user believes they moved,
    // and they would find out when they could no longer sign in.
    //
    // `totp` is the kind because of where this sits in the file — under the
    // item's `login` object — and not because of what it is called.
    carry(item, "totp", stringOf(login["totp"]), "totp");
  }

  const folderId = source["folderId"];
  if (typeof folderId === "string" && folderId !== "") {
    const folderName = folders.get(folderId);
    if (folderName === undefined) {
      // An id naming no folder is a damaged export, not a crash and not a
      // reason to refuse an item that has its password. The item goes to the
      // root, and the id it claimed is recorded rather than dropped, so the
      // fact that a folder was named and could not be resolved is visible
      // instead of being indistinguishable from an item that had no folder.
      carry(item, "folderId", folderId, "metadata");
    } else {
      item.folderPath = folderSegments(folderName, FOLDER_SEPARATOR);
    }
  }

  carryCollections(item, source["collectionIds"], collections);
  carryFields(item, source["fields"]);
  carry(item, "reprompt", repromptText(source["reprompt"]), "metadata");

  return item;
}

/** Reads a Bitwarden JSON export. Never throws. */
export function parseBitwardenJson(text: string): ImportResult {
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

  // Before anything else, and before the `items` check: a password-protected
  // export has no `items` array at all — just a `data` blob — so testing for
  // items first would answer "this is not a Bitwarden export" for a file that
  // plainly is one, and send the user looking for the wrong problem.
  if (root?.["encrypted"] === true || root?.["passwordProtected"] === true) {
    return { items: [], errors: [{ row: 1, message: ENCRYPTED_EXPORT }] };
  }

  const raw = root?.["items"];
  if (!Array.isArray(raw)) {
    return {
      items: [],
      errors: [
        { row: 1, message: "This file has no items array, so it is not a Bitwarden JSON export" },
      ],
    };
  }

  const folders = namesById(root?.["folders"]);
  const collections = namesById(root?.["collections"]);
  const items: ImportItem[] = [];
  const errors: ImportRowError[] = [];

  raw.forEach((entry, at) => {
    const outcome = jsonItem(entry, at + 1, folders, collections);
    if ("message" in outcome) {
      errors.push(outcome);
    } else {
      items.push(outcome);
    }
  });

  return { items, errors };
}

/* -------------------------------------------------------------------------- */
/*                                     CSV                                    */
/* -------------------------------------------------------------------------- */

/** The header's columns, addressable by lowercased name. */
interface Columns {
  /** True when the file has this column at all. */
  has(column: string): boolean;
  /**
   * The value of `column` in `row`, or `undefined` for a column the file does
   * not have and for a row that ended before reaching it — both of which mean
   * "the export did not say", as distinct from `""`, which is the export saying
   * the field is empty.
   */
  value(row: CsvRow, column: string): string | undefined;
}

function indexColumns(header: readonly string[]): Columns {
  const at = new Map<string, number>();
  header.forEach((cell, position) => {
    // Trimmed and lowercased, as `detect.ts` matches them: a spreadsheet round
    // trip changes the case and can add a space, and neither changes which
    // column holds the password. A BOM on the first name is removed by the
    // reader, and `trim` removes a stray one anywhere else.
    const key = cell.trim().toLowerCase();
    // First occurrence wins for a duplicated name, matching the reader's rule.
    if (!at.has(key)) at.set(key, position);
  });

  return {
    has: (column) => at.has(column),
    value: (row, column) => {
      const position = at.get(column);
      return position === undefined ? undefined : row.values[position];
    },
  };
}

/**
 * The URLs in one `login_uri` cell.
 *
 * Bitwarden's CSV writer joins an item's URIs with a comma into a single quoted
 * column, so a login with three sites arrives as one string and has to be split
 * back apart. Each URL is trimmed — a leading space breaks a URL and a
 * spreadsheet round trip adds one — which is a liberty taken with URLs only and
 * never with the password.
 */
function splitUris(value: string): string[] {
  return value
    .split(",")
    .map((uri) => uri.trim())
    .filter((uri) => uri !== "");
}

/** Bitwarden writes `1` for a favourite and `0` for the rest. */
function isFavorite(value: string | undefined): boolean {
  const text = value?.trim().toLowerCase();
  return text === "1" || text === "true";
}

function csvItem(row: CsvRow, columns: Columns, width: number): ImportItem | ImportRowError {
  if (row.extra.length > 0) {
    // Fields past the end of the header. An export whose writer failed to quote
    // a password containing a comma produces exactly this, and from here on the
    // values no longer line up with the columns naming them — so the field this
    // row calls a password is part of one, and the rest is in `row.extra`.
    //
    // All-empty surplus is the trailing-comma shape rather than a column shift,
    // and says so; `browser.ts` carries the same distinction and the same
    // reason for still refusing the row.
    const allSurplusEmpty = row.extra.every((value) => value === "");
    return {
      row: row.line,
      message: allSurplusEmpty
        ? `This row has ${row.values.length} fields where the header has ${width}, ` +
          `though every surplus field is empty, so a trailing comma is the likely cause`
        : `This row has ${row.values.length} fields where the header has ${width}, ` +
          `so a value has been split across columns`,
    };
  }

  // A row whose type column is absent or blank is read as a login, which is
  // what the remaining columns describe. The guess is safe rather than
  // confident: if such a row were really a card it would carry no password, and
  // the password rule below turns it into a visible error row rather than an
  // item.
  const word = (columns.value(row, CSV_COLUMNS.type) ?? "").trim().toLowerCase();
  const kind = word === "" ? "login" : CSV_KINDS.get(word);
  if (kind === undefined) {
    return {
      row: row.line,
      message: `This row is a Bitwarden ${word}, which Keyhole cannot import yet, so it was not imported`,
    };
  }

  const item = blankImportItem(row.line);
  item.type = kind;
  item.name = columns.value(row, CSV_COLUMNS.name) ?? "";
  item.notes = columns.value(row, CSV_COLUMNS.notes) ?? "";
  item.favorite = isFavorite(columns.value(row, CSV_COLUMNS.favorite));

  // An absent or empty cell splits to no segments, which is the root — the same
  // answer the JSON export's absent `folderId` gives.
  item.folderPath = folderSegments(columns.value(row, CSV_COLUMNS.folder) ?? "", FOLDER_SEPARATOR);

  if (kind === "login") {
    const password = columns.value(row, CSV_COLUMNS.password);
    if (password === undefined) {
      return { row: row.line, message: "This row ends before its password column" };
    }
    if (password === "") {
      return { row: row.line, message: "This row has an empty password, so it was not imported" };
    }
    item.username = columns.value(row, CSV_COLUMNS.username) ?? "";
    // Byte for byte: the value as the reader unescaped it, and nothing else.
    item.password = password;
    item.urls = splitUris(columns.value(row, CSV_COLUMNS.uri) ?? "");
    carry(item, "totp", columns.value(row, CSV_COLUMNS.totp) ?? "", "totp");
  }

  // The `fields` column is the user's custom fields flattened by Bitwarden into
  // one blob, one `name: value` per line. It is carried whole rather than split
  // back apart on ": ", because a value containing that sequence would split
  // wrongly and there would be nothing to say it had happened. The JSON export
  // keeps the fields separate and this parser keeps them separate there.
  // `custom` even though it arrives as one blob: it is the user's own fields,
  // and what the preview screen says about losing them should read the same way
  // it does for the JSON export, where they arrive one at a time.
  carry(item, "fields", columns.value(row, CSV_COLUMNS.fields) ?? "", "custom");
  carry(item, "reprompt", repromptText(columns.value(row, CSV_COLUMNS.reprompt)), "metadata");

  return item;
}

/**
 * Reads a Bitwarden CSV export. Never throws.
 *
 * A file with no `login_password` column comes back as a single error against
 * line 1 with no items — detection routes such a file elsewhere and this parser
 * should never see it, but "never throws" has to hold for the caller that gets
 * the routing wrong too.
 */
export function parseBitwardenCsv(text: string): ImportResult {
  const table = parseCsv(text);
  const columns = indexColumns(table.header);

  if (!columns.has(CSV_COLUMNS.password)) {
    return {
      items: [],
      errors: [
        {
          row: 1,
          message: "This file has no login_password column, so it is not a Bitwarden CSV export",
        },
        ...table.errors,
      ],
    };
  }

  // A record the reader reported damage on is not mapped at all. Its fields have
  // already been shown not to mean what their columns say — an unclosed quote
  // swallows the rest of the file into one value — so importing it would store a
  // password the user never had, underneath a report that said the file had a
  // problem. The reader's error is that row's error; it does not get a second.
  const damaged = new Set(table.errors.map((error) => error.row));
  const items: ImportItem[] = [];
  const errors: ImportRowError[] = [...table.errors];

  for (const row of table.rows) {
    if (damaged.has(row.line)) continue;
    const outcome = csvItem(row, columns, table.header.length);
    if ("message" in outcome) {
      errors.push(outcome);
    } else {
      items.push(outcome);
    }
  }

  // By line, so the report reads in the order of the user's own file. Stable, so
  // a reader error and a row error on one line keep the order above.
  errors.sort((left, right) => left.row - right.row);

  return { items, errors };
}
