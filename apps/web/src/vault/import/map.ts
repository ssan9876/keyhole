import type { ItemPlaintext } from "@keyhole/crypto";
import { parseCsv, type CsvRow } from "./csv.js";
import type { ImportParser } from "./detect.js";
import { blankImportItem, folderSegments, type ImportItem, type ImportResult } from "./types.js";
import {
  indexColumns,
  mapCsvRows,
  requiredPassword,
  surplusFieldsError,
  type Columns,
  type RowOutcome,
} from "./parsers/shared.js";
import { parseBitwardenCsv, parseBitwardenJson } from "./parsers/bitwarden.js";
import { parseBrowserCsv } from "./parsers/browser.js";
import { parseDashlaneCsv, parseDashlaneJson } from "./parsers/dashlane.js";
import { parseKeePassCsv } from "./parsers/keepass.js";
import { parseKeeperCsv, parseKeeperJson } from "./parsers/keeper.js";
import { parseLastPassCsv } from "./parsers/lastpass.js";
import { parseNordPassCsv } from "./parsers/nordpass.js";
import { parseOnePasswordCsv } from "./parsers/onepassword.js";
import { parseProtonPassJson } from "./parsers/protonpass.js";

/**
 * The boundary between "what the export said" and "what Keyhole stores".
 *
 * Two jobs, and they are here together because they are the same question asked
 * from two ends: the parsers produce `ImportItem`, Keyhole stores
 * `ItemPlaintext`, and something has to decide what happens to the parts of the
 * first that the second has no field for. This module is that decision, stated
 * once. The generic-CSV mapping is the same decision made by the user instead of
 * by a parser, for a file no parser recognises.
 *
 * Nothing here encrypts, holds a key, or touches the network — `upload.ts` does
 * that with what this returns.
 */

/* -------------------------------------------------------------------------- */
/*                        The intermediate shape to Keyhole                   */
/* -------------------------------------------------------------------------- */

/**
 * The heading the appended block sits under.
 *
 * A fixed string rather than something composed per format, so a user who has
 * imported from two managers sees one recognisable marker, and so a future
 * "strip the import block" tool has something to match on.
 */
const IMPORTED_HEADING = "--- Imported details ---";

/**
 * The label a TOTP seed lands under.
 *
 * Keyhole has no TOTP field in v1 (spec section 1, non-goals), so the seed's
 * only home is the note — but **not merged anonymously into free text**. A user
 * who set up a second factor months ago and now needs the seed has to be able to
 * find it, and the exporter's own column name (`OTPAuth`, `otpSecret`,
 * `login_totp`, `$oneTimeCode` — five spellings across the formats here) is not
 * something they will search for. The phrase is spelled out in full, with the
 * source's own name kept beside it because that is what they will recognise when
 * they do find the line.
 */
const TOTP_LABEL = "One-time password (TOTP) secret";

/**
 * How a folder path is shown once it reaches the note.
 *
 * One separator for every format. The parsers already split their own —
 * Bitwarden's `/`, LastPass's `\`, KeePassXC's `/` — so the user never sees
 * their manager's punctuation reproduced as part of a name.
 */
const PATH_SEPARATOR = " / ";

export interface MapOptions {
  /**
   * The folder every mapped item is placed in, or `null` for none.
   *
   * **The only way an import can reach a real folder, and it must come from the
   * caller.** A `folderId` is an id in this user's vault, which no export can
   * know; see `ImportItem.folderPath`.
   */
  folderId?: string | null;
}

/**
 * One line of the appended block, for one thing Keyhole has no field for.
 *
 * The kinds are labelled differently because they are different claims. A
 * `custom` field is something the user typed and is shown under the name they
 * gave it, with nothing added. A `metadata` field is the exporter's
 * record-keeping and says so, because a line the user does not recognise reads
 * as a mistake unless it explains itself. A `totp` field gets the full phrase —
 * see `TOTP_LABEL`.
 *
 * A value containing newlines is written as-is, so a multi-line custom field
 * spans multiple lines of the block. Escaping it would make the value unusable
 * for the thing it is there for: being read and copied.
 */
function extraLine(field: { name: string; value: string; kind: string }): string {
  if (field.kind === "totp") {
    return `${TOTP_LABEL}, exported as "${field.name}": ${field.value}`;
  }
  if (field.kind === "metadata") {
    return `${field.name} (recorded by the exporter, not by you): ${field.value}`;
  }
  return `${field.name}: ${field.value}`;
}

/**
 * The note Keyhole stores: the user's own text, then everything the export
 * carried that has no field of its own.
 *
 * Appended rather than discarded, and appended **below** the user's text so
 * their own words are still the first thing they read.
 */
function composeNotes(item: ImportItem, carried: readonly string[]): string {
  const lines: string[] = [];
  if (item.folderPath.length > 0) {
    lines.push(`Folder: ${item.folderPath.join(PATH_SEPARATOR)}`);
  }
  lines.push(...carried);
  lines.push(...item.extra.map(extraLine));

  if (lines.length === 0) return item.notes;

  const block = [IMPORTED_HEADING, ...lines].join("\n");
  return item.notes === "" ? block : `${item.notes}\n\n${block}`;
}

/**
 * One parsed row as the item Keyhole will encrypt.
 *
 * ## The two shapes that do not line up, and what happens to them
 *
 * **`folderPath` is a path; `folderId` is an id.** `folderId` stays `null`
 * unless the caller names one, and the path is written into the note.
 *
 * Creating the folders instead was the alternative, and it was rejected: Keyhole
 * has a folders API but **no folder screen**. An import that created twenty
 * folders would put every item somewhere the user cannot see, cannot rename and
 * cannot empty, and the only evidence it happened would be items that had
 * apparently vanished from the flat list they do have. A line of text in the
 * note is visible today, survives until a folder screen exists, and costs
 * nothing to undo. Nothing here depends on a screen that does not exist.
 *
 * **A `note` row that carries a password becomes a `login`.** `NoteItem` has no
 * password field, so the alternative is deleting a secret during an operation
 * that ends by telling the user to delete their export file. A note's username
 * and URLs, which also have nowhere to go, are written into the note instead —
 * they are not secrets, and a line of text loses nothing.
 */
export function toItemPlaintext(item: ImportItem, options: MapOptions = {}): ItemPlaintext {
  const folderId = options.folderId ?? null;
  // The password decides, not the declared type: a type is a label the export
  // wrote, and a password is a thing that will stop working if it is dropped.
  const isLogin = item.type === "login" || item.password !== "";

  if (isLogin) {
    return {
      type: "login",
      name: item.name,
      username: item.username,
      // Byte for byte, as every parser preserved it.
      password: item.password,
      urls: [...item.urls],
      notes: composeNotes(item, []),
      favorite: item.favorite,
      folderId,
      passwordHistory: [],
    };
  }

  const carried: string[] = [];
  if (item.username !== "") carried.push(`Username: ${item.username}`);
  for (const url of item.urls) carried.push(`Web address: ${url}`);

  return {
    type: "note",
    name: item.name,
    notes: composeNotes(item, carried),
    favorite: item.favorite,
    folderId,
  };
}

/** Every row of a parse, in file order. */
export function toItemPlaintexts(
  items: readonly ImportItem[],
  options: MapOptions = {},
): ItemPlaintext[] {
  return items.map((item) => toItemPlaintext(item, options));
}

/* -------------------------------------------------------------------------- */
/*                          The generic CSV column map                        */
/* -------------------------------------------------------------------------- */

/**
 * Which column of an unrecognised CSV holds what.
 *
 * Every field is the header's **own spelling** of a column name, so the mapping
 * screen can show the user exactly what it picked, and `null` for a field this
 * file has no column for. Matching against the header is case-insensitive and
 * trimmed, as everywhere else in this directory.
 */
export interface CsvColumnMapping {
  name: string | null;
  username: string | null;
  password: string | null;
  url: string | null;
  notes: string | null;
  folder: string | null;
  /**
   * What the folder column nests with. `/` unless the user says otherwise.
   *
   * A separator rather than a guess, because guessing wrong produces a folder
   * literally named `Personal\Forums` — see `folderSegments`.
   */
  folderSeparator: string;
  /** The column holding a one-time-password seed, carried with kind `totp`. */
  totp: string | null;
  /**
   * Columns carried into `extra` as custom fields, under their own names.
   *
   * `suggestMapping` puts every column it could not place in here rather than
   * leaving it out: a column dropped because nothing recognised its name is
   * still a column dropped, and the user cannot miss what they were never shown.
   */
  custom: readonly string[];
}

/** The candidate names for one field, most likely first. */
const CANDIDATES: Record<string, readonly string[]> = {
  name: ["name", "title", "account", "item name", "entry", "display name"],
  username: ["username", "user name", "login name", "login", "user", "email", "login_username"],
  password: ["password", "login_password", "pass"],
  url: ["url", "uri", "website", "web site", "web address", "login_uri", "site", "link"],
  notes: ["notes", "note", "comments", "comment", "extra", "description"],
  folder: ["folder", "group", "grouping", "category", "path"],
  totp: ["totp", "otpauth", "otp", "otpsecret", "otp secret", "login_totp"],
};

/**
 * A starting mapping for a header no parser recognised.
 *
 * A **suggestion**, never an answer: it is what the mapping screen opens with,
 * and the preview screen is what confirms it. Nothing here can tell a `password`
 * column from a column called `password hint`, and the user can.
 *
 * Every column it could not place becomes a custom field, so a file's odd column
 * ends up in the note rather than nowhere.
 */
export function suggestMapping(header: readonly string[]): CsvColumnMapping {
  const byLower = new Map<string, string>();
  for (const cell of header) {
    const key = cell.trim().toLowerCase();
    // First occurrence wins, as `indexColumns` and `csv.ts` both do.
    if (!byLower.has(key)) byLower.set(key, cell.trim());
  }

  const pick = (field: string): string | null => {
    for (const candidate of CANDIDATES[field] ?? []) {
      const found = byLower.get(candidate);
      if (found !== undefined) return found;
    }
    return null;
  };

  const mapping: CsvColumnMapping = {
    name: pick("name"),
    username: pick("username"),
    password: pick("password"),
    url: pick("url"),
    notes: pick("notes"),
    folder: pick("folder"),
    folderSeparator: "/",
    totp: pick("totp"),
    custom: [],
  };

  const placed = new Set(
    [
      mapping.name,
      mapping.username,
      mapping.password,
      mapping.url,
      mapping.notes,
      mapping.folder,
      mapping.totp,
    ].filter((column): column is string => column !== null),
  );
  mapping.custom = [...byLower.values()].filter((column) => !placed.has(column));

  return mapping;
}

/** `columns.value`, keyed by the mapping's spelling of the name. */
function read(columns: Columns, row: CsvRow, column: string | null): string | undefined {
  return column === null ? undefined : columns.value(row, column.trim().toLowerCase());
}

function genericRow(
  row: CsvRow,
  mapping: CsvColumnMapping,
  columns: Columns,
  width: number,
): RowOutcome {
  const surplus = surplusFieldsError(row, width);
  if (surplus !== null) return surplus;

  const checked = requiredPassword(row, read(columns, row, mapping.password));
  if (typeof checked !== "string") return checked;

  const url = read(columns, row, mapping.url) ?? "";
  const item = blankImportItem(row.line);
  // The URL as the file wrote it, when there is no name column or the cell is
  // empty. An item with no name at all is unfindable in the vault list, and the
  // text the user's own file carried is a better label than an invented one.
  item.name = read(columns, row, mapping.name) || url;
  item.username = read(columns, row, mapping.username) ?? "";
  item.password = checked;
  item.urls = url === "" ? [] : [url];
  item.notes = read(columns, row, mapping.notes) ?? "";
  item.folderPath = folderSegments(
    read(columns, row, mapping.folder) ?? "",
    mapping.folderSeparator,
  );

  const totp = read(columns, row, mapping.totp);
  if (mapping.totp !== null && totp !== undefined && totp !== "") {
    // `totp` because the *user* said this column is a second factor, which is
    // the same kind of evidence a parser has: where the value sat, not what it
    // was called.
    item.extra.push({ name: mapping.totp, value: totp, kind: "totp" });
  }
  for (const column of mapping.custom) {
    const value = read(columns, row, column);
    if (value === undefined || value === "") continue;
    item.extra.push({ name: column, value, kind: "custom" });
  }

  return item;
}

/**
 * Reads a CSV using a mapping the user chose. Never throws.
 *
 * With no mapping it uses `suggestMapping`, which is what an unrecognised file
 * shows on the mapping screen before the user touches anything.
 *
 * **A file with no password column is refused whole**, rather than becoming a
 * vault of items with empty passwords. That is the same rule every parser here
 * obeys, applied one level up: a blank imported over a real password has no
 * undo, and this is the one path where the column choice is a human's.
 */
export function parseGenericCsv(text: string, mapping?: CsvColumnMapping): ImportResult {
  const table = parseCsv(text);
  const chosen = mapping ?? suggestMapping(table.header);
  const columns = indexColumns(table.header);

  if (chosen.password === null) {
    return {
      items: [],
      errors: [
        {
          row: 1,
          message:
            "No column has been chosen as the password, so no row could be imported; " +
            "choose one on the mapping screen",
        },
        ...table.errors,
      ],
    };
  }

  return mapCsvRows(table, (row) => genericRow(row, chosen, columns, table.header.length));
}

/* -------------------------------------------------------------------------- */
/*                       The formats a user can name by hand                  */
/* -------------------------------------------------------------------------- */

/**
 * Every format the user can choose on the mapping screen.
 *
 * **`ImportParser` plus `keeper-csv`.** `ImportParser` is the set of answers
 * *detection* can give, and Keeper's CSV is not one of them: it writes no header
 * row, so there is nothing to sign and `detect` answers `generic-csv` for it
 * forever (see `parsers/keeper.ts`). Adding it to `ImportParser` would mean a
 * detection result that detection can never produce; leaving it out of the
 * picker would make `parseKeeperCsv` unreachable code and leave a Keeper user
 * mapping seven anonymous columns by hand.
 */
export type ManualFormat = ImportParser | "keeper-csv";

/**
 * The formats this function can read from text.
 *
 * `onepassword-1pux` is excluded in the type rather than at runtime: a `.1pux`
 * is a ZIP, so it arrives as bytes and its parser is async. A caller holding one
 * calls `parseOnePassword1pux` directly, and the compiler says so.
 */
export type TextFormat = Exclude<ManualFormat, "onepassword-1pux">;

export interface ManualFormatChoice {
  id: ManualFormat;
  /** What the picker shows. */
  label: string;
  /** Something the user must know before choosing this one. */
  caution?: string;
}

export const MANUAL_FORMATS: readonly ManualFormatChoice[] = [
  { id: "bitwarden-json", label: "Bitwarden (.json)" },
  { id: "bitwarden-csv", label: "Bitwarden (.csv)" },
  { id: "onepassword-1pux", label: "1Password (.1pux)" },
  { id: "onepassword-csv", label: "1Password (.csv)" },
  { id: "lastpass-csv", label: "LastPass (.csv)" },
  { id: "browser-csv", label: "Chrome, Edge, Brave, Firefox or Safari (.csv)" },
  { id: "keepass-csv", label: "KeePass or KeePassXC (.csv)" },
  { id: "nordpass-csv", label: "NordPass (.csv)" },
  { id: "dashlane-json", label: "Dashlane (.json)" },
  { id: "dashlane-csv", label: "Dashlane (.csv)" },
  { id: "protonpass-json", label: "Proton Pass (.json)" },
  { id: "keeper-json", label: "Keeper (.json)" },
  {
    id: "keeper-csv",
    label: "Keeper (.csv)",
    // Stated on the choice itself because it is the one format here whose
    // columns cannot be checked against anything: with no header row, a file
    // whose column order differs from the expected one maps a URL into the
    // password field and reports nothing. The preview screen is the only check
    // there is, so the user has to be told to read it.
    caution:
      "A Keeper CSV has no header row, so its columns are read by position. " +
      "Check the preview carefully: a different column order maps silently wrong.",
  },
  { id: "generic-csv", label: "Something else (choose the columns yourself)" },
];

const TEXT_PARSERS: Record<TextFormat, (text: string) => ImportResult> = {
  "browser-csv": parseBrowserCsv,
  "bitwarden-csv": parseBitwardenCsv,
  "bitwarden-json": parseBitwardenJson,
  "lastpass-csv": parseLastPassCsv,
  "onepassword-csv": parseOnePasswordCsv,
  "keepass-csv": parseKeePassCsv,
  "nordpass-csv": parseNordPassCsv,
  "dashlane-csv": parseDashlaneCsv,
  "dashlane-json": parseDashlaneJson,
  "protonpass-json": parseProtonPassJson,
  "keeper-json": parseKeeperJson,
  "keeper-csv": parseKeeperCsv,
  "generic-csv": parseGenericCsv,
};

/**
 * Reads a file as the format the user named. Never throws.
 *
 * The mapping is read only by `generic-csv`; every other format knows its own
 * columns. Passing one alongside a named vendor format is harmless and ignored.
 */
export function parseText(
  format: TextFormat,
  text: string,
  mapping?: CsvColumnMapping,
): ImportResult {
  if (format === "generic-csv") return parseGenericCsv(text, mapping);
  return TEXT_PARSERS[format](text);
}
