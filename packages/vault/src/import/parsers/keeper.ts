import { parseCsvRecords, type CsvRecord } from "../csv.js";
import {
  blankImportItem,
  folderSegments,
  type ImportItem,
  type ImportResult,
  type ImportRowError,
} from "../types.js";
import { carry, isRowError, mapCsvRows, requiredPassword, type RowOutcome } from "./shared.js";

/**
 * Keeper's two exports: the JSON one, and the CSV with **no header row**.
 *
 * ## Why the CSV is different from every other parser here
 *
 * Keeper writes no header line. The first line of the file is a credential, so
 * handing it to `parseCsv` costs the user their first login — read as the column
 * names — and costs it silently, because a row of credentials is a perfectly
 * well-formed header. That is why this file reads `parseCsvRecords` instead,
 * which treats no record as a header.
 *
 * Two consequences follow, and both matter to whoever builds the import screen:
 *
 * 1. **A Keeper CSV cannot be detected.** Task 2 established this: there is no
 *    header to sign, so `detect` answers `generic-csv` for it and always will.
 *    A Keeper CSV import can therefore only ever be reached by the **user
 *    explicitly choosing the format**, which the generic-CSV mapper in Task 8
 *    must let them do. Without that, `parseKeeperCsv` is unreachable code and a
 *    Keeper user is stuck mapping seven anonymous columns by hand.
 * 2. **It is positional, and that cannot be made safe.** Every other parser here
 *    looks columns up by name, so a wrong guess about the layout produces a
 *    visible error rather than a mis-mapped password. Keeper has no names to
 *    look up. If the real column order differs from the one below, a record
 *    shorter than four fields is still refused — the password position is
 *    genuinely absent — but a record of full width is mapped **silently wrong**:
 *    a URL stored as a password, a password stored as a note. There is no check
 *    that can tell those apart, because there is nothing in the file to check
 *    against. The order below is Bitwarden's importer's, recorded in Task 2's
 *    report; it is the strongest evidence available and it is still evidence
 *    about somebody else's code.
 *
 * ## The contract (stated in full in the plan, Tasks 3-7)
 *
 * Returns the intermediate shape, never `ItemPlaintext`. **Never throws.**
 * **Never guesses at a password.** **Preserves the password byte for byte.**
 */

/* -------------------------------------------------------------------------- */
/*                                     CSV                                    */
/* -------------------------------------------------------------------------- */

/**
 * The fixed column order, from Bitwarden's `keeper-csv-importer.ts` as recorded
 * in `.superpowers/sdd/task-2-report.md`: folder, title, login, password, URL,
 * notes, then alternating custom-field name and value for as many as the record
 * has.
 */
const FOLDER = 0;
const TITLE = 1;
const LOGIN = 2;
const PASSWORD = 3;
const URL = 4;
const NOTES = 5;
/** Everything from here on is `name,value` pairs. */
const CUSTOM_FIELDS = 6;

/**
 * What Keeper nests folders with.
 *
 * A backslash, as LastPass uses. Worth confirming against a real export: if
 * Keeper in fact nests with `/`, a subfolder arrives as one folder with a slash
 * in its name — visible in the preview screen, and wrong.
 */
const FOLDER_SEPARATOR = "\\";

/** `values[at]`, or `undefined` for a record that ended before reaching it. */
function at(record: CsvRecord, position: number): string | undefined {
  return record.values[position];
}

/**
 * The custom fields written after the notes column, as `name,value` pairs.
 *
 * A pair whose value is missing — an odd number of trailing columns — is kept
 * with an empty value rather than dropped, which is why `carry` is not used
 * here: `carry` skips an empty value, and in a positional format the *name* is
 * itself evidence that a field was there. A pair that is empty on both sides is
 * a trailing comma and is skipped, since carrying it would put a nameless,
 * valueless entry on the item.
 */
function carryCustomFields(item: ImportItem, record: CsvRecord): void {
  const trailing = record.values.slice(CUSTOM_FIELDS);
  for (let index = 0; index < trailing.length; index += 2) {
    const name = trailing[index] ?? "";
    const value = trailing[index + 1] ?? "";
    if (name === "" && value === "") continue;
    item.extra.push({ name: name === "" ? "(unnamed field)" : name, value, kind: "custom" });
  }
}

function csvRecord(record: CsvRecord): RowOutcome {
  // No surplus-fields check, because there is no header to have a width. Every
  // column past the sixth is a custom field, which is the format rather than
  // damage — and it is also why an unquoted comma in a Keeper password is
  // undetectable here: the split halves simply become a custom field.
  const password = requiredPassword(record, at(record, PASSWORD));
  if (typeof password !== "string") return password;

  const url = at(record, URL) ?? "";
  const item = blankImportItem(record.line);
  item.name = at(record, TITLE) ?? "";
  item.username = at(record, LOGIN) ?? "";
  // Byte for byte: the value as the reader unescaped it, and nothing else.
  item.password = password;
  item.urls = url === "" ? [] : [url];
  item.notes = at(record, NOTES) ?? "";
  item.folderPath = folderSegments(at(record, FOLDER) ?? "", FOLDER_SEPARATOR);
  carryCustomFields(item, record);

  return item;
}

/**
 * Reads a Keeper CSV export, which has no header row. Never throws.
 *
 * Reachable only when the user names the format: see the note at the top of this
 * file. An empty file is no items and no errors, which is the honest answer —
 * there is no header whose absence could be reported.
 */
export function parseKeeperCsv(text: string): ImportResult {
  return mapCsvRows(parseCsvRecords(text), csvRecord);
}

/* -------------------------------------------------------------------------- */
/*                                    JSON                                    */
/* -------------------------------------------------------------------------- */

/**
 * The `custom_fields` key Keeper reserves for a record's one-time-password seed.
 *
 * A `$` prefix is reserved, so the user cannot create a field of this name
 * themselves — which makes it a position rather than a label, and `totp` the
 * right kind. A field the user named `oneTimeCode` is a different thing and
 * stays `custom`, which is the distinction `ImportFieldKind` exists for.
 */
const TOTP_FIELD = "$oneTimeCode";

function asObject(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringOf(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/**
 * Every folder path a record claims, personal and shared alike.
 *
 * A Keeper record can be filed in more than one folder at once. Keyhole's item
 * has one, so the first is taken and the rest are recorded in `extra` — dropping
 * them would lose grouping the user can see in Keeper today.
 */
function foldersOf(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const paths: string[] = [];
  for (const entry of value) {
    const folder = asObject(entry);
    if (folder === null) continue;
    const path = stringOf(folder["folder"]) || stringOf(folder["shared_folder"]);
    if (path !== "") paths.push(path);
  }
  return paths;
}

/** Carries `custom_fields`, which Keeper writes as an object of name to value. */
function carryCustomObject(item: ImportItem, value: unknown): void {
  const fields = asObject(value);
  if (fields === null) return;
  for (const [name, content] of Object.entries(fields)) {
    carry(item, name, stringOf(content), name === TOTP_FIELD ? "totp" : "custom");
  }
}

/** One record of the `records` array, as an item or the reason it is not one. */
function jsonRecord(raw: unknown, position: number): RowOutcome {
  const source = asObject(raw);
  if (source === null) {
    return {
      row: position,
      message: `Record ${position} is not an object, so it could not be read`,
    };
  }

  const title = stringOf(source["title"]);
  const label = title === "" ? `Record ${position}` : `Record ${position} ("${title}")`;

  const password = source["password"];
  // Absent and empty are different answers and both are refusals: absent is a
  // damaged export, empty is Keeper saying there is no password here.
  if (typeof password !== "string") {
    return { row: position, message: `${label} has no password, so it was not imported` };
  }
  if (password === "") {
    return { row: position, message: `${label} has an empty password, so it was not imported` };
  }

  const item = blankImportItem(position);
  item.name = title;
  item.username = stringOf(source["login"]);
  // Byte for byte: the string `JSON.parse` produced and nothing else.
  item.password = password;
  item.notes = stringOf(source["notes"]);

  const url = stringOf(source["login_url"]);
  if (url !== "") item.urls = [url];

  const [first, ...rest] = foldersOf(source["folders"]);
  if (first !== undefined) item.folderPath = folderSegments(first, FOLDER_SEPARATOR);
  carry(item, "folders", rest.join(", "), "metadata");

  carryCustomObject(item, source["custom_fields"]);

  return item;
}

/**
 * Reads a Keeper JSON export. Never throws.
 *
 * `keeper-export.json` is the **lowest-confidence fixture in the set** — Task 2
 * recorded it as Keeper Commander's shape from memory, verified against no
 * source. Every field below is read by name, so a wrong reconstruction produces
 * an empty item or a visible refusal rather than a mis-mapped password, but the
 * shape itself wants checking against a real export.
 */
export function parseKeeperJson(text: string): ImportResult {
  let body: unknown;
  try {
    body = JSON.parse(text) as unknown;
  } catch {
    return {
      items: [],
      errors: [{ row: 1, message: "This file is not valid JSON, so nothing could be read from it" }],
    };
  }

  const records = asObject(body)?.["records"];
  if (!Array.isArray(records)) {
    return {
      items: [],
      errors: [
        { row: 1, message: "This file has no records array, so it is not a Keeper JSON export" },
      ],
    };
  }

  const items: ImportItem[] = [];
  const errors: ImportRowError[] = [];

  records.forEach((raw, index) => {
    const outcome = jsonRecord(raw, index + 1);
    if (isRowError(outcome)) {
      errors.push(outcome);
    } else {
      items.push(outcome);
    }
  });

  return { items, errors };
}
