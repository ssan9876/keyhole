import { parseCsv, type CsvRow } from "../csv.js";
import {
  blankImportItem,
  type ImportItem,
  type ImportItemType,
  type ImportResult,
  type ImportRowError,
} from "../types.js";
import {
  carry,
  indexColumns,
  isRowError,
  mapCsvRows,
  requiredPassword,
  surplusFieldsError,
  type Columns,
  type RowOutcome,
} from "./shared.js";

/**
 * Dashlane's two exports: the credentials CSV and the JSON.
 *
 * ## What is confident here and what is not
 *
 * `dashlane-credentials.csv` is one of Task 2's **reconstructions**. Bitwarden's
 * own importer confirms the column *set* — `title, note, username, password,
 * url, otpSecret, category` — but `username2` and `username3`, and the order of
 * all nine, come from weaker sources. Every lookup below is therefore **by
 * column name**: against a wrong reconstruction a name lookup finds nothing and
 * produces a visible error row, where positional access would put a password
 * into the note field of a real export and report nothing at all.
 *
 * ## The ZIP
 *
 * Dashlane's "export to CSV" downloads a **ZIP holding several CSVs** —
 * `credentials.csv` beside `securenotes.csv`, `payments.csv`, `ids.csv` and
 * `personalInfo.csv`. This file handles `credentials.csv`'s contents, which is
 * what the plan asks for; **reading the archive is Task 6's question**, since
 * that task owns the `.1pux` ZIP reader and nothing in this repo can open one
 * yet. What is written down about it is in the task report — including the part
 * that is not shared with `.1pux`: a `.1pux` holds one `export.data`, so
 * finding the member is trivial, whereas a Dashlane archive holds five files of
 * which one is logins and the rest are item kinds that need their own parsers or
 * their own error rows.
 *
 * The JSON export is a single file and needs none of that, which is the reason
 * to prefer it and the reason it is implemented here in full.
 *
 * ## The contract (stated in full in the plan, Tasks 3-7)
 *
 * Returns the intermediate shape, never `ItemPlaintext`. **Never throws** — a
 * malformed row or record comes back as a per-row error beside the ones that
 * parsed, and that includes a file that is not JSON at all. **Never guesses at a
 * password.** **Preserves the password byte for byte.**
 *
 * ## What `sourceRow` means
 *
 * For the CSV it is the line, straight from the reader. **A JSON export has no
 * rows**, so it is the record's 1-based position counted across every list in
 * the order below, and every JSON message names the list and the position within
 * it — `AUTHENTIFIANT item 3 ("Example Mail")` — because that is what a user can
 * actually search a Dashlane export for. A line number would need byte offsets
 * `JSON.parse` does not report.
 */

/* -------------------------------------------------------------------------- */
/*                                     CSV                                    */
/* -------------------------------------------------------------------------- */

/** The credentials CSV's column names, lowercased as the header index holds them. */
const CSV_COLUMNS = {
  username: "username",
  /** Dashlane lets one credential carry three logins. */
  username2: "username2",
  username3: "username3",
  title: "title",
  password: "password",
  notes: "note",
  url: "url",
  folder: "category",
  totp: "otpsecret",
} as const;

/**
 * A Dashlane category is one flat name, so it is one segment and is never split.
 *
 * Deliberately not `folderSegments`: Dashlane has no nested categories, so there
 * is no separator, and choosing one anyway would turn a category the user named
 * `Home/Office` into two folders that never existed. The empty case is still
 * `[]`, which is the root, and the name is not trimmed.
 */
function folderOf(value: string | undefined): string[] {
  return value === undefined || value === "" ? [] : [value];
}

function csvItem(row: CsvRow, columns: Columns, width: number): RowOutcome {
  const surplus = surplusFieldsError(row, width);
  if (surplus !== null) return surplus;

  const password = requiredPassword(row, columns.value(row, CSV_COLUMNS.password));
  if (typeof password !== "string") return password;

  const url = columns.value(row, CSV_COLUMNS.url) ?? "";
  const item = blankImportItem(row.line);
  item.name = columns.value(row, CSV_COLUMNS.title) ?? "";
  item.username = columns.value(row, CSV_COLUMNS.username) ?? "";
  // Byte for byte: the value as the reader unescaped it, and nothing else.
  item.password = password;
  item.urls = url === "" ? [] : [url];
  item.notes = columns.value(row, CSV_COLUMNS.notes) ?? "";
  item.folderPath = folderOf(columns.value(row, CSV_COLUMNS.folder));

  // Only the first login can be the item's username. The other two are
  // sign-ins the user believes they moved, so they are carried rather than
  // dropped — `custom`, because they are the user's own data rather than
  // Dashlane's record-keeping, and the preview screen should warn about losing
  // them in those terms.
  for (const column of [CSV_COLUMNS.username2, CSV_COLUMNS.username3]) {
    carry(item, columns.sourceName(column), columns.value(row, column), "custom");
  }
  // `totp` from where the value sat — Dashlane's `otpSecret` column — and not
  // from what the column is called. Keyhole has no TOTP field in v1.
  carry(
    item,
    columns.sourceName(CSV_COLUMNS.totp),
    columns.value(row, CSV_COLUMNS.totp),
    "totp",
  );

  return item;
}

/**
 * Reads Dashlane's `credentials.csv`. Never throws.
 *
 * A file without both distinguishing columns comes back as a single error
 * against line 1 with no items — detection routes such a file elsewhere and this
 * parser should never see it, but "never throws" has to hold for the caller that
 * gets the routing wrong too.
 */
export function parseDashlaneCsv(text: string): ImportResult {
  const table = parseCsv(text);
  const columns = indexColumns(table.header);

  if (!columns.has(CSV_COLUMNS.title) || !columns.has(CSV_COLUMNS.password)) {
    return {
      items: [],
      errors: [
        {
          row: 1,
          message:
            "This file has no title and password columns, so it is not a Dashlane credentials CSV",
        },
        ...table.errors,
      ],
    };
  }

  return mapCsvRows(table, (row) => csvItem(row, columns, table.header.length));
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
 * Deliberately not a stringifier: `note` is `null` on most records, and
 * `String(null)` would put the word "null" in the user's vault.
 */
function stringOf(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/** One of Dashlane's record lists, and what its records become. */
interface RecordList {
  /** The root key, which is also what an error names so the user can find it. */
  readonly key: string;
  /** The kind its records become, or `null` for one Keyhole cannot store. */
  readonly kind: ImportItemType | null;
  /** What to call this kind in the sentence that refuses it. */
  readonly described: string;
}

/**
 * Every list Dashlane writes, in the order they are numbered.
 *
 * The unsupported ones are here rather than ignored so their records become
 * **named error rows**: "imported 200 of 214" with the other 14 explained is a
 * count the user can act on, where "imported 200" from a 214-record file is a
 * number they have no way to check.
 */
const RECORD_LISTS: readonly RecordList[] = [
  { key: "AUTHENTIFIANT", kind: "login", described: "login" },
  { key: "SECURENOTE", kind: "note", described: "secure note" },
  { key: "PAYMENTMEANS_CREDITCARD", kind: null, described: "credit card" },
  { key: "PAYMENTMEAN_PAYPAL", kind: null, described: "PayPal account" },
  { key: "BANKSTATEMENT", kind: null, described: "bank account" },
  { key: "ADDRESS", kind: null, described: "address" },
  { key: "IDCARD", kind: null, described: "identity document" },
  { key: "IDENTITY", kind: null, described: "identity" },
  { key: "EMAIL", kind: null, described: "email account" },
];

/**
 * A record's display title.
 *
 * `title` for a credential or a note; `name` for the record kinds that use it,
 * so a card's error still names the card rather than saying nothing.
 */
function titleOf(source: Record<string, unknown>): string {
  const title = stringOf(source["title"]);
  return title === "" ? stringOf(source["name"]) : title;
}

/** One record, as an item or as the reason it is not one. */
function jsonRecord(
  raw: unknown,
  list: RecordList,
  at: number,
  position: number,
): RowOutcome {
  // The list and the position within it, because that is what a user can search
  // their own export for; `position` is the number that orders the report and is
  // unique across every list.
  const source = asObject(raw);
  const title = source === null ? "" : titleOf(source);
  const label =
    title === "" ? `${list.key} item ${at}` : `${list.key} item ${at} ("${title}")`;

  if (source === null) {
    return { row: position, message: `${label} is not an object, so it could not be read` };
  }

  if (list.kind === null) {
    return {
      row: position,
      message:
        `${label} is a Dashlane ${list.described}, which Keyhole cannot import yet, ` +
        "so it was not imported",
    };
  }

  const item = blankImportItem(position);
  item.type = list.kind;
  item.name = title;

  if (list.kind === "note") {
    // A Dashlane secure note keeps its text in `content`, not in `note`.
    item.notes = stringOf(source["content"]);
    return item;
  }

  const password = source["password"];
  // Absent and empty are different answers and both are refusals: absent is a
  // damaged export, empty is Dashlane saying there is no password here. Neither
  // is an item, because a blank imported over a real password cannot be
  // recovered from an export the user has been told to delete.
  if (typeof password !== "string") {
    return { row: position, message: `${label} has no password, so it was not imported` };
  }
  if (password === "") {
    return { row: position, message: `${label} has an empty password, so it was not imported` };
  }

  // Dashlane keeps a credential's `login` and `email` in separate fields and a
  // record can carry both. Keyhole has one username, so the other is carried
  // rather than dropped — and only when it is not already the username, or
  // every ordinary record would report the same value twice.
  const login = stringOf(source["login"]);
  const email = stringOf(source["email"]);
  item.username = login === "" ? email : login;
  item.password = password;
  item.notes = stringOf(source["note"]);
  item.folderPath = folderOf(stringOf(source["category"]));

  // `url` when the record has one; `domain` is the bare host Dashlane also
  // writes, and is what the export said even though it is not a URL. Inventing
  // a scheme for it would be this layer claiming something the file does not.
  const url = stringOf(source["url"]) || stringOf(source["domain"]);
  if (url !== "") item.urls = [url];

  if (email !== "" && email !== item.username) {
    carry(item, "email", email, "custom");
  }
  carry(item, "otpSecret", stringOf(source["otpSecret"]), "totp");

  return item;
}

/** Reads a Dashlane JSON export. Never throws. */
export function parseDashlaneJson(text: string): ImportResult {
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
  const present = RECORD_LISTS.filter((list) => Array.isArray(root?.[list.key]));
  if (present.length === 0) {
    return {
      items: [],
      errors: [
        {
          row: 1,
          message:
            "This file has none of Dashlane's record lists, so it is not a Dashlane JSON export",
        },
      ],
    };
  }

  const items: ImportItem[] = [];
  const errors: ImportRowError[] = [];
  let position = 0;

  for (const list of present) {
    const records = root?.[list.key];
    if (!Array.isArray(records)) continue;
    records.forEach((raw, index) => {
      position += 1;
      const outcome = jsonRecord(raw, list, index + 1, position);
      if (isRowError(outcome)) {
        errors.push(outcome);
      } else {
        items.push(outcome);
      }
    });
  }

  return { items, errors };
}
