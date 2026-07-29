import { parseCsv, type CsvRow } from "../csv.js";
import { blankImportItem, folderSegments, type ImportResult } from "../types.js";
import {
  carry,
  indexColumns,
  mapCsvRows,
  requiredPassword,
  surplusFieldsError,
  type Columns,
  type RowOutcome,
} from "./shared.js";

/**
 * LastPass's CSV export.
 *
 * `url,username,password,totp,extra,name,grouping,fav` — eight columns whose
 * names are, two of them, actively misleading. `extra` is the note body, not
 * anything extra; `grouping` is the folder. Both are read by name from the
 * header rather than by position, so an export whose columns have been reordered
 * still maps and one whose columns have been renamed fails visibly.
 *
 * ## The `http://sn` marker
 *
 * **A row whose `url` is `http://sn` is a secure note, not a login.** That is
 * LastPass's own marker and it is the only thing in the row that says so: a
 * secure note is exported in exactly the same eight columns as a login, with the
 * note body in `extra` and the login columns empty.
 *
 * Missing it costs the user the note twice. The item would be a login pointing
 * at a host called `sn` — a URL that goes nowhere and that duplicate detection
 * would then match against every other note in the file, since they all share
 * it. And because a note carries no password, the "never guess at a password"
 * rule would refuse the row outright, so every secure note in the export would
 * arrive as an error and none of them as an item.
 *
 * The marker is compared trimmed and lowercased, as column names are: a round
 * trip through a spreadsheet is the ordinary way an export arrives recased, and
 * that must not silently turn every note back into a broken login. The cost is
 * that a real login at a host genuinely called `sn`, with no path, would be read
 * as a note — an intranet host of exactly that name, exported by exactly this
 * product. It is the trade LastPass itself makes, since its own importer cannot
 * tell those apart either.
 *
 * ## The contract (stated in full in the plan, Tasks 3-7)
 *
 * Returns the intermediate shape, never `ItemPlaintext`. **Never throws** — a
 * malformed row comes back as a per-row error beside the rows that parsed.
 * **Never guesses at a password** for a login row. **Preserves the password byte
 * for byte** — nothing here trims or normalizes any value.
 */

/** The column names, lowercased as the header index holds them. */
const COLUMNS = {
  url: "url",
  username: "username",
  password: "password",
  totp: "totp",
  /** LastPass's name for the note body. */
  notes: "extra",
  name: "name",
  /** LastPass's name for the folder. */
  folder: "grouping",
  favorite: "fav",
} as const;

/**
 * The `url` value LastPass writes on a secure note.
 *
 * Lowercased here because the comparison lowercases the row's value too.
 */
const SECURE_NOTE_URL = "http://sn";

/**
 * What LastPass nests folders with.
 *
 * A backslash, which is the reason `folderPath` is segments rather than a
 * string: written through as one name, `Personal\Forums` becomes a folder
 * literally called `Personal\Forums`, and nothing downstream can tell that
 * apart from a folder whose name really does contain a backslash.
 */
const FOLDER_SEPARATOR = "\\";

/** True for the `http://sn` marker, whatever case or padding it arrives in. */
function isSecureNote(url: string | undefined): boolean {
  return (url ?? "").trim().toLowerCase() === SECURE_NOTE_URL;
}

/** LastPass writes `1` for a favourite and `0` for the rest. */
function isFavorite(value: string | undefined): boolean {
  const text = value?.trim().toLowerCase();
  return text === "1" || text === "true";
}

function toItem(row: CsvRow, columns: Columns, width: number): RowOutcome {
  const surplus = surplusFieldsError(row, width);
  if (surplus !== null) return surplus;

  const url = columns.value(row, COLUMNS.url) ?? "";
  const note = isSecureNote(url);

  const item = blankImportItem(row.line);
  item.type = note ? "note" : "login";
  item.name = columns.value(row, COLUMNS.name) ?? "";
  item.notes = columns.value(row, COLUMNS.notes) ?? "";
  item.favorite = isFavorite(columns.value(row, COLUMNS.favorite));
  // An absent or empty cell splits to no segments, which is the root.
  item.folderPath = folderSegments(columns.value(row, COLUMNS.folder) ?? "", FOLDER_SEPARATOR);

  if (note) {
    // The marker is LastPass's flag, not a site. Carrying it as a URL would
    // give every secure note in the export the same meaningless host, which is
    // also the host duplicate detection would then group them all under.
    //
    // A secure note's username and password columns are empty in every export
    // LastPass writes: the note types that have credentials (Server, Database,
    // Email) keep them inside the note body, which is carried whole above.
    return item;
  }

  const password = requiredPassword(row, columns.value(row, COLUMNS.password));
  if (typeof password !== "string") return password;

  item.username = columns.value(row, COLUMNS.username) ?? "";
  // Byte for byte: the value as the reader unescaped it, and nothing else. A
  // trailing space is part of the password.
  item.password = password;
  item.urls = url === "" ? [] : [url];
  // Keyhole has no TOTP field in v1 (spec section 1, non-goals), and dropping
  // the seed silently would lose a second factor the user believes they moved.
  // `totp` is the kind because of where the value sat — LastPass's `totp`
  // column — and not because of what the column is called.
  carry(item, columns.sourceName(COLUMNS.totp), columns.value(row, COLUMNS.totp), "totp");

  return item;
}

/**
 * Reads a LastPass CSV export. Never throws.
 *
 * A file without LastPass's two distinguishing columns comes back as a single
 * error against line 1 with no items — detection routes such a file to the
 * generic column mapper and this parser should never see it, but "never throws"
 * has to hold for the caller that gets the routing wrong too.
 */
export function parseLastPassCsv(text: string): ImportResult {
  const table = parseCsv(text);
  const columns = indexColumns(table.header);

  // `password` and `grouping` together, because `password` alone is half the
  // formats here and `grouping` alone would accept a file with no password
  // column at all — which would then produce one refusal per row rather than
  // one sentence about the file.
  if (!columns.has(COLUMNS.password) || !columns.has(COLUMNS.folder)) {
    return {
      items: [],
      errors: [
        {
          row: 1,
          message:
            "This file has no password and grouping columns, so it is not a LastPass CSV export",
        },
        ...table.errors,
      ],
    };
  }

  return mapCsvRows(table, (row) => toItem(row, columns, table.header.length));
}
