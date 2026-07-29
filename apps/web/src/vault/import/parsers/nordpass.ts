import { parseCsv, type CsvRow } from "../csv.js";
import {
  blankImportItem,
  type ImportItemType,
  type ImportResult,
} from "../types.js";
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
 * NordPass's CSV export.
 *
 * **One row shape for every kind of item.** NordPass writes the same 22 columns
 * for a login, a credit card, a secure note and a piece of personal
 * information — `name,url,additional_urls,username,password,note,
 * cardholdername,cardnumber,cvc,expirydate,zipcode,folder,full_name,
 * phone_number,email,address1,address2,city,country,state,type,custom_fields` —
 * and the `type` column is the only thing that says which one a row is. Fifteen
 * of those columns are empty on every login.
 *
 * That is also why a card row must be **named** rather than skipped. A card has
 * no password, so the "never guess at a password" rule would already refuse it —
 * but with a sentence about an empty password, which sends the user looking for
 * a broken login that does not exist. "Imported 200 of 214" with the other 14
 * named as cards is a count they can act on; "imported 200" from a 214-item file
 * is a number they have no way to check, and that is the kind of loss discovered
 * months later.
 *
 * ## The contract (stated in full in the plan, Tasks 3-7)
 *
 * Returns the intermediate shape, never `ItemPlaintext`. **Never throws.**
 * **Never guesses at a password** for a login row. **Preserves the password byte
 * for byte** — nothing here trims or normalizes any value.
 */

/** The column names, lowercased as the header index holds them. */
const COLUMNS = {
  name: "name",
  url: "url",
  additionalUrls: "additional_urls",
  username: "username",
  password: "password",
  notes: "note",
  folder: "folder",
  type: "type",
  customFields: "custom_fields",
  /** Not read, but named: its presence is what identifies the export. */
  cardholder: "cardholdername",
} as const;

/** The `type` words that map onto one of Keyhole's two kinds. */
const KINDS = new Map<string, ImportItemType>([
  ["password", "login"],
  ["note", "note"],
]);

/**
 * The types Keyhole has no home for, and what to call each one.
 *
 * A word NordPass writes with an underscore reads badly in a sentence, so the
 * ones known here are spelled out. A type not in this map is reported using the
 * export's own word: naming it is what lets the user match the error to a row in
 * their own file, and a generic "unsupported item" cannot be looked up.
 */
const UNSUPPORTED = new Map<string, string>([
  ["credit_card", "credit card"],
  ["identity", "identity"],
]);

/**
 * NordPass folders do not nest, so a folder is one segment and is never split.
 *
 * **Deliberately not `folderSegments`.** Every other format here nests with a
 * character — Bitwarden and KeePassXC with `/`, LastPass and Keeper with `\` —
 * and splits at it. NordPass has a single flat level, so there is no separator,
 * and picking one anyway would turn a folder the user named `Home/Office` into
 * two folders that never existed. The empty case still yields `[]`, which is the
 * root, and the name is not trimmed.
 *
 * This is the behaviour most worth checking against a real export: if NordPass
 * has since gained nested folders, this produces one folder with a separator in
 * its name rather than a tree — visible in the preview screen, and wrong.
 */
function folderOf(value: string | undefined): string[] {
  return value === undefined || value === "" ? [] : [value];
}

/**
 * A login's URLs: the main one, then each line of `additional_urls`.
 *
 * **Split at newlines only.** A newline cannot appear inside a URL; a comma can,
 * and a comma-split would break a URL rather than the list. If NordPass in fact
 * joins them with a comma, a multi-URL login arrives with one wrong URL in the
 * list — visible in the preview screen — rather than with a URL silently cut in
 * half. This is the other behaviour worth checking against a real export.
 */
function urlsOf(main: string, additional: string | undefined): string[] {
  const urls = main === "" ? [] : [main];
  for (const line of (additional ?? "").split("\n")) {
    const url = line.trim();
    // Trimmed because a `\r\n`-terminated cell leaves a `\r` on each line and a
    // leading space breaks a URL. A liberty taken with URLs only, never with
    // the password.
    if (url !== "") urls.push(url);
  }
  return urls;
}

function toItem(row: CsvRow, columns: Columns, width: number): RowOutcome {
  const surplus = surplusFieldsError(row, width);
  if (surplus !== null) return surplus;

  // A row whose type column is absent or blank is read as a login, which is
  // what the remaining columns describe. The guess is safe rather than
  // confident: a card with no type word carries no password either, so the
  // password rule below turns it into a visible error row rather than an item.
  const word = (columns.value(row, COLUMNS.type) ?? "").trim().toLowerCase();
  const kind = word === "" ? "login" : KINDS.get(word);
  if (kind === undefined) {
    const described = UNSUPPORTED.get(word) ?? word;
    return {
      row: row.line,
      message: `This row is a NordPass ${described}, which Keyhole cannot import yet, so it was not imported`,
    };
  }

  const item = blankImportItem(row.line);
  item.type = kind;
  item.name = columns.value(row, COLUMNS.name) ?? "";
  item.notes = columns.value(row, COLUMNS.notes) ?? "";
  item.folderPath = folderOf(columns.value(row, COLUMNS.folder));

  if (kind === "login") {
    const password = requiredPassword(row, columns.value(row, COLUMNS.password));
    if (typeof password !== "string") return password;
    item.username = columns.value(row, COLUMNS.username) ?? "";
    // Byte for byte: the value as the reader unescaped it, and nothing else.
    item.password = password;
    item.urls = urlsOf(
      columns.value(row, COLUMNS.url) ?? "",
      columns.value(row, COLUMNS.additionalUrls),
    );
  }

  // NordPass flattens a login's custom fields into one cell. Carried whole
  // rather than split back apart, because nothing in the cell says which
  // separator it used and a wrong guess would split a value silently — the same
  // reasoning `bitwarden.ts` applies to its CSV's `fields` column. `custom`
  // because it is the user's own fields, whatever shape they arrive in.
  carry(
    item,
    columns.sourceName(COLUMNS.customFields),
    columns.value(row, COLUMNS.customFields),
    "custom",
  );

  return item;
}

/**
 * Reads a NordPass CSV export. Never throws.
 *
 * A file without NordPass's two distinguishing columns comes back as a single
 * error against line 1 with no items — detection routes such a file to the
 * generic column mapper and this parser should never see it, but "never throws"
 * has to hold for the caller that gets the routing wrong too.
 */
export function parseNordPassCsv(text: string): ImportResult {
  const table = parseCsv(text);
  const columns = indexColumns(table.header);

  // `cardholdername` alongside `password`, because it is present in every
  // NordPass export whatever the vault holds — NordPass writes one row shape —
  // and it is the column no other format here has. `password` alone would
  // accept most of the CSVs in this project.
  if (!columns.has(COLUMNS.password) || !columns.has(COLUMNS.cardholder)) {
    return {
      items: [],
      errors: [
        {
          row: 1,
          message:
            "This file has no password and cardholdername columns, so it is not a NordPass CSV export",
        },
        ...table.errors,
      ],
    };
  }

  return mapCsvRows(table, (row) => toItem(row, columns, table.header.length));
}
