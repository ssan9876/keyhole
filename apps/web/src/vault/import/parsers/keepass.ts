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
 * The two KeePass CSV exports: KeePass 2's "KeePass CSV (1.x)" and KeePassXC's
 * own.
 *
 * Two products, two column layouts, one parser — the arrangement `browser.ts`
 * proved for the five browsers, and for the same reason: `detect.ts` answers
 * `keepass-csv` for both, so the import flow calls one function, and the layout
 * is chosen from the header rather than from the vendor. They share not one
 * column name:
 *
 * - **KeePass 1.x:** `"Account","Login Name","Password","Web Site","Comments"`
 * - **KeePassXC:** `"Group","Title","Username","Password","URL","Notes","TOTP",
 *   "Icon","Last Modified","Created"`
 *
 * Sharing nothing is what makes one table safe: no file can match both
 * fingerprints, so choosing by header is unambiguous, and the two mappings sit
 * beside each other where the difference is visible rather than in two files
 * where it has to be remembered.
 *
 * ## The `Root/` decision
 *
 * KeePassXC's `Group` is a `/`-separated path and it usually begins `Root/`.
 * **The leading segment is kept.** A KeePassXC user will therefore see a folder
 * called `Root` wrapping their whole import, and that is the lesser cost:
 *
 * - `Root` is the *default* name of the database's root group, not a fixed one.
 *   The user can rename it, and a database converted from KeePass 1.x often has
 *   it named after the file. So a rule that strips a segment because it is
 *   spelled "Root" deletes a real folder in one database and nothing at all in
 *   another — it is exactly the name-matching rule `types.ts` warns against,
 *   where the label is treated as evidence.
 * - Stripping the first segment *unconditionally* is worse: it would flatten a
 *   real top-level folder for any export that does not include the root group,
 *   and nothing in the file says which kind it is.
 * - The two failures are not symmetrical. An extra `Root` folder is visible in
 *   the preview screen and the user can move things out of it. A folder deleted
 *   here is gone before anything downstream can ask about it.
 *
 * Offering to drop a common leading segment belongs to the mapper (Task 8),
 * where the user can see what it would do and say yes.
 *
 * ## The contract (stated in full in the plan, Tasks 3-7)
 *
 * Returns the intermediate shape, never `ItemPlaintext`. **Never throws.**
 * **Never guesses at a password.** **Preserves the password byte for byte** —
 * nothing here trims or normalizes any value.
 */

/** One export's column names, and where each one belongs in an `ImportItem`. */
interface KeePassLayout {
  /** Names the layout in a comment or a test; not shown to the user. */
  readonly id: "keepassxc" | "keepass-1x";
  /**
   * The columns that must all be present for this layout to fit the file.
   *
   * A subset test, so the optional trailing columns KeePassXC has gained over
   * the years (`TOTP`, `Icon`, the two timestamps) are neither required nor in
   * the way. The two layouts share no column name at all, so a file can match
   * at most one of them however loose each test is.
   */
  readonly fingerprint: readonly string[];
  /** The `/`-separated group path, or `null` for an export with no folders. */
  readonly folder: string | null;
  readonly name: string;
  readonly username: string;
  readonly password: string;
  readonly url: string;
  readonly notes: string;
  /** The TOTP column, or `null` for an export that has none. */
  readonly totp: string | null;
}

/**
 * Both layouts, KeePassXC first.
 *
 * Order decides nothing here — the fingerprints are disjoint — but the more
 * specific one is first so that a fingerprint broadened by accident produces a
 * wrong answer somewhere a test looks rather than being masked.
 */
const LAYOUTS: readonly KeePassLayout[] = [
  {
    id: "keepassxc",
    fingerprint: ["group", "title", "username", "password", "url", "notes"],
    folder: "group",
    name: "title",
    username: "username",
    password: "password",
    url: "url",
    notes: "notes",
    totp: "totp",
  },
  {
    id: "keepass-1x",
    fingerprint: ["account", "login name", "password", "web site", "comments"],
    // KeePass 1.x's CSV carries no group column at all, so every item is at the
    // root. That is the format rather than a loss: the export does not say
    // which group an entry was in, so there is nothing to carry.
    folder: null,
    name: "account",
    username: "login name",
    password: "password",
    url: "web site",
    notes: "comments",
    totp: null,
  },
];

/**
 * What KeePassXC nests groups with.
 *
 * A forward slash, and the reason `folderPath` is segments: written through as
 * one name, `Root/Personal` becomes a folder literally called `Root/Personal`.
 */
const FOLDER_SEPARATOR = "/";

/**
 * KeePassXC's `Icon`, `Last Modified` and `Created` columns are dropped, and
 * that is a decision rather than an oversight.
 *
 * None is anything the user typed. An icon index and two timestamps are
 * KeePassXC's own record-keeping and mean nothing outside its database;
 * carrying them would put three lines of noise in the note of every imported
 * item, which is not preservation. `TOTP` is different — it is a secret the
 * user will notice the absence of — and it is carried.
 */
function toItem(row: CsvRow, layout: KeePassLayout, columns: Columns, width: number): RowOutcome {
  const surplus = surplusFieldsError(row, width);
  if (surplus !== null) return surplus;

  const password = requiredPassword(row, columns.value(row, layout.password));
  if (typeof password !== "string") return password;

  const url = columns.value(row, layout.url) ?? "";
  const item = blankImportItem(row.line);
  item.name = columns.value(row, layout.name) ?? "";
  item.username = columns.value(row, layout.username) ?? "";
  // Byte for byte: the value as the reader unescaped it, and nothing else.
  item.password = password;
  item.urls = url === "" ? [] : [url];
  item.notes = columns.value(row, layout.notes) ?? "";
  // An absent column, or an empty cell, splits to no segments — the root.
  item.folderPath = folderSegments(
    columns.value(row, layout.folder) ?? "",
    FOLDER_SEPARATOR,
  );

  if (layout.totp !== null) {
    // `kind` from where the value sat: KeePassXC's TOTP column holds the seed
    // itself. Keyhole has no TOTP field in v1 (spec section 1, non-goals).
    carry(
      item,
      columns.sourceName(layout.totp),
      columns.value(row, layout.totp),
      "totp",
    );
  }

  return item;
}

/**
 * Reads either KeePass CSV export. Never throws.
 *
 * A file neither layout fits comes back as a single error against line 1 with
 * no items — detection routes such a file to the generic column mapper and this
 * parser should never see it, but "never throws" has to hold for the caller that
 * gets the routing wrong too.
 */
export function parseKeePassCsv(text: string): ImportResult {
  const table = parseCsv(text);
  const columns = indexColumns(table.header);
  const layout = LAYOUTS.find((candidate) =>
    candidate.fingerprint.every((column) => columns.has(column)),
  );

  if (layout === undefined) {
    return {
      items: [],
      errors: [
        {
          row: 1,
          message:
            "This file matches neither the KeePass 1.x nor the KeePassXC column names, " +
            "so it is not a KeePass CSV export",
        },
        ...table.errors,
      ],
    };
  }

  return mapCsvRows(table, (row) => toItem(row, layout, columns, table.header.length));
}
