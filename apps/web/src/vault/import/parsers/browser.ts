import { parseCsv, type CsvRow } from "../csv.js";
import {
  blankImportItem,
  type ImportFieldKind,
  type ImportItem,
  type ImportResult,
  type ImportRowError,
} from "../types.js";

/**
 * The password export of every browser Keyhole reads: Chrome, Edge, Brave,
 * Firefox and Safari.
 *
 * Five products, **three column layouts**, one parser. Chrome, Edge and Brave
 * ship Chromium's exporter unchanged and emit byte-identical files; Firefox and
 * Safari each write their own header. Treating them as five formats would be
 * five copies of one mapping, and the copies would drift.
 *
 * ## What decides which layout is used
 *
 * The header, by column *name*. Not the detected vendor, and not position:
 *
 * - **Not the vendor**, because `detect` legitimately answers "chrome, edge or
 *   brave" for a renamed download, so there are files where the vendor is not a
 *   single value at all. The header is unambiguous where the vendor is not, and
 *   it keeps this a pure function of the file's text.
 * - **Not position**, because `safari-passwords.csv` is a reconstruction — Task
 *   2 confirmed Safari's column *set* from Bitwarden's importer but found no
 *   source quoting the header line, so its order is a guess. Positional access
 *   against a wrong guess puts a password into the notes field of a real export
 *   and reports nothing; name lookup against a wrong guess fails to find the
 *   column and produces a visible error row instead.
 *
 * Names are matched lowercased and trimmed, as `detect` matches them, so an
 * export that has been through a spreadsheet still maps.
 *
 * ## The contract (stated in full in the plan, Tasks 3-7)
 *
 * Returns the intermediate shape, never `ItemPlaintext`. **Never throws** — a
 * malformed row comes back as a per-row error beside the rows that parsed.
 * **Never guesses at a password**: absent, empty, or from a row the CSV reader
 * flagged as damaged is an error row, never an item with a blank password,
 * because a blank imported over a real password has no undo and the user is
 * about to be told to delete the export. **Preserves the password byte for
 * byte** — nothing here trims or normalizes any value.
 *
 * Rows for the same host with different usernames are separate items.
 * Deduplication belongs to `dedupe.ts`, which reports rather than merges; a
 * parser that collapsed them would delete one of the user's two accounts before
 * anything downstream could ask about it.
 */

/** One export's column names, and where each one belongs in an `ImportItem`. */
interface BrowserLayout {
  /** Names the layout in a comment or a test; not shown to the user. */
  readonly id: "firefox" | "safari" | "chromium";
  /**
   * The columns that must all be present for this layout to fit the file.
   *
   * A **subset** test, and deliberately looser than `detect.ts`, which matches a
   * browser export's header by its whole column set. Extra columns are ignored
   * and absent optional ones tolerated: Chrome only grew its `note` column
   * around 2023, and older exports stop at `password`.
   *
   * That looseness is safe because of what actually separates the three, which
   * is not the strictness of the test: Chromium exports a `name` column, Safari
   * a `title`, Firefox neither, and no browser export here carries two of those.
   * So a file `detect` routes to this parser is claimed by exactly one layout.
   * (A 1Password CSV would match the Safari layout on `title, url, username,
   * password` — detection sends it elsewhere, which is why this is stated as the
   * reason rather than left to be inferred from the fingerprints.)
   */
  readonly fingerprint: readonly string[];
  /**
   * The column holding a display name, or `null` for an export that has none.
   *
   * Firefox is the `null`: it exports no name column at all, so every Firefox
   * item's name is **derived** from its URL rather than exported. See `hostOf`.
   */
  readonly name: string | null;
  readonly url: string;
  readonly username: string;
  readonly password: string;
  /** The user's own free text, or `null` where the export has no such column. */
  readonly notes: string | null;
  /**
   * Columns holding something Keyhole has no field for, carried into `extra`
   * under the header's own spelling of the name.
   *
   * `extra` rather than the note, for both of these, because `types.ts` makes
   * `extra` the channel the mapper appends to the note *from* and the preview
   * screen lists "what will not survive" *from*. Writing them into `notes` here
   * would produce the same note and destroy the second use: nothing downstream
   * could tell a TOTP secret from a sentence the user typed.
   *
   * The `kind` is declared here, per column, rather than derived from the name
   * at the point of carrying — which is what `types.ts` asks of every parser: a
   * field is what its position in the file says it is, and this layout table is
   * where this parser records what it knows about its own columns.
   */
  readonly carry: readonly { readonly column: string; readonly kind: ImportFieldKind }[];
}

/**
 * Every layout, most specific first.
 *
 * Firefox first because its fingerprint is the longest; the three are mutually
 * exclusive in practice (Firefox has neither `name` nor `title`, and no export
 * here has both), so order only decides an answer for a header no browser
 * writes.
 */
const LAYOUTS: readonly BrowserLayout[] = [
  {
    id: "firefox",
    fingerprint: ["url", "username", "password", "httprealm", "formactionorigin", "guid"],
    name: null,
    url: "url",
    username: "username",
    password: "password",
    notes: null,
    /**
     * `httpRealm` is carried; `formActionOrigin`, `guid`, `timeCreated`,
     * `timeLastUsed` and `timePasswordChanged` are dropped, and that is a
     * decision rather than an oversight.
     *
     * None of the six is anything the user typed. `httpRealm` is at least
     * *about* the login — it names the HTTP-auth realm the password unlocks,
     * it is set on a minority of rows, and it is the one a user could look at
     * and recognise. The other five are Firefox's own record-keeping: a
     * `formActionOrigin` restates the URL on nearly every row, and a guid and
     * three timestamps mean nothing outside Firefox's own database. Carrying
     * them would put five lines of noise in the note of every imported item,
     * which is not preservation.
     *
     * `metadata`, not `custom`: it is Firefox's record of the HTTP-auth realm,
     * not something the user typed, and the preview screen should not warn about
     * losing it in the same words it warns about losing their own fields.
     */
    carry: [{ column: "httprealm", kind: "metadata" }],
  },
  {
    id: "safari",
    fingerprint: ["title", "url", "username", "password"],
    name: "title",
    url: "url",
    username: "username",
    password: "password",
    notes: "notes",
    /**
     * Safari's `OTPAuth` column holds a TOTP secret, and Keyhole has no TOTP
     * field in v1 (spec section 1, non-goals). Dropping it silently would lose
     * a second factor the user believes they moved, and they would find out
     * when they could no longer sign in.
     *
     * `totp` is the kind whatever the column happens to be spelled: Safari
     * writes `OTPAuth`, Bitwarden writes `totp`, Dashlane writes `otpSecret`,
     * and the point of the kind is that nothing downstream has to know that.
     */
    carry: [{ column: "otpauth", kind: "totp" }],
  },
  {
    id: "chromium",
    fingerprint: ["name", "url", "username", "password"],
    name: "name",
    url: "url",
    username: "username",
    password: "password",
    notes: "note",
    carry: [],
  },
];

/** The header's columns, addressable by lowercased name. */
interface Columns {
  /** True when the file has this column at all. */
  has(column: string): boolean;
  /**
   * The value of `column` in `row`.
   *
   * `undefined` for a column the file does not have, for a row that ended
   * before reaching it, and for the `null` column of a layout that has none —
   * all three of which mean "the export did not say", as distinct from `""`,
   * which is the export saying the field is empty.
   */
  value(row: CsvRow, column: string | null): string | undefined;
  /** The header's own spelling of `column`, for keying `extra`. */
  sourceName(column: string): string;
}

function indexColumns(header: readonly string[]): Columns {
  const at = new Map<string, number>();
  header.forEach((cell, position) => {
    // Trimmed and lowercased: a spreadsheet round trip changes the case and can
    // add a space, and neither changes which column holds the password. A BOM
    // on the first name is removed by the reader, and `trim` removes a stray
    // one anywhere else.
    const key = cell.trim().toLowerCase();
    // First occurrence wins for a duplicated name, matching the reader's rule.
    if (!at.has(key)) at.set(key, position);
  });

  return {
    has: (column) => at.has(column),
    value: (row, column) => {
      if (column === null) return undefined;
      const position = at.get(column);
      return position === undefined ? undefined : row.values[position];
    },
    sourceName: (column) => {
      const position = at.get(column);
      const cell = position === undefined ? undefined : header[position];
      // The file's own spelling, so `extra` is keyed the way `types.ts` asks:
      // by "the source's own column or property name". A Safari export writes
      // `OTPAuth`, and that is what the user will be shown.
      return cell === undefined ? column : cell.trim();
    },
  };
}

/**
 * A display name for the item: the export's, or the URL's host when it has none.
 *
 * **A derived name is not something the export stated.** Firefox has no name
 * column at all, so every Firefox item takes this path, and a Chrome or Safari
 * row whose name column is empty does too.
 */
function displayName(exported: string | undefined, url: string): string {
  if (exported !== undefined && exported !== "") return exported;
  return hostOf(url);
}

function hostOf(url: string): string {
  if (url === "") return "";
  try {
    // `host`, not `hostname`: the port is part of the name. Two services on one
    // host at different ports are different sites, and a derived name that
    // dropped the port would give both of them the same one.
    const host = new URL(url).host;
    return host === "" ? url : host;
  } catch {
    // Not a URL this platform can parse — a bare `mail.example.com` with no
    // scheme, or anything a hand-edited file holds. The text the user's own
    // file carried is a better label than an invented one, and a name is never
    // worth refusing a row over: only the password is.
    return url;
  }
}

function toItem(
  row: CsvRow,
  layout: BrowserLayout,
  columns: Columns,
  width: number,
): ImportItem | ImportRowError {
  if (row.extra.length > 0) {
    // Fields past the end of the header. An export whose writer failed to quote
    // a password containing a comma produces exactly this, and from here on the
    // values no longer line up with the columns naming them — so the field this
    // row calls a password is part of one, and the rest is in `row.extra`.
    //
    // Surplus fields that are **all empty** are a different shape and get a
    // different sentence: nothing has shifted, and a trailing comma is the
    // ordinary cause. The row is still refused, because the other way to get an
    // empty surplus field is a last column whose value ended in a comma, and
    // the two are the same bytes. But "a value has been split across columns" is
    // a claim about this row that is simply false, and it sends the user looking
    // through their export for damage that is not there.
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

  const password = columns.value(row, layout.password);
  if (password === undefined) {
    return { row: row.line, message: "This row ends before its password column" };
  }
  if (password === "") {
    return { row: row.line, message: "This row has an empty password, so it was not imported" };
  }

  const url = columns.value(row, layout.url) ?? "";
  const item = blankImportItem(row.line);
  item.name = displayName(columns.value(row, layout.name), url);
  item.username = columns.value(row, layout.username) ?? "";
  // Byte for byte: the value as the reader unescaped it, and nothing else. A
  // trailing space is part of the password.
  item.password = password;
  item.urls = url === "" ? [] : [url];
  item.notes = columns.value(row, layout.notes) ?? "";

  for (const { column, kind } of layout.carry) {
    const carried = columns.value(row, column);
    // Only when the column actually holds something: otherwise every Safari
    // item without a TOTP seed would carry an empty `OTPAuth`, and the preview
    // screen would warn about the loss of nothing on every row of the import.
    if (carried !== undefined && carried !== "") {
      item.extra.push({ name: columns.sourceName(column), value: carried, kind });
    }
  }

  return item;
}

/**
 * Reads a browser's password export. Never throws.
 *
 * A file no layout fits comes back as a single error against line 1 with no
 * items — detection routes such a file to the generic column mapper and this
 * parser should never see it, but "never throws" has to hold for the caller
 * that gets the routing wrong too.
 */
export function parseBrowserCsv(text: string): ImportResult {
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
            "This file has no url, username and password columns, " +
            "so no browser export layout fits it",
        },
        ...table.errors,
      ],
    };
  }

  // A record the reader reported damage on is not mapped at all. Its fields
  // have already been shown not to mean what their columns say — an unclosed
  // quote swallows the rest of the file into one value — so importing it would
  // store a password the user never had, underneath a report that said the file
  // had a problem. The reader's error is that row's error; it does not get a
  // second one.
  const damaged = new Set(table.errors.map((error) => error.row));
  const items: ImportItem[] = [];
  const errors: ImportRowError[] = [...table.errors];

  for (const row of table.rows) {
    if (damaged.has(row.line)) continue;
    const outcome = toItem(row, layout, columns, table.header.length);
    if ("message" in outcome) {
      errors.push(outcome);
    } else {
      items.push(outcome);
    }
  }

  // By line, so the report reads in the order of the user's own file. Stable,
  // so a reader error and a row error on one line keep the order above.
  errors.sort((left, right) => left.row - right.row);

  return { items, errors };
}
