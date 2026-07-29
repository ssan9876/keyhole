import type { CsvRow, CsvTable } from "../csv.js";
import type {
  ImportFieldKind,
  ImportItem,
  ImportResult,
  ImportRowError,
} from "../types.js";

/**
 * The parts every CSV parser in Tasks 3–7 turned out to write identically.
 *
 * **Extracted on the third use, not the first.** `browser.ts` and
 * `bitwarden.ts` each wrote these by hand; a third and fourth copy were about to
 * be written for LastPass, KeePass, NordPass, Dashlane and Keeper. Two copies of
 * a thing is a coincidence and abstracting them guesses at what they have in
 * common; seven copies of a thing is a fact, and the copies drift. The
 * refuse-the-row messages in particular are shown to the user, and three
 * different sentences for one condition is a support burden with no upside.
 *
 * Nothing here decides what a *format* means — which column is the password,
 * what separates a folder, which types a vendor has that Keyhole does not. That
 * knowledge stays in the parser, where the export it describes is named. What
 * lives here is the machinery every parser needs regardless of format:
 *
 * - addressing a header's columns by name rather than by position,
 * - the "an item, or the reason it is not one" return shape,
 * - refusing a row the CSV reader already reported damage on,
 * - the two refusals that are about the password rather than about the format.
 *
 * ## Why the column index is by name and not by position
 *
 * Half of this project's fixtures are reconstructions rather than bytes from a
 * real export, so their column *order* is a guess (`.superpowers/sdd/task-2-
 * report.md` records which). Positional access against a wrong guess writes a
 * password into the notes field of a real export and reports nothing; name
 * lookup against a wrong guess fails to find the column and produces a visible
 * error row. When the guess is wrong, one of those is recoverable.
 */

/**
 * An item, or the reason the row could not become one.
 *
 * A parser's per-row mapping returns this and never throws: spec §7 makes rows
 * all-or-nothing individually, so one malformed line cannot cost the user the
 * other 399 and cannot produce a half-encrypted record.
 */
export type RowOutcome = ImportItem | ImportRowError;

/**
 * True when a mapping refused the row.
 *
 * `"message" in outcome` rather than a tag field: `ImportItem` has no `message`
 * and `ImportRowError` has nothing else, so the two are already distinguishable
 * and a discriminant would be a field every parser had to remember to set.
 */
export function isRowError(outcome: RowOutcome): outcome is ImportRowError {
  return "message" in outcome;
}

/** The header's columns, addressable by lowercased name. */
export interface Columns {
  /** True when the file has this column at all. */
  has(column: string): boolean;
  /**
   * The value of `column` in `row`.
   *
   * `undefined` for a column the file does not have, for a row that ended
   * before reaching it, and for `null` — which a layout uses to say it has no
   * such column at all. All three mean "the export did not say", as distinct
   * from `""`, which is the export saying the field is empty.
   */
  value(row: CsvRow, column: string | null): string | undefined;
  /**
   * The header's own spelling of `column`, for naming an `extra` entry.
   *
   * `types.ts` asks that an `ImportField.name` be "the source's own spelling",
   * because it is what the user will recognise: a Safari export writes
   * `OTPAuth`, and that is what they should be shown. Falls back to the
   * lowercased key for a column the header does not have, which is only reached
   * when a caller asks about a column it has not checked for.
   */
  sourceName(column: string): string;
}

/**
 * Indexes a header so its columns can be read by name.
 *
 * Names are matched **trimmed and lowercased**, as `detect.ts` matches them: a
 * round trip through a spreadsheet changes the case and can add a space, and
 * neither changes which column holds the password. A BOM on the first name is
 * removed by the reader, and `trim` removes a stray one anywhere else.
 *
 * **First occurrence wins** for a duplicated name, matching `csv.ts`'s rule for
 * the same situation. Real exports do duplicate a column name, and the
 * alternative — last wins — hands the parser the second `password` column,
 * which is the one more likely to be empty.
 */
export function indexColumns(header: readonly string[]): Columns {
  const at = new Map<string, number>();
  header.forEach((cell, position) => {
    const key = cell.trim().toLowerCase();
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
      return cell === undefined ? column : cell.trim();
    },
  };
}

/**
 * The reason a row with more fields than the header must be refused, or `null`
 * when it has no surplus.
 *
 * An export whose writer failed to quote a password containing a comma produces
 * exactly this, and from that field on the values no longer line up with the
 * columns naming them — so what this row calls a password is part of one, and
 * the rest is in `row.extra`.
 *
 * Surplus fields that are **all empty** are a different shape and get a
 * different sentence: nothing has shifted, and a trailing comma is the ordinary
 * cause. The row is still refused, because the other way to get an empty
 * surplus field is a last column whose value ended in a comma and the two are
 * the same bytes. But "a value has been split across columns" is a claim about
 * this row that is simply false, and it sends the user looking through their
 * export for damage that is not there.
 */
export function surplusFieldsError(row: CsvRow, width: number): ImportRowError | null {
  if (row.extra.length === 0) return null;
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

/**
 * The password of a login row, or the reason the row cannot become an item.
 *
 * **Never guesses at a password**, which is the contract's rule with no undo:
 * importing a blank over a real password cannot be recovered from an export the
 * user is about to be told to delete.
 *
 * `undefined` and `""` are different failures and both are refusals: the first
 * is a row that ended before its password column, the second is the export
 * stating there is no password here. They get different sentences because they
 * send the user to look at different things.
 *
 * Returns the password itself on success, so the caller narrows with
 * `typeof … === "string"` and cannot forget to check.
 */
export function requiredPassword(
  row: CsvRow,
  value: string | undefined,
): string | ImportRowError {
  if (value === undefined) {
    return { row: row.line, message: "This row ends before its password column" };
  }
  if (value === "") {
    return { row: row.line, message: "This row has an empty password, so it was not imported" };
  }
  return value;
}

/**
 * Adds one entry to `item.extra`, in the order the export carried it.
 *
 * One entry each, **never merged by name**, because two things can legitimately
 * claim one name: Bitwarden allows two custom fields with the same name, and a
 * custom field may itself be named `totp`. Merging them leaves the user's two
 * "PIN" fields as one string nothing downstream can take apart again.
 *
 * An absent or empty value is not carried at all: otherwise every ordinary
 * login would arrive with an empty `totp` and the preview screen would warn
 * about the loss of nothing on every row of the import.
 *
 * `kind` is the caller's to state from **where in the file the value sat**,
 * never from what the column was called — see `ImportFieldKind`.
 */
export function carry(
  item: ImportItem,
  name: string,
  value: string | undefined,
  kind: ImportFieldKind,
): void {
  if (value === undefined || value === "") return;
  item.extra.push({ name, value, kind });
}

/**
 * Runs `toItem` over a CSV table's rows and collects the two outcomes.
 *
 * **A record the reader reported damage on is not mapped at all.** Its fields
 * have already been shown not to mean what their columns say — an unclosed
 * quote swallows the rest of the file into one value — so importing it would
 * store a password the user never had, underneath a report that said the file
 * had a problem. The reader's error is that row's error; it does not get a
 * second one.
 *
 * Errors come back sorted by line, so the report reads in the order of the
 * user's own file. The sort is stable, so a reader error and a row error on one
 * line keep the order above.
 */
export function mapCsvRows(table: CsvTable, toItem: (row: CsvRow) => RowOutcome): ImportResult {
  const damaged = new Set(table.errors.map((error) => error.row));
  const items: ImportItem[] = [];
  const errors: ImportRowError[] = [...table.errors];

  for (const row of table.rows) {
    if (damaged.has(row.line)) continue;
    const outcome = toItem(row);
    if (isRowError(outcome)) {
      errors.push(outcome);
    } else {
      items.push(outcome);
    }
  }

  errors.sort((left, right) => left.row - right.row);

  return { items, errors };
}
