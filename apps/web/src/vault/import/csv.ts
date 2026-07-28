import type { ImportRowError } from "./types.js";

/**
 * A real CSV reader, because `text.split(",")` corrupts password exports.
 *
 * Every hazard below appears in an export produced by a shipping password
 * manager, and every one of them is silent — a naive split does not fail, it
 * returns the wrong string:
 *
 * - a password containing a comma splits into two fields, shifting every column
 *   after it by one, so the URL becomes the tail of the password;
 * - a password containing a quote needs CSV's `""` escape, and un-escaping it
 *   wrongly leaves the value off by one character;
 * - a secure note contains newlines, which end the row for a line-splitter and
 *   drop everything after the first line;
 * - a Windows export ends rows with CRLF, and splitting on `\n` glues a `\r` to
 *   the last field of every row — including the header, so lookups by column
 *   name miss entirely;
 * - a UTF-8 BOM makes the first header name `\uFEFFurl` rather than `url`, with
 *   the same effect on the first column of every row.
 *
 * RFC 4180 with the leniencies real files require: a bare LF or CR ends a row
 * as readily as CRLF, a quote inside an unquoted field is data, and a row may
 * have any number of fields regardless of the header's width.
 *
 * The delimiter is a comma. Semicolon- and tab-separated exports exist and are
 * not handled here; adding one means a parameter and its own tests, not a guess
 * at the delimiter, because guessing wrong on a file full of commas-in-
 * passwords is exactly the failure this module exists to prevent.
 */

const QUOTE = '"';
const DELIMITER = ",";
const BOM = "\uFEFF";

export interface CsvRow {
  /**
   * 1-based line in the source file where this record begins.
   *
   * Not the record's index: a quoted newline makes those two diverge, and this
   * number is what a per-row error shows the user so they can find the line in
   * their own file.
   */
  line: number;
  /**
   * Every field of the record, in source order, exactly as the file held it —
   * including any past the end of the header.
   */
  values: readonly string[];
  /**
   * Fields beyond the header's width.
   *
   * Never discarded. A password with an unescaped comma in it puts its own tail
   * here, and dropping the surplus would delete part of a password with no
   * error at all. Kept so the mapper can refuse the row and say which one.
   */
  extra: readonly string[];
  /**
   * The value in `column`, or `undefined` if this record ended before reaching
   * it (or the header has no such column).
   *
   * `undefined` and `""` are different answers and both occur: `""` is the
   * export stating the field is empty, `undefined` is the export not stating
   * anything. Padding short rows with `""` would erase that distinction, and
   * with it the mapper's ability to tell "this login has no username" from
   * "this row is truncated".
   */
  get(column: string): string | undefined;
}

export interface CsvTable {
  /** The first non-blank record. Empty for an empty file. */
  header: readonly string[];
  /** Every record after the header, blank lines excluded. */
  rows: readonly CsvRow[];
  /**
   * Structural problems found while reading, addressed by line.
   *
   * Reading never throws: a damaged line is a bad row, not a bad file, and one
   * of them must not cost the user the other 399.
   */
  errors: readonly ImportRowError[];
}

interface RawRecord {
  line: number;
  fields: string[];
  /**
   * True for a record that is a single empty *unquoted* field — a blank line.
   * A line holding `""` is a record with one empty field and is not blank; the
   * two are one character apart in the file and mean different things.
   */
  blank: boolean;
}

interface ScanResult {
  records: RawRecord[];
  errors: ImportRowError[];
}

function scan(text: string): ScanResult {
  const records: RawRecord[] = [];
  const errors: ImportRowError[] = [];

  let fields: string[] = [];
  let field = "";
  // Whether the cursor is between an opening quote and its close.
  let inQuotes = false;
  // Whether the *current field* opened with a quote. A quote is only structural
  // at the start of a field, so `pa"ss` unquoted is a literal quote, and the
  // character after a closing quote continues the same field rather than
  // opening a new quoted run.
  let fieldWasQuoted = false;
  // Whether any field of the current record opened with a quote — the one thing
  // that separates a blank line from a line holding `""`.
  let recordHadQuote = false;
  let line = 1;
  let recordLine = 1;

  const endField = (): void => {
    fields.push(field);
    field = "";
    fieldWasQuoted = false;
  };

  const endRecord = (): void => {
    endField();
    records.push({
      line: recordLine,
      fields,
      blank: !recordHadQuote && fields.length === 1 && fields[0] === "",
    });
    fields = [];
    recordHadQuote = false;
  };

  let i = 0;
  while (i < text.length) {
    // charAt rather than indexing: noUncheckedIndexedAccess types text[i] as
    // string | undefined.
    const ch = text.charAt(i);

    if (inQuotes) {
      if (ch === QUOTE) {
        if (text.charAt(i + 1) === QUOTE) {
          // A doubled quote is CSV's only escape for a literal quote. Deleting
          // these four lines is the difference between `pa"ss` and `pa"ss"`.
          field += QUOTE;
          i += 2;
          continue;
        }
        inQuotes = false;
        i += 1;
        continue;
      }
      // Inside quotes everything is data, newlines included: a multi-line
      // secure note is the ordinary case. The line counter still advances so
      // later rows report the line the user will actually see.
      if (ch === "\n") line += 1;
      field += ch;
      i += 1;
      continue;
    }

    if (ch === QUOTE && field === "" && !fieldWasQuoted) {
      inQuotes = true;
      fieldWasQuoted = true;
      recordHadQuote = true;
      i += 1;
      continue;
    }

    if (ch === DELIMITER) {
      endField();
      i += 1;
      continue;
    }

    if (ch === "\r" || ch === "\n") {
      // CRLF, a bare LF, and a bare CR all end a record. Consuming CRLF as one
      // terminator is what keeps `\r` out of the last field of every row.
      i += ch === "\r" && text.charAt(i + 1) === "\n" ? 2 : 1;
      line += 1;
      endRecord();
      recordLine = line;
      continue;
    }

    field += ch;
    i += 1;
  }

  if (inQuotes) {
    // The file ended inside a quoted field. Everything from the opening quote
    // onward has been swallowed into one value, which is worth saying out loud:
    // silently returning it as a password is how a truncated export becomes a
    // vault full of wrong secrets.
    errors.push({
      row: recordLine,
      message: "This row opens a quoted field that is never closed",
    });
  }

  // A record still in progress at EOF — a file whose last line has no
  // terminator. The guard is what stops a trailing newline from inventing a
  // blank row: after one, there is no field, no delimiter, and no quote.
  if (field !== "" || fields.length > 0 || fieldWasQuoted || inQuotes) {
    endRecord();
  }

  return { records, errors };
}

function buildRow(record: RawRecord, index: Map<string, number>, width: number): CsvRow {
  const values = record.fields;
  return {
    line: record.line,
    values,
    extra: values.slice(width),
    get(column: string): string | undefined {
      const at = index.get(column);
      // A short row leaves values[at] undefined, which is the answer: the
      // record never reached that column.
      return at === undefined ? undefined : values[at];
    },
  };
}

/**
 * Reads `text` into a header and rows. Never throws.
 *
 * A leading UTF-8 BOM is removed before anything else, so the first column is
 * addressable by the name the user sees. Blank lines are skipped; a line
 * holding `""` is not blank.
 */
export function parseCsv(text: string): CsvTable {
  const withoutBom = text.startsWith(BOM) ? text.slice(BOM.length) : text;
  const { records, errors } = scan(withoutBom);

  const meaningful = records.filter((record) => !record.blank);
  const headerRecord = meaningful.shift();
  if (headerRecord === undefined) {
    return { header: [], rows: [], errors };
  }

  const header = headerRecord.fields;
  // First occurrence wins for a duplicated column name. Exports do produce
  // them, and the alternative — last wins — would hand the mapper the second
  // `password` column, which is the one more likely to be empty.
  const index = new Map<string, number>();
  header.forEach((name, at) => {
    if (!index.has(name)) index.set(name, at);
  });

  return {
    header,
    rows: meaningful.map((record) => buildRow(record, index, header.length)),
    errors,
  };
}
