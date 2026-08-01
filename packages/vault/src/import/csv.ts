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

/**
 * One record of a file that has **no header line**, so nothing can be addressed
 * by name and every field is a position.
 *
 * Keeper's CSV export is the case: it writes no header at all, so `parseCsv`
 * would read the user's first login as the column names and lose it. This is
 * the same records `parseCsv` sees, before any of them is treated as a header.
 */
export interface CsvRecord {
  /** 1-based line in the source file where this record begins. */
  line: number;
  /** Every field, in source order, exactly as the file held it. */
  values: readonly string[];
}

export interface CsvRecords {
  /** Every record, blank lines excluded. */
  rows: readonly CsvRecord[];
  /** Structural problems found while reading, addressed by line. */
  errors: readonly ImportRowError[];
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
  // Whether this record has already been reported as damaged. One error per
  // record: a row with three undoubled quotes is one broken row, and three
  // identical messages against one line would be read as three broken rows.
  let recordReported = false;
  let line = 1;
  let recordLine = 1;
  // The line the currently-open quote was opened on. Only meaningful while
  // `inQuotes`, and only read at EOF, where the difference between it and the
  // final line count is how much of the file one unclosed quote swallowed.
  let quoteOpenedLine = 1;

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
    recordReported = false;
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
        // A closing quote may only be followed by the end of the field, the end
        // of the record, or the end of the file. Anything else means the writer
        // opened a quoted field and then wrote a `"` inside it without doubling
        // it — the classic CSV-writer bug, and the reason `""` exists at all.
        //
        // Without this check the characters after the quote pair are appended to
        // the same field and the pair is dropped, so `"pa"ss"` reads back as
        // `pass"`: one character deleted from the middle of the password, one
        // appended at the end, the same length, and no error. It is the only
        // structural anomaly this reader can see that would otherwise rewrite a
        // value instead of reporting it, so it is reported and the mapper
        // refuses the row.
        const next = text.charAt(i);
        const endsField = next === "" || next === DELIMITER || next === "\r" || next === "\n";
        if (!endsField && !recordReported) {
          recordReported = true;
          errors.push({
            row: recordLine,
            message: "This row has a quote inside a quoted field that is not doubled",
          });
        }
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
      quoteOpenedLine = line;
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
    //
    // **How much it swallowed is part of the message**, because the count the
    // user reads is otherwise wrong in the direction that matters. A stray `"`
    // at row 50 of a 400-row export produces 48 items and one error naming line
    // 50, while the other 350 rows are inside line 50's last field. "One row
    // broke" and "one row broke and took 350 with it" call for different
    // actions, and the file no longer says which happened.
    const swallowed = line - quoteOpenedLine;
    errors.push({
      row: recordLine,
      message:
        swallowed === 0
          ? "This row opens a quoted field that is never closed"
          : `This row opens a quoted field that is never closed; the remaining ` +
            `${swallowed} ${swallowed === 1 ? "line" : "lines"} of the file ` +
            `${swallowed === 1 ? "was" : "were"} read as part of it`,
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
 * Reads `text` into records, treating **none** of them as a header. Never
 * throws.
 *
 * For the one export here that writes no header line: Keeper's CSV. Handing
 * such a file to `parseCsv` costs the user their first login, which is read as
 * the column names instead — and silently, since a row of credentials is a
 * perfectly well-formed header.
 *
 * A leading UTF-8 BOM is removed, blank lines are skipped, and a line holding
 * `""` is not blank — all exactly as `parseCsv` does, because both go through
 * the same scanner and differ only in whether the first record is spent.
 */
export function parseCsvRecords(text: string): CsvRecords {
  const withoutBom = text.startsWith(BOM) ? text.slice(BOM.length) : text;
  const { records, errors } = scan(withoutBom);
  return {
    rows: records
      .filter((record) => !record.blank)
      .map((record) => ({ line: record.line, values: record.fields })),
    errors,
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
