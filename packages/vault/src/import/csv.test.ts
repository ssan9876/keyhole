import { describe, expect, it } from "vitest";
import { parseCsv, type CsvRow, type CsvTable } from "./csv.js";

// Line endings are always built by joining explicit escapes, never written as
// literal newlines inside a template literal. This file can be checked out with
// CRLF endings on Windows, which would silently turn every "\n" case into a
// "\r\n" case -- and the CRLF test below would then prove nothing, because both
// sides of the distinction it exists for would have become the same bytes.
const lf = (...lines: string[]): string => lines.join("\n");
const crlf = (...lines: string[]): string => lines.join("\r\n");

// Indexing is checked rather than optional-chained: `table.rows[0]?.get(...)`
// yields undefined for a missing row, which silently satisfies any
// `toBeUndefined()` assertion about an absent field.
const rowAt = (table: CsvTable, index: number): CsvRow => {
  const row = table.rows[index];
  if (row === undefined) {
    throw new Error(`expected a row at index ${index}, got ${table.rows.length} rows`);
  }
  return row;
};

describe("parseCsv", () => {
  it("reads an unquoted row into fields addressed by header name", () => {
    const table = parseCsv(lf("name,username,password", "GitHub,octocat,hunter2"));

    expect(table.header).toEqual(["name", "username", "password"]);
    expect(table.rows).toHaveLength(1);
    expect(rowAt(table, 0).get("name")).toBe("GitHub");
    expect(rowAt(table, 0).get("username")).toBe("octocat");
    expect(rowAt(table, 0).get("password")).toBe("hunter2");
  });

  it("keeps a comma inside quotes in the field it belongs to", () => {
    // The case the whole reader exists for. split(",") gives this row five
    // fields instead of three, so `password` becomes "p and `url` becomes ss --
    // and it reports no error at all. The user finds out months later, when the
    // password does not work.
    const table = parseCsv(
      lf("name,password,url", 'Bank,"p,ss,w,rd",https://bank.example'),
    );

    const row = rowAt(table, 0);
    expect(row.values).toHaveLength(3);
    expect(row.get("password")).toBe("p,ss,w,rd");
    expect(row.get("url")).toBe("https://bank.example");
  });

  it("turns a doubled quote into one literal quote in the value", () => {
    // "" is CSV's only escape for a quote inside a quoted field. Without the
    // unescape the value comes back as pa"ss" -- wrong by one character, and
    // wrong in a way that looks entirely plausible on screen.
    const table = parseCsv(lf("name,password", 'Forum,"pa""ss"'));

    expect(rowAt(table, 0).get("password")).toBe('pa"ss');
  });

  it("reads a field that is nothing but an escaped quote as a single quote", () => {
    // The degenerate form of the case above: four quote characters in the file
    // are one quote character in the password.
    const table = parseCsv(lf("name,password", 'Odd,""""'));

    expect(rowAt(table, 0).get("password")).toBe('"');
  });

  it("keeps a newline inside quotes in the field instead of ending the row", () => {
    // A multi-line secure note is the ordinary case, not an exotic one.
    const table = parseCsv(
      lf("name,notes", 'Wifi,"line one', 'line two"', "Router,plain"),
    );

    expect(table.rows).toHaveLength(2);
    const notes = rowAt(table, 0).get("notes");
    // Asserting the row count alone would pass for a reader that ended the row
    // at the newline and dropped the tail; the newline must survive *in the
    // value*.
    expect(notes).toContain("\n");
    expect(notes).toBe(lf("line one", "line two"));
    expect(rowAt(table, 1).get("name")).toBe("Router");
  });

  it("preserves a CRLF that is inside a quoted field", () => {
    // A Windows-exported note carries CRLF inside the field. It is data, not
    // structure, and rewriting it is a decision this layer has no business
    // making.
    const table = parseCsv(crlf("name,notes", 'Wifi,"line one', 'line two"'));

    expect(rowAt(table, 0).get("notes")).toBe(crlf("line one", "line two"));
  });

  it("ends rows on CRLF without leaving the carriage return in the last field", () => {
    // Splitting on "\n" alone leaves "\r" glued to the final field of every
    // row, so the header key becomes "password\r" and every lookup by name
    // misses.
    const table = parseCsv(crlf("name,password", "Mail,s3cret", ""));

    expect(table.header).toEqual(["name", "password"]);
    expect(table.rows).toHaveLength(1);
    expect(rowAt(table, 0).get("password")).toBe("s3cret");
  });

  it("strips a UTF-8 BOM so the first column is addressable by its name", () => {
    // Written as an escape, never as a literal character: a literal BOM at the
    // head of this string is invisible in review and can be dropped by an
    // editor or a file write, leaving the test asserting nothing.
    const table = parseCsv(
      "\uFEFF" + lf("url,username,password", "https://x.example,me,pw"),
    );

    expect(table.header[0]).toBe("url");
    // The lookup is the part that matters: a header of "\uFEFFurl" makes every
    // parser's get("url") return undefined and every row look empty.
    expect(rowAt(table, 0).get("url")).toBe("https://x.example");
  });

  it("reports a column the row ended before reaching as absent", () => {
    const table = parseCsv(lf("name,username,password,notes", "Router,admin"));

    const row = rowAt(table, 0);
    expect(row.get("username")).toBe("admin");
    expect(row.get("password")).toBeUndefined();
    expect(row.get("notes")).toBeUndefined();
  });

  it("distinguishes an empty quoted field from a column the row never reached", () => {
    // "" is the export saying "this account has no username"; running off the
    // end of the row is the export not saying anything about that column at
    // all. The mapper turns the first into an empty field and the second into a
    // row error, so a reader that pads short rows with "" costs exactly that
    // difference -- silently.
    const table = parseCsv(lf("name,username,password,notes", 'NoUser,""'));

    const row = rowAt(table, 0);
    expect(row.get("username")).toBe("");
    expect(row.get("password")).toBeUndefined();
    expect(row.get("notes")).toBeUndefined();
  });

  it("reads an unquoted empty field as present and empty", () => {
    const table = parseCsv(lf("name,username,password", "NoUser,,pw"));

    const row = rowAt(table, 0);
    expect(row.get("username")).toBe("");
    expect(row.get("password")).toBe("pw");
  });

  it("keeps fields past the end of the header instead of dropping them", () => {
    // A password holding an unescaped comma lands here. Dropping the surplus
    // would delete the tail of it with no error; keeping it lets the mapper
    // refuse the row and tell the user which one.
    const table = parseCsv(lf("name,username,password", "Shop,me,pw,surplus"));

    const row = rowAt(table, 0);
    expect(row.get("password")).toBe("pw");
    expect(row.extra).toEqual(["surplus"]);
    expect(row.values).toHaveLength(4);
  });

  it("returns no header and no rows for an empty file", () => {
    const table = parseCsv("");

    expect(table.header).toEqual([]);
    expect(table.rows).toEqual([]);
  });

  it("returns no header and no rows for a file holding only a newline", () => {
    const table = parseCsv("\n");

    expect(table.header).toEqual([]);
    expect(table.rows).toEqual([]);
  });

  it("returns the header and no rows for a header-only file", () => {
    const table = parseCsv("name,username,password");

    expect(table.header).toEqual(["name", "username", "password"]);
    expect(table.rows).toEqual([]);
  });

  it("does not invent a blank row from the file's trailing newline", () => {
    const table = parseCsv(lf("name,password", "A,1", ""));

    expect(table.rows).toHaveLength(1);
  });

  it("skips a blank line between rows", () => {
    const table = parseCsv(lf("name,password", "A,1", "", "B,2"));

    expect(table.rows).toHaveLength(2);
    expect(rowAt(table, 1).get("name")).toBe("B");
  });

  it("keeps a line holding one empty quoted field, unlike a blank line", () => {
    // '""' is a row with one empty field; an empty line is no row at all. They
    // are one character apart in the file and mean different things.
    const table = parseCsv(lf("name,password", '""'));

    expect(table.rows).toHaveLength(1);
    expect(rowAt(table, 0).get("name")).toBe("");
  });

  it("treats a quote in the middle of an unquoted field as a literal quote", () => {
    // Quotes are only structural at the start of a field. An exporter that
    // wrote pa"ss without quoting meant the password to contain a quote.
    const table = parseCsv(lf("name,password", 'Legacy,pa"ss'));

    expect(rowAt(table, 0).get("password")).toBe('pa"ss');
  });

  it("numbers rows by their line in the file, counting a quoted newline", () => {
    // The per-row error report sends the user to a line in their own file.
    // Counting records instead of lines sends them to the wrong one, and a
    // multi-line note -- the thing that makes the two differ -- is common.
    const table = parseCsv(lf("name,notes", 'A,"one', 'two"', "B,three"));

    expect(rowAt(table, 0).line).toBe(2);
    expect(rowAt(table, 1).line).toBe(4);
  });

  it("reports an unclosed quote rather than silently swallowing the rest of the file", () => {
    const table = parseCsv(lf("name,password", 'Broken,"never closed', "Next,pw"));

    expect(table.errors).toHaveLength(1);
    expect(table.errors[0]?.row).toBe(2);
    // Singular, because exactly one line was swallowed. Asserted in full rather
    // than matched loosely: "1 lines ... were" is the kind of thing a plural
    // rule written for the two-line case gets wrong and nothing notices.
    expect(table.errors[0]?.message).toBe(
      "This row opens a quoted field that is never closed; " +
        "the remaining 1 line of the file was read as part of it",
    );
    // The swallowed text is still returned rather than discarded: the user gets
    // told which line broke and can still see what was in it.
    expect(rowAt(table, 0).get("password")).toBe(lf("never closed", "Next,pw"));
  });

  it("says how many lines an unclosed quote swallowed, not just which line opened it", () => {
    // Rows 4 and 5 are consumed into row 3's field. A message naming only line 3
    // makes this indistinguishable from one broken row -- and in a 400-row
    // export with a stray quote at row 50, the user reads "48 items, 1 error"
    // while 350 passwords sit inside line 50's last field. Nothing is corrupted
    // (the mapper refuses the swallowing row) but the count is wrong in the one
    // direction that matters, and the file no longer says so.
    const table = parseCsv(lf("name,password", "A,1", 'B,"oops', "C,3", "D,4"));

    expect(table.errors).toHaveLength(1);
    expect(table.errors[0]?.row).toBe(3);
    expect(table.errors[0]?.message).toBe(
      "This row opens a quoted field that is never closed; " +
        "the remaining 2 lines of the file were read as part of it",
    );
    // The rows named in the message really are gone: three data lines in, two
    // rows out.
    expect(table.rows).toHaveLength(2);
  });

  it("does not claim an unclosed quote swallowed anything when the file ends on its line", () => {
    // The quote opens on the last line, so there is nothing after it to swallow
    // and a "the remaining 0 lines" clause would be noise on the commonest
    // shape of this defect: a download that was cut short.
    const table = parseCsv(lf("name,password", 'Broken,"never closed'));

    expect(table.errors).toEqual([
      { row: 2, message: "This row opens a quoted field that is never closed" },
    ]);
  });

  it("reports a quoted field holding an undoubled quote instead of rewriting the value", () => {
    // The classic CSV-writer bug: the exporter quoted the field but did not
    // double the `"` inside it. Appending what follows to the same field and
    // dropping the quote pair turns the password `pa"ss` into `pass"` -- the
    // same length, one character deleted from the middle and one appended at
    // the end -- and reports nothing at all. It is the one structural anomaly
    // this reader can see that would otherwise rewrite a password rather than
    // report it.
    const table = parseCsv(lf("name,password", 'Site,"pa"ss"'));

    expect(table.errors).toEqual([
      { row: 2, message: "This row has a quote inside a quoted field that is not doubled" },
    ]);
    // The damaged value is still returned, as it is for an unclosed quote: the
    // user is told which line broke and can still see what was in it. What must
    // not happen is the row arriving as an item, and that is the mapper's job.
    expect(rowAt(table, 0).get("password")).toBe('pass"');
  });

  it("reports an undoubled quote in a field that also holds a comma", () => {
    // The same defect one character worse: the field genuinely needed quoting,
    // so an exporter that wrote it unquoted was never an option and the row
    // cannot be salvaged by re-reading it as unquoted data.
    const table = parseCsv(lf("name,password", 'Site,"p,a"ss"'));

    expect(table.errors).toEqual([
      { row: 2, message: "This row has a quote inside a quoted field that is not doubled" },
    ]);
  });

  it("reports a row with two undoubled quoted fields once, not once per field", () => {
    // Two damaged fields in one record, each closing its quote against a
    // character that is not a delimiter, a line ending or the end of the file.
    // One broken row is one error: two identical messages against one line read
    // as two broken rows, and the count is what the user uses to decide whether
    // their export came across.
    const table = parseCsv(lf("name,password,notes", 'Site,"a"b,"c"d'));

    expect(table.errors).toEqual([
      { row: 2, message: "This row has a quote inside a quoted field that is not doubled" },
    ]);
  });

  it("ends rows on a bare carriage return, as a classic-Mac export writes them", () => {
    // Without this the whole file is one enormous row and the import shows a
    // single item whose name is the entire vault.
    const table = parseCsv(["name,password", "A,1", "B,2"].join("\r"));

    expect(table.header).toEqual(["name", "password"]);
    expect(table.rows).toHaveLength(2);
    expect(rowAt(table, 1).get("password")).toBe("2");
  });

  it("reports no errors for a ragged but well-formed file", () => {
    // The error channel drives a per-row report the user reads before
    // importing. Everything here is ordinary in a real export -- a short row, a
    // surplus field, a blank line, quoted commas and newlines, an escaped quote
    // and a trailing newline -- and none of it is a defect. An error channel
    // that flags all of them tells the user their whole vault is broken, which
    // is both wrong and the fastest way to make them stop reading it.
    const table = parseCsv(
      lf(
        "name,username,password",
        "Short,onlyuser",
        "Surplus,me,pw,extra",
        "",
        'Comma,me,"p,w"',
        'Quote,me,"p""w"',
        'Note,me,"line one',
        'line two"',
        "",
      ),
    );

    expect(table.errors).toEqual([]);
    expect(table.rows).toHaveLength(5);
  });
});
