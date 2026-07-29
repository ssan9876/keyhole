import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import type { ImportItem, ImportResult } from "../types.js";
import { parseBrowserCsv } from "./browser.js";

/**
 * Fixtures are located from the running test file's own path, for the reasons
 * `detect.test.ts` sets out: `import.meta.url` is an http URL under this
 * project's jsdom environment, and `process.cwd()` depends on where vitest was
 * started. One directory up from `parsers/`.
 */
const read = (file: string): string => {
  const testPath = expect.getState().testPath;
  if (testPath === undefined) {
    throw new Error("vitest reported no test path, so fixtures cannot be located");
  }
  return readFileSync(join(dirname(testPath), "..", "fixtures", file), "utf8");
};

/**
 * The header line of a fixture, so an inline case cannot pass against a header
 * this test invented.
 *
 * Every case below that is not a golden builds its file from a *real* header
 * plus rows written here. That keeps the part with provenance (the column names
 * and their order, recorded in `.superpowers/sdd/task-2-report.md`) out of this
 * file's hands while letting a case exercise a row no fixture contains.
 */
const headerLine = (file: string): string => {
  // Split on both endings: .gitattributes normalises the checkout to LF, but a
  // \r left on the header would attach to its last column name and every lookup
  // for that column would miss.
  const [first] = read(file).split(/\r?\n/);
  if (first === undefined || first === "") {
    throw new Error(`${file} has no header line`);
  }
  return first;
};

const withRows = (file: string, ...rows: string[]): string =>
  [headerLine(file), ...rows].join("\n");

/**
 * The one item of a single-row case.
 *
 * Indexing is checked rather than optional-chained: `result.items[0]?.password`
 * is `undefined` for a row that failed to parse, which silently satisfies an
 * assertion about an absent field instead of failing it.
 */
const only = (result: ImportResult): ImportItem => {
  const [item, ...rest] = result.items;
  if (item === undefined || rest.length > 0) {
    throw new Error(
      `expected exactly one item, got ${result.items.length}; ` +
        `errors: ${JSON.stringify(result.errors)}`,
    );
  }
  return item;
};

/** The sentence every fixture carries so a stray copy is not mistaken for a vault. */
const NOTICE = "GENERATED FIXTURE - no real credential appears in this file";

/**
 * What the three byte-identical Chromium fixtures must produce.
 *
 * Written once and asserted against each of the three files: they are the same
 * bytes under three names, so three separately-typed expectations would only be
 * three chances to make a typo.
 */
const CHROMIUM_ITEMS: readonly ImportItem[] = [
  {
    type: "login",
    name: "mail.example.com",
    username: "ada@example.com",
    password: "fixture-pw-8Hq2vN",
    urls: ["https://mail.example.com/"],
    notes: NOTICE,
    favorite: false,
    folderPath: [],
    extra: [],
    sourceRow: 2,
  },
  {
    type: "login",
    name: "forum.example.org",
    username: "ada",
    password: "fixture,pw,with,commas",
    urls: ["https://forum.example.org/"],
    notes: "",
    favorite: false,
    folderPath: [],
    extra: [],
    sourceRow: 3,
  },
];

describe("parseBrowserCsv, against one sample export per browser", () => {
  for (const file of [
    "chrome-passwords.csv",
    "microsoft-edge-passwords.csv",
    "brave-passwords.csv",
  ]) {
    it(`maps name, url, username, password and note from ${file}`, () => {
      expect(parseBrowserCsv(read(file))).toEqual({ items: CHROMIUM_ITEMS, errors: [] });
    });
  }

  it("maps the Firefox export, deriving each name from the URL host", () => {
    // Firefox exports no name column at all, so `name` here is derived rather
    // than exported -- see the comment on `hostOf` in browser.ts.
    //
    // `httpRealm` lands in `extra` (it is the fixture's carrier for the
    // generated-fixture notice, hence the sentence); `formActionOrigin`, `guid`
    // and the three timestamps are dropped, which is a deliberate, stated choice
    // rather than an oversight -- none is anything the user typed.
    expect(parseBrowserCsv(read("firefox-logins.csv"))).toEqual({
      items: [
        {
          type: "login",
          name: "mail.example.com",
          username: "ada@example.com",
          password: "fixture-pw-8Hq2vN",
          urls: ["https://mail.example.com"],
          notes: "",
          favorite: false,
          folderPath: [],
          extra: [{ name: "httpRealm", value: NOTICE, kind: "metadata" }],
          sourceRow: 2,
        },
        {
          type: "login",
          name: "forum.example.org",
          username: "ada",
          password: "fixture,pw,with,commas",
          urls: ["https://forum.example.org"],
          notes: "",
          favorite: false,
          folderPath: [],
          extra: [],
          sourceRow: 3,
        },
      ],
      errors: [],
    });
  });

  it("maps Title, URL, Username, Password and Notes from the Safari export", () => {
    // The Safari fixture's OTPAuth column is empty in both rows, so `extra` is
    // empty here; the column carrying a secret is the test below.
    expect(parseBrowserCsv(read("safari-passwords.csv"))).toEqual({
      items: [
        {
          type: "login",
          name: "mail.example.com",
          username: "ada@example.com",
          password: "fixture-pw-8Hq2vN",
          urls: ["https://mail.example.com"],
          notes: NOTICE,
          favorite: false,
          folderPath: [],
          extra: [],
          sourceRow: 2,
        },
        {
          type: "login",
          name: "forum.example.org",
          username: "ada",
          password: "fixture,pw,with,commas",
          urls: ["https://forum.example.org"],
          notes: "",
          favorite: false,
          folderPath: [],
          extra: [],
          sourceRow: 3,
        },
      ],
      errors: [],
    });
  });
});

describe("parseBrowserCsv, on the password itself", () => {
  it("keeps a password holding both a comma and a quote exactly as the file escaped it", () => {
    // The case Task 1's CSV reader exists for, proved end to end: the file holds
    // `"fixture,pw""with""quotes"` and the item must hold fixture,pw"with"quotes.
    // A naive split gives this row six fields and a password of `"fixture`.
    const csv = withRows(
      "chrome-passwords.csv",
      'forum.example.org,https://forum.example.org/,ada,"fixture,pw""with""quotes",',
    );

    expect(only(parseBrowserCsv(csv)).password).toBe('fixture,pw"with"quotes');
  });

  it("keeps a trailing space in a password rather than trimming it", () => {
    // A trailing space is part of the password. Trimming it produces a value
    // that looks identical on screen and fails at the login form, which is the
    // hardest kind of import bug for a user to diagnose.
    const csv = withRows(
      "chrome-passwords.csv",
      'forum.example.org,https://forum.example.org/,ada,"fixture-pw-8Hq2vN ",',
    );

    expect(only(parseBrowserCsv(csv)).password).toBe("fixture-pw-8Hq2vN ");
  });
});

describe("parseBrowserCsv, on names derived from the URL", () => {
  it("derives a Firefox name from host and port, leaving the URL's path in the URL", () => {
    const url = "https://intranet.example.org:8443/apps/mail/login?next=%2Finbox";
    const csv = withRows(
      "firefox-logins.csv",
      `"${url}","ada@example.com","fixture-pw-8Hq2vN","",` +
        '"https://intranet.example.org:8443",' +
        '"{33333333-3333-4333-8333-333333333333}","1751328000000","1751328000000","1751328000000"',
    );

    const item = only(parseBrowserCsv(csv));
    // The port stays: two services on one host at different ports are different
    // sites, and a name that dropped the port would name them identically.
    expect(item.name).toBe("intranet.example.org:8443");
    // The path and query stay in the URL and out of the name.
    expect(item.urls).toEqual([url]);
  });

  it("leaves the URL list empty for a row with no URL, rather than listing one empty string", () => {
    // `[""]` would be worse than `[]` downstream: duplicate detection compares
    // normalized hosts, and every URL-less item would then share one host and
    // be reported as a duplicate of every other.
    const csv = withRows(
      "firefox-logins.csv",
      '"","ada@example.com","fixture-pw-8Hq2vN","","",' +
        '"{88888888-8888-4888-8888-888888888888}","1751328000000","1751328000000","1751328000000"',
    );

    const item = only(parseBrowserCsv(csv));

    expect(item.urls).toEqual([]);
    // Nothing to derive a name from, and no name column to fall back to. The
    // row still imports: it has a password, which is the only thing worth
    // refusing a row over.
    expect(item.name).toBe("");
  });

  it("falls back to the URL as written when it is not a URL the browser can parse", () => {
    const csv = withRows(
      "firefox-logins.csv",
      '"not a url at all","ada@example.com","fixture-pw-8Hq2vN","","",' +
        '"{44444444-4444-4444-8444-444444444444}","1751328000000","1751328000000","1751328000000"',
    );

    // Not an error row: only the password is worth refusing a row over. A name
    // is a label, and showing the user the text their own file held beats
    // showing them nothing.
    expect(only(parseBrowserCsv(csv)).name).toBe("not a url at all");
  });
});

describe("parseBrowserCsv, on rows a browser exports that Keyhole has no field for", () => {
  it("keeps a Firefox row whose username column is empty, as an item with no username", () => {
    // A password with no username is a real login -- a PIN-style site, or a
    // form Firefox never captured a username from. Refusing it would lose it.
    const csv = withRows(
      "firefox-logins.csv",
      '"https://kiosk.example.org","","fixture-pw-8Hq2vN","",' +
        '"https://kiosk.example.org",' +
        '"{55555555-5555-4555-8555-555555555555}","1751328000000","1751328000000","1751328000000"',
    );

    const result = parseBrowserCsv(csv);

    expect(result.errors).toEqual([]);
    expect(only(result).username).toBe("");
    expect(only(result).password).toBe("fixture-pw-8Hq2vN");
  });

  it("keeps two Firefox rows for one host with different usernames as two items", () => {
    // Deduplication is Task 8's job and it reports rather than merges. A parser
    // that collapsed these would delete one of the user's two accounts before
    // anything downstream ever saw it.
    const csv = withRows(
      "firefox-logins.csv",
      '"https://mail.example.com","ada@example.com","fixture-pw-8Hq2vN","",' +
        '"https://mail.example.com",' +
        '"{66666666-6666-4666-8666-666666666666}","1751328000000","1751328000000","1751328000000"',
      '"https://mail.example.com","bob@example.com","fixture-pw-9Kd3xR","",' +
        '"https://mail.example.com",' +
        '"{77777777-7777-4777-8777-777777777777}","1751328000000","1751328000000","1751328000000"',
    );

    const result = parseBrowserCsv(csv);

    expect(result.items.map((item) => item.username)).toEqual([
      "ada@example.com",
      "bob@example.com",
    ]);
    expect(result.items.map((item) => item.password)).toEqual([
      "fixture-pw-8Hq2vN",
      "fixture-pw-9Kd3xR",
    ]);
  });

  it("carries Safari's OTPAuth secret into extra, leaving the user's own note alone", () => {
    // Keyhole has no TOTP field in v1 (spec section 1, non-goals). `extra` is
    // the shape's channel for exactly this, and it is what lets the preview
    // screen tell the user what will not survive -- appending it to the note
    // here would make that undetectable downstream.
    const otpauth = "otpauth://totp/Example:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    const csv = withRows(
      "safari-passwords.csv",
      `mail.example.com,https://mail.example.com,ada@example.com,fixture-pw-8Hq2vN,` +
        `a note the user typed,${otpauth}`,
    );

    const item = only(parseBrowserCsv(csv));

    expect(item.extra).toEqual([{ name: "OTPAuth", value: otpauth, kind: "totp" }]);
    expect(item.notes).toBe("a note the user typed");
  });

  it("leaves extra empty when Safari's OTPAuth column is present but empty", () => {
    // Otherwise every Safari item without a TOTP seed would carry an empty
    // `OTPAuth` entry, and the preview screen would warn about a loss of
    // nothing on every row of the import.
    const csv = withRows(
      "safari-passwords.csv",
      "mail.example.com,https://mail.example.com,ada@example.com,fixture-pw-8Hq2vN,note,",
    );

    expect(only(parseBrowserCsv(csv)).extra).toEqual([]);
  });
});

describe("parseBrowserCsv, on columns in an order it did not expect", () => {
  it("maps a Safari export whose columns are reordered to the same items as the fixture's order", () => {
    // `safari-passwords.csv` is a reconstruction: Task 2 confirmed Safari's
    // column *set* from Bitwarden's importer but found no source quoting the
    // header line, so its order is a guess. Positional access would therefore
    // put a password into the notes field of a real export and report nothing.
    //
    // This compares two parses rather than a literal, so it asserts only the
    // claim in its name -- that order does not matter. Which column means what
    // is the golden test's claim, above.
    const reordered = [
      "URL,Title,OTPAuth,Notes,Password,Username",
      `https://mail.example.com,mail.example.com,,${NOTICE},fixture-pw-8Hq2vN,ada@example.com`,
      'https://forum.example.org,forum.example.org,,,"fixture,pw,with,commas",ada',
    ].join("\n");

    expect(parseBrowserCsv(reordered).items).toEqual(
      parseBrowserCsv(read("safari-passwords.csv")).items,
    );
  });
});

describe("parseBrowserCsv, on rows it must refuse", () => {
  it("reports a row with an empty password and still returns the rows either side", () => {
    // The rule with no undo: an item with a blank password imported over a real
    // one cannot be recovered from the export, because the export is what the
    // user is about to be told to delete.
    const csv = withRows(
      "chrome-passwords.csv",
      "good.example.com,https://good.example.com/,ada,fixture-pw-8Hq2vN,",
      "blank.example.com,https://blank.example.com/,ada,,",
      "later.example.com,https://later.example.com/,bob,fixture-pw-9Kd3xR,",
    );

    const result = parseBrowserCsv(csv);

    expect(result.errors).toEqual([
      { row: 3, message: "This row has an empty password, so it was not imported" },
    ]);
    expect(result.items.map((item) => item.name)).toEqual([
      "good.example.com",
      "later.example.com",
    ]);
  });

  it("reports a row that ends before its password column rather than importing a blank", () => {
    const csv = withRows(
      "chrome-passwords.csv",
      "good.example.com,https://good.example.com/,ada,fixture-pw-8Hq2vN,",
      "short.example.com,https://short.example.com/,ada",
    );

    const result = parseBrowserCsv(csv);

    expect(result.errors).toEqual([{ row: 3, message: "This row ends before its password column" }]);
    expect(result.items.map((item) => item.name)).toEqual(["good.example.com"]);
  });

  it("reports a row with more fields than the header instead of importing its first part", () => {
    // An export whose writer failed to quote a password containing a comma
    // produces exactly this. The tail of the password is in `extra`, so the
    // fields no longer line up with the header and every value after the
    // password is one column left of where it belongs.
    const csv = withRows(
      "chrome-passwords.csv",
      "good.example.com,https://good.example.com/,ada,fixture-pw-8Hq2vN,",
      "split.example.com,https://split.example.com/,ada,fixture,pw,with,commas,",
    );

    const result = parseBrowserCsv(csv);

    expect(result.errors).toEqual([
      {
        row: 3,
        message: "This row has 8 fields where the header has 5, so a value has been split across columns",
      },
    ]);
    expect(result.items.map((item) => item.name)).toEqual(["good.example.com"]);
  });

  it("refuses a row the CSV reader flagged, rather than importing its swallowed tail", () => {
    // A file that ends inside a quoted field: the reader reports the damage and
    // still hands the record over, with everything from the opening quote
    // onwards swallowed into one value. Importing that would store a password
    // the user never had, under a report that said the file had a problem.
    const csv = withRows(
      "chrome-passwords.csv",
      "good.example.com,https://good.example.com/,ada,fixture-pw-8Hq2vN,",
      'truncated.example.com,https://truncated.example.com/,ada,"fixture-pw-9K',
    );

    const result = parseBrowserCsv(csv);

    expect(result.errors).toEqual([
      { row: 3, message: "This row opens a quoted field that is never closed" },
    ]);
    expect(result.items.map((item) => item.name)).toEqual(["good.example.com"]);
  });

  it("says a row with a trailing comma has empty surplus fields, not a value split apart", () => {
    // The row has one field more than the header and that field is empty:
    // nothing has shifted, and every column still holds what its name says. It
    // is still refused -- a last column whose value ended in a comma produces
    // the same bytes -- but telling the user a value "has been split across
    // columns" is a claim about their file that is false, and it sends them
    // hunting for damage that is not there.
    const csv = withRows(
      "chrome-passwords.csv",
      "good.example.com,https://good.example.com/,ada,fixture-pw-8Hq2vN,a note,",
    );

    expect(parseBrowserCsv(csv).errors).toEqual([
      {
        row: 2,
        message:
          "This row has 6 fields where the header has 5, though every surplus field is empty, " +
          "so a trailing comma is the likely cause",
      },
    ]);
  });

  it("refuses a row whose quoted password holds an undoubled quote, and keeps its neighbours", () => {
    // An exporter that quoted the password but failed to double the `"` inside
    // it. The row has exactly as many fields as the header, so nothing else here
    // would refuse it -- it would arrive as an item whose password is
    // `fixture-pw9Kd3xR"` rather than `fixture-pw"9Kd3xR`: the same length, one
    // character deleted from the middle and one appended at the end, and no
    // error to tell the user which of their logins to check.
    const csv = withRows(
      "chrome-passwords.csv",
      "before.example.com,https://before.example.com/,ada,fixture-pw-8Hq2vN,",
      'broken.example.com,https://broken.example.com/,ada,"fixture-pw"9Kd3xR",',
      "after.example.com,https://after.example.com/,bob,fixture-pw-7Jm4tQ,",
    );

    const result = parseBrowserCsv(csv);

    expect(result.errors).toEqual([
      { row: 3, message: "This row has a quote inside a quoted field that is not doubled" },
    ]);
    // The rows either side are the point: one damaged line must not cost the
    // user the rest of the file.
    expect(result.items.map((item) => item.name)).toEqual([
      "before.example.com",
      "after.example.com",
    ]);
    expect(result.items.map((item) => item.password)).toEqual([
      "fixture-pw-8Hq2vN",
      "fixture-pw-7Jm4tQ",
    ]);
  });

  it("answers with one error for a CSV that is not a browser export, instead of throwing", () => {
    // Detection routes this file to the generic mapper, so the parser should
    // never see it -- but "never throws" has to hold for the caller that gets
    // the routing wrong too, and a thrown exception here would take down the
    // import screen rather than one row.
    expect(parseBrowserCsv(read("unknown-manager-export.csv"))).toEqual({
      items: [],
      errors: [
        {
          row: 1,
          message: "This file has no url, username and password columns, so no browser export layout fits it",
        },
      ],
    });
  });

  it("answers with one error for an empty file, where there is no header at all", () => {
    expect(parseBrowserCsv("")).toEqual({
      items: [],
      errors: [
        {
          row: 1,
          message: "This file has no url, username and password columns, so no browser export layout fits it",
        },
      ],
    });
  });
});

describe("parseBrowserCsv, on files mangled in transit", () => {
  it("maps a Chrome export whose header a spreadsheet rewrote in capitals and spaced out", () => {
    // Column names are matched lowercased and trimmed, the way detection
    // already matches them. A round trip through a spreadsheet changes the case
    // and can add a space; neither changes which column holds the password.
    // The header is written out here rather than taken from the fixture,
    // because being different from the fixture's is the point of the case.
    const csv = [
      " Name , URL , Username , Password , Note ",
      "mail.example.com,https://mail.example.com/,ada@example.com,fixture-pw-8Hq2vN,note",
    ].join("\n");

    const item = only(parseBrowserCsv(csv));

    expect(item.username).toBe("ada@example.com");
    expect(item.password).toBe("fixture-pw-8Hq2vN");
  });

  it("reads the first of two columns sharing a name, as the CSV reader does", () => {
    // `csv.ts` records that real exports duplicate a column name, and that the
    // second `password` is the one more likely to be empty -- so last-wins here
    // would turn every login in such a file into an empty-password error row.
    const csv = [
      "name,url,username,password,password",
      "mail.example.com,https://mail.example.com/,ada,fixture-pw-8Hq2vN,",
    ].join("\n");

    expect(only(parseBrowserCsv(csv)).password).toBe("fixture-pw-8Hq2vN");
  });

  it("maps a Chrome export saved with CRLF line endings", () => {
    // Windows exports end rows with CRLF. A reader that split on \n would leave
    // a \r on the last column of the header and on the note of every row.
    const csv = withRows(
      "chrome-passwords.csv",
      "mail.example.com,https://mail.example.com/,ada@example.com,fixture-pw-8Hq2vN,a note",
    ).replaceAll("\n", "\r\n");

    expect(only(parseBrowserCsv(csv)).notes).toBe("a note");
  });

  it("maps a Chrome export that still carries a UTF-8 BOM on its first column name", () => {
    // A BOM makes the first header name "\uFEFFname", so a lookup for "name"
    // misses and the first column of every row is unreachable. Written as an
    // escape rather than a literal: a literal BOM here is invisible on screen
    // and the case would silently stop being the case it claims to be.
    const csv = "\uFEFF" + withRows(
      "chrome-passwords.csv",
      "mail.example.com,https://mail.example.com/,ada@example.com,fixture-pw-8Hq2vN,a note",
    );

    expect(only(parseBrowserCsv(csv)).name).toBe("mail.example.com");
  });
});
