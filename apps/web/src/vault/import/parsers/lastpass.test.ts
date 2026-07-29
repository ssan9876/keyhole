import { describe, expect, it } from "vitest";
import { NOTICE, only, read, withRows } from "./fixture.js";
import { parseLastPassCsv } from "./lastpass.js";

const FIXTURE = "lastpass-export.csv";

/** A row of the fixture's shape: url,username,password,totp,extra,name,grouping,fav */
const row = (
  url: string,
  username: string,
  password: string,
  totp: string,
  extra: string,
  name: string,
  grouping: string,
  fav: string,
): string => [url, username, password, totp, extra, name, grouping, fav].join(",");

describe("parseLastPassCsv, against the sample export", () => {
  it("maps url, username, password, the extra note, the name and the backslash grouping", () => {
    // The whole parsed output, not a spot check. The fixture's three rows are
    // two logins and the secure note LastPass marks with `http://sn`.
    expect(parseLastPassCsv(read(FIXTURE))).toEqual({
      items: [
        {
          type: "login",
          name: "Example Mail",
          username: "ada@example.com",
          password: "fixture-pw-8Hq2vN",
          urls: ["https://mail.example.com"],
          notes: NOTICE,
          favorite: true,
          folderPath: ["Personal"],
          extra: [],
          sourceRow: 2,
        },
        {
          type: "login",
          name: "Example Forum",
          username: "ada",
          password: "fixture,pw,with,commas",
          urls: ["https://forum.example.org"],
          notes: "",
          favorite: false,
          // `Personal\Forums` is two segments. LastPass nests with a backslash,
          // which is why `folderPath` is segments rather than a string: written
          // through as one name it would become a folder literally called
          // `Personal\Forums`.
          folderPath: ["Personal", "Forums"],
          extra: [],
          sourceRow: 3,
        },
        {
          type: "note",
          name: "Router notes",
          username: "",
          password: "",
          // The marker is not a URL and is not carried as one.
          urls: [],
          notes: "first line\nsecond line",
          favorite: false,
          folderPath: ["Work"],
          extra: [],
          // The line the record *begins* on, which is what the user can find in
          // their own file. The quoted note body spans lines 4 and 5.
          sourceRow: 4,
        },
      ],
      errors: [],
    });
  });
});

describe("parseLastPassCsv, on the http://sn secure-note marker", () => {
  it("reads a row whose url is http://sn as a note rather than a login with that URL", () => {
    // LastPass's marker for a secure note, and the whole of it: the row is
    // otherwise shaped exactly like a login. Missing it turns every note into a
    // login pointing at a host called `sn`, and — because a note row carries no
    // password — into an empty-password error row as well, so the user loses
    // the note twice over.
    const csv = withRows(
      FIXTURE,
      row("http://sn", "", "", "", "the note body", "Wifi codes", "Work", "0"),
    );

    const item = only(parseLastPassCsv(csv));

    expect(item.type).toBe("note");
    expect(item.urls).toEqual([]);
  });

  it("keeps a note row rather than refusing it for having no password", () => {
    // Only a login needs a password. A note with an empty password column is
    // the ordinary case for every secure note LastPass exports.
    const csv = withRows(
      FIXTURE,
      row("http://sn", "", "", "", "the note body", "Wifi codes", "Work", "0"),
    );

    const result = parseLastPassCsv(csv);

    expect(result.errors).toEqual([]);
    expect(only(result).notes).toBe("the note body");
  });

  it("still reads http://sn as the marker when a spreadsheet has recased it", () => {
    // The marker is compared trimmed and lowercased, as column names are. A
    // round trip through a spreadsheet is the ordinary way an export arrives
    // recased, and it must not silently turn every note back into a login.
    const csv = withRows(
      FIXTURE,
      row("HTTP://SN", "", "", "", "the note body", "Wifi codes", "Work", "0"),
    );

    expect(only(parseLastPassCsv(csv)).type).toBe("note");
  });

  it("treats a real http://sn/ URL with a path as a login, not as the marker", () => {
    // The marker is the exact string. A host genuinely called `sn` is unlikely
    // but not impossible, and anything past the bare authority is not what
    // LastPass writes for a note.
    const csv = withRows(
      FIXTURE,
      row("http://sn/login", "ada", "fixture-pw-8Hq2vN", "", "", "Intranet", "Work", "0"),
    );

    const item = only(parseLastPassCsv(csv));

    expect(item.type).toBe("login");
    expect(item.urls).toEqual(["http://sn/login"]);
  });
});

describe("parseLastPassCsv, on the password itself", () => {
  it("keeps a password holding both a comma and a quote exactly as the file escaped it", () => {
    // The file holds `"fixture,pw""with""quotes"` and the item must hold
    // fixture,pw"with"quotes. A naive split gives this row ten fields and a
    // password of `"fixture`.
    const csv = withRows(
      FIXTURE,
      'https://forum.example.org,ada,"fixture,pw""with""quotes",,,Example Forum,Personal,0',
    );

    expect(only(parseLastPassCsv(csv)).password).toBe('fixture,pw"with"quotes');
  });

  it("keeps a trailing space in a password rather than trimming it", () => {
    const csv = withRows(
      FIXTURE,
      'https://forum.example.org,ada,"fixture-pw-8Hq2vN ",,,Example Forum,Personal,0',
    );

    expect(only(parseLastPassCsv(csv)).password).toBe("fixture-pw-8Hq2vN ");
  });
});

describe("parseLastPassCsv, on the grouping column", () => {
  it("splits a nested grouping at the backslash into one segment per folder", () => {
    const csv = withRows(
      FIXTURE,
      row(
        "https://wiki.example.org",
        "ada",
        "fixture-pw-9Kd3xR",
        "",
        "",
        "Example Wiki",
        "Work\\Servers\\Europe",
        "0",
      ),
    );

    expect(only(parseLastPassCsv(csv)).folderPath).toEqual(["Work", "Servers", "Europe"]);
  });

  it("places a row with an empty grouping at the root rather than in a folder with no name", () => {
    const csv = withRows(
      FIXTURE,
      row("https://wiki.example.org", "ada", "fixture-pw-9Kd3xR", "", "", "Example Wiki", "", "0"),
    );

    expect(only(parseLastPassCsv(csv)).folderPath).toEqual([]);
  });

  it("keeps the spaces around a folder name, since a rename is not this layer's to make", () => {
    const csv = withRows(
      FIXTURE,
      row(
        "https://wiki.example.org",
        "ada",
        "fixture-pw-9Kd3xR",
        "",
        "",
        "Example Wiki",
        " Work \\ Servers ",
        "0",
      ),
    );

    expect(only(parseLastPassCsv(csv)).folderPath).toEqual([" Work ", " Servers "]);
  });
});

describe("parseLastPassCsv, on what Keyhole has no field for", () => {
  it("carries the totp column into extra as a second factor, not as a custom field", () => {
    // `kind` comes from where the value sat: LastPass's `totp` column is the
    // seed itself. Keyhole has no TOTP field in v1 (spec section 1, non-goals),
    // so dropping it would lose a second factor the user believes they moved.
    const seed = "otpauth://totp/Example:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    const csv = withRows(
      FIXTURE,
      row("https://mail.example.com", "ada", "fixture-pw-8Hq2vN", seed, "", "Example Mail", "", "0"),
    );

    expect(only(parseLastPassCsv(csv)).extra).toEqual([
      { name: "totp", value: seed, kind: "totp" },
    ]);
  });

  it("leaves extra empty when the totp column is present but empty", () => {
    // Otherwise every ordinary login would carry an empty `totp` and the
    // preview screen would warn about the loss of nothing on every row.
    const csv = withRows(
      FIXTURE,
      row("https://mail.example.com", "ada", "fixture-pw-8Hq2vN", "", "", "Example Mail", "", "0"),
    );

    expect(only(parseLastPassCsv(csv)).extra).toEqual([]);
  });

  it("reads fav 1 as favourite and 0 as not, rather than any non-empty value", () => {
    const csv = withRows(
      FIXTURE,
      row("https://a.example.com", "ada", "fixture-pw-8Hq2vN", "", "", "A", "", "1"),
      row("https://b.example.com", "ada", "fixture-pw-9Kd3xR", "", "", "B", "", "0"),
    );

    expect(parseLastPassCsv(csv).items.map((item) => item.favorite)).toEqual([true, false]);
  });
});

describe("parseLastPassCsv, on rows it must refuse", () => {
  it("refuses a login row with an empty password and keeps the passwords either side", () => {
    // LastPass's characteristic malformation: a note whose `http://sn` marker
    // has been lost — to a hand edit, or to a spreadsheet rewriting the URL
    // column — arrives as a login with no password. Importing it as a blank
    // password over a real one has no undo, because the user is about to be
    // told to delete the export.
    const csv = withRows(
      FIXTURE,
      row("https://good.example.com", "ada", "fixture-pw-8Hq2vN", "", "", "Good", "", "0"),
      row("https://blank.example.com", "ada", "", "", "was a note", "Lost marker", "", "0"),
      row("https://later.example.com", "bob", "fixture-pw-9Kd3xR", "", "", "Later", "", "0"),
    );

    const result = parseLastPassCsv(csv);

    expect(result.errors).toEqual([
      { row: 3, message: "This row has an empty password, so it was not imported" },
    ]);
    expect(result.items.map((item) => item.password)).toEqual([
      "fixture-pw-8Hq2vN",
      "fixture-pw-9Kd3xR",
    ]);
  });

  it("refuses a login row that ends before its password column rather than importing a blank", () => {
    const csv = withRows(
      FIXTURE,
      row("https://good.example.com", "ada", "fixture-pw-8Hq2vN", "", "", "Good", "", "0"),
      "https://short.example.com,ada",
    );

    const result = parseLastPassCsv(csv);

    expect(result.errors).toEqual([{ row: 3, message: "This row ends before its password column" }]);
    expect(result.items.map((item) => item.password)).toEqual(["fixture-pw-8Hq2vN"]);
  });

  it("refuses a row with more fields than the header instead of importing its first part", () => {
    const csv = withRows(
      FIXTURE,
      row("https://good.example.com", "ada", "fixture-pw-8Hq2vN", "", "", "Good", "", "0"),
      "https://split.example.com,ada,fixture,pw,with,commas,Split,Personal,0",
    );

    const result = parseLastPassCsv(csv);

    expect(result.errors).toEqual([
      {
        row: 3,
        message:
          "This row has 9 fields where the header has 8, so a value has been split across columns",
      },
    ]);
    expect(result.items.map((item) => item.password)).toEqual(["fixture-pw-8Hq2vN"]);
  });

  it("refuses a row the CSV reader flagged, rather than importing its swallowed tail", () => {
    const csv = withRows(
      FIXTURE,
      row("https://good.example.com", "ada", "fixture-pw-8Hq2vN", "", "", "Good", "", "0"),
      'https://truncated.example.com,ada,"fixture-pw-9K',
    );

    const result = parseLastPassCsv(csv);

    expect(result.errors).toEqual([
      { row: 3, message: "This row opens a quoted field that is never closed" },
    ]);
    expect(result.items.map((item) => item.password)).toEqual(["fixture-pw-8Hq2vN"]);
  });

  it("answers with one error for a CSV that is not a LastPass export, instead of throwing", () => {
    // Detection routes such a file to the generic mapper, so this parser should
    // never see it — but "never throws" has to hold for the caller that gets
    // the routing wrong too.
    expect(parseLastPassCsv(read("unknown-manager-export.csv"))).toEqual({
      items: [],
      errors: [
        {
          row: 1,
          message:
            "This file has no password and grouping columns, so it is not a LastPass CSV export",
        },
      ],
    });
  });
});
