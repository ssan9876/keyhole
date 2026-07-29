import { describe, expect, it } from "vitest";
import { NOTICE, only, read, withRows } from "./fixture.js";
import { parseKeePassCsv } from "./keepass.js";

const KEEPASS_1X = "keepass2-export.csv";
const KEEPASSXC = "keepassxc-export.csv";

/**
 * A KeePassXC row: Group,Title,Username,Password,URL,Notes,TOTP,Icon,Last
 * Modified,Created.
 *
 * Every field is quoted because KeePassXC quotes every field, and because a row
 * one field short of the header would be refused for ending before its password
 * column rather than testing what the case claims.
 */
const xcRow = (
  group: string,
  title: string,
  username: string,
  password: string,
  url: string,
  notes: string,
  totp = "",
): string =>
  [group, title, username, password, url, notes, totp, "0", "2026-07-01T00:00:00Z", "2026-06-01T00:00:00Z"]
    .map((value) => `"${value}"`)
    .join(",");

describe("parseKeePassCsv, against the KeePass 1.x sample export", () => {
  it("maps Account, Login Name, Password, Web Site and Comments, with no folder", () => {
    // KeePass 2's "KeePass CSV (1.x)" export. It carries no group column at
    // all, so every item is at the root — that is the format, not a loss.
    expect(parseKeePassCsv(read(KEEPASS_1X))).toEqual({
      items: [
        {
          type: "login",
          name: "Example Mail",
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
          name: "Example Forum",
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

describe("parseKeePassCsv, against the KeePassXC sample export", () => {
  it("maps Group, Title, Username, Password, URL and Notes, keeping the Root segment", () => {
    // `Root/Personal` stays two segments, leading `Root` included. KeePassXC
    // names the database's root group, the user may rename it, and stripping a
    // segment because it is spelled "Root" would delete a real folder in one
    // database and nothing in another. See the comment on `FOLDER_SEPARATOR`.
    expect(parseKeePassCsv(read(KEEPASSXC))).toEqual({
      items: [
        {
          type: "login",
          name: "Example Mail",
          username: "ada@example.com",
          password: "fixture-pw-8Hq2vN",
          urls: ["https://mail.example.com"],
          notes: NOTICE,
          favorite: false,
          folderPath: ["Root", "Personal"],
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
          folderPath: ["Root", "Personal"],
          extra: [],
          sourceRow: 3,
        },
      ],
      errors: [],
    });
  });
});

describe("parseKeePassCsv, on the KeePassXC group path", () => {
  it("splits a nested group at the slash into one segment per folder", () => {
    const csv = withRows(
      KEEPASSXC,
      xcRow(
        "Root/Work/Servers/Europe",
        "Example Wiki",
        "ada",
        "fixture-pw-9Kd3xR",
        "https://wiki.example.org",
        "",
      ),
    );

    expect(only(parseKeePassCsv(csv)).folderPath).toEqual([
      "Root",
      "Work",
      "Servers",
      "Europe",
    ]);
  });

  it("keeps a leading Root segment rather than treating the name as punctuation", () => {
    // Stated as its own case because it is a decision, not a side effect: a
    // KeePassXC user will see a folder called Root wrapping their import, and
    // that is preferred to a rule that fires on a name the user can change.
    const csv = withRows(
      KEEPASSXC,
      xcRow("Root", "Loose entry", "ada", "fixture-pw-9Kd3xR", "https://a.example.com", ""),
    );

    expect(only(parseKeePassCsv(csv)).folderPath).toEqual(["Root"]);
  });

  it("places an entry with an empty group at the root rather than in a folder with no name", () => {
    const csv = withRows(
      KEEPASSXC,
      xcRow("", "Loose entry", "ada", "fixture-pw-9Kd3xR", "https://a.example.com", ""),
    );

    expect(only(parseKeePassCsv(csv)).folderPath).toEqual([]);
  });
});

describe("parseKeePassCsv, on what Keyhole has no field for", () => {
  it("carries KeePassXC's TOTP column into extra as a second factor", () => {
    // `kind` from where the value sat: KeePassXC's TOTP column holds the seed.
    // Keyhole has no TOTP field in v1 (spec section 1, non-goals).
    const seed = "otpauth://totp/Example:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    const csv = withRows(
      KEEPASSXC,
      xcRow(
        "Root/Personal",
        "Example Mail",
        "ada",
        "fixture-pw-8Hq2vN",
        "https://mail.example.com",
        "",
        seed,
      ),
    );

    expect(only(parseKeePassCsv(csv)).extra).toEqual([
      { name: "TOTP", value: seed, kind: "totp" },
    ]);
  });

  it("leaves extra empty when the TOTP column is present but empty", () => {
    const csv = withRows(
      KEEPASSXC,
      xcRow(
        "Root/Personal",
        "Example Mail",
        "ada",
        "fixture-pw-8Hq2vN",
        "https://mail.example.com",
        "",
      ),
    );

    expect(only(parseKeePassCsv(csv)).extra).toEqual([]);
  });
});

describe("parseKeePassCsv, on the password itself", () => {
  it("keeps a KeePassXC password holding both a comma and a quote as the file escaped it", () => {
    const csv = withRows(
      KEEPASSXC,
      '"Root/Personal","Example Forum","ada","fixture,pw""with""quotes",' +
        '"https://forum.example.org","","","0","2026-07-01T00:00:00Z","2026-06-01T00:00:00Z"',
    );

    expect(only(parseKeePassCsv(csv)).password).toBe('fixture,pw"with"quotes');
  });

  it("keeps a KeePass 1.x password holding both a comma and a quote as the file escaped it", () => {
    const csv = withRows(
      KEEPASS_1X,
      '"Example Forum","ada","fixture,pw""with""quotes","https://forum.example.org",""',
    );

    expect(only(parseKeePassCsv(csv)).password).toBe('fixture,pw"with"quotes');
  });

  it("keeps a trailing space in a password rather than trimming it", () => {
    const csv = withRows(
      KEEPASSXC,
      xcRow(
        "Root/Personal",
        "Example Mail",
        "ada",
        "fixture-pw-8Hq2vN ",
        "https://mail.example.com",
        "",
      ),
    );

    expect(only(parseKeePassCsv(csv)).password).toBe("fixture-pw-8Hq2vN ");
  });
});

describe("parseKeePassCsv, on multi-line notes", () => {
  it("keeps both lines of a KeePass 1.x Comments field that spans a newline", () => {
    // KeePass's Comments and KeePassXC's Notes routinely hold multi-line text —
    // it is where a KeePass user keeps everything the entry has no field for.
    // A line-splitting reader drops everything after the first line.
    const csv = withRows(
      KEEPASS_1X,
      '"Router notes","ada","fixture-pw-9Kd3xR","https://router.example.org","first line\nsecond line"',
    );

    expect(only(parseKeePassCsv(csv)).notes).toBe("first line\nsecond line");
  });
});

describe("parseKeePassCsv, on rows it must refuse", () => {
  it("refuses an entry whose multi-line Notes opens a quote it never closes", () => {
    // KeePass's characteristic malformation. Notes are the multi-line column,
    // so an export truncated mid-note — or hand-edited — ends inside a quoted
    // field, and everything from that quote onwards is swallowed into one
    // value. Importing that would store a password the user never had.
    const csv = withRows(
      KEEPASS_1X,
      '"Example Mail","ada","fixture-pw-8Hq2vN","https://mail.example.com","fine"',
      '"Router notes","ada","fixture-pw-9Kd3xR","https://router.example.org","first line',
    );

    const result = parseKeePassCsv(csv);

    expect(result.errors).toEqual([
      { row: 3, message: "This row opens a quoted field that is never closed" },
    ]);
    expect(result.items.map((item) => item.password)).toEqual(["fixture-pw-8Hq2vN"]);
  });

  it("refuses an entry with an empty password and keeps the passwords either side", () => {
    const csv = withRows(
      KEEPASSXC,
      xcRow("Root", "Good", "ada", "fixture-pw-8Hq2vN", "https://good.example.com", ""),
      xcRow("Root", "Blank", "ada", "", "https://blank.example.com", ""),
      xcRow("Root", "Later", "bob", "fixture-pw-9Kd3xR", "https://later.example.com", ""),
    );

    const result = parseKeePassCsv(csv);

    expect(result.errors).toEqual([
      { row: 3, message: "This row has an empty password, so it was not imported" },
    ]);
    expect(result.items.map((item) => item.password)).toEqual([
      "fixture-pw-8Hq2vN",
      "fixture-pw-9Kd3xR",
    ]);
  });

  it("refuses an entry that ends before its password column rather than importing a blank", () => {
    const csv = withRows(KEEPASSXC, '"Root","Short","ada"');

    expect(parseKeePassCsv(csv).errors).toEqual([
      { row: 2, message: "This row ends before its password column" },
    ]);
  });

  it("answers with one error for a CSV that is neither KeePass layout, instead of throwing", () => {
    expect(parseKeePassCsv(read("unknown-manager-export.csv"))).toEqual({
      items: [],
      errors: [
        {
          row: 1,
          message:
            "This file matches neither the KeePass 1.x nor the KeePassXC column names, " +
            "so it is not a KeePass CSV export",
        },
      ],
    });
  });
});

describe("parseKeePassCsv, on choosing between the two layouts", () => {
  it("reads a KeePassXC export whose columns are reordered to the same items as the fixture's", () => {
    // Lookups are by column name, so order does not decide anything. This
    // compares two parses rather than a literal, so it asserts only the claim
    // in its name; which column means what is the golden's claim.
    const reordered = [
      '"Notes","Password","Title","Group","URL","Username","TOTP","Icon","Last Modified","Created"',
      `"${NOTICE}","fixture-pw-8Hq2vN","Example Mail","Root/Personal",` +
        '"https://mail.example.com","ada@example.com","","0","2026-07-01T00:00:00Z","2026-06-01T00:00:00Z"',
      '"","fixture,pw,with,commas","Example Forum","Root/Personal",' +
        '"https://forum.example.org","ada","","0","2026-07-01T00:00:00Z","2026-06-01T00:00:00Z"',
    ].join("\n");

    expect(parseKeePassCsv(reordered).items).toEqual(parseKeePassCsv(read(KEEPASSXC)).items);
  });

  it("reads a KeePass 1.x header a spreadsheet rewrote in capitals and spaced out", () => {
    // Column names are matched lowercased and trimmed, the way detection
    // matches them. A round trip through a spreadsheet changes the case, can
    // add a space, and drops the quotes KeePass wrote around every name; none
    // of that changes which column holds the password.
    const csv = [
      " ACCOUNT , LOGIN NAME , PASSWORD , WEB SITE , COMMENTS ",
      '"Example Mail","ada@example.com","fixture-pw-8Hq2vN","https://mail.example.com",""',
    ].join("\n");

    const item = only(parseKeePassCsv(csv));

    expect(item.username).toBe("ada@example.com");
    expect(item.password).toBe("fixture-pw-8Hq2vN");
  });
});
