import { describe, expect, it } from "vitest";
import { DEFLATED, zipOf } from "../zip-fixture.js";
import { NOTICE, only, read, readBytes, withRows } from "./fixture.js";
import {
  parseOnePassword1pux,
  parseOnePasswordCsv,
  parseOnePasswordExportData,
} from "./onepassword.js";

const ARCHIVE = "1password-export.1pux";
const CSV = "1password-export.csv";

/* -------------------------------------------------------------------------- */
/*                        Builders for the .1pux's JSON                        */
/* -------------------------------------------------------------------------- */

/** One `export.data`, holding one account with one vault of the given items. */
const inVault = (vault: string, ...items: unknown[]): string =>
  JSON.stringify({
    accounts: [
      {
        attrs: { accountName: "Example Person", name: "Example Person", email: "ada@example.com" },
        vaults: [{ attrs: { uuid: "B".repeat(26), name: vault, type: "P" }, items }],
      },
    ],
  });

/** The two `loginFields` entries every ordinary 1Password login carries. */
const credentials = (username: string, password: string): unknown[] => [
  { value: username, id: "username", name: "username", designation: "username" },
  { value: password, id: "password", name: "password", designation: "password" },
];

/** A 1Password login item (category `001`). */
const login = (
  title: string,
  loginFields: readonly unknown[],
  rest: Record<string, unknown> = {},
): Record<string, unknown> => ({
  uuid: "C".repeat(26),
  favIndex: 0,
  createdAt: 1751328000,
  updatedAt: 1751328000,
  state: "active",
  categoryUuid: "001",
  details: { loginFields, notesPlain: "", sections: [], passwordHistory: [] },
  overview: { title, subtitle: "", url: "", urls: [] },
  ...rest,
});

/** A login whose `details` carry the given sections beside its credentials. */
const withSections = (title: string, sections: readonly unknown[]): Record<string, unknown> =>
  login(title, credentials("ada", "fixture-pw-8Hq2vN"), {
    details: {
      loginFields: credentials("ada", "fixture-pw-8Hq2vN"),
      notesPlain: "",
      sections,
      passwordHistory: [],
    },
  });

/** An archive shaped like a `.1pux`, holding the given `export.data`. */
const archiveOf = (exportData: string): Uint8Array =>
  zipOf(
    { name: "export.attributes", body: '{"version":3,"description":"1Password Unencrypted Export"}' },
    { name: "export.data", body: exportData },
  );

/* -------------------------------------------------------------------------- */
/*                                   The CSV                                   */
/* -------------------------------------------------------------------------- */

describe("parseOnePasswordCsv, against the sample export", () => {
  it("maps both rows in full, including the password written with commas in it", () => {
    expect(parseOnePasswordCsv(read(CSV))).toEqual({
      items: [
        {
          type: "login",
          name: "Example Mail",
          username: "ada@example.com",
          password: "fixture-pw-8Hq2vN",
          urls: ["https://mail.example.com"],
          notes: NOTICE,
          favorite: true,
          folderPath: [],
          extra: [{ name: "Tags", value: "Personal", kind: "metadata" }],
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
          extra: [{ name: "Tags", value: "Personal;Forums", kind: "metadata" }],
          sourceRow: 3,
        },
      ],
      errors: [],
    });
  });
});

describe("parseOnePasswordCsv, on the reconstruction its header line is", () => {
  // `.superpowers/sdd/task-2-report.md` lists this fixture's header as one of
  // the four it could not source from a real export: the column *names* are a
  // reconstruction and their *order* is a guess. Positional access against a
  // wrong guess writes a password into the notes field of a real export and
  // reports nothing; a name lookup produces a visible error instead.

  it("maps the password from the column named Password however the header is ordered", () => {
    const csv = [
      "Notes,Tags,Archived,Favorite,OTPAuth,Password,Username,Url,Title",
      "a note,,false,false,,fixture-pw-9Kd3xR,ada,https://wiki.example.org,Example Wiki",
    ].join("\n");

    expect(only(parseOnePasswordCsv(csv)).password).toBe("fixture-pw-9Kd3xR");
  });

  it("finds the address column whether the export spells it Url or Website", () => {
    const csv = [
      "Title,Website,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes",
      "Example Wiki,https://wiki.example.org,ada,fixture-pw-9Kd3xR,,false,false,,",
    ].join("\n");

    expect(only(parseOnePasswordCsv(csv)).urls).toEqual(["https://wiki.example.org"]);
  });

  it("reads a file with no password column as not a 1Password export at all", () => {
    // Detection routes such a file elsewhere and this parser should never see
    // it, but "never throws" has to hold for the caller that gets the routing
    // wrong too — and the alternative is a file of blank passwords.
    const csv = "Title,Url,Username,OTPAuth\nExample Mail,https://mail.example.com,ada,\n";

    expect(parseOnePasswordCsv(csv)).toEqual({
      items: [],
      errors: [
        { row: 1, message: "This file has no Password column, so it is not a 1Password CSV export" },
      ],
    });
  });
});

describe("parseOnePasswordCsv, on a row it will not turn into an item", () => {
  it("refuses a row whose password was written with an unquoted comma, keeping the rows around it", () => {
    // The characteristic damage in a CSV of passwords: from the unquoted comma
    // on, the values no longer line up with the columns naming them, so what
    // this row calls a password is only part of one.
    const csv = withRows(
      CSV,
      "Example Mail,https://mail.example.com,ada,fixture-pw-8Hq2vN,,false,false,,",
      "Example Forum,https://forum.example.org,ada,fixture,pw,unquoted,,false,false,Personal,a note",
      "Example Wiki,https://wiki.example.org,ada,fixture-pw-9Kd3xR,,false,false,,",
    );

    const result = parseOnePasswordCsv(csv);

    expect(result.errors).toEqual([
      {
        row: 3,
        message: "This row has 11 fields where the header has 9, so a value has been split across columns",
      },
    ]);
    expect(result.items.map((item) => item.name)).toEqual(["Example Mail", "Example Wiki"]);
  });

  it("refuses a row with an empty password rather than importing a blank over a real one", () => {
    const csv = withRows(CSV, "Example Mail,https://mail.example.com,ada,,,false,false,,");

    expect(parseOnePasswordCsv(csv).errors).toEqual([
      { row: 2, message: "This row has an empty password, so it was not imported" },
    ]);
  });

  it("refuses a row that ends before its password column", () => {
    const csv = withRows(CSV, "Example Mail,https://mail.example.com,ada");

    expect(parseOnePasswordCsv(csv).errors).toEqual([
      { row: 2, message: "This row ends before its password column" },
    ]);
  });
});

describe("parseOnePasswordCsv, on what Keyhole has no field for", () => {
  it("carries the OTPAuth column as a second factor, since Keyhole has no TOTP field", () => {
    const uri = "otpauth://totp/Example:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    const csv = withRows(
      CSV,
      `Example Mail,https://mail.example.com,ada,fixture-pw-8Hq2vN,${uri},false,false,,`,
    );

    expect(only(parseOnePasswordCsv(csv)).extra).toEqual([
      { name: "OTPAuth", value: uri, kind: "totp" },
    ]);
  });

  it("carries tags whole and leaves the item at the root, rather than guessing a separator", () => {
    // 1Password's CSV carries no vault column, so tags are the only grouping in
    // the file — and an item can have several, so no one of them is "the"
    // folder. Splitting them would need a separator this reconstructed fixture
    // only guesses at, and picking the first would be a guess that looked like
    // a fact. Same reasoning as Bitwarden's `collectionIds`.
    const csv = withRows(
      CSV,
      'Example Mail,https://mail.example.com,ada,fixture-pw-8Hq2vN,,false,false,"Work;Servers/Prod",',
    );

    const item = only(parseOnePasswordCsv(csv));

    expect(item.folderPath).toEqual([]);
    expect(item.extra).toEqual([{ name: "Tags", value: "Work;Servers/Prod", kind: "metadata" }]);
  });

  it("records that an item was archived and still imports it, since the user did not delete it", () => {
    const csv = withRows(
      CSV,
      "Example Mail,https://mail.example.com,ada,fixture-pw-8Hq2vN,,false,true,,",
    );

    const item = only(parseOnePasswordCsv(csv));

    expect(item.password).toBe("fixture-pw-8Hq2vN");
    expect(item.extra).toEqual([{ name: "Archived", value: "true", kind: "metadata" }]);
  });

  it("carries nothing for an item that is not archived, so the preview warns about nothing", () => {
    const csv = withRows(
      CSV,
      "Example Mail,https://mail.example.com,ada,fixture-pw-8Hq2vN,,false,false,,",
    );

    expect(only(parseOnePasswordCsv(csv)).extra).toEqual([]);
  });
});

/* -------------------------------------------------------------------------- */
/*                                  The .1pux                                  */
/* -------------------------------------------------------------------------- */

describe("parseOnePassword1pux, against the sample archive", () => {
  it("reads export.data out of the ZIP and maps its one item in full", async () => {
    expect(await parseOnePassword1pux(readBytes(ARCHIVE))).toEqual({
      items: [
        {
          type: "login",
          name: "Example Mail",
          username: "ada@example.com",
          password: "fixture-pw-8Hq2vN",
          urls: ["https://mail.example.com"],
          notes: NOTICE,
          favorite: false,
          folderPath: ["Personal"],
          extra: [],
          sourceRow: 1,
        },
      ],
      errors: [],
    });
  });

  it("reads a deflated archive too, which is what a real export writes", async () => {
    const data = inVault("Personal", login("Example Mail", credentials("ada", "fixture-pw-8Hq2vN")));
    const archive = zipOf({ name: "export.data", body: data, method: DEFLATED });

    expect(only(await parseOnePassword1pux(archive)).password).toBe("fixture-pw-8Hq2vN");
  });
});

describe("parseOnePassword1pux, on a file that is not the archive it claims to be", () => {
  it("reports a file that is not an archive rather than throwing", async () => {
    const notAnArchive = new TextEncoder().encode("Title,Url,Username,Password\n");

    expect(await parseOnePassword1pux(notAnArchive)).toEqual({
      items: [],
      errors: [
        {
          row: 1,
          message:
            "This file could not be read as a 1Password .1pux archive. This file does not end " +
            "with a ZIP end-of-central-directory record, so it is not a ZIP archive or the " +
            "download did not finish",
        },
      ],
    });
  });

  it("names what an archive holds when it has no export.data, since Dashlane also ships a ZIP", async () => {
    const dashlane = zipOf(
      { name: "credentials.csv", body: "username,title,password\n" },
      { name: "securenotes.csv", body: "title,note\n" },
    );

    expect(await parseOnePassword1pux(dashlane)).toEqual({
      items: [],
      errors: [
        {
          row: 1,
          message:
            "This file could not be read as a 1Password .1pux archive. This archive has no " +
            '"export.data" in it; it holds credentials.csv, securenotes.csv',
        },
      ],
    });
  });

  it("reports an export.data that is not JSON rather than throwing", async () => {
    expect(await parseOnePassword1pux(archiveOf("not json at all"))).toEqual({
      items: [],
      errors: [{ row: 1, message: "This file is not valid JSON, so nothing could be read from it" }],
    });
  });

  it("reports an export.data with no accounts array, so a wrong format is named not guessed", () => {
    expect(parseOnePasswordExportData('{"version":3}')).toEqual({
      items: [],
      errors: [
        { row: 1, message: "This file has no accounts array, so it is not a 1Password .1pux export" },
      ],
    });
  });
});

describe("parseOnePasswordExportData, on where an item sits in the export", () => {
  it("takes the vault's name as the item's folder", () => {
    expect(
      only(
        parseOnePasswordExportData(
          inVault("Work", login("Wiki", credentials("ada", "fixture-pw-9Kd3xR"))),
        ),
      ).folderPath,
    ).toEqual(["Work"]);
  });

  it("keeps a vault name containing a slash whole, since 1Password vaults do not nest", () => {
    expect(
      only(
        parseOnePasswordExportData(
          inVault("Home/Office", login("Wiki", credentials("ada", "fixture-pw-9Kd3xR"))),
        ),
      ).folderPath,
    ).toEqual(["Home/Office"]);
  });

  it("counts an item's position across every vault of every account", () => {
    const data = JSON.stringify({
      accounts: [
        {
          attrs: { name: "Personal account" },
          vaults: [
            {
              attrs: { name: "Personal" },
              items: [login("One", credentials("ada", "fixture-pw-1"))],
            },
            { attrs: { name: "Shared" }, items: [login("Two", credentials("ada", "fixture-pw-2"))] },
          ],
        },
        {
          attrs: { name: "Work account" },
          vaults: [
            { attrs: { name: "Work" }, items: [login("Three", credentials("ada", "fixture-pw-3"))] },
          ],
        },
      ],
    });

    expect(parseOnePasswordExportData(data).items.map((item) => [item.name, item.sourceRow])).toEqual(
      [
        ["One", 1],
        ["Two", 2],
        ["Three", 3],
      ],
    );
  });

  it("names the account only when the export holds more than one of them", () => {
    const twoAccounts = JSON.stringify({
      accounts: [
        {
          attrs: { name: "Personal account" },
          vaults: [
            {
              attrs: { name: "Personal" },
              items: [login("One", credentials("ada", "fixture-pw-1"))],
            },
          ],
        },
        {
          attrs: { name: "Work account" },
          vaults: [
            { attrs: { name: "Personal" }, items: [login("Two", credentials("ada", "fixture-pw-2"))] },
          ],
        },
      ],
    });
    const oneAccount = inVault("Personal", login("One", credentials("ada", "fixture-pw-1")));

    // Two vaults called "Personal" in one export are two different vaults, and
    // with only the vault name carried they become one folder. The account name
    // is what says otherwise — and on a single-account export it is the same
    // value on every row, which is a warning about losing nothing.
    expect(parseOnePasswordExportData(twoAccounts).items.map((item) => item.extra)).toEqual([
      [{ name: "account", value: "Personal account", kind: "metadata" }],
      [{ name: "account", value: "Work account", kind: "metadata" }],
    ]);
    expect(only(parseOnePasswordExportData(oneAccount)).extra).toEqual([]);
  });
});

describe("parseOnePasswordExportData, on the login fields 1Password nests", () => {
  it("takes the username and password from their designations, not from their order", () => {
    const data = inVault(
      "Personal",
      login("Mail", [
        { value: "fixture-pw-8Hq2vN", name: "password", designation: "password" },
        { value: "ada@example.com", name: "username", designation: "username" },
      ]),
    );

    const item = only(parseOnePasswordExportData(data));

    expect(item.username).toBe("ada@example.com");
    expect(item.password).toBe("fixture-pw-8Hq2vN");
  });

  it("keeps a password containing a comma and a quote byte for byte", () => {
    const password = 'fixture,pw,"with quotes" and a trailing space ';
    const data = inVault("Personal", login("Mail", credentials("ada", password)));

    expect(only(parseOnePasswordExportData(data)).password).toBe(password);
  });

  it("refuses a login with no password field rather than importing a blank", () => {
    const data = inVault(
      "Personal",
      login("Mail", [{ value: "ada", name: "username", designation: "username" }]),
    );

    expect(parseOnePasswordExportData(data).errors).toEqual([
      { row: 1, message: 'Item 1 ("Mail") has no password, so it was not imported' },
    ]);
  });

  it("refuses a login whose password field is empty, which is 1Password saying there is none", () => {
    const data = inVault("Personal", login("Mail", credentials("ada", "")));

    expect(parseOnePasswordExportData(data).errors).toEqual([
      { row: 1, message: 'Item 1 ("Mail") has an empty password, so it was not imported' },
    ]);
  });

  it("carries a login field that is neither the username nor the password", () => {
    const data = inVault(
      "Personal",
      login("Mail", [
        ...credentials("ada", "fixture-pw-8Hq2vN"),
        { value: "0123", name: "memorable word", designation: "" },
      ]),
    );

    expect(only(parseOnePasswordExportData(data)).extra).toEqual([
      { name: "memorable word", value: "0123", kind: "custom" },
    ]);
  });

  it("reads overview.urls as objects with a url field, not as the strings Proton Pass writes", () => {
    // 1Password writes `urls: [{label, url}]`. Reading the entries themselves
    // gives `[object Object]` for every URL of every multi-site login — a value
    // that looks like a string right up until somebody tries to visit it.
    const data = inVault(
      "Personal",
      login("Mail", credentials("ada", "fixture-pw-8Hq2vN"), {
        overview: {
          title: "Mail",
          url: "https://mail.example.com",
          urls: [
            { label: "website", url: "https://mail.example.com" },
            { label: "admin", url: "https://admin.example.com" },
          ],
        },
      }),
    );

    expect(only(parseOnePasswordExportData(data)).urls).toEqual([
      "https://mail.example.com",
      "https://admin.example.com",
    ]);
  });

  it("falls back to overview.url when the export lists no urls array", () => {
    const data = inVault(
      "Personal",
      login("Mail", credentials("ada", "fixture-pw-8Hq2vN"), {
        overview: { title: "Mail", url: "https://mail.example.com" },
      }),
    );

    expect(only(parseOnePasswordExportData(data)).urls).toEqual(["https://mail.example.com"]);
  });

  it("marks an item with a non-zero favIndex as a favourite", () => {
    const data = inVault(
      "Personal",
      login("Mail", credentials("ada", "fixture-pw-8Hq2vN"), { favIndex: 1 }),
    );

    expect(only(parseOnePasswordExportData(data)).favorite).toBe(true);
  });
});

describe("parseOnePasswordExportData, on a section's custom fields", () => {
  it("calls a field a second factor because its value is a totp, not because of its title", () => {
    // The rule `ImportFieldKind` exists for: a user can title a text field
    // "totp", and 1Password's own one-time-password field can be titled
    // anything. Where the value sat is evidence; what it was called is a label.
    const uri = "otpauth://totp/Example:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    const data = inVault(
      "Personal",
      withSections("Mail", [
        {
          title: "",
          name: "Section_1",
          fields: [
            { title: "totp", id: "a", value: { string: "not actually a second factor" } },
            { title: "Sign-in code", id: "b", value: { totp: uri } },
          ],
        },
      ]),
    );

    expect(only(parseOnePasswordExportData(data)).extra).toEqual([
      { name: "totp", value: "not actually a second factor", kind: "custom" },
      { name: "Sign-in code", value: uri, kind: "totp" },
    ]);
  });

  it("qualifies a field's name with its section's, so two fields of one name stay apart", () => {
    const data = inVault(
      "Personal",
      withSections("Mail", [
        { title: "Recovery", name: "s1", fields: [{ title: "Answer", value: { string: "blue" } }] },
        { title: "Backup", name: "s2", fields: [{ title: "Answer", value: { string: "green" } }] },
      ]),
    );

    expect(only(parseOnePasswordExportData(data)).extra).toEqual([
      { name: "Recovery / Answer", value: "blue", kind: "custom" },
      { name: "Backup / Answer", value: "green", kind: "custom" },
    ]);
  });

  it("carries a concealed field's value, which is the secret the user typed", () => {
    const data = inVault(
      "Personal",
      withSections("Mail", [
        { title: "", name: "s1", fields: [{ title: "PIN", value: { concealed: "0451" } }] },
      ]),
    );

    expect(only(parseOnePasswordExportData(data)).extra).toEqual([
      { name: "PIN", value: "0451", kind: "custom" },
    ]);
  });

  it("names an untitled field rather than keying it by a position nothing can read", () => {
    const data = inVault(
      "Personal",
      withSections("Mail", [
        { title: "", name: "s1", fields: [{ title: "", value: { string: "kept" } }] },
      ]),
    );

    expect(only(parseOnePasswordExportData(data)).extra).toEqual([
      { name: "(unnamed field)", value: "kept", kind: "custom" },
    ]);
  });
});

describe("parseOnePasswordExportData, on the categories Keyhole has no home for", () => {
  const ofCategory = (categoryUuid: string, title: string): string =>
    inVault("Personal", {
      uuid: "D".repeat(26),
      favIndex: 0,
      state: "active",
      categoryUuid,
      details: { loginFields: [], notesPlain: "", sections: [] },
      overview: { title },
    });

  it("names a credit card, an identity and a document rather than skipping them silently", () => {
    // "Imported 200 of 214" with the other 14 explained is a count the user can
    // act on; "imported 200" from a 214-item file is a number they have no way
    // to check.
    const cases: readonly [string, string, string][] = [
      ["002", "Example Card", "credit card"],
      ["004", "Example Identity", "identity"],
      ["006", "Example Document", "document"],
    ];

    expect(
      cases.map(([categoryUuid, title]) => parseOnePasswordExportData(ofCategory(categoryUuid, title)).errors),
    ).toEqual(
      cases.map(([, title, described]) => [
        {
          row: 1,
          message: `Item 1 ("${title}") is a 1Password ${described}, which Keyhole cannot import yet, so it was not imported`,
        },
      ]),
    );
  });

  it("names a category it has never heard of by its own number", () => {
    expect(parseOnePasswordExportData(ofCategory("999", "Example Thing")).errors).toEqual([
      {
        row: 1,
        message:
          'Item 1 ("Example Thing") is a 1Password item of category 999, which Keyhole cannot ' +
          "import yet, so it was not imported",
      },
    ]);
  });

  it("keeps the items around a refused one, so one card cannot cost the user a vault", () => {
    const data = inVault(
      "Personal",
      login("One", credentials("ada", "fixture-pw-1")),
      {
        uuid: "D".repeat(26),
        state: "active",
        categoryUuid: "002",
        details: { loginFields: [] },
        overview: { title: "Example Card" },
      },
      login("Three", credentials("ada", "fixture-pw-3")),
    );

    const result = parseOnePasswordExportData(data);

    expect(result.items.map((item) => item.name)).toEqual(["One", "Three"]);
    expect(result.errors.map((error) => error.row)).toEqual([2]);
  });

  it("maps a secure note to a note, which needs no password to be an item", () => {
    const data = inVault("Personal", {
      uuid: "E".repeat(26),
      favIndex: 0,
      state: "active",
      categoryUuid: "003",
      details: { loginFields: [], notesPlain: "the note's text", sections: [] },
      overview: { title: "Example Note" },
    });

    const item = only(parseOnePasswordExportData(data));

    expect(item.type).toBe("note");
    expect(item.notes).toBe("the note's text");
    expect(item.password).toBe("");
  });
});

describe("parseOnePasswordExportData, on an item 1Password has archived", () => {
  it("records the archived state and still imports the item, since it was not deleted", () => {
    const data = inVault(
      "Personal",
      login("Mail", credentials("ada", "fixture-pw-8Hq2vN"), { state: "archived" }),
    );

    const item = only(parseOnePasswordExportData(data));

    expect(item.password).toBe("fixture-pw-8Hq2vN");
    expect(item.extra).toEqual([{ name: "state", value: "archived", kind: "metadata" }]);
  });

  it("carries the overview's tags as metadata, matching what the CSV path does with its column", () => {
    const data = inVault(
      "Personal",
      login("Mail", credentials("ada", "fixture-pw-8Hq2vN"), {
        overview: { title: "Mail", url: "", urls: [], tags: ["Work", "Servers/Prod"] },
      }),
    );

    expect(only(parseOnePasswordExportData(data)).extra).toEqual([
      { name: "tags", value: "Work, Servers/Prod", kind: "metadata" },
    ]);
  });
});

describe("parseOnePasswordExportData, on an export it cannot walk", () => {
  it("refuses an item that is not an object rather than throwing", () => {
    expect(parseOnePasswordExportData(inVault("Personal", "not an item")).errors).toEqual([
      { row: 1, message: "Item 1 is not an object, so it could not be read" },
    ]);
  });

  it("refuses a login whose details are missing rather than reading a password from nothing", () => {
    const data = inVault("Personal", {
      uuid: "F".repeat(26),
      state: "active",
      categoryUuid: "001",
      overview: { title: "Mail" },
    });

    expect(parseOnePasswordExportData(data).errors).toEqual([
      { row: 1, message: 'Item 1 ("Mail") is a login with no login details, so it was not imported' },
    ]);
  });

  it("names an item with no title by its position alone, which is still something to search for", () => {
    const data = inVault("Personal", login("", []));

    expect(parseOnePasswordExportData(data).errors).toEqual([
      { row: 1, message: "Item 1 has no password, so it was not imported" },
    ]);
  });
});
