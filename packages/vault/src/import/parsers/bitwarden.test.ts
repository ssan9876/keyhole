import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import type { ImportItem, ImportResult } from "../types.js";
import { parseBitwardenCsv, parseBitwardenJson } from "./bitwarden.js";

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
 * The header line of the CSV fixture, so an inline case cannot pass against a
 * header this test invented.
 *
 * Every CSV case below that is not the golden builds its file from the *real*
 * header plus rows written here, which keeps the part with provenance — the
 * column names and their order — out of this file's hands. Copied from
 * `browser.test.ts`, which explains the split on both line endings: the
 * checkout is normalised to LF, but a `\r` left on the header would attach to
 * its last column name and every lookup for that column would miss.
 */
const headerLine = (file: string): string => {
  const [first] = read(file).split(/\r?\n/);
  if (first === undefined || first === "") {
    throw new Error(`${file} has no header line`);
  }
  return first;
};

const withRows = (...rows: string[]): string =>
  [headerLine("bitwarden-export.csv"), ...rows].join("\n");

/**
 * A Bitwarden JSON export around the given body.
 *
 * The JSON path has no equivalent of `headerLine` — a JSON export's shape is
 * its key names, not a line — so inline cases write those keys out. They are
 * the same keys the fixture uses, and the golden is what pins them to a file
 * with provenance.
 */
const asExport = (body: Record<string, unknown>): string =>
  JSON.stringify({ encrypted: false, folders: [], ...body }, null, 2);

/**
 * The one item of a single-item case.
 *
 * Indexing is checked rather than optional-chained: `result.items[0]?.password`
 * is `undefined` for an item that failed to parse, which silently satisfies an
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

/** The fixture's TOTP value, which is long enough to be worth naming once. */
const TOTP = "otpauth://totp/Example:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";

describe("parseBitwardenJson, against the sample export", () => {
  it("maps logins, a note, folder names and the card it cannot store", () => {
    // The golden. It asserts the whole result — every field of every item and
    // the error the card produces — so a mapping that moves one field to the
    // wrong place fails here and nowhere else.
    expect(parseBitwardenJson(read("bitwarden-export.json"))).toEqual({
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
          sourceRow: 1,
        },
        {
          type: "note",
          name: "Router notes",
          username: "",
          password: "",
          urls: [],
          notes: "first line\nsecond line",
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
          urls: [
            "https://forum.example.org",
            "https://forum.example.org/login",
            "androidapp://org.example.forum",
          ],
          notes: "",
          favorite: false,
          folderPath: ["Work", "Servers"],
          // In the order the export carried them, which is the order `extra` is
          // a list to preserve.
          extra: [
            { name: "totp", value: TOTP, kind: "totp" },
            { name: "Security question", value: "first pet", kind: "custom" },
            { name: "reprompt", value: "1", kind: "metadata" },
          ],
          sourceRow: 3,
        },
      ],
      errors: [
        {
          row: 4,
          message:
            'Item 4 ("Example Card") is a Bitwarden card, which Keyhole cannot import yet, ' +
            "so it was not imported",
        },
      ],
    });
  });
});

describe("parseBitwardenJson, on the item kinds Keyhole has", () => {
  it("maps a secure note to a note item carrying the export's text and no password", () => {
    // `type: 2` and no `login` object at all. The item must still arrive: a
    // note is one of Keyhole's two kinds, and refusing it for having no
    // password would drop every note in the vault.
    const json = asExport({
      items: [{ type: 2, name: "Router notes", notes: "first line\nsecond line" }],
    });

    const item = only(parseBitwardenJson(json));

    expect(item.type).toBe("note");
    expect(item.notes).toBe("first line\nsecond line");
    expect(item.password).toBe("");
  });

  it("reads a URL from the uri field of each object in login.uris, in order", () => {
    // `login.uris` is an array of *objects* with a `uri` field, not an array of
    // strings. Reading the elements as strings yields "[object Object]" as the
    // URL of every multi-site login, which looks like a URL until it is used.
    const json = asExport({
      items: [
        {
          type: 1,
          name: "Example Forum",
          login: {
            uris: [
              { match: null, uri: "https://forum.example.org" },
              { match: null, uri: "https://forum.example.org/login" },
              { match: 3, uri: "androidapp://org.example.forum" },
            ],
            username: "ada",
            password: "fixture-pw-8Hq2vN",
          },
        },
      ],
    });

    expect(only(parseBitwardenJson(json)).urls).toEqual([
      "https://forum.example.org",
      "https://forum.example.org/login",
      "androidapp://org.example.forum",
    ]);
  });

  it("splits Bitwarden's slash-nested folder name into path segments", () => {
    // Bitwarden stores a nested folder as one folder whose *name* contains a
    // slash: `Work/Servers` is the documented way to make a subfolder and how
    // its own clients render the tree. So the slash is the nesting, and a folder
    // whose name genuinely contains one is indistinguishable from a nested
    // folder in Bitwarden's model too -- splitting matches what Bitwarden itself
    // shows the user.
    //
    // This reverses the reading Task 4 wrote here. `folderPath` is segments
    // precisely so the answer is given once, by the parser that knows what its
    // format meant, rather than by `map.ts` guessing at a separator it was never
    // told about -- LastPass's `grouping` nests with a backslash.
    const json = asExport({
      folders: [{ id: "44444444-4444-4444-8444-444444444444", name: "Work/Servers" }],
      items: [
        {
          type: 1,
          name: "Example Wiki",
          folderId: "44444444-4444-4444-8444-444444444444",
          login: { uris: [], username: "ada", password: "fixture-pw-8Hq2vN" },
        },
      ],
    });

    expect(only(parseBitwardenJson(json)).folderPath).toEqual(["Work", "Servers"]);
  });

  it("places an item with no folderId at the root rather than in a folder named empty", () => {
    // No segments is the root. A single empty segment would be a folder with no
    // name, which `map.ts` would dutifully create.
    const json = asExport({
      items: [
        {
          type: 1,
          name: "Example Mail",
          folderId: null,
          login: { uris: [], username: "ada", password: "fixture-pw-8Hq2vN" },
        },
      ],
    });

    expect(only(parseBitwardenJson(json)).folderPath).toEqual([]);
  });
});

describe("parseBitwardenJson, on what Keyhole has no field for", () => {
  it("carries a TOTP seed, a custom field and a reprompt flag into extra", () => {
    // `types.ts` names these three as the contents of `extra`. Dropping them
    // loses a second factor and the user's own custom fields; writing them into
    // the note instead would make them indistinguishable downstream from a
    // sentence the user typed, so the preview screen could not warn about them.
    const json = asExport({
      items: [
        {
          type: 1,
          name: "Example Forum",
          reprompt: 1,
          fields: [{ name: "Security question", value: "first pet", type: 0 }],
          login: { uris: [], username: "ada", password: "fixture-pw-8Hq2vN", totp: TOTP },
        },
      ],
    });

    expect(only(parseBitwardenJson(json)).extra).toEqual([
      { name: "totp", value: TOTP, kind: "totp" },
      { name: "Security question", value: "first pet", kind: "custom" },
      { name: "reprompt", value: "1", kind: "metadata" },
    ]);
  });

  it("leaves extra empty for an item with no totp, no custom fields and reprompt off", () => {
    // Otherwise every ordinary login would carry an empty `totp` and a
    // `reprompt` of 0, and the preview screen would warn about the loss of
    // nothing on every row of the import.
    const json = asExport({
      items: [
        {
          type: 1,
          name: "Example Mail",
          reprompt: 0,
          login: { uris: [], username: "ada", password: "fixture-pw-8Hq2vN", totp: null },
        },
      ],
    });

    expect(only(parseBitwardenJson(json)).extra).toEqual([]);
  });

  it("keeps two custom fields sharing a name as two entries, not one merged value", () => {
    // Bitwarden's `fields[]` is an array and nothing stops a user having two
    // fields with one name. `extra` is a list for this reason: a record keyed by
    // name has to either drop one of them or glue them into a single string that
    // nothing downstream can take apart again, and this is the channel that
    // exists to stop the user's own data going missing.
    const json = asExport({
      items: [
        {
          type: 1,
          name: "Example Forum",
          fields: [
            { name: "Recovery code", value: "first", type: 1 },
            { name: "Recovery code", value: "second", type: 1 },
          ],
          login: { uris: [], username: "ada", password: "fixture-pw-8Hq2vN" },
        },
      ],
    });

    expect(only(parseBitwardenJson(json)).extra).toEqual([
      { name: "Recovery code", value: "first", kind: "custom" },
      { name: "Recovery code", value: "second", kind: "custom" },
    ]);
  });

  it("does not call a custom field named totp a second factor", () => {
    // The reason `kind` comes from where the value sat in the file and never
    // from what it is called. Bitwarden puts the real seed at `login.totp` and
    // separately lets a user create a custom field they happen to name "totp".
    // Matching on the name makes those one thing, and the preview screen then
    // tells the user their note is a second factor and their second factor is a
    // note.
    const json = asExport({
      items: [
        {
          type: 1,
          name: "Example Forum",
          fields: [{ name: "totp", value: "just what I called this field", type: 0 }],
          login: { uris: [], username: "ada", password: "fixture-pw-8Hq2vN", totp: TOTP },
        },
      ],
    });

    expect(only(parseBitwardenJson(json)).extra).toEqual([
      { name: "totp", value: TOTP, kind: "totp" },
      { name: "totp", value: "just what I called this field", kind: "custom" },
    ]);
  });

  it("names an organisation export's collections in extra, since they are not folders", () => {
    // An organisation export carries `collections` instead of `folders`, and an
    // item names them in `collectionIds`. An item can be in several, so no one
    // of them is "the" folder; recording the names is what lets the preview
    // screen say the grouping is not coming across.
    const json = asExport({
      collections: [
        { id: "77777777-7777-4777-8777-777777777777", name: "Shared/Infra" },
        { id: "88888888-8888-4888-8888-888888888888", name: "Shared/Billing" },
      ],
      items: [
        {
          type: 1,
          name: "Example Console",
          folderId: null,
          collectionIds: [
            "77777777-7777-4777-8777-777777777777",
            "88888888-8888-4888-8888-888888888888",
          ],
          login: { uris: [], username: "ada", password: "fixture-pw-8Hq2vN" },
        },
      ],
    });

    const item = only(parseBitwardenJson(json));

    expect(item.folderPath).toEqual([]);
    // A collection name is carried as text, not split: `Shared/Infra` is one
    // collection's name, and this is not the item's folder in the first place.
    expect(item.extra).toEqual([
      { name: "collections", value: "Shared/Infra, Shared/Billing", kind: "metadata" },
    ]);
  });
});

describe("parseBitwardenJson, on items it must refuse", () => {
  for (const { type, described } of [
    { type: 3, described: "card" },
    { type: 4, described: "identity" },
    { type: 5, described: "SSH key" },
  ]) {
    it(`reports a type ${type} item as an error naming it a ${described}`, () => {
      // A silent skip is what makes an import count untrustworthy: "imported 2
      // of 3" with the third explained is something a user can act on;
      // "imported 2" from a 3-item file is not.
      const json = asExport({
        items: [
          {
            type: 1,
            name: "Example Mail",
            login: { uris: [], username: "ada", password: "fixture-pw-8Hq2vN" },
          },
          { type, name: "Example Other" },
        ],
      });

      const result = parseBitwardenJson(json);

      expect(result.errors).toEqual([
        {
          row: 2,
          message:
            `Item 2 ("Example Other") is a Bitwarden ${described}, ` +
            "which Keyhole cannot import yet, so it was not imported",
        },
      ]);
      expect(result.items.map((item) => item.name)).toEqual(["Example Mail"]);
    });
  }

  it("reports an item of a type it has never heard of by that type's number", () => {
    const json = asExport({ items: [{ type: 9, name: "Something New" }] });

    expect(parseBitwardenJson(json).errors).toEqual([
      {
        row: 1,
        message:
          'Item 1 ("Something New") is a Bitwarden item of type 9, ' +
          "which Keyhole cannot import yet, so it was not imported",
      },
    ]);
  });

  it("refuses a login whose password is empty instead of importing a blank over a real one", () => {
    // The rule with no undo. The export is what the user is about to be told to
    // delete, so a blank imported over a real password cannot be recovered.
    const json = asExport({
      items: [
        {
          type: 1,
          name: "Example Blank",
          login: { uris: [], username: "ada", password: "" },
        },
      ],
    });

    const result = parseBitwardenJson(json);

    expect(result.errors).toEqual([
      { row: 1, message: 'Item 1 ("Example Blank") has an empty password, so it was not imported' },
    ]);
    expect(result.items).toEqual([]);
  });

  it("refuses a login whose password field is absent, and keeps the items either side", () => {
    const json = asExport({
      items: [
        {
          type: 1,
          name: "Example Mail",
          login: { uris: [], username: "ada", password: "fixture-pw-8Hq2vN" },
        },
        { type: 1, name: "Example Missing", login: { uris: [], username: "ada" } },
        {
          type: 1,
          name: "Example Forum",
          login: { uris: [], username: "bob", password: "fixture-pw-9Kd3xR" },
        },
      ],
    });

    const result = parseBitwardenJson(json);

    expect(result.errors).toEqual([
      { row: 2, message: 'Item 2 ("Example Missing") has no password, so it was not imported' },
    ]);
    expect(result.items.map((item) => item.name)).toEqual(["Example Mail", "Example Forum"]);
  });

  it("refuses a login item that carries no login object at all", () => {
    const json = asExport({ items: [{ type: 1, name: "Example Empty" }] });

    expect(parseBitwardenJson(json).errors).toEqual([
      {
        row: 1,
        message: 'Item 1 ("Example Empty") is a login with no login details, so it was not imported',
      },
    ]);
  });

  it("reports an item that does not say which kind it is, rather than assuming login", () => {
    const json = asExport({ items: [{ name: "Example Typeless" }] });

    expect(parseBitwardenJson(json).errors).toEqual([
      {
        row: 1,
        message:
          'Item 1 ("Example Typeless") does not say what kind of item it is, so it was not imported',
      },
    ]);
  });

  it("names an unreadable item by its position when it has no name to quote", () => {
    const json = asExport({ items: ["not an object at all"] });

    expect(parseBitwardenJson(json).errors).toEqual([
      { row: 1, message: "Item 1 is not an object, so it could not be read" },
    ]);
  });
});

describe("parseBitwardenJson, on an export it cannot read at all", () => {
  it("tells the user to export again unencrypted rather than failing to parse", () => {
    // Bitwarden's encrypted export is a realistic first attempt: it is one of
    // the choices in the same export dialog. Its items are ciphertext strings,
    // so a parser that ploughed on would produce 200 error rows about
    // unreadable passwords instead of the one sentence that fixes it.
    const encrypted = read("bitwarden-export.json").replace(
      '"encrypted": false',
      '"encrypted": true',
    );

    expect(parseBitwardenJson(encrypted)).toEqual({
      items: [],
      errors: [
        {
          row: 1,
          message:
            "This is an encrypted Bitwarden export, which cannot be read without your " +
            "Bitwarden password. Export it again with the file format set to .json " +
            "rather than .json (Encrypted), and upload that file.",
        },
      ],
    });
  });

  it("gives the same instruction for a password-protected export, which has no items", () => {
    // The other encrypted shape: "Export file password" produces a single
    // `data` blob with `passwordProtected: true` and no `items` array at all.
    // Reported by the same sentence, because the user's fix is the same one.
    const json = JSON.stringify({
      encrypted: true,
      passwordProtected: true,
      salt: "not-a-real-salt",
      kdfIterations: 600000,
      data: "2.GENERATED-FIXTURE-not-real-ciphertext",
    });

    expect(parseBitwardenJson(json).errors).toEqual([
      {
        row: 1,
        message:
          "This is an encrypted Bitwarden export, which cannot be read without your " +
          "Bitwarden password. Export it again with the file format set to .json " +
          "rather than .json (Encrypted), and upload that file.",
      },
    ]);
  });

  it("answers with one error for a file that is not JSON, instead of throwing", () => {
    // Detection routes this file elsewhere, so the parser should never see it —
    // but "never throws" has to hold for the caller that gets the routing wrong
    // too, and an exception here would take down the import screen.
    expect(parseBitwardenJson(read("bitwarden-export.csv"))).toEqual({
      items: [],
      errors: [{ row: 1, message: "This file is not valid JSON, so nothing could be read from it" }],
    });
  });

  it("answers with one error for JSON that carries no items array", () => {
    expect(parseBitwardenJson('{"encrypted": false, "folders": []}')).toEqual({
      items: [],
      errors: [
        { row: 1, message: "This file has no items array, so it is not a Bitwarden JSON export" },
      ],
    });
  });
});

describe("parseBitwardenCsv, against the sample export", () => {
  it("maps the folder, favorite, type, name, note and login columns", () => {
    // The golden for the flatter CSV shape: a `folder` column holding a name
    // rather than an id, `type` as a word rather than a number, and one
    // `login_uri` column holding every URI.
    expect(parseBitwardenCsv(read("bitwarden-export.csv"))).toEqual({
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
          folderPath: [],
          extra: [],
          sourceRow: 3,
        },
        {
          type: "note",
          name: "Router notes",
          username: "",
          password: "",
          urls: [],
          notes: "first line\nsecond line",
          favorite: false,
          folderPath: ["Work"],
          extra: [],
          sourceRow: 4,
        },
        {
          type: "login",
          name: "Example Wiki",
          username: "ada",
          password: "fixture-pw-9Kd3xR",
          urls: [
            "https://wiki.example.org",
            "https://wiki.example.org/login",
            "androidapp://org.example.wiki",
          ],
          notes: "",
          favorite: false,
          folderPath: ["Work", "Servers"],
          // The `fields` column is one blob of the user's custom fields, one
          // `name: value` per line. It is carried whole rather than split back
          // apart, because a value containing ": " would split wrongly and
          // silently.
          extra: [
            { name: "totp", value: TOTP, kind: "totp" },
            { name: "fields", value: "Security question: first pet", kind: "custom" },
            { name: "reprompt", value: "1", kind: "metadata" },
          ],
          sourceRow: 6,
        },
      ],
      errors: [],
    });
  });
});

describe("parseBitwardenCsv, on the password itself", () => {
  it("keeps a password holding both a comma and a quote exactly as the file escaped it", () => {
    // The case Task 1's CSV reader exists for, proved through this parser: the
    // file holds `"fixture,pw""with""quotes"` and the item must hold
    // fixture,pw"with"quotes. A naive split gives this row three extra fields
    // and a password of `"fixture`.
    const csv = withRows(
      'Personal,0,login,Example Forum,,,0,https://forum.example.org,ada,"fixture,pw""with""quotes",',
    );

    expect(only(parseBitwardenCsv(csv)).password).toBe('fixture,pw"with"quotes');
  });

  it("keeps a trailing space in a password rather than trimming it", () => {
    // A trailing space is part of the password. Trimming produces a value that
    // looks identical on screen and fails at the login form, which is the
    // hardest kind of import bug for a user to diagnose.
    const csv = withRows(
      'Personal,0,login,Example Forum,,,0,https://forum.example.org,ada,"fixture-pw-8Hq2vN ",',
    );

    expect(only(parseBitwardenCsv(csv)).password).toBe("fixture-pw-8Hq2vN ");
  });
});

describe("parseBitwardenCsv, on the columns that are not the browser CSVs'", () => {
  it("splits one login_uri column holding three comma-separated URIs into three URLs", () => {
    // Bitwarden's CSV writer joins an item's URIs with a comma into a single
    // quoted column, which is why this is a split rather than one URL.
    const csv = withRows(
      "Personal,0,login,Example Wiki,,,0," +
        '"https://wiki.example.org,https://wiki.example.org/login,androidapp://org.example.wiki",' +
        "ada,fixture-pw-8Hq2vN,",
    );

    expect(only(parseBitwardenCsv(csv)).urls).toEqual([
      "https://wiki.example.org",
      "https://wiki.example.org/login",
      "androidapp://org.example.wiki",
    ]);
  });

  it("splits the folder column at the slash, as the JSON export's folder names are split", () => {
    // The same rule on both of Bitwarden's exports, because it is the same
    // product's same nesting convention written into two file formats. Answering
    // differently in the two parsers is how one vendor ends up with two folder
    // trees in the imported vault.
    const csv = withRows(
      "Work/Servers,0,login,Example Wiki,,,0,https://wiki.example.org,ada,fixture-pw-8Hq2vN,",
    );

    expect(only(parseBitwardenCsv(csv)).folderPath).toEqual(["Work", "Servers"]);
  });

  it("reads favorite 1 as favourite and 0 as not, rather than any non-empty value", () => {
    const csv = withRows(
      "Personal,1,login,Starred,,,0,https://a.example.org,ada,fixture-pw-8Hq2vN,",
      "Personal,0,login,Plain,,,0,https://b.example.org,ada,fixture-pw-9Kd3xR,",
    );

    expect(parseBitwardenCsv(csv).items.map((item) => item.favorite)).toEqual([true, false]);
  });

  it("imports a note row with no password, since only a login needs one", () => {
    // Every note in a Bitwarden CSV has an empty `login_password`. A parser
    // that applied the login rule to them would refuse every note in the file.
    const csv = withRows('Work,0,note,Router notes,"first line\nsecond line",,0,,,,');

    const item = only(parseBitwardenCsv(csv));

    expect(item.type).toBe("note");
    expect(item.password).toBe("");
  });
});

describe("parseBitwardenCsv, on rows it must refuse", () => {
  it("reports a card row as an error naming its type, so the imported count adds up", () => {
    // Whether Bitwarden's CSV writer emits card rows at all is not settled —
    // the fixture has none — so this is written inline rather than into the
    // fixture. Either way an unknown type word must be reported, not skipped.
    const csv = withRows(
      "Personal,0,login,Example Mail,,,0,https://mail.example.com,ada,fixture-pw-8Hq2vN,",
      "Personal,0,card,Example Card,,,0,,,,",
    );

    const result = parseBitwardenCsv(csv);

    expect(result.errors).toEqual([
      {
        row: 3,
        message: "This row is a Bitwarden card, which Keyhole cannot import yet, so it was not imported",
      },
    ]);
    expect(result.items.map((item) => item.name)).toEqual(["Example Mail"]);
  });

  it("reports a login row with an empty password and still returns the rows either side", () => {
    const csv = withRows(
      "Personal,0,login,Example Mail,,,0,https://mail.example.com,ada,fixture-pw-8Hq2vN,",
      "Personal,0,login,Example Blank,,,0,https://blank.example.com,ada,,",
      "Personal,0,login,Example Forum,,,0,https://forum.example.org,bob,fixture-pw-9Kd3xR,",
    );

    const result = parseBitwardenCsv(csv);

    expect(result.errors).toEqual([
      { row: 3, message: "This row has an empty password, so it was not imported" },
    ]);
    expect(result.items.map((item) => item.name)).toEqual(["Example Mail", "Example Forum"]);
  });

  it("reports a login row that ends before its password column rather than importing a blank", () => {
    const csv = withRows("Personal,0,login,Example Short,,,0,https://short.example.com,ada");

    expect(parseBitwardenCsv(csv).errors).toEqual([
      { row: 2, message: "This row ends before its password column" },
    ]);
  });

  it("reports a row with more fields than the header instead of importing its first part", () => {
    // An export whose writer failed to quote a password containing a comma
    // produces exactly this, and from there every value after the password sits
    // one column left of where it belongs.
    const csv = withRows(
      "Personal,0,login,Example Mail,,,0,https://mail.example.com,ada,fixture-pw-8Hq2vN,",
      "Personal,0,login,Example Split,,,0,https://split.example.com,ada,fixture,pw,commas,",
    );

    const result = parseBitwardenCsv(csv);

    expect(result.errors).toEqual([
      {
        row: 3,
        message:
          "This row has 13 fields where the header has 11, so a value has been split across columns",
      },
    ]);
    expect(result.items.map((item) => item.name)).toEqual(["Example Mail"]);
  });

  it("says a row with a trailing comma has empty surplus fields, not a value split apart", () => {
    // Same distinction as `browser.test.ts` draws, because both parsers write
    // the same sentence: an empty surplus field is a trailing comma, not a
    // column shift, and saying otherwise sends the user looking for damage that
    // is not in their file.
    const csv = withRows(
      "Personal,0,login,Example Mail,,,0,https://mail.example.com,ada,fixture-pw-8Hq2vN,,",
    );

    expect(parseBitwardenCsv(csv).errors).toEqual([
      {
        row: 2,
        message:
          "This row has 12 fields where the header has 11, though every surplus field is empty, " +
          "so a trailing comma is the likely cause",
      },
    ]);
  });

  it("refuses a row the CSV reader flagged, rather than importing its swallowed tail", () => {
    // A file that ends inside a quoted field: the reader reports the damage and
    // still hands the record over, with everything from the opening quote
    // swallowed into one value. Importing that would store a password the user
    // never had, under a report that said the file had a problem.
    const csv = withRows(
      "Personal,0,login,Example Mail,,,0,https://mail.example.com,ada,fixture-pw-8Hq2vN,",
      'Personal,0,login,Example Cut,,,0,https://cut.example.com,ada,"fixture-pw-9K',
    );

    const result = parseBitwardenCsv(csv);

    expect(result.errors).toEqual([
      { row: 3, message: "This row opens a quoted field that is never closed" },
    ]);
    expect(result.items.map((item) => item.name)).toEqual(["Example Mail"]);
  });

  it("answers with one error for a CSV that is not a Bitwarden export, instead of throwing", () => {
    expect(parseBitwardenCsv(read("unknown-manager-export.csv"))).toEqual({
      items: [],
      errors: [
        {
          row: 1,
          message: "This file has no login_password column, so it is not a Bitwarden CSV export",
        },
      ],
    });
  });

  it("answers with one error for an empty file, where there is no header at all", () => {
    expect(parseBitwardenCsv("")).toEqual({
      items: [],
      errors: [
        {
          row: 1,
          message: "This file has no login_password column, so it is not a Bitwarden CSV export",
        },
      ],
    });
  });
});

describe("parseBitwardenCsv, on files mangled in transit", () => {
  it("maps a Bitwarden export whose header a spreadsheet rewrote in capitals and spaced out", () => {
    // Column names are matched lowercased and trimmed, as detection matches
    // them. The header is written out here rather than taken from the fixture,
    // because differing from the fixture's is the point of the case.
    const csv = [
      " Folder , Favorite , Type , Name , Notes , Fields , Reprompt , " +
        "Login_URI , Login_Username , Login_Password , Login_TOTP ",
      "Personal,0,login,Example Mail,,,0,https://mail.example.com,ada,fixture-pw-8Hq2vN,",
    ].join("\n");

    const item = only(parseBitwardenCsv(csv));

    expect(item.username).toBe("ada");
    expect(item.password).toBe("fixture-pw-8Hq2vN");
  });
});
