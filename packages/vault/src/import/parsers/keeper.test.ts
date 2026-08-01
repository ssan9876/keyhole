import { describe, expect, it } from "vitest";
import { NOTICE, only, read } from "./fixture.js";
import { parseKeeperCsv, parseKeeperJson } from "./keeper.js";

const CSV = "keeper-export.csv";
const JSON_FIXTURE = "keeper-export.json";

describe("parseKeeperCsv, against the sample export", () => {
  it("maps folder, title, login, password, url and notes by position, reading no header", () => {
    // Keeper's CSV has **no header row**, so the first line is a credential and
    // not column names. Handing this file to the header-reading path would eat
    // the user's first login silently — a row of credentials is a perfectly
    // well-formed header.
    expect(parseKeeperCsv(read(CSV))).toEqual({
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
        {
          type: "login",
          name: "Example Forum",
          username: "ada",
          password: "fixture,pw,with,commas",
          urls: ["https://forum.example.org"],
          notes: "",
          favorite: false,
          folderPath: ["Personal"],
          extra: [],
          sourceRow: 2,
        },
      ],
      errors: [],
    });
  });

  it("reads the very first line as a record rather than as column names", () => {
    // Stated on its own because it is the whole difference between this parser
    // and every other CSV parser here, and because getting it wrong loses
    // exactly one login per import — the least likely loss to be noticed.
    const csv = "Personal,Only Row,ada,fixture-pw-8Hq2vN,https://a.example.com,";

    expect(only(parseKeeperCsv(csv)).name).toBe("Only Row");
  });
});

describe("parseKeeperCsv, on the columns past the sixth", () => {
  it("pairs the trailing columns into named custom fields", () => {
    // Keeper writes custom fields as alternating name,value pairs after the
    // notes column, for as many as the record has.
    const csv =
      "Personal,Example Mail,ada,fixture-pw-8Hq2vN,https://mail.example.com,," +
      "Account number,11112222,Branch,Cambridge";

    expect(only(parseKeeperCsv(csv)).extra).toEqual([
      { name: "Account number", value: "11112222", kind: "custom" },
      { name: "Branch", value: "Cambridge", kind: "custom" },
    ]);
  });

  it("keeps a trailing custom field whose name has no value beside it", () => {
    // An odd number of trailing columns means the last pair is half written.
    // Dropping it would silently lose whichever half is there.
    const csv =
      "Personal,Example Mail,ada,fixture-pw-8Hq2vN,https://mail.example.com,,Account number";

    expect(only(parseKeeperCsv(csv)).extra).toEqual([
      { name: "Account number", value: "", kind: "custom" },
    ]);
  });

  it("leaves extra empty for a record with no trailing columns", () => {
    const csv = "Personal,Example Mail,ada,fixture-pw-8Hq2vN,https://mail.example.com,";

    expect(only(parseKeeperCsv(csv)).extra).toEqual([]);
  });
});

describe("parseKeeperCsv, on the folder column", () => {
  it("splits a nested folder at the backslash into one segment per folder", () => {
    const csv = "Work\\Servers\\Europe,Example Wiki,ada,fixture-pw-9Kd3xR,https://w.example.org,";

    expect(only(parseKeeperCsv(csv)).folderPath).toEqual(["Work", "Servers", "Europe"]);
  });

  it("places a record with an empty folder at the root rather than in a folder with no name", () => {
    const csv = ",Example Wiki,ada,fixture-pw-9Kd3xR,https://w.example.org,";

    expect(only(parseKeeperCsv(csv)).folderPath).toEqual([]);
  });
});

describe("parseKeeperCsv, on the password itself", () => {
  it("keeps a password holding both a comma and a quote exactly as the file escaped it", () => {
    const csv = 'Personal,Example Forum,ada,"fixture,pw""with""quotes",https://forum.example.org,';

    expect(only(parseKeeperCsv(csv)).password).toBe('fixture,pw"with"quotes');
  });

  it("keeps a trailing space in a password rather than trimming it", () => {
    const csv = 'Personal,Example Forum,ada,"fixture-pw-8Hq2vN ",https://forum.example.org,';

    expect(only(parseKeeperCsv(csv)).password).toBe("fixture-pw-8Hq2vN ");
  });
});

describe("parseKeeperCsv, on records it must refuse", () => {
  it("refuses a record that ends before its password column, which is all it can catch", () => {
    // Keeper's characteristic malformation, and the honest limit of a
    // positional format: a record shorter than six fields is visible, because
    // the password position is simply not there. A record whose *order* is
    // wrong is not visible at all — there is no header to disagree with.
    const csv = [
      "Personal,Example Mail,ada,fixture-pw-8Hq2vN,https://mail.example.com,",
      "Personal,Truncated,ada",
    ].join("\n");

    const result = parseKeeperCsv(csv);

    expect(result.errors).toEqual([{ row: 2, message: "This row ends before its password column" }]);
    expect(result.items.map((item) => item.password)).toEqual(["fixture-pw-8Hq2vN"]);
  });

  it("refuses a record with an empty password and keeps the passwords either side", () => {
    const csv = [
      "Personal,Good,ada,fixture-pw-8Hq2vN,https://good.example.com,",
      "Personal,Blank,ada,,https://blank.example.com,",
      "Personal,Later,bob,fixture-pw-9Kd3xR,https://later.example.com,",
    ].join("\n");

    const result = parseKeeperCsv(csv);

    expect(result.errors).toEqual([
      { row: 2, message: "This row has an empty password, so it was not imported" },
    ]);
    expect(result.items.map((item) => item.password)).toEqual([
      "fixture-pw-8Hq2vN",
      "fixture-pw-9Kd3xR",
    ]);
  });

  it("refuses a record the CSV reader flagged, rather than importing its swallowed tail", () => {
    const csv = [
      "Personal,Good,ada,fixture-pw-8Hq2vN,https://good.example.com,",
      'Personal,Truncated,ada,"fixture-pw-9K',
    ].join("\n");

    const result = parseKeeperCsv(csv);

    expect(result.errors).toEqual([
      { row: 2, message: "This row opens a quoted field that is never closed" },
    ]);
    expect(result.items.map((item) => item.password)).toEqual(["fixture-pw-8Hq2vN"]);
  });

  it("answers with no items and no errors for an empty file, instead of throwing", () => {
    expect(parseKeeperCsv("")).toEqual({ items: [], errors: [] });
  });
});

describe("parseKeeperJson, against the sample export", () => {
  it("maps records with title, login, password, login_url, notes and the first folder", () => {
    expect(parseKeeperJson(read(JSON_FIXTURE))).toEqual({
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
        {
          type: "login",
          name: "Example Forum",
          username: "ada",
          password: "fixture,pw,with,commas",
          urls: ["https://forum.example.org"],
          notes: "",
          favorite: false,
          folderPath: ["Personal"],
          extra: [],
          sourceRow: 2,
        },
      ],
      errors: [],
    });
  });
});

describe("parseKeeperJson, on the folders a record claims", () => {
  it("splits a nested folder path at the backslash", () => {
    const json = JSON.stringify({
      shared_folders: [],
      records: [
        {
          title: "Example Wiki",
          login: "ada",
          password: "fixture-pw-9Kd3xR",
          folders: [{ folder: "Work\\Servers" }],
        },
      ],
    });

    expect(only(parseKeeperJson(json)).folderPath).toEqual(["Work", "Servers"]);
  });

  it("reads a shared_folder entry as the folder, since a record may be in one instead", () => {
    const json = JSON.stringify({
      shared_folders: [],
      records: [
        {
          title: "Example Wiki",
          login: "ada",
          password: "fixture-pw-9Kd3xR",
          folders: [{ shared_folder: "Team" }],
        },
      ],
    });

    expect(only(parseKeeperJson(json)).folderPath).toEqual(["Team"]);
  });

  it("takes the first of several folders and records the rest rather than dropping them", () => {
    // A Keeper record can be filed in more than one folder at once. Keyhole's
    // item has one folder, so the others have to be visible somewhere.
    const json = JSON.stringify({
      shared_folders: [],
      records: [
        {
          title: "Example Wiki",
          login: "ada",
          password: "fixture-pw-9Kd3xR",
          folders: [{ folder: "Work" }, { folder: "Archive" }],
        },
      ],
    });

    const item = only(parseKeeperJson(json));

    expect(item.folderPath).toEqual(["Work"]);
    expect(item.extra).toEqual([{ name: "folders", value: "Archive", kind: "metadata" }]);
  });
});

describe("parseKeeperJson, on custom fields", () => {
  it("carries each custom field under the name the user gave it", () => {
    const json = JSON.stringify({
      shared_folders: [],
      records: [
        {
          title: "Example Mail",
          login: "ada",
          password: "fixture-pw-8Hq2vN",
          custom_fields: { "Account number": "11112222", Branch: "Cambridge" },
        },
      ],
    });

    expect(only(parseKeeperJson(json)).extra).toEqual([
      { name: "Account number", value: "11112222", kind: "custom" },
      { name: "Branch", value: "Cambridge", kind: "custom" },
    ]);
  });

  it("carries a TOTP custom field as a second factor, since Keeper keys it structurally", () => {
    // Keeper writes a record's one-time-password seed into `custom_fields`
    // under the reserved key `$oneTimeCode`, which the user cannot type as a
    // field name — so it is a position rather than a label.
    const json = JSON.stringify({
      shared_folders: [],
      records: [
        {
          title: "Example Mail",
          login: "ada",
          password: "fixture-pw-8Hq2vN",
          custom_fields: { $oneTimeCode: "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP" },
        },
      ],
    });

    expect(only(parseKeeperJson(json)).extra).toEqual([
      {
        name: "$oneTimeCode",
        value: "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP",
        kind: "totp",
      },
    ]);
  });

  it("does not call a custom field the user named oneTimeCode a second factor", () => {
    const json = JSON.stringify({
      shared_folders: [],
      records: [
        {
          title: "Example Mail",
          login: "ada",
          password: "fixture-pw-8Hq2vN",
          custom_fields: { oneTimeCode: "a note the user typed" },
        },
      ],
    });

    expect(only(parseKeeperJson(json)).extra).toEqual([
      { name: "oneTimeCode", value: "a note the user typed", kind: "custom" },
    ]);
  });
});

describe("parseKeeperJson, on records it must refuse", () => {
  it("refuses a record whose password is empty instead of importing a blank over a real one", () => {
    const json = JSON.stringify({
      shared_folders: [],
      records: [
        { title: "Blank", login: "ada", password: "" },
        { title: "Good", login: "ada", password: "fixture-pw-8Hq2vN" },
      ],
    });

    const result = parseKeeperJson(json);

    expect(result.errors).toEqual([
      { row: 1, message: 'Record 1 ("Blank") has an empty password, so it was not imported' },
    ]);
    expect(result.items.map((item) => item.password)).toEqual(["fixture-pw-8Hq2vN"]);
  });

  it("refuses a record whose password field is absent, which is a damaged export", () => {
    const json = JSON.stringify({ shared_folders: [], records: [{ title: "No password" }] });

    expect(parseKeeperJson(json).errors).toEqual([
      { row: 1, message: 'Record 1 ("No password") has no password, so it was not imported' },
    ]);
  });

  it("answers with one error for a file that is not JSON, instead of throwing", () => {
    expect(parseKeeperJson("Personal,Example,ada,fixture-pw-8Hq2vN")).toEqual({
      items: [],
      errors: [{ row: 1, message: "This file is not valid JSON, so nothing could be read from it" }],
    });
  });

  it("answers with one error for JSON that carries no records array", () => {
    expect(parseKeeperJson('{"shared_folders":[]}')).toEqual({
      items: [],
      errors: [
        { row: 1, message: "This file has no records array, so it is not a Keeper JSON export" },
      ],
    });
  });
});
