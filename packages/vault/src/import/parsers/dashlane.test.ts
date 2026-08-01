import { describe, expect, it } from "vitest";
import { NOTICE, only, read, withRows } from "../../testing/fixture.js";
import { parseDashlaneCsv, parseDashlaneJson } from "./dashlane.js";

const CSV = "dashlane-credentials.csv";
const JSON_FIXTURE = "dashlane-export.json";

/** A Dashlane JSON export around the given record arrays. */
const asExport = (body: Record<string, unknown>): string => JSON.stringify(body);

describe("parseDashlaneCsv, against the sample credentials export", () => {
  it("maps username, title, password, note, url and category", () => {
    // `dashlane-credentials.csv` is one of Task 2's reconstructions: Bitwarden's
    // importer confirms the column *set*, but `username2`/`username3` and the
    // whole ordering come from weaker sources. Every lookup here is by column
    // name, so a wrong reconstruction fails visibly rather than mis-mapping.
    expect(parseDashlaneCsv(read(CSV))).toEqual({
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
          folderPath: ["Personal"],
          extra: [],
          sourceRow: 3,
        },
      ],
      errors: [],
    });
  });
});

describe("parseDashlaneCsv, on the columns beyond one login's own", () => {
  it("carries the second and third username columns rather than dropping them", () => {
    // Dashlane lets one credential carry three logins. Only the first can be
    // the item's username, and dropping the other two would lose sign-ins the
    // user believes they moved.
    const csv = withRows(
      CSV,
      "ada@example.com,ada.lovelace,ada@example.org,Example Mail," +
        "fixture-pw-8Hq2vN,,https://mail.example.com,Personal,",
    );

    const item = only(parseDashlaneCsv(csv));

    expect(item.username).toBe("ada@example.com");
    expect(item.extra).toEqual([
      { name: "username2", value: "ada.lovelace", kind: "custom" },
      { name: "username3", value: "ada@example.org", kind: "custom" },
    ]);
  });

  it("carries otpSecret into extra as a second factor", () => {
    const seed = "JBSWY3DPEHPK3PXP";
    const csv = withRows(
      CSV,
      `ada,,,Example Mail,fixture-pw-8Hq2vN,,https://mail.example.com,Personal,${seed}`,
    );

    expect(only(parseDashlaneCsv(csv)).extra).toEqual([
      { name: "otpSecret", value: seed, kind: "totp" },
    ]);
  });

  it("keeps a category containing a slash whole, since Dashlane categories do not nest", () => {
    const csv = withRows(
      CSV,
      "ada,,,Example Mail,fixture-pw-8Hq2vN,,https://mail.example.com,Home/Office,",
    );

    expect(only(parseDashlaneCsv(csv)).folderPath).toEqual(["Home/Office"]);
  });
});

describe("parseDashlaneCsv, on the password itself", () => {
  it("keeps a password holding both a comma and a quote exactly as the file escaped it", () => {
    const csv = withRows(
      CSV,
      'ada,,,Example Forum,"fixture,pw""with""quotes",,https://forum.example.org,Personal,',
    );

    expect(only(parseDashlaneCsv(csv)).password).toBe('fixture,pw"with"quotes');
  });

  it("keeps a trailing space in a password rather than trimming it", () => {
    const csv = withRows(
      CSV,
      'ada,,,Example Forum,"fixture-pw-8Hq2vN ",,https://forum.example.org,Personal,',
    );

    expect(only(parseDashlaneCsv(csv)).password).toBe("fixture-pw-8Hq2vN ");
  });
});

describe("parseDashlaneCsv, on rows it must refuse", () => {
  it("refuses a row with an empty password and keeps the passwords either side", () => {
    const csv = withRows(
      CSV,
      "ada,,,Good,fixture-pw-8Hq2vN,,https://good.example.com,Personal,",
      "ada,,,Blank,,,https://blank.example.com,Personal,",
      "bob,,,Later,fixture-pw-9Kd3xR,,https://later.example.com,Personal,",
    );

    const result = parseDashlaneCsv(csv);

    expect(result.errors).toEqual([
      { row: 3, message: "This row has an empty password, so it was not imported" },
    ]);
    expect(result.items.map((item) => item.password)).toEqual([
      "fixture-pw-8Hq2vN",
      "fixture-pw-9Kd3xR",
    ]);
  });

  it("answers with one error for a CSV that is not a Dashlane credentials export", () => {
    expect(parseDashlaneCsv(read("unknown-manager-export.csv"))).toEqual({
      items: [],
      errors: [
        {
          row: 1,
          message:
            "This file has no title and password columns, so it is not a Dashlane credentials CSV",
        },
      ],
    });
  });
});

describe("parseDashlaneJson, against the sample export", () => {
  it("maps AUTHENTIFIANT logins and SECURENOTE notes, numbering items across both lists", () => {
    expect(parseDashlaneJson(read(JSON_FIXTURE))).toEqual({
      items: [
        {
          type: "login",
          name: "Example Mail",
          // `email` is the only login this record carries, so it is the
          // username; the empty `login` is not carried.
          username: "ada@example.com",
          password: "fixture-pw-8Hq2vN",
          urls: ["mail.example.com"],
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
          urls: ["forum.example.org"],
          notes: "",
          favorite: false,
          folderPath: ["Personal"],
          extra: [],
          sourceRow: 2,
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
          sourceRow: 3,
        },
      ],
      errors: [],
    });
  });
});

describe("parseDashlaneJson, on the two login fields Dashlane keeps apart", () => {
  it("prefers login over email and carries the email so neither sign-in is lost", () => {
    // Dashlane stores a credential's `login` and `email` separately and a
    // record can carry both. Keyhole has one username field, so the other has
    // to go somewhere visible rather than nowhere.
    const json = asExport({
      AUTHENTIFIANT: [
        {
          title: "Example Mail",
          url: "https://mail.example.com",
          login: "ada",
          email: "ada@example.com",
          password: "fixture-pw-8Hq2vN",
        },
      ],
    });

    const item = only(parseDashlaneJson(json));

    expect(item.username).toBe("ada");
    expect(item.extra).toEqual([{ name: "email", value: "ada@example.com", kind: "custom" }]);
  });

  it("does not carry the email a second time when it is already the username", () => {
    const json = asExport({
      AUTHENTIFIANT: [
        {
          title: "Example Mail",
          url: "https://mail.example.com",
          login: "",
          email: "ada@example.com",
          password: "fixture-pw-8Hq2vN",
        },
      ],
    });

    const item = only(parseDashlaneJson(json));

    expect(item.username).toBe("ada@example.com");
    expect(item.extra).toEqual([]);
  });

  it("falls back to the bare domain when a record carries no url", () => {
    // The fixture's records carry `domain` and no `url`. A bare host is not a
    // URL, but it is what the export said, and inventing a scheme would be this
    // layer claiming something the file does not.
    const json = asExport({
      AUTHENTIFIANT: [
        { title: "Example Mail", domain: "mail.example.com", password: "fixture-pw-8Hq2vN" },
      ],
    });

    expect(only(parseDashlaneJson(json)).urls).toEqual(["mail.example.com"]);
  });
});

describe("parseDashlaneJson, on the record kinds it has no home for", () => {
  it("names a credit card by its list and position rather than skipping it", () => {
    // Naming the list is what makes the error findable: a Dashlane JSON export
    // has no line numbers a user can search, but it does have these keys.
    const json = asExport({
      AUTHENTIFIANT: [
        { title: "Example Mail", url: "https://mail.example.com", password: "fixture-pw-8Hq2vN" },
      ],
      PAYMENTMEANS_CREDITCARD: [{ bank: "Example Bank", name: "Ada's card" }],
    });

    const result = parseDashlaneJson(json);

    expect(result.errors).toEqual([
      {
        row: 2,
        message:
          'PAYMENTMEANS_CREDITCARD item 1 ("Ada\'s card") is a Dashlane credit card, ' +
          "which Keyhole cannot import yet, so it was not imported",
      },
    ]);
    expect(result.items.map((item) => item.name)).toEqual(["Example Mail"]);
  });

  it("names an identity record by its list even when it has no title to quote", () => {
    const json = asExport({ IDENTITY: [{ firstName: "Ada" }] });

    expect(parseDashlaneJson(json).errors).toEqual([
      {
        row: 1,
        message:
          "IDENTITY item 1 is a Dashlane identity, which Keyhole cannot import yet, " +
          "so it was not imported",
      },
    ]);
  });
});

describe("parseDashlaneJson, on records it must refuse", () => {
  it("refuses a login whose password is empty instead of importing a blank over a real one", () => {
    const json = asExport({
      AUTHENTIFIANT: [
        { title: "Blank", url: "https://blank.example.com", password: "" },
        { title: "Good", url: "https://good.example.com", password: "fixture-pw-8Hq2vN" },
      ],
    });

    const result = parseDashlaneJson(json);

    expect(result.errors).toEqual([
      {
        row: 1,
        message: 'AUTHENTIFIANT item 1 ("Blank") has an empty password, so it was not imported',
      },
    ]);
    expect(result.items.map((item) => item.password)).toEqual(["fixture-pw-8Hq2vN"]);
  });

  it("refuses a login whose password field is absent, which is a damaged export", () => {
    const json = asExport({ AUTHENTIFIANT: [{ title: "No password" }] });

    expect(parseDashlaneJson(json).errors).toEqual([
      {
        row: 1,
        message: 'AUTHENTIFIANT item 1 ("No password") has no password, so it was not imported',
      },
    ]);
  });

  it("answers with one error for a file that is not JSON, instead of throwing", () => {
    expect(parseDashlaneJson("title,password\nExample,fixture-pw-8Hq2vN")).toEqual({
      items: [],
      errors: [{ row: 1, message: "This file is not valid JSON, so nothing could be read from it" }],
    });
  });

  it("answers with one error for JSON carrying none of Dashlane's record lists", () => {
    expect(parseDashlaneJson('{"items":[]}')).toEqual({
      items: [],
      errors: [
        {
          row: 1,
          message:
            "This file has none of Dashlane's record lists, so it is not a Dashlane JSON export",
        },
      ],
    });
  });
});
