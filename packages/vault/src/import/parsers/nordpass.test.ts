import { describe, expect, it } from "vitest";
import { NOTICE, only, read, withRows } from "../../testing/fixture.js";
import { parseNordPassCsv } from "./nordpass.js";

const FIXTURE = "nordpass-export.csv";

/**
 * A NordPass row built by column name.
 *
 * NordPass writes 22 columns for every item whatever its kind, so a row written
 * out by hand is 21 commas of which most are empty and one miscount silently
 * shifts every field after it. Naming the columns is what stops a case here
 * from testing a mapping the test itself got wrong.
 */
const row = (values: Readonly<Record<string, string>>): string => {
  const header = read(FIXTURE).split(/\r?\n/)[0]?.split(",") ?? [];
  return header
    .map((column) => {
      const value = values[column] ?? "";
      // Quote only when the value needs it, as NordPass does.
      return /[",\n]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value;
    })
    .join(",");
};

describe("parseNordPassCsv, against the sample export", () => {
  it("maps the two login rows and reports the card row by name, so the count adds up", () => {
    // The whole parsed output. The card row is the point of the fixture's third
    // line: Keyhole has no card item, and "imported 2 of 3" with the third
    // explained is a count the user can act on, where a silent skip is a number
    // they have no way to check.
    expect(parseNordPassCsv(read(FIXTURE))).toEqual({
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
      errors: [
        {
          row: 4,
          message:
            "This row is a NordPass credit card, which Keyhole cannot import yet, " +
            "so it was not imported",
        },
      ],
    });
  });
});

describe("parseNordPassCsv, on the item kinds it has no home for", () => {
  it("names an identity row as an identity rather than skipping it", () => {
    const csv = withRows(
      FIXTURE,
      row({ name: "Ada Lovelace", full_name: "Ada Lovelace", type: "identity" }),
    );

    expect(parseNordPassCsv(csv).errors).toEqual([
      {
        row: 2,
        message:
          "This row is a NordPass identity, which Keyhole cannot import yet, so it was not imported",
      },
    ]);
  });

  it("reports a type it has never heard of using the export's own word for it", () => {
    // Naming the word NordPass wrote is what lets the user match the error to a
    // row in their own file; a generic "unsupported item" cannot be looked up.
    const csv = withRows(FIXTURE, row({ name: "Something new", type: "passkey" }));

    expect(parseNordPassCsv(csv).errors).toEqual([
      {
        row: 2,
        message:
          "This row is a NordPass passkey, which Keyhole cannot import yet, so it was not imported",
      },
    ]);
  });

  it("maps a note row to a note item and does not require it to have a password", () => {
    // Only the two claims in the name: the row becomes a note, and having no
    // password is not a reason to refuse it. Which column the note body comes
    // from is the golden's claim — its first login row carries the fixture
    // notice in `note` — and asserting it a second time here would make a
    // single mapping regression fail two tests instead of naming one.
    const csv = withRows(
      FIXTURE,
      row({ name: "Router notes", note: "first line", folder: "Work", type: "note" }),
    );

    const result = parseNordPassCsv(csv);

    expect(result.errors).toEqual([]);
    expect(only(result).type).toBe("note");
  });
});

describe("parseNordPassCsv, on the password itself", () => {
  it("keeps a password holding both a comma and a quote exactly as the file escaped it", () => {
    const csv = withRows(
      FIXTURE,
      row({
        name: "Example Forum",
        url: "https://forum.example.org",
        username: "ada",
        password: 'fixture,pw"with"quotes',
        type: "password",
      }),
    );

    expect(only(parseNordPassCsv(csv)).password).toBe('fixture,pw"with"quotes');
  });

  it("keeps a trailing space in a password rather than trimming it", () => {
    const csv = withRows(
      FIXTURE,
      row({ name: "Example Mail", password: "fixture-pw-8Hq2vN ", type: "password" }),
    );

    expect(only(parseNordPassCsv(csv)).password).toBe("fixture-pw-8Hq2vN ");
  });
});

describe("parseNordPassCsv, on the columns beyond the login's own", () => {
  it("keeps a folder name containing a slash whole, since NordPass folders do not nest", () => {
    // NordPass has one flat level of folders, so there is no separator to split
    // at. Splitting at `/` on the assumption that it nests would turn one
    // folder the user named `Home/Office` into two that never existed.
    const csv = withRows(
      FIXTURE,
      row({ name: "Example Mail", password: "fixture-pw-8Hq2vN", folder: "Home/Office" }),
    );

    expect(only(parseNordPassCsv(csv)).folderPath).toEqual(["Home/Office"]);
  });

  it("places a row with an empty folder at the root rather than in a folder with no name", () => {
    const csv = withRows(FIXTURE, row({ name: "Example Mail", password: "fixture-pw-8Hq2vN" }));

    expect(only(parseNordPassCsv(csv)).folderPath).toEqual([]);
  });

  it("adds each line of additional_urls to the item's URLs, after the main one", () => {
    // NordPass writes a login's other sites into one cell. It is split at
    // newlines only: a newline cannot appear inside a URL, whereas a comma can,
    // and splitting at commas would break the URL rather than the list.
    const csv = withRows(
      FIXTURE,
      row({
        name: "Example Wiki",
        url: "https://wiki.example.org",
        additional_urls: "https://wiki.example.org/login\nhttps://wiki.example.net",
        password: "fixture-pw-9Kd3xR",
      }),
    );

    expect(only(parseNordPassCsv(csv)).urls).toEqual([
      "https://wiki.example.org",
      "https://wiki.example.org/login",
      "https://wiki.example.net",
    ]);
  });

  it("carries the custom_fields cell into extra as the user's own fields", () => {
    // NordPass flattens a login's custom fields into one cell. Carried whole
    // rather than split back apart, because nothing in the cell says which
    // separator it used and a wrong guess would split a value silently.
    const csv = withRows(
      FIXTURE,
      row({
        name: "Example Mail",
        password: "fixture-pw-8Hq2vN",
        custom_fields: "Security question: first pet",
      }),
    );

    expect(only(parseNordPassCsv(csv)).extra).toEqual([
      { name: "custom_fields", value: "Security question: first pet", kind: "custom" },
    ]);
  });

  it("leaves extra empty for a login with no custom fields", () => {
    const csv = withRows(FIXTURE, row({ name: "Example Mail", password: "fixture-pw-8Hq2vN" }));

    expect(only(parseNordPassCsv(csv)).extra).toEqual([]);
  });
});

describe("parseNordPassCsv, on rows it must refuse", () => {
  it("refuses a login row with an empty password and keeps the passwords either side", () => {
    const csv = withRows(
      FIXTURE,
      row({ name: "Good", password: "fixture-pw-8Hq2vN", type: "password" }),
      row({ name: "Blank", password: "", type: "password" }),
      row({ name: "Later", password: "fixture-pw-9Kd3xR", type: "password" }),
    );

    const result = parseNordPassCsv(csv);

    expect(result.errors).toEqual([
      { row: 3, message: "This row has an empty password, so it was not imported" },
    ]);
    expect(result.items.map((item) => item.password)).toEqual([
      "fixture-pw-8Hq2vN",
      "fixture-pw-9Kd3xR",
    ]);
  });

  it("refuses a login row that ends before its password column rather than importing a blank", () => {
    const csv = withRows(FIXTURE, "Short,https://short.example.com");

    expect(parseNordPassCsv(csv).errors).toEqual([
      { row: 2, message: "This row ends before its password column" },
    ]);
  });

  it("answers with one error for a CSV that is not a NordPass export, instead of throwing", () => {
    expect(parseNordPassCsv(read("unknown-manager-export.csv"))).toEqual({
      items: [],
      errors: [
        {
          row: 1,
          message: "This file has no password and cardholdername columns, so it is not a NordPass CSV export",
        },
      ],
    });
  });
});
