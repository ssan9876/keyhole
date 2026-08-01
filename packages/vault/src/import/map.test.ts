import { describe, expect, it } from "vitest";
import {
  MANUAL_FORMATS,
  parseGenericCsv,
  parseText,
  suggestMapping,
  toItemPlaintext,
  toItemPlaintexts,
  type CsvColumnMapping,
} from "./map.js";
import { blankImportItem, type ImportItem } from "./types.js";
import { only } from "./parsers/fixture.js";

function row(fields: Partial<ImportItem>, line = 1): ImportItem {
  return { ...blankImportItem(line), ...fields };
}

/** The notes of the one item a single-row case produced. */
function notesOf(item: ImportItem): string {
  const mapped = toItemPlaintext(item);
  return mapped.notes;
}

describe("toItemPlaintext, on the shape of the item it produces", () => {
  it("turns a login row into a login item with an empty password history", () => {
    const item = row({
      type: "login",
      name: "Example Mail",
      username: "ada",
      password: "fixture-pw-8Hq2vN",
      urls: ["https://mail.example.com"],
      notes: "a note",
      favorite: true,
    });

    expect(toItemPlaintext(item)).toEqual({
      type: "login",
      name: "Example Mail",
      username: "ada",
      password: "fixture-pw-8Hq2vN",
      urls: ["https://mail.example.com"],
      notes: "a note",
      favorite: true,
      folderId: null,
      passwordHistory: [],
    });
  });

  it("turns a note row into a note item, which has no username or password field", () => {
    const item = row({ type: "note", name: "Wifi", notes: "the code" });

    expect(toItemPlaintext(item)).toEqual({
      type: "note",
      name: "Wifi",
      notes: "the code",
      favorite: false,
      folderId: null,
    });
  });

  it("keeps a note row that carries a password as a login, rather than dropping it", () => {
    // Keyhole's note item has no password field, so mapping this as a note
    // deletes a secret with no undo — and the user is about to be told to
    // delete their export file.
    const item = row({ type: "note", name: "Server", password: "fixture-pw-8Hq2vN" });

    expect(toItemPlaintext(item)).toMatchObject({ type: "login", password: "fixture-pw-8Hq2vN" });
  });

  it("preserves the password byte for byte, trailing space included", () => {
    const item = row({ password: "fixture-pw-8Hq2vN " });

    expect(toItemPlaintext(item)).toMatchObject({ password: "fixture-pw-8Hq2vN " });
  });

  it("leaves the note untouched for a row with no folder and nothing extra", () => {
    expect(notesOf(row({ notes: "just what the user wrote" }))).toBe("just what the user wrote");
  });

  it("maps a whole file in one call, in file order", () => {
    const items = toItemPlaintexts([row({ name: "one" }, 2), row({ name: "two" }, 3)]);

    expect(items.map((item) => item.name)).toEqual(["one", "two"]);
  });
});

describe("toItemPlaintext, on what the export carried that Keyhole has no field for", () => {
  it("names a totp entry as a one-time-password secret, not as anonymous free text", () => {
    // Keyhole has no TOTP field in v1. The seed still has to reach the user in
    // a form they can search for and recognise months later; merged into the
    // note under the exporter's own spelling alone, it reads as noise.
    const item = row({
      notes: "",
      extra: [{ name: "OTPAuth", value: "otpauth://totp/x?secret=JBSWY3DP", kind: "totp" }],
    });

    const notes = notesOf(item);

    expect(notes).toContain("One-time password (TOTP) secret");
    expect(notes).toContain("OTPAuth");
    expect(notes).toContain("otpauth://totp/x?secret=JBSWY3DP");
  });

  it("writes a custom entry under the name the user gave it", () => {
    const item = row({ extra: [{ name: "PIN", value: "1234", kind: "custom" }] });

    expect(notesOf(item)).toContain("PIN: 1234");
  });

  it("marks a metadata entry as the exporter's own, not as something the user typed", () => {
    const item = row({ extra: [{ name: "httpRealm", value: "Intranet", kind: "metadata" }] });
    const notes = notesOf(item);

    expect(notes).toContain("httpRealm");
    expect(notes).toContain("Intranet");
    expect(notes).toContain("exporter");
  });

  it("keeps two entries of the same name as two lines rather than merging them", () => {
    const item = row({
      extra: [
        { name: "PIN", value: "1111", kind: "custom" },
        { name: "PIN", value: "2222", kind: "custom" },
      ],
    });
    const notes = notesOf(item);

    expect(notes).toContain("PIN: 1111");
    expect(notes).toContain("PIN: 2222");
  });

  it("keeps the user's own note above what the import appended", () => {
    const item = row({
      notes: "what the user wrote",
      extra: [{ name: "PIN", value: "1234", kind: "custom" }],
    });

    expect(notesOf(item).startsWith("what the user wrote")).toBe(true);
  });

  it("appends the extras to a note item too, which would otherwise lose them", () => {
    const item = row({
      type: "note",
      notes: "the code",
      extra: [{ name: "PIN", value: "1234", kind: "custom" }],
    });

    expect(toItemPlaintext(item).notes).toContain("PIN: 1234");
  });

  it("writes a note row's username and web address into the note, having no field for them", () => {
    // A LastPass secure note carries both. `NoteItem` has neither field, and
    // dropping them would lose something the user can see in LastPass today.
    const item = row({ type: "note", username: "ada", urls: ["https://x.com"] });
    const notes = toItemPlaintext(item).notes;

    expect(notes).toContain("Username: ada");
    expect(notes).toContain("Web address: https://x.com");
  });
});

describe("toItemPlaintext, on the folder an export named", () => {
  it("leaves folderId null and writes the path into the note", () => {
    // Keyhole's folders have an API but no screen. Creating folders here would
    // put the item somewhere the user cannot see, rename or empty; the note is
    // somewhere they can read today, and the path survives for when a folder
    // screen exists.
    const item = row({ folderPath: ["Work", "Servers"] });
    const mapped = toItemPlaintext(item);

    expect(mapped.folderId).toBeNull();
    expect(mapped.notes).toContain("Work / Servers");
  });

  it("joins the path with one separator whatever the export nested with", () => {
    // The segments arrive already split by the parser, so the display never
    // shows a backslash for LastPass and a slash for KeePassXC.
    expect(notesOf(row({ folderPath: ["A", "B", "C"] }))).toContain("A / B / C");
  });

  it("says nothing about a folder for a row the export placed at the root", () => {
    expect(notesOf(row({ folderPath: [], notes: "n" }))).toBe("n");
  });

  it("puts every item in the folder the caller chose, when it chose one", () => {
    // The one way an import can reach a real folder id: the caller passes one.
    // Nothing here invents an id, because no export can know one.
    expect(toItemPlaintext(row({}), { folderId: "f1" }).folderId).toBe("f1");
  });
});

describe("suggestMapping", () => {
  it("finds the obvious columns of a header nobody wrote a parser for", () => {
    const mapping = suggestMapping(["Name", "Web Site", "Login Name", "Password", "Comments"]);

    expect(mapping.name).toBe("Name");
    expect(mapping.username).toBe("Login Name");
    expect(mapping.password).toBe("Password");
    expect(mapping.url).toBe("Web Site");
    expect(mapping.notes).toBe("Comments");
  });

  it("leaves a column it cannot place unset rather than guessing at it", () => {
    const mapping = suggestMapping(["a", "b", "c"]);

    expect(mapping.password).toBeNull();
    expect(mapping.username).toBeNull();
  });

  it("returns the header's own spelling, so the screen can show what it picked", () => {
    expect(suggestMapping(["PASSWORD"]).password).toBe("PASSWORD");
  });

  it("marks a column it could not place as a custom field, rather than dropping it", () => {
    // A column dropped because nothing recognised its name is still a column
    // dropped, and the user cannot miss what they were never shown.
    expect(suggestMapping(["password", "Security question"]).custom).toEqual([
      "Security question",
    ]);
  });
});

describe("parseGenericCsv", () => {
  const mapping = (fields: Partial<CsvColumnMapping>): CsvColumnMapping => ({
    ...suggestMapping([]),
    ...fields,
  });

  it("reads each field from the column the user picked for it", () => {
    const csv = ["one,two,three,four", "Example,ada,fixture-pw-8Hq2vN,https://x.com"].join("\n");

    expect(
      only(
        parseGenericCsv(
          csv,
          mapping({ name: "one", username: "two", password: "three", url: "four" }),
        ),
      ),
    ).toMatchObject({
      name: "Example",
      username: "ada",
      password: "fixture-pw-8Hq2vN",
      urls: ["https://x.com"],
    });
  });

  it("refuses the whole file when no column has been picked as the password", () => {
    // Guessing here is the failure with no undo. Better an error the mapping
    // screen shows than a vault of items with empty passwords.
    const csv = ["one,two", "Example,ada"].join("\n");

    const result = parseGenericCsv(csv, mapping({ name: "one", username: "two" }));

    expect(result.items).toEqual([]);
    expect(result.errors[0]?.message).toContain("password");
  });

  it("refuses a row whose password cell is empty and keeps the rows around it", () => {
    const csv = ["u,p", "https://a.example.com,fixture-pw-8Hq2vN", "https://b.example.com,"].join(
      "\n",
    );

    const result = parseGenericCsv(csv, mapping({ url: "u", password: "p" }));

    expect(result.items).toHaveLength(1);
    expect(result.errors).toEqual([
      { row: 3, message: "This row has an empty password, so it was not imported" },
    ]);
  });

  it("splits the folder column on the separator the user named", () => {
    const csv = ["f,p", "Work\\Servers,fixture-pw-8Hq2vN"].join("\n");

    expect(
      only(parseGenericCsv(csv, mapping({ folder: "f", password: "p", folderSeparator: "\\" })))
        .folderPath,
    ).toEqual(["Work", "Servers"]);
  });

  it("carries the column named as the one-time-password secret with the totp kind", () => {
    // The kind is what the mapper and the preview screen read; a column called
    // anything at all is a totp secret if the user says that is what it is.
    const csv = ["p,seed", "fixture-pw-8Hq2vN,JBSWY3DPEHPK3PXP"].join("\n");

    expect(only(parseGenericCsv(csv, mapping({ password: "p", totp: "seed" }))).extra).toEqual([
      { name: "seed", value: "JBSWY3DPEHPK3PXP", kind: "totp" },
    ]);
  });

  it("carries the columns the user marked as custom fields under their own names", () => {
    const csv = ["p,pin,branch", "fixture-pw-8Hq2vN,1234,Cambridge"].join("\n");

    expect(
      only(parseGenericCsv(csv, mapping({ password: "p", custom: ["pin", "branch"] }))).extra,
    ).toEqual([
      { name: "pin", value: "1234", kind: "custom" },
      { name: "branch", value: "Cambridge", kind: "custom" },
    ]);
  });

  it("uses the suggested mapping when the caller passes none", () => {
    const csv = ["name,url,username,password", "Example,https://x.com,ada,fixture-pw-8Hq2vN"].join(
      "\n",
    );

    expect(only(parseGenericCsv(csv))).toMatchObject({
      name: "Example",
      username: "ada",
      password: "fixture-pw-8Hq2vN",
    });
  });
});

describe("the formats a user can name by hand", () => {
  it("offers Keeper's CSV, which detection can never answer on its own", () => {
    // Keeper writes no header row, so there is nothing to sign and `detect`
    // answers generic-csv for it forever. Without this entry `parseKeeperCsv`
    // is unreachable code.
    expect(MANUAL_FORMATS.map((choice) => choice.id)).toContain("keeper-csv");
  });

  it("warns on the Keeper entry that its column order cannot be checked", () => {
    const keeper = MANUAL_FORMATS.find((choice) => choice.id === "keeper-csv");

    expect(keeper?.caution).toBeTruthy();
  });

  it("offers every parser the detector can answer, so a wrong guess is correctable", () => {
    const ids = MANUAL_FORMATS.map((choice) => choice.id);

    expect(ids).toContain("bitwarden-json");
    expect(ids).toContain("generic-csv");
  });

  it("reads a Keeper CSV's first line as a record rather than as column names", () => {
    const csv = "Personal,Only Row,ada,fixture-pw-8Hq2vN,https://a.example.com,";

    expect(only(parseText("keeper-csv", csv)).name).toBe("Only Row");
  });

  it("routes a named format to that format's parser", () => {
    const csv = ["name,url,username,password,note", "Example,https://x.com,ada,pw-8Hq2vN,"].join(
      "\n",
    );

    expect(only(parseText("browser-csv", csv)).name).toBe("Example");
  });

  it("routes the generic format through the column mapping the user chose", () => {
    const csv = ["one,two", "Example,fixture-pw-8Hq2vN"].join("\n");
    const chosen: CsvColumnMapping = { ...suggestMapping([]), name: "one", password: "two" };

    expect(only(parseText("generic-csv", csv, chosen)).password).toBe("fixture-pw-8Hq2vN");
  });
});
