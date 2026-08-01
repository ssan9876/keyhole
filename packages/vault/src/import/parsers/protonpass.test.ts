import { describe, expect, it } from "vitest";
import { NOTICE, only, read } from "../../testing/fixture.js";
import { parseProtonPassJson } from "./protonpass.js";

const FIXTURE = "proton-pass-export.json";

/** A Proton Pass export holding one vault of the given items. */
const inVault = (name: string, ...items: unknown[]): string =>
  JSON.stringify({
    version: "1.31.2",
    userId: "11111111-1111-4111-8111-111111111111",
    encrypted: false,
    vaults: { "22222222-2222-4222-8222-222222222222": { name, description: "", items } },
  });

/** A Proton Pass login item around the given content. */
const login = (
  name: string,
  content: Record<string, unknown>,
  rest: Record<string, unknown> = {},
): unknown => ({
  itemId: "33333333-3333-4333-8333-333333333333",
  state: 1,
  ...rest,
  data: {
    metadata: { name, note: "", itemUuid: "33333333-3333-4333-8333-333333333333" },
    extraFields: [],
    type: "login",
    content,
  },
});

describe("parseProtonPassJson, against the sample export", () => {
  it("maps the login and takes the vault's name as its folder", () => {
    expect(parseProtonPassJson(read(FIXTURE))).toEqual({
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
});

describe("parseProtonPassJson, on the vault an item sits in", () => {
  it("gives each vault's items that vault's name as their folder", () => {
    // Proton Pass has no folders — it has vaults, and an item belongs to
    // exactly one. The vault name is therefore the folder, and it is the only
    // grouping the export carries.
    const json = JSON.stringify({
      encrypted: false,
      vaults: {
        "1": { name: "Personal", items: [login("Mail", { password: "fixture-pw-8Hq2vN" })] },
        "2": { name: "Work", items: [login("Wiki", { password: "fixture-pw-9Kd3xR" })] },
      },
    });

    expect(parseProtonPassJson(json).items.map((item) => item.folderPath)).toEqual([
      ["Personal"],
      ["Work"],
    ]);
  });

  it("keeps a vault name containing a slash whole, since Proton Pass vaults do not nest", () => {
    const json = inVault("Home/Office", login("Mail", { password: "fixture-pw-8Hq2vN" }));

    expect(only(parseProtonPassJson(json)).folderPath).toEqual(["Home/Office"]);
  });

  it("places an item from an unnamed vault at the root rather than in a folder with no name", () => {
    const json = inVault("", login("Mail", { password: "fixture-pw-8Hq2vN" }));

    expect(only(parseProtonPassJson(json)).folderPath).toEqual([]);
  });
});

describe("parseProtonPassJson, on the two login fields Proton Pass keeps apart", () => {
  it("prefers itemUsername over itemEmail and carries the email so neither is lost", () => {
    const json = inVault(
      "Personal",
      login("Mail", {
        itemEmail: "ada@example.com",
        itemUsername: "ada",
        password: "fixture-pw-8Hq2vN",
        urls: [],
      }),
    );

    const item = only(parseProtonPassJson(json));

    expect(item.username).toBe("ada");
    expect(item.extra).toEqual([{ name: "itemEmail", value: "ada@example.com", kind: "custom" }]);
  });

  it("does not carry the email a second time when it is already the username", () => {
    const json = inVault(
      "Personal",
      login("Mail", { itemEmail: "ada@example.com", itemUsername: "", password: "fixture-pw-8Hq2vN" }),
    );

    const item = only(parseProtonPassJson(json));

    expect(item.username).toBe("ada@example.com");
    expect(item.extra).toEqual([]);
  });
});

describe("parseProtonPassJson, on what Keyhole has no field for", () => {
  it("reads urls as an array of strings, not of objects as Bitwarden writes them", () => {
    // Proton Pass writes `urls: ["https://…"]`. Reading them the way Bitwarden's
    // are read — `entry.uri` on each — would give `undefined` for every URL of
    // every item and drop the lot.
    const json = inVault(
      "Personal",
      login("Wiki", {
        password: "fixture-pw-9Kd3xR",
        urls: ["https://wiki.example.org", "https://wiki.example.net"],
      }),
    );

    expect(only(parseProtonPassJson(json)).urls).toEqual([
      "https://wiki.example.org",
      "https://wiki.example.net",
    ]);
  });

  it("carries the login's own totpUri as a second factor", () => {
    const uri = "otpauth://totp/Example:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    const json = inVault(
      "Personal",
      login("Mail", { password: "fixture-pw-8Hq2vN", totpUri: uri }),
    );

    expect(only(parseProtonPassJson(json)).extra).toEqual([
      { name: "totpUri", value: uri, kind: "totp" },
    ]);
  });

  it("carries a user-made extra field under the name the user gave it", () => {
    const json = inVault("Personal", {
      state: 1,
      data: {
        metadata: { name: "Mail", note: "" },
        extraFields: [
          { fieldName: "Recovery code", type: "hidden", data: { content: "fixture-code-7Jm4tQ" } },
        ],
        type: "login",
        content: { password: "fixture-pw-8Hq2vN" },
      },
    });

    expect(only(parseProtonPassJson(json)).extra).toEqual([
      { name: "Recovery code", value: "fixture-code-7Jm4tQ", kind: "custom" },
    ]);
  });

  it("calls an extra field a second factor from its declared type, not from its name", () => {
    // `type` here is Proton Pass's own field-type discriminator, set by the
    // app rather than typed by the user — so it is where the value sat, which
    // is what `ImportFieldKind` says the kind must come from. A user's text
    // field *named* "totp" stays custom, which the case below pins.
    const json = inVault("Personal", {
      state: 1,
      data: {
        metadata: { name: "Mail", note: "" },
        extraFields: [
          { fieldName: "Work 2FA", type: "totp", data: { content: "JBSWY3DPEHPK3PXP" } },
          { fieldName: "totp", type: "text", data: { content: "a note the user typed" } },
        ],
        type: "login",
        content: { password: "fixture-pw-8Hq2vN" },
      },
    });

    expect(only(parseProtonPassJson(json)).extra).toEqual([
      { name: "Work 2FA", value: "JBSWY3DPEHPK3PXP", kind: "totp" },
      { name: "totp", value: "a note the user typed", kind: "custom" },
    ]);
  });

  it("records that an item carried passkeys, without carrying the passkeys themselves", () => {
    // A passkey cannot be imported and its material has no business in a note.
    // Saying how many there were is what stops the user believing they moved.
    const json = inVault(
      "Personal",
      login("Mail", {
        password: "fixture-pw-8Hq2vN",
        passkeys: [{ keyId: "aaa", domain: "example.com" }, { keyId: "bbb" }],
      }),
    );

    expect(only(parseProtonPassJson(json)).extra).toEqual([
      { name: "passkeys", value: "2", kind: "metadata" },
    ]);
  });
});

describe("parseProtonPassJson, on the item types it has no home for", () => {
  it("maps a note item to a note item rather than refusing it for having no password", () => {
    // Only the claim in the name. Which metadata field the note text comes from
    // is the golden's claim — its login carries the fixture notice in
    // `metadata.note`, and both kinds take that value on the same line — so
    // asserting it again here would make one mapping regression fail two tests
    // instead of naming one.
    const json = inVault("Personal", {
      state: 1,
      data: {
        metadata: { name: "Router notes", note: "first line\nsecond line" },
        extraFields: [],
        type: "note",
        content: {},
      },
    });

    const result = parseProtonPassJson(json);

    expect(result.errors).toEqual([]);
    expect(only(result).type).toBe("note");
  });

  it("names a credit card item as a credit card rather than skipping it", () => {
    const json = inVault(
      "Personal",
      login("Mail", { password: "fixture-pw-8Hq2vN" }),
      {
        state: 1,
        data: {
          metadata: { name: "Ada's card", note: "" },
          extraFields: [],
          type: "creditCard",
          content: {},
        },
      },
    );

    const result = parseProtonPassJson(json);

    expect(result.errors).toEqual([
      {
        row: 2,
        message:
          'Item 2 ("Ada\'s card") is a Proton Pass credit card, which Keyhole cannot ' +
          "import yet, so it was not imported",
      },
    ]);
    // The login either side is the point: an item Keyhole cannot store must not
    // cost the user the ones it can. Its password rather than its name, because
    // which field holds the display name is the golden's claim, not this one's.
    expect(result.items.map((item) => item.password)).toEqual(["fixture-pw-8Hq2vN"]);
  });

  it("reports a trashed item as trashed rather than importing what the user deleted", () => {
    // Proton Pass exports the trash alongside the vault. Importing it silently
    // resurrects items the user chose to delete; dropping it silently loses
    // items they may not have meant to. Naming it lets them decide.
    const json = inVault(
      "Personal",
      login("Deleted", { password: "fixture-pw-8Hq2vN" }, { state: 2 }),
    );

    expect(parseProtonPassJson(json).errors).toEqual([
      {
        row: 1,
        message: 'Item 1 ("Deleted") is in the Proton Pass trash, so it was not imported',
      },
    ]);
  });
});

describe("parseProtonPassJson, on items it must refuse", () => {
  it("refuses a login whose password is empty instead of importing a blank over a real one", () => {
    const json = inVault(
      "Personal",
      login("Blank", { password: "" }),
      login("Good", { password: "fixture-pw-8Hq2vN" }),
    );

    const result = parseProtonPassJson(json);

    expect(result.errors).toEqual([
      { row: 1, message: 'Item 1 ("Blank") has an empty password, so it was not imported' },
    ]);
    expect(result.items.map((item) => item.password)).toEqual(["fixture-pw-8Hq2vN"]);
  });

  it("refuses a login whose password field is absent, which is a damaged export", () => {
    const json = inVault("Personal", login("No password", { urls: [] }));

    expect(parseProtonPassJson(json).errors).toEqual([
      { row: 1, message: 'Item 1 ("No password") has no password, so it was not imported' },
    ]);
  });

  it("tells the user to export again unencrypted rather than failing to parse", () => {
    const json = JSON.stringify({ version: "1.31.2", encrypted: true, vaults: {} });

    expect(parseProtonPassJson(json)).toEqual({
      items: [],
      errors: [
        {
          row: 1,
          message:
            "This is an encrypted Proton Pass export, which cannot be read without your " +
            "Proton Pass password. Export it again unencrypted and upload that file.",
        },
      ],
    });
  });

  it("answers with one error for a file that is not JSON, instead of throwing", () => {
    expect(parseProtonPassJson("name,url\nExample,https://example.com")).toEqual({
      items: [],
      errors: [{ row: 1, message: "This file is not valid JSON, so nothing could be read from it" }],
    });
  });

  it("answers with one error for JSON that carries no vaults object", () => {
    expect(parseProtonPassJson('{"items":[]}')).toEqual({
      items: [],
      errors: [
        {
          row: 1,
          message: "This file has no vaults object, so it is not a Proton Pass JSON export",
        },
      ],
    });
  });
});
