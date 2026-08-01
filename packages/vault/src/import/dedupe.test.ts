import { describe, expect, it } from "vitest";
import type { ItemRecord } from "../items.js";
import { existingFromRecords, findDuplicates, matchHost, type ExistingItem } from "./dedupe.js";
import { blankImportItem, type ImportItem } from "./types.js";

/** A login row, with only the fields duplicate detection reads spelled out. */
function row(fields: Partial<ImportItem>, line = 1): ImportItem {
  return { ...blankImportItem(line), ...fields };
}

function vaultItem(fields: Partial<ExistingItem>): ExistingItem {
  return { id: "i1", name: "", username: "", urls: [], ...fields };
}

describe("matchHost", () => {
  it("answers the same host for two URLs that differ only in path", () => {
    // The whole point of comparing hosts rather than URLs: these are one
    // account, and a full-URL comparison calls them two.
    expect(matchHost("https://x.com/login")).toBe(matchHost("https://x.com/"));
  });

  it("drops a leading www. so the bare domain and the www one are one host", () => {
    expect(matchHost("https://www.example.com/")).toBe("example.com");
  });

  it("drops only the first www. label, so a host really called www.www.x is kept", () => {
    // Stripping repeatedly would rename a host that genuinely nests the label.
    expect(matchHost("https://www.www.example.com/")).toBe("www.example.com");
  });

  it("lowercases the host, so a hand-typed capital does not split an account", () => {
    expect(matchHost("HTTPS://Example.COM/Path")).toBe("example.com");
  });

  it("ignores the scheme, so an http row and an https row are one account", () => {
    expect(matchHost("http://example.com/")).toBe(matchHost("https://example.com/"));
  });

  it("drops the root label's trailing dot, which resolves to the same host", () => {
    expect(matchHost("https://example.com./")).toBe("example.com");
  });

  it("keeps a non-default port, because two ports are two services", () => {
    expect(matchHost("https://example.com:8443/")).toBe("example.com:8443");
    // The default port is not part of the name: a browser writes it away, and
    // an export that spells it out means the same site.
    expect(matchHost("https://example.com:443/")).toBe("example.com");
  });

  it("reads a host out of a value with no scheme, which several exports write", () => {
    // KeePass and LastPass exports carry bare hosts; refusing to compare them
    // would exempt whole files from duplicate detection.
    expect(matchHost("mail.example.com")).toBe("mail.example.com");
    expect(matchHost("example.com/login")).toBe("example.com");
  });

  it("answers the same host for a Unicode domain and its punycode spelling", () => {
    // Two managers can export the same site either way, and they are one host.
    expect(matchHost("https://☃.com/")).toBe(matchHost("https://xn--n3h.com/"));
  });

  it("answers null for an empty value and for text that holds no host", () => {
    expect(matchHost("")).toBeNull();
    expect(matchHost("   ")).toBeNull();
    expect(matchHost("Bank of America")).toBeNull();
  });
});

describe("findDuplicates, within one file", () => {
  it("groups two rows whose URLs differ only in path under one host and username", () => {
    // The mutation guard: comparing full URLs instead of hosts fails here.
    const rows = [
      row({ urls: ["https://x.com/login"], username: "ada" }, 2),
      row({ urls: ["https://x.com/"], username: "ada" }, 3),
    ];

    const report = findDuplicates(rows);

    expect(report.groups).toEqual([
      { key: { host: "x.com", username: "ada" }, rows: [0, 1], existing: [] },
    ]);
  });

  it("groups a www row with a bare-domain row for the same username", () => {
    const rows = [
      row({ urls: ["https://www.x.com/"], username: "ada" }, 2),
      row({ urls: ["https://x.com/account"], username: "ada" }, 3),
    ];

    expect(findDuplicates(rows).groups).toHaveLength(1);
  });

  it("reports no group for two usernames on one host, which are two accounts", () => {
    const rows = [
      row({ urls: ["https://x.com/"], username: "ada" }, 2),
      row({ urls: ["https://x.com/"], username: "grace" }, 3),
    ];

    expect(findDuplicates(rows).groups).toEqual([]);
  });

  it("reports no group for one username across two hosts", () => {
    const rows = [
      row({ urls: ["https://x.com/"], username: "ada" }, 2),
      row({ urls: ["https://y.com/"], username: "ada" }, 3),
    ];

    expect(findDuplicates(rows).groups).toEqual([]);
  });

  it("reports no group for one username on two ports of a host, which are two services", () => {
    const rows = [
      row({ urls: ["https://x.com:8443/"], username: "ada" }, 2),
      row({ urls: ["https://x.com/"], username: "ada" }, 3),
    ];

    expect(findDuplicates(rows).groups).toEqual([]);
  });

  it("matches usernames ignoring case and surrounding space", () => {
    const rows = [
      row({ urls: ["https://x.com/"], username: "Ada@Example.com" }, 2),
      row({ urls: ["https://x.com/"], username: " ada@example.com " }, 3),
    ];

    expect(findDuplicates(rows).groups).toHaveLength(1);
  });

  it("keys a row on its first URL when the export carried several", () => {
    // A row belongs to one group or the group a user skips is ambiguous. The
    // first URL is the one the exports write as the primary.
    const rows = [
      row({ urls: ["https://x.com/", "https://alt.example.com/"], username: "ada" }, 2),
      row({ urls: ["https://x.com/in"], username: "ada" }, 3),
      row({ urls: ["https://alt.example.com/"], username: "ada" }, 4),
    ];

    expect(findDuplicates(rows).groups).toEqual([
      { key: { host: "x.com", username: "ada" }, rows: [0, 1], existing: [] },
    ]);
  });

  it("lists the row indices in the order they were given, not in match order", () => {
    const rows = [
      row({ urls: ["https://x.com/"], username: "ada" }, 2),
      row({ urls: ["https://y.com/"], username: "ada" }, 3),
      row({ urls: ["https://x.com/two"], username: "ada" }, 4),
    ];

    expect(findDuplicates(rows).groups[0]?.rows).toEqual([0, 2]);
  });

  it("groups three rows of one account together rather than as two pairs", () => {
    const rows = [
      row({ urls: ["https://x.com/a"], username: "ada" }, 2),
      row({ urls: ["https://x.com/b"], username: "ada" }, 3),
      row({ urls: ["https://x.com/c"], username: "ada" }, 4),
    ];

    expect(findDuplicates(rows).groups[0]?.rows).toEqual([0, 1, 2]);
  });
});

describe("findDuplicates, on rows nothing can be compared against", () => {
  it("does not group two URL-less rows that happen to share a username", () => {
    // The failure this is here to prevent: keying every URL-less row under one
    // empty host puts a whole file's worth of unrelated rows in one group, and
    // a user who skips that group loses items that were never duplicates.
    const rows = [
      row({ urls: [], username: "ada" }, 2),
      row({ urls: [], username: "ada" }, 3),
    ];

    expect(findDuplicates(rows).groups).toEqual([]);
  });

  it("lists a URL-less row as unchecked rather than as checked and clean", () => {
    // "We could not check this" and "we checked and it is not a duplicate" are
    // different answers, and the preview screen has to be able to say which.
    const rows = [
      row({ urls: [], username: "ada" }, 2),
      row({ urls: ["https://x.com/"], username: "ada" }, 3),
    ];

    expect(findDuplicates(rows).unchecked).toEqual([0]);
  });

  it("lists a row whose URL holds no host as unchecked", () => {
    const rows = [row({ urls: ["Bank of America"], username: "ada" }, 2)];

    expect(findDuplicates(rows).unchecked).toEqual([0]);
  });

  it("lists a note row as unchecked, since a note is not an account", () => {
    const rows = [row({ type: "note", urls: ["https://x.com/"], name: "Wifi" }, 2)];

    expect(findDuplicates(rows).unchecked).toEqual([0]);
  });

  it("does not group a note with a login on the same host and username", () => {
    const rows = [
      row({ type: "note", urls: ["https://x.com/"], username: "ada" }, 2),
      row({ urls: ["https://x.com/"], username: "ada" }, 3),
    ];

    expect(findDuplicates(rows).groups).toEqual([]);
  });

  it("leaves unchecked empty when every row carried a host", () => {
    const rows = [row({ urls: ["https://x.com/"], username: "ada" }, 2)];

    expect(findDuplicates(rows).unchecked).toEqual([]);
  });
});

describe("findDuplicates, against the vault already on this device", () => {
  it("reports a lone row that matches an item already in the vault", () => {
    // Importing the same export twice, or importing after adding a few by hand,
    // is the common case — and within the file alone there is nothing to see.
    const rows = [row({ urls: ["https://x.com/login"], username: "ada" }, 2)];
    const existing = [vaultItem({ id: "v1", name: "X", urls: ["https://x.com/"], username: "ada" })];

    expect(findDuplicates(rows, existing).groups).toEqual([
      {
        key: { host: "x.com", username: "ada" },
        rows: [0],
        existing: [{ id: "v1", name: "X", urls: ["https://x.com/"], username: "ada" }],
      },
    ]);
  });

  it("reports no group for a vault item the file does not touch", () => {
    const rows = [row({ urls: ["https://x.com/"], username: "ada" }, 2)];
    const existing = [vaultItem({ id: "v1", urls: ["https://y.com/"], username: "ada" })];

    expect(findDuplicates(rows, existing).groups).toEqual([]);
  });

  it("normalizes the vault item's host the same way as the file's", () => {
    const rows = [row({ urls: ["https://x.com/"], username: "ada" }, 2)];
    const existing = [vaultItem({ id: "v1", urls: ["https://WWW.X.com/account"], username: "ADA" })];

    expect(findDuplicates(rows, existing).groups).toHaveLength(1);
  });

  it("puts the file's rows and the vault's matches in one group, not two", () => {
    const rows = [
      row({ urls: ["https://x.com/a"], username: "ada" }, 2),
      row({ urls: ["https://x.com/b"], username: "ada" }, 3),
    ];
    const existing = [vaultItem({ id: "v1", urls: ["https://x.com/"], username: "ada" })];

    const report = findDuplicates(rows, existing);

    expect(report.groups).toHaveLength(1);
    expect(report.groups[0]?.rows).toEqual([0, 1]);
    expect(report.groups[0]?.existing.map((item) => item.id)).toEqual(["v1"]);
  });
});

describe("existingFromRecords", () => {
  const record = (fields: Partial<ItemRecord>): ItemRecord => ({
    id: "v1",
    revision: 1,
    collectionId: null,
    deletedAt: null,
    plaintext: null,
    ...fields,
  });

  it("reduces a decrypted login to its id, name, username and urls", () => {
    const records = [
      record({
        id: "v1",
        plaintext: {
          type: "login",
          name: "X",
          username: "ada",
          password: "secret",
          urls: ["https://x.com/"],
          notes: "",
          favorite: false,
          folderId: null,
          passwordHistory: [],
        },
      }),
    ];

    expect(existingFromRecords(records)).toEqual([
      { id: "v1", name: "X", username: "ada", urls: ["https://x.com/"] },
    ]);
  });

  it("carries no password out of the vault, so nothing here can leak one", () => {
    const records = [
      record({
        plaintext: {
          type: "login",
          name: "X",
          username: "ada",
          password: "vault-plaintext-8Hq2vN",
          urls: ["https://x.com/"],
          notes: "",
          favorite: false,
          folderId: null,
          passwordHistory: [],
        },
      }),
    ];

    expect(JSON.stringify(existingFromRecords(records))).not.toContain("vault-plaintext-8Hq2vN");
  });

  it("skips a record this device could not decrypt, which it cannot compare", () => {
    // A row in a collection whose key is not held reads as plaintext: null.
    // Claiming it is not a duplicate would be a claim nothing checked.
    expect(existingFromRecords([record({ plaintext: null })])).toEqual([]);
  });

  it("skips a note, which has no username to compare", () => {
    const records = [
      record({
        plaintext: { type: "note", name: "Wifi", notes: "", favorite: false, folderId: null },
      }),
    ];

    expect(existingFromRecords(records)).toEqual([]);
  });
});
