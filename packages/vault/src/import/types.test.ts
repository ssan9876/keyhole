import { describe, expect, it } from "vitest";
import { blankImportItem, folderSegments } from "./types.js";

describe("blankImportItem", () => {
  it("starts every field empty so a parser only sets what its export carried", () => {
    // Seven parsers will build on this. If each invents its own defaults, one
    // of them ends up with `folderPath: [""]` and the mapper files those items
    // into a folder with no name instead of leaving them at the root.
    const item = blankImportItem(12);

    expect(item).toEqual({
      type: "login",
      name: "",
      username: "",
      password: "",
      urls: [],
      notes: "",
      favorite: false,
      folderPath: [],
      extra: [],
      sourceRow: 12,
    });
  });

  it("gives each item its own urls and extra arrays", () => {
    // A shared default would make one row's second URL appear on every other
    // row that never set one.
    const first = blankImportItem(1);
    const second = blankImportItem(2);
    first.urls.push("https://x.example");
    first.extra.push({ name: "totp", value: "seed", kind: "totp" });

    expect(second.urls).toEqual([]);
    expect(second.extra).toEqual([]);
  });
});

describe("folderSegments", () => {
  it("splits at the separator the format uses, not at one it picked", () => {
    // The whole point of taking the separator as an argument. Bitwarden nests
    // with "/", LastPass's `grouping` with "\", and a shared helper that assumed
    // either would give the other parser a folder named "Personal\Forums".
    expect(folderSegments("Work/Servers", "/")).toEqual(["Work", "Servers"]);
    expect(folderSegments("Work\\Servers", "\\")).toEqual(["Work", "Servers"]);
  });

  it("leaves a name alone when it holds the other format's separator", () => {
    // A backslash is an ordinary character in a Bitwarden folder name. Splitting
    // on anything but the format's own separator invents a folder the export
    // never had.
    expect(folderSegments("Work\\Servers", "/")).toEqual(["Work\\Servers"]);
  });

  it("returns no segments for an empty path, which is the root", () => {
    expect(folderSegments("", "/")).toEqual([]);
  });

  it("drops the empty segments a leading, trailing or doubled separator makes", () => {
    // Punctuation, not folders. A `""` segment reaching `map.ts` becomes a
    // folder with no name in the user's vault.
    expect(folderSegments("/Work//Servers/", "/")).toEqual(["Work", "Servers"]);
  });

  it("does not trim a segment, because a name with spaces is still that name", () => {
    // Renaming the user's folder is not this layer's decision to make, and it is
    // the kind of tidying that only shows up as a duplicate folder later.
    expect(folderSegments(" Work / Servers ", "/")).toEqual([" Work ", " Servers "]);
  });
});
