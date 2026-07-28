import { describe, expect, it } from "vitest";
import { blankImportItem } from "./types.js";

describe("blankImportItem", () => {
  it("starts every field empty so a parser only sets what its export carried", () => {
    // Seven parsers will build on this. If each invents its own defaults, one
    // of them ends up with `folderName: ""` and the mapper files those items
    // into a folder literally named "" instead of leaving them at the root.
    const item = blankImportItem(12);

    expect(item).toEqual({
      type: "login",
      name: "",
      username: "",
      password: "",
      urls: [],
      notes: "",
      favorite: false,
      folderName: null,
      extra: {},
      sourceRow: 12,
    });
  });

  it("gives each item its own urls array and extra object", () => {
    // A shared default would make one row's second URL appear on every other
    // row that never set one.
    const first = blankImportItem(1);
    const second = blankImportItem(2);
    first.urls.push("https://x.example");
    first.extra["totp"] = "seed";

    expect(second.urls).toEqual([]);
    expect(second.extra).toEqual({});
  });
});
