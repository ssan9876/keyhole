import { describe, expect, it } from "vitest";
import { buildPrecacheList, cacheName } from "./precache.js";

describe("buildPrecacheList", () => {
  it("includes index.html and at least one hashed asset the build emitted", () => {
    // This is the "proves the build hook ran" check: the Vite hook feeds this
    // the real bundle filenames, and a shell precache that dropped the hashed
    // JS/CSS would install an app that cannot boot offline.
    const list = buildPrecacheList([
      "index.html",
      "assets/index-AbC123.js",
      "assets/index-XyZ789.css",
    ]);
    expect(list).toContain("index.html");
    const hashed = list.filter((name) => /^assets\/.+-[\w-]+\.\w+$/.test(name));
    expect(hashed.length).toBeGreaterThanOrEqual(1);
    expect(list).toContain("assets/index-AbC123.js");
    expect(list).toContain("assets/index-XyZ789.css");
  });

  it("does not duplicate index.html when the bundle already lists it", () => {
    const list = buildPrecacheList(["index.html", "assets/a-1.js"]);
    expect(list.filter((name) => name === "index.html")).toHaveLength(1);
  });

  it("carries the shell even if the bundle keys omit index.html", () => {
    // index.html is the navigable shell the offline fallback depends on, so it
    // is always present regardless of how the bundle enumerates its entries.
    const list = buildPrecacheList(["assets/a-1.js"]);
    expect(list).toContain("index.html");
  });

  it("leaves out non-asset, non-shell files like the manifest and icons", () => {
    // The manifest and icons are served on demand; only the code shell needs to
    // be precached to boot offline, and precaching more only risks staleness.
    const list = buildPrecacheList([
      "index.html",
      "assets/index-AbC123.js",
      "manifest.webmanifest",
      "icon-512.png",
    ]);
    expect(list).not.toContain("manifest.webmanifest");
    expect(list).not.toContain("icon-512.png");
  });
});

describe("cacheName", () => {
  it("embeds a build id so a changed precache list lands in a new cache", () => {
    const a = cacheName(["index.html", "assets/a-1.js"]);
    const b = cacheName(["index.html", "assets/a-2.js"]);
    expect(a).toMatch(/^keyhole-shell-/);
    expect(a).not.toBe(b);
  });

  it("is stable for the same list regardless of enumeration order", () => {
    expect(cacheName(["index.html", "assets/a-1.js"])).toBe(
      cacheName(["assets/a-1.js", "index.html"]),
    );
  });
});
