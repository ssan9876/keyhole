import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// The manifest is a static file the browser reads, not code — so the only thing
// that can go wrong is shape: a file that will not parse, or one missing a
// member an install prompt requires, is silently non-installable and no other
// test in this suite would notice. This reads the real file from disk (not a
// fixture) and checks exactly the members installability depends on. cwd is the
// package root under vitest, and public/ ships verbatim from there.
const manifestPath = resolve(process.cwd(), "public/manifest.webmanifest");

function readManifest(): unknown {
  return JSON.parse(readFileSync(manifestPath, "utf8"));
}

describe("web app manifest", () => {
  it("is valid JSON that parses to an object", () => {
    const manifest = readManifest();
    expect(typeof manifest).toBe("object");
    expect(manifest).not.toBeNull();
  });

  it("names the app Keyhole with a short_name that fits under a home-screen icon", () => {
    const manifest = readManifest() as Record<string, unknown>;
    expect(manifest.name).toBe("Keyhole");
    expect(typeof manifest.short_name).toBe("string");
    expect((manifest.short_name as string).length).toBeGreaterThan(0);
    // A short_name over ~12 chars is truncated by launchers; keep it honest.
    expect((manifest.short_name as string).length).toBeLessThanOrEqual(12);
  });

  it("declares start_url '/' so the installed app opens at the vault root", () => {
    const manifest = readManifest() as Record<string, unknown>;
    expect(manifest.start_url).toBe("/");
  });

  it("declares display 'standalone' so it launches without browser chrome", () => {
    const manifest = readManifest() as Record<string, unknown>;
    expect(manifest.display).toBe("standalone");
  });

  it("carries theme_color and background_color as hex colours", () => {
    const manifest = readManifest() as Record<string, unknown>;
    const hex = /^#[0-9a-fA-F]{6}$/;
    expect(manifest.theme_color).toMatch(hex);
    expect(manifest.background_color).toMatch(hex);
  });

  it("carries well-formed icons at 192 and 512 including a maskable one", () => {
    const manifest = readManifest() as Record<string, unknown>;
    const icons = manifest.icons;
    // Without an icons array the OS has nothing to place on the home screen and
    // the install prompt is suppressed. This is the member the mutation removes.
    expect(Array.isArray(icons)).toBe(true);
    const list = icons as Array<Record<string, unknown>>;
    expect(list.length).toBeGreaterThan(0);

    for (const icon of list) {
      expect(typeof icon.src).toBe("string");
      expect((icon.src as string).length).toBeGreaterThan(0);
      expect(typeof icon.sizes).toBe("string");
      expect(icon.type).toBe("image/png");
    }

    const sizes = list.map((icon) => icon.sizes);
    expect(sizes).toContain("192x192");
    expect(sizes).toContain("512x512");

    const purposes = list.flatMap((icon) =>
      typeof icon.purpose === "string" ? icon.purpose.split(/\s+/) : [],
    );
    expect(purposes).toContain("maskable");
  });
});
