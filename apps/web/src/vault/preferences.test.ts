import { describe, expect, it } from "vitest";
import {
  AUTO_LOCK_STORAGE_KEY,
  EMAIL_STORAGE_KEY,
  createPreferences,
  type PreferenceStore,
} from "./preferences.js";

/** An in-memory PreferenceStore. The point of the interface is that these
 *  tests need no DOM at all — which is what makes the module movable. */
function fakeStore(initial: Record<string, string> = {}): PreferenceStore {
  const map = new Map(Object.entries(initial));
  return {
    get: (key) => map.get(key) ?? null,
    set: (key, value) => void map.set(key, value),
    remove: (key) => void map.delete(key),
  };
}

describe("email", () => {
  it("round-trips a remembered address", () => {
    const prefs = createPreferences(fakeStore());
    prefs.rememberEmail("a@b.c");
    expect(prefs.rememberedEmail()).toBe("a@b.c");
  });

  it("reports null when nothing is remembered", () => {
    expect(createPreferences(fakeStore()).rememberedEmail()).toBeNull();
  });

  it("forgets", () => {
    const prefs = createPreferences(fakeStore({ [EMAIL_STORAGE_KEY]: "a@b.c" }));
    prefs.forgetEmail();
    expect(prefs.rememberedEmail()).toBeNull();
  });
});

describe("auto-lock", () => {
  it("defaults to 15 when unset", () => {
    expect(createPreferences(fakeStore()).readAutoLock()).toBe(15);
  });

  it("reads a stored numeric setting as a number, not a string", () => {
    const prefs = createPreferences(fakeStore({ [AUTO_LOCK_STORAGE_KEY]: "30" }));
    expect(prefs.readAutoLock()).toBe(30);
  });

  it("reads a stored string setting", () => {
    const prefs = createPreferences(fakeStore({ [AUTO_LOCK_STORAGE_KEY]: "on-close" }));
    expect(prefs.readAutoLock()).toBe("on-close");
  });

  // Guards the existing behaviour: "0" would otherwise mean either a
  // zero-length timeout or an unbounded one depending on how it is read.
  it("falls back to the default for an unrecognised value", () => {
    const prefs = createPreferences(fakeStore({ [AUTO_LOCK_STORAGE_KEY]: "0" }));
    expect(prefs.readAutoLock()).toBe(15);
  });

  it("writes a setting as a string", () => {
    const store = fakeStore();
    createPreferences(store).writeAutoLock("never");
    expect(store.get(AUTO_LOCK_STORAGE_KEY)).toBe("never");
  });
});
