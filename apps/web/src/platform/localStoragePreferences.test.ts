import { beforeEach, describe, expect, it } from "vitest";
import { localStoragePreferences } from "./localStoragePreferences.js";

describe("localStoragePreferences", () => {
  beforeEach(() => localStorage.clear());

  it("writes through to localStorage", () => {
    localStoragePreferences().set("k", "v");
    expect(localStorage.getItem("k")).toBe("v");
  });

  it("reads through from localStorage", () => {
    localStorage.setItem("k", "v");
    expect(localStoragePreferences().get("k")).toBe("v");
  });

  it("reports null for an absent key", () => {
    expect(localStoragePreferences().get("nope")).toBeNull();
  });

  it("removes", () => {
    localStorage.setItem("k", "v");
    localStoragePreferences().remove("k");
    expect(localStorage.getItem("k")).toBeNull();
  });
});
