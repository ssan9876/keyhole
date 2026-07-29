import { describe, expect, it } from "vitest";
import { route } from "./route.js";

describe("route", () => {
  it("routes an /api data request to bypass so vault ciphertext is never cached", () => {
    expect(route({ url: "https://vault.example/api/sync" })).toBe("bypass");
  });

  it("routes an /api auth request to bypass because auth carries secrets too", () => {
    expect(route({ url: "https://vault.example/api/auth/login" })).toBe("bypass");
  });

  it("routes a hashed /assets file to cache-first because its name pins its content", () => {
    expect(route({ url: "https://vault.example/assets/index-AbC123.js" })).toBe("cache-first");
  });

  it("routes a navigation to network-first so a cold offline load still reaches the shell", () => {
    expect(route({ url: "https://vault.example/", mode: "navigate" })).toBe("network-first");
    expect(route({ url: "https://vault.example/enroll/x", mode: "navigate" })).toBe("network-first");
  });

  it("routes any other same-origin request to network without caching", () => {
    expect(route({ url: "https://vault.example/favicon.ico" })).toBe("network");
  });

  it("keeps /api on bypass even when it arrives as a navigation", () => {
    // Defence in depth: /api is checked before the navigation rule, so a crafted
    // navigation to an /api path can never fall through to a caching strategy.
    expect(route({ url: "https://vault.example/api/export", mode: "navigate" })).toBe("bypass");
  });
});
