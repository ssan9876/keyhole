import { describe, expect, it } from "vitest";
import { inviteTokenFromPath } from "./App.js";

describe("inviteTokenFromPath", () => {
  it("extracts the token from a setup link", () => {
    // This is the shape keyhole admin create prints, so it is the shape a real
    // invite arrives in.
    expect(inviteTokenFromPath("/enroll/bgeu3hr9bRZJ6tHrG9iPcrOeInVFkZHiQvM")).toBe(
      "bgeu3hr9bRZJ6tHrG9iPcrOeInVFkZHiQvM",
    );
  });

  it("decodes a percent-encoded token", () => {
    expect(inviteTokenFromPath("/enroll/a%2Fb")).toBe("a/b");
  });

  it("returns null for every other path", () => {
    for (const path of ["/", "/vault", "/enroll", "/enroll/", "/enroll/a/b"]) {
      expect(inviteTokenFromPath(path)).toBeNull();
    }
  });
});
