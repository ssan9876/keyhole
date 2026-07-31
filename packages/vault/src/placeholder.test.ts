import { expect, it } from "vitest";
import { PACKAGE_NAME } from "./index.js";

it("resolves the package entry point", () => {
  expect(PACKAGE_NAME).toBe("@keyhole/vault");
});
