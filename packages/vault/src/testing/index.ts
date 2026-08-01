/**
 * Test-only helpers, kept out of `src/index.ts`'s barrel and exported through
 * their own `@keyhole/vault/testing` subpath instead.
 *
 * These modules reach into `node:fs`, `node:path`, and `node:zlib` — fine for
 * a test run under Node, fatal for the MV3 service worker this package is
 * also shipped into. A wildcard export from the main barrel would pull one of
 * them into the extension build and fail on a `node:zlib` resolution the
 * bundler cannot satisfy. Living under a separate subpath keeps that failure
 * from ever being reachable by accident.
 */
export * from "./test-helpers.js";
export * from "./fixture.js";
export * from "./zip-fixture.js";
