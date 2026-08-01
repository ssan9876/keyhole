/**
 * The single entry point for the vault layer.
 *
 * Consumers — the web app today, the browser extension next — import from
 * `@keyhole/vault` and never reach into `src/` directly. That is what makes
 * the internal file layout changeable without touching a client.
 */
export * from "./account.js";
export * from "./admin.js";
export * from "./api.js";
export * from "./collections.js";
export * from "./directory.js";
export * from "./enroll.js";
export * from "./folders.js";
export * from "./generator.js";
export * from "./items.js";
export * from "./preferences.js";
export * from "./recover.js";
export * from "./session.js";
export * from "./store.js";
export * from "./types.js";
export * from "./unlock.js";

export * from "./import/csv.js";
export * from "./import/dedupe.js";
export * from "./import/detect.js";
export * from "./import/map.js";
export * from "./import/types.js";
export * from "./import/upload.js";
export * from "./import/zip.js";

// The bytes-vs-text parser split (see useImportPanel.ts) means the UI calls
// this one parser directly instead of through map.ts's text-only dispatch.
// Not part of the brief's literal barrel list — added because `.1pux` import
// breaks without it. Every other parser stays internal to `map.ts`.
export { parseOnePassword1pux } from "./import/parsers/onepassword.js";
