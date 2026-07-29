import { useCallback, useMemo } from "react";
import type { ApiClient } from "../vault/api.js";
import type { Session } from "../vault/session.js";
import type { VaultStore } from "../vault/store.js";
import { parseCsv } from "../vault/import/csv.js";
import { detect } from "../vault/import/detect.js";
import { findDuplicates, existingFromRecords } from "../vault/import/dedupe.js";
import {
  MANUAL_FORMATS,
  parseText,
  suggestMapping,
  toItemPlaintexts,
  type CsvColumnMapping,
  type ManualFormat,
} from "../vault/import/map.js";
import { parseOnePassword1pux } from "../vault/import/parsers/onepassword.js";
import type { ImportResult } from "../vault/import/types.js";
import { uploadItems, type UploadOptions } from "../vault/import/upload.js";
import { useVaultState } from "./useVault.js";
import type {
  ImportRequest,
  ImportScreenProps,
  InspectResult,
  PreviewRequest,
  PreviewResult,
  PreviewRow,
} from "./screens/ImportScreen.js";

/**
 * The import controller: the bytes-vs-text seam, the parse, the duplicate
 * report, and the encrypt-and-upload, kept out of the screen for the same
 * reason the last four panels are — the screen stays presentational and this
 * holds everything that touches the file, the vault, and the network.
 *
 * Returns exactly the props `ImportScreen` needs, so a caller renders it as
 * `<ImportScreen {...useImportPanel({ api, session, store })} />`.
 *
 * ## The seam that decides whether a real import works
 *
 * `detect` reads text and most parsers read text, but `parseOnePassword1pux`
 * reads *bytes*: a `.1pux` is a ZIP, and decoding a ZIP as UTF-8 replaces most
 * of its header bytes and produces a string that can never be turned back into
 * the archive. So the file is read once as an `ArrayBuffer` and kept as bytes;
 * text is derived from those bytes only for the formats that want it, and the
 * `.1pux` path is handed the bytes untouched. `parseFile` below is the one place
 * that branch lives, and `parseText`'s type deliberately excludes the async
 * `.1pux` path so the compiler enforces the split rather than a comment asking
 * for it.
 */
export function useImportPanel({
  api,
  session,
  store,
}: {
  api: ApiClient;
  session: Session;
  store: VaultStore;
}): ImportScreenProps {
  const state = useVaultState(store);

  // Only collections this device holds a key for: importing into one whose key
  // is missing would fail every item, and `uploadItems` refuses it up front.
  const collections = useMemo(
    () =>
      state.collections
        .filter((collection) => collection.usable)
        .map((collection) => ({ id: collection.id, name: collection.name })),
    [state.collections],
  );

  const onInspect = useCallback(async (file: File): Promise<InspectResult> => {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const text = decodeText(bytes);
    const detected = detect(file.name, text);
    // The raw header, in the file's own spelling, for the generic column
    // mapper. Only the first record is needed, so this reads a slice rather
    // than a multi-megabyte export in full — the same bound `detect` uses.
    const header = parseCsv(text.slice(0, HEADER_PROBE_LIMIT)).header;
    return {
      filename: file.name,
      // `ImportParser` is a subset of `ManualFormat`, so detection's answer is
      // already a valid choice for the picker.
      format: detected.parser,
      vendors: detected.vendors,
      header,
      suggestedMapping: suggestMapping(header),
    };
  }, []);

  const onPreview = useCallback(
    async (input: PreviewRequest): Promise<PreviewResult> => {
      const result = await parseFile(input.file, input.format, input.mapping);
      // Against the vault as it stands on this device, not only within the
      // file: re-importing the same export, or importing after adding a login
      // by hand, are the two ordinary ways to end up with duplicates and
      // neither shows up in a file compared against itself.
      const existing = existingFromRecords(store.getState().items);
      const duplicates = findDuplicates(result.items, existing);
      return {
        rows: result.items.map(toPreviewRow),
        errors: result.errors,
        duplicates,
      };
    },
    [store],
  );

  const onImport = useCallback(
    async (input: ImportRequest) => {
      const result = await parseFile(input.file, input.format, input.mapping);
      const skip = new Set(input.skipRows);
      // Parsing is deterministic, so re-parsing here yields the same items in
      // the same order the preview reported, and the skip indices still name
      // the rows the user chose. Filtering rather than re-deriving keeps the
      // rows the user decided about exactly the rows that are excluded.
      const kept = result.items.filter((_item, index) => !skip.has(index));
      const plaintexts = toItemPlaintexts(kept, { folderId: null });
      // Built conditionally rather than with `onProgress: input.onProgress`,
      // because `exactOptionalPropertyTypes` refuses an explicit `undefined`
      // where the option is optional.
      const options: UploadOptions = { collectionId: input.collectionId };
      if (input.onProgress !== undefined) options.onProgress = input.onProgress;
      const outcome = await uploadItems({ api, session }, plaintexts, options);
      // Best-effort, exactly as the collections panel resyncs after a change:
      // the items already landed on the server, so a blipped resync must not
      // read as a failed import. They simply appear at the next successful sync
      // (a tab focus, or the reload the completion screen invites).
      await store.resync({ api, session }).catch(() => undefined);
      return outcome;
    },
    [api, session, store],
  );

  return { formats: MANUAL_FORMATS, collections, onInspect, onPreview, onImport };
}

/**
 * How much of the file to read to find a CSV header. Matches `detect`'s own
 * bound: a header line is never more than a few hundred bytes, so reading a
 * whole export to find it would be pure waste.
 */
const HEADER_PROBE_LIMIT = 8192;

/** A file's bytes as text, for the formats that read text. Never throws. */
function decodeText(bytes: Uint8Array): string {
  // Not `fatal`: detection runs this on every upload, including a `.1pux` whose
  // bytes are a ZIP, and a decode that threw on the archive would take out the
  // one thing detection needs from it — the `PK` magic, which is
  // ASCII and survives a lossy decode intact. The `.1pux` is never *parsed*
  // from this text; `parseFile` hands its parser the bytes.
  return new TextDecoder().decode(bytes);
}

/**
 * The one place the bytes-vs-text branch lives.
 *
 * The `.1pux` parser is handed the bytes; every other format is handed text
 * decoded from those same bytes. `parseText`'s parameter excludes
 * `"onepassword-1pux"`, so after the guard below the compiler knows `format` is
 * a text format — the split is enforced, not merely documented.
 */
async function parseFile(
  file: File,
  format: ManualFormat,
  mapping: CsvColumnMapping | null,
): Promise<ImportResult> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (format === "onepassword-1pux") {
    return parseOnePassword1pux(bytes);
  }
  const text = decodeText(bytes);
  if (format === "generic-csv" && mapping !== null) {
    const header = parseCsv(text.slice(0, HEADER_PROBE_LIMIT)).header;
    return parseText("generic-csv", text, normalizeMapping(mapping, header));
  }
  return parseText(format, text);
}

/**
 * Recomputes which columns become custom fields from the header and the user's
 * choices, so a column the user moved off a field is not both a mapped field
 * and a note line.
 *
 * `suggestMapping` fills `custom` for its *suggested* selections; the moment the
 * user picks a different password column, that suggestion is stale. Every
 * column the user did not place is carried into the note, matching
 * `suggestMapping`'s rule that a column dropped because nothing recognised it is
 * still a column dropped.
 */
function normalizeMapping(mapping: CsvColumnMapping, header: readonly string[]): CsvColumnMapping {
  const placed = new Set(
    [
      mapping.name,
      mapping.username,
      mapping.password,
      mapping.url,
      mapping.notes,
      mapping.folder,
      mapping.totp,
    ]
      .filter((column): column is string => column !== null)
      .map((column) => column.trim().toLowerCase()),
  );

  const seen = new Set<string>();
  const custom: string[] = [];
  for (const cell of header) {
    const trimmed = cell.trim();
    const key = trimmed.toLowerCase();
    // First occurrence wins, as `suggestMapping` and `csv.ts` both do, and a
    // placed column is never carried a second time as a custom field.
    if (trimmed === "" || placed.has(key) || seen.has(key)) continue;
    seen.add(key);
    custom.push(trimmed);
  }

  return { ...mapping, custom };
}

/** The masked prefix a preview shows for a password, long enough to catch a
 *  column shift and short enough not to print the secret. */
const PASSWORD_PREVIEW_CHARS = 3;

/**
 * One parsed item as the preview renders it — display-safe, and never the whole
 * password.
 *
 * The password is shown as its first few characters only, which is what makes a
 * shifted column visible: a URL mapped into the password field reads as `htt…`,
 * where the whole value would be a shoulder-surfable secret and none of it
 * would say more about a mis-map than the prefix already does. Keeper's
 * header-less CSV has no other check, so this is the check.
 */
function toPreviewRow(item: ImportResult["items"][number], index: number): PreviewRow {
  const password = item.password;
  const passwordPreview =
    password.length > PASSWORD_PREVIEW_CHARS
      ? `${password.slice(0, PASSWORD_PREVIEW_CHARS)}…`
      : password;
  return {
    index,
    sourceRow: item.sourceRow,
    type: item.type,
    name: item.name,
    username: item.username,
    passwordPreview,
    urls: item.urls,
    // Everything that will be folded into the note instead of a field of its
    // own: the folder path, TOTP seeds, custom fields, exporter metadata.
    carriedCount: item.extra.length + (item.folderPath.length > 0 ? 1 : 0),
  };
}
