/**
 * The intermediate shape every importer produces.
 *
 * Each format is a pure function from file text to `ImportResult`, so adding a
 * password manager is a parser plus a detection signature rather than a branch
 * in a growing conditional, and everything downstream — duplicate detection,
 * the preview screen, the encrypt-and-upload step — is written once.
 *
 * This is deliberately *not* `ItemPlaintext` from `@keyhole/crypto`. It is
 * convertible to one, and `map.ts` does that conversion, but it is a wider
 * shape on purpose: an export carries things Keyhole has no field for, and the
 * moment the parser is forced into Keyhole's shape that information is gone
 * with no record that it ever existed. `folderName` and `extra` are the two
 * places that surplus lives.
 *
 * Nothing here holds key material and nothing here is encrypted; this is the
 * user's plaintext vault sitting in memory, which is why the flow ends by
 * telling them to delete the export file.
 */

/** Which of Keyhole's two item kinds a row became. */
export type ImportItemType = "login" | "note";

/** One row of an export, in Keyhole's vocabulary but not yet its shape. */
export interface ImportItem {
  /**
   * Flat rather than a discriminated union, unlike `ItemPlaintext`. A CSV row's
   * kind is a value read at runtime from a column, so a union would make every
   * parser branch before it can fill in a single field — and a note row in a
   * Bitwarden export still carries the (empty) login columns. `map.ts` narrows
   * once, at the boundary, instead of seven parsers narrowing separately.
   */
  type: ImportItemType;
  name: string;
  username: string;
  password: string;
  urls: string[];
  notes: string;
  favorite: boolean;
  /**
   * The folder's *name*, as the export wrote it.
   *
   * A Keyhole item carries a `folderId`, which is an id in this user's vault
   * and something no export can possibly know. Resolving the name to an id (or
   * creating the folder) is the mapper's job; carrying the name this far is
   * what makes that possible at all. `null` means the export placed the item at
   * the root — distinct from `""`, which would be a folder actually named "".
   */
  folderName: string | null;
  /**
   * Whatever the source carried that Keyhole has no home for, keyed by the
   * source's own column or property name: TOTP seeds, custom fields, card
   * numbers, "reprompt" flags.
   *
   * Dropping these silently loses data the user believes they moved. Keeping
   * them lets the mapper append them to the note and lets the preview screen
   * say what will not survive.
   */
  extra: Record<string, string>;
  /**
   * 1-based line in the source file this row came from, so an error can name a
   * line the user can actually find in their own file.
   */
  sourceRow: number;
}

/**
 * One row that could not be turned into an item.
 *
 * Spec §7: rows are all-or-nothing individually, with a per-row error report. A
 * parser never throws for a bad row — it returns the error alongside the rows
 * that did parse, so one malformed line cannot cost the user the other 399 and
 * cannot produce a half-encrypted record.
 */
export interface ImportRowError {
  /** 1-based line in the source file. */
  row: number;
  message: string;
}

/** What a parser returns: the rows that worked, and the rows that did not. */
export interface ImportResult {
  items: ImportItem[];
  errors: ImportRowError[];
}

/**
 * An item with every field empty, for a parser to fill in from its export.
 *
 * The defaults are stated once here rather than seven times across the parsers,
 * where they would drift.
 */
export function blankImportItem(sourceRow: number): ImportItem {
  return {
    type: "login",
    name: "",
    username: "",
    password: "",
    urls: [],
    notes: "",
    favorite: false,
    folderName: null,
    extra: {},
    sourceRow,
  };
}
