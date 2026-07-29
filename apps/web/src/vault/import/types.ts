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
 * with no record that it ever existed. `folderPath` and `extra` are the two
 * places that surplus lives.
 *
 * Nothing here holds key material and nothing here is encrypted; this is the
 * user's plaintext vault sitting in memory, which is why the flow ends by
 * telling them to delete the export file.
 */

/** Which of Keyhole's two item kinds a row became. */
export type ImportItemType = "login" | "note";

/**
 * What an `extra` entry *is*, as distinct from what its export called it.
 *
 * **Settled here on purpose, because seven parsers write into `extra`.** Left to
 * the name alone, one TOTP secret arrives as `OTPAuth` from Safari, `totp` from
 * Bitwarden's JSON, `login_totp` from its CSV, `otpSecret` from Dashlane and
 * `totp` from LastPass — five spellings of one thing, and `map.ts` and the
 * preview screen would need a growing table of them to tell a second factor from
 * a card number.
 *
 * **A parser sets `kind` from where in the file it found the value, never by
 * matching the label.** The distinction is not academic: Bitwarden puts the real
 * TOTP seed at `login.totp` *and* lets a user create a custom field they happen
 * to name "totp". The first is a second factor, the second is something the user
 * typed, and a name-matching rule calls them the same thing — then the preview
 * screen tells the user something false about both. Where the value sat in the
 * file is evidence; what it was called is a label.
 *
 * Keep this list short. A kind earns its place by changing what something
 * downstream *does*, not by describing the data more finely.
 */
export type ImportFieldKind =
  /** A one-time-password secret: a bare base32 seed or a whole `otpauth://` URI. */
  | "totp"
  /** A field the user made themselves, under a name they chose. */
  | "custom"
  /**
   * The exporter's own record-keeping, which Keyhole has no setting for:
   * Bitwarden's `reprompt` and `collectionIds`, Firefox's `httpRealm`. Kept
   * because dropping it silently is still dropping it, and separated from
   * `custom` so the preview screen can say it differently — nobody typed these,
   * and a warning about losing them should not read like a warning about losing
   * the user's own notes.
   */
  | "metadata";

/**
 * One thing the export carried that Keyhole has no field for.
 *
 * **A list of named fields, not a `Record<string, string>` keyed by name.** Two
 * of these can legitimately share a name and mean different things: Bitwarden's
 * `fields[]` is an array of `{name, value, type}` and nothing stops a user
 * having two custom fields called "PIN"; LastPass's and NordPass's custom
 * columns are the same. A record would keep one of them — the shape that exists
 * to stop information going missing would be where it went missing.
 */
export interface ImportField {
  /**
   * The source's own spelling of the name: Safari's `OTPAuth`, Bitwarden's
   * `reprompt`, the name the user gave their own field.
   *
   * This is the **display label**, and it is kept exactly as the file wrote it
   * because it is what the user will recognise. Nothing downstream should branch
   * on it; that is what `kind` is for.
   */
  name: string;
  value: string;
  /** What this field is. See `ImportFieldKind`. */
  kind: ImportFieldKind;
}

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
   * The folder the export placed this item in, as path segments from the root.
   *
   * **Segments rather than a string, because there is no one separator.**
   * Bitwarden nests with `/` and stores `Work/Servers` as one folder name;
   * LastPass's `grouping` uses `\`; KeePassXC exports `Root/Personal`. Five
   * parsers writing five conventions into one string leaves `map.ts` guessing
   * which one a given name used, and the cost of guessing wrong is a folder
   * literally named `Personal\Forums`. Splitting at the parser — the one place
   * that knows what its own format meant by that character — removes the
   * question rather than documenting an answer nobody reads. Use
   * `folderSegments`.
   *
   * `[]` is the export placing the item at the root. No segment is ever `""`:
   * an empty one comes from punctuation (a leading, trailing or doubled
   * separator), never from a folder, and passing one on would have `map.ts`
   * create a folder with no name.
   *
   * A Keyhole item carries a `folderId`, which is an id in this user's vault and
   * something no export can possibly know. Resolving these names to an id (or
   * creating the folders) is the mapper's job; carrying the names this far is
   * what makes that possible at all.
   */
  folderPath: string[];
  /**
   * Whatever the source carried that Keyhole has no home for: TOTP seeds,
   * custom fields, card numbers, "reprompt" flags.
   *
   * Dropping these silently loses data the user believes they moved. Keeping
   * them lets the mapper append them to the note and lets the preview screen
   * say what will not survive.
   *
   * In the source's own order, and one entry per thing the source carried —
   * never merged by name. See `ImportField`.
   */
  extra: ImportField[];
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
    folderPath: [],
    extra: [],
    sourceRow,
  };
}

/**
 * A folder path split at `separator`, with empty segments dropped.
 *
 * The one place a parser should turn its export's folder string into the
 * segments `folderPath` wants, so that "what does this format use to nest?" is
 * answered once per format, in the parser, rather than left for `map.ts` to
 * infer from a string that no longer says.
 *
 * **Nothing is trimmed.** A folder called `" Work "` is a folder called
 * `" Work "`, and deciding otherwise is this layer inventing a rename. Empty
 * segments are dropped because a leading, trailing or doubled separator is
 * punctuation rather than a folder with no name.
 */
export function folderSegments(path: string, separator: string): string[] {
  return path.split(separator).filter((segment) => segment !== "");
}
