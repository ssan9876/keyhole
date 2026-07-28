import { parseCsv } from "./csv.js";

/**
 * Which password manager an export came from, and which parser reads it.
 *
 * Detection is header-signature based: the shape of the file decides, and the
 * filename is consulted only where the shape genuinely cannot tell (see
 * `chromium-csv` below). Nothing here reads a password — it reads column names
 * and JSON keys — but it runs on the user's whole plaintext vault, so it never
 * throws: an unrecognised file is a `generic-csv` answer, not an exception.
 *
 * **Parser and vendor are deliberately two fields, not one id.** They have
 * different cardinalities in both directions:
 *
 * - five vendors share one parser — Chrome, Edge, Brave, Safari and Firefox all
 *   export a `url, username, password` CSV, and folding them into five format
 *   ids would mean five copies of one parser;
 * - one vendor spans two parsers — a Bitwarden `.json` and a Bitwarden `.csv`
 *   are the same product and completely different code.
 *
 * A single id would have to pick one of those to be wrong about. The parser is
 * what the *program* branches on; the vendor is what the *user* is told. Keeping
 * them apart is also what lets detection answer honestly when it knows the
 * parser but cannot name the product.
 */

/** Which parser will read the file. The only field the import flow branches on. */
export type ImportParser =
  /** Chrome, Edge, Brave, Firefox and Safari: one parser, three column layouts. */
  | "browser-csv"
  | "bitwarden-csv"
  | "bitwarden-json"
  | "lastpass-csv"
  | "onepassword-csv"
  | "onepassword-1pux"
  /** KeePass 2's "KeePass CSV (1.x)" export and KeePassXC's own CSV. */
  | "keepass-csv"
  | "nordpass-csv"
  | "dashlane-csv"
  | "dashlane-json"
  | "protonpass-json"
  | "keeper-json"
  /**
   * The fallback, and the reason detection never fails. A manager nobody
   * anticipated still reaches the column-mapping screen, which is the whole
   * point: a dead end at the front door is the worst outcome for an import.
   */
  | "generic-csv";

/** Which product the export came from. Shown to the user; never branched on. */
export type ImportVendor =
  | "bitwarden"
  | "lastpass"
  | "onepassword"
  | "chrome"
  | "edge"
  | "brave"
  | "firefox"
  | "safari"
  | "keepass"
  | "keepassxc"
  | "nordpass"
  | "dashlane"
  | "protonpass"
  | "keeper";

export interface DetectedFormat {
  parser: ImportParser;
  /**
   * Every vendor whose export is consistent with this file, and there is no
   * separate "the" vendor field on purpose.
   *
   * - **one** entry: the evidence names a product.
   * - **more than one**: the products are indistinguishable from this file, and
   *   the honest answer is all of them. Chrome, Edge and Brave share Chromium's
   *   exporter and emit byte-identical CSVs; only the download's filename can
   *   separate them, and a user who renamed the file has erased that. A single
   *   `vendor` field would have to guess here, and a caller reading it would
   *   never learn that a guess had happened.
   * - **empty**: nothing recognised the file. `parser` is `"generic-csv"`.
   */
  vendors: readonly ImportVendor[];
}

/** Names the rule that fired, so a test can address one signature at a time. */
export type FormatSignatureId =
  | "bitwarden-json"
  | "protonpass-json"
  | "dashlane-json"
  | "keeper-json"
  | "onepassword-1pux"
  | "bitwarden-csv"
  | "lastpass-csv"
  | "chromium-csv"
  | "firefox-csv"
  | "safari-csv"
  | "onepassword-csv"
  | "keepassxc-csv"
  | "keepass-csv"
  | "nordpass-csv"
  | "dashlane-csv";

/**
 * A file reduced to the things a signature asks about, computed once.
 *
 * Public because the cross-check test runs all fifteen signatures against every
 * fixture, and re-deriving this per signature would mean fifteen `JSON.parse`
 * calls on a multi-megabyte export. `detect` does the same thing once.
 */
export interface FileEvidence {
  /** The name as given, with any directory part removed. */
  readonly filename: string;
  /** `filename` lowercased, which is the only form the matchers look at. */
  readonly lowerFilename: string;
  readonly content: string;
  /**
   * The CSV header row, lowercased and trimmed. Empty when the file has no
   * parsable first record — including when it is JSON, which is harmless: no
   * CSV signature matches an empty header.
   */
  readonly csvHeader: readonly string[];
  /** The parsed JSON body, or `undefined` when the file is not JSON. */
  readonly json: unknown;
}

/**
 * How much of the file to hand the CSV reader when looking for the header.
 *
 * The header is the first record, so reading a 40 MB export in full to find it
 * would be pure waste. 8 KiB is far more than any real header line — NordPass's,
 * the widest here, is 190 characters — and a truncation mid-record cannot throw,
 * because the reader reports a damaged record rather than raising.
 */
const HEADER_PROBE_LIMIT = 8192;

/**
 * The four bytes every ZIP archive starts with, and a `.1pux` is a ZIP.
 *
 * Spelled as escapes because two of the four are control characters, which do
 * not survive being written into a source file as literals. All four are below
 * U+0080, so a file read as UTF-8 yields exactly these code points however
 * mangled the rest of the archive looks when decoded as text.
 */
const ZIP_MAGIC = "PK\u0003\u0004";

function basename(filename: string): string {
  const cut = Math.max(filename.lastIndexOf("/"), filename.lastIndexOf("\\"));
  return cut === -1 ? filename : filename.slice(cut + 1);
}

function parseJsonBody(content: string): unknown {
  const trimmed = content.trimStart();
  // Attempting JSON.parse on every upload would mean parse-failing on every CSV,
  // which is merely wasteful; checking the first character keeps it cheap and
  // costs nothing in accuracy, since a JSON export's root is an object.
  if (!trimmed.startsWith("{")) return undefined;
  try {
    return JSON.parse(trimmed) as unknown;
  } catch {
    // A truncated or hand-edited JSON export is a file we cannot name, not an
    // error to raise here. It falls through to the generic CSV mapper.
    return undefined;
  }
}

/** Reduces a file to the evidence the signatures read. Never throws. */
export function probe(filename: string, content: string): FileEvidence {
  const name = basename(filename);
  const header = parseCsv(content.slice(0, HEADER_PROBE_LIMIT)).header;
  return {
    filename: name,
    lowerFilename: name.toLowerCase(),
    content,
    csvHeader: header.map((column) => column.trim().toLowerCase()),
    json: parseJsonBody(content),
  };
}

/** True when the header carries every one of `columns`, in any order. */
function hasColumns(file: FileEvidence, ...columns: string[]): boolean {
  return columns.every((column) => file.csvHeader.includes(column));
}

/**
 * True when the header is exactly `columns`, in order and with nothing else.
 *
 * The strict form exists for the browser CSVs, whose columns are a subset of
 * several richer exports: NordPass's header also opens `name,url,...,password,
 * note`, and `hasColumns` would call a NordPass export a Chrome one.
 */
function headerIs(file: FileEvidence, ...columns: string[]): boolean {
  return (
    file.csvHeader.length === columns.length &&
    columns.every((column, at) => file.csvHeader[at] === column)
  );
}

function asObject(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function hasArray(value: unknown, key: string): boolean {
  const object = asObject(value);
  return object !== null && Array.isArray(object[key]);
}

export interface FormatSignature {
  readonly id: FormatSignatureId;
  readonly parser: ImportParser;
  /**
   * The vendors this file could have come from, or `null` when the signature
   * does not recognise it.
   *
   * Returning the vendor list from the *match* rather than declaring it on the
   * signature is what keeps Chrome, Edge and Brave inside a single rule. Three
   * filename-keyed signatures would all fire on one file — the header rule and
   * the filename rule both matching — and "exactly one signature matches" is the
   * invariant that catches an over-broad signature.
   */
  match(file: FileEvidence): readonly ImportVendor[] | null;
}

const BITWARDEN: readonly ImportVendor[] = ["bitwarden"];
const CHROMIUM_FAMILY: readonly ImportVendor[] = ["chrome", "edge", "brave"];

/**
 * Dashlane's JSON export is one array per record kind, keyed in capitals.
 * A vault with no logins has no `AUTHENTIFIANT`, so any one of these is enough.
 */
const DASHLANE_JSON_KEYS = [
  "AUTHENTIFIANT",
  "SECURENOTE",
  "ADDRESS",
  "BANKSTATEMENT",
  "IDCARD",
  "IDENTITY",
  "PAYMENTMEANS_CREDITCARD",
  "PAYMENTMEAN_PAYPAL",
  "EMAIL",
];

/**
 * Every rule, most specific first.
 *
 * Order decides `detect`'s answer only if two rules can fire on one file, and
 * the cross-check suite exists to prove none can. It is ordered anyway so that a
 * rule broadened by accident produces a wrong answer somewhere a test looks,
 * rather than being masked by whichever rule happened to run first.
 */
export const FORMAT_SIGNATURES: readonly FormatSignature[] = [
  {
    id: "bitwarden-json",
    parser: "bitwarden-json",
    match: (file) =>
      hasArray(file.json, "items") &&
      (hasArray(file.json, "folders") ||
        hasArray(file.json, "collections") ||
        asObject(file.json)?.["encrypted"] !== undefined)
        ? BITWARDEN
        : null,
  },
  {
    id: "protonpass-json",
    parser: "protonpass-json",
    match: (file) => {
      const root = asObject(file.json);
      // `vaults` is a map keyed by vault id, not an array — the distinction
      // matters, because it is what separates this from a Bitwarden export,
      // which also carries `encrypted`.
      return root !== null &&
        asObject(root["vaults"]) !== null &&
        root["encrypted"] !== undefined
        ? ["protonpass"]
        : null;
    },
  },
  {
    id: "dashlane-json",
    parser: "dashlane-json",
    match: (file) =>
      DASHLANE_JSON_KEYS.some((key) => hasArray(file.json, key)) ? ["dashlane"] : null,
  },
  {
    id: "keeper-json",
    parser: "keeper-json",
    match: (file) =>
      hasArray(file.json, "records") && hasArray(file.json, "shared_folders")
        ? ["keeper"]
        : null,
  },
  {
    id: "onepassword-1pux",
    parser: "onepassword-1pux",
    // A `.1pux` is a ZIP holding `export.data`. Both halves are checked: the
    // extension alone would accept a renamed CSV, and the ZIP magic alone would
    // swallow Dashlane's and Proton Pass's exports, which are also ZIPs.
    match: (file) =>
      file.lowerFilename.endsWith(".1pux") && file.content.startsWith(ZIP_MAGIC)
        ? ["onepassword"]
        : null,
  },
  {
    id: "bitwarden-csv",
    parser: "bitwarden-csv",
    match: (file) =>
      hasColumns(file, "login_uri", "login_username", "login_password", "reprompt")
        ? BITWARDEN
        : null,
  },
  {
    id: "lastpass-csv",
    parser: "lastpass-csv",
    // `grouping` (the folder) and `extra` (the note) together are LastPass's
    // fingerprint; `url`/`username`/`password` alone are half the formats here.
    match: (file) =>
      hasColumns(file, "grouping", "extra", "url", "username", "password")
        ? ["lastpass"]
        : null,
  },
  {
    id: "chromium-csv",
    parser: "browser-csv",
    match: (file) => {
      // Chrome added `note` around 2023; older exports stop at `password`.
      const chromium =
        headerIs(file, "name", "url", "username", "password", "note") ||
        headerIs(file, "name", "url", "username", "password");
      if (!chromium) return null;
      // Edge and Brave ship Chromium's exporter unchanged, so the bytes are
      // identical and the download's name is the only remaining evidence. When
      // it has been renamed there is nothing left to distinguish them, and the
      // answer is all three rather than the most popular one.
      if (file.lowerFilename.includes("edge")) return ["edge"];
      if (file.lowerFilename.includes("brave")) return ["brave"];
      if (file.lowerFilename.includes("chrome")) return ["chrome"];
      return CHROMIUM_FAMILY;
    },
  },
  {
    id: "firefox-csv",
    parser: "browser-csv",
    match: (file) =>
      hasColumns(file, "url", "username", "password", "httprealm", "formactionorigin", "guid")
        ? ["firefox"]
        : null,
  },
  {
    id: "safari-csv",
    parser: "browser-csv",
    match: (file) =>
      headerIs(file, "title", "url", "username", "password", "notes", "otpauth") ||
      headerIs(file, "title", "url", "username", "password", "notes")
        ? ["safari"]
        : null,
  },
  {
    id: "onepassword-csv",
    parser: "onepassword-csv",
    // `archived` is the column no other export here has; without it this rule
    // and Safari's would both fire on a Safari file.
    match: (file) =>
      hasColumns(file, "title", "password", "otpauth", "archived", "tags")
        ? ["onepassword"]
        : null,
  },
  {
    id: "keepassxc-csv",
    parser: "keepass-csv",
    match: (file) =>
      hasColumns(file, "group", "title", "username", "password", "url", "notes", "totp")
        ? ["keepassxc"]
        : null,
  },
  {
    id: "keepass-csv",
    parser: "keepass-csv",
    // KeePass 2's "KeePass CSV (1.x)" export. Nothing is shared with KeePassXC's
    // column names, which is why one parser needs two signatures and the vendor
    // is what tells it which column map to use.
    match: (file) =>
      headerIs(file, "account", "login name", "password", "web site", "comments")
        ? ["keepass"]
        : null,
  },
  {
    id: "nordpass-csv",
    parser: "nordpass-csv",
    // NordPass writes one row shape for logins, cards and addresses alike, so
    // the card columns are present in every export and are its fingerprint.
    match: (file) =>
      hasColumns(file, "name", "url", "username", "password", "cardholdername", "cvc", "folder")
        ? ["nordpass"]
        : null,
  },
  {
    id: "dashlane-csv",
    parser: "dashlane-csv",
    match: (file) =>
      hasColumns(file, "title", "password", "url", "otpsecret", "category")
        ? ["dashlane"]
        : null,
  },
];

/** What an unrecognised file gets: the generic mapper, and no vendor claim. */
const UNRECOGNISED: DetectedFormat = { parser: "generic-csv", vendors: [] };

/**
 * Names the format of `content`, using `filename` only where the bytes cannot
 * decide.
 *
 * Never throws and never fails. A file no signature claims is reported as
 * `generic-csv` with no vendors, which routes it to the manual column-mapping
 * screen — someone exporting from a manager that is not on this list should
 * still end up with their vault imported.
 */
export function detect(filename: string, content: string): DetectedFormat {
  const file = probe(filename, content);
  for (const signature of FORMAT_SIGNATURES) {
    const vendors = signature.match(file);
    if (vendors !== null) return { parser: signature.parser, vendors };
  }
  return UNRECOGNISED;
}
