import { parseCsv, type CsvRow } from "../csv.js";
import {
  blankImportItem,
  type ImportItem,
  type ImportItemType,
  type ImportResult,
  type ImportRowError,
} from "../types.js";
import { isZipProblem, openZip } from "../zip.js";
import {
  carry,
  indexColumns,
  isRowError,
  mapCsvRows,
  requiredPassword,
  surplusFieldsError,
  type Columns,
  type RowOutcome,
} from "./shared.js";

/**
 * 1Password's two exports: the `.1pux` archive and the CSV.
 *
 * **A `.1pux` is a ZIP holding `export.data`**, which is the JSON this file
 * maps. `zip.ts` opens the container — see its header for why that is the
 * engine's own `DecompressionStream` and not a dependency — and everything
 * below works on the text it hands back.
 *
 * The two exports are not two spellings of one file. The `.1pux` nests items
 * under accounts and vaults, keeps a login's username and password in a
 * `loginFields` array addressed by a `designation`, and puts the user's own
 * fields in `sections`. The CSV is one flat row per login with no vault column
 * at all. Nothing but the vendor is shared, so the mapping is written twice
 * rather than bent into one table.
 *
 * ## The contract (stated in full in the plan, Tasks 3-7)
 *
 * Returns the intermediate shape, never `ItemPlaintext`. **Never throws** — a
 * malformed item comes back as a per-row error beside the items that parsed,
 * and that includes a file that is not an archive, an archive with the wrong
 * member in it, and a member that is not JSON. **Never guesses at a password**:
 * absent, empty, or from a row the CSV reader flagged as damaged is an error
 * row, never an item with a blank password. **Preserves the password byte for
 * byte.**
 *
 * ## Why the `.1pux` path is the only asynchronous parser
 *
 * Every other parser here is a pure function from text to `ImportResult`.
 * `parseOnePassword1pux` returns a promise because inflating a ZIP member goes
 * through `DecompressionStream`, which is a stream and has no synchronous form.
 * `parseOnePasswordExportData` is the synchronous half — the whole mapping, on
 * the text — so the format's behaviour is testable without a container around
 * it, and only the unwrapping is asynchronous.
 *
 * ## What `sourceRow` means here, and why it differs between the two
 *
 * For the CSV it is the line, straight from the reader. **A `.1pux` has no
 * rows**, so it is the item's 1-based position counted across every vault of
 * every account in the order the export lists them, and every message opens
 * with `Item N ("the item's title")` so the number is never presented as a
 * line. A line number would need the byte offsets `JSON.parse` does not report.
 *
 * ## The CSV fixture is a reconstruction, and this parser is written for that
 *
 * `.superpowers/sdd/task-2-report.md` lists `1password-export.csv` among the
 * four fixtures whose header line could not be sourced from a real export:
 * 1Password's support page names the fields in prose but never quotes the
 * header, so `Url` vs `Website` and `OTPAuth` vs `One-time password` are that
 * task's reconstruction, and the *order* is a guess. Every lookup below is
 * therefore **by column name**, and the address column accepts more than one
 * spelling: against a wrong reconstruction a name lookup finds nothing and
 * produces a visible error row, where positional access would put a password
 * into the notes field of a real export and report nothing at all.
 */

/* -------------------------------------------------------------------------- */
/*                             Shared between both                            */
/* -------------------------------------------------------------------------- */

/**
 * Where a vault's name goes, and what does *not* happen to it.
 *
 * 1Password has vaults, and an item belongs to exactly one, so the vault name is
 * the only grouping the `.1pux` carries and it is what `folderPath` gets. A
 * vault does not nest, so its name is one whole segment and is never split:
 * choosing a separator anyway would turn a vault the user called `Home/Office`
 * into two folders that never existed.
 *
 * **Tags are not the folder, in either export.** An item can carry several, so
 * no one of them is "the" folder and picking the first would be a guess that
 * looked like a fact — the same reasoning `bitwarden.ts` applies to an
 * organisation export's `collectionIds`. They are carried instead, so the
 * preview screen can say the grouping is not coming across. This costs the CSV
 * path real structure, because a 1Password CSV has no vault column and tags are
 * the only grouping in the file; it is recorded in the task report as the
 * judgement it is.
 */
function vaultFolder(name: string): string[] {
  return name === "" ? [] : [name];
}

/* -------------------------------------------------------------------------- */
/*                                  The .1pux                                 */
/* -------------------------------------------------------------------------- */

/** The member of a `.1pux` archive that holds the vault. */
const EXPORT_DATA = "export.data";

/** 1Password's category ids that map onto one of Keyhole's two kinds. */
const CATEGORIES = new Map<string, ImportItemType>([
  ["001", "login"],
  ["003", "note"],
]);

/**
 * The categories Keyhole has no home for, and 1Password's own word for each.
 *
 * Named rather than skipped. "Imported 200 of 214" with the other 14 explained
 * is a count the user can act on; "imported 200" from a 214-item file is a
 * number they have no way to check, and the difference is exactly the kind of
 * loss that is discovered months later.
 *
 * `005` is 1Password's "Password" item — a saved password with no username,
 * which the browser extension creates when it generates one. It is listed here
 * rather than mapped to a login on purpose: it keeps its secret somewhere other
 * than `loginFields`, and a parser that guessed at where would be guessing at a
 * password. Naming it tells the user exactly what did not come across.
 */
const UNSUPPORTED = new Map<string, string>([
  ["002", "credit card"],
  ["004", "identity"],
  ["005", "password item"],
  ["006", "document"],
  ["100", "software license"],
  ["101", "bank account"],
  ["102", "database"],
  ["103", "driver license"],
  ["104", "outdoor license"],
  ["105", "membership"],
  ["106", "passport"],
  ["107", "rewards program"],
  ["108", "social security number"],
  ["109", "wireless router"],
  ["110", "server"],
  ["111", "email account"],
  ["112", "API credential"],
  ["113", "medical record"],
  ["115", "SSH key"],
]);

/** The `state` of an item 1Password has not archived. */
const ACTIVE = "active";

/** The `value` key a section field uses for a one-time-password secret. */
const TOTP_VALUE = "totp";

function asObject(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * A JSON string as itself, and anything else as `""`.
 *
 * Deliberately not a stringifier: `notesPlain` is absent on most items and
 * `String(undefined)` would put the word "undefined" in the user's vault.
 */
function stringOf(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/** A JSON scalar as text, for the fields where 1Password writes several types. */
function scalarText(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return "";
}

/**
 * The URLs of a login.
 *
 * **`overview.urls` is an array of objects with a `url` field**, not an array
 * of strings as Proton Pass writes. Reading the entries themselves gives
 * `[object Object]` for every URL of every multi-site login — a value that
 * looks like a string right up until somebody tries to visit it.
 *
 * `overview.url` is the primary address and is repeated inside `urls` on every
 * export seen so far; it is read only when `urls` yields nothing, so an
 * ordinary item does not arrive with the same address twice.
 */
function urlsOf(overview: Record<string, unknown> | null): string[] {
  const listed = overview?.["urls"];
  const urls: string[] = [];
  if (Array.isArray(listed)) {
    for (const entry of listed) {
      const url = asObject(entry)?.["url"];
      // An entry with no `url`, or a null one, is nothing to carry rather than
      // an empty string to carry: `[""]` downstream would make every URL-less
      // item a duplicate of every other, since duplicate detection compares
      // hosts.
      if (typeof url === "string" && url !== "") urls.push(url);
    }
  }
  if (urls.length > 0) return urls;
  const single = stringOf(overview?.["url"]);
  return single === "" ? [] : [single];
}

/** The first `loginFields` entry with the given designation, or `undefined`. */
function designated(fields: readonly unknown[], designation: string): string | undefined {
  for (const entry of fields) {
    const field = asObject(entry);
    if (field?.["designation"] === designation) {
      const value = field["value"];
      // Only a string counts. A number where a password belongs is a broken
      // export, and coercing it would invent a password that was never typed.
      return typeof value === "string" ? value : undefined;
    }
  }
  return undefined;
}

/**
 * Carries every `loginFields` entry that is neither the username nor the
 * password.
 *
 * 1Password records the whole sign-in form it filled, so this is where a second
 * password box or a memorable word ends up. Entries with an empty value — the
 * submit button, a checkbox nobody ticked — are dropped by `carry`, which is
 * what keeps the preview screen from warning about the loss of nothing on every
 * row.
 *
 * `custom` because the user typed it into a form, and never `totp`: a
 * `loginFields` entry is a form input, and 1Password keeps a real second factor
 * in a section field whose value is a `totp` — see `carrySections`.
 */
function carryOtherLoginFields(item: ImportItem, fields: readonly unknown[]): void {
  for (const entry of fields) {
    const field = asObject(entry);
    if (field === null) continue;
    const designation = stringOf(field["designation"]);
    if (designation === "username" || designation === "password") continue;
    const name = stringOf(field["name"]);
    carry(
      item,
      name === "" ? (designation === "" ? "(unnamed field)" : designation) : name,
      scalarText(field["value"]),
      "custom",
    );
  }
}

/**
 * Carries the user's own fields, which 1Password groups into sections.
 *
 * **The `kind` comes from the shape of the field's `value`, never from its
 * title.** A section field's value is an object with exactly one key naming its
 * type — `{"concealed": "…"}`, `{"string": "…"}`, `{"totp": "otpauth://…"}` —
 * and that key is 1Password's own discriminator, set by the app. It is where
 * the value sat, which is what `ImportFieldKind` requires the kind to come
 * from: a user can title a text field "totp", and the whole point of that rule
 * is that such a field is not a second factor.
 *
 * The name is qualified with the section's title when it has one, because a
 * section is what the user sees the field under and two sections can hold two
 * fields of the same name. A value that is not a scalar — 1Password's `address`
 * field is an object of its own — is not carried, because there is no honest
 * way to write one into a text field; those live on categories this parser
 * refuses by name anyway.
 */
function carrySections(item: ImportItem, sections: unknown): void {
  if (!Array.isArray(sections)) return;
  for (const entry of sections) {
    const section = asObject(entry);
    const fields = section?.["fields"];
    if (!Array.isArray(fields)) continue;
    const heading = stringOf(section?.["title"]);
    for (const rawField of fields) {
      const field = asObject(rawField);
      if (field === null) continue;
      const typed = asObject(field["value"]);
      const [type, value] = Object.entries(typed ?? {})[0] ?? [];
      if (type === undefined) continue;
      const title = stringOf(field["title"]);
      const name = title === "" ? "(unnamed field)" : title;
      carry(
        item,
        heading === "" ? name : `${heading} / ${name}`,
        scalarText(value),
        type === TOTP_VALUE ? "totp" : "custom",
      );
    }
  }
}

/** The overview's tags as one value, or `""` when there are none. */
function tagsText(overview: Record<string, unknown> | null): string {
  const tags = overview?.["tags"];
  if (!Array.isArray(tags)) return "";
  return tags.filter((tag): tag is string => typeof tag === "string" && tag !== "").join(", ");
}

/** One item of one vault, as an item or as the reason it is not one. */
function vaultItem(
  raw: unknown,
  vault: string,
  account: string,
  position: number,
): RowOutcome {
  const source = asObject(raw);
  if (source === null) {
    return { row: position, message: `Item ${position} is not an object, so it could not be read` };
  }

  const overview = asObject(source["overview"]);
  const name = stringOf(overview?.["title"]);
  // The title is what the user will recognise; the position is what makes two
  // items of the same title distinguishable. Both, because either alone leaves
  // a report the user cannot act on.
  const label = name === "" ? `Item ${position}` : `Item ${position} ("${name}")`;

  const category = stringOf(source["categoryUuid"]);
  const kind = CATEGORIES.get(category);
  if (kind === undefined) {
    const described =
      UNSUPPORTED.get(category) ??
      (category === "" ? "item of no stated category" : `item of category ${category}`);
    return {
      row: position,
      message:
        `${label} is a 1Password ${described}, which Keyhole cannot import yet, ` +
        "so it was not imported",
    };
  }

  const details = asObject(source["details"]);
  const item = blankImportItem(position);
  item.type = kind;
  item.name = name;
  item.notes = stringOf(details?.["notesPlain"]);
  // `favIndex` is a sort position rather than a flag: zero is "not a
  // favourite" and anything else is the order they appear in.
  item.favorite = typeof source["favIndex"] === "number" && source["favIndex"] !== 0;
  item.folderPath = vaultFolder(vault);

  if (kind === "login") {
    if (details === null) {
      return {
        row: position,
        message: `${label} is a login with no login details, so it was not imported`,
      };
    }
    const fields = Array.isArray(details["loginFields"]) ? details["loginFields"] : [];

    const password = designated(fields, "password");
    // Absent and empty are different answers and both are refusals: absent is a
    // damaged export, empty is 1Password saying there is no password here.
    // Neither is an item, because a blank imported over a real password cannot
    // be recovered from an export the user has been told to delete.
    if (password === undefined) {
      return { row: position, message: `${label} has no password, so it was not imported` };
    }
    if (password === "") {
      return { row: position, message: `${label} has an empty password, so it was not imported` };
    }

    item.username = designated(fields, "username") ?? "";
    // Byte for byte: the string `JSON.parse` produced and nothing else. A
    // trailing space is part of the password.
    item.password = password;
    item.urls = urlsOf(overview);
    carryOtherLoginFields(item, fields);
  }

  carrySections(item, details?.["sections"]);
  carry(item, "tags", tagsText(overview), "metadata");
  // An archived item was not deleted, so refusing it would lose something the
  // user deliberately kept. It is imported and the fact recorded, so the
  // preview screen can say so rather than the item arriving indistinguishable
  // from an active one.
  const state = stringOf(source["state"]);
  carry(item, "state", state === ACTIVE ? "" : state, "metadata");
  carry(item, "account", account, "metadata");

  return item;
}

/**
 * Reads a `.1pux`'s `export.data`. Never throws.
 *
 * Exported for the reason the header gives: it is the whole of the format's
 * mapping with none of the container, so every behaviour of this parser can be
 * tested against text rather than against bytes somebody had to build a ZIP for.
 */
export function parseOnePasswordExportData(text: string): ImportResult {
  let body: unknown;
  try {
    body = JSON.parse(text) as unknown;
  } catch {
    return {
      items: [],
      errors: [{ row: 1, message: "This file is not valid JSON, so nothing could be read from it" }],
    };
  }

  const accounts = asObject(body)?.["accounts"];
  if (!Array.isArray(accounts)) {
    return {
      items: [],
      errors: [
        { row: 1, message: "This file has no accounts array, so it is not a 1Password .1pux export" },
      ],
    };
  }

  // The account's name is carried only when there is more than one of them. A
  // single-account export writes the same value on every row, and a warning
  // that appears on every item of every ordinary import is a warning about
  // nothing. With two accounts it is the only thing separating two vaults that
  // are both called "Personal".
  const named = accounts.length > 1;
  const items: ImportItem[] = [];
  const errors: ImportRowError[] = [];
  let position = 0;

  for (const rawAccount of accounts) {
    const account = asObject(rawAccount);
    const accountName = named ? stringOf(asObject(account?.["attrs"])?.["name"]) : "";
    const vaults = account?.["vaults"];
    if (!Array.isArray(vaults)) continue;

    for (const rawVault of vaults) {
      const vault = asObject(rawVault);
      const vaultName = stringOf(asObject(vault?.["attrs"])?.["name"]);
      const contents = vault?.["items"];
      if (!Array.isArray(contents)) continue;

      for (const entry of contents) {
        position += 1;
        const outcome = vaultItem(entry, vaultName, accountName, position);
        if (isRowError(outcome)) {
          errors.push(outcome);
        } else {
          items.push(outcome);
        }
      }
    }
  }

  return { items, errors };
}

/**
 * Reads a `.1pux` archive. Never throws and never rejects.
 *
 * Takes bytes rather than text because a `.1pux` is a ZIP: decoding one as
 * UTF-8 replaces most of its headers and produces a string that can never be
 * turned back into the archive.
 *
 * A container problem is reported with the format named in front of it. The
 * sentences `zip.ts` writes are specific — "this archive has no export.data in
 * it; it holds credentials.csv, securenotes.csv" is exactly what a user who
 * renamed a Dashlane export needs to read — but on their own they never say
 * which format was expected.
 */
export async function parseOnePassword1pux(archive: Uint8Array): Promise<ImportResult> {
  const opened = openZip(archive);
  if (isZipProblem(opened)) return archiveProblem(opened.problem);

  const text = await opened.readText(EXPORT_DATA);
  if (isZipProblem(text)) return archiveProblem(text.problem);

  return parseOnePasswordExportData(text);
}

function archiveProblem(problem: string): ImportResult {
  return {
    items: [],
    errors: [
      { row: 1, message: `This file could not be read as a 1Password .1pux archive. ${problem}` },
    ],
  };
}

/* -------------------------------------------------------------------------- */
/*                                   The CSV                                  */
/* -------------------------------------------------------------------------- */

/** The CSV export's column names, lowercased as the header index holds them. */
const CSV_COLUMNS = {
  title: "title",
  username: "username",
  password: "password",
  otpauth: "otpauth",
  favorite: "favorite",
  archived: "archived",
  tags: "tags",
} as const;

/**
 * The spellings the address and note columns are accepted under.
 *
 * 1Password's own documentation calls the first field "Website" in prose while
 * the reconstruction guessed `Url`, and detection does not require either of
 * them — it keys on `title`, `password`, `otpauth`, `archived` and `tags` — so
 * a real export spelling this column the other way would reach this parser and
 * lose every URL. Accepting both costs a lookup and removes the guess.
 */
const ADDRESS_COLUMNS = ["url", "website", "urls"] as const;
const NOTE_COLUMNS = ["notes", "note"] as const;

/** The first of `names` the header actually has, or `null` for none of them. */
function firstNamed(columns: Columns, names: readonly string[]): string | null {
  return names.find((name) => columns.has(name)) ?? null;
}

/** 1Password writes `true` and `false` in the two flag columns. */
function isTrue(value: string | undefined): boolean {
  return value?.trim().toLowerCase() === "true";
}

/** The flag's own text when it is set, and `""` when it is not. */
function flagText(value: string | undefined): string {
  return isTrue(value) ? (value?.trim() ?? "") : "";
}

/** Where the layout's two variable columns turned out to be. */
interface CsvLayout {
  readonly address: string | null;
  readonly note: string | null;
}

function csvItem(row: CsvRow, columns: Columns, layout: CsvLayout, width: number): RowOutcome {
  const surplus = surplusFieldsError(row, width);
  if (surplus !== null) return surplus;

  // Every row of a 1Password CSV is a login: the export has no type column, and
  // the columns it does have describe nothing else. A row that were really a
  // card would carry no password, and the rule below turns that into a visible
  // error row rather than an item.
  const password = requiredPassword(row, columns.value(row, CSV_COLUMNS.password));
  if (typeof password !== "string") return password;

  const item = blankImportItem(row.line);
  item.name = columns.value(row, CSV_COLUMNS.title) ?? "";
  item.username = columns.value(row, CSV_COLUMNS.username) ?? "";
  // Byte for byte: the value as the reader unescaped it, and nothing else.
  item.password = password;
  item.notes = columns.value(row, layout.note) ?? "";
  item.favorite = isTrue(columns.value(row, CSV_COLUMNS.favorite));

  const address = columns.value(row, layout.address) ?? "";
  // One column, one address. Splitting it on a comma — as Bitwarden's CSV
  // requires — would take a URL containing one apart, and nothing in a
  // 1Password export says the column ever holds two.
  item.urls = address === "" ? [] : [address];

  // Keyhole has no TOTP field in v1 (spec section 1, non-goals). Dropping the
  // seed silently would lose a second factor the user believes they moved, and
  // they would find out when they could no longer sign in. `totp` is the kind
  // because of which column this is — 1Password's own one-time-password column
  // — and not because of what it is called.
  carry(item, columns.sourceName(CSV_COLUMNS.otpauth), columns.value(row, CSV_COLUMNS.otpauth), "totp");
  // In the header's own order from here, so the report reads the way the file
  // does.
  carry(item, columns.sourceName(CSV_COLUMNS.archived), flagText(columns.value(row, CSV_COLUMNS.archived)), "metadata");
  carry(item, columns.sourceName(CSV_COLUMNS.tags), columns.value(row, CSV_COLUMNS.tags), "metadata");

  return item;
}

/**
 * Reads a 1Password CSV export. Never throws.
 *
 * A file with no password column comes back as a single error against line 1
 * with no items — detection routes such a file elsewhere and this parser should
 * never see it, but "never throws" has to hold for the caller that gets the
 * routing wrong too, and the alternative is a file of blank passwords.
 */
export function parseOnePasswordCsv(text: string): ImportResult {
  const table = parseCsv(text);
  const columns = indexColumns(table.header);

  if (!columns.has(CSV_COLUMNS.password)) {
    return {
      items: [],
      errors: [
        { row: 1, message: "This file has no Password column, so it is not a 1Password CSV export" },
        ...table.errors,
      ],
    };
  }

  const layout: CsvLayout = {
    address: firstNamed(columns, ADDRESS_COLUMNS),
    note: firstNamed(columns, NOTE_COLUMNS),
  };

  return mapCsvRows(table, (row) => csvItem(row, columns, layout, table.header.length));
}
