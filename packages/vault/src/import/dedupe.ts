import type { ItemRecord } from "../items.js";
import type { ImportItem } from "./types.js";

/**
 * Which rows of an import are already accounts the user has.
 *
 * **Reports, never merges.** Nothing here drops a row, edits one, or decides
 * anything: it returns groups, and the preview screen asks the user what to do
 * with each. Merging two logins means choosing which password survives, and the
 * only party who can make that choice is the person who knows which one still
 * works. A silent merge is also the one mistake this whole flow cannot undo —
 * the export file is deleted at the end of it.
 *
 * ## What counts as a duplicate
 *
 * The same **normalized host** and the same **username**. Not the same URL:
 * `https://x.com/login` and `https://x.com/` are one account, and every export
 * writes that pair differently — Chrome stores the form's action URL, Bitwarden
 * stores whatever the user typed, KeePass stores a bare host. Comparing whole
 * URLs finds almost nothing, and finding nothing is indistinguishable from
 * having nothing to find.
 *
 * ## Against the vault, not only within the file
 *
 * Importing the same export twice, and importing after adding a handful of
 * logins by hand, are the two ordinary ways to end up with duplicates — and
 * neither shows up in a file compared only against itself. `existingFromRecords`
 * reduces the unlocked vault to the four fields compared here, and carries no
 * password out of it.
 */

/**
 * The pair two items must share to be the same account.
 *
 * A single-valued key on purpose: it makes the groups a partition of the rows,
 * so "skip this group" names an unambiguous set of rows. Matching on *any*
 * shared host would put a row with three URLs in three groups at once, and a
 * user skipping one of them would be skipping a row they had also chosen to
 * import.
 */
export interface DuplicateKey {
  /** As `matchHost` normalizes it. */
  host: string;
  /** Trimmed and lowercased, as `matchUsername` normalizes it. */
  username: string;
}

/**
 * A vault item reduced to what duplicate detection compares.
 *
 * **No password field, deliberately.** This shape is built from decrypted vault
 * plaintext and is handed to the preview screen; giving it a password would put
 * every existing secret into a structure the UI renders, for a comparison that
 * never looks at one.
 */
export interface ExistingItem {
  id: string;
  /** For naming the item in the report. Never compared. */
  name: string;
  username: string;
  urls: readonly string[];
}

/** One account that more than one row, or a row and the vault, both claim. */
export interface DuplicateGroup {
  key: DuplicateKey;
  /**
   * Indices into the rows passed to `findDuplicates`, ascending.
   *
   * Indices rather than the items themselves: the caller has the array, and a
   * decision the user makes about a group has to name rows the caller can then
   * exclude. Never empty — a group with no row from the file is a fact about
   * the vault alone and not something an import should report.
   */
  rows: number[];
  /** Vault items sharing the key. Empty when the clash is only within the file. */
  existing: ExistingItem[];
}

export interface DuplicateReport {
  /** In the order of each group's first row. */
  groups: DuplicateGroup[];
  /**
   * Indices of rows that were **not compared to anything**, because they carry
   * no host to compare on — no URL at all, a URL holding no host, or a note.
   *
   * Separate from "checked and clean", because they are a different answer and
   * the preview screen has to be able to say which one it is giving.
   *
   * These rows are *not* keyed under an empty host. Doing that would put every
   * URL-less row that shares a username — one person's own email address, on
   * every note and every app credential in the file — into one enormous group,
   * and a user who skipped that group would lose rows that were never
   * duplicates of anything.
   */
  unchecked: number[];
}

/**
 * The host two rows must share, or `null` when the value holds no host.
 *
 * What is normalized, and why each one:
 *
 * - **The scheme is discarded.** A site that moved to HTTPS did not become a
 *   different account, and old exports are full of `http://`.
 * - **Case is discarded**, with `toLowerCase` rather than `toLocaleLowerCase`:
 *   a locale-sensitive fold makes the answer depend on the browser's language
 *   (Turkish maps `I` to a dotless `ı`), and a duplicate report that changes
 *   with the user's locale is worse than one that is merely wrong.
 * - **A leading `www.` is dropped**, once. Exports disagree about it for the
 *   same site. Dropping it repeatedly would rename a host genuinely called
 *   `www.www.example.com`.
 * - **A trailing dot is dropped.** `example.com.` is the fully qualified
 *   spelling of `example.com` and resolves to the same server.
 * - **A Unicode host is punycoded**, because `new URL` does it — so the same
 *   site exported as `☃.com` by one manager and `xn--n3h.com` by another
 *   compares equal.
 * - **The port is kept**, when it is not the scheme's default. Two services on
 *   one machine at different ports are two services, and `admin@host:8443` and
 *   `admin@host:9000` are routinely different accounts. `new URL` removes a
 *   default port for us, so `https://x.com:443` and `https://x.com` agree.
 *
 * **The path, query and fragment are discarded**, which is the whole point.
 *
 * A value with no scheme is parsed by re-reading it behind `https://` rather
 * than by cutting the string by hand: several exports write a bare
 * `mail.example.com`, and the platform's parser already knows about userinfo,
 * ports, IPv6 brackets and IDN. The direct parse is tried first, because
 * `https://` + `https://x.com:8080/y` would read `https` as the host.
 */
export function matchHost(url: string): string | null {
  const trimmed = url.trim();
  if (trimmed === "") return null;

  const parsed = parseUrl(trimmed) ?? parseUrl(`https://${trimmed}`);
  if (parsed === null) return null;

  let hostname = parsed.hostname.toLowerCase();
  if (hostname.endsWith(".")) hostname = hostname.slice(0, -1);
  if (hostname.startsWith("www.")) hostname = hostname.slice("www.".length);
  if (hostname === "") return null;

  return parsed.port === "" ? hostname : `${hostname}:${parsed.port}`;
}

/** `new URL`, but `null` for a value it refuses or reads as host-less. */
function parseUrl(value: string): URL | null {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  // `mailto:a@b.com` and `x.com:8080/a` both parse with an empty hostname; both
  // want the second attempt, behind an explicit scheme.
  return parsed.hostname === "" ? null : parsed;
}

/**
 * The username two rows must share.
 *
 * Case-folded and trimmed, and **only for the comparison** — the item itself is
 * never rewritten. The two are worth folding because the same address exported
 * by two managers legitimately differs in case, and a trailing space is
 * invisible everywhere the user has ever seen the value. The cost of folding
 * too far is a group the user glances at and imports anyway; the cost of not
 * folding is a duplicate that is never mentioned.
 *
 * An empty username is a value like any other: two rows on one host with no
 * username recorded are plausibly the same login, and the user can say.
 */
function matchUsername(username: string): string {
  return username.trim().toLowerCase();
}

/** The key a row is compared under, or `null` when it cannot be compared. */
function keyOf(item: {
  type?: string;
  username: string;
  urls: readonly string[];
}): DuplicateKey | null {
  // A note is not an account: it has no username, and Keyhole's note item has
  // no field for one. Comparing notes on host alone would group every note
  // exported from one site.
  if (item.type === "note") return null;
  const [first] = item.urls;
  if (first === undefined) return null;
  const host = matchHost(first);
  if (host === null) return null;
  return { host, username: matchUsername(item.username) };
}

function keyText(key: DuplicateKey): string {
  // "\n" as the separator because it appears in neither a host nor a username,
  // so no pair of distinct keys can collide into one string.
  return `${key.host}\n${key.username}`;
}

/**
 * Every account claimed twice, and every row nothing could be compared.
 *
 * `existing` is the vault as it stands on this device; omit it to compare a file
 * against itself alone, which is what a caller with no vault loaded has.
 */
export function findDuplicates(
  rows: readonly ImportItem[],
  existing: readonly ExistingItem[] = [],
): DuplicateReport {
  const byKey = new Map<string, DuplicateGroup>();
  const unchecked: number[] = [];

  rows.forEach((item, index) => {
    const key = keyOf(item);
    if (key === null) {
      unchecked.push(index);
      return;
    }
    const text = keyText(key);
    const group = byKey.get(text) ?? { key, rows: [], existing: [] };
    group.rows.push(index);
    byKey.set(text, group);
  });

  for (const item of existing) {
    const key = keyOf(item);
    if (key === null) continue;
    // Only against groups the file already claims. A vault item nothing in the
    // import touches is not part of this report; the user is being asked about
    // rows they are importing, not about their existing vault.
    byKey.get(keyText(key))?.existing.push(item);
  }

  const groups = [...byKey.values()].filter(
    (group) => group.rows.length > 1 || group.existing.length > 0,
  );

  return { groups, unchecked };
}

/**
 * The unlocked vault, reduced to what duplicate detection compares.
 *
 * Three kinds of record are skipped, and each absence means "not compared"
 * rather than "not a duplicate":
 *
 * - a **tombstone**, whose ciphertext the server has already blanked;
 * - a record this device **could not decrypt** — an item in a collection whose
 *   key is not held, or a damaged blob. There is nothing to compare, and
 *   claiming a row is not a duplicate of an item nobody read would be a claim
 *   nothing checked;
 * - a **note**, which has no username.
 */
export function existingFromRecords(records: readonly ItemRecord[]): ExistingItem[] {
  const items: ExistingItem[] = [];
  for (const record of records) {
    const plaintext = record.plaintext;
    if (plaintext === null || plaintext.type !== "login") continue;
    // Rebuilt field by field rather than spread: a spread would carry the
    // password of every item in the vault into a structure the preview screen
    // renders, for a comparison that never reads one.
    items.push({
      id: record.id,
      name: plaintext.name,
      username: plaintext.username,
      urls: [...plaintext.urls],
    });
  }
  return items;
}
