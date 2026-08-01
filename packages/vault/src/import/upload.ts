import { encryptItem, type ItemPlaintext } from "@keyhole/crypto";
import { ApiError, type ApiClient } from "../api.js";
import { parentKeyFor } from "../items.js";
import type { Session } from "../session.js";

/**
 * The last step of an import: encrypt every item in the browser, then post the
 * ciphertext in batches the server will accept.
 *
 * **Plaintext never leaves the browser.** Everything above this module works in
 * the clear — the parsers, the duplicate report, the preview screen — and this
 * is the boundary where that stops. Only `encryptItem`'s output is sent, and a
 * test asserts that no request body contains a known plaintext password, as the
 * literal string and as base64 of its raw bytes.
 *
 * **It holds no key.** The user key and the collection keys stay in
 * `session.ts`; this module asks for one per import and keeps nothing after it
 * returns.
 *
 * ## Why it returns a count instead of throwing
 *
 * An import is not one operation. It is a few thousand items in several
 * requests, and a failure partway through leaves a real number of them in the
 * vault. A thrown error would carry the reason and lose the number, and a user
 * told "the import failed" after 3000 of their 4000 logins were written will
 * either import the file again — and get 3000 duplicates — or believe none of it
 * arrived. So this returns an `UploadOutcome` on every path, and the count in it
 * is always what the server confirmed.
 */

/**
 * The most items one request may carry.
 *
 * `internal/httpapi/items.go:15` rejects more, because the store writes a batch
 * in a single SQLite transaction and SQLite tolerates one writer: an unbounded
 * batch blocks every other write for as long as it runs.
 */
export const MAX_ITEMS_PER_REQUEST = 1000;

/**
 * The most bytes one request body may hold, matching `maxBulkBody` in
 * `internal/httpapi/items.go:18`.
 *
 * **Chunking on count alone is not enough**, which is the thing the count limit
 * hides. An item's ciphertext is base64 of its whole JSON body, so a vault of
 * long secure notes — a recovery-code list, a pasted SSH key, a page of
 * instructions — produces items of tens of kilobytes each, and 1000 of those is
 * comfortably past 8 MiB while being exactly at the row limit. The request is
 * then refused with a message about a size the user's item *count* never came
 * near, and the import stops with no way for them to act on it. So a chunk is
 * closed by whichever limit it reaches first.
 */
export const MAX_BODY_BYTES = 8 << 20;

/**
 * The size a chunk is actually closed at.
 *
 * Under the cap by 64 KiB. The measurement below is of `JSON.stringify` output
 * in UTF-16 code units, which equals the UTF-8 byte count only because every
 * character in a body is ASCII — base64 ciphertext, a ULID, `null`. That is true
 * today and is not something this module can enforce, so the margin covers being
 * wrong about it, plus the envelope around the array.
 */
const BODY_BUDGET = MAX_BODY_BYTES - 65536;

/** What one item looks like on the wire. Every field is opaque to the server. */
interface BulkEntry {
  collectionId: string | null;
  ciphertext: string;
  wrappedItemKey: string;
}

export interface UploadProgress {
  /** Items the server has confirmed. Never a count of what was attempted. */
  uploaded: number;
  total: number;
}

export interface UploadOutcome {
  /**
   * How many items are in the vault as a result of this run.
   *
   * Counted from chunks the server answered successfully, and never from what
   * was sent. `items.slice(uploaded)` is exactly what a retry should send.
   */
  uploaded: number;
  total: number;
  /**
   * Items whose fate is genuinely unknown: the chunk that failed, when the
   * failure cannot say whether the write happened.
   *
   * A 4xx is the server declining before it wrote anything, so those items are
   * known not to be there and this is 0. A lost connection or a 5xx is not:
   * `CreateItemsBulk` commits in one transaction, but the transaction can commit
   * and the response still never arrive. Reporting those 1000 items as simply
   * absent would send the user into a retry that duplicates them; reporting them
   * as present would lose them. Saying which items are in question is the only
   * answer that is true.
   */
  inDoubt: number;
  /** null when every item landed. */
  error: Error | null;
}

export interface UploadOptions {
  /** The collection to import into, or null/absent for personal items. */
  collectionId?: string | null;
  /** Called after each chunk the server confirms. */
  onProgress?: (progress: UploadProgress) => void;
}

/**
 * True when the failure means the items definitely were not written.
 *
 * Only a 4xx qualifies. The server validates the whole batch before it opens a
 * transaction, so a refusal is a refusal — but a 500 can be raised after the
 * commit, and a dropped connection says nothing at all.
 */
function definitelyNotWritten(error: unknown): boolean {
  return error instanceof ApiError && error.status < 500;
}

function asError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}

/**
 * Encrypts `items` and posts them in batches, stopping at the first failure.
 *
 * Never throws: every failure comes back in the outcome, alongside the count of
 * what actually landed.
 */
export async function uploadItems(
  deps: { api: ApiClient; session: Session },
  items: readonly ItemPlaintext[],
  options: UploadOptions = {},
): Promise<UploadOutcome> {
  const total = items.length;
  const collectionId = options.collectionId ?? null;

  // An empty batch is a 400 from the server ("items must not be empty"), so a
  // request here would turn "nothing to import" into a failed import.
  if (total === 0) {
    return { uploaded: 0, total: 0, inDoubt: 0, error: null };
  }

  // Fetched once and not retained: the session is the only holder. Null means
  // this device does not have the key for the chosen collection, which is a
  // refusal to write rather than something to discover halfway through.
  const parentKey = parentKeyFor(deps.session, collectionId);
  if (parentKey === null) {
    return {
      uploaded: 0,
      total,
      inDoubt: 0,
      error: new Error(
        "This device cannot open the key for that collection, so it cannot import into it",
      ),
    };
  }

  let uploaded = 0;
  let chunk: BulkEntry[] = [];
  let chunkBytes = 0;

  const send = async (): Promise<Error | null> => {
    try {
      await deps.api.post("/api/items/bulk", { items: chunk });
    } catch (error) {
      return asError(error);
    }
    // Counted only here, after the server answered. This line and the
    // `definitelyNotWritten` branch are the whole difference between a
    // resumable failure and a lying one.
    uploaded += chunk.length;
    options.onProgress?.({ uploaded, total });
    chunk = [];
    chunkBytes = 0;
    return null;
  };

  const failure = (error: Error, attempted: number): UploadOutcome => ({
    uploaded,
    total,
    inDoubt: definitelyNotWritten(error) ? 0 : attempted,
    error,
  });

  for (const item of items) {
    const encrypted = await encryptItem(item, parentKey);
    const entry: BulkEntry = {
      collectionId,
      ciphertext: encrypted.ciphertext,
      wrappedItemKey: encrypted.wrappedItemKey,
    };
    // +1 for the comma this entry needs once it is not the first.
    const entryBytes = JSON.stringify(entry).length + 1;

    // `chunk.length > 0` is what stops a single item larger than the whole
    // budget from flushing an empty chunk forever. Such an item is sent alone,
    // the server refuses it on the body cap, and the outcome says so — which is
    // the honest end for an item no request can carry.
    if (
      chunk.length > 0 &&
      (chunk.length >= MAX_ITEMS_PER_REQUEST || chunkBytes + entryBytes > BODY_BUDGET)
    ) {
      const attempted = chunk.length;
      const error = await send();
      if (error !== null) return failure(error, attempted);
    }

    chunk.push(entry);
    chunkBytes += entryBytes;
  }

  if (chunk.length > 0) {
    const attempted = chunk.length;
    const error = await send();
    if (error !== null) return failure(error, attempted);
  }

  return { uploaded, total, inDoubt: 0, error: null };
}
