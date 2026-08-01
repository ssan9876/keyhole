/**
 * Enough of the ZIP container to read one member out of an export archive.
 *
 * A 1Password `.1pux` is a ZIP holding `export.data`, and Dashlane's "export to
 * CSV" is a ZIP holding five of them. Neither can be read without opening the
 * container first, so this is the one file in the import path that deals in
 * bytes rather than text.
 *
 * ## Why this exists rather than a dependency
 *
 * This code sits directly in the path of the user's entire plaintext vault. A
 * runtime dependency here is supply chain in the worst possible place, and the
 * plan's constraint is that none is added without reporting first. The
 * alternative is not "write a decompressor" — **the browser already has one**.
 * `DecompressionStream("deflate-raw")` is the same zlib every one of those
 * packages wraps, shipped by the engine, updated by the engine, and present in
 * every browser this app already requires for WebCrypto.
 *
 * What a dependency would have bought is the part `DecompressionStream` does not
 * do: ZIP is a *container*, and a raw deflate stream is only what sits inside
 * one member of it. Finding that member — the end-of-central-directory record,
 * the central directory, each member's local header — is what the code below
 * is, and it is the honest cost of not taking the dependency. It is table
 * lookups and bounds checks, all of it reviewable in one sitting, and it decides
 * *where* the bytes are rather than *what* they mean.
 *
 * ## Nothing here throws
 *
 * The CSV reader's rule, for the same reason: an archive is a file a user
 * downloaded, and a download that stopped early, a renamed CSV, or an archive
 * with a password on it are all things that arrive here in the ordinary course
 * of somebody moving their vault. Every one of them comes back as a `ZipProblem`
 * with a sentence the user can act on. A reader that throws on a truncated file
 * turns a bad download into a stack trace.
 *
 * ## What is deliberately not supported
 *
 * - **Zip64.** A password export is measured in megabytes; the 4 GiB fields are
 *   enough. A Zip64 marker is refused by name rather than read as the 32-bit
 *   value it is standing in for, which would be a wrong offset silently.
 * - **Encrypted entries.** Named, so the user is told to re-export rather than
 *   sent looking for a corrupt download by a checksum failure on ciphertext.
 * - **Compression methods other than stored and deflate.** Every real archive
 *   from every password manager uses one of the two; anything else is named.
 *
 * ## The checksum is verified, and that is not a formality
 *
 * Every member's CRC-32 is checked against the value the archive recorded. The
 * bytes coming out of here become somebody's passwords: a member that expanded
 * to *something* is not the same as a member that expanded to what was put in,
 * and the difference is a password that no longer signs them in, discovered
 * long after the export file was deleted.
 */

/** Why an archive, or one member of it, could not be read. */
export interface ZipProblem {
  /** A sentence for the user, naming what is wrong and what it means. */
  readonly problem: string;
}

/**
 * True when a call refused rather than returning what was asked for.
 *
 * `"problem" in value` after an object check, matching `isRowError` in
 * `parsers/shared.ts`: neither `Uint8Array` nor `string` has such a key, so the
 * two outcomes are already distinguishable and a discriminant would be a field
 * every caller had to remember to set. The object check is what keeps `in` from
 * throwing on the `string` that `readText` returns on success.
 */
export function isZipProblem(value: unknown): value is ZipProblem {
  return typeof value === "object" && value !== null && "problem" in value;
}

/** An opened archive: what it holds, and the bytes of any one of them. */
export interface ZipArchive {
  /**
   * Every member's name, in the order the central directory lists them.
   *
   * Dashlane's archive holds `credentials.csv` beside `securenotes.csv` and
   * three more, so *which* member to read is the caller's decision and it needs
   * the names to make it. A `.1pux` holds one `export.data` and needs none of
   * that, which is why this reader lists rather than assuming.
   */
  readonly names: readonly string[];
  /** One member's bytes, or why they could not be produced. Never throws. */
  read(name: string): Promise<Uint8Array | ZipProblem>;
  /** One member decoded as UTF-8, or why it could not be. Never throws. */
  readText(name: string): Promise<string | ZipProblem>;
}

const LOCAL_HEADER = 0x04034b50;
const CENTRAL_HEADER = 0x02014b50;
const END_OF_CENTRAL_DIRECTORY = 0x06054b50;

/** The two compression methods every real password-manager export uses. */
const STORED = 0;
const DEFLATED = 8;

/** Bit 0 of the general-purpose flags: this member is encrypted. */
const ENCRYPTED = 0x0001;

/**
 * The value a 32-bit field holds when the real one is in a Zip64 extra field.
 *
 * Read as a number it is 4 GiB minus one, which as an offset points nowhere and
 * as a length reads past the end of every file. Refusing it by name is the
 * difference between a sentence and a wrong answer.
 */
const ZIP64_MARKER = 0xffffffff;

const END_RECORD_LENGTH = 22;
const LOCAL_HEADER_LENGTH = 30;
const CENTRAL_ENTRY_LENGTH = 46;

/** The largest archive comment the format allows, which is how far back to scan. */
const MAX_COMMENT_LENGTH = 0xffff;

const NOT_AN_ARCHIVE: ZipProblem = {
  problem:
    "This file does not end with a ZIP end-of-central-directory record, so it is " +
    "not a ZIP archive or the download did not finish",
};

/** One member, as the central directory describes it. */
interface DirectoryEntry {
  readonly name: string;
  readonly flags: number;
  readonly method: number;
  readonly checksum: number;
  readonly compressedSize: number;
  readonly uncompressedSize: number;
  readonly localHeaderOffset: number;
}

/* -------------------------------------------------------------------------- */
/*                                   CRC-32                                    */
/* -------------------------------------------------------------------------- */

let table: Uint32Array | null = null;

/** The standard CRC-32 table, built once on first use. */
function crcTable(): Uint32Array {
  if (table !== null) return table;
  const built = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let value = n;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    built[n] = value >>> 0;
  }
  table = built;
  return built;
}

/** The CRC-32 of `bytes`, as the ZIP format computes it. */
function crc32(bytes: Uint8Array): number {
  const lookup = crcTable();
  let value = 0xffffffff;
  for (const byte of bytes) {
    // The index is masked to 0-255 and the table has 256 entries, so the
    // fallback is unreachable; it is here because `noUncheckedIndexedAccess`
    // types every element as possibly absent and an assertion would hide a real
    // out-of-range read if this loop were ever changed.
    value = (lookup[(value ^ byte) & 0xff] ?? 0) ^ (value >>> 8);
  }
  return (value ^ 0xffffffff) >>> 0;
}

/* -------------------------------------------------------------------------- */
/*                                  Inflation                                  */
/* -------------------------------------------------------------------------- */

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const merged = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    merged.set(part, at);
    at += part.length;
  }
  return merged;
}

/**
 * `body` expanded by the engine's own inflate, or `null` when it is not a valid
 * deflate stream.
 *
 * A ZIP member holds a **raw** deflate stream — no zlib header, no gzip wrapper
 * — which is exactly what `"deflate-raw"` names. Asking for `"deflate"` here
 * would consume the first two bytes of the user's data as a header that is not
 * there and fail on every archive.
 *
 * The rejection path is a `try` around the whole read because the stream reports
 * a corrupt input by rejecting the reader's promise, and an unhandled rejection
 * from a file the user chose is the throw this module exists not to do.
 */
async function inflateRaw(body: Uint8Array<ArrayBuffer>): Promise<Uint8Array | null> {
  try {
    // `BufferSource` rather than `Uint8Array` because that is what the DOM types
    // give `DecompressionStream`'s writable end; a narrower source will not pipe
    // into it. The argument is an owned `ArrayBuffer` for the same reason —
    // `BufferSource` excludes a view onto a `SharedArrayBuffer`.
    const source = new ReadableStream<BufferSource>({
      start(controller) {
        controller.enqueue(body);
        controller.close();
      },
    });
    const reader = source.pipeThrough(new DecompressionStream("deflate-raw")).getReader();
    const chunks: Uint8Array[] = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value !== undefined) chunks.push(value);
    }
    return concat(chunks);
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/*                             The container itself                            */
/* -------------------------------------------------------------------------- */

/**
 * The offset of the end-of-central-directory record, or `-1`.
 *
 * Scanned backwards because the record is last, and the record's own comment
 * length is checked against the bytes that follow it — an archive comment, or a
 * member holding a ZIP of its own, can contain the four signature bytes, and
 * accepting the first match would read the directory of the wrong archive.
 */
function endRecordAt(view: DataView, length: number): number {
  const earliest = Math.max(0, length - END_RECORD_LENGTH - MAX_COMMENT_LENGTH);
  for (let at = length - END_RECORD_LENGTH; at >= earliest; at -= 1) {
    if (
      view.getUint32(at, true) === END_OF_CENTRAL_DIRECTORY &&
      view.getUint16(at + 20, true) === length - at - END_RECORD_LENGTH
    ) {
      return at;
    }
  }
  return -1;
}

/**
 * The central directory's entries, or the reason it could not be walked.
 *
 * The count in the end record is not trusted over the bounds: a damaged archive
 * can claim more entries than it holds, and reading past the directory would
 * interpret whatever follows as a header.
 */
function readDirectory(
  view: DataView,
  bytes: Uint8Array,
  start: number,
  end: number,
  count: number,
): DirectoryEntry[] | ZipProblem {
  const entries: DirectoryEntry[] = [];
  let at = start;

  for (let n = 0; n < count; n += 1) {
    if (at + CENTRAL_ENTRY_LENGTH > end || view.getUint32(at, true) !== CENTRAL_HEADER) {
      return { problem: "This archive's central directory is damaged, so its contents could not be listed" };
    }
    const nameLength = view.getUint16(at + 28, true);
    const extraLength = view.getUint16(at + 30, true);
    const commentLength = view.getUint16(at + 32, true);
    const nameEnd = at + CENTRAL_ENTRY_LENGTH + nameLength;
    if (nameEnd > end) {
      return { problem: "This archive's central directory is damaged, so its contents could not be listed" };
    }

    entries.push({
      // Decoded as UTF-8 whatever the name flag says. Every member of a `.1pux`
      // and of a Dashlane archive is named in ASCII, where UTF-8 and the
      // format's legacy CP437 agree byte for byte, so the distinction cannot
      // change which member a caller finds.
      name: new TextDecoder().decode(bytes.subarray(at + CENTRAL_ENTRY_LENGTH, nameEnd)),
      flags: view.getUint16(at + 8, true),
      method: view.getUint16(at + 10, true),
      checksum: view.getUint32(at + 16, true),
      compressedSize: view.getUint32(at + 20, true),
      uncompressedSize: view.getUint32(at + 24, true),
      localHeaderOffset: view.getUint32(at + 42, true),
    });

    at = nameEnd + extraLength + commentLength;
  }

  return entries;
}

/** One member's stored bytes, exactly as the archive holds them. */
function compressedBytes(
  view: DataView,
  bytes: Uint8Array,
  entry: DirectoryEntry,
): Uint8Array<ArrayBuffer> | ZipProblem {
  const header = entry.localHeaderOffset;
  if (
    header + LOCAL_HEADER_LENGTH > bytes.length ||
    view.getUint32(header, true) !== LOCAL_HEADER
  ) {
    return {
      problem:
        `This archive's record of where ${quoted(entry.name)} begins does not point at a ` +
        "file header, so the archive is damaged",
    };
  }

  // The local header's own name and extra lengths, not the directory's: a
  // writer is allowed to put different extra fields in the two places, and using
  // the directory's length here would start the read a few bytes off — which
  // deflate reports as damage and a stored member does not report at all.
  const nameLength = view.getUint16(header + 26, true);
  const extraLength = view.getUint16(header + 28, true);
  const start = header + LOCAL_HEADER_LENGTH + nameLength + extraLength;
  const end = start + entry.compressedSize;
  if (end > bytes.length) {
    return {
      problem:
        `This archive says ${quoted(entry.name)} is ${entry.compressedSize} bytes but the ` +
        "file ends before them, so the download did not finish",
    };
  }

  // Copied rather than viewed, so the returned bytes do not hold the whole
  // archive alive behind them and cannot be changed by a later read. The copy
  // owns its `ArrayBuffer`, which is what `DecompressionStream` will accept.
  const copy = new Uint8Array(entry.compressedSize);
  copy.set(bytes.subarray(start, end));
  return copy;
}

function quoted(name: string): string {
  return `"${name}"`;
}

/**
 * Opens an archive, or says why it is not one. Never throws.
 *
 * Reading the directory is eager and reading a member is not: the directory is
 * a few hundred bytes and the caller needs the names to choose, while the
 * members are the vault and expanding one nobody asked for would put it in
 * memory for no reason.
 */
export function openZip(bytes: Uint8Array): ZipArchive | ZipProblem {
  if (bytes.length < END_RECORD_LENGTH) return NOT_AN_ARCHIVE;

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const end = endRecordAt(view, bytes.length);
  if (end === -1) return NOT_AN_ARCHIVE;

  const count = view.getUint16(end + 10, true);
  const directorySize = view.getUint32(end + 12, true);
  const directoryOffset = view.getUint32(end + 16, true);
  // A Zip64 archive writes `ZIP64_MARKER` in both of these, which this check
  // catches on its way past: 4 GiB minus one is outside every file that reaches
  // here, so it lands on the same sentence rather than being read as an offset.
  if (directoryOffset + directorySize > bytes.length) {
    return {
      problem:
        "This archive's central directory is recorded outside the file, so the archive is damaged",
    };
  }

  const directory = readDirectory(
    view,
    bytes,
    directoryOffset,
    directoryOffset + directorySize,
    count,
  );
  if (isZipProblem(directory)) return directory;
  // Re-bound rather than used directly, because the narrowing above does not
  // reach into the closures below and `read` is one of them.
  const entries: readonly DirectoryEntry[] = directory;

  // First occurrence wins for a repeated name, matching `csv.ts`'s rule for a
  // repeated column. A ZIP is allowed to hold two members of one name, and the
  // first is the one every other reader shows.
  const byName = new Map<string, DirectoryEntry>();
  for (const entry of entries) {
    if (!byName.has(entry.name)) byName.set(entry.name, entry);
  }

  async function read(name: string): Promise<Uint8Array | ZipProblem> {
    const entry = byName.get(name);
    if (entry === undefined) {
      const held = entries.length === 0 ? "nothing" : entries.map((one) => one.name).join(", ");
      return { problem: `This archive has no ${quoted(name)} in it; it holds ${held}` };
    }

    if ((entry.flags & ENCRYPTED) !== 0) {
      return {
        problem: `This archive encrypted ${quoted(name)} with a password, so its contents cannot be read`,
      };
    }
    if (entry.compressedSize === ZIP64_MARKER || entry.uncompressedSize === ZIP64_MARKER) {
      return {
        problem: `This archive records ${quoted(name)} in the Zip64 format, which Keyhole cannot read`,
      };
    }
    if (entry.method !== STORED && entry.method !== DEFLATED) {
      return {
        problem:
          `This archive compressed ${quoted(name)} with method ${entry.method}, which Keyhole ` +
          "cannot read; only stored and deflated entries are supported",
      };
    }

    const stored = compressedBytes(view, bytes, entry);
    if (isZipProblem(stored)) return stored;

    const contents = entry.method === STORED ? stored : await inflateRaw(stored);
    if (contents === null) {
      return {
        problem:
          `The compressed contents of ${quoted(name)} could not be expanded, so the file is damaged`,
      };
    }

    // The checksum before the length, because a length that matches proves
    // nothing about the bytes and this is the check that decides whether the
    // user gets their own passwords back.
    if (crc32(contents) !== entry.checksum || contents.length !== entry.uncompressedSize) {
      return {
        problem:
          `The contents of ${quoted(name)} do not match the checksum this archive recorded ` +
          "for them, so the file is damaged",
      };
    }

    return contents;
  }

  return {
    names: entries.map((entry) => entry.name),
    read,
    async readText(name: string): Promise<string | ZipProblem> {
      const contents = await read(name);
      if (isZipProblem(contents)) return contents;
      try {
        // `fatal` on purpose. The alternative substitutes U+FFFD for a byte it
        // cannot decode, which is a silent edit — and in this file the edited
        // byte can be part of a password. An error the user can see beats a
        // password that no longer signs them in.
        return new TextDecoder("utf-8", { fatal: true }).decode(contents);
      } catch {
        return {
          problem: `The contents of ${quoted(name)} are not valid UTF-8 text, so they could not be read`,
        };
      }
    },
  };
}
