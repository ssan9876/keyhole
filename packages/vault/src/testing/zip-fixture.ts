import { crc32, deflateRawSync } from "node:zlib";

/**
 * A ZIP archive built in a test, rather than committed as a blob.
 *
 * `zip.test.ts` needs to deform a valid archive a dozen ways — a wrong CRC, a
 * size that runs past the end of the file, a compression method nothing here
 * can read — and `onepassword.test.ts` needs an archive that is a perfectly
 * good ZIP holding the wrong member. Committing fifteen binaries to say that
 * would leave a reviewer unable to see what distinguishes one from the next.
 *
 * **The CRCs come from `node:zlib.crc32` and the compression from
 * `node:zlib.deflateRawSync`.** Both are implementations `zip.ts` does not
 * share: if the reader's CRC table were wrong it would disagree with zlib's and
 * every test would fail, where a builder using the reader's own table would
 * agree with it and prove nothing.
 *
 * Not a `.test.ts` file, so vitest does not collect it as a suite with no tests
 * in it — the same reason `parsers/fixture.ts` is named as it is.
 */

const LOCAL_HEADER = 0x04034b50;
const CENTRAL_HEADER = 0x02014b50;
const END_OF_CENTRAL_DIRECTORY = 0x06054b50;

/** The two compression methods a real password-manager archive uses. */
export const STORED = 0;
export const DEFLATED = 8;

/** One member of an archive under construction. */
export interface ZipMember {
  readonly name: string;
  readonly body: string | Uint8Array;
  /** `STORED` or `DEFLATED`; a real `.1pux` deflates, the committed one stores. */
  readonly method?: number;
  /** The general-purpose bit flags, for the encrypted-entry case. */
  readonly flags?: number;
  /**
   * An extra field written into the **local** header only.
   *
   * Real writers do this — a macOS-made archive carries an extended-timestamp
   * field locally that the central directory does not repeat — and it is the
   * one case where the two headers disagree about where a member's bytes begin.
   */
  readonly localExtra?: Uint8Array;
}

const encode = (value: string): Uint8Array => new TextEncoder().encode(value);

const bytesOf = (value: string | Uint8Array): Uint8Array =>
  typeof value === "string" ? encode(value) : value;

export function concat(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const merged = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    merged.set(part, at);
    at += part.length;
  }
  return merged;
}

/** A ZIP archive holding exactly the given members, in the given order. */
export function zipOf(...members: readonly ZipMember[]): Uint8Array {
  const local: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;

  for (const member of members) {
    const name = encode(member.name);
    const plain = bytesOf(member.body);
    const method = member.method ?? STORED;
    const body = method === DEFLATED ? new Uint8Array(deflateRawSync(plain)) : plain;
    // `>>> 0` because the header field is unsigned and `crc32` hands back a
    // number JavaScript would otherwise write as negative.
    const checksum = crc32(plain) >>> 0;
    const localExtra = member.localExtra ?? new Uint8Array(0);

    const header = new Uint8Array(30 + name.length + localExtra.length);
    const headerView = new DataView(header.buffer);
    headerView.setUint32(0, LOCAL_HEADER, true);
    headerView.setUint16(4, 20, true);
    headerView.setUint16(6, member.flags ?? 0, true);
    headerView.setUint16(8, method, true);
    headerView.setUint32(14, checksum, true);
    headerView.setUint32(18, body.length, true);
    headerView.setUint32(22, plain.length, true);
    headerView.setUint16(26, name.length, true);
    headerView.setUint16(28, localExtra.length, true);
    header.set(name, 30);
    header.set(localExtra, 30 + name.length);

    const entry = new Uint8Array(46 + name.length);
    const entryView = new DataView(entry.buffer);
    entryView.setUint32(0, CENTRAL_HEADER, true);
    entryView.setUint16(4, 20, true);
    entryView.setUint16(6, 20, true);
    entryView.setUint16(8, member.flags ?? 0, true);
    entryView.setUint16(10, method, true);
    entryView.setUint32(16, checksum, true);
    entryView.setUint32(20, body.length, true);
    entryView.setUint32(24, plain.length, true);
    entryView.setUint16(28, name.length, true);
    entryView.setUint32(42, offset, true);
    entry.set(name, 46);

    local.push(header, body);
    central.push(entry);
    offset += header.length + body.length;
  }

  const directorySize = central.reduce((total, entry) => total + entry.length, 0);
  const end = new Uint8Array(22);
  const endView = new DataView(end.buffer);
  endView.setUint32(0, END_OF_CENTRAL_DIRECTORY, true);
  endView.setUint16(8, members.length, true);
  endView.setUint16(10, members.length, true);
  endView.setUint32(12, directorySize, true);
  endView.setUint32(16, offset, true);

  return concat([...local, ...central, end]);
}
