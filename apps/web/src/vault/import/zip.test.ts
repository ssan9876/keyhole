import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { crc32, deflateRawSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { isZipProblem, openZip, type ZipArchive } from "./zip.js";

/**
 * The archives here are **built in the test**, not committed as blobs.
 *
 * A ZIP fixture is unreadable in review and unchangeable without a script, and
 * every case below is a deliberate deformation of a valid archive — a wrong
 * CRC, a size that runs past the end of the file, a compression method nothing
 * here can read. Committing eight binaries to say that would leave a reviewer
 * unable to see what distinguishes one from the next.
 *
 * **The builder's CRCs come from `node:zlib.crc32` and its deflate from
 * `node:zlib.deflateRawSync`.** Both are implementations `zip.ts` does not
 * share: if the reader's CRC table were wrong it would disagree with zlib's and
 * every stored-member test would fail, where a builder using the reader's own
 * table would agree with it and prove nothing.
 *
 * The real `.1pux` fixture is read at the end, so the whole path is exercised
 * against bytes this file did not write.
 */

const LOCAL_HEADER = 0x04034b50;
const CENTRAL_HEADER = 0x02014b50;
const END_OF_CENTRAL_DIRECTORY = 0x06054b50;

const STORED = 0;
const DEFLATED = 8;

interface Member {
  readonly name: string;
  readonly body: string | Uint8Array;
  /** `STORED` or `DEFLATED`; a real `.1pux` uses both. */
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

const utf8 = (value: string | Uint8Array): Uint8Array =>
  typeof value === "string" ? new TextEncoder().encode(value) : value;

/** A ZIP archive holding exactly the given members. */
function zipOf(...members: readonly Member[]): Uint8Array {
  const local: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;

  for (const member of members) {
    const name = new TextEncoder().encode(member.name);
    const plain = utf8(member.body);
    const method = member.method ?? STORED;
    const body = method === DEFLATED ? new Uint8Array(deflateRawSync(plain)) : plain;
    // `>>> 0` because `crc32` returns a signed-looking number for high values
    // and the header field is unsigned.
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

/** The offset of the first central-directory entry, read from the archive's own end record. */
function directoryAt(archive: Uint8Array): number {
  const view = new DataView(archive.buffer, archive.byteOffset, archive.byteLength);
  return view.getUint32(archive.length - 22 + 16, true);
}

/** Rewrites one little-endian field of the first central-directory entry. */
function patchDirectory(
  archive: Uint8Array,
  fieldOffset: number,
  bytes: 2 | 4,
  value: number,
): Uint8Array {
  const patched = archive.slice();
  const view = new DataView(patched.buffer);
  const at = directoryAt(patched) + fieldOffset;
  if (bytes === 2) view.setUint16(at, value, true);
  else view.setUint32(at, value, true);
  return patched;
}

/** The archive under test, or a failure of `openZip` reported as one. */
function opened(archive: Uint8Array): ZipArchive {
  const result = openZip(archive);
  if (isZipProblem(result)) {
    throw new Error(`expected the archive to open, got: ${result.problem}`);
  }
  return result;
}

/** The problem `openZip` reported, or a failure to report one. */
function problemOpening(archive: Uint8Array): string {
  const result = openZip(archive);
  if (!isZipProblem(result)) {
    throw new Error(`expected the archive to be refused, but it opened with ${result.names.length} members`);
  }
  return result.problem;
}

/** The text of a member that reads, or a failure to read it reported as one. */
async function textOf(archive: Uint8Array, name: string): Promise<string> {
  const result = await opened(archive).readText(name);
  if (isZipProblem(result)) {
    throw new Error(`expected ${name} to read, got: ${result.problem}`);
  }
  return result;
}

/** The problem reading a member reported, or a failure to report one. */
async function problemReading(archive: Uint8Array, name: string): Promise<string> {
  const result = await opened(archive).readText(name);
  if (!isZipProblem(result)) {
    throw new Error(`expected ${name} to be refused, but it read as ${JSON.stringify(result)}`);
  }
  return result.problem;
}

/**
 * The real `.1pux` fixture's bytes.
 *
 * Located from the running test file's own path for the reasons `detect.test.ts`
 * sets out: `import.meta.url` is an http URL under this project's jsdom
 * environment, and `process.cwd()` depends on where vitest was started.
 */
function readFixture(file: string): Uint8Array {
  const testPath = expect.getState().testPath;
  if (testPath === undefined) {
    throw new Error("vitest reported no test path, so fixtures cannot be located");
  }
  return new Uint8Array(readFileSync(join(dirname(testPath), "fixtures", file)));
}

const JSON_BODY = '{"accounts":[]}';

describe("openZip, on the members an archive holds", () => {
  it("names every member in the order the central directory lists them", () => {
    // Dashlane's export is several CSVs in one archive, so choosing which
    // member to read is a caller's decision and needs the names to make it.
    const archive = zipOf(
      { name: "credentials.csv", body: "url,username,password\n" },
      { name: "securenotes.csv", body: "title,note\n" },
      { name: "payments.csv", body: "type,name\n" },
    );

    expect(opened(archive).names).toEqual([
      "credentials.csv",
      "securenotes.csv",
      "payments.csv",
    ]);
  });

  it("reads a stored member's bytes back unchanged", async () => {
    const archive = zipOf({ name: "export.data", body: JSON_BODY, method: STORED });

    expect(await textOf(archive, "export.data")).toBe(JSON_BODY);
  });

  it("reads a deflated member, which is what a real .1pux writes", async () => {
    // The committed fixture stores its members uncompressed so a reviewer can
    // read them. A real export does not, so a reader tested only against the
    // fixture would pass here and fail on every file a user actually has.
    const body = JSON.stringify({ accounts: [{ vaults: [] }] }).repeat(40);
    const archive = zipOf({ name: "export.data", body, method: DEFLATED });

    expect(await textOf(archive, "export.data")).toBe(body);
  });

  it("keeps a member's bytes exact across deflate, including a password's punctuation", async () => {
    // The whole reason this reader exists is to hand a parser a password. A
    // round trip that dropped a trailing space or mangled a quote would be
    // invisible in a JSON.parse that still succeeded.
    const body = JSON.stringify({ password: 'fixture-pw "quoted", commaé\t ' });
    const archive = zipOf({ name: "export.data", body, method: DEFLATED });

    expect(await textOf(archive, "export.data")).toBe(body);
  });

  it("finds a member's bytes when only its local header carries an extra field", async () => {
    // The two headers are allowed to disagree about their extra fields, and a
    // reader that measured from the central directory's length would start this
    // member nine bytes early: deflate reports that as damage, and a stored
    // member does not report it at all.
    const archive = zipOf({
      name: "export.data",
      body: JSON_BODY,
      // An extended-timestamp field (id 0x5455), which is what a macOS writer
      // puts in a local header and leaves out of the central directory.
      localExtra: new Uint8Array([0x55, 0x54, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
    });

    expect(await textOf(archive, "export.data")).toBe(JSON_BODY);
  });

  it("reads the first of two members sharing a name, as csv.ts does for a repeated column", async () => {
    const archive = zipOf(
      { name: "export.data", body: '{"first":true}' },
      { name: "export.data", body: '{"second":true}' },
    );

    expect(await textOf(archive, "export.data")).toBe('{"first":true}');
  });

  it("opens an archive with no members at all and reports it holds none", () => {
    expect(opened(zipOf()).names).toEqual([]);
  });
});

describe("openZip, on an archive or member it cannot read", () => {
  it("names a member the archive does not hold rather than throwing", async () => {
    const archive = zipOf({ name: "export.attributes", body: "{}" });

    expect(await problemReading(archive, "export.data")).toBe(
      'This archive has no "export.data" in it; it holds export.attributes',
    );
  });

  it("refuses a truncated archive rather than throwing, since its end record is gone", () => {
    // The failure this exists for: a download that stopped early. Throwing here
    // is the CSV reader's Critical from two tasks ago in a new file.
    const archive = zipOf({ name: "export.data", body: JSON_BODY });

    expect(problemOpening(archive.slice(0, archive.length - 10))).toBe(
      "This file does not end with a ZIP end-of-central-directory record, so it is " +
        "not a ZIP archive or the download did not finish",
    );
  });

  it("refuses an archive whose central directory is recorded past the end of the file", () => {
    const archive = zipOf({ name: "export.data", body: JSON_BODY });
    const view = new DataView(archive.buffer);
    view.setUint32(archive.length - 22 + 16, archive.length + 1000, true);

    expect(problemOpening(archive)).toBe(
      "This archive's central directory is recorded outside the file, so the archive is damaged",
    );
  });

  it("refuses a member whose compressed data is recorded past the end of the file", async () => {
    // Truncation after the central directory has been read: the names all look
    // right and the bytes are not there.
    const archive = zipOf({ name: "export.data", body: JSON_BODY });
    // Offset 20 of a central-directory entry is the compressed size.
    const patched = patchDirectory(archive, 20, 4, 100_000);

    expect(await problemReading(patched, "export.data")).toBe(
      'This archive says "export.data" is 100000 bytes but the file ends before them, ' +
        "so the download did not finish",
    );
  });

  it("refuses a member whose bytes do not match the checksum the archive recorded", async () => {
    // A CRC failure on a password file is not a formality. Returning the bytes
    // anyway would hand the parser a password that is not the user's.
    const archive = zipOf({ name: "export.data", body: JSON_BODY });
    const damaged = archive.slice();
    // One letter of `{"accounts":[]}`, changed to another letter. Deliberately
    // still valid UTF-8 and still valid JSON: the only thing standing between
    // this and a parser being handed contents nobody exported is the checksum.
    damaged[30 + "export.data".length + 2] = "b".charCodeAt(0);

    expect(await problemReading(damaged, "export.data")).toBe(
      'The contents of "export.data" do not match the checksum this archive recorded ' +
        "for them, so the file is damaged",
    );
  });

  it("names a compression method it cannot read rather than returning the compressed bytes", async () => {
    const archive = zipOf({ name: "export.data", body: JSON_BODY });
    // Offset 10 of a central-directory entry is the compression method; 12 is
    // bzip2, which browsers have no decompressor for.
    const patched = patchDirectory(archive, 10, 2, 12);

    expect(await problemReading(patched, "export.data")).toBe(
      'This archive compressed "export.data" with method 12, which Keyhole cannot read; ' +
        "only stored and deflated entries are supported",
    );
  });

  it("refuses an encrypted member rather than handing back its ciphertext", async () => {
    // Bit 0 of the general-purpose flags. Without this check the ciphertext
    // would fail the CRC and be reported as damage, which sends the user
    // looking for a corrupt download instead of a password prompt.
    const archive = zipOf({ name: "export.data", body: JSON_BODY, flags: 1 });

    expect(await problemReading(archive, "export.data")).toBe(
      'This archive encrypted "export.data" with a password, so its contents cannot be read',
    );
  });

  it("refuses a Zip64 archive rather than reading a 32-bit field that means something else", async () => {
    const archive = zipOf({ name: "export.data", body: JSON_BODY });
    // 0xFFFFFFFF in a size field is Zip64's marker that the real value lives in
    // an extra field this reader does not parse.
    const patched = patchDirectory(archive, 20, 4, 0xffffffff);

    expect(await problemReading(patched, "export.data")).toBe(
      'This archive records "export.data" in the Zip64 format, which Keyhole cannot read',
    );
  });

  it("refuses bytes that are not an archive at all", () => {
    const csv = new TextEncoder().encode("url,username,password\nhttps://example.com,ada,pw\n");

    expect(problemOpening(csv)).toBe(
      "This file does not end with a ZIP end-of-central-directory record, so it is " +
        "not a ZIP archive or the download did not finish",
    );
  });

  it("refuses an empty file rather than reading past its start", () => {
    expect(problemOpening(new Uint8Array(0))).toBe(
      "This file does not end with a ZIP end-of-central-directory record, so it is " +
        "not a ZIP archive or the download did not finish",
    );
  });

  it("refuses a member whose bytes are not valid UTF-8 rather than substituting question marks", async () => {
    // U+FFFD in place of a byte is a silent edit, and in a password file the
    // edited byte could be part of a password. An error the user can see beats
    // a password that no longer signs them in.
    const archive = zipOf({ name: "export.data", body: new Uint8Array([0x7b, 0xff, 0xfe, 0x7d]) });

    expect(await problemReading(archive, "export.data")).toBe(
      'The contents of "export.data" are not valid UTF-8 text, so they could not be read',
    );
  });

  it("refuses a member declared deflated whose bytes are not a deflate stream", async () => {
    // A stored member relabelled as compressed: the engine's inflate rejects,
    // and a rejected promise from a file the user chose is the throw this
    // module exists not to do.
    const archive = zipOf({ name: "export.data", body: JSON_BODY, method: STORED });
    // Offset 10 of a central-directory entry is the compression method.
    const patched = patchDirectory(archive, 10, 2, DEFLATED);

    expect(await problemReading(patched, "export.data")).toBe(
      'The compressed contents of "export.data" could not be expanded, so the file is damaged',
    );
  });

  it("refuses a member whose local header is not where the directory says", async () => {
    const archive = zipOf({ name: "export.data", body: JSON_BODY });
    // Offset 42 of a central-directory entry is the local header's offset.
    const patched = patchDirectory(archive, 42, 4, 3);

    expect(await problemReading(patched, "export.data")).toBe(
      'This archive\'s record of where "export.data" begins does not point at a file header, ' +
        "so the archive is damaged",
    );
  });
});

describe("openZip, against the committed .1pux fixture", () => {
  const FIXTURE = "1password-export.1pux";

  it("names the three entries 1Password's format defines plus the fixture notice", () => {
    expect(opened(readFixture(FIXTURE)).names).toEqual([
      "KEYHOLE-FIXTURE-NOTICE.txt",
      "export.attributes",
      "export.data",
    ]);
  });

  it("reads export.data as the JSON an account, a vault and an item nest in", async () => {
    const text = await textOf(readFixture(FIXTURE), "export.data");

    expect(JSON.parse(text)).toMatchObject({
      accounts: [{ vaults: [{ attrs: { name: "Personal" }, items: [{ categoryUuid: "001" }] }] }],
    });
  });

  it("reads export.attributes, which is how a caller can check the export's version", async () => {
    const text = await textOf(readFixture(FIXTURE), "export.attributes");

    expect(JSON.parse(text)).toMatchObject({
      version: 3,
      description: "1Password Unencrypted Export",
    });
  });
});
