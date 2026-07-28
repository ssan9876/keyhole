import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  FORMAT_SIGNATURES,
  detect,
  probe,
  type FormatSignatureId,
  type ImportParser,
  type ImportVendor,
} from "./detect.js";

/**
 * Where the fixtures live, resolved from the running test file's own path.
 *
 * Not from `import.meta.url`, which under this project's jsdom environment is an
 * http URL that `fileURLToPath` rejects; and not from `process.cwd()`, which
 * would silently depend on the directory vitest was started in.
 */
const fixtureDir = (): string => {
  const testPath = expect.getState().testPath;
  if (testPath === undefined) {
    throw new Error("vitest reported no test path, so fixtures cannot be located");
  }
  return join(dirname(testPath), "fixtures");
};

// utf8 for every fixture, the .1pux included. Its first four bytes are the ZIP
// magic, all below U+0080, so they survive the decode intact — and the rest of
// the archive turning into replacement characters is exactly what the browser's
// File.text() would hand detect() too.
const read = (file: string): string => readFileSync(join(fixtureDir(), file), "utf8");

/** The sentence every fixture carries so a stray copy cannot be mistaken for a vault. */
const NOTICE = "GENERATED FIXTURE - no real credential appears in this file";

interface Fixture {
  /** File in `fixtures/`, and also the name handed to `detect`. */
  readonly file: string;
  /** The one signature that may claim this file; `null` for the generic fallback. */
  readonly signature: FormatSignatureId | null;
  readonly parser: ImportParser;
  readonly vendors: readonly ImportVendor[];
  /** What the fixture is for, when the file alone does not say. */
  readonly note?: string;
}

/**
 * Every fixture and the single answer detection owes it.
 *
 * Two guards below keep this table honest: one fails if a file appears in
 * `fixtures/` without a row here, the other if a signature in `detect.ts` has no
 * fixture at all. Without them the cross-check silently shrinks as formats are
 * added, which is the failure mode a per-format test suite already has.
 */
const FIXTURES: readonly Fixture[] = [
  {
    file: "bitwarden-export.csv",
    signature: "bitwarden-csv",
    parser: "bitwarden-csv",
    vendors: ["bitwarden"],
  },
  {
    file: "bitwarden-export.json",
    signature: "bitwarden-json",
    parser: "bitwarden-json",
    vendors: ["bitwarden"],
  },
  {
    file: "lastpass-export.csv",
    signature: "lastpass-csv",
    parser: "lastpass-csv",
    vendors: ["lastpass"],
  },
  {
    file: "chrome-passwords.csv",
    signature: "chromium-csv",
    parser: "browser-csv",
    vendors: ["chrome"],
    note: "byte-identical to the Edge and Brave fixtures; only the name differs",
  },
  {
    file: "microsoft-edge-passwords.csv",
    signature: "chromium-csv",
    parser: "browser-csv",
    vendors: ["edge"],
  },
  {
    file: "brave-passwords.csv",
    signature: "chromium-csv",
    parser: "browser-csv",
    vendors: ["brave"],
  },
  {
    file: "firefox-logins.csv",
    signature: "firefox-csv",
    parser: "browser-csv",
    vendors: ["firefox"],
  },
  {
    file: "safari-passwords.csv",
    signature: "safari-csv",
    parser: "browser-csv",
    vendors: ["safari"],
  },
  {
    file: "1password-export.csv",
    signature: "onepassword-csv",
    parser: "onepassword-csv",
    vendors: ["onepassword"],
  },
  {
    file: "1password-export.1pux",
    signature: "onepassword-1pux",
    parser: "onepassword-1pux",
    vendors: ["onepassword"],
    note: "a real ZIP archive, stored uncompressed so its JSON stays readable",
  },
  {
    file: "keepassxc-export.csv",
    signature: "keepassxc-csv",
    parser: "keepass-csv",
    vendors: ["keepassxc"],
  },
  {
    file: "keepass2-export.csv",
    signature: "keepass-csv",
    parser: "keepass-csv",
    vendors: ["keepass"],
  },
  {
    file: "nordpass-export.csv",
    signature: "nordpass-csv",
    parser: "nordpass-csv",
    vendors: ["nordpass"],
  },
  {
    file: "dashlane-credentials.csv",
    signature: "dashlane-csv",
    parser: "dashlane-csv",
    vendors: ["dashlane"],
  },
  {
    file: "dashlane-export.json",
    signature: "dashlane-json",
    parser: "dashlane-json",
    vendors: ["dashlane"],
  },
  {
    file: "proton-pass-export.json",
    signature: "protonpass-json",
    parser: "protonpass-json",
    vendors: ["protonpass"],
  },
  {
    file: "keeper-export.json",
    signature: "keeper-json",
    parser: "keeper-json",
    vendors: ["keeper"],
  },
  {
    file: "keeper-export.csv",
    signature: null,
    parser: "generic-csv",
    vendors: [],
    note: "Keeper's CSV export has no header row, so there is nothing to detect on",
  },
  {
    file: "unknown-manager-export.csv",
    signature: null,
    parser: "generic-csv",
    vendors: [],
    note: "stands for every manager not on the list",
  },
];

const claimedBy = (file: string, content: string): FormatSignatureId[] => {
  const evidence = probe(file, content);
  return FORMAT_SIGNATURES.filter((signature) => signature.match(evidence) !== null).map(
    (signature) => signature.id,
  );
};

describe("detect, against one sample export per format", () => {
  for (const fixture of FIXTURES) {
    const claim =
      fixture.vendors.length === 0
        ? "the generic mapper and no vendor"
        : `the ${fixture.parser} parser, from ${fixture.vendors.join(" or ")}`;

    it(`reads ${fixture.file} as ${claim}`, () => {
      expect(detect(fixture.file, read(fixture.file))).toEqual({
        parser: fixture.parser,
        vendors: fixture.vendors,
      });
    });
  }
});

/**
 * The suite that earns its keep.
 *
 * "Every fixture detects as itself" passes even when a signature is broad enough
 * to swallow three other formats, because `detect` returns on the first match
 * and the ordering hides it. So this runs every fixture past every signature and
 * demands exactly one claim — an over-broad rule then fails on the *other*
 * format's test, where a maintainer will actually see it.
 */
describe("no fixture is claimed by another format's signature", () => {
  for (const fixture of FIXTURES) {
    const expected = fixture.signature === null ? [] : [fixture.signature];
    const claim =
      fixture.signature === null
        ? "no signature at all claims"
        : `only ${fixture.signature} claims`;

    it(`${claim} ${fixture.file}`, () => {
      expect(claimedBy(fixture.file, read(fixture.file))).toEqual(expected);
    });
  }
});

describe("the fixture set and the signature list stay in step", () => {
  it("has a table row for every file in fixtures/, so none escapes the cross-check", () => {
    const onDisk = readdirSync(fixtureDir())
      .filter((name) => name !== "README.md")
      .sort();

    expect(onDisk).toEqual(FIXTURES.map((fixture) => fixture.file).sort());
  });

  it("has at least one fixture for every signature in detect.ts", () => {
    const covered = new Set(FIXTURES.map((fixture) => fixture.signature));

    const uncovered = FORMAT_SIGNATURES.filter((signature) => !covered.has(signature.id));

    expect(uncovered.map((signature) => signature.id)).toEqual([]);
  });

  it("carries the generated-fixture notice inside every fixture's own bytes", () => {
    // A fixture that escapes this repo must announce on sight that it is not
    // somebody's vault. The .1pux is included: its entries are stored rather
    // than deflated precisely so the sentence survives into the archive's bytes.
    const missing = FIXTURES.filter((fixture) => !read(fixture.file).includes(NOTICE));

    expect(missing.map((fixture) => fixture.file)).toEqual([]);
  });
});

describe("detect, where the file cannot name its own vendor", () => {
  it("names all three Chromium browsers when the download has been renamed", () => {
    // Not a hedge: Chrome, Edge and Brave ship the same exporter, so a file
    // called passwords.csv carries no evidence of which one wrote it. Answering
    // "chrome" here would be a guess the caller could not tell from a finding.
    expect(detect("passwords.csv", read("chrome-passwords.csv"))).toEqual({
      parser: "browser-csv",
      vendors: ["chrome", "edge", "brave"],
    });
  });

  it("keeps the Chrome, Edge and Brave fixtures byte-identical", () => {
    // The test above is only meaningful while this holds. If someone edits one
    // of the three, the filename stops being the only difference and the
    // ambiguity this module reports would quietly become detectable.
    const chrome = read("chrome-passwords.csv");

    expect(read("microsoft-edge-passwords.csv")).toBe(chrome);
    expect(read("brave-passwords.csv")).toBe(chrome);
  });

  it("still names Edge when the export is nested in a directory path", () => {
    // The vendor is read from the file's own name, not the path it arrived by,
    // so a Downloads folder called "chrome" cannot rename an Edge export.
    expect(detect("C:/Users/ada/chrome/microsoft-edge-passwords.csv", read("chrome-passwords.csv")))
      .toEqual({ parser: "browser-csv", vendors: ["edge"] });
  });
});

describe("detect, on files mangled in transit", () => {
  it("detects a Bitwarden export whose first column name carries a UTF-8 BOM", () => {
    // A BOM makes the first header name "\uFEFFfolder". Every column lookup
    // after that misses, and the export lands in the generic mapper as if it
    // came from a manager nobody supports.
    expect(detect("bitwarden-export.csv", "\uFEFF" + read("bitwarden-export.csv"))).toEqual({
      parser: "bitwarden-csv",
      vendors: ["bitwarden"],
    });
  });

  it("detects a KeePassXC export saved with CRLF line endings", () => {
    // Windows exports end rows with CRLF. Split on "\n" and the last header name
    // becomes "created\r", which is not a column any signature asks for. The
    // conversion is applied here rather than shipped in the fixture because
    // .gitattributes normalises the checkout to LF, which would erase it.
    const crlf = read("keepassxc-export.csv").replaceAll("\n", "\r\n");

    expect(detect("keepassxc-export.csv", crlf)).toEqual({
      parser: "keepass-csv",
      vendors: ["keepassxc"],
    });
  });

  it("detects a Chrome export whose header the browser wrote in capitals", () => {
    // Column names are matched lowercased. Firefox's own importer does the same,
    // and an export edited in a spreadsheet comes back with the case changed.
    const shouted = read("chrome-passwords.csv").replace(
      "name,url,username,password,note",
      "Name,URL,Username,Password,Note",
    );

    expect(detect("chrome-passwords.csv", shouted)).toEqual({
      parser: "browser-csv",
      vendors: ["chrome"],
    });
  });
});

describe("detect, on files it cannot place", () => {
  it("routes an unrecognised CSV to the generic mapper instead of refusing it", () => {
    const result = detect("unknown-manager-export.csv", read("unknown-manager-export.csv"));

    expect(result.parser).toBe("generic-csv");
    expect(result.vendors).toEqual([]);
  });

  it("answers for an empty file rather than throwing on the missing header", () => {
    expect(detect("empty.csv", "")).toEqual({ parser: "generic-csv", vendors: [] });
  });

  it("answers for JSON that parses but matches nothing", () => {
    expect(detect("something.json", '{"totally":"unrelated"}')).toEqual({
      parser: "generic-csv",
      vendors: [],
    });
  });

  it("answers for JSON that does not parse at all", () => {
    // A truncated download is a file we cannot name, not an exception to raise.
    expect(detect("truncated.json", '{"items": [{"name": "Exampl')).toEqual({
      parser: "generic-csv",
      vendors: [],
    });
  });

  it("refuses to call a bare ZIP a 1pux, since Dashlane and Proton also ship ZIPs", () => {
    // The magic bytes alone would claim any archive. Both halves are required.
    expect(detect("export.zip", read("1password-export.1pux"))).toEqual({
      parser: "generic-csv",
      vendors: [],
    });
  });

  it("refuses to call a renamed CSV a 1pux, since the bytes are not an archive", () => {
    expect(detect("pretend.1pux", read("bitwarden-export.csv"))).toEqual({
      parser: "bitwarden-csv",
      vendors: ["bitwarden"],
    });
  });
});
