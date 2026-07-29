import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { expect } from "vitest";
import type { ImportItem, ImportResult } from "../types.js";

/**
 * What every parser test needs to reach a fixture and read one item out of a
 * result.
 *
 * Written once here rather than a seventh time: `browser.test.ts` and
 * `bitwarden.test.ts` each carry their own copy, and six more test files were
 * about to. Those two keep their copies deliberately — the extraction of
 * `shared.ts` was proved by their passing byte-for-byte unmodified, and
 * rewriting them afterwards would spend that proof for a tidier import list.
 *
 * Not a `.test.ts` file, so vitest does not collect it as a suite with no
 * tests in it.
 */

/**
 * A fixture's text.
 *
 * Located from the running test file's own path, for the reasons
 * `detect.test.ts` sets out: `import.meta.url` is an http URL under this
 * project's jsdom environment, and `process.cwd()` depends on where vitest was
 * started. One directory up from `parsers/`.
 */
export function read(file: string): string {
  const testPath = expect.getState().testPath;
  if (testPath === undefined) {
    throw new Error("vitest reported no test path, so fixtures cannot be located");
  }
  return readFileSync(join(dirname(testPath), "..", "fixtures", file), "utf8");
}

/**
 * The header line of a CSV fixture, so an inline case cannot pass against a
 * header the test invented.
 *
 * Every case that is not a golden builds its file from a *real* header plus
 * rows written in the test. That keeps the part with provenance — the column
 * names and their order, recorded in `.superpowers/sdd/task-2-report.md` — out
 * of the test's hands while letting a case exercise a row no fixture contains.
 */
export function headerLine(file: string): string {
  // Split on both endings: .gitattributes normalises the checkout to LF, but a
  // `\r` left on the header would attach to its last column name and every
  // lookup for that column would miss.
  const [first] = read(file).split(/\r?\n/);
  if (first === undefined || first === "") {
    throw new Error(`${file} has no header line`);
  }
  return first;
}

/** A CSV made of a fixture's real header and rows written by the test. */
export function withRows(file: string, ...rows: string[]): string {
  return [headerLine(file), ...rows].join("\n");
}

/**
 * The one item of a single-item case.
 *
 * Indexing is checked rather than optional-chained: `result.items[0]?.password`
 * is `undefined` for a row that failed to parse, which silently satisfies an
 * assertion about an absent field instead of failing it.
 */
export function only(result: ImportResult): ImportItem {
  const [item, ...rest] = result.items;
  if (item === undefined || rest.length > 0) {
    throw new Error(
      `expected exactly one item, got ${result.items.length}; ` +
        `errors: ${JSON.stringify(result.errors)}`,
    );
  }
  return item;
}

/** The sentence every fixture carries so a stray copy is not mistaken for a vault. */
export const NOTICE = "GENERATED FIXTURE - no real credential appears in this file";
