import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Runtime code in src/ must run unmodified in a browser. Nothing in the build
 * enforces that: vitest.config.ts runs the Node environment and tsconfig.json
 * puts "types": ["node"] on the whole package, so a `node:buffer` import in
 * runtime code would typecheck, pass every test, and only fail once the web app
 * shipped. Tests and scripts/ are exempt — they never reach a browser.
 */
const NODE_BUILTINS = new Set([
  "assert",
  "buffer",
  "child_process",
  "crypto",
  "events",
  "fs",
  "http",
  "https",
  "net",
  "os",
  "path",
  "process",
  "stream",
  "url",
  "util",
  "worker_threads",
  "zlib",
]);

const srcDir = dirname(fileURLToPath(import.meta.url));

/** Recurses into subdirectories so a future src/ subfolder cannot silently
 *  escape the node: import check below. Paths are returned relative to
 *  srcDir (e.g. "nested/probe.ts") so callers can still join(srcDir, name). */
function runtimeSourceFiles(dir: string = srcDir): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const entryPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...runtimeSourceFiles(entryPath));
    } else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) {
      files.push(relative(srcDir, entryPath));
    }
  }
  return files;
}

/** Every module specifier in the file: `from "x"`, `import "x"`, `require("x")`. */
function importSpecifiers(source: string): string[] {
  const specifiers: string[] = [];
  const patterns = [
    /\bfrom\s*["']([^"']+)["']/gu,
    /\bimport\s*\(\s*["']([^"']+)["']/gu,
    /\bimport\s+["']([^"']+)["']/gu,
    /\brequire\s*\(\s*["']([^"']+)["']/gu,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      specifiers.push(match[1] as string);
    }
  }
  return specifiers;
}

describe("browser safety", () => {
  // Without this, a scan that silently found nothing would report success —
  // the exact way a guard test comes to assert nothing.
  it("actually scans the runtime source", () => {
    const files = runtimeSourceFiles();
    expect(files.length).toBeGreaterThan(5);
    expect(files).toContain("index.ts");
    expect(files).not.toContain("keys.test.ts");
    expect(importSpecifiers(readFileSync(join(srcDir, "keys.ts"), "utf8"))).toContain(
      "@noble/curves/ed25519",
    );
  });

  it("imports no Node builtin anywhere in runtime source", () => {
    const offenders: string[] = [];
    for (const name of runtimeSourceFiles()) {
      const source = readFileSync(join(srcDir, name), "utf8");
      for (const specifier of importSpecifiers(source)) {
        if (specifier.startsWith("node:") || NODE_BUILTINS.has(specifier)) {
          offenders.push(`${name} imports ${specifier}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  // Proves the detector works, so a future refactor cannot neuter it and leave
  // the suite green.
  it("detects a Node import when one is present", () => {
    const sample = 'import { Buffer } from "node:buffer";\nimport { join } from "path";\n';
    const found = importSpecifiers(sample).filter(
      (specifier) => specifier.startsWith("node:") || NODE_BUILTINS.has(specifier),
    );
    expect(found).toEqual(["node:buffer", "path"]);
  });
});
