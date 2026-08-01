import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { renderHook } from "@testing-library/react";
import { fakeApi, openSession } from "../../../../packages/vault/src/test-helpers.js";
import type { ItemRecord, LoginItem, CollectionSummary, VaultState, VaultStore } from "@keyhole/vault";
import { DEFLATED, zipOf } from "../../../../packages/vault/src/import/zip-fixture.js";
import { useImportPanel } from "./useImportPanel.js";

/**
 * The controller behind the import screen. These tests exercise the two things
 * only the hook can get wrong: the bytes-vs-text seam (a `.1pux` is a ZIP and
 * must reach its parser as bytes, never as decoded text) and the wiring of
 * parse → dedupe → encrypt-and-upload against a real session.
 */

/** A fixture's text, from the import fixtures directory in packages/vault. */
function fixture(file: string): string {
  const testPath = expect.getState().testPath;
  if (testPath === undefined) throw new Error("vitest reported no test path");
  return readFileSync(
    join(dirname(testPath), "..", "..", "..", "..", "packages", "vault", "src", "import", "fixtures", file),
    "utf8",
  );
}

/**
 * A `File` whose bytes the hook can read.
 *
 * jsdom's own `File` has no `arrayBuffer()`, and the hook reads the upload as an
 * `ArrayBuffer` — the whole seam this suite exists to test. The hook consumes
 * exactly `name` and `arrayBuffer()`, both of which a real browser `File`
 * provides, so this stands in for one without dragging in a jsdom limitation
 * that production never hits.
 */
function fileOf(name: string, content: string | Uint8Array): File {
  const bytes = typeof content === "string" ? new TextEncoder().encode(content) : content;
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  return { name, arrayBuffer: async () => buffer } as unknown as File;
}

function fakeStore(
  items: ItemRecord[] = [],
  collections: CollectionSummary[] = [],
): { store: VaultStore; resync: ReturnType<typeof vi.fn> } {
  const state: VaultState = { revision: 1, items, folders: [], collections, status: "ready", error: null };
  const resync = vi.fn().mockResolvedValue(undefined);
  const store: VaultStore = {
    getState: () => state,
    subscribe: () => () => undefined,
    async load() {},
    resync,
    upsert() {},
    remove() {},
    clear() {},
  };
  return { store, resync };
}

function existingLogin(username: string, urls: string[]): ItemRecord {
  const plaintext: LoginItem = {
    type: "login",
    name: "Existing",
    username,
    password: "irrelevant-to-comparison",
    urls,
    notes: "",
    favorite: false,
    folderId: null,
    passwordHistory: [],
  };
  return { id: "existing-1", revision: 1, collectionId: null, deletedAt: null, plaintext };
}

describe("useImportPanel, the bytes-vs-text seam", () => {
  it("reads a .1pux from its bytes, so the ZIP survives to the parser", async () => {
    // A .1pux is a ZIP holding export.data. If the hook read it as text first,
    // the archive's non-ASCII header bytes would be replaced and the parser
    // would report a corrupt archive with no items. A parsed login is the proof
    // the bytes reached parseOnePassword1pux untouched.
    const exportData = JSON.stringify({
      accounts: [
        {
          attrs: { name: "Personal" },
          vaults: [
            {
              attrs: { name: "Private" },
              items: [
                {
                  overview: { title: "Example Login", url: "https://example.com", urls: [{ url: "https://example.com" }] },
                  categoryUuid: "001",
                  state: "active",
                  details: {
                    loginFields: [
                      { designation: "username", value: "ada@example.com" },
                      { designation: "password", value: "onepassword-fixture-pw" },
                    ],
                  },
                },
              ],
            },
          ],
        },
      ],
    });
    const archive = zipOf({ name: "export.data", body: exportData, method: DEFLATED });
    const file = fileOf("vault.1pux", archive);

    const { store } = fakeStore();
    const session = openSession();
    const api = fakeApi();
    const { result } = renderHook(() => useImportPanel({ api, session, store }));

    const inspected = await result.current.onInspect(file);
    expect(inspected.format).toBe("onepassword-1pux");

    const preview = await result.current.onPreview({ file, format: "onepassword-1pux", mapping: null });
    expect(preview.errors).toEqual([]);
    expect(preview.rows).toHaveLength(1);
    expect(preview.rows[0]?.name).toBe("Example Login");
    expect(preview.rows[0]?.username).toBe("ada@example.com");
    // The start of the password only, which is what makes a shifted column
    // visible without printing the secret.
    expect(preview.rows[0]?.passwordPreview).toBe("one…");
  });
});

describe("useImportPanel, detecting and previewing a text export", () => {
  it("detects a Bitwarden JSON export and previews its items and the card it cannot read", async () => {
    const file = fileOf("bitwarden-export.json", fixture("bitwarden-export.json"));
    const { store } = fakeStore();
    const { result } = renderHook(() =>
      useImportPanel({ api: fakeApi(), session: openSession(), store }),
    );

    const inspected = await result.current.onInspect(file);
    expect(inspected.format).toBe("bitwarden-json");
    expect(inspected.vendors).toContain("bitwarden");

    const preview = await result.current.onPreview({ file, format: "bitwarden-json", mapping: null });
    expect(preview.rows.map((row) => row.name)).toEqual(["Example Mail", "Router notes", "Example Forum"]);
    // The card is reported, never dropped, so "imported 3 of 4" is a number the
    // user can act on.
    expect(preview.errors).toHaveLength(1);
    expect(preview.errors[0]?.row).toBe(4);
    expect(preview.errors[0]?.message).toMatch(/card/i);
    expect(preview.rows.find((row) => row.name === "Example Mail")?.passwordPreview).toBe("fix…");
  });

  it("reports a row already in the vault as a duplicate, matched on host and username", async () => {
    const file = fileOf("bw.json", fixture("bitwarden-export.json"));
    // Same host and username as the fixture's "Example Mail", exported with a
    // different URL path — which is exactly the case dedupe compares on host for.
    const existing = existingLogin("ada@example.com", ["https://mail.example.com/inbox"]);
    const { store } = fakeStore([existing]);
    const { result } = renderHook(() =>
      useImportPanel({ api: fakeApi(), session: openSession(), store }),
    );

    const preview = await result.current.onPreview({ file, format: "bitwarden-json", mapping: null });

    expect(preview.duplicates.groups).toHaveLength(1);
    expect(preview.duplicates.groups[0]?.key.host).toBe("mail.example.com");
    expect(preview.duplicates.groups[0]?.existing).toHaveLength(1);
  });
});

describe("useImportPanel, the generic column mapper", () => {
  it("reads the password from the chosen column and carries an unmapped column into the notes", async () => {
    const csv = "account,secret,note\nExample,s3cr3t-value,a memo\n";
    const file = fileOf("unknown-manager.csv", csv);
    const { store } = fakeStore();
    const { result } = renderHook(() =>
      useImportPanel({ api: fakeApi(), session: openSession(), store }),
    );

    const inspected = await result.current.onInspect(file);
    expect(inspected.format).toBe("generic-csv");
    expect(inspected.header).toEqual(["account", "secret", "note"]);

    // The user maps "secret" as the password and clears the notes mapping, so
    // "note" is left over and must be carried rather than dropped.
    const mapping = { ...inspected.suggestedMapping, name: "account", password: "secret", notes: null };
    const preview = await result.current.onPreview({ file, format: "generic-csv", mapping });

    expect(preview.rows).toHaveLength(1);
    expect(preview.rows[0]?.name).toBe("Example");
    expect(preview.rows[0]?.passwordPreview).toBe("s3c…");
    // "note" was placed nowhere, so it becomes a carried field rather than
    // silently vanishing.
    expect(preview.rows[0]?.carriedCount).toBeGreaterThanOrEqual(1);
  });
});

describe("useImportPanel, importing", () => {
  it("uploads only the rows not skipped and returns the server-confirmed count", async () => {
    const file = fileOf("bw.json", fixture("bitwarden-export.json"));
    const posted: { items: unknown[] }[] = [];
    const api = fakeApi({
      post: async (path, body) => {
        if (path === "/api/items/bulk") {
          posted.push(body as { items: unknown[] });
          return null;
        }
        throw new Error(`unexpected POST ${path}`);
      },
    });
    const { store, resync } = fakeStore();
    const { result } = renderHook(() => useImportPanel({ api, session: openSession(), store }));

    // Three items parse (two logins and a note); skip the first (Example Mail).
    const outcome = await result.current.onImport({
      file,
      format: "bitwarden-json",
      mapping: null,
      skipRows: [0],
      collectionId: null,
    });

    // The count is what the server confirmed, and it is two — the skipped row
    // never reached the request.
    expect(outcome.uploaded).toBe(2);
    expect(outcome.total).toBe(2);
    expect(posted).toHaveLength(1);
    expect(posted[0]?.items).toHaveLength(2);
    // The imported items appear in the vault without a reload.
    expect(resync).toHaveBeenCalled();
  });

  it("never sends a known plaintext password in a request body", async () => {
    // The whole point of the flow: plaintext is encrypted in the browser and
    // only ciphertext is posted. Searched as the literal string, the needle a
    // leak would actually take.
    const file = fileOf("bw.json", fixture("bitwarden-export.json"));
    const bodies: string[] = [];
    const api = fakeApi({
      post: async (path, body) => {
        if (path === "/api/items/bulk") {
          bodies.push(JSON.stringify(body));
          return null;
        }
        throw new Error(`unexpected POST ${path}`);
      },
    });
    const { store } = fakeStore();
    const { result } = renderHook(() => useImportPanel({ api, session: openSession(), store }));

    await result.current.onImport({
      file,
      format: "bitwarden-json",
      mapping: null,
      skipRows: [],
      collectionId: null,
    });

    for (const body of bodies) {
      expect(body).not.toContain("fixture-pw-8Hq2vN");
      expect(body).not.toContain("fixture,pw,with,commas");
    }
  });
});
