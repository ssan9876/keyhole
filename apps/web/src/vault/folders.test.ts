import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  decryptString,
  encryptString,
  generateUserKey,
  toBase64,
  utf8Encode,
} from "@keyhole/crypto";
import { ApiError } from "./api.js";
import {
  FolderConflictError,
  createFolder,
  decryptFolders,
  renameFolder,
  type WireFolder,
} from "./folders.js";
import { fakeApi, sessionWithUserKey } from "./test-helpers.js";

/**
 * Counts every call the module under test makes to the real `decryptString`,
 * while still running the real one. The tombstone test needs to prove a folder
 * with no name to open is *not* fed to decryption at all — a result of
 * `name: null` alone cannot show that, because a failed decrypt also yields
 * null.
 *
 * `vi.hoisted` because `vi.mock`'s factory is hoisted above every `const` here
 * and runs at import time, so a plain module-level object would still be in its
 * temporal dead zone when the factory closes over it.
 */
const { decrypt } = vi.hoisted(() => ({ decrypt: { calls: 0 } }));

vi.mock("@keyhole/crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@keyhole/crypto")>();
  return {
    ...actual,
    decryptString: async (...args: Parameters<typeof actual.decryptString>) => {
      decrypt.calls += 1;
      return actual.decryptString(...args);
    },
  };
});

beforeEach(() => {
  decrypt.calls = 0;
});

function wireFolder(overrides: Partial<WireFolder> = {}): WireFolder {
  return {
    id: "f1",
    encryptedName: "",
    revision: 1,
    deletedAt: null,
    ...overrides,
  };
}

describe("decryptFolders", () => {
  it("decrypts a folder name back to plaintext", async () => {
    const userKey = generateUserKey();
    const encryptedName = await encryptString("Work", userKey);

    const [record] = await decryptFolders([wireFolder({ encryptedName })], userKey);

    expect(record?.name).toBe("Work");
  });

  it("returns an undecryptable folder with name null instead of dropping it", async () => {
    const userKey = generateUserKey();
    const good = await encryptString("Readable", userKey);

    const records = await decryptFolders(
      [
        wireFolder({ id: "bad", encryptedName: "not-an-envelope" }),
        wireFolder({ id: "good", encryptedName: good }),
      ],
      userKey,
    );

    // One folder whose name will not open must not blank out the whole list;
    // the UI renders name === null as "couldn't decrypt this folder".
    expect(records).toHaveLength(2);
    expect(records.find((r) => r.id === "bad")?.name).toBeNull();
    expect(records.find((r) => r.id === "good")?.name).toBe("Readable");
  });

  it("returns a tombstone with name null and never attempts to decrypt it", async () => {
    // A deleted folder has had its name cleared server-side, so encryptedName
    // may be blank. Feeding a blank string to decryptString would throw; the
    // contract is that the tombstone is skipped, not decrypted-and-caught.
    const records = await decryptFolders(
      [wireFolder({ deletedAt: "2026-01-02T00:00:00Z", encryptedName: "" })],
      generateUserKey(),
    );

    expect(records[0]?.name).toBeNull();
    expect(records[0]?.deletedAt).not.toBeNull();
    expect(decrypt.calls).toBe(0);
  });
});

describe("createFolder", () => {
  it("sends a ciphertext that decrypts back to the typed name under the userKey", async () => {
    const userKey = generateUserKey();
    let sent: { encryptedName: string } | null = null;
    const api = fakeApi({
      post: async (_path, body) => {
        sent = body as { encryptedName: string };
        return wireFolder({ id: "new", encryptedName: sent.encryptedName });
      },
    });

    const record = await createFolder({ api, session: sessionWithUserKey(userKey) }, "Travel Documents");

    // The proof the name made the round trip: the exact blob the request
    // carried opens to the typed name under the userKey.
    await expect(decryptString(sent!.encryptedName, userKey)).resolves.toBe("Travel Documents");
    expect(record.name).toBe("Travel Documents");
  });

  it("never carries the plaintext folder name in the request body", async () => {
    const userKey = generateUserKey();
    const name = "Travel Documents";
    let sent: unknown = null;
    const api = fakeApi({
      post: async (_path, body) => {
        sent = body;
        return wireFolder({ id: "new", encryptedName: (body as { encryptedName: string }).encryptedName });
      },
    });

    await createFolder({ api, session: sessionWithUserKey(userKey) }, name);

    const dump = JSON.stringify(sent);
    // Searched two ways on purpose: the literal string catches a name left in
    // the clear, and base64-of-the-bytes catches a name that was merely encoded
    // rather than encrypted. A decimal or hex needle would miss both while the
    // value sat in plain sight.
    expect(dump).not.toContain(name);
    expect(dump).not.toContain(toBase64(utf8Encode(name)));
  });
});

describe("renameFolder", () => {
  it("sends the revision it was given", async () => {
    const userKey = generateUserKey();
    let sent: { revision: number } | null = null;
    const api = fakeApi({
      put: async (_path, body) => {
        sent = body as { revision: number };
        return wireFolder({ id: "f1", revision: 8 });
      },
    });

    await renameFolder({ api, session: sessionWithUserKey(userKey) }, "f1", 7, "Renamed");

    // The server rejects a stale revision with 409; sending the wrong one turns
    // every rename into a phantom conflict.
    expect(sent!.revision).toBe(7);
  });

  it("raises a typed conflict carrying the server's current folder", async () => {
    const userKey = generateUserKey();
    const winner = wireFolder({ id: "f1", revision: 9, encryptedName: "theirs" });
    const api = fakeApi({
      put: async () => {
        throw new ApiError("conflict", 409, "changed", {
          error: { code: "conflict", message: "changed" },
          folder: winner,
        });
      },
    });

    const error = (await renameFolder(
      { api, session: sessionWithUserKey(userKey) },
      "f1",
      1,
      "Mine",
    ).catch((e: unknown) => e)) as FolderConflictError;

    // Without the winning row the client cannot show the user what they are
    // colliding with, so it hands the current folder back on the error.
    expect(error).toBeInstanceOf(FolderConflictError);
    expect(error.current.revision).toBe(9);
  });
});
