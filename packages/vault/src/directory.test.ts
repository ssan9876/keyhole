import { describe, expect, it } from "vitest";
import { generateKeyPair, publicKeyFingerprint, toBase64 } from "@keyhole/crypto";
import { loadDirectory } from "./directory.js";
import { fakeApi } from "./test-helpers.js";

describe("loadDirectory", () => {
  it("computes each entry's fingerprint from its public key and email", async () => {
    const them = generateKeyPair();
    const api = fakeApi({
      get: async () => ({
        users: [
          { id: "u2", name: "Bee", email: "bee@example.com", publicKey: toBase64(them.publicKey) },
        ],
      }),
    });

    const [entry] = await loadDirectory({ api });

    // Recomputed here from the same inputs: a fingerprint that is merely
    // "some string" would satisfy a truthiness check while displaying a value
    // the other person's client never produces, defeating the comparison the
    // fingerprint exists for.
    expect(entry?.fingerprint).toBe(publicKeyFingerprint(them.publicKey, "bee@example.com"));
    expect(entry?.fingerprint).not.toBe("");
  });

  it("skips an entry whose public key is not valid base64 rather than failing the whole list", async () => {
    const them = generateKeyPair();
    const api = fakeApi({
      get: async () => ({
        users: [
          { id: "u2", name: "Bad", email: "bad@example.com", publicKey: "!!! not base64 !!!" },
          { id: "u3", name: "Good", email: "good@example.com", publicKey: toBase64(them.publicKey) },
        ],
      }),
    });

    const entries = await loadDirectory({ api });

    expect(entries.map((e) => e.id)).toEqual(["u3"]);
  });

  it("returns an empty list when the server sends no users", async () => {
    const api = fakeApi({ get: async () => ({ users: [] }) });
    await expect(loadDirectory({ api })).resolves.toEqual([]);
  });
});
