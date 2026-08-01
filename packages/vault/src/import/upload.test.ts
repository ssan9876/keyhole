import { decryptItem, toBase64, utf8Encode, type ItemPlaintext } from "@keyhole/crypto";
import { describe, expect, it } from "vitest";
import { ApiError, NetworkError, type ApiClient } from "../api.js";
import { openSession, sessionWithCollectionKeys } from "../test-helpers.js";
import { MAX_BODY_BYTES, MAX_ITEMS_PER_REQUEST, uploadItems } from "./upload.js";

/** A password that appears in no fixture, so a hit in a body is this test's. */
const SECRET = "fixture-pw-8Hq2vN-leak-canary";

function login(name: string, password = SECRET): ItemPlaintext {
  return {
    type: "login",
    name,
    username: "ada",
    password,
    urls: ["https://mail.example.com"],
    notes: "",
    favorite: false,
    folderId: null,
    passwordHistory: [],
  };
}

function manyLogins(count: number): ItemPlaintext[] {
  return Array.from({ length: count }, (_, index) => login(`item ${index}`));
}

interface BulkBody {
  items: { collectionId: string | null; ciphertext: string; wrappedItemKey: string }[];
}

/**
 * An api client that records every bulk request and answers as the server does.
 *
 * `fail` decides the fate of a request by its 1-based number, so a test can
 * break the fourth one without knowing anything about how the third was built.
 */
function recordingApi(fail: (request: number) => Error | null = () => null): {
  api: ApiClient;
  bodies: BulkBody[];
  paths: string[];
} {
  const bodies: BulkBody[] = [];
  const paths: string[] = [];
  const api: ApiClient = {
    get: () => Promise.reject(new Error("unexpected GET")),
    post: <T>(path: string, body?: unknown): Promise<T> => {
      paths.push(path);
      bodies.push(body as BulkBody);
      const error = fail(bodies.length);
      if (error !== null) return Promise.reject(error);
      const sent = (body as BulkBody).items;
      return Promise.resolve({
        items: sent.map((_, index) => ({ id: `id-${bodies.length}-${index}` })),
      } as T);
    },
    put: () => Promise.reject(new Error("unexpected PUT")),
    patch: () => Promise.reject(new Error("unexpected PATCH")),
    del: () => Promise.reject(new Error("unexpected DELETE")),
  };
  return { api, bodies, paths };
}

describe("uploadItems, on the batch sizes the server accepts", () => {
  it("sends exactly 1000 items in one request, the most the server takes", async () => {
    // internal/httpapi/items.go:15 rejects more than 1000. One item over the
    // line and the whole batch is refused.
    const { api, bodies } = recordingApi();
    const session = openSession();

    await uploadItems({ api, session }, manyLogins(MAX_ITEMS_PER_REQUEST));

    expect(bodies).toHaveLength(1);
    expect(bodies[0]?.items).toHaveLength(1000);
  });

  it("splits 1001 items into a request of 1000 and a request of 1", async () => {
    const { api, bodies } = recordingApi();
    const session = openSession();

    await uploadItems({ api, session }, manyLogins(MAX_ITEMS_PER_REQUEST + 1));

    expect(bodies.map((body) => body.items.length)).toEqual([1000, 1]);
  });

  it("sends every request to the bulk endpoint", async () => {
    const { api, paths } = recordingApi();
    const session = openSession();

    await uploadItems({ api, session }, manyLogins(1001));

    expect(paths).toEqual(["/api/items/bulk", "/api/items/bulk"]);
  });

  it("sends no request at all for an empty import", async () => {
    // The server answers an empty items array with a 400, so a request here
    // would turn "nothing to do" into a failed import.
    const { api, bodies } = recordingApi();
    const session = openSession();

    const outcome = await uploadItems({ api, session }, []);

    expect(bodies).toEqual([]);
    expect(outcome).toMatchObject({ uploaded: 0, total: 0, error: null });
  });

  it("keeps every request body under the server's 8 MiB cap by splitting on size", async () => {
    // 300 items is far under the 1000-item limit, so a count-only chunker sends
    // them in one request -- and the server rejects it on the body cap, with a
    // message about a limit the count never came near.
    const { api, bodies } = recordingApi();
    const session = openSession();
    const big = Array.from({ length: 300 }, (_, index) => ({
      ...login(`big ${index}`),
      notes: "x".repeat(30_000),
    }));

    const outcome = await uploadItems({ api, session }, big);

    expect(bodies.length).toBeGreaterThan(1);
    for (const body of bodies) {
      expect(JSON.stringify(body).length).toBeLessThan(MAX_BODY_BYTES);
    }
    expect(outcome).toMatchObject({ uploaded: 300, error: null });
  });
});

describe("uploadItems, on what it reports after a chunk fails", () => {
  it("reports the 3000 items that landed, not the 4000 it had sent by then", async () => {
    // The failure this test exists for: a count of what was attempted reads as
    // a count of what is in the vault, and the user retries the whole file.
    const { api } = recordingApi((request) =>
      request === 4 ? new ApiError("internal", 500, "boom", null) : null,
    );
    const session = openSession();

    const outcome = await uploadItems({ api, session }, manyLogins(3001));

    expect(outcome.uploaded).toBe(3000);
    expect(outcome.total).toBe(3001);
    expect(outcome.error).not.toBeNull();
  });

  it("stops at the failed chunk rather than carrying on to the ones after it", async () => {
    const { api, bodies } = recordingApi((request) =>
      request === 2 ? new ApiError("internal", 500, "boom", null) : null,
    );
    const session = openSession();

    await uploadItems({ api, session }, manyLogins(3001));

    expect(bodies).toHaveLength(2);
  });

  it("counts a chunk the server never answered as in doubt, not as failed", async () => {
    // The request left the browser and the reply did not come back. It may have
    // been written. Reporting it as simply not imported invites a retry that
    // duplicates 1000 items; reporting it as imported invites the opposite.
    const { api } = recordingApi((request) =>
      request === 2 ? new NetworkError(new Error("offline")) : null,
    );
    const session = openSession();

    const outcome = await uploadItems({ api, session }, manyLogins(2001));

    expect(outcome.uploaded).toBe(1000);
    expect(outcome.inDoubt).toBe(1000);
  });

  it("counts a chunk the server refused as not in doubt, because it said so", async () => {
    // A 4xx is the server declining before it wrote anything, which is the one
    // case where "these did not land" is a fact rather than an inference.
    const { api } = recordingApi((request) =>
      request === 2 ? new ApiError("bad_request", 400, "nope", null) : null,
    );
    const session = openSession();

    const outcome = await uploadItems({ api, session }, manyLogins(2001));

    expect(outcome.uploaded).toBe(1000);
    expect(outcome.inDoubt).toBe(0);
  });

  it("reports every item as landed and no error when every chunk was accepted", async () => {
    const { api } = recordingApi();
    const session = openSession();

    expect(await uploadItems({ api, session }, manyLogins(1001))).toEqual({
      uploaded: 1001,
      total: 1001,
      inDoubt: 0,
      error: null,
    });
  });

  it("reports progress as the count that has landed, after each chunk", async () => {
    const { api } = recordingApi();
    const session = openSession();
    const seen: number[] = [];

    await uploadItems({ api, session }, manyLogins(2001), {
      onProgress: (progress) => seen.push(progress.uploaded),
    });

    expect(seen).toEqual([1000, 2000, 2001]);
  });

  it("reports nothing uploaded, and sends nothing, for a collection it has no key for", async () => {
    const { api, bodies } = recordingApi();
    const session = openSession();

    const outcome = await uploadItems({ api, session }, manyLogins(3), {
      collectionId: "c-not-held",
    });

    expect(bodies).toEqual([]);
    expect(outcome).toMatchObject({ uploaded: 0, total: 3, inDoubt: 0 });
    expect(outcome.error?.message).toContain("collection");
  });
});

describe("uploadItems, on what reaches the network", () => {
  it("puts no plaintext password in any request body, as text or as base64", async () => {
    // Searched as the literal string *and* as base64 of the raw bytes, because
    // those are the two forms a leak would actually take here: the value copied
    // into a field, or the value encoded by something that was meant to encrypt
    // it. A decimal or hex needle would pass while the password sat in plain
    // sight.
    const { api, bodies } = recordingApi();
    const session = openSession();

    await uploadItems({ api, session }, manyLogins(3));

    const wire = JSON.stringify(bodies);
    const base64 = toBase64(utf8Encode(SECRET));
    expect(wire).not.toContain(SECRET);
    expect(wire).not.toContain(base64);
    expect(wire).not.toContain(base64.replace(/=+$/, ""));
  });

  it("puts no item name, username or URL in any request body either", async () => {
    // The body is the whole item, so a leak of the name is a leak of which
    // services the user has an account with.
    const { api, bodies } = recordingApi();
    const session = openSession();

    await uploadItems({ api, session }, manyLogins(3));

    const wire = JSON.stringify(bodies);
    expect(wire).not.toContain("mail.example.com");
    expect(wire).not.toContain("item 0");
  });

  it("sends ciphertext that opens back to the same item under the user key", async () => {
    // Without this, the leak assertion above passes just as well for an upload
    // that dropped the password on the floor.
    const { api, bodies } = recordingApi();
    const session = openSession();
    const item = login("Example Mail");

    await uploadItems({ api, session }, [item]);

    const sent = bodies[0]?.items[0];
    expect(sent).toBeDefined();
    expect(
      await decryptItem(
        { ciphertext: sent?.ciphertext ?? "", wrappedItemKey: sent?.wrappedItemKey ?? "" },
        session.getKeys().userKey,
      ),
    ).toEqual(item);
  });

  it("wraps the item key under the chosen collection's key, not the user key", async () => {
    const collectionKey = new Uint8Array(32).fill(7);
    const session = sessionWithCollectionKeys(new Map([["c1", collectionKey]]));
    const { api, bodies } = recordingApi();
    const item = login("Shared Mail");

    await uploadItems({ api, session }, [item], { collectionId: "c1" });

    const sent = bodies[0]?.items[0];
    expect(sent?.collectionId).toBe("c1");
    expect(
      await decryptItem(
        { ciphertext: sent?.ciphertext ?? "", wrappedItemKey: sent?.wrappedItemKey ?? "" },
        collectionKey,
      ),
    ).toEqual(item);
  });

  it("marks a personal item's collectionId as null rather than omitting it", async () => {
    // The server reads an omitted collectionId as "no change" on update; the
    // bulk path creates, but sending it explicitly is what items.ts does and
    // what the field's pointer type exists for.
    const { api, bodies } = recordingApi();
    const session = openSession();

    await uploadItems({ api, session }, manyLogins(1));

    expect(bodies[0]?.items[0]?.collectionId).toBeNull();
  });
});
