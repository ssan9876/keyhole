import { describe, expect, it, vi } from "vitest";
import {
  generateCollectionKey,
  generateKeyPair,
  openSealed,
  sealToUser,
  toBase64,
} from "@keyhole/crypto";
import {
  addMember,
  adoptCollections,
  createCollection,
  fulfilGrant,
  removeMember,
  type PendingGrant,
  type WireCollection,
} from "./collections.js";
import { fakeApi, openSession } from "./testing/test-helpers.js";

// Wraps the real generateCollectionKey so the zeroize-on-failure test below
// can get its hands on the exact buffer createCollection generated
// internally. Re-opening the sealed blob it sent would not work: sealing
// already copies the plaintext bytes into ciphertext, so the opened result
// stays intact even after the source buffer is zeroized — only a reference
// to the original buffer can show the zeroing happened.
vi.mock("@keyhole/crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@keyhole/crypto")>();
  return { ...actual, generateCollectionKey: vi.fn(actual.generateCollectionKey) };
});

function wire(over: Partial<WireCollection> = {}): WireCollection {
  return {
    id: "c1",
    name: "Household",
    role: "member",
    sealedCollectionKey: "",
    createdBy: "u1",
    createdAt: "2026-07-27T00:00:00Z",
    ...over,
  };
}

describe("adoptCollections", () => {
  it("opens a sealed key and puts the collection key itself into the session", async () => {
    const me = generateKeyPair();
    const collectionKey = generateCollectionKey();
    const session = openSession(me.privateKey);

    await adoptCollections(
      [wire({ sealedCollectionKey: await sealToUser(collectionKey, me.publicKey) })],
      session,
    );

    // Byte equality, not merely "something was stored": a wrong-but-present
    // key decrypts nothing and would surface months later as an unreadable
    // shared item.
    expect(session.getCollectionKey("c1")).toEqual(collectionKey);
  });

  it("reports a collection whose sealed key will not open as unusable, and stores no key for it", async () => {
    const me = generateKeyPair();
    const someoneElse = generateKeyPair();
    const session = openSession(me.privateKey);

    const summaries = await adoptCollections(
      [
        wire({
          // Sealed to a different recipient: this client cannot open it.
          sealedCollectionKey: await sealToUser(generateCollectionKey(), someoneElse.publicKey),
        }),
      ],
      session,
    );

    expect(summaries).toEqual([
      { id: "c1", name: "Household", role: "member", usable: false },
    ]);
    expect(session.getCollectionKey("c1")).toBeNull();
  });

  it("survives a malformed sealed key rather than losing every other collection", async () => {
    const me = generateKeyPair();
    const good = generateCollectionKey();
    const session = openSession(me.privateKey);

    const summaries = await adoptCollections(
      [
        wire({ id: "bad", sealedCollectionKey: "not json at all" }),
        wire({ id: "good", sealedCollectionKey: await sealToUser(good, me.publicKey) }),
      ],
      session,
    );

    expect(summaries.map((c) => c.usable)).toEqual([false, true]);
    expect(session.getCollectionKey("good")).toEqual(good);
  });

  it("normalizes an unrecognized role to member rather than trusting the server's string", async () => {
    const me = generateKeyPair();
    const session = openSession(me.privateKey);

    const summaries = await adoptCollections(
      [
        wire({
          role: "owner",
          sealedCollectionKey: await sealToUser(generateCollectionKey(), me.publicKey),
        }),
      ],
      session,
    );

    expect(summaries[0]?.role).toBe("member");
  });

  it("zeroizes the key of a collection that has disappeared from sync", async () => {
    const me = generateKeyPair();
    const revoked = generateCollectionKey();
    const session = openSession(me.privateKey);

    await adoptCollections(
      [wire({ id: "c1", sealedCollectionKey: await sealToUser(revoked, me.publicKey) })],
      session,
    );
    const held = session.getCollectionKey("c1");
    expect(held).not.toBeNull();

    // Membership revoked: the collection stops appearing entirely.
    await adoptCollections([], session);

    expect(held?.every((byte) => byte === 0)).toBe(true);
    expect(session.getCollectionKey("c1")).toBeNull();
  });

  it("reuses the key object it already holds when a collection is unchanged", async () => {
    const me = generateKeyPair();
    const collectionKey = generateCollectionKey();
    const session = openSession(me.privateKey);
    const sealed = await sealToUser(collectionKey, me.publicKey);

    await adoptCollections([wire({ sealedCollectionKey: sealed })], session);
    const first = session.getCollectionKey("c1");

    await adoptCollections([wire({ sealedCollectionKey: sealed })], session);

    // Identity, not equality. setCollectionKeys zeroizes any key the new map
    // does not carry over by reference, so re-opening the blob into a fresh
    // buffer would blank the live key on every sync — and the bytes would
    // still compare equal, which is why this asserts the reference.
    expect(session.getCollectionKey("c1")).toBe(first);
    expect(first?.every((byte) => byte === 0)).toBe(false);
  });
});

describe("createCollection", () => {
  it("seals the new key to the creator's own public key and never sends the key itself", async () => {
    const me = generateKeyPair();
    const session = openSession(me.privateKey);
    let sent: { name: string; sealedCollectionKey: string } | null = null;
    const api = fakeApi({
      post: async (_path, body) => {
        sent = body as typeof sent;
        return {
          id: "c1", name: "Household", role: "manager",
          sealedCollectionKey: (body as { sealedCollectionKey: string }).sealedCollectionKey,
          createdBy: "u1", createdAt: "2026-07-27T00:00:00Z",
        };
      },
    });

    const summary = await createCollection(
      { api, session },
      { name: "Household", ownPublicKey: toBase64(me.publicKey) },
    );

    const opened = await openSealed(sent!.sealedCollectionKey, me.privateKey);
    expect(opened.length).toBe(32);
    // The raw key must appear nowhere in the request. Base64 of the raw bytes
    // is the shape a leak would actually take on this wire — a decimal or
    // hex needle would pass while the key sat in plain sight.
    expect(JSON.stringify(sent)).not.toContain(toBase64(opened));
    expect(summary).toEqual({ id: "c1", name: "Household", role: "manager", usable: true });
  });

  it("installs the new collection's key in the session, so an item can be added to it immediately", async () => {
    const me = generateKeyPair();
    const session = openSession(me.privateKey);
    let sent: { sealedCollectionKey: string } | null = null;
    const api = fakeApi({
      post: async (_path, body) => {
        sent = body as typeof sent;
        return {
          id: "c1", name: "Household", role: "manager",
          sealedCollectionKey: (body as { sealedCollectionKey: string }).sealedCollectionKey,
          createdBy: "u1", createdAt: "2026-07-27T00:00:00Z",
        };
      },
    });

    await createCollection(
      { api, session },
      { name: "Household", ownPublicKey: toBase64(me.publicKey) },
    );

    // Byte equality against the exact key that was sealed and sent, not just
    // "something 32 bytes long is present" — a stale or unrelated key would
    // satisfy the weaker check while still leaving the item unreadable.
    const opened = await openSealed(sent!.sealedCollectionKey, me.privateKey);
    expect(session.getCollectionKey("c1")).toEqual(opened);
  });

  it("preserves the keys of collections already held while adding the new one", async () => {
    const me = generateKeyPair();
    const session = openSession(me.privateKey);
    const existing = new Uint8Array(32).fill(4);
    session.setCollectionKeys(new Map([["existing", existing]]));
    const api = fakeApi({
      post: async (_path, body) => ({
        id: "c1", name: "Household", role: "manager",
        sealedCollectionKey: (body as { sealedCollectionKey: string }).sealedCollectionKey,
        createdBy: "u1", createdAt: "2026-07-27T00:00:00Z",
      }),
    });

    await createCollection(
      { api, session },
      { name: "Household", ownPublicKey: toBase64(me.publicKey) },
    );

    // Same object, not merely equal bytes: setCollectionKeys zeroizes by
    // identity, so a call that dropped and re-added "existing" would have
    // blanked this very array even though the assertion on bytes would
    // still (misleadingly) pass if it re-created an equal-valued buffer.
    expect(session.getCollectionKey("existing")).toBe(existing);
    expect(session.getCollectionKey("c1")).not.toBeNull();
  });

  it("zeroizes the freshly generated key and does not install it when the server call fails", async () => {
    const me = generateKeyPair();
    const session = openSession(me.privateKey);
    const api = fakeApi({
      post: async () => {
        throw new Error("server rejected the request");
      },
    });
    const spy = vi.mocked(generateCollectionKey);
    const callsBefore = spy.mock.calls.length;

    await expect(
      createCollection({ api, session }, { name: "Household", ownPublicKey: toBase64(me.publicKey) }),
    ).rejects.toThrow("server rejected the request");

    // The buffer createCollection actually generated and held, captured by
    // reference through the spy — the only way to observe that it, and not
    // some unrelated copy, was zeroized. The value was never installed in the
    // session, so nothing else would ever get a chance to clear it.
    expect(spy.mock.calls.length).toBe(callsBefore + 1);
    const generated = spy.mock.results[callsBefore]?.value as Uint8Array;
    expect(generated).toBeInstanceOf(Uint8Array);
    expect(generated.length).toBe(32);
    expect(generated.every((byte) => byte === 0)).toBe(true);
    expect(session.getCollectionKey("c1")).toBeNull();
  });
});

describe("addMember", () => {
  it("seals this client's collection key to the recipient and reports granted", async () => {
    const me = generateKeyPair();
    const them = generateKeyPair();
    const collectionKey = generateCollectionKey();
    const session = openSession(me.privateKey);
    session.setCollectionKeys(new Map([["c1", collectionKey]]));

    let sent: { userId: string; role: string; sealedCollectionKey: string } | null = null;
    const api = fakeApi({
      post: async (_path, body) => { sent = body as typeof sent; return { status: "granted" }; },
    });

    const outcome = await addMember({ api, session }, {
      collectionId: "c1",
      recipient: { id: "u2", name: "Bee", email: "bee@example.com", publicKey: toBase64(them.publicKey), fingerprint: "x" },
      role: "member",
    });

    expect(outcome).toBe("granted");
    // Sealed to THEM, not to me: sealing to the wrong recipient produces a
    // blob the server accepts and the new member can never open.
    await expect(openSealed(sent!.sealedCollectionKey, them.privateKey)).resolves.toEqual(collectionKey);
    await expect(openSealed(sent!.sealedCollectionKey, me.privateKey)).rejects.toThrow();
  });

  it("records a pending grant, with no sealed key, when this client holds no key for the collection", async () => {
    const me = generateKeyPair();
    const them = generateKeyPair();
    const session = openSession(me.privateKey);   // no keyring entry for c1

    let sent: Record<string, unknown> | null = null;
    const api = fakeApi({
      post: async (_path, body) => { sent = body as Record<string, unknown>; return { status: "pending" }; },
    });

    const outcome = await addMember({ api, session }, {
      collectionId: "c1",
      recipient: { id: "u2", name: "Bee", email: "bee@example.com", publicKey: toBase64(them.publicKey), fingerprint: "x" },
      role: "member",
    });

    expect(outcome).toBe("pending");
    // Not "" and not a fabricated blob: a fabricated one would be accepted and
    // would lock the target out of a collection they appear to have.
    expect(sent!["sealedCollectionKey"]).toBeUndefined();
  });

  it("reports pending when the server answers 202 even though a sealed key was sent", async () => {
    // Trust the server's own answer rather than the branch taken locally: this
    // client holds the key and sends a real sealed blob, but the server still
    // reports 202/pending (e.g. it decided the recipient's membership needs a
    // separate approval step) and that must be what the caller sees.
    const me = generateKeyPair();
    const them = generateKeyPair();
    const collectionKey = generateCollectionKey();
    const session = openSession(me.privateKey);
    session.setCollectionKeys(new Map([["c1", collectionKey]]));

    let sent: { sealedCollectionKey?: string } | null = null;
    const api = fakeApi({
      post: async (_path, body) => {
        sent = body as typeof sent;
        return { status: "pending" };
      },
    });

    const outcome = await addMember({ api, session }, {
      collectionId: "c1",
      recipient: { id: "u2", name: "Bee", email: "bee@example.com", publicKey: toBase64(them.publicKey), fingerprint: "x" },
      role: "member",
    });

    expect(outcome).toBe("pending");
    expect(sent!.sealedCollectionKey).toBeDefined();
  });
});

describe("fulfilGrant", () => {
  const grant: PendingGrant = {
    collectionId: "c1",
    collectionName: "Household",
    userId: "u2",
    role: "member",
    requestedBy: "u3",
    createdAt: "2026-07-27T00:00:00Z",
  };

  it("seals the held collection key to the waiting user", async () => {
    const me = generateKeyPair();
    const them = generateKeyPair();
    const collectionKey = generateCollectionKey();
    const session = openSession(me.privateKey);
    session.setCollectionKeys(new Map([["c1", collectionKey]]));

    let sent: { userId: string; sealedCollectionKey: string } | null = null;
    const api = fakeApi({
      post: async (_path, body) => { sent = body as typeof sent; return { status: "granted" }; },
    });
    const recipient = { id: "u2", name: "Bee", email: "bee@example.com", publicKey: toBase64(them.publicKey), fingerprint: "x" };

    await fulfilGrant({ api, session }, { grant, recipient });

    expect(sent!.userId).toBe("u2");
    await expect(openSealed(sent!.sealedCollectionKey, them.privateKey)).resolves.toEqual(collectionKey);
  });

  it("refuses when this client holds no key for the collection, without calling the server", async () => {
    const me = generateKeyPair();
    const them = generateKeyPair();
    const session = openSession(me.privateKey);   // no keyring entry for c1
    const api = fakeApi({ post: async () => { throw new Error("must not be called"); } });
    const recipient = { id: "u2", name: "Bee", email: "bee@example.com", publicKey: toBase64(them.publicKey), fingerprint: "x" };

    await expect(fulfilGrant({ api, session }, { grant, recipient })).rejects.toThrow(/cannot open/i);
  });

  it("refuses when the recipient's id does not match the grant's userId", async () => {
    // Sealing to the wrong person is silent: the server stores the blob against
    // grant.userId regardless, and that user can never open it.
    const me = generateKeyPair();
    const them = generateKeyPair();
    const collectionKey = generateCollectionKey();
    const session = openSession(me.privateKey);
    session.setCollectionKeys(new Map([["c1", collectionKey]]));
    const api = fakeApi({ post: async () => { throw new Error("must not be called"); } });
    const recipient = { id: "u3", name: "Cee", email: "cee@example.com", publicKey: toBase64(them.publicKey), fingerprint: "x" };

    await expect(
      fulfilGrant({ api, session }, { grant: { ...grant, userId: "u2" }, recipient }),
    ).rejects.toThrow(/does not match/i);
  });
});

describe("removeMember", () => {
  it("calls DELETE for that member and no one else", async () => {
    const session = openSession();
    let path: string | null = null;
    const api = fakeApi({ del: async (p) => { path = p; return null; } });

    await removeMember({ api, session }, { collectionId: "c1", userId: "u2" });

    expect(path).toBe("/api/collections/c1/members/u2");
  });
});
