import { describe, expect, it } from "vitest";
import { generateCollectionKey, generateKeyPair, sealToUser } from "@keyhole/crypto";
import { adoptCollections, type WireCollection } from "./collections.js";
import { openSession } from "./test-helpers.js";

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
