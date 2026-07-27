# Keyhole Sharing, Administration, and Settings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the multi-user web client — shared collections, the admin screens that create users and grant access, and the account settings that change a master password, end a session, or replace a recovery code.

**Architecture:** No server changes. Every endpoint this plan needs already exists and is tested (`internal/httpapi/{collections,directory,account,admin}.go`). The work is entirely in `apps/web`, and it keeps Plan 3's split: a framework-free core in `src/vault/` that owns every byte of key material, and a thin React layer in `src/ui/` that is forbidden by ESLint from importing `@keyhole/crypto` at all. The one structural addition is a **collection keyring** inside `session.ts` — collection keys are key material, so they live in the same module as the userKey and die at the same instant.

**Tech Stack:** TypeScript, React 19, Vite 6, Vitest 3 + Testing Library (jsdom), Playwright 1.52, `@keyhole/crypto` (workspace).

## Global Constraints

Every task's requirements implicitly include this section.

- **`src/ui/**` must never import `@keyhole/crypto`.** `apps/web/eslint.config.js` enforces it with `no-restricted-imports`, and it fires on type-only imports too. Plaintext *types* the UI needs are re-exported from `src/vault/types.ts`; add to that file rather than reaching past it.
- **Key material lives only in `src/vault/session.ts`.** Nothing else retains a `Uint8Array` key across calls. Functions receive what they need as an argument.
- **`localStorage` holds exactly two keys, both non-secret:** `keyhole.email` (existing) and `keyhole.autolock` (added by Task 8). Nothing else — no tokens, no plaintext, no ciphertext.
- **`params` is `DEFAULT_KDF_PARAMS_JSON`, verbatim.** Never `JSON.stringify` an object into that field. Key order is part of the contract; `internal/httpapi/account.go:76` compares the bytes and returns 400 on any difference. The reason is enumeration resistance: prelogin answers an unknown address with this exact string.
- **`recoveryKdfParams` is NOT pinned** — send `JSON.stringify(blob.params)`. No endpoint returns it, so it leaks nothing, and recording the params the blob was actually made under is what keeps a correct recovery code from failing later.
- **Colour comes from `src/ui/tokens.css` and means something.** `--danger` for destructive, `--ink-muted` for secondary. No new hex values in components.
- **Every form control is labelled** via the `Field` component or an explicit `htmlFor`/`id` pair. Design spec §6.4 lists this as a requirement.
- **Every task ends with a mutation check.** Break the production code deliberately, run the named test, watch it fail with the expected message, revert. Paste the failure output into the task report. A test that still passes under mutation is not a test.
- Test names must describe what the body actually verifies. This repo has shipped fifteen tests whose names promised more than their bodies checked; the mutation step is the defence.
- Commit after each task. Conventional commit prefixes (`feat(web):`, `fix(web):`, `test(web):`).

## Verification commands

```bash
cd apps/web && pnpm test          # vitest, whole app
cd apps/web && pnpm typecheck     # tsc --noEmit
cd apps/web && pnpm lint          # eslint, includes the crypto-import gate
cd apps/web && pnpm test:e2e      # playwright, real Go server (Task 12 only)
```

Run a single file with `pnpm vitest run src/vault/collections.test.ts`, a single test with `-t "name"`.

## Known gap this plan does NOT close

**A forgotten master password is still unrecoverable.** `POST /api/account/recovery` rotates the recovery blob for a user who is already authenticated; no endpoint returns `recovery_protected_user_key` to someone who cannot log in. Redeeming a recovery code needs a database migration, a `deriveRecoveryAuthHash` addition to `packages/crypto` with new pinned test vectors, and two new unauthenticated endpoints — a server-and-crypto feature, not a settings screen, and out of scope here.

Task 10 therefore corrects the enrolment copy, which currently promises something the product cannot do. It must not be left claiming otherwise while the redemption path does not exist.

---

## File Structure

**Created:**

| Path | Responsibility |
|---|---|
| `src/vault/collections.ts` | Opening sealed collection keys, creating collections, membership, fulfilling grants |
| `src/vault/directory.ts` | The share-target list and public-key fingerprints |
| `src/vault/account.ts` | Profile, change master password, regenerate recovery code, sessions |
| `src/vault/autolock.ts` | Idle timer and the auto-lock preference |
| `src/vault/admin.ts` | Users, invites, reset, delete, audit, membership graph |
| `src/ui/screens/CollectionsScreen.tsx` | Collection list, members, pending grants |
| `src/ui/screens/SettingsScreen.tsx` | Auto-lock, master password, sessions, recovery code |
| `src/ui/screens/AdminScreen.tsx` | Users, invite links, audit log |
| `src/ui/components/Confirm.tsx` | Typed-confirmation dialog for destructive actions |

**Modified:**

| Path | Change |
|---|---|
| `src/vault/session.ts` | Collection keyring; `open()` zeroizes prior material |
| `src/vault/items.ts` | Parent key resolved per item; `collectionId` always explicit on the wire |
| `src/vault/store.ts` | Sync carries collections; adopts their keys; exposes them in state |
| `src/vault/types.ts` | Re-export any new plaintext-shaped type the UI needs |
| `src/ui/screens/VaultScreen.tsx` | Navigation, collection filter and badge, collection picker in the editor |
| `src/ui/screens/EnrolScreen.tsx` | Recovery-code copy corrected (Task 10) |
| `src/ui/App.tsx` | Screen switch, auto-lock wiring |
| `e2e/server.ts`, `e2e/vault.spec.ts` | A second user, and a sharing journey |

---

## Task 1: The collection keyring

`session.ts` is the only module that retains key material, and design spec §6.3 makes that a reviewable gate — a gate that only works if there is one place to look. Collection keys are key material, so they go here rather than into a second holder.

**Files:**
- Modify: `apps/web/src/vault/session.ts`
- Test: `apps/web/src/vault/session.test.ts`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  ```ts
  getCollectionKey(collectionId: string): Uint8Array | null
  setCollectionKeys(next: Map<string, Uint8Array>): void
  ```
  on `Session`. `lock()` zeroizes every collection key. `open()` zeroizes any material already held.

- [ ] **Step 1: Write the failing tests**

Append to `apps/web/src/vault/session.test.ts`:

```ts
describe("collection keyring", () => {
  function openSession(): Session {
    const session = createSession();
    session.open({
      tokens: { accessToken: "a", refreshToken: "r" },
      user: { id: "u1", email: "a@example.com", name: "A", role: "user" },
      userKey: new Uint8Array(32).fill(1),
      privateKey: new Uint8Array(32).fill(2),
    });
    return session;
  }

  it("returns a collection key that was set, and null for one that was not", () => {
    const session = openSession();
    const key = new Uint8Array(32).fill(7);
    session.setCollectionKeys(new Map([["c1", key]]));

    expect(session.getCollectionKey("c1")).toBe(key);
    expect(session.getCollectionKey("c2")).toBeNull();
  });

  it("zeroizes a collection key that the replacement map drops", () => {
    const session = openSession();
    const revoked = new Uint8Array(32).fill(7);
    const kept = new Uint8Array(32).fill(9);
    session.setCollectionKeys(new Map([["c1", revoked], ["c2", kept]]));

    // A membership revoked server-side simply stops appearing in /api/sync.
    session.setCollectionKeys(new Map([["c2", kept]]));

    expect(revoked.every((byte) => byte === 0)).toBe(true);
    expect(kept.every((byte) => byte === 9)).toBe(true);
    expect(session.getCollectionKey("c1")).toBeNull();
  });

  it("does not zeroize a key the replacement map carries over by identity", () => {
    const session = openSession();
    const key = new Uint8Array(32).fill(7);
    session.setCollectionKeys(new Map([["c1", key]]));
    session.setCollectionKeys(new Map([["c1", key]]));

    expect(key.every((byte) => byte === 7)).toBe(true);
  });

  it("zeroizes every collection key on lock", () => {
    const session = openSession();
    const first = new Uint8Array(32).fill(7);
    const second = new Uint8Array(32).fill(8);
    session.setCollectionKeys(new Map([["c1", first], ["c2", second]]));

    session.lock();

    expect(first.every((byte) => byte === 0)).toBe(true);
    expect(second.every((byte) => byte === 0)).toBe(true);
    expect(session.getCollectionKey("c1")).toBeNull();
  });

  it("zeroizes the keys of a previous session when open() is called again", () => {
    const session = openSession();
    const stale = new Uint8Array(32).fill(7);
    session.setCollectionKeys(new Map([["c1", stale]]));
    const staleUserKey = session.getKeys().userKey;

    session.open({
      tokens: { accessToken: "a2", refreshToken: "r2" },
      user: { id: "u2", email: "b@example.com", name: "B", role: "user" },
      userKey: new Uint8Array(32).fill(3),
      privateKey: new Uint8Array(32).fill(4),
    });

    expect(stale.every((byte) => byte === 0)).toBe(true);
    expect(staleUserKey.every((byte) => byte === 0)).toBe(true);
    expect(session.getCollectionKey("c1")).toBeNull();
  });
});
```

Add `Session` to the existing type imports at the top of the file if it is not already imported.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd apps/web && pnpm vitest run src/vault/session.test.ts
```

Expected: five failures, `session.setCollectionKeys is not a function`.

- [ ] **Step 3: Extend the Session interface**

In `apps/web/src/vault/session.ts`, add to `interface Session`, after `getKeys()`:

```ts
  /** The key for one collection, or null when this client holds none — either
   *  because the user is not a member or because the sealed blob would not
   *  open. Callers must handle null; an item in that collection is simply
   *  unreadable here, which is not an error worth throwing over. */
  getCollectionKey(collectionId: string): Uint8Array | null;
  /**
   * Replaces the whole keyring, zeroizing every key the new map does not
   * carry over.
   *
   * Whole-map replacement rather than per-key insertion because that is the
   * shape of the truth: /api/sync sends the full collection list every time
   * (internal/store/sync.go:17), so a revoked membership is expressed by
   * absence. Merging would keep a revoked collection's key alive in memory
   * indefinitely with nothing to ever remove it.
   */
  setCollectionKeys(next: Map<string, Uint8Array>): void;
```

- [ ] **Step 4: Implement it**

In `createSession`, add beside the other closure variables:

```ts
  let collectionKeys = new Map<string, Uint8Array>();
```

Add these methods to the returned object, after `getKeys()`:

```ts
    getCollectionKey(collectionId) {
      return collectionKeys.get(collectionId) ?? null;
    },
    setCollectionKeys(next) {
      // Identity, not equality: adoptCollections reuses the existing Uint8Array
      // for an unchanged collection, and zeroizing a buffer the new map still
      // points at would silently blank a live key.
      for (const [id, key] of collectionKeys) {
        if (next.get(id) !== key) zeroize(key);
      }
      collectionKeys = next;
    },
```

Replace `open` and `lock` with:

```ts
    open(input) {
      // Zeroize whatever this session already held. Reachable in ordinary use:
      // enrol-then-login opens twice, and any future re-authentication would
      // too. Without this, the first unlock's keys stay live in the heap for
      // the life of the tab with no reference left to clear them.
      zeroize(userKey, privateKey, ...collectionKeys.values());
      collectionKeys = new Map();

      tokens = input.tokens;
      user = input.user;
      userKey = input.userKey;
      privateKey = input.privateKey;
      notify();
    },
```

```ts
    lock() {
      zeroize(userKey, privateKey, ...collectionKeys.values());
      collectionKeys = new Map();
      userKey = null;
      privateKey = null;
      tokens = null;
      user = null;
      notify();
    },
```

- [ ] **Step 5: Run the tests**

```bash
cd apps/web && pnpm vitest run src/vault/session.test.ts
```

Expected: PASS, including every pre-existing test in the file.

- [ ] **Step 6: Mutation check**

Change `if (next.get(id) !== key) zeroize(key);` to `if (next.get(id) === undefined) zeroize(key);` — a plausible reading of the same intent.

```bash
cd apps/web && pnpm vitest run src/vault/session.test.ts -t "zeroizes a collection key that the replacement map drops"
```

That one still passes. Now run the whole describe block: **"does not zeroize a key the replacement map carries over by identity"** must fail. Revert.

Second mutation: delete the `zeroize(...)` line from `open()`. "zeroizes the keys of a previous session when open() is called again" must fail. Revert.

- [ ] **Step 7: Commit**

```bash
git add apps/web/src/vault/session.ts apps/web/src/vault/session.test.ts
git commit -m "feat(web): hold collection keys in the session and zeroize them with it"
```

---

## Task 2: Adopting collections from sync

`/api/sync` already returns every collection the caller belongs to, in full, on every sync — including the `sealedCollectionKey` sealed to that user's public key. This task opens those blobs.

**Files:**
- Create: `apps/web/src/vault/collections.ts`
- Test: `apps/web/src/vault/collections.test.ts`

**Interfaces:**
- Consumes: `Session` from Task 1; `openSealed` from `@keyhole/crypto`.
- Produces:
  ```ts
  interface WireCollection {
    id: string; name: string; role: string;
    sealedCollectionKey: string; createdBy: string; createdAt: string;
  }
  interface CollectionSummary {
    id: string; name: string; role: "manager" | "member"; usable: boolean;
  }
  async function adoptCollections(wire: WireCollection[], session: Session): Promise<CollectionSummary[]>
  ```

**Context the implementer needs:** the collection *name* is plaintext on the wire. That is deliberate — design spec §3.9.3 lists collection names and the membership graph as metadata visible to the server. Do not try to decrypt it.

- [ ] **Step 1: Write the failing test**

Create `apps/web/src/vault/collections.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { generateCollectionKey, generateKeyPair, sealToUser } from "@keyhole/crypto";
import { createSession, type Session } from "./session.js";
import { adoptCollections, type WireCollection } from "./collections.js";

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

function openSession(privateKey: Uint8Array): Session {
  const session = createSession();
  session.open({
    tokens: { accessToken: "a", refreshToken: "r" },
    user: { id: "u1", email: "a@example.com", name: "A", role: "user" },
    userKey: new Uint8Array(32).fill(1),
    privateKey,
  });
  return session;
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
});
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd apps/web && pnpm vitest run src/vault/collections.test.ts
```

Expected: FAIL, `Failed to resolve import "./collections.js"`.

- [ ] **Step 3: Implement**

Create `apps/web/src/vault/collections.ts`:

```ts
import { openSealed } from "@keyhole/crypto";
import type { Session } from "./session.js";

/** The server's shape for one collection the caller belongs to. `name` is
 *  plaintext by design — spec §3.9.3 lists collection names as metadata the
 *  server can see. */
export interface WireCollection {
  id: string;
  name: string;
  role: string;
  sealedCollectionKey: string;
  createdBy: string;
  createdAt: string;
}

export type CollectionRole = "manager" | "member";

export interface CollectionSummary {
  id: string;
  name: string;
  role: CollectionRole;
  /** False when this client could not open the sealed key. The collection is
   *  still listed: hiding it would leave a user staring at items they cannot
   *  read with nothing anywhere explaining why. */
  usable: boolean;
}

/** The server's role is a string from a database column. Anything this client
 *  does not recognize is treated as the least privileged value rather than
 *  passed through — an unknown string must never widen what the UI offers. */
function normalizeRole(role: string): CollectionRole {
  return role === "manager" ? "manager" : "member";
}

/**
 * Opens every sealed collection key and installs the result as the session's
 * whole keyring.
 *
 * One failure never sinks the rest, for the same reason decryptRecords works
 * row by row: one unopenable blob is a bad row, not a bad vault.
 */
export async function adoptCollections(
  wire: WireCollection[],
  session: Session,
): Promise<CollectionSummary[]> {
  const { privateKey } = session.getKeys();
  const next = new Map<string, Uint8Array>();
  const summaries: CollectionSummary[] = [];

  for (const collection of wire) {
    let usable = false;
    try {
      // Reuse the key already held when the sealed blob is unchanged, so the
      // session's identity check does not zeroize a live key on every sync.
      const existing = session.getCollectionKey(collection.id);
      next.set(collection.id, existing ?? (await openSealed(collection.sealedCollectionKey, privateKey)));
      usable = true;
    } catch {
      // A substituted public key, a corrupt blob, or a grant sealed before this
      // user re-enrolled with a new keypair. All present the same way.
    }
    summaries.push({
      id: collection.id,
      name: collection.name,
      role: normalizeRole(collection.role),
      usable,
    });
  }

  session.setCollectionKeys(next);
  return summaries;
}
```

- [ ] **Step 4: Run the tests**

```bash
cd apps/web && pnpm vitest run src/vault/collections.test.ts
```

Expected: PASS (5 tests).

- [ ] **Step 5: Mutation check**

Replace the `catch` body with `throw error` (and `catch (error)`). "survives a malformed sealed key rather than losing every other collection" must fail — the whole call rejects.

Second mutation: change `normalizeRole` to `return role as CollectionRole`. "normalizes an unrecognized role to member" must fail with `expected 'owner' to be 'member'`. Revert both.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/vault/collections.ts apps/web/src/vault/collections.test.ts
git commit -m "feat(web): open sealed collection keys from sync into the session keyring"
```

---

## Task 3: Items under a collection key

Today every item is encrypted under the userKey. A shared item is encrypted under its collection key instead, so `decryptRecords` must choose a parent per row, and writes must say which collection they belong to.

**Files:**
- Modify: `apps/web/src/vault/items.ts`
- Modify: `apps/web/src/vault/store.ts` (call-site change only; state changes land in Task 4)
- Modify: `apps/web/src/ui/screens/VaultScreen.tsx` (call-site change only)
- Test: `apps/web/src/vault/items.test.ts`

**Interfaces:**
- Consumes: `Session.getCollectionKey` (Task 1).
- Produces:
  ```ts
  function parentKeyFor(session: Session, collectionId: string | null): Uint8Array | null
  async function decryptRecords(wire: WireItem[], session: Session): Promise<ItemRecord[]>
  async function createItem(deps, plaintext: ItemPlaintext, collectionId: string | null): Promise<ItemRecord>
  async function updateItem(deps, input: { id: string; revision: number; collectionId: string | null; plaintext: ItemPlaintext }): Promise<ItemRecord>
  ```

**Design decision the implementer must not re-litigate.** `updateItem` takes `collectionId` as a required, explicit `string | null` and always sends it. The server treats an *omitted* `collectionId` as "no change" and an explicit `null` as "move to personal" (`internal/httpapi/items.go:21`), and that distinction is a data-loss trap: a client that forgets to echo the field would move a shared item back to personal, and every other member's next sync would drop it with no error anywhere. Always stating it removes the trap from this client entirely. The signature changes from positional arguments to one object because four positional parameters, two of which are `string`, is how `id` and `collectionId` get swapped.

- [ ] **Step 1: Write the failing tests**

Add to `apps/web/src/vault/items.test.ts`. Keep the existing tests; they still describe personal items.

```ts
import { encryptItem, generateCollectionKey } from "@keyhole/crypto";
// ...plus whatever the file already imports

describe("collection items", () => {
  const COLLECTION_KEY = generateCollectionKey();
  const USER_KEY = new Uint8Array(32).fill(1);

  function sessionWith(collectionKeys: Map<string, Uint8Array>): Session {
    const session = createSession();
    session.open({
      tokens: { accessToken: "a", refreshToken: "r" },
      user: { id: "u1", email: "a@example.com", name: "A", role: "user" },
      userKey: USER_KEY,
      privateKey: new Uint8Array(32).fill(2),
    });
    session.setCollectionKeys(collectionKeys);
    return session;
  }

  it("decrypts a collection item with the collection key, not the user key", async () => {
    const plaintext: LoginItem = { ...BLANK, name: "Shared router" };
    const encrypted = await encryptItem(plaintext, COLLECTION_KEY);
    const session = sessionWith(new Map([["c1", COLLECTION_KEY]]));

    const [record] = await decryptRecords(
      [wireItem({ id: "i1", collectionId: "c1", ...encrypted })],
      session,
    );

    expect(record?.plaintext?.name).toBe("Shared router");
  });

  it("leaves a collection item unreadable when the session holds no key for it", async () => {
    const encrypted = await encryptItem({ ...BLANK, name: "Shared router" }, COLLECTION_KEY);
    const session = sessionWith(new Map());

    const [record] = await decryptRecords(
      [wireItem({ id: "i1", collectionId: "c1", ...encrypted })],
      session,
    );

    // Not an exception and not a dropped row: the list shows "couldn't
    // decrypt", which is the honest answer.
    expect(record?.plaintext).toBeNull();
    expect(record?.id).toBe("i1");
  });

  it("still decrypts a personal item with the user key when a keyring is present", async () => {
    const encrypted = await encryptItem({ ...BLANK, name: "Mine" }, USER_KEY);
    const session = sessionWith(new Map([["c1", COLLECTION_KEY]]));

    const [record] = await decryptRecords(
      [wireItem({ id: "i1", collectionId: null, ...encrypted })],
      session,
    );

    expect(record?.plaintext?.name).toBe("Mine");
  });

  it("encrypts a new collection item under the collection key", async () => {
    const session = sessionWith(new Map([["c1", COLLECTION_KEY]]));
    let sent: { ciphertext: string; wrappedItemKey: string; collectionId: string | null } | null = null;
    const api = fakeApi({
      post: async (_path, body) => {
        sent = body as typeof sent;
        return wireItem({ id: "i1", collectionId: "c1", ...(body as object) });
      },
    });

    await createItem({ api, session }, { ...BLANK, name: "Shared router" }, "c1");

    expect(sent?.collectionId).toBe("c1");
    // The proof that the right parent was used: only the collection key opens it.
    await expect(decryptItem(sent!, COLLECTION_KEY)).resolves.toMatchObject({
      name: "Shared router",
    });
    await expect(decryptItem(sent!, USER_KEY)).rejects.toThrow();
  });

  it("refuses to create an item in a collection this client cannot open", async () => {
    const session = sessionWith(new Map());
    const api = fakeApi({ post: async () => { throw new Error("must not be called"); } });

    await expect(
      createItem({ api, session }, { ...BLANK, name: "Shared router" }, "c1"),
    ).rejects.toThrow(/cannot open/i);
  });

  it("always sends collectionId on update, so an unchanged shared item is never moved to personal", async () => {
    const session = sessionWith(new Map([["c1", COLLECTION_KEY]]));
    let sent: Record<string, unknown> | null = null;
    const api = fakeApi({
      put: async (_path, body) => {
        sent = body as Record<string, unknown>;
        return wireItem({ id: "i1", collectionId: "c1" });
      },
    });

    await updateItem(
      { api, session },
      { id: "i1", revision: 4, collectionId: "c1", plaintext: { ...BLANK, name: "Edited" } },
    );

    // The field is present, not merely correct: an omitted collectionId means
    // "no change" to the server, and relying on that is the data-loss trap
    // this signature exists to remove.
    expect(Object.keys(sent!)).toContain("collectionId");
    expect(sent!["collectionId"]).toBe("c1");
  });

  it("re-encrypts under the user key when an item is moved out of a collection", async () => {
    const session = sessionWith(new Map([["c1", COLLECTION_KEY]]));
    let sent: { ciphertext: string; wrappedItemKey: string } | null = null;
    const api = fakeApi({
      put: async (_path, body) => {
        sent = body as typeof sent;
        return wireItem({ id: "i1", collectionId: null });
      },
    });

    await updateItem(
      { api, session },
      { id: "i1", revision: 4, collectionId: null, plaintext: { ...BLANK, name: "Now mine" } },
    );

    await expect(decryptItem(sent!, USER_KEY)).resolves.toMatchObject({ name: "Now mine" });
    await expect(decryptItem(sent!, COLLECTION_KEY)).rejects.toThrow();
  });
});
```

`BLANK`, `wireItem`, and `fakeApi` are the helpers already in this file — reuse them; if `wireItem` does not yet accept `collectionId`, extend it. Import `decryptItem` and `LoginItem` from `@keyhole/crypto` (test files are not subject to the UI import ban).

- [ ] **Step 2: Run to verify failure**

```bash
cd apps/web && pnpm vitest run src/vault/items.test.ts
```

Expected: failures on the new block, plus type errors on `decryptRecords(wire, session)`.

- [ ] **Step 3: Implement**

In `apps/web/src/vault/items.ts`, add after the `ItemConflictError` class:

```ts
/**
 * The key an item's body is encrypted under: the userKey for a personal item,
 * the collection key for a shared one.
 *
 * Returns null rather than throwing when the collection key is missing —
 * decryptRecords turns that into an unreadable row, which is the honest
 * outcome, while the write paths turn it into a thrown error, because writing
 * an item nobody can open is not something to do quietly.
 */
export function parentKeyFor(session: Session, collectionId: string | null): Uint8Array | null {
  if (collectionId === null) return session.getKeys().userKey;
  return session.getCollectionKey(collectionId);
}

function requireParentKey(session: Session, collectionId: string | null): Uint8Array {
  const key = parentKeyFor(session, collectionId);
  if (key === null) {
    throw new Error(
      `This device cannot open the key for that collection, so it cannot write to it`,
    );
  }
  return key;
}
```

Change `decryptRecords` to take the session and resolve per row:

```ts
export async function decryptRecords(
  wire: WireItem[],
  session: Session,
): Promise<ItemRecord[]> {
  const records: ItemRecord[] = [];
  for (const item of wire) {
    if (item.deletedAt !== null) {
      records.push(toRecord(item, null));
      continue;
    }
    const parentKey = parentKeyFor(session, item.collectionId);
    if (parentKey === null) {
      // An item in a collection whose key this client does not hold. Shown as
      // undecryptable rather than dropped, for the same reason a corrupt blob
      // is: a silently missing row reads as data loss.
      records.push(toRecord(item, null));
      continue;
    }
    try {
      const plaintext = await decryptItem(
        { ciphertext: item.ciphertext, wrappedItemKey: item.wrappedItemKey },
        parentKey,
      );
      records.push(toRecord(item, plaintext));
    } catch {
      records.push(toRecord(item, null));
    }
  }
  return records;
}
```

Replace `createItem` and `updateItem`:

```ts
export async function createItem(
  deps: { api: ApiClient; session: Session },
  plaintext: ItemPlaintext,
  collectionId: string | null,
): Promise<ItemRecord> {
  const encrypted = await encryptItem(plaintext, requireParentKey(deps.session, collectionId));
  const created = await deps.api.post<WireItem>("/api/items", {
    collectionId,
    ciphertext: encrypted.ciphertext,
    wrappedItemKey: encrypted.wrappedItemKey,
  });
  return toRecord(created, plaintext);
}

export interface ItemUpdate {
  id: string;
  revision: number;
  /** Always explicit. The server reads an omitted field as "no change", and a
   *  client that forgets to echo it moves a shared item to personal — which
   *  every other member's next sync sees as the item vanishing. */
  collectionId: string | null;
  plaintext: ItemPlaintext;
}

export async function updateItem(
  deps: { api: ApiClient; session: Session },
  input: ItemUpdate,
): Promise<ItemRecord> {
  // The parent is the *target* collection: a move re-encrypts the body under
  // the destination's key in the same write.
  const encrypted = await encryptItem(
    input.plaintext,
    requireParentKey(deps.session, input.collectionId),
  );
  try {
    const updated = await deps.api.put<WireItem>(`/api/items/${input.id}`, {
      collectionId: input.collectionId,
      ciphertext: encrypted.ciphertext,
      wrappedItemKey: encrypted.wrappedItemKey,
      revision: input.revision,
    });
    return toRecord(updated, input.plaintext);
  } catch (error) {
    if (error instanceof ApiError && error.code === "conflict") {
      const body = error.body as { item?: WireItem };
      if (body.item !== undefined) {
        throw new ItemConflictError(body.item);
      }
    }
    throw error;
  }
}
```

- [ ] **Step 4: Fix the call sites**

`apps/web/src/vault/store.ts`, inside `fetchInto`:

```ts
      const records = await decryptRecords(response.items, deps.session);
```

`apps/web/src/ui/screens/VaultScreen.tsx`, in the 409 branch of `save`:

```ts
          const [serverRecord] = await decryptRecords([error.current], session);
```

and in `save` itself, thread the collection through — a temporary shape that Task 9 replaces:

```ts
      if (editing === "new") {
        store.upsert(await createItem({ api, session }, next, null));
        // ...
      }
      // ...
        const updated = await updateItem(
          { api, session },
          { id: editing.id, revision: editing.revision, collectionId: editing.collectionId, plaintext: next },
        );
```

- [ ] **Step 5: Run the whole suite**

```bash
cd apps/web && pnpm test && pnpm typecheck
```

Expected: all green. `pnpm typecheck` is the gate that proves no call site was missed.

- [ ] **Step 6: Mutation check**

Mutation A — in `decryptRecords`, replace `parentKeyFor(session, item.collectionId)` with `session.getKeys().userKey`. "decrypts a collection item with the collection key, not the user key" must fail.

Mutation B — in `updateItem`, delete the `collectionId` line from the PUT body. "always sends collectionId on update…" must fail on the `Object.keys` assertion. This is the important one: without it the test would pass on a client that silently un-shares every item it edits.

Mutation C — in `requireParentKey`, `return key ?? new Uint8Array(32)`. "refuses to create an item in a collection this client cannot open" must fail. Revert all three.

- [ ] **Step 7: Commit**

```bash
git add apps/web/src/vault/items.ts apps/web/src/vault/items.test.ts apps/web/src/vault/store.ts apps/web/src/ui/screens/VaultScreen.tsx
git commit -m "feat(web): encrypt and decrypt items under their collection key"
```

---

## Task 4: Collections in the vault store

The store already fetches `/api/sync`. This task keeps its collections and hands their keys to the session, so a single sync is all it takes for a newly shared item to become readable.

**Files:**
- Modify: `apps/web/src/vault/store.ts`
- Test: `apps/web/src/vault/store.test.ts`

**Interfaces:**
- Consumes: `adoptCollections` (Task 2).
- Produces: `VaultState.collections: CollectionSummary[]`.

- [ ] **Step 1: Write the failing tests**

Add to `apps/web/src/vault/store.test.ts`:

```ts
describe("collections in sync", () => {
  it("puts the collection key into the session before decrypting the items that need it", async () => {
    const me = generateKeyPair();
    const collectionKey = generateCollectionKey();
    const session = openSession(me.privateKey);
    const encrypted = await encryptItem({ ...BLANK, name: "Shared router" }, collectionKey);

    const api = fakeApi({
      get: async () => ({
        revision: 4,
        items: [wireItem({ id: "i1", collectionId: "c1", ...encrypted })],
        folders: [],
        collections: [
          {
            id: "c1",
            name: "Household",
            role: "manager",
            sealedCollectionKey: await sealToUser(collectionKey, me.publicKey),
            createdBy: "u1",
            createdAt: "2026-07-27T00:00:00Z",
          },
        ],
      }),
    });

    const store = createVaultStore();
    await store.load({ api, session });

    // Ordering is the whole point: adopt first, decrypt second. Reversed, this
    // item is unreadable on the sync that delivers it and only appears after
    // some later refresh.
    expect(store.getState().items[0]?.plaintext?.name).toBe("Shared router");
    expect(store.getState().collections).toEqual([
      { id: "c1", name: "Household", role: "manager", usable: true },
    ]);
  });

  it("keeps collections from the full list on an incremental resync", async () => {
    // /api/sync sends collections in full every time, so a resync that merged
    // them would be harmless but one that ignored them would strand a
    // newly-granted collection until the next full load.
    // ...build a store already loaded with c1, then resync returning c1 and c2
    expect(store.getState().collections.map((c) => c.id)).toEqual(["c1", "c2"]);
  });

  it("drops a collection that has disappeared from sync", async () => {
    // load with c1, then resync with collections: []
    expect(store.getState().collections).toEqual([]);
    expect(session.getCollectionKey("c1")).toBeNull();
  });

  it("clears collections on clear()", async () => {
    // load with c1, then:
    store.clear();
    expect(store.getState().collections).toEqual([]);
  });
});
```

Flesh out the three sketched tests against the file's existing helpers; a sketch is not an acceptable committed test.

- [ ] **Step 2: Run to verify failure**

```bash
cd apps/web && pnpm vitest run src/vault/store.test.ts
```

- [ ] **Step 3: Implement**

In `apps/web/src/vault/store.ts`:

```ts
import { adoptCollections, type CollectionSummary, type WireCollection } from "./collections.js";
```

```ts
export interface VaultState {
  revision: number;
  items: ItemRecord[];
  /** Sent in full on every sync, so this is a replacement rather than a merge:
   *  a revoked membership is expressed by absence (internal/store/sync.go:17). */
  collections: CollectionSummary[];
  status: "empty" | "loading" | "ready" | "error";
  error: string | null;
}

interface SyncResponse {
  revision: number;
  items: WireItem[];
  collections: WireCollection[];
}
```

```ts
const EMPTY: VaultState = {
  revision: 0,
  items: [],
  collections: [],
  status: "empty",
  error: null,
};
```

In `fetchInto`, adopt before decrypting:

```ts
      const response = await deps.api.get<SyncResponse>(path);
      // Before decryptRecords, not after: the items in a collection granted
      // since the last sync arrive in this same response, and they are
      // unreadable until their key is in the session.
      const collections = await adoptCollections(response.collections ?? [], deps.session);
      const records = await decryptRecords(response.items, deps.session);
      set({
        revision: response.revision,
        items: since === null ? merge([], records) : merge(state.items, records),
        collections,
        status: "ready",
        error: null,
      });
```

`clear()` already resets to `EMPTY`, which now includes `collections: []`.

- [ ] **Step 4: Run the tests**

```bash
cd apps/web && pnpm test && pnpm typecheck
```

- [ ] **Step 5: Mutation check**

Move the `adoptCollections` call to *after* `decryptRecords`. "puts the collection key into the session before decrypting the items that need it" must fail with the item's plaintext undefined. Revert.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/vault/store.ts apps/web/src/vault/store.test.ts
git commit -m "feat(web): carry collections through sync and adopt their keys first"
```
---

## Task 5: The directory and public-key fingerprints

Sharing needs the recipient's X25519 public key, and the server is where public keys live. Design spec §3.9.1 accepts that a compromised server could substitute one — and names the mitigation: a fingerprint the two people can read aloud. That mitigation only exists if the UI renders it, so it ships in the same task as the directory.

**Files:**
- Create: `apps/web/src/vault/directory.ts`
- Test: `apps/web/src/vault/directory.test.ts`

**Interfaces:**
- Consumes: `ApiClient`.
- Produces:
  ```ts
  interface DirectoryEntry { id: string; name: string; email: string; publicKey: string; fingerprint: string }
  async function loadDirectory(deps: { api: ApiClient }): Promise<DirectoryEntry[]>
  ```

`GET /api/directory` returns `{ users: [{ id, name, email, publicKey }] }`, active accounts with a public key only, ordered by name.

- [ ] **Step 1: Write the failing test**

Create `apps/web/src/vault/directory.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { generateKeyPair, publicKeyFingerprint, toBase64 } from "@keyhole/crypto";
import { loadDirectory } from "./directory.js";

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
```

Add a small `fakeApi` helper to this file (or import the shared one if `items.test.ts` exports it — do not duplicate a third copy; if two copies already exist, extract one into `src/vault/test-helpers.ts` and use it from all three).

- [ ] **Step 2: Run to verify failure**

```bash
cd apps/web && pnpm vitest run src/vault/directory.test.ts
```

- [ ] **Step 3: Implement**

Create `apps/web/src/vault/directory.ts`:

```ts
import { fromBase64, publicKeyFingerprint } from "@keyhole/crypto";
import type { ApiClient } from "./api.js";

export interface DirectoryEntry {
  id: string;
  name: string;
  email: string;
  /** Base64, as the server sends it. Kept because sealToUser needs the bytes
   *  and re-encoding at the call site is one more place to get it wrong. */
  publicKey: string;
  /**
   * The comparable value from design spec §3.9.1. The server distributes
   * public keys and could substitute one; two people reading this aloud is
   * the mitigation, so it is computed here and always rendered — never
   * optional, never behind a disclosure.
   */
  fingerprint: string;
}

interface DirectoryResponse {
  users: { id: string; name: string; email: string; publicKey: string }[];
}

export async function loadDirectory(deps: { api: ApiClient }): Promise<DirectoryEntry[]> {
  const response = await deps.api.get<DirectoryResponse>("/api/directory");
  const entries: DirectoryEntry[] = [];
  for (const user of response.users) {
    let fingerprint: string;
    try {
      fingerprint = publicKeyFingerprint(fromBase64(user.publicKey), user.email);
    } catch {
      // An unparseable public key cannot be sealed to, so offering the account
      // as a share target would promise something that cannot happen.
      continue;
    }
    entries.push({ ...user, fingerprint });
  }
  return entries;
}
```

- [ ] **Step 4: Run the tests**

```bash
cd apps/web && pnpm vitest run src/vault/directory.test.ts
```

- [ ] **Step 5: Mutation check**

Replace the fingerprint line with `fingerprint = user.id;`. The first test must fail with a mismatch, not merely a truthiness complaint. Revert.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/vault/directory.ts apps/web/src/vault/directory.test.ts
git commit -m "feat(web): load the share directory with comparable key fingerprints"
```

---

## Task 6: Collection administration

Creating a collection, adding and removing members, and fulfilling the grants an admin could only request. This is where design spec §3.5's central consequence shows: **the server cannot grant access**, because it never holds a collection key. An admin who is not a member can only record an intention, and some member's client completes it later.

**Files:**
- Modify: `apps/web/src/vault/collections.ts`
- Test: `apps/web/src/vault/collections.test.ts`

**Interfaces:**
- Consumes: `Session`, `ApiClient`, `DirectoryEntry` (Task 5).
- Produces:
  ```ts
  interface PendingGrant { collectionId: string; collectionName: string; userId: string; role: string; requestedBy: string; createdAt: string }
  interface Member { userId: string; name: string; email: string; role: string; grantedAt: string }

  async function createCollection(deps, input: { name: string; ownPublicKey: string }): Promise<CollectionSummary>
  async function deleteCollection(deps, collectionId: string): Promise<void>
  async function listMembers(deps, collectionId: string): Promise<Member[]>
  async function addMember(deps, input: { collectionId: string; recipient: DirectoryEntry; role: "manager" | "member" }): Promise<"granted" | "pending">
  async function removeMember(deps, input: { collectionId: string; userId: string }): Promise<void>
  async function loadPendingGrants(deps): Promise<PendingGrant[]>
  async function fulfilGrant(deps, input: { grant: PendingGrant; recipient: DirectoryEntry }): Promise<void>
  ```
  `deps` is `{ api: ApiClient; session: Session }` throughout.

**Server behaviour the implementer must match exactly:**

| Call | Server | Meaning |
|---|---|---|
| `POST /api/collections {name, sealedCollectionKey}` | 201 `collectionJSON` | Admin only. Creator becomes manager. |
| `POST /api/collections/{id}/members` **with** `sealedCollectionKey` | 201 `{status:"granted"}` | Caller holds the key; access is immediate. |
| `POST /api/collections/{id}/members` **without** it | 202 `{status:"pending"}` | Intention recorded; a member must finish it. |
| `POST /api/collections/{id}/grants {userId, sealedCollectionKey}` | 201 `{status:"granted"}` | Manager **and** member only. |
| `DELETE /api/collections/{id}/members/{userId}` | 204 | Not retroactive — see below. |

- [ ] **Step 1: Write the failing tests**

Append to `apps/web/src/vault/collections.test.ts`:

```ts
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
    // ...as above, then:
    expect(session.getCollectionKey("c1")).toEqual(opened);
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
    // Trust the server's own answer rather than the branch taken locally.
    // ...api returns { status: "pending" }
    expect(outcome).toBe("pending");
  });
});

describe("fulfilGrant", () => {
  it("seals the held collection key to the waiting user", async () => {
    // ...manager holding c1's key, grant for u2, recipient = u2's directory entry
    await expect(openSealed(sent!.sealedCollectionKey, them.privateKey)).resolves.toEqual(collectionKey);
  });

  it("refuses when this client holds no key for the collection, without calling the server", async () => {
    const api = fakeApi({ post: async () => { throw new Error("must not be called"); } });
    await expect(fulfilGrant({ api, session }, { grant, recipient })).rejects.toThrow(/cannot open/i);
  });

  it("refuses when the recipient's id does not match the grant's userId", async () => {
    // Sealing to the wrong person is silent: the server stores the blob against
    // grant.userId regardless, and that user can never open it.
    await expect(
      fulfilGrant({ api, session }, { grant: { ...grant, userId: "u2" }, recipient: { ...recipient, id: "u3" } }),
    ).rejects.toThrow(/does not match/i);
  });
});

describe("removeMember", () => {
  it("calls DELETE for that member and no one else", async () => {
    let path: string | null = null;
    const api = fakeApi({ del: async (p) => { path = p; return null; } });
    await removeMember({ api, session }, { collectionId: "c1", userId: "u2" });
    expect(path).toBe("/api/collections/c1/members/u2");
  });
});
```

Flesh out every sketched test fully before committing.

- [ ] **Step 2: Run to verify failure**

```bash
cd apps/web && pnpm vitest run src/vault/collections.test.ts
```

- [ ] **Step 3: Implement**

Append to `apps/web/src/vault/collections.ts`. Update the import line:

```ts
import {
  fromBase64,
  generateCollectionKey,
  openSealed,
  sealToUser,
  zeroize,
} from "@keyhole/crypto";
import type { ApiClient } from "./api.js";
import type { DirectoryEntry } from "./directory.js";
import type { Session } from "./session.js";

type Deps = { api: ApiClient; session: Session };
```

```ts
export interface PendingGrant {
  collectionId: string;
  collectionName: string;
  userId: string;
  role: string;
  requestedBy: string;
  createdAt: string;
}

export interface Member {
  userId: string;
  name: string;
  email: string;
  role: string;
  grantedAt: string;
}

/**
 * Creates a collection and seals its key to the creator, who becomes its first
 * manager.
 *
 * The collection key is generated here and sealed here; the server receives
 * only the sealed blob and never holds a key that opens anything. That is what
 * makes "an admin cannot read another user's vault" a cryptographic fact
 * rather than a permission check.
 */
export async function createCollection(
  deps: Deps,
  input: { name: string; ownPublicKey: string },
): Promise<CollectionSummary> {
  const collectionKey = generateCollectionKey();
  const sealedCollectionKey = await sealToUser(collectionKey, fromBase64(input.ownPublicKey));

  const created = await deps.api.post<WireCollection>("/api/collections", {
    name: input.name,
    sealedCollectionKey,
  });

  // Install it directly rather than waiting for the next sync to seal-and-open
  // a key we already have in hand.
  const next = new Map<string, Uint8Array>();
  for (const id of currentCollectionIds(deps.session)) {
    const existing = deps.session.getCollectionKey(id);
    if (existing !== null) next.set(id, existing);
  }
  next.set(created.id, collectionKey);
  deps.session.setCollectionKeys(next);

  return { id: created.id, name: created.name, role: "manager", usable: true };
}

export async function deleteCollection(deps: Deps, collectionId: string): Promise<void> {
  await deps.api.del(`/api/collections/${collectionId}`);
}

export async function listMembers(deps: Deps, collectionId: string): Promise<Member[]> {
  const response = await deps.api.get<{ members: Member[] }>(
    `/api/collections/${collectionId}/members`,
  );
  return response.members;
}

export async function loadPendingGrants(deps: Deps): Promise<PendingGrant[]> {
  const response = await deps.api.get<{ pendingGrants: PendingGrant[] }>(
    "/api/collections/pending-grants",
  );
  return response.pendingGrants;
}

/**
 * Adds a member, taking whichever of the two paths this client can.
 *
 * Holding the collection key means sealing it and granting access outright.
 * Not holding it — an admin who is not a member — means recording an intention
 * the server cannot carry out, because it has no key either. The returned
 * value is the server's own answer, not the branch taken here: reporting
 * "granted" for a 202 would tell an admin the user has access when they do not.
 */
export async function addMember(
  deps: Deps,
  input: { collectionId: string; recipient: DirectoryEntry; role: "manager" | "member" },
): Promise<"granted" | "pending"> {
  const collectionKey = deps.session.getCollectionKey(input.collectionId);
  const body: Record<string, unknown> = {
    userId: input.recipient.id,
    role: input.role,
  };
  if (collectionKey !== null) {
    body["sealedCollectionKey"] = await sealToUser(
      collectionKey,
      fromBase64(input.recipient.publicKey),
    );
  }

  const response = await deps.api.post<{ status?: string }>(
    `/api/collections/${input.collectionId}/members`,
    body,
  );
  return response.status === "granted" ? "granted" : "pending";
}

export async function removeMember(
  deps: Deps,
  input: { collectionId: string; userId: string },
): Promise<void> {
  await deps.api.del(`/api/collections/${input.collectionId}/members/${input.userId}`);
}

/**
 * Completes a grant an admin could only request.
 *
 * The recipient check is not defensive padding. Sealing to the wrong person
 * fails silently in the worst way: the server stores the blob against
 * grant.userId whatever it contains, so the intended member gets a membership
 * whose key they can never open, and nothing anywhere reports it.
 */
export async function fulfilGrant(
  deps: Deps,
  input: { grant: PendingGrant; recipient: DirectoryEntry },
): Promise<void> {
  if (input.recipient.id !== input.grant.userId) {
    throw new Error("The chosen recipient does not match the pending grant");
  }
  const collectionKey = deps.session.getCollectionKey(input.grant.collectionId);
  if (collectionKey === null) {
    throw new Error("This device cannot open the key for that collection");
  }
  await deps.api.post(`/api/collections/${input.grant.collectionId}/grants`, {
    userId: input.grant.userId,
    sealedCollectionKey: await sealToUser(collectionKey, fromBase64(input.recipient.publicKey)),
  });
}
```

`createCollection` needs the ids the session currently holds. Add a `collectionIds(): string[]` accessor to `Session` in the same task (interface, implementation returning `[...collectionKeys.keys()]`, and a test that it lists exactly the ids set), and use it instead of the `currentCollectionIds` placeholder above. `zeroize` is imported for the failure path: if the POST rejects, zeroize `collectionKey` before rethrowing, since it was never installed and nothing else will ever clear it.

- [ ] **Step 4: Run the tests**

```bash
cd apps/web && pnpm test && pnpm typecheck && pnpm lint
```

- [ ] **Step 5: Mutation check**

Mutation A — in `addMember`, seal to `deps.session.getKeys().privateKey`'s own public key instead of the recipient's (use any wrong key). "seals this client's collection key to the recipient and reports granted" must fail on the `openSealed(..., them.privateKey)` assertion.

Mutation B — in `addMember`, `return collectionKey !== null ? "granted" : "pending"`. "reports pending when the server answers 202 even though a sealed key was sent" must fail.

Mutation C — delete the recipient-id check in `fulfilGrant`. "refuses when the recipient's id does not match the grant's userId" must fail. Revert all three.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/vault/collections.ts apps/web/src/vault/collections.test.ts apps/web/src/vault/session.ts apps/web/src/vault/session.test.ts
git commit -m "feat(web): create collections, manage members, and fulfil pending grants"
```

---

## Task 7: Account settings core

Changing the master password, replacing the recovery code, and ending sessions. All three re-verify the master password server-side, because a stolen access token must not be enough to overwrite key material with garbage.

**Files:**
- Create: `apps/web/src/vault/account.ts`
- Test: `apps/web/src/vault/account.test.ts`

**Interfaces:**
- Consumes: `ApiClient`, `Session`.
- Produces:
  ```ts
  interface AccountProfile { id: string; email: string; name: string; role: string; publicKey: string; createdAt: string; fingerprint: string }
  interface DeviceSession { id: string; deviceLabel: string; createdAt: string; lastSeenAt: string; current: boolean }

  async function loadAccount(deps): Promise<AccountProfile>
  async function changeMasterPassword(deps, input: { email: string; currentPassword: string; newPassword: string }): Promise<void>
  async function regenerateRecoveryCode(deps, input: { email: string; currentPassword: string }): Promise<string>
  async function listSessions(deps): Promise<DeviceSession[]>
  async function revokeSession(deps, sessionId: string): Promise<void>
  ```

**The protocol, which the implementer must not shortcut.** Both write endpoints require `currentAuthHash`. Producing it needs the account's *current* KDF salt, which comes from `POST /api/auth/prelogin {email}` — the same call `unlock` makes. So:

1. `prelogin(email)` → `{ kdfSalt, params }`.
2. `deriveMasterKey(currentPassword, fromBase64(kdfSalt), JSON.parse(params))` → `deriveAuthHash` → `currentAuthHash`. Zeroize the master key.
3. For a password change: `rotateMasterPassword(newPassword, session.getKeys().userKey)` — the userKey is deliberately unchanged, so no item, folder, or collection key is touched and nothing needs re-encrypting.
4. `POST /api/account/password` with `params: DEFAULT_KDF_PARAMS_JSON` **verbatim** and `kdfSalt: toBase64(rotation.kdfSalt)`.

`POST /api/account/password` revokes every other session server-side (`store.RotatePassword` takes the current session id to keep). The current session survives, so the UI must not lock afterwards.

- [ ] **Step 1: Write the failing tests**

Create `apps/web/src/vault/account.test.ts`:

```ts
import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_KDF_PARAMS,
  DEFAULT_KDF_PARAMS_JSON,
  deriveAuthHash,
  deriveMasterKey,
  fromBase64,
  generateKdfSalt,
  recoverUserKey,
  toBase64,
  unwrapKey,
  deriveWrapKey,
} from "@keyhole/crypto";
import { changeMasterPassword, regenerateRecoveryCode } from "./account.js";

describe("changeMasterPassword", () => {
  it("sends the pinned params string byte for byte", async () => {
    const salt = generateKdfSalt();
    const calls: { path: string; body: Record<string, unknown> }[] = [];
    const api = fakeApi({
      post: async (path, body) => {
        calls.push({ path, body: body as Record<string, unknown> });
        return path.endsWith("prelogin")
          ? { kdfSalt: toBase64(salt), params: DEFAULT_KDF_PARAMS_JSON }
          : null;
      },
    });

    await changeMasterPassword(
      { api, session: unlockedSession() },
      { email: "a@example.com", currentPassword: "old-password", newPassword: "new-password" },
    );

    const rotate = calls.find((c) => c.path === "/api/account/password");
    // Byte equality against the constant, not a parsed comparison. The server
    // compares the raw string; a semantically identical object with reordered
    // keys is rejected with 400 (internal/httpapi/account.go:76).
    expect(rotate?.body["params"]).toBe(DEFAULT_KDF_PARAMS_JSON);
  });

  it("derives currentAuthHash from the salt prelogin returned, not from a fresh one", async () => {
    const salt = generateKdfSalt();
    // ...capture the POST body
    const expected = toBase64(deriveAuthHash(await deriveMasterKey("old-password", salt, DEFAULT_KDF_PARAMS)));
    expect(rotate?.body["currentAuthHash"]).toBe(expected);
  });

  it("re-wraps the SAME userKey under the new password, so existing items still open", async () => {
    const session = unlockedSession();
    const userKey = session.getKeys().userKey;
    // ...capture protectedUserKey and kdfSalt from the POST body
    const newMaster = await deriveMasterKey("new-password", fromBase64(rotate?.body["kdfSalt"] as string), DEFAULT_KDF_PARAMS);
    // The proof: the blob the server will store unwraps to the key this
    // session is already using. A regenerated userKey would pass any
    // "something was sent" assertion and orphan every item in the vault.
    await expect(unwrapKey(rotate?.body["protectedUserKey"] as string, deriveWrapKey(newMaster)))
      .resolves.toEqual(userKey);
  });

  it("never sends either password or the userKey", async () => {
    // ...
    const serialized = JSON.stringify(calls);
    expect(serialized).not.toContain("old-password");
    expect(serialized).not.toContain("new-password");
    expect(serialized).not.toContain(toBase64(userKey));
  });

  it("does not call the rotate endpoint when prelogin fails", async () => {
    const api = fakeApi({ post: async () => { throw new NetworkError(new Error("down")); } });
    await expect(changeMasterPassword(/* ... */)).rejects.toThrow(NetworkError);
    expect(calls.map((c) => c.path)).toEqual(["/api/auth/prelogin"]);
  });
});

describe("regenerateRecoveryCode", () => {
  it("returns a code that unwraps the current userKey from the blob it uploaded", async () => {
    const session = unlockedSession();
    // ...capture the POST /api/account/recovery body
    const code = await regenerateRecoveryCode({ api, session }, { email: "a@example.com", currentPassword: "old-password" });

    const recovered = await recoverUserKey(
      rotate?.body["recoveryProtectedUserKey"] as string,
      code,
      fromBase64(rotate?.body["recoverySalt"] as string),
      JSON.parse(rotate?.body["recoveryKdfParams"] as string),
    );
    // End to end through the real crypto: this is what "the code works" means,
    // and nothing weaker distinguishes a correct blob from a well-shaped one.
    expect(recovered).toEqual(session.getKeys().userKey);
  });

  it("sends recoveryKdfParams as the params the blob was actually made under", async () => {
    expect(JSON.parse(rotate?.body["recoveryKdfParams"] as string)).toEqual(DEFAULT_KDF_PARAMS);
  });

  it("never sends the recovery code itself", async () => {
    const code = await regenerateRecoveryCode(/* ... */);
    // The server never sees it — that is the whole design (spec §3.6).
    expect(JSON.stringify(calls)).not.toContain(code.replace(/-/g, ""));
    expect(JSON.stringify(calls)).not.toContain(code);
  });
});
```

**Argon2id at 64 MiB takes roughly half a second per derivation, deliberately.** Several of these tests run two or three. Give this file `{ timeout: 30_000 }` on the affected tests. **Do not lower `DEFAULT_KDF_PARAMS` to make tests fast** — that parameter set is the product's security floor and is pinned by the server.

Flesh out every sketch fully.

- [ ] **Step 2: Run to verify failure**

```bash
cd apps/web && pnpm vitest run src/vault/account.test.ts
```

- [ ] **Step 3: Implement**

Create `apps/web/src/vault/account.ts`:

```ts
import {
  DEFAULT_KDF_PARAMS,
  DEFAULT_KDF_PARAMS_JSON,
  createRecoveryBlob,
  deriveAuthHash,
  deriveMasterKey,
  fromBase64,
  generateRecoveryCode,
  publicKeyFingerprint,
  rotateMasterPassword,
  toBase64,
  zeroize,
  type KdfParams,
} from "@keyhole/crypto";
import type { ApiClient } from "./api.js";
import type { Session } from "./session.js";

type Deps = { api: ApiClient; session: Session };

export interface AccountProfile {
  id: string;
  email: string;
  name: string;
  role: string;
  publicKey: string;
  createdAt: string;
  /** The user's own fingerprint, so they can read it to someone comparing. */
  fingerprint: string;
}

export interface DeviceSession {
  id: string;
  deviceLabel: string;
  createdAt: string;
  lastSeenAt: string;
  current: boolean;
}

interface PreloginResponse {
  kdfSalt: string;
  params: string;
}

/**
 * Re-derives the current auth hash, which both write endpoints require.
 *
 * The session proves who the caller is; it does not prove they hold the master
 * password. Both endpoints overwrite key material, so without this a stolen
 * access token would be enough to write garbage over a wrapped key and destroy
 * a vault beyond recovery.
 *
 * The salt must come from prelogin — it is the salt this account's current
 * password was derived under, and a fresh one would produce a hash that
 * verifies against nothing.
 */
async function currentAuthHash(deps: Deps, email: string, currentPassword: string): Promise<string> {
  const prelogin = await deps.api.post<PreloginResponse>("/api/auth/prelogin", { email });
  const params = JSON.parse(prelogin.params) as KdfParams;
  const masterKey = await deriveMasterKey(currentPassword, fromBase64(prelogin.kdfSalt), params);
  try {
    return toBase64(deriveAuthHash(masterKey));
  } finally {
    zeroize(masterKey);
  }
}

export async function loadAccount(deps: Deps): Promise<AccountProfile> {
  const profile = await deps.api.get<Omit<AccountProfile, "fingerprint">>("/api/account");
  let fingerprint = "";
  try {
    fingerprint = publicKeyFingerprint(fromBase64(profile.publicKey), profile.email);
  } catch {
    // A pending account has no public key. Showing an empty fingerprint beats
    // failing the whole settings screen.
  }
  return { ...profile, fingerprint };
}

/**
 * Changes the master password without touching the userKey.
 *
 * Only the wrapping is redone, so no item, folder, or collection key is
 * re-encrypted and nothing in the vault needs rewriting. The server revokes
 * every other session but keeps this one, so the vault stays unlocked here.
 */
export async function changeMasterPassword(
  deps: Deps,
  input: { email: string; currentPassword: string; newPassword: string },
): Promise<void> {
  const current = await currentAuthHash(deps, input.email, input.currentPassword);
  const rotation = await rotateMasterPassword(
    input.newPassword,
    deps.session.getKeys().userKey,
    DEFAULT_KDF_PARAMS,
  );
  await deps.api.post("/api/account/password", {
    currentAuthHash: current,
    kdfSalt: toBase64(rotation.kdfSalt),
    // The pinned constant, verbatim. Never JSON.stringify an object here.
    params: DEFAULT_KDF_PARAMS_JSON,
    authHash: toBase64(rotation.authHash),
    protectedUserKey: rotation.protectedUserKey,
  });
}

/**
 * Issues a new recovery code and invalidates the old one.
 *
 * Returns the code, which is shown once and then gone: the server stores only
 * a blob the code opens, and cannot reproduce it.
 */
export async function regenerateRecoveryCode(
  deps: Deps,
  input: { email: string; currentPassword: string },
): Promise<string> {
  const current = await currentAuthHash(deps, input.email, input.currentPassword);
  const recoveryCode = generateRecoveryCode();
  const blob = await createRecoveryBlob(
    deps.session.getKeys().userKey,
    recoveryCode,
    DEFAULT_KDF_PARAMS,
  );
  await deps.api.post("/api/account/recovery", {
    currentAuthHash: current,
    recoverySalt: toBase64(blob.recoverySalt),
    // NOT pinned, deliberately: no endpoint returns this, so it leaks nothing,
    // and recording the params the blob was actually made under is what keeps
    // a correct code from failing later.
    recoveryKdfParams: JSON.stringify(blob.params),
    recoveryProtectedUserKey: blob.recoveryProtectedUserKey,
  });
  return recoveryCode;
}

export async function listSessions(deps: Deps): Promise<DeviceSession[]> {
  const response = await deps.api.get<{ sessions: DeviceSession[] }>("/api/account/sessions");
  return response.sessions;
}

export async function revokeSession(deps: Deps, sessionId: string): Promise<void> {
  await deps.api.del(`/api/account/sessions/${sessionId}`);
}
```

- [ ] **Step 4: Run the tests**

```bash
cd apps/web && pnpm vitest run src/vault/account.test.ts
```

- [ ] **Step 5: Mutation check**

Mutation A — `params: JSON.stringify(DEFAULT_KDF_PARAMS)`. "sends the pinned params string byte for byte" must fail. (Note it may pass by luck if the object's literal key order matches; the assertion is `toBe` against the constant, so reorder one key in the object to make the mutation representative.)

Mutation B — in `changeMasterPassword`, pass `generateUserKey()` instead of `deps.session.getKeys().userKey`. "re-wraps the SAME userKey…" must fail. Every other test in the file still passes, which is the point.

Mutation C — in `currentAuthHash`, use `generateKdfSalt()` instead of the prelogin salt. "derives currentAuthHash from the salt prelogin returned" must fail. Revert all three.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/vault/account.ts apps/web/src/vault/account.test.ts
git commit -m "feat(web): change the master password, reissue recovery codes, and end sessions"
```

---

## Task 8: Auto-lock

Design spec §3.8: 15 minutes idle by default; 1 / 5 / 15 / 30 / 60, on-close, or never. Lock zeroizes every key — which `session.lock()` already does after Task 1.

**Files:**
- Create: `apps/web/src/vault/autolock.ts`
- Test: `apps/web/src/vault/autolock.test.ts`

**Interfaces:**
- Produces:
  ```ts
  type AutoLockSetting = 1 | 5 | 15 | 30 | 60 | "on-close" | "never";
  const AUTO_LOCK_STORAGE_KEY = "keyhole.autolock";
  const DEFAULT_AUTO_LOCK: AutoLockSetting = 15;
  function readAutoLock(): AutoLockSetting
  function writeAutoLock(setting: AutoLockSetting): void
  function startAutoLock(input: { setting: AutoLockSetting; onLock: () => void; now?: () => number }): () => void
  ```
  `startAutoLock` returns a teardown function.

**Implementation notes.** Use `setTimeout` reset on activity, not a polling interval — a polling timer wakes the CPU every second forever. Listen on `pointerdown`, `keydown`, `visibilitychange`, and `focus`. For `"on-close"`, lock on `visibilitychange` when `document.visibilityState === "hidden"`; there is no timer. For `"never"`, register nothing and return a no-op.

**Wall-clock, not timer count.** A `setTimeout` does not fire while a laptop is asleep and browsers throttle timers in background tabs. Record the last-activity timestamp and, on every wake and every `visibilitychange`, compare `now() - lastActivity` against the threshold and lock immediately if it has passed. A timer-only implementation leaves a vault unlocked across a closed lid, which is exactly the case auto-lock exists for. `now` is injectable so the test can prove it.

- [ ] **Step 1: Write the failing tests**

Create `apps/web/src/vault/autolock.test.ts`:

```ts
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  AUTO_LOCK_STORAGE_KEY,
  DEFAULT_AUTO_LOCK,
  readAutoLock,
  startAutoLock,
  writeAutoLock,
} from "./autolock.js";

describe("the auto-lock preference", () => {
  beforeEach(() => localStorage.clear());

  it("defaults to 15 minutes when nothing is stored", () => {
    expect(readAutoLock()).toBe(15);
    expect(DEFAULT_AUTO_LOCK).toBe(15);
  });

  it("round-trips every documented setting", () => {
    for (const setting of [1, 5, 15, 30, 60, "on-close", "never"] as const) {
      writeAutoLock(setting);
      expect(readAutoLock()).toBe(setting);
    }
  });

  it("falls back to the default when the stored value is not a documented setting", () => {
    // Anything else — a hand-edited value, a setting from a future version —
    // must not leave the vault unlocked forever.
    localStorage.setItem(AUTO_LOCK_STORAGE_KEY, "0");
    expect(readAutoLock()).toBe(15);
    localStorage.setItem(AUTO_LOCK_STORAGE_KEY, "forever");
    expect(readAutoLock()).toBe(15);
  });

  it("stores nothing but the setting under its own key", () => {
    writeAutoLock(30);
    expect(Object.keys(localStorage)).toEqual([AUTO_LOCK_STORAGE_KEY]);
  });
});

describe("startAutoLock", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("locks after the configured idle period", () => {
    const onLock = vi.fn();
    startAutoLock({ setting: 1, onLock });

    vi.advanceTimersByTime(59_000);
    expect(onLock).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1_001);
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("restarts the countdown on user activity", () => {
    const onLock = vi.fn();
    startAutoLock({ setting: 1, onLock });

    vi.advanceTimersByTime(50_000);
    window.dispatchEvent(new Event("keydown"));
    vi.advanceTimersByTime(50_000);

    expect(onLock).not.toHaveBeenCalled();
    vi.advanceTimersByTime(11_000);
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("locks on wake when more wall-clock time passed than the timer saw", () => {
    // The case auto-lock exists for: the lid was closed. setTimeout did not
    // fire, so a timer-only implementation leaves the vault open.
    let clock = 0;
    const onLock = vi.fn();
    startAutoLock({ setting: 1, onLock, now: () => clock });

    clock = 120_000; // two minutes of real time, no timers fired
    document.dispatchEvent(new Event("visibilitychange"));

    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("locks immediately when the page is hidden and the setting is on-close", () => {
    const onLock = vi.fn();
    vi.spyOn(document, "visibilityState", "get").mockReturnValue("hidden");
    startAutoLock({ setting: "on-close", onLock });

    document.dispatchEvent(new Event("visibilitychange"));

    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("never locks when the setting is never, however long it idles", () => {
    const onLock = vi.fn();
    startAutoLock({ setting: "never", onLock });
    vi.advanceTimersByTime(24 * 60 * 60 * 1000);
    expect(onLock).not.toHaveBeenCalled();
  });

  it("stops locking after teardown", () => {
    const onLock = vi.fn();
    const stop = startAutoLock({ setting: 1, onLock });
    stop();
    vi.advanceTimersByTime(120_000);
    expect(onLock).not.toHaveBeenCalled();
  });

  it("removes its listeners on teardown, so activity after unmount does nothing", () => {
    const onLock = vi.fn();
    const stop = startAutoLock({ setting: 1, onLock });
    stop();
    window.dispatchEvent(new Event("keydown"));
    vi.advanceTimersByTime(120_000);
    expect(onLock).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run to verify failure**

```bash
cd apps/web && pnpm vitest run src/vault/autolock.test.ts
```

- [ ] **Step 3: Implement**

Create `apps/web/src/vault/autolock.ts`:

```ts
/**
 * Idle auto-lock. Design spec §3.8.
 *
 * The setting is a preference, not a secret, so it may be persisted — this and
 * `keyhole.email` are the only two values this application writes to storage.
 */

export type AutoLockSetting = 1 | 5 | 15 | 30 | 60 | "on-close" | "never";

export const AUTO_LOCK_STORAGE_KEY = "keyhole.autolock";
export const DEFAULT_AUTO_LOCK: AutoLockSetting = 15;

const SETTINGS: readonly AutoLockSetting[] = [1, 5, 15, 30, 60, "on-close", "never"];

export function readAutoLock(): AutoLockSetting {
  const raw = localStorage.getItem(AUTO_LOCK_STORAGE_KEY);
  if (raw === null) return DEFAULT_AUTO_LOCK;
  const parsed: AutoLockSetting = /^\d+$/.test(raw) ? (Number(raw) as AutoLockSetting) : (raw as AutoLockSetting);
  // An unrecognized value falls back rather than passing through. A stored "0"
  // would otherwise mean a zero-length timeout or an unbounded one depending
  // on how it is read, and either is a worse answer than the default.
  return SETTINGS.includes(parsed) ? parsed : DEFAULT_AUTO_LOCK;
}

export function writeAutoLock(setting: AutoLockSetting): void {
  localStorage.setItem(AUTO_LOCK_STORAGE_KEY, String(setting));
}

const ACTIVITY_EVENTS = ["pointerdown", "keydown", "focus"] as const;

export function startAutoLock(input: {
  setting: AutoLockSetting;
  onLock: () => void;
  now?: () => number;
}): () => void {
  if (input.setting === "never") return () => undefined;

  const now = input.now ?? (() => Date.now());
  const onHidden = (): void => {
    if (document.visibilityState === "hidden") input.onLock();
  };

  if (input.setting === "on-close") {
    document.addEventListener("visibilitychange", onHidden);
    return () => document.removeEventListener("visibilitychange", onHidden);
  }

  const idleMs = input.setting * 60_000;
  let lastActivity = now();
  let timer: ReturnType<typeof setTimeout> | null = null;

  const fire = (): void => {
    timer = null;
    input.onLock();
  };

  const restart = (): void => {
    lastActivity = now();
    if (timer !== null) clearTimeout(timer);
    timer = setTimeout(fire, idleMs);
  };

  // A setTimeout does not run while the machine is asleep, and browsers
  // throttle timers in background tabs — so the timer alone would leave a
  // vault unlocked across a closed lid, the exact case this feature exists
  // for. Every wake re-checks the wall clock.
  const checkElapsed = (): void => {
    if (now() - lastActivity >= idleMs) {
      if (timer !== null) clearTimeout(timer);
      fire();
      return;
    }
    restart();
  };

  for (const event of ACTIVITY_EVENTS) window.addEventListener(event, restart);
  document.addEventListener("visibilitychange", checkElapsed);
  restart();

  return () => {
    if (timer !== null) clearTimeout(timer);
    for (const event of ACTIVITY_EVENTS) window.removeEventListener(event, restart);
    document.removeEventListener("visibilitychange", checkElapsed);
  };
}
```

- [ ] **Step 4: Run the tests**

```bash
cd apps/web && pnpm vitest run src/vault/autolock.test.ts
```

- [ ] **Step 5: Mutation check**

Mutation A — delete the `document.addEventListener("visibilitychange", checkElapsed)` line. "locks on wake when more wall-clock time passed than the timer saw" must fail. This is the mutation that matters: a timer-only implementation passes every other test in the file.

Mutation B — in `readAutoLock`, `return parsed;` unconditionally. "falls back to the default when the stored value is not a documented setting" must fail.

Mutation C — make the teardown a no-op. "removes its listeners on teardown" must fail. Revert all three.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/vault/autolock.ts apps/web/src/vault/autolock.test.ts
git commit -m "feat(web): auto-lock on idle, on close, and on wake after a closed lid"
```

---

## Task 9: Administration core

Users, invite links, disable, reset, delete, and the audit log. All eight endpoints exist; this task is the typed client for them.

**Files:**
- Create: `apps/web/src/vault/admin.ts`
- Test: `apps/web/src/vault/admin.test.ts`

**Interfaces:**
- Produces:
  ```ts
  interface AdminUser { id: string; email: string; name: string; role: string; status: string; hasPendingInvite: boolean; createdAt: string }
  interface Invite { inviteUrl: string; expiresIn: string }
  interface AuditEntry { id: string; actorUserId: string; action: string; target: string; metadata: string; createdAt: string }
  interface CollectionOverview { id: string; name: string; createdBy: string; createdAt: string; memberCount: number }

  async function listUsers(deps): Promise<AdminUser[]>
  async function createUser(deps, input: { email: string; name: string; role: "admin" | "user" }): Promise<{ user: AdminUser } & Invite>
  async function reissueInvite(deps, userId: string): Promise<Invite>
  async function setUserStatus(deps, input: { userId: string; status: "active" | "disabled" }): Promise<AdminUser>
  async function resetUser(deps, input: { userId: string; confirmEmail: string }): Promise<Invite & { message: string }>
  async function deleteUser(deps, userId: string): Promise<void>
  async function loadAudit(deps, input?: { limit?: number; before?: string }): Promise<AuditEntry[]>
  async function loadCollectionOverview(deps): Promise<{ collections: CollectionOverview[]; pendingGrants: PendingGrant[] }>
  ```

**Server contracts worth stating.** `POST /api/admin/users` returns `{user, inviteUrl, expiresIn}` — **the raw invite token exists exactly once, in that response, and cannot be recovered afterwards**, so the UI must show it and say so. `POST /api/admin/users/{id}/reset` requires `confirmEmail` matching the account's normalized email and returns 400 otherwise. Deleting a user who created a collection or granted a membership returns 409 `conflict` with an explanatory message — surface it verbatim rather than a generic failure.

- [ ] **Step 1: Write the failing tests**

Create `apps/web/src/vault/admin.test.ts`. Cover at minimum:

```ts
it("returns the one-time invite url from the create response", async () => {
  // Nothing else ever produces it.
});

it("sends confirmEmail on reset, so the server's own check can run", async () => {
  // The dialog's typed confirmation is re-checked server-side because an
  // irreversible action that destroys a vault must not hinge on a client check.
  expect(sent?.["confirmEmail"]).toBe("bee@example.com");
});

it("surfaces the server's explanation when deleting a referenced user conflicts", async () => {
  // 409 with "this account created a collection or granted a membership..."
  // A generic "could not delete" leaves the operator with no next step.
  await expect(deleteUser({ api }, "u2")).rejects.toThrow(/created a collection/);
});

it("passes limit and before through to the audit query string", async () => {
  await loadAudit({ api }, { limit: 50, before: "2026-07-01T00:00:00Z" });
  expect(path).toBe("/api/admin/audit?limit=50&before=2026-07-01T00%3A00%3A00Z");
});

it("requests the audit log with no query string when given no arguments", async () => {
  await loadAudit({ api });
  expect(path).toBe("/api/admin/audit");
});

it("defaults a new user's role to user rather than admin", async () => {
  // Defaulting the other way would silently make every invited person an
  // administrator.
});
```

- [ ] **Step 2: Run to verify failure**

```bash
cd apps/web && pnpm vitest run src/vault/admin.test.ts
```

- [ ] **Step 3: Implement**

Create `apps/web/src/vault/admin.ts` with the interfaces above. Notes:

- Build the audit query with `URLSearchParams` so `before` is encoded. Append `?` only when there is at least one parameter.
- Let `ApiError` propagate. Its `message` is the server's own text, and `internal/httpapi/errors.go` states that codes are stable while messages are for humans — so branch on `error.code`, display `error.message`.
- `deps` is `{ api: ApiClient }`. Nothing here touches key material: an admin holds no ability to read another user's vault, and this module must not be the place that changes.

- [ ] **Step 4: Run the tests**

```bash
cd apps/web && pnpm test && pnpm typecheck && pnpm lint
```

- [ ] **Step 5: Mutation check**

Mutation A — default `role` to `"admin"`. "defaults a new user's role to user rather than admin" must fail.

Mutation B — drop `confirmEmail` from the reset body. Its test must fail. Revert both.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/vault/admin.ts apps/web/src/vault/admin.test.ts
git commit -m "feat(web): typed client for user administration and the audit log"
```
---

## Task 10: Shell navigation, the collections screen, and honest recovery copy

**Files:**
- Create: `apps/web/src/ui/screens/CollectionsScreen.tsx`
- Create: `apps/web/src/ui/components/Confirm.tsx`
- Modify: `apps/web/src/ui/screens/VaultScreen.tsx`
- Modify: `apps/web/src/ui/screens/EnrolScreen.tsx`
- Modify: `apps/web/src/ui/App.tsx`
- Test: `apps/web/src/ui/screens/CollectionsScreen.test.tsx`, plus additions to `VaultScreen.test.tsx` and `EnrolScreen.test.tsx`

**Interfaces:**
- Consumes: everything from Tasks 2, 5, 6. `useVaultState(store).collections` for the list.
- Produces: a `Tab` union `"vault" | "collections" | "settings" | "admin"` owned by `VaultScreen`, and `Confirm`.

**Scope of the shell change.** `VaultScreen` gains a tab strip in its existing header, beside Lock. The `admin` tab renders only when `session.user?.role === "admin"` — hiding it is a UI courtesy, not the security boundary; `requireAdmin` on the server is the boundary, and this task must not be written as though the reverse were true.

**The three things the collections screen must do:**

1. **List collections with their role**, and mark an unusable one plainly: *"Shared with you, but this device can't open it. Ask a member to grant access again."* Never hide it.
2. **Pending grants, prominently.** Any grant this user can fulfil — they are a manager of that collection and hold its key — appears with a "Grant access" action. Design spec §3.5 requires the UI show these explicitly rather than pretending the grant was instant.
3. **Members**, with each member's fingerprint from the directory, and an Add member control that names the fingerprint before sealing.

**Copy that must appear verbatim, because it states a real limitation.** On the remove-member confirmation (design spec §5.1):

> Removing a member does not rotate the collection key. Someone who kept a copy can still read what they already had. If this removal is adversarial, change the shared passwords too.

And on the move-out-of-collection control in the item editor (`packages/crypto/src/item.ts:149`):

> Moving this out does not take back access. A former member who kept the item key can still read it, including future edits.

- [ ] **Step 1: Write the failing tests**

Create `apps/web/src/ui/screens/CollectionsScreen.test.tsx`:

```tsx
it("lists a collection with the caller's role", async () => {
  render(<CollectionsScreen {...props({ collections: [{ id: "c1", name: "Household", role: "manager", usable: true }] })} />);
  expect(await screen.findByText("Household")).toBeInTheDocument();
  expect(screen.getByText(/manager/i)).toBeInTheDocument();
});

it("says a collection is unopenable on this device rather than hiding it", async () => {
  render(<CollectionsScreen {...props({ collections: [{ id: "c1", name: "Household", role: "member", usable: false }] })} />);
  expect(await screen.findByText("Household")).toBeInTheDocument();
  expect(screen.getByText(/can't open it/i)).toBeInTheDocument();
});

it("offers to fulfil a pending grant and passes the matching directory entry", async () => {
  const onFulfil = vi.fn().mockResolvedValue(undefined);
  render(<CollectionsScreen {...props({
    pendingGrants: [{ collectionId: "c1", collectionName: "Household", userId: "u2", role: "member", requestedBy: "u1", createdAt: "2026-07-27T00:00:00Z" }],
    directory: [{ id: "u2", name: "Bee", email: "bee@example.com", publicKey: "AA==", fingerprint: "ABCD-EFGH-JKMN-PQRS" }],
    onFulfil,
  })} />);

  await userEvent.click(await screen.findByRole("button", { name: /grant access/i }));

  // The recipient, not just the grant: sealing to the wrong person is silent.
  expect(onFulfil).toHaveBeenCalledWith(
    expect.objectContaining({ userId: "u2" }),
    expect.objectContaining({ id: "u2" }),
  );
});

it("shows the recipient's fingerprint before sealing a key to them", async () => {
  // Spec §3.9.1's mitigation only exists if it is on screen at the moment the
  // decision is made.
  expect(await screen.findByText("ABCD-EFGH-JKMN-PQRS")).toBeInTheDocument();
});

it("warns that removing a member is not retroactive, before removing them", async () => {
  const onRemove = vi.fn();
  render(<CollectionsScreen {...props({ members: [{ userId: "u2", name: "Bee", email: "bee@example.com", role: "member", grantedAt: "..." }] })} />);
  await userEvent.click(await screen.findByRole("button", { name: /remove/i }));

  expect(screen.getByText(/does not rotate the collection key/i)).toBeInTheDocument();
  expect(onRemove).not.toHaveBeenCalled();   // still behind the confirmation
});

it("tells an admin that adding a member they cannot seal to is only a request", async () => {
  // addMember returned "pending".
  expect(await screen.findByText(/a member of this collection must grant/i)).toBeInTheDocument();
});

it("does not offer Create collection to a non-admin", () => {
  render(<CollectionsScreen {...props({ role: "user" })} />);
  expect(screen.queryByRole("button", { name: /create collection/i })).not.toBeInTheDocument();
});
```

Add to `apps/web/src/ui/screens/VaultScreen.test.tsx`:

```tsx
it("shows a shared badge on an item that belongs to a collection", async () => { /* ... */ });

it("filters the list to one collection when that collection is selected", async () => { /* ... */ });

it("does not render the admin tab for a non-admin session", () => { /* ... */ });

it("saves a new item into the collection chosen in the editor", async () => {
  // The assertion is on the collectionId reaching createItem, not on the
  // control's appearance: a picker that renders and passes null shares nothing.
  expect(createItem).toHaveBeenCalledWith(expect.anything(), expect.anything(), "c1");
});
```

Add to `apps/web/src/ui/screens/EnrolScreen.test.tsx`:

```tsx
it("does not claim the recovery code can be redeemed today", () => {
  // The redemption endpoint does not exist. Promising it here is the app
  // telling a user their vault is recoverable when it is not.
  render(<EnrolScreen {...props} />);
  // ...after enrolling
  expect(screen.queryByText(/only way back into your vault/i)).not.toBeInTheDocument();
});
```

**Careful with label queries.** `getByLabelText(/name/i)` also matches "Username" — this exact bug has been shipped twice in this repo. Use exact strings or anchored patterns: `getByLabelText("Name")`, `getByLabelText(/^collection$/i)`.

- [ ] **Step 2: Run to verify failure**

```bash
cd apps/web && pnpm vitest run src/ui
```

- [ ] **Step 3: Build `Confirm`**

`apps/web/src/ui/components/Confirm.tsx` — a focus-trapped dialog (`role="alertdialog"`, `aria-modal`, focus moved to it on open, Escape cancels, focus returned on close; design spec §6.4 requires focus-trapped dialogs). Props:

```tsx
interface ConfirmProps {
  title: string;
  body: ReactNode;
  confirmLabel: string;
  /** When set, the confirm button stays disabled until the user types this
   *  exactly. Used for admin reset, which destroys a vault. */
  requireTyped?: string;
  onConfirm(): void;
  onCancel(): void;
}
```

- [ ] **Step 4: Build the collections screen and wire the tabs**

`CollectionsScreen` is presentational: it takes data and callbacks as props and holds no `api`/`session`. `VaultScreen` owns the tab state and does the calling. That keeps the screen testable without a fake API and keeps every crypto-adjacent call in one place.

In `VaultScreen`:
- header gains `<nav>` with tab buttons (`aria-current="page"` on the active one);
- `admin` tab rendered only when `session.user?.role === "admin"`;
- a collection filter above the list, plus a `Shared · <name>` badge on rows with a `collectionId`;
- the item editor gains a collection `<select>`, defaulting to the item's current collection, listing only `usable` collections plus Personal;
- `save` passes the chosen `collectionId` to `createItem` / `updateItem`.

In `App.tsx`, nothing changes for tabs — `VaultScreen` owns them.

- [ ] **Step 5: Correct the enrolment copy**

In `EnrolScreen.tsx`, replace the recovery paragraph:

```tsx
        <p style={{ color: "var(--ink-muted)" }}>
          Save this somewhere safe and offline. It is shown once and cannot be
          recovered afterwards &mdash; not by an administrator, and not by
          anyone with the database.
        </p>
        <p style={{ color: "var(--ink-muted)" }}>
          Note: redeeming this code is not built yet. Today it protects a copy
          of your key for a future release; it will not currently get you back
          into a vault whose master password you have forgotten.
        </p>
```

This is not optional polish. The screen currently tells every new user that the code is "the only way back into your vault if you forget your master password", and no code path anywhere can honour that.

- [ ] **Step 6: Run everything**

```bash
cd apps/web && pnpm test && pnpm typecheck && pnpm lint
```

`pnpm lint` matters here: these are the first new `.tsx` files since the parser fix, and the crypto-import ban must be seen to run on them. Confirm it does by temporarily adding `import { zeroize } from "@keyhole/crypto";` to `CollectionsScreen.tsx` and checking lint fails, then removing it.

- [ ] **Step 7: Mutation check**

Mutation A — in the editor's save path, pass `null` instead of the chosen collection. "saves a new item into the collection chosen in the editor" must fail.

Mutation B — in `CollectionsScreen`, filter out `usable: false` collections. "says a collection is unopenable on this device rather than hiding it" must fail.

Mutation C — in the fulfil handler, pass the first directory entry rather than the one matching `grant.userId`. "offers to fulfil a pending grant and passes the matching directory entry" must fail — make the fixture's directory have two entries so this mutation is detectable at all. Revert.

- [ ] **Step 8: Commit**

```bash
git add apps/web/src/ui
git commit -m "feat(web): collections screen, shared items, and honest recovery-code copy"
```

---

## Task 11: The settings screen

**Files:**
- Create: `apps/web/src/ui/screens/SettingsScreen.tsx`
- Test: `apps/web/src/ui/screens/SettingsScreen.test.tsx`
- Modify: `apps/web/src/ui/App.tsx` (auto-lock wiring)

**Four sections:** auto-lock, master password, active sessions, recovery code.

**Requirements with teeth:**

- The **change-password form requires the current password** and a confirmed new one. A mismatch is caught before any Argon2id runs — the user waits a second per derivation, and making them wait to be told they typoed the confirmation is gratuitous.
- After a successful change, say plainly: **"Your other devices have been signed out."** The server revokes every other session (`store.RotatePassword`), and a user who does not know that will think something is broken.
- The **new recovery code is shown once**, gated behind the same "I have saved this" acknowledgement as enrolment, and cleared from component state when acknowledged.
- **Revoking the current session locks the vault.** The `sessions` list marks it `current: true`. Revoking any other one just refreshes the list.
- **Auto-lock "never" carries a warning** — design spec §3.8 says so explicitly.
- Every failure distinguishes network from wrong-password from server error. A `NetworkError` must never read as "wrong master password" (design spec §9).

- [ ] **Step 1: Write the failing tests**

```tsx
it("rejects a mismatched confirmation before deriving anything", async () => {
  const onChangePassword = vi.fn();
  // ...fill new + confirm differently, submit
  expect(screen.getByRole("alert")).toHaveTextContent(/do not match/i);
  expect(onChangePassword).not.toHaveBeenCalled();
});

it("says the other devices were signed out after a successful password change", async () => {
  expect(await screen.findByText(/other devices have been signed out/i)).toBeInTheDocument();
});

it("reports a wrong current password as a wrong password, not a server fault", async () => {
  onChangePassword.mockRejectedValue(new ApiError("unauthorized", 401, "master password is incorrect", null));
  expect(await screen.findByRole("alert")).toHaveTextContent(/master password is incorrect/i);
});

it("reports an unreachable server as a connection problem, not a wrong password", async () => {
  onChangePassword.mockRejectedValue(new NetworkError(new Error("down")));
  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent(/could not reach/i);
  expect(alert).not.toHaveTextContent(/password/i);
});

it("shows a new recovery code once and hides it after acknowledgement", async () => {
  await userEvent.click(screen.getByRole("button", { name: /new recovery code/i }));
  const code = await screen.findByText(/^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){4}$/);
  await userEvent.click(screen.getByLabelText(/I have saved this/i));
  await userEvent.click(screen.getByRole("button", { name: /done/i }));
  expect(code).not.toBeInTheDocument();
});

it("locks the vault when the current session is revoked", async () => {
  const onLock = vi.fn();
  // sessions fixture has one entry with current: true
  await userEvent.click(screen.getByRole("button", { name: /sign out this device/i }));
  expect(onLock).toHaveBeenCalled();
});

it("does not lock the vault when another session is revoked", async () => {
  expect(onLock).not.toHaveBeenCalled();
  expect(onRevoke).toHaveBeenCalledWith("s2");
});

it("warns when auto-lock is set to never", async () => {
  await userEvent.selectOptions(screen.getByLabelText(/auto-lock/i), "never");
  expect(screen.getByText(/stays unlocked until you close/i)).toBeInTheDocument();
});

it("persists the chosen auto-lock setting", async () => {
  await userEvent.selectOptions(screen.getByLabelText(/auto-lock/i), "30");
  expect(readAutoLock()).toBe(30);
});
```

- [ ] **Step 2–4: Implement, run, and wire auto-lock**

`SettingsScreen` is presentational like `CollectionsScreen`; `VaultScreen` supplies the callbacks that call `src/vault/account.ts`.

In `App.tsx`, start the timer when the session is unlocked and tear it down when it locks:

```tsx
  const [autoLock, setAutoLock] = useState(readAutoLock);

  useEffect(() => {
    if (!isUnlocked) return undefined;
    return startAutoLock({
      setting: autoLock,
      onLock: () => {
        store.clear();
        session.lock();
      },
    });
  }, [autoLock, isUnlocked, session, store]);
```

Pass `setAutoLock` down so a change takes effect immediately rather than at the next reload — the effect's dependency array restarts the timer.

- [ ] **Step 5: Mutation check**

Mutation A — in the error handler, collapse every failure to `"Wrong master password"`. "reports an unreachable server as a connection problem" must fail.

Mutation B — always call `onLock` after revoking. "does not lock the vault when another session is revoked" must fail.

Mutation C — in `App.tsx`, drop `autoLock` from the effect's dependency array. Write the covering test first if the existing ones do not catch it (change the setting, advance timers past the new interval, assert the lock). Revert.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/ui
git commit -m "feat(web): settings for auto-lock, master password, sessions, and recovery"
```

---

## Task 12: The admin screen

**Files:**
- Create: `apps/web/src/ui/screens/AdminScreen.tsx`
- Test: `apps/web/src/ui/screens/AdminScreen.test.tsx`

**Three sections:** users, collections overview, audit log.

**Requirements with teeth:**

- **The invite link is shown once and said to be once.** The raw token exists only in the create response. Render it in a selectable, copyable field with: *"Hand this over out of band. It cannot be shown again — reissue a new one if it is lost."* Wire a copy button, but never rely on the clipboard alone, which fails silently in insecure contexts.
- **Reset requires typing the account's email** in the `Confirm` dialog (`requireTyped`), and the dialog states what is destroyed: key material, personal items, and every collection membership, with re-granting required after they enrol again. The server re-checks it; the dialog is not the only gate but it is the one the human reads.
- **A 409 on delete shows the server's own message** — it names the obstacle and the next step, and a generic "could not delete" throws that away.
- **The audit log is a table** with actor, action, target, and time, newest first, with a "Load older" control passing `before`.

- [ ] **Step 1: Write the failing tests**

```tsx
it("shows the invite link and says it cannot be shown again", async () => {
  // ...create a user
  expect(await screen.findByDisplayValue(/\/enroll\/tok_/)).toBeInTheDocument();
  expect(screen.getByText(/cannot be shown again/i)).toBeInTheDocument();
});

it("keeps reset disabled until the account's email is typed exactly", async () => {
  await userEvent.click(screen.getByRole("button", { name: /reset/i }));
  const confirm = screen.getByRole("button", { name: /reset this account/i });
  expect(confirm).toBeDisabled();
  await userEvent.type(screen.getByLabelText(/type the email/i), "bee@example.co");
  expect(confirm).toBeDisabled();
  await userEvent.type(screen.getByLabelText(/type the email/i), "m");
  expect(confirm).toBeEnabled();
});

it("states that collection access must be re-granted after a reset", async () => {
  expect(screen.getByText(/re-granted/i)).toBeInTheDocument();
});

it("shows the server's explanation when a delete conflicts", async () => {
  onDelete.mockRejectedValue(new ApiError("conflict", 409, "this account created a collection or granted a membership. Delete or reassign those collections first, or disable the account instead.", null));
  await userEvent.click(/* delete, confirm */);
  expect(await screen.findByRole("alert")).toHaveTextContent(/reassign those collections/i);
});

it("passes the oldest loaded entry as `before` when loading older audit entries", async () => {
  await userEvent.click(screen.getByRole("button", { name: /load older/i }));
  expect(onLoadAudit).toHaveBeenCalledWith(expect.objectContaining({ before: "2026-07-01T00:00:00Z" }));
});

it("renders no key material for any listed user", () => {
  // The admin list endpoint carries none by construction; this asserts the
  // screen does not invent a place to put some.
  const html = container.innerHTML.toLowerCase().replace(/_/g, "");
  for (const needle of ["protecteduserkey", "encryptedprivatekey", "authhash", "kdfsalt", "recoverysalt"]) {
    expect(html).not.toContain(needle);
  }
});
```

That last test's normalization — lowercase and strip underscores — is deliberate, and copied from `internal/httpapi/helpers_test.go` for the same reason: a needle list that only spells one casing missed every key it existed to catch when this was written in Go.

- [ ] **Step 2–4: Implement and run**

```bash
cd apps/web && pnpm test && pnpm typecheck && pnpm lint
```

- [ ] **Step 5: Mutation check**

Mutation A — drop `requireTyped` from the reset dialog. "keeps reset disabled until the account's email is typed exactly" must fail.

Mutation B — replace the delete error branch with a literal `"Could not delete this account"`. "shows the server's explanation when a delete conflicts" must fail. Revert.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/ui
git commit -m "feat(web): admin screen for users, invites, resets, and the audit log"
```

---

## Task 13: End to end — two users share a collection

Plan 3's Playwright suite found a real application bug on its first run and proved a claim no mock could. This task extends it to the flow that matters most here, because sharing spans two browsers, two keypairs, and a sealed blob the server cannot inspect.

**Files:**
- Modify: `apps/web/e2e/server.ts`
- Create: `apps/web/e2e/sharing.spec.ts`

**Interfaces:**
- Consumes: the existing helper that builds the Go binary, migrates, runs `admin create`, parses the invite URL from stdout, and waits on `/healthz`.
- Produces: `createUser(adminContext, {email, name})` returning the invite URL, so a spec can enrol a second account.

**Two footguns already paid for in Plan 3, do not rediscover them:**
- `pnpm dev` binds IPv6-only `localhost`; the health check on `127.0.0.1` never connects. Pass `--host 127.0.0.1`.
- `reuseExistingServer` will silently attach to a stale server from a previous run. Keep it off in CI.

- [ ] **Step 1: Write the failing spec**

`apps/web/e2e/sharing.spec.ts`, one test, using two browser contexts:

```ts
test("an admin shares a collection and the second user reads the item", async ({ browser }) => {
  // 1. Admin enrols from the CLI invite URL, sets a master password.
  // 2. Admin > Users > creates "bee@example.com", copies the invite URL.
  // 3. Second context opens that URL, enrols, saves its recovery code.
  // 4. Admin > Collections > creates "Household".
  // 5. Admin adds Bee as a member — the fingerprint is on screen before
  //    confirming — and the result reads "granted", not "pending", because
  //    the admin created the collection and holds its key.
  // 6. Admin creates an item in Household with a distinctive password.
  // 7. Bee reloads, unlocks, and sees the item with the correct password.
  //    This is the assertion the whole feature exists for: a value that
  //    travelled through the server as ciphertext only, opened by a key the
  //    server never held.
  // 8. Admin removes Bee, and is shown the not-retroactive warning.
  // 9. Bee reloads and unlocks: the item is gone from her list.
});
```

Also add one negative assertion that a mock cannot make:

```ts
test("the server rejects a params object with reordered keys", async ({ request }) => {
  // Plan 3 proved this: JSON.stringify of an equivalent object passes by luck
  // when V8 preserves literal key order, and fails the moment anything
  // reorders. The pinned constant is the contract.
  // Expect 400 and: field "params": must match the server's current KDF parameters exactly
});
```

- [ ] **Step 2: Run it**

```bash
cd apps/web && pnpm test:e2e
```

Expect real failures first, and expect at least one of them to be an application bug rather than a test bug — that is what this task is for. Fix the application, not the assertion, unless the assertion is genuinely wrong.

- [ ] **Step 3: Commit**

```bash
git add apps/web/e2e
git commit -m "test(web): end-to-end sharing between two real accounts"
```

---

## Task 14: Final pass

- [ ] **Step 1: Full verification**

```bash
cd apps/web && pnpm test && pnpm typecheck && pnpm lint && pnpm test:e2e
pnpm -r test
go build ./... && go vet ./... && gofmt -l . && go test ./...
```

Go is unchanged by this plan, so it must still be green — if it is not, something reached outside the intended scope.

- [ ] **Step 2: Check the two storage keys**

In a browser with an unlocked vault, `Object.keys(localStorage)` must be exactly `["keyhole.email", "keyhole.autolock"]`. Then `indexedDB.databases()` must be empty. Design spec §6.3 is a gate; this is the check that it held.

- [ ] **Step 3: Check the import ban still fires**

Add `import { zeroize } from "@keyhole/crypto";` to one new `.tsx` file, run `pnpm lint`, confirm it fails, remove it. A `.ts` probe does not prove this — that mistake is exactly why the rule silently did not run for a whole task in Plan 3.

- [ ] **Step 4: Commit any fixes and hand off**

Use superpowers:finishing-a-development-branch.

---

## Self-review

**Spec coverage.** §3.5 sealing and pending grants → Tasks 2, 6, 10. §3.8 auto-lock → Task 8, 11. §3.9.1 fingerprints → Tasks 5, 10. §5.1 collection roles and the not-retroactive warning → Tasks 6, 10. §6.2 screens: collections ✓, settings ✓, admin ✓; import is Plan 6; item detail and generator shipped in Plan 3. §6.3 memory-only → Tasks 1, 14. §9 error handling → Tasks 11, 12.

**Deliberately not covered, and why.**
- **Recovery-code redemption.** Needs a migration, a crypto addition with new pinned vectors, and two unauthenticated endpoints. Task 10 corrects the copy so the product stops promising it.
- **Folders.** The API exists; no screen. Items carry `folderId` in their plaintext and it round-trips untouched.
- **PWA and the offline ciphertext cache** (§6.5). Belongs with the deployment plan, which is what decides how the app is served.
- **Import** (§7). Its own plan.
- **Collection key rotation on removal.** Deferred by the spec itself (§5.1); this plan surfaces the consequence in the UI instead of hiding it.

**Type consistency check.** `CollectionSummary` is produced by `adoptCollections` (Task 2) and `createCollection` (Task 6) and consumed by `VaultState.collections` (Task 4) and every screen — same four fields throughout. `DirectoryEntry` is produced only by Task 5 and consumed by Tasks 6 and 10. `updateItem` takes one object from Task 3 onward; every call site is updated in Task 3, and `pnpm typecheck` is the gate. `PendingGrant` is declared in `collections.ts` and re-exported for `admin.ts`'s overview rather than declared twice.
