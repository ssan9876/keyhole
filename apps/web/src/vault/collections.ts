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
      // Reuse the key already held when this id was already held, rather than
      // opening the sealed blob again. Required: setCollectionKeys zeroizes
      // by object identity, so handing back a freshly-opened buffer for an
      // unchanged collection would zeroize the live key on every sync. Sound:
      // collection keys are never rotated (design spec §5.1 — removing a
      // member does not rotate the key; rotation is deliberately deferred),
      // and the grant paths in internal/store/collections.go only ever
      // re-seal that same key to a new recipient. So a re-sealed blob for an
      // id we already hold is guaranteed to carry the key we already have.
      //
      // If collection-key rotation is ever implemented, this line becomes
      // wrong: a rotated key would arrive under an id already held and never
      // be opened, and the vault would silently keep decrypting with a
      // superseded key.
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
  try {
    const sealedCollectionKey = await sealToUser(collectionKey, fromBase64(input.ownPublicKey));

    const created = await deps.api.post<WireCollection>("/api/collections", {
      name: input.name,
      sealedCollectionKey,
    });

    // Install it directly rather than waiting for the next sync to seal-and-open
    // a key we already have in hand.
    const next = new Map<string, Uint8Array>();
    for (const id of deps.session.collectionIds()) {
      const existing = deps.session.getCollectionKey(id);
      if (existing !== null) next.set(id, existing);
    }
    next.set(created.id, collectionKey);
    deps.session.setCollectionKeys(next);

    return { id: created.id, name: created.name, role: "manager", usable: true };
  } catch (err) {
    // The key was generated but never handed to setCollectionKeys, so nothing
    // else in this codebase will ever get a chance to zero it out.
    zeroize(collectionKey);
    throw err;
  }
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
