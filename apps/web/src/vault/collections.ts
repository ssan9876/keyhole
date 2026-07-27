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
