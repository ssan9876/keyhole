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
