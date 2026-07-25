import { sha256 } from "@noble/hashes/sha256";
import { concatBytes, utf8Encode } from "./encoding.js";
import { encodeCrockford, groupChars } from "./crockford.js";

const FINGERPRINT_CHARS = 16;
const GROUP_SIZE = 4;

/**
 * A short, human-readable identifier for a public key, shown so two people can
 * read it aloud and confirm the server handed them the right key. Binding the
 * email in means a substituted key under a different identity will not match.
 */
export function publicKeyFingerprint(publicKey: Uint8Array, email: string): string {
  const normalizedEmail = utf8Encode(email.trim().toLowerCase());
  const digest = sha256(concatBytes(normalizedEmail, publicKey));
  return groupChars(encodeCrockford(digest.slice(0, FINGERPRINT_CHARS)), GROUP_SIZE);
}
