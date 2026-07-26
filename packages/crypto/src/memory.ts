/**
 * Overwrite key material once it is no longer needed — this is what auto-lock
 * calls to clear wrapKey, userKey, and any decrypted item keys (spec §3.8).
 *
 * It is also used inside this package, for secrets the application layer never
 * sees and therefore cannot clear: the masterKey and wrappingKey behind
 * enrollment, rotation and an unlock session; the recovery key; per-item keys;
 * and the ephemeral private key, X25519 shared secret and derived seal key
 * behind sealing. The rule there is narrow — clear only what this package
 * itself created and is about to discard, never a value returned to the caller
 * and never one the caller passed in.
 *
 * **This narrows the window in which a heap snapshot yields a key; it does not
 * close it.** A JavaScript engine may already have copied the bytes elsewhere
 * — during garbage collection, for instance — and nothing in the language lets
 * us reach those copies. It is worth doing regardless. It is not a security
 * boundary, and no threat model should be written as though it were.
 */
export function zeroize(...buffers: (Uint8Array | null | undefined)[]): void {
  for (const buffer of buffers) {
    buffer?.fill(0);
  }
}
