/**
 * Overwrite key material once it is no longer needed — this is what auto-lock
 * calls to clear wrapKey, userKey, and any decrypted item keys.
 *
 * An honest caveat: JavaScript gives no guarantee the engine has not already
 * copied these bytes elsewhere (during GC compaction, for example), so this
 * narrows the window in which a heap snapshot yields a key rather than closing
 * it. It is worth doing regardless; it is not a security boundary.
 */
export function zeroize(...buffers: (Uint8Array | null | undefined)[]): void {
  for (const buffer of buffers) {
    buffer?.fill(0);
  }
}
