// Deriving the shell precache list from the real build output, and naming the
// cache after it. Both are pure so the Vite hook and the service worker share
// one tested implementation.

/**
 * Turns the filenames Vite emitted into the shell precache list: index.html
 * (the navigable shell) plus every hashed asset. Hand-maintaining this list is
 * the documented footgun — it goes stale on the first rebuild and precaches a
 * filename that now 404s, which fails `install`. So the Vite build hook calls
 * this with the actual emitted bundle keys.
 *
 * The manifest, icons, and any other emitted file are deliberately left out:
 * only the code shell has to be on disk to boot offline, and precaching more
 * just widens the surface that can go stale.
 */
export function buildPrecacheList(emitted: readonly string[]): string[] {
  const assets = emitted.filter((name) => name.startsWith("assets/"));
  return ["index.html", ...[...assets].sort()];
}

/**
 * Names the cache after a hash of the precache list. Asset filenames already
 * carry content hashes, so hashing the sorted list yields a stable per-build
 * id: a new build lands in a new cache, and `activate` deletes every cache that
 * is not the current one — a clean swap with no stale shell surviving.
 */
export function cacheName(precache: readonly string[]): string {
  // FNV-1a over the sorted, newline-joined list. Order-independent by sorting
  // first, so the same build always names the same cache.
  let hash = 0x811c9dc5;
  const joined = [...precache].sort().join("\n");
  for (let i = 0; i < joined.length; i++) {
    hash ^= joined.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return `keyhole-shell-${(hash >>> 0).toString(36)}`;
}
