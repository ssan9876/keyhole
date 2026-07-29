// The per-request handler and the lifecycle helpers, written against injected
// `cache` and `fetch` so they run — and are inspected — without a browser. The
// security-critical property lives here: for a "bypass" (and a plain "network")
// route, cache.put is never called, so an /api response cannot reach disk.

import { route } from "./route.js";

// Exactly the global fetch signature, so the SW wires in `fetch` with no
// wrapper, and precacheShell can pass a URL string plus an init.
export type Fetcher = typeof fetch;

/** The slice of the Cache API the handler uses. Narrowed to an interface so a
 *  test can supply a fake and read back exactly what was written. A real
 *  `Cache` is assignable to it. */
export interface CacheLike {
  match(request: RequestInfo | URL): Promise<Response | undefined>;
  put(request: RequestInfo | URL, response: Response): Promise<void>;
}

/** The slice of CacheStorage `deleteStaleCaches` needs. A real `CacheStorage`
 *  is assignable to it. */
export interface CacheStorageLike {
  keys(): Promise<string[]>;
  delete(cacheName: string): Promise<boolean>;
}

export interface HandlerDeps {
  cache: CacheLike;
  fetch: Fetcher;
  /** Cache key the offline navigation fallback serves. Defaults to "/". */
  shellUrl?: string;
}

export async function handleRequest(request: Request, deps: HandlerDeps): Promise<Response> {
  const shellUrl = deps.shellUrl ?? "/";

  switch (route(request)) {
    case "bypass":
      // Straight to the network. No cache read, no cache write — this one line
      // is why a stolen device yields no vault.
      return deps.fetch(request);

    case "cache-first": {
      // Immutable hashed asset: serve the cached copy if present, otherwise
      // fetch once and keep it. Its hashed name guarantees the bytes never
      // change under that URL.
      const cached = await deps.cache.match(request);
      if (cached) return cached;
      const response = await deps.fetch(request);
      if (response.ok) await deps.cache.put(request, response.clone());
      return response;
    }

    case "network-first": {
      // Navigation: prefer the network so a new deploy is picked up, and fall
      // back to the precached shell when offline. The fresh response is NOT
      // cached here — the precache plus the SW-update swap keep the shell fresh,
      // and caching per-navigation would pile up one entry per /enroll/<token>.
      try {
        return await deps.fetch(request);
      } catch (error) {
        const shell = (await deps.cache.match(request)) ?? (await deps.cache.match(shellUrl));
        if (shell) return shell;
        throw error;
      }
    }

    default:
      // "network": same-origin but not part of the shell. No caching either way.
      return deps.fetch(request);
  }
}

/**
 * `install` calls this: fetch and store exactly the current build's shell. Any
 * asset that does not come back 2xx throws, which fails the install rather than
 * caching a 404 — a half-populated cache would boot a broken app offline.
 *
 * index.html is stored under the navigable shell URL ("/"), not the literal
 * "/index.html": the Go file server 301-redirects the literal path to "/", and
 * caching a redirect would make the offline fallback miss.
 */
export async function precacheShell(
  deps: { cache: CacheLike; fetch: Fetcher },
  precache: readonly string[],
  shellUrl = "/",
): Promise<void> {
  await Promise.all(
    precache.map(async (name) => {
      const url = name === "index.html" ? shellUrl : `/${name}`;
      // A URL string (not a constructed Request) so a relative "/" resolves
      // against the SW scope in the browser. `cache: "reload"` makes install
      // populate from the network, never from the browser's HTTP cache.
      const response = await deps.fetch(url, { cache: "reload" });
      if (!response.ok) {
        throw new Error(`precache failed for ${url}: ${response.status}`);
      }
      await deps.cache.put(url, response.clone());
    }),
  );
}

/**
 * `activate` calls this: delete every cache whose name is not the current
 * build's, so a superseded shell cannot survive into the new version.
 */
export async function deleteStaleCaches(
  caches: CacheStorageLike,
  currentName: string,
): Promise<void> {
  const names = await caches.keys();
  await Promise.all(
    names.filter((name) => name !== currentName).map((name) => caches.delete(name)),
  );
}
