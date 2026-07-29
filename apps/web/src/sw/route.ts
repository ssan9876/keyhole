// The routing decision, as a pure function — no browser, no cache, no fetch, so
// every rule below is unit-testable directly. The service worker glue in sw.ts
// does nothing but call this and act on the answer.

export type Route = "bypass" | "cache-first" | "network-first" | "network";

/** The minimal shape route needs: a URL and, for navigations, the request mode.
 *  A real `Request` satisfies it structurally, and a test can pass a plain
 *  object — the fetch spec forbids constructing a Request with mode "navigate",
 *  so the pure function must not depend on the Request constructor. */
export interface RoutableRequest {
  readonly url: string;
  readonly mode?: string;
}

export function route(request: RoutableRequest): Route {
  const { pathname } = new URL(request.url);

  // THE rule this whole plan turns on. An /api response carries a bearer token
  // and vault ciphertext; it is never read from the cache and never written to
  // it. Checked first, before every other rule, so nothing can route an /api
  // path to a caching strategy.
  if (pathname === "/api" || pathname.startsWith("/api/")) return "bypass";

  // A navigation — the address bar, or a deep link like /enroll/<token>.
  // Network-first: online it picks up a fresh deploy, offline it falls back to
  // the precached shell so a cold load still reaches the unlock screen instead
  // of a browser error page.
  if (request.mode === "navigate") return "network-first";

  // Hashed, immutable build assets. Vite content-hashes every filename it emits
  // under /assets/, and the Go server serves that prefix `immutable`, so the
  // name pins the bytes and cache-first is permanently safe.
  if (pathname.startsWith("/assets/")) return "cache-first";

  // Anything else same-origin (a favicon, the manifest): straight to the
  // network, cached neither way.
  return "network";
}
