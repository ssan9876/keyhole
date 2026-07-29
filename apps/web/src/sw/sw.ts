// The service worker entry — thin glue over the tested pure functions in this
// directory. It is bundled to dist/sw.js ONLY by the Vite build hook (see
// vite.config.ts's swPrecachePlugin); nothing in the app, in dev, or in the
// test run imports it, so a dev/test session behaves exactly as it did before
// this file existed.
//
// __PRECACHE__ is replaced at build time (Vite `define`) with the real emitted
// shell filenames — index.html plus the hashed assets. Hand-maintaining that
// list would precache a stale filename that 404s and fail install on the first
// rebuild; deriving it from the bundle is the whole point.

import {
  deleteStaleCaches,
  handleRequest,
  precacheShell,
  type CacheLike,
} from "./handler.js";
import { cacheName } from "./precache.js";

declare const __PRECACHE__: readonly string[];

const PRECACHE = __PRECACHE__;
const CACHE = cacheName(PRECACHE);
const SHELL_URL = "/";

// Only the service-worker-specific bits are declared locally; caches, fetch,
// URL, Request, and Response come from the DOM lib. Declaring a minimal shape
// (rather than pulling the whole WebWorker lib in, which collides with DOM
// globally) keeps typecheck clean without a second tsconfig.
interface ExtendableEventLike {
  waitUntil(promise: Promise<unknown>): void;
}
interface FetchEventLike extends ExtendableEventLike {
  readonly request: Request;
  respondWith(response: Response | Promise<Response>): void;
}
interface ServiceWorkerScope {
  readonly registration: { readonly scope: string };
  skipWaiting(): Promise<void>;
  readonly clients: { claim(): Promise<void> };
  addEventListener(type: "install" | "activate", listener: (event: ExtendableEventLike) => void): void;
  addEventListener(type: "fetch", listener: (event: FetchEventLike) => void): void;
}

const sw = self as unknown as ServiceWorkerScope;

sw.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      const cache = (await caches.open(CACHE)) as CacheLike;
      await precacheShell({ cache, fetch }, PRECACHE, SHELL_URL);
      // Take over as soon as the shell is cached rather than waiting for every
      // tab to close; activate then wipes any older cache.
      await sw.skipWaiting();
    })(),
  );
});

sw.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      await deleteStaleCaches(caches, CACHE);
      await sw.clients.claim();
    })(),
  );
});

sw.addEventListener("fetch", (event) => {
  // Same-origin only, matching the server CSP default-src 'self'. A cross-origin
  // request is left entirely to the browser — the SW fetches nothing off-origin.
  const scopeOrigin = new URL(sw.registration.scope).origin;
  if (new URL(event.request.url).origin !== scopeOrigin) return;

  event.respondWith(
    (async () => {
      const cache = (await caches.open(CACHE)) as CacheLike;
      return handleRequest(event.request, { cache, fetch, shellUrl: SHELL_URL });
    })(),
  );
});
