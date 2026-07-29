// Registering the service worker — the one place the app opts into it, and it
// opts in only in a production build. The routing and lifecycle logic lives in
// sw.ts (and its tested pure helpers); this file decides *whether* to bring any
// of it to life at all.

/**
 * Registers the service worker, but only in a production build the browser
 * supports, and never in a way that can break boot.
 *
 * `isProduction` defaults to `import.meta.env.PROD`; it is a parameter purely so
 * the guard is testable without stubbing the build env. In the real app,
 * main.tsx calls this with no argument, so the value is whatever Vite compiled
 * in — true for `vite build`, false for `vite` dev.
 *
 * Two guards, both load-bearing:
 *   - `!isProduction` keeps dev (where the SW cache fights HMR) and the vitest
 *     run (which has no real SW) behaving exactly as they did before this
 *     existed. This is the guard the dev/test path depends on.
 *   - `"serviceWorker" in navigator` lets an old browser boot instead of
 *     throwing on a missing API.
 *
 * A failed registration is logged and swallowed: a shell that will not install
 * or load offline is a lost enhancement, never a broken app. Nothing about the
 * vault depends on the service worker.
 *
 * No auto-reload is wired here on a new version, deliberately. Task 2's
 * skipWaiting/clients.claim swaps assets on the next navigation, which is
 * enough; a reload triggered under the user could interrupt someone mid-edit.
 */
export function registerServiceWorker(isProduction: boolean = import.meta.env.PROD): void {
  if (!isProduction) return;
  if (!("serviceWorker" in navigator)) return;
  navigator.serviceWorker.register("/sw.js").catch((error: unknown) => {
    console.error("Keyhole: service worker registration failed", error);
  });
}
