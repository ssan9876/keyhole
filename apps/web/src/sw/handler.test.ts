import { describe, expect, it } from "vitest";
import { deleteStaleCaches, handleRequest, precacheShell } from "./handler.js";

/**
 * A fake Cache the SW writes to, so a test can inspect exactly what landed on
 * disk. `store` is the whole point: the /api rule is proven by asserting this
 * map holds no /api key after an /api request is handled.
 */
const urlOf = (req: RequestInfo | URL): string =>
  typeof req === "string" ? req : req instanceof URL ? req.href : req.url;

function fakeCache() {
  const store = new Map<string, Response>();
  const keyOf = urlOf;
  return {
    store,
    match: async (req: RequestInfo | URL) => store.get(keyOf(req)),
    put: async (req: RequestInfo | URL, res: Response) => {
      store.set(keyOf(req), res);
    },
  };
}

describe("handleRequest", () => {
  it("writes no /api entry to the cache while handling an /api request", async () => {
    const cache = fakeCache();
    const fetched: string[] = [];
    const fetch: typeof globalThis.fetch = async (input) => {
      fetched.push(urlOf(input));
      return new Response("vault-ciphertext");
    };
    const request = new Request("https://vault.example/api/sync");

    const response = await handleRequest(request, { cache, fetch });

    // It reached the network and returned the live response...
    expect(fetched).toContain("https://vault.example/api/sync");
    expect(await response.text()).toBe("vault-ciphertext");
    // ...and left nothing on disk. Inspect the cache directly: no /api key, and
    // in fact no key at all. This is THE assertion the whole plan turns on, and
    // it must fail if the /api rule is flipped to a caching strategy.
    expect([...cache.store.keys()].filter((key) => key.includes("/api"))).toEqual([]);
    expect(cache.store.size).toBe(0);
  });

  it("serves a hashed asset from cache without touching the network", async () => {
    const cache = fakeCache();
    cache.store.set("https://vault.example/assets/index-AbC123.js", new Response("cached-js"));
    let networkCalls = 0;
    const fetch = async () => {
      networkCalls++;
      return new Response("network-js");
    };
    const request = new Request("https://vault.example/assets/index-AbC123.js");

    const response = await handleRequest(request, { cache, fetch });

    expect(await response.text()).toBe("cached-js");
    expect(networkCalls).toBe(0);
  });

  it("caches a hashed asset the first time it is fetched, then it is immutable", async () => {
    const cache = fakeCache();
    const fetch = async () => new Response("fresh-js");
    const request = new Request("https://vault.example/assets/index-AbC123.js");

    await handleRequest(request, { cache, fetch });

    expect(cache.store.has("https://vault.example/assets/index-AbC123.js")).toBe(true);
  });

  it("falls back to the cached shell when a navigation cannot reach the network", async () => {
    const cache = fakeCache();
    cache.store.set("/", new Response("<!doctype html>shell"));
    const fetch = async () => {
      throw new TypeError("Failed to fetch"); // offline
    };
    const request = { url: "https://vault.example/enroll/x", mode: "navigate" } as unknown as Request;

    const response = await handleRequest(request, { cache, fetch, shellUrl: "/" });

    // A deep link opened cold and offline still gets the shell (the unlock
    // screen), not the browser's own error page.
    expect(await response.text()).toBe("<!doctype html>shell");
  });

  it("does not cache a navigation response, so per-token URLs never accumulate", async () => {
    const cache = fakeCache();
    const fetch = async () => new Response("<!doctype html>fresh");
    const request = {
      url: "https://vault.example/enroll/secret-token",
      mode: "navigate",
    } as unknown as Request;

    await handleRequest(request, { cache, fetch, shellUrl: "/" });

    expect(cache.store.size).toBe(0);
  });
});

describe("precacheShell", () => {
  it("stores the shell under '/' rather than the literal index.html path", async () => {
    const cache = fakeCache();
    const fetch = async () => new Response("ok");

    await precacheShell({ cache, fetch }, ["index.html", "assets/a-1.js"], "/");

    // The Go file server 301-redirects /index.html to /, which cache.add would
    // reject; the shell is fetched and stored under "/" so navigation fallback
    // can find it.
    expect([...cache.store.keys()]).toContain("/");
    expect([...cache.store.keys()]).toContain("/assets/a-1.js");
    expect([...cache.store.keys()]).not.toContain("/index.html");
  });

  it("rejects the install when a precached asset is missing, rather than caching a 404", async () => {
    const cache = fakeCache();
    const fetch = async () => new Response("not found", { status: 404 });

    await expect(precacheShell({ cache, fetch }, ["assets/gone-1.js"], "/")).rejects.toThrow();
  });
});

describe("deleteStaleCaches", () => {
  it("deletes every cache except the current build's", async () => {
    const deleted: string[] = [];
    const caches = {
      keys: async () => ["keyhole-shell-old", "keyhole-shell-current", "unrelated"],
      delete: async (name: string) => {
        deleted.push(name);
        return true;
      },
    };

    await deleteStaleCaches(caches, "keyhole-shell-current");

    expect(deleted).toContain("keyhole-shell-old");
    expect(deleted).toContain("unrelated");
    expect(deleted).not.toContain("keyhole-shell-current");
  });
});
