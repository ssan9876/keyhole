import { describe, expect, it, vi } from "vitest";
import { registerServiceWorker } from "./register.js";

/**
 * Installs a stand-in `navigator.serviceWorker.register`, returning a restore.
 *
 * jsdom has no `navigator.serviceWorker` at all, so a test that only checked
 * "register was not called" against the bare environment would pass because the
 * API is absent, not because the production guard held — and a registration
 * wired into the dev path would sail straight through. Supplying the API makes
 * the guard the ONLY thing that can stop the call.
 */
function withServiceWorker(register: (url: string) => Promise<unknown>): () => void {
  const previous = Object.getOwnPropertyDescriptor(navigator, "serviceWorker");
  Object.defineProperty(navigator, "serviceWorker", {
    value: { register },
    configurable: true,
  });
  return () => {
    if (previous) Object.defineProperty(navigator, "serviceWorker", previous);
    else Reflect.deleteProperty(navigator, "serviceWorker");
  };
}

describe("registerServiceWorker", () => {
  it("does not register the service worker outside a production build", () => {
    // The whole point of the guard: dev fights the SW cache against HMR and the
    // vitest run has no real SW, so both must behave exactly as they did before
    // registration existed. import.meta.env.PROD is false under vitest, exactly
    // as under `vite` dev; asserting it here makes the precondition explicit so
    // this test cannot pass silently if a future config ever flips it.
    expect(import.meta.env.PROD).toBe(false);
    const register = vi.fn((_url: string) => Promise.resolve({}));
    const restore = withServiceWorker(register);
    try {
      registerServiceWorker();
      expect(register).not.toHaveBeenCalled();
    } finally {
      restore();
    }
  });

  it("registers /sw.js exactly once in a production build the browser supports", () => {
    const register = vi.fn((_url: string) => Promise.resolve({}));
    const restore = withServiceWorker(register);
    try {
      registerServiceWorker(true);
      expect(register).toHaveBeenCalledTimes(1);
      expect(register).toHaveBeenCalledWith("/sw.js");
    } finally {
      restore();
    }
  });

  it("does not throw where the browser lacks service-worker support, even in production", () => {
    // An old browser without navigator.serviceWorker must still boot the app,
    // not crash on a missing API.
    Reflect.deleteProperty(navigator, "serviceWorker");
    expect("serviceWorker" in navigator).toBe(false);
    expect(() => registerServiceWorker(true)).not.toThrow();
  });

  it("swallows a failed registration so a boot never depends on the service worker", async () => {
    // A rejected register() must be caught inside registerServiceWorker: an
    // app that will not install or load offline is a lost enhancement, never a
    // broken boot. An uncaught rejection here would surface as a test failure.
    const register = vi.fn((_url: string) => Promise.reject(new Error("registration blocked")));
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const restore = withServiceWorker(register);
    try {
      registerServiceWorker(true);
      // Let the rejected promise settle and its .catch run.
      await Promise.resolve();
      await Promise.resolve();
      expect(errorSpy).toHaveBeenCalled();
    } finally {
      restore();
      errorSpy.mockRestore();
    }
  });
});
