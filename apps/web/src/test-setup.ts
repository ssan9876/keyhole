import "@testing-library/jest-dom/vitest";

// jsdom does not implement window.isSecureContext -- it is simply absent,
// which App.tsx's boot guard (added for TLS deployments) treats as an
// insecure origin and refuses to render anything past the warning screen.
// Every test in this suite other than the guard's own negative cases
// exercises the app the way it runs in production, over HTTPS, so default
// this to true here once instead of in every file. The guard's own tests
// override it locally with vi.stubGlobal.
Object.defineProperty(window, "isSecureContext", {
  value: true,
  configurable: true,
  writable: true,
});
