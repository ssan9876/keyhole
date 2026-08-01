# Keyhole Browser Extension Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Prerequisite:** `docs/superpowers/plans/2026-07-30-packages-vault-extraction.md` must be complete and merged. Every task here imports from `@keyhole/vault`.

**Goal:** A Chromium (Chrome and Edge) MV3 extension that fills saved Keyhole credentials into web pages from a toolbar popup and offers to save new ones.

**Architecture:** Four contexts split by what each may know. An offscreen document holds all key material in a closure and runs the vault session; a service worker routes messages and owns no keys; a React popup renders every screen; a content script detects forms, applies a single fill on demand, and reports submissions. The server gains no endpoints.

**Tech Stack:** TypeScript 5.8, Vite 6, React 19, vitest, Playwright, Chrome MV3, `psl` for registrable-domain parsing.

## Global Constraints

- **Never fill over plain `http://`**, except `localhost`.
- **Never fill into cross-origin iframes.**
- **Never fill on page load, and never auto-submit.** Filling happens only on explicit user action.
- **One credential per fill.** The content script never receives the vault or a candidate list.
- **The service worker holds no key material.** It may hold one pending save capture, bounded to 5 minutes, cleared on lock and on browser close.
- **Domain matching is on the registrable domain (eTLD+1), never a substring.**
- **Clipboard copies clear after 20 seconds.**
- **Excluded surfaces:** `file://`, `chrome://`, `edge://`, `https://chrome.google.com/webstore`, `https://chromewebstore.google.com`, and the extension's own pages.
- **No remote code.** The MV3 CSP forbids it; no dependency may be fetched at runtime.
- **The service worker has no DOM.** No `window`, no `document`, no `localStorage`, no `sessionStorage`. This is gated by ESLint in Task 1, not left to convention — `packages/vault` shipped with the same property maintained only by a docstring, and its final review found nothing would have stopped a contributor breaking it.
- **Do NOT add `WebWorker` to the extension's tsconfig `lib`.** This package is genuinely mixed: the popup and content script need `DOM`, the service worker must not use it. TypeScript cannot express both — listing `DOM` and `WebWorker` together produces duplicate-declaration errors. `packages/vault` uses `lib: ["ES2022", "WebWorker"]` because it is uniformly DOM-free; do not copy that here. Inherit `DOM` from `tsconfig.base.json` and let the ESLint rule above carry the worker's constraint instead.
- TypeScript is strict per `tsconfig.base.json`: `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`. Type-only imports must use `import type`.
- Relative imports carry a `.js` extension.
- The unit-test total from the extraction plan's Task 4 is the floor. It must never drop.
- Run all commands from the repository root.

## File Structure

| File | Responsibility |
|---|---|
| `apps/extension/manifest.json` | MV3 manifest; permissions and entry points |
| `apps/extension/vite.config.ts` | Multi-entry build: popup, service worker, offscreen, content script |
| `apps/extension/src/match/site.ts` | Registrable-domain matching — the security-critical module |
| `apps/extension/src/platform/chromePreferences.ts` | Hydrated `PreferenceStore` over `chrome.storage.local` |
| `apps/extension/src/platform/serverUrl.ts` | Server address config and host-permission request |
| `apps/extension/src/messages.ts` | The typed message protocol shared by all four contexts |
| `apps/extension/src/offscreen/offscreen.ts` | Owns `Session` + `VaultStore`; the only place keys exist |
| `apps/extension/src/worker/worker.ts` | Message router, alarms, badge |
| `apps/extension/src/worker/capture.ts` | Pending save-capture state machine |
| `apps/extension/src/worker/lock.ts` | Alarm-driven auto-lock |
| `apps/extension/src/content/detect.ts` | Form and field detection |
| `apps/extension/src/content/fill.ts` | Applies one credential to detected fields |
| `apps/extension/src/content/content.ts` | Content-script entry; wires detect, fill, submit observation |
| `apps/extension/src/popup/*` | React UI: unlock, list, item, generator, save prompt, settings |

Each module is split so its tests can run in isolation: `match`, `detect`, `fill`, and `capture` are pure functions over inputs, with no `chrome.*` calls. Everything that touches `chrome.*` is confined to `platform/`, `worker/`, `offscreen/`, and the content-script entry.

---

### Task 1: Scaffold the extension package

**Files:**
- Create: `apps/extension/package.json`, `tsconfig.json`, `vitest.config.ts`, `eslint.config.js`, `vite.config.ts`, `manifest.json`
- Create: `apps/extension/src/popup/index.html`, `src/popup/main.tsx`
- Create: `apps/extension/src/worker/worker.ts`, `src/offscreen/offscreen.html`, `src/offscreen/offscreen.ts`, `src/content/content.ts`
- Create: `apps/extension/src/scaffold.test.ts`

**Interfaces:**
- Consumes: `@keyhole/vault`.
- Produces: a loadable unpacked extension; the build command `pnpm --filter @keyhole/extension build` emitting `dist/`.

- [ ] **Step 1: Write `apps/extension/package.json`**

```json
{
  "name": "@keyhole/extension",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "build": "vite build",
    "test": "vitest run",
    "test:watch": "vitest",
    "typecheck": "tsc --noEmit",
    "lint": "eslint ."
  },
  "dependencies": {
    "@keyhole/crypto": "workspace:*",
    "@keyhole/vault": "workspace:*",
    "psl": "^1.15.0",
    "react": "^19.1.0",
    "react-dom": "^19.1.0"
  },
  "devDependencies": {
    "@types/chrome": "^0.0.313",
    "@types/psl": "^1.1.3",
    "@types/react": "^19.1.0",
    "@types/react-dom": "^19.1.0",
    "@vitejs/plugin-react": "^4.4.0",
    "eslint": "^9.26.0",
    "jsdom": "^26.1.0",
    "typescript-eslint": "^8.32.0",
    "vite": "^6.3.0",
    "vitest": "^3.1.4"
  }
}
```

- [ ] **Step 2: Write `apps/extension/tsconfig.json`**

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "jsx": "react-jsx",
    "types": ["chrome", "vitest/globals"]
  },
  "include": ["src", "*.config.ts"]
}
```

- [ ] **Step 3: Write `apps/extension/vitest.config.ts`**

```ts
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    // jsdom, because form detection and fill are the heart of this package and
    // they operate on real DOM nodes.
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    testTimeout: 30_000,
  },
});
```

- [ ] **Step 4: Write `apps/extension/eslint.config.js`**

```js
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    files: ["src/**/*.{ts,tsx}"],
    extends: [tseslint.configs.recommended],
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
  {
    // The same gate the web app carries, for the same reason: the popup and
    // content script must not hold key material. Only src/offscreen may reach
    // the vault session directly.
    files: ["src/popup/**/*.{ts,tsx}", "src/content/**/*.ts", "src/worker/**/*.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          paths: [
            {
              name: "@keyhole/crypto",
              message:
                "Only src/offscreen may touch crypto. Everything else asks it " +
                "over the message protocol.",
            },
          ],
          // Name-only bans are trivially defeated by a deep relative path.
          // apps/web shipped with exactly that hole.
          patterns: [
            {
              group: ["**/packages/crypto/**"],
              message:
                "Only src/offscreen may touch crypto, by any path. Everything " +
                "else asks it over the message protocol.",
            },
          ],
        },
      ],
    },
  },
  {
    // The service worker runs with no DOM at all. Nothing in the type system
    // catches this: tsconfig inherits `lib: DOM` (which the popup and content
    // script genuinely need), and @types/node declares `localStorage`
    // globally, so even a WebWorker lib would miss it. packages/vault learned
    // this the expensive way — it held the same property by docstring alone
    // until a review pointed out nothing enforced it.
    //
    // Scoped to the worker only. The offscreen document is a real page and
    // has a DOM; the popup and content script obviously do.
    files: ["src/worker/**/*.ts"],
    ignores: ["src/worker/**/*.test.ts"],
    rules: {
      "no-restricted-globals": [
        "error",
        {
          name: "localStorage",
          message: "A service worker has no localStorage. Use chrome.storage.",
        },
        {
          name: "sessionStorage",
          message: "A service worker has no sessionStorage.",
        },
        {
          name: "document",
          message: "A service worker has no DOM. Ask the offscreen document or a tab.",
        },
        {
          name: "window",
          message: "A service worker has no window. Use `self` if you need the global.",
        },
      ],
    },
  },
);
```

- [ ] **Step 5: Write `apps/extension/manifest.json`**

`host_permissions` is deliberately absent: a self-hosted install cannot know the server address at build time, so it is requested at runtime as an optional permission (Task 4).

```json
{
  "manifest_version": 3,
  "name": "Keyhole",
  "version": "0.1.0",
  "description": "Fill and save credentials from your self-hosted Keyhole vault.",
  "minimum_chrome_version": "116",
  "action": { "default_popup": "src/popup/index.html", "default_title": "Keyhole" },
  "background": { "service_worker": "service-worker.js", "type": "module" },
  "permissions": ["storage", "alarms", "offscreen", "activeTab", "scripting", "clipboardWrite"],
  "optional_host_permissions": ["https://*/*"],
  "content_scripts": [
    {
      "matches": ["https://*/*", "http://localhost/*"],
      "js": ["content.js"],
      "run_at": "document_idle",
      "all_frames": false
    }
  ],
  "content_security_policy": {
    "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
  }
}
```

Two notes worth understanding before changing either line. `'wasm-unsafe-eval'` is required because Argon2id runs via `hash-wasm`; without it the offscreen document cannot unlock. `"all_frames": false` is the cross-origin-iframe constraint enforced at the manifest level, which is stronger than a runtime check.

- [ ] **Step 6: Write `apps/extension/vite.config.ts`**

```ts
import { fileURLToPath } from "node:url";
import { copyFileSync } from "node:fs";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

const entry = (path: string): string => fileURLToPath(new URL(path, import.meta.url));

// The manifest is not an ES module and Vite will not emit it; copy it verbatim.
function copyManifest(): Plugin {
  return {
    name: "keyhole-copy-manifest",
    apply: "build",
    closeBundle() {
      copyFileSync(entry("./manifest.json"), entry("./dist/manifest.json"));
    },
  };
}

export default defineConfig({
  plugins: [react(), copyManifest()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: entry("./src/popup/index.html"),
        offscreen: entry("./src/offscreen/offscreen.html"),
        // Flat, predictable names because manifest.json references them by
        // path and a hashed filename would break every reload.
        "service-worker": entry("./src/worker/worker.ts"),
        content: entry("./src/content/content.ts"),
      },
      output: {
        entryFileNames: "[name].js",
        chunkFileNames: "chunks/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
});
```

- [ ] **Step 7: Write minimal entry points**

`src/popup/index.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Keyhole</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="./main.tsx"></script>
  </body>
</html>
```

`src/popup/main.tsx`:

```tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

const root = document.getElementById("root");
if (root === null) throw new Error("No #root element");
createRoot(root).render(
  <StrictMode>
    <p>Keyhole</p>
  </StrictMode>,
);
```

`src/offscreen/offscreen.html`:

```html
<!doctype html>
<html lang="en">
  <head><meta charset="utf-8" /><title>Keyhole offscreen</title></head>
  <body><script type="module" src="./offscreen.ts"></script></body>
</html>
```

`src/offscreen/offscreen.ts`, `src/worker/worker.ts`, and `src/content/content.ts` each start as:

```ts
export {};
```

- [ ] **Step 8: Write the scaffold test**

`src/scaffold.test.ts`:

```ts
import { readFileSync } from "node:fs";
import { expect, it } from "vitest";

const manifest = JSON.parse(
  readFileSync(new URL("../manifest.json", import.meta.url), "utf8"),
) as {
  manifest_version: number;
  host_permissions?: string[];
  content_scripts: { all_frames: boolean }[];
  content_security_policy: { extension_pages: string };
};

it("is an MV3 manifest", () => {
  expect(manifest.manifest_version).toBe(3);
});

// A self-hosted install cannot know the server address at build time. A static
// host_permissions entry would either over-grant or not work.
it("declares no static host permissions", () => {
  expect(manifest.host_permissions).toBeUndefined();
});

// The cross-origin-iframe constraint, enforced where it cannot be bypassed at
// runtime.
it("never injects into subframes", () => {
  for (const script of manifest.content_scripts) {
    expect(script.all_frames).toBe(false);
  }
});

// Argon2id runs through hash-wasm; without this the vault cannot unlock.
it("permits wasm in extension pages", () => {
  expect(manifest.content_security_policy.extension_pages).toContain("'wasm-unsafe-eval'");
});
```

- [ ] **Step 9: Install, test, build**

```bash
pnpm install && pnpm --filter @keyhole/extension test && pnpm --filter @keyhole/extension build
```

Expected: 4 tests pass; `apps/extension/dist/` contains `manifest.json`, `service-worker.js`, `content.js`, and the popup and offscreen HTML.

- [ ] **Step 9a: Prove both ESLint gates fire**

A gate nobody has seen fire is not a gate. `packages/vault` shipped a lint config that CI never ran, and the crypto ban in `apps/web` had a deep-relative-path hole that went unnoticed until a review probed it. Verify by hand:

```bash
printf 'export const x = localStorage.getItem("k");\n' > apps/extension/src/worker/__gate-probe.ts
printf 'import { zeroize } from "../../../../packages/crypto/src/memory.js";\nexport const y = zeroize;\n' > apps/extension/src/popup/__crypto-probe.ts
pnpm --filter @keyhole/extension lint
```

Expected: FAIL twice — `no-restricted-globals` on `__gate-probe.ts`, and `no-restricted-imports` on `__crypto-probe.ts` matching the `patterns` group rather than the `paths` name. If the second does not fire, the `patterns` entry is wrong and the ban is name-only.

Then remove both:

```bash
rm apps/extension/src/worker/__gate-probe.ts apps/extension/src/popup/__crypto-probe.ts
```

Record the exact error output for both in your report.

- [ ] **Step 10: Load it in Chrome by hand**

Open `chrome://extensions`, enable Developer mode, choose "Load unpacked", select `apps/extension/dist`. Expected: the extension loads with no errors, and clicking its icon shows "Keyhole".

- [ ] **Step 11: Add `dist/` to gitignore and commit**

```bash
printf 'apps/extension/dist/\n' >> .gitignore
git add apps/extension .gitignore pnpm-lock.yaml
git commit -m "feat(extension): scaffold the MV3 extension package"
```

---

### Task 2: Registrable-domain matching

The most security-critical module in the project. Written first, and tested adversarially rather than for the happy path.

**Files:**
- Create: `apps/extension/src/match/site.ts`
- Create: `apps/extension/src/match/site.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `function registrableDomain(url: string): string | null`
  - `function isFillableUrl(url: string): boolean`
  - `function matchesSite(itemUrls: readonly string[], pageUrl: string): boolean`

- [ ] **Step 1: Write the failing tests**

`src/match/site.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { isFillableUrl, matchesSite, registrableDomain } from "./site.js";

describe("registrableDomain", () => {
  it("reduces a subdomain to eTLD+1", () => {
    expect(registrableDomain("https://gist.github.com/x")).toBe("github.com");
  });

  // The public suffix list is why this cannot be "last two labels".
  it("respects multi-label public suffixes", () => {
    expect(registrableDomain("https://foo.co.uk")).toBe("foo.co.uk");
    expect(registrableDomain("https://a.b.foo.co.uk")).toBe("foo.co.uk");
  });

  it("returns null for a bare public suffix", () => {
    expect(registrableDomain("https://co.uk")).toBeNull();
  });

  it("returns null for garbage", () => {
    expect(registrableDomain("not a url")).toBeNull();
  });

  it("returns the host for localhost", () => {
    expect(registrableDomain("http://localhost:5173/x")).toBe("localhost");
  });
});

describe("isFillableUrl", () => {
  it("accepts https", () => {
    expect(isFillableUrl("https://example.com")).toBe(true);
  });

  // A password filled onto a cleartext page is a password disclosed.
  it("rejects plain http", () => {
    expect(isFillableUrl("http://example.com")).toBe(false);
  });

  it("accepts http on localhost, for development", () => {
    expect(isFillableUrl("http://localhost:5173")).toBe(true);
  });

  it.each([
    "file:///etc/passwd",
    "chrome://settings",
    "edge://settings",
    "https://chrome.google.com/webstore",
    "https://chromewebstore.google.com/detail/x",
  ])("rejects %s", (url) => {
    expect(isFillableUrl(url)).toBe(false);
  });
});

describe("matchesSite", () => {
  it("matches an exact host", () => {
    expect(matchesSite(["https://github.com"], "https://github.com/login")).toBe(true);
  });

  it("matches across subdomains of the same registrable domain", () => {
    expect(matchesSite(["https://github.com"], "https://gist.github.com/x")).toBe(true);
  });

  // Every one of these is a real phishing shape. Substring matching passes
  // all of them; that is the bug this module exists to prevent.
  it.each([
    ["https://github.com.evil.tk/login", "suffix-appended"],
    ["https://evil-github.com/login", "hyphen-prefixed"],
    ["https://githubxcom.evil.tk/login", "separator-substituted"],
    ["https://notgithub.com/login", "label-prefixed"],
    ["https://github.com.br.evil.io/login", "double-suffixed"],
  ])("refuses %s (%s)", (pageUrl) => {
    expect(matchesSite(["https://github.com"], pageUrl)).toBe(false);
  });

  it("refuses when the item has no urls", () => {
    expect(matchesSite([], "https://github.com")).toBe(false);
  });

  it("ignores an unparseable stored url rather than throwing", () => {
    expect(matchesSite(["not a url", "https://github.com"], "https://github.com")).toBe(true);
  });

  it("refuses on a page that is not fillable at all", () => {
    expect(matchesSite(["https://github.com"], "http://github.com")).toBe(false);
  });
});
```

- [ ] **Step 2: Run to confirm failure**

```bash
pnpm --filter @keyhole/extension test -- src/match/site.test.ts
```

Expected: FAIL — unresolved import.

- [ ] **Step 3: Implement**

`src/match/site.ts`:

```ts
import psl from "psl";

/**
 * Registrable-domain matching. The most security-critical module here.
 *
 * Naive matching is how autofillers leak credentials: `includes("github.com")`
 * is true for `github.com.evil.tk`, and "last two labels" is wrong for every
 * multi-label public suffix like `co.uk`. Both mistakes hand a password to an
 * attacker who controls a hostname, which costs nothing to arrange. So the
 * Public Suffix List is bundled and consulted, and the comparison is equality
 * between registrable domains — never a substring, never a suffix test.
 */

const BLOCKED_HOSTS = new Set(["chrome.google.com", "chromewebstore.google.com"]);

/** Loopback development servers are the one place plain http is permitted:
 *  the traffic never leaves the machine. */
function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

function parse(url: string): URL | null {
  try {
    return new URL(url);
  } catch {
    // A stored item may hold anything a user typed. An unparseable URL is not
    // an error worth throwing over — it simply matches nothing.
    return null;
  }
}

export function registrableDomain(url: string): string | null {
  const parsed = parse(url);
  if (parsed === null) return null;
  if (isLoopback(parsed.hostname)) return parsed.hostname;

  const result = psl.parse(parsed.hostname);
  // psl returns a union: an error result, or a parsed one. `in` narrows it;
  // reading `.error` off the union directly does not compile under strict mode.
  if ("error" in result) return null;
  // `domain` is null when the host *is* a public suffix (`co.uk`), which is
  // never a thing anyone holds an account on and must never match.
  return result.domain;
}

export function isFillableUrl(url: string): boolean {
  const parsed = parse(url);
  if (parsed === null) return false;
  if (BLOCKED_HOSTS.has(parsed.hostname)) return false;
  if (parsed.protocol === "https:") return true;
  return parsed.protocol === "http:" && isLoopback(parsed.hostname);
}

export function matchesSite(itemUrls: readonly string[], pageUrl: string): boolean {
  if (!isFillableUrl(pageUrl)) return false;
  const page = registrableDomain(pageUrl);
  if (page === null) return false;
  return itemUrls.some((stored) => registrableDomain(stored) === page);
}
```

- [ ] **Step 4: Run to confirm it passes**

```bash
pnpm --filter @keyhole/extension test -- src/match/site.test.ts
```

Expected: PASS, 21 tests.

- [ ] **Step 5: Prove the tests would catch the bug**

Temporarily replace the body of `matchesSite`'s `some` callback with the naive version — `stored.includes(page)` — and re-run. Expected: the five phishing cases FAIL. Restore the correct implementation and re-run to green. A test that does not fail against the wrong implementation is not testing anything.

- [ ] **Step 6: Commit**

```bash
git add apps/extension/src/match
git commit -m "feat(extension): registrable-domain matching via the public suffix list

Substring matching passes github.com.evil.tk. Tested against five real
phishing shapes, each verified to fail against the naive implementation."
```

---

### Task 3: The chrome.storage preference adapter

**Files:**
- Create: `apps/extension/src/platform/chromePreferences.ts`
- Create: `apps/extension/src/platform/chromePreferences.test.ts`

**Interfaces:**
- Consumes: `PreferenceStore` from `@keyhole/vault`.
- Produces: `async function hydratedPreferenceStore(area?: chrome.storage.StorageArea): Promise<PreferenceStore>`

- [ ] **Step 1: Write the failing tests**

`src/platform/chromePreferences.test.ts`:

```ts
import { describe, expect, it, vi } from "vitest";
import { hydratedPreferenceStore } from "./chromePreferences.js";

function fakeArea(initial: Record<string, string> = {}) {
  const data: Record<string, string> = { ...initial };
  return {
    get: vi.fn(async () => ({ ...data })),
    set: vi.fn(async (items: Record<string, string>) => void Object.assign(data, items)),
    remove: vi.fn(async (key: string) => void delete data[key]),
    /** Test-only view of what was actually persisted. */
    raw: data,
  };
}

describe("hydratedPreferenceStore", () => {
  it("serves reads synchronously from the hydrated snapshot", async () => {
    const area = fakeArea({ "keyhole.email": "a@b.c" });
    const store = await hydratedPreferenceStore(area as unknown as chrome.storage.StorageArea);
    expect(store.get("keyhole.email")).toBe("a@b.c");
  });

  it("reports null for an absent key", async () => {
    const store = await hydratedPreferenceStore(fakeArea() as unknown as chrome.storage.StorageArea);
    expect(store.get("nope")).toBeNull();
  });

  it("makes a write visible to the next synchronous read", async () => {
    const area = fakeArea();
    const store = await hydratedPreferenceStore(area as unknown as chrome.storage.StorageArea);
    store.set("k", "v");
    // The point of the cache: no await between set and get.
    expect(store.get("k")).toBe("v");
  });

  it("writes through to the storage area", async () => {
    const area = fakeArea();
    const store = await hydratedPreferenceStore(area as unknown as chrome.storage.StorageArea);
    store.set("k", "v");
    await vi.waitFor(() => expect(area.raw["k"]).toBe("v"));
  });

  it("removes from both the cache and the area", async () => {
    const area = fakeArea({ k: "v" });
    const store = await hydratedPreferenceStore(area as unknown as chrome.storage.StorageArea);
    store.remove("k");
    expect(store.get("k")).toBeNull();
    await vi.waitFor(() => expect(area.raw["k"]).toBeUndefined());
  });
});
```

- [ ] **Step 2: Run to confirm failure**

```bash
pnpm --filter @keyhole/extension test -- src/platform/chromePreferences.test.ts
```

Expected: FAIL — unresolved import.

- [ ] **Step 3: Implement**

`src/platform/chromePreferences.ts`:

```ts
import type { PreferenceStore } from "@keyhole/vault";

/**
 * `PreferenceStore` over `chrome.storage.local`.
 *
 * The interface is synchronous and `chrome.storage` is not, so the whole area
 * is read once at context startup and served from memory thereafter, with
 * writes going through in the background. That is safe because the area holds
 * exactly two small preference keys and this is the only writer.
 *
 * The alternative — an async PreferenceStore — would have forced every caller
 * in the web app, including `useState(readAutoLock)`, into an effect, to solve
 * a problem only the extension has.
 *
 * A rejected write is logged and dropped rather than thrown: the caller is a
 * synchronous setter with nowhere to put an error, and losing a remembered
 * email is not worth crashing a context over.
 */
export async function hydratedPreferenceStore(
  area: chrome.storage.StorageArea = chrome.storage.local,
): Promise<PreferenceStore> {
  const cache = new Map<string, string>();
  const initial = (await area.get(null)) as Record<string, unknown>;
  for (const [key, value] of Object.entries(initial)) {
    if (typeof value === "string") cache.set(key, value);
  }

  const report = (error: unknown): void => {
    console.error("Keyhole: could not persist a preference", error);
  };

  return {
    get: (key) => cache.get(key) ?? null,
    set: (key, value) => {
      cache.set(key, value);
      void area.set({ [key]: value }).catch(report);
    },
    remove: (key) => {
      cache.delete(key);
      void area.remove(key).catch(report);
    },
  };
}
```

- [ ] **Step 4: Run to confirm it passes**

```bash
pnpm --filter @keyhole/extension test -- src/platform/chromePreferences.test.ts
```

Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add apps/extension/src/platform
git commit -m "feat(extension): hydrated PreferenceStore over chrome.storage.local"
```

---

### Task 4: Server address and host permission

**Files:**
- Create: `apps/extension/src/platform/serverUrl.ts`
- Create: `apps/extension/src/platform/serverUrl.test.ts`

**Interfaces:**
- Consumes: `PreferenceStore` (Task 3).
- Produces:
  - `const SERVER_URL_KEY = "keyhole.serverUrl"`
  - `function normaliseServerUrl(raw: string): string | null`
  - `function originPattern(serverUrl: string): string`
  - `function readServerUrl(store: PreferenceStore): string | null`
  - `function writeServerUrl(store: PreferenceStore, url: string): void`

- [ ] **Step 1: Write the failing tests**

`src/platform/serverUrl.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import type { PreferenceStore } from "@keyhole/vault";
import {
  SERVER_URL_KEY,
  normaliseServerUrl,
  originPattern,
  readServerUrl,
  writeServerUrl,
} from "./serverUrl.js";

function fakeStore(initial: Record<string, string> = {}): PreferenceStore {
  const map = new Map(Object.entries(initial));
  return {
    get: (key) => map.get(key) ?? null,
    set: (key, value) => void map.set(key, value),
    remove: (key) => void map.delete(key),
  };
}

describe("normaliseServerUrl", () => {
  it("keeps a bare https origin", () => {
    expect(normaliseServerUrl("https://vault.example.com")).toBe("https://vault.example.com");
  });

  it("strips a trailing slash, so paths concatenate cleanly", () => {
    expect(normaliseServerUrl("https://vault.example.com/")).toBe("https://vault.example.com");
  });

  it("strips a path, because only the origin is ever used", () => {
    expect(normaliseServerUrl("https://vault.example.com/vault/x")).toBe("https://vault.example.com");
  });

  it("assumes https when no scheme is given", () => {
    expect(normaliseServerUrl("vault.example.com")).toBe("https://vault.example.com");
  });

  it("preserves a non-default port", () => {
    expect(normaliseServerUrl("https://vault.example.com:8477")).toBe("https://vault.example.com:8477");
  });

  it("permits http on localhost for development", () => {
    expect(normaliseServerUrl("http://localhost:8477")).toBe("http://localhost:8477");
  });

  // The vault would be sent over cleartext. Refuse rather than warn.
  it("refuses plain http on a remote host", () => {
    expect(normaliseServerUrl("http://vault.example.com")).toBeNull();
  });

  it("refuses garbage", () => {
    expect(normaliseServerUrl("  ")).toBeNull();
  });
});

describe("originPattern", () => {
  it("produces a match pattern chrome.permissions accepts", () => {
    expect(originPattern("https://vault.example.com")).toBe("https://vault.example.com/*");
  });
});

describe("read/write", () => {
  it("round-trips", () => {
    const store = fakeStore();
    writeServerUrl(store, "https://vault.example.com");
    expect(readServerUrl(store)).toBe("https://vault.example.com");
  });

  it("reports null before setup", () => {
    expect(readServerUrl(fakeStore())).toBeNull();
  });

  it("stores under the documented key", () => {
    const store = fakeStore();
    writeServerUrl(store, "https://vault.example.com");
    expect(store.get(SERVER_URL_KEY)).toBe("https://vault.example.com");
  });
});
```

- [ ] **Step 2: Run to confirm failure**

```bash
pnpm --filter @keyhole/extension test -- src/platform/serverUrl.test.ts
```

Expected: FAIL — unresolved import.

- [ ] **Step 3: Implement**

`src/platform/serverUrl.ts`:

```ts
import type { PreferenceStore } from "@keyhole/vault";

/**
 * Where this install's Keyhole server lives.
 *
 * Every deployment is somebody's own hostname, so this cannot be baked into
 * the manifest and cannot be a static host permission. It is collected at
 * setup, stored as a preference, and turned into a match pattern that
 * `chrome.permissions.request` will accept.
 */
export const SERVER_URL_KEY = "keyhole.serverUrl";

function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

export function normaliseServerUrl(raw: string): string | null {
  const trimmed = raw.trim();
  if (trimmed === "") return null;
  // A user typing a hostname means https. Defaulting the other way would send
  // an auth hash over cleartext because someone omitted five characters.
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

  let parsed: URL;
  try {
    parsed = new URL(withScheme);
  } catch {
    return null;
  }

  if (parsed.protocol === "http:" && !isLoopback(parsed.hostname)) return null;
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
  // `origin` drops the path, query, and any trailing slash in one step.
  return parsed.origin;
}

export function originPattern(serverUrl: string): string {
  return `${serverUrl}/*`;
}

export function readServerUrl(store: PreferenceStore): string | null {
  return store.get(SERVER_URL_KEY);
}

export function writeServerUrl(store: PreferenceStore, url: string): void {
  store.set(SERVER_URL_KEY, url);
}
```

- [ ] **Step 4: Run to confirm it passes**

```bash
pnpm --filter @keyhole/extension test -- src/platform/serverUrl.test.ts
```

Expected: PASS, 12 tests.

- [ ] **Step 5: Commit**

```bash
git add apps/extension/src/platform/serverUrl.ts apps/extension/src/platform/serverUrl.test.ts
git commit -m "feat(extension): server address config and origin pattern"
```

---

### Task 5: The message protocol

Every cross-context call goes through one typed union. Defined before any context uses it, so the four implementations cannot drift.

**Files:**
- Create: `apps/extension/src/messages.ts`
- Create: `apps/extension/src/messages.test.ts`

**Interfaces:**
- Consumes: `ItemRecord` from `@keyhole/vault`.
- Produces: `type Request`, `type Response`, `function isRequest(value: unknown): value is Request`, and `type ItemSummary`.

- [ ] **Step 1: Write the failing tests**

`src/messages.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { isRequest } from "./messages.js";

describe("isRequest", () => {
  it("accepts a well-formed request", () => {
    expect(isRequest({ kind: "vault/status" })).toBe(true);
  });

  it.each([null, undefined, 42, "vault/status", [], {}, { kind: 42 }, { kind: "" }])(
    "rejects %s",
    (value) => {
      expect(isRequest(value)).toBe(false);
    },
  );

  // Anything on a page can postMessage. The guard is the boundary, so it must
  // reject rather than assume.
  it("rejects an unknown kind", () => {
    expect(isRequest({ kind: "vault/exfiltrate" })).toBe(false);
  });
});
```

- [ ] **Step 2: Run to confirm failure**

```bash
pnpm --filter @keyhole/extension test -- src/messages.test.ts
```

Expected: FAIL — unresolved import.

- [ ] **Step 3: Implement**

`src/messages.ts`:

```ts
/**
 * The one protocol every context speaks.
 *
 * A single discriminated union rather than ad-hoc objects, because four
 * contexts implement halves of it and a typo in a string literal would
 * otherwise be a runtime-only failure in whichever one nobody tested by hand.
 *
 * `isRequest` is a real boundary, not a formality: content scripts share a
 * world with the page, so anything reaching the worker is untrusted until it
 * has been shape-checked.
 */

/** What the popup renders. Deliberately not the full item: no password, and
 *  nothing the popup does not draw. The password crosses only on a fill. */
export interface ItemSummary {
  id: string;
  name: string;
  username: string;
  matchesCurrentSite: boolean;
}

export interface Credential {
  username: string;
  password: string;
}

export interface CaptureCandidate {
  url: string;
  username: string;
  password: string;
}

export type Request =
  | { kind: "vault/status" }
  | { kind: "vault/unlock"; email: string; masterPassword: string }
  | { kind: "vault/lock" }
  | { kind: "vault/items"; pageUrl: string | null; query: string }
  | { kind: "vault/credential"; itemId: string }
  | { kind: "vault/save"; capture: CaptureCandidate; itemId: string | null; name: string }
  | { kind: "tab/fill"; itemId: string }
  | { kind: "capture/report"; capture: CaptureCandidate }
  | { kind: "capture/pending" }
  | { kind: "capture/dismiss" }
  | { kind: "activity/ping" };

export type Response =
  | { ok: true; kind: "vault/status"; unlocked: boolean; email: string | null; serverUrl: string | null }
  | { ok: true; kind: "vault/items"; items: ItemSummary[] }
  | { ok: true; kind: "vault/credential"; credential: Credential }
  | { ok: true; kind: "capture/pending"; capture: CaptureCandidate | null; suggestedName: string }
  | { ok: true; kind: "ack" }
  | { ok: false; error: string; code: "locked" | "network" | "permission" | "credentials" | "internal" };

const KINDS: ReadonlySet<string> = new Set<Request["kind"]>([
  "vault/status",
  "vault/unlock",
  "vault/lock",
  "vault/items",
  "vault/credential",
  "vault/save",
  "tab/fill",
  "capture/report",
  "capture/pending",
  "capture/dismiss",
  "activity/ping",
]);

export function isRequest(value: unknown): value is Request {
  if (typeof value !== "object" || value === null) return false;
  const kind: unknown = (value as { kind?: unknown }).kind;
  return typeof kind === "string" && KINDS.has(kind);
}
```

- [ ] **Step 4: Run to confirm it passes**

```bash
pnpm --filter @keyhole/extension test -- src/messages.test.ts
```

Expected: PASS, 10 tests.

- [ ] **Step 5: Commit**

```bash
git add apps/extension/src/messages.ts apps/extension/src/messages.test.ts
git commit -m "feat(extension): the typed cross-context message protocol"
```

---

### Task 6: Form detection

**Files:**
- Create: `apps/extension/src/content/detect.ts`
- Create: `apps/extension/src/content/detect.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `interface DetectedForm { username: HTMLInputElement | null; password: HTMLInputElement | null; }`
  - `function detectForm(root: Document | HTMLElement): DetectedForm`

- [ ] **Step 1: Write the failing tests**

`src/content/detect.test.ts`:

```ts
import { beforeEach, describe, expect, it } from "vitest";
import { detectForm } from "./detect.js";

function render(html: string): Document {
  document.body.innerHTML = html;
  return document;
}

beforeEach(() => {
  document.body.innerHTML = "";
});

describe("detectForm", () => {
  it("finds a conventional login form", () => {
    const doc = render(`
      <form>
        <input name="username" type="text" />
        <input name="password" type="password" />
      </form>`);
    const found = detectForm(doc);
    expect(found.username?.getAttribute("name")).toBe("username");
    expect(found.password?.getAttribute("name")).toBe("password");
  });

  it("prefers an autocomplete hint over a name guess", () => {
    const doc = render(`
      <form>
        <input name="q" type="text" autocomplete="username" />
        <input name="user" type="text" />
        <input type="password" autocomplete="current-password" />
      </form>`);
    expect(detectForm(doc).username?.getAttribute("name")).toBe("q");
  });

  it("treats an email input as the username", () => {
    const doc = render(`
      <form>
        <input type="email" name="e" />
        <input type="password" />
      </form>`);
    expect(detectForm(doc).username?.getAttribute("name")).toBe("e");
  });

  // A second-step page has no username field at all.
  it("finds a password with no username present", () => {
    const doc = render(`<form><input type="password" /></form>`);
    const found = detectForm(doc);
    expect(found.password).not.toBeNull();
    expect(found.username).toBeNull();
  });

  // Honeypots are how bot-detection catches naive fillers. Filling one is a
  // ban, not a bug report.
  it.each([
    `<input type="password" style="display:none" />`,
    `<input type="password" hidden />`,
    `<input type="password" aria-hidden="true" />`,
  ])("skips the hidden decoy in %s", (decoy) => {
    const doc = render(`<form>${decoy}<input type="password" name="real" /></form>`);
    expect(detectForm(doc).password?.getAttribute("name")).toBe("real");
  });

  it("skips a disabled or readonly field", () => {
    const doc = render(`
      <form>
        <input type="password" disabled name="off" />
        <input type="password" readonly name="ro" />
        <input type="password" name="real" />
      </form>`);
    expect(detectForm(doc).password?.getAttribute("name")).toBe("real");
  });

  // A registration form: filling the confirmation with the current password
  // silently breaks the signup.
  it("takes the first password field when a form has two", () => {
    const doc = render(`
      <form>
        <input type="password" name="new" />
        <input type="password" name="confirm" />
      </form>`);
    expect(detectForm(doc).password?.getAttribute("name")).toBe("new");
  });

  it("reports nothing on a page with no password field", () => {
    const doc = render(`<form><input type="text" name="search" /></form>`);
    expect(detectForm(doc)).toEqual({ username: null, password: null });
  });

  it("takes the username nearest above the password, not the first on the page", () => {
    const doc = render(`
      <input type="text" name="newsletter" />
      <form>
        <input type="text" name="login" />
        <input type="password" />
      </form>`);
    expect(detectForm(doc).username?.getAttribute("name")).toBe("login");
  });
});
```

- [ ] **Step 2: Run to confirm failure**

```bash
pnpm --filter @keyhole/extension test -- src/content/detect.test.ts
```

Expected: FAIL — unresolved import.

- [ ] **Step 3: Implement**

`src/content/detect.ts`:

```ts
/**
 * Which fields on this page are the login fields.
 *
 * A pure function over a DOM subtree so it can be tested against real markup
 * in jsdom without any `chrome.*` surface. Everything here is heuristic; the
 * tests encode the shapes that actually matter, and the ordering of the rules
 * is the design.
 */

export interface DetectedForm {
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
}

/**
 * Bot-detection honeypots are hidden password inputs that a human never fills.
 * Filling one identifies the extension as a bot and gets the user blocked, so
 * visibility is checked before anything else.
 *
 * jsdom computes no layout, so `offsetParent` is unavailable; this checks the
 * attributes and inline styles that both jsdom and a real browser agree on.
 */
function isVisible(field: HTMLInputElement): boolean {
  if (field.hidden || field.disabled || field.readOnly) return false;
  if (field.getAttribute("aria-hidden") === "true") return false;
  if (field.type === "hidden") return false;
  const style = field.style;
  if (style.display === "none" || style.visibility === "hidden") return false;
  return true;
}

function candidates(root: Document | HTMLElement, selector: string): HTMLInputElement[] {
  return [...root.querySelectorAll<HTMLInputElement>(selector)].filter(isVisible);
}

const USERNAME_SELECTOR = [
  "input[autocomplete='username']",
  "input[type='email']",
  "input[type='text']",
  "input[type='tel']",
  "input:not([type])",
].join(",");

function scoreUsername(field: HTMLInputElement): number {
  // An explicit autocomplete hint is the site telling us the answer; it beats
  // every guess we could make from a name.
  if (field.getAttribute("autocomplete") === "username") return 3;
  if (field.type === "email") return 2;
  const haystack = `${field.name} ${field.id}`.toLowerCase();
  if (/user|email|login|account/.test(haystack)) return 1;
  return 0;
}

export function detectForm(root: Document | HTMLElement): DetectedForm {
  // First, not last: on a registration form the second password field is the
  // confirmation, and filling it with the existing password breaks the signup.
  const password = candidates(root, "input[type='password']")[0] ?? null;
  if (password === null) return { username: null, password: null };

  // Prefer the enclosing form. A page-level search box or newsletter input is
  // a text field too, and scoring across the whole document would find it.
  const scope = password.closest("form") ?? root;
  const usernames = candidates(scope, USERNAME_SELECTOR).filter((field) => field !== password);
  if (usernames.length === 0) return { username: null, password };

  // Ties break toward the field nearest above the password, which is where a
  // username sits in every conventional layout. `reduce` keeps the first of an
  // equal pair, and DOM order is document order, so this falls out.
  const best = usernames.reduce((winner, field) =>
    scoreUsername(field) > scoreUsername(winner) ? field : winner,
  );
  return { username: scoreUsername(best) > 0 ? best : usernames[0] ?? null, password };
}
```

- [ ] **Step 4: Run to confirm it passes**

```bash
pnpm --filter @keyhole/extension test -- src/content/detect.test.ts
```

Expected: PASS, 13 tests.

- [ ] **Step 5: Commit**

```bash
git add apps/extension/src/content/detect.ts apps/extension/src/content/detect.test.ts
git commit -m "feat(extension): login form detection

Honeypot and confirm-password cases are encoded as tests because both are
silent failures: one gets the user flagged as a bot, the other breaks signup."
```

---

### Task 7: Fill execution

**Files:**
- Create: `apps/extension/src/content/fill.ts`
- Create: `apps/extension/src/content/fill.test.ts`

**Interfaces:**
- Consumes: `DetectedForm` (Task 6), `Credential` (Task 5).
- Produces: `function applyFill(form: DetectedForm, credential: Credential): boolean`

- [ ] **Step 1: Write the failing tests**

`src/content/fill.test.ts`:

```ts
import { beforeEach, describe, expect, it, vi } from "vitest";
import { applyFill } from "./fill.js";

function inputs(): { username: HTMLInputElement; password: HTMLInputElement } {
  document.body.innerHTML = `
    <form>
      <input type="text" id="u" />
      <input type="password" id="p" />
    </form>`;
  return {
    username: document.getElementById("u") as HTMLInputElement,
    password: document.getElementById("p") as HTMLInputElement,
  };
}

const credential = { username: "me@example.com", password: "hunter2" };

beforeEach(() => {
  document.body.innerHTML = "";
});

describe("applyFill", () => {
  it("sets both values", () => {
    const { username, password } = inputs();
    expect(applyFill({ username, password }, credential)).toBe(true);
    expect(username.value).toBe("me@example.com");
    expect(password.value).toBe("hunter2");
  });

  // React and Vue track their own state; a bare `.value =` leaves the
  // framework believing the field is still empty and it wipes the fill on the
  // next render.
  it("dispatches input and change so frameworks observe the write", () => {
    const { username, password } = inputs();
    const seen: string[] = [];
    for (const event of ["input", "change"]) {
      password.addEventListener(event, () => seen.push(event));
    }
    applyFill({ username, password }, credential);
    expect(seen).toEqual(["input", "change"]);
  });

  it("dispatches bubbling events, since frameworks listen at the root", () => {
    const { username, password } = inputs();
    const seen: string[] = [];
    document.body.addEventListener("input", () => seen.push("input"));
    applyFill({ username, password }, credential);
    expect(seen.length).toBeGreaterThan(0);
  });

  it("fills the password alone on a second-step page", () => {
    const { password } = inputs();
    expect(applyFill({ username: null, password }, credential)).toBe(true);
    expect(password.value).toBe("hunter2");
  });

  it("reports failure and writes nothing when there is no password field", () => {
    const { username } = inputs();
    expect(applyFill({ username, password: null }, credential)).toBe(false);
    expect(username.value).toBe("");
  });

  // The constraint that rules out the whole family of invisible-form attacks.
  it("never submits the form", () => {
    const { username, password } = inputs();
    const form = document.querySelector("form") as HTMLFormElement;
    const onSubmit = vi.fn((event: Event) => event.preventDefault());
    form.addEventListener("submit", onSubmit);
    applyFill({ username, password }, credential);
    expect(onSubmit).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run to confirm failure**

```bash
pnpm --filter @keyhole/extension test -- src/content/fill.test.ts
```

Expected: FAIL — unresolved import.

- [ ] **Step 3: Implement**

`src/content/fill.ts`:

```ts
import type { Credential } from "../messages.js";
import type { DetectedForm } from "./detect.js";

/**
 * Writes one credential into the detected fields, and nothing else.
 *
 * It does not submit, does not focus, and does not touch any field it was not
 * handed. Not submitting is the rule that rules out invisible-form harvesting:
 * a hidden form the user never saw cannot be completed without them pressing
 * the button themselves.
 */

/**
 * React and Vue install their own value setter on the input prototype and
 * track state separately from the DOM. Assigning `.value` directly leaves the
 * framework thinking the field is empty, so it reverts the fill on the next
 * render. Calling the native setter and then dispatching makes the write look
 * exactly like typing.
 */
function setValue(field: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  )?.set;
  if (setter === undefined) {
    field.value = value;
  } else {
    setter.call(field, value);
  }
  // Bubbling, because frameworks delegate their listeners at the document root
  // rather than binding each input.
  field.dispatchEvent(new Event("input", { bubbles: true }));
  field.dispatchEvent(new Event("change", { bubbles: true }));
}

export function applyFill(form: DetectedForm, credential: Credential): boolean {
  // No password field means this is not a login form, whatever else it looks
  // like. Writing the username alone would leave a half-filled form and no
  // sign of what went wrong.
  if (form.password === null) return false;
  if (form.username !== null) setValue(form.username, credential.username);
  setValue(form.password, credential.password);
  return true;
}
```

- [ ] **Step 4: Run to confirm it passes**

```bash
pnpm --filter @keyhole/extension test -- src/content/fill.test.ts
```

Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add apps/extension/src/content/fill.ts apps/extension/src/content/fill.test.ts
git commit -m "feat(extension): apply a single credential to detected fields

Uses the native value setter plus bubbling events so React-controlled inputs
keep the fill instead of reverting it on the next render. Never submits."
```

---

### Task 8: The save-capture state machine

**Files:**
- Create: `apps/extension/src/worker/capture.ts`
- Create: `apps/extension/src/worker/capture.test.ts`

**Interfaces:**
- Consumes: `CaptureCandidate` (Task 5), `matchesSite` (Task 2).
- Produces:
  - `type CaptureVerdict = { action: "ignore" } | { action: "create"; suggestedName: string } | { action: "update"; itemId: string }`
  - `function classifyCapture(input: { capture: CaptureCandidate; existing: readonly KnownLogin[] }): CaptureVerdict`
  - `interface KnownLogin { id: string; urls: readonly string[]; username: string; password: string; }`

- [ ] **Step 1: Write the failing tests**

`src/worker/capture.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { classifyCapture, type KnownLogin } from "./capture.js";

const capture = {
  url: "https://github.com/session",
  username: "me@example.com",
  password: "hunter2",
};

const known = (over: Partial<KnownLogin> = {}): KnownLogin => ({
  id: "item-1",
  urls: ["https://github.com"],
  username: "me@example.com",
  password: "hunter2",
  ...over,
});

describe("classifyCapture", () => {
  it("offers to create when nothing matches the site", () => {
    expect(classifyCapture({ capture, existing: [] })).toEqual({
      action: "create",
      suggestedName: "github.com",
    });
  });

  it("offers to create when the site matches but the username is new", () => {
    const verdict = classifyCapture({
      capture,
      existing: [known({ username: "someone-else@example.com" })],
    });
    expect(verdict).toEqual({ action: "create", suggestedName: "github.com" });
  });

  it("offers to update when the username matches and the password differs", () => {
    const verdict = classifyCapture({
      capture,
      existing: [known({ password: "old-password" })],
    });
    expect(verdict).toEqual({ action: "update", itemId: "item-1" });
  });

  // The common case by far. Prompting here would train the user to dismiss.
  it("ignores an exact match", () => {
    expect(classifyCapture({ capture, existing: [known()] })).toEqual({ action: "ignore" });
  });

  it("ignores a capture with an empty password", () => {
    const verdict = classifyCapture({
      capture: { ...capture, password: "" },
      existing: [],
    });
    expect(verdict).toEqual({ action: "ignore" });
  });

  it("ignores a capture from a page it would never fill", () => {
    const verdict = classifyCapture({
      capture: { ...capture, url: "http://github.com/session" },
      existing: [],
    });
    expect(verdict).toEqual({ action: "ignore" });
  });

  // An item saved for another site must not be updated because the username
  // happens to be the same address.
  it("does not match a same-username item from a different site", () => {
    const verdict = classifyCapture({
      capture,
      existing: [known({ urls: ["https://gitlab.com"], password: "old" })],
    });
    expect(verdict).toEqual({ action: "create", suggestedName: "github.com" });
  });

  it("compares usernames case-insensitively, as email is", () => {
    const verdict = classifyCapture({
      capture: { ...capture, username: "ME@example.com" },
      existing: [known({ password: "old" })],
    });
    expect(verdict).toEqual({ action: "update", itemId: "item-1" });
  });
});
```

- [ ] **Step 2: Run to confirm failure**

```bash
pnpm --filter @keyhole/extension test -- src/worker/capture.test.ts
```

Expected: FAIL — unresolved import.

- [ ] **Step 3: Implement**

`src/worker/capture.ts`:

```ts
import type { CaptureCandidate } from "../messages.js";
import { matchesSite, registrableDomain } from "../match/site.js";

/**
 * Whether a submitted credential is worth prompting about.
 *
 * Pure, and separated from the worker, because the interesting behaviour is
 * entirely in the decision: prompting on an exact match trains the user to
 * dismiss the prompt, and then the one that matters is dismissed too.
 */

export interface KnownLogin {
  id: string;
  urls: readonly string[];
  username: string;
  password: string;
}

export type CaptureVerdict =
  | { action: "ignore" }
  | { action: "create"; suggestedName: string }
  | { action: "update"; itemId: string };

const IGNORE: CaptureVerdict = { action: "ignore" };

export function classifyCapture(input: {
  capture: CaptureCandidate;
  existing: readonly KnownLogin[];
}): CaptureVerdict {
  const { capture, existing } = input;
  if (capture.password === "") return IGNORE;
  // The same rule as filling: a page we would refuse to fill is a page we
  // refuse to learn from.
  const domain = registrableDomain(capture.url);
  if (domain === null || !matchesSite([capture.url], capture.url)) return IGNORE;

  const sameUser = capture.username.toLowerCase();
  const onThisSite = existing.filter((item) => matchesSite(item.urls, capture.url));
  const match = onThisSite.find((item) => item.username.toLowerCase() === sameUser);

  if (match === undefined) return { action: "create", suggestedName: domain };
  if (match.password === capture.password) return IGNORE;
  return { action: "update", itemId: match.id };
}
```

- [ ] **Step 4: Run to confirm it passes**

```bash
pnpm --filter @keyhole/extension test -- src/worker/capture.test.ts
```

Expected: PASS, 8 tests.

- [ ] **Step 5: Commit**

```bash
git add apps/extension/src/worker/capture.ts apps/extension/src/worker/capture.test.ts
git commit -m "feat(extension): classify a submitted credential as new, changed, or known"
```

---

### Task 9: Alarm-driven auto-lock

**Files:**
- Create: `apps/extension/src/worker/lock.ts`
- Create: `apps/extension/src/worker/lock.test.ts`

**Interfaces:**
- Consumes: `AutoLockSetting` from `@keyhole/vault`.
- Produces: `function shouldLock(input: { setting: AutoLockSetting; lastActivity: number; now: number }): boolean` and `const LOCK_ALARM_NAME = "keyhole.autolock"`.

- [ ] **Step 1: Write the failing tests**

`src/worker/lock.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { shouldLock } from "./lock.js";

const MINUTE = 60_000;

describe("shouldLock", () => {
  it("never locks when set to never", () => {
    expect(shouldLock({ setting: "never", lastActivity: 0, now: 1e12 })).toBe(false);
  });

  // "on-close" is handled by the session simply not surviving the browser
  // exiting; there is no idle timer to run.
  it("never locks on a timer when set to on-close", () => {
    expect(shouldLock({ setting: "on-close", lastActivity: 0, now: 1e12 })).toBe(false);
  });

  it("does not lock before the interval elapses", () => {
    expect(shouldLock({ setting: 15, lastActivity: 0, now: 14 * MINUTE })).toBe(false);
  });

  it("locks once the interval elapses", () => {
    expect(shouldLock({ setting: 15, lastActivity: 0, now: 15 * MINUTE })).toBe(true);
  });

  // The case an alarm alone misses: alarms do not fire while the machine is
  // asleep, so the check must be against the wall clock, not against how many
  // ticks were observed.
  it("locks after a long sleep that fired no alarms", () => {
    expect(shouldLock({ setting: 5, lastActivity: 0, now: 9 * 60 * MINUTE })).toBe(true);
  });

  it("does not lock when the clock jumps backwards", () => {
    expect(shouldLock({ setting: 15, lastActivity: 10 * MINUTE, now: 0 })).toBe(false);
  });
});
```

- [ ] **Step 2: Run to confirm failure**

```bash
pnpm --filter @keyhole/extension test -- src/worker/lock.test.ts
```

Expected: FAIL — unresolved import.

- [ ] **Step 3: Implement**

`src/worker/lock.ts`:

```ts
import type { AutoLockSetting } from "@keyhole/vault";

/**
 * Idle auto-lock for the extension.
 *
 * The web app drives this from DOM events; a service worker has none, so the
 * decision is a pure function of the wall clock and an alarm calls it.
 *
 * Against the wall clock rather than a tick count for the same reason the web
 * app re-checks on wake: `chrome.alarms` does not fire while the machine is
 * asleep, so counting ticks would leave a vault unlocked across a closed lid —
 * exactly the case this feature exists for.
 */

export const LOCK_ALARM_NAME = "keyhole.autolock";

/** How often the alarm fires. One minute is the finest granularity Chrome
 *  honours for a repeating alarm, and it bounds the overshoot on the shortest
 *  setting to a minute. */
export const LOCK_ALARM_PERIOD_MINUTES = 1;

export function shouldLock(input: {
  setting: AutoLockSetting;
  lastActivity: number;
  now: number;
}): boolean {
  if (input.setting === "never" || input.setting === "on-close") return false;
  const elapsed = input.now - input.lastActivity;
  // A backwards clock jump yields a negative elapsed time. Locking on that
  // would be a spurious lock the user cannot explain; waiting is harmless
  // because the next honest tick will still catch a real idle period.
  if (elapsed < 0) return false;
  return elapsed >= input.setting * 60_000;
}
```

- [ ] **Step 4: Run to confirm it passes**

```bash
pnpm --filter @keyhole/extension test -- src/worker/lock.test.ts
```

Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add apps/extension/src/worker/lock.ts apps/extension/src/worker/lock.test.ts
git commit -m "feat(extension): wall-clock idle lock decision for the service worker"
```

---

### Task 10: The offscreen document

Where every key lives. This is the task that makes the extension a real client.

**Files:**
- Modify: `apps/extension/src/offscreen/offscreen.ts`
- Create: `apps/extension/src/offscreen/vaultHost.ts`
- Create: `apps/extension/src/offscreen/vaultHost.test.ts`

**Interfaces:**
- Consumes: `createSession`, `createVaultStore`, `createApiClient`, `unlock`, `matchesSite`, `Request`, `Response`.
- Produces: `function createVaultHost(deps: VaultHostDeps): VaultHost` with `handle(request: Request): Promise<Response>`.

- [ ] **Step 1: Write the failing tests**

`src/offscreen/vaultHost.test.ts`:

```ts
import { describe, expect, it, vi } from "vitest";
import { createVaultHost } from "./vaultHost.js";

/** A vault host wired to fakes. The real session and store are exercised by
 *  packages/vault's own suite; what matters here is the request handling and,
 *  above all, what does and does not cross the boundary. */
function host(over: Partial<Parameters<typeof createVaultHost>[0]> = {}) {
  return createVaultHost({
    serverUrl: "https://vault.example.com",
    unlock: vi.fn(async () => undefined),
    loadVault: vi.fn(async () => undefined),
    readItems: () => [
      {
        id: "a",
        name: "GitHub",
        username: "me@example.com",
        password: "hunter2",
        urls: ["https://github.com"],
      },
    ],
    isUnlocked: () => true,
    lock: vi.fn(),
    rememberedEmail: () => "me@example.com",
    ...over,
  });
}

describe("vault/items", () => {
  it("flags items that match the current site", async () => {
    const response = await host().handle({
      kind: "vault/items",
      pageUrl: "https://gist.github.com/x",
      query: "",
    });
    expect(response).toMatchObject({ ok: true, kind: "vault/items" });
    if (!response.ok || response.kind !== "vault/items") throw new Error("wrong shape");
    expect(response.items[0]?.matchesCurrentSite).toBe(true);
  });

  // The single most important assertion in this file. A summary carrying a
  // password would put every password in the vault into the popup on open.
  it("never includes a password in a summary", async () => {
    const response = await host().handle({ kind: "vault/items", pageUrl: null, query: "" });
    expect(JSON.stringify(response)).not.toContain("hunter2");
  });

  it("filters by query across the whole vault", async () => {
    const response = await host().handle({ kind: "vault/items", pageUrl: null, query: "hub" });
    if (!response.ok || response.kind !== "vault/items") throw new Error("wrong shape");
    expect(response.items).toHaveLength(1);
  });

  it("returns nothing for a query that matches nothing", async () => {
    const response = await host().handle({ kind: "vault/items", pageUrl: null, query: "zzz" });
    if (!response.ok || response.kind !== "vault/items") throw new Error("wrong shape");
    expect(response.items).toHaveLength(0);
  });

  it("refuses when locked", async () => {
    const response = await host({ isUnlocked: () => false }).handle({
      kind: "vault/items",
      pageUrl: null,
      query: "",
    });
    expect(response).toEqual({ ok: false, error: expect.any(String), code: "locked" });
  });
});

describe("vault/credential", () => {
  it("returns the password for exactly the requested item", async () => {
    const response = await host().handle({ kind: "vault/credential", itemId: "a" });
    if (!response.ok || response.kind !== "vault/credential") throw new Error("wrong shape");
    expect(response.credential).toEqual({ username: "me@example.com", password: "hunter2" });
  });

  it("refuses an unknown id rather than returning a neighbour", async () => {
    const response = await host().handle({ kind: "vault/credential", itemId: "nope" });
    expect(response).toMatchObject({ ok: false });
  });

  it("refuses when locked", async () => {
    const response = await host({ isUnlocked: () => false }).handle({
      kind: "vault/credential",
      itemId: "a",
    });
    expect(response).toEqual({ ok: false, error: expect.any(String), code: "locked" });
  });
});

describe("vault/unlock", () => {
  it("reports a wrong password distinctly from a network failure", async () => {
    const wrong = host({
      isUnlocked: () => false,
      unlock: vi.fn(async () => {
        const error = new Error("Wrong master password");
        error.name = "WrongMasterPasswordError";
        throw error;
      }),
    });
    const response = await wrong.handle({
      kind: "vault/unlock",
      email: "a@b.c",
      masterPassword: "no",
    });
    expect(response).toMatchObject({ ok: false, code: "credentials" });
  });

  it("reports an unreachable server as a network failure, not a bad password", async () => {
    const down = host({
      isUnlocked: () => false,
      unlock: vi.fn(async () => {
        const error = new Error("Could not reach the server");
        error.name = "NetworkError";
        throw error;
      }),
    });
    const response = await down.handle({
      kind: "vault/unlock",
      email: "a@b.c",
      masterPassword: "right",
    });
    expect(response).toMatchObject({ ok: false, code: "network" });
  });
});
```

- [ ] **Step 2: Run to confirm failure**

```bash
pnpm --filter @keyhole/extension test -- src/offscreen/vaultHost.test.ts
```

Expected: FAIL — unresolved import.

- [ ] **Step 3: Implement the host**

`src/offscreen/vaultHost.ts`:

```ts
import type { Request, Response, ItemSummary } from "../messages.js";
import { matchesSite } from "../match/site.js";

/**
 * The request handler for the one context that holds keys.
 *
 * Its dependencies are injected rather than constructed so that the decisions
 * worth testing — what crosses the boundary, and how a failure is classified —
 * can be tested without an Argon2id derivation in every case.
 *
 * The rule this module exists to enforce: a password leaves here only in
 * response to `vault/credential`, naming one item. `vault/items` returns
 * summaries, and a summary has no password field at all, so the popup cannot
 * hold the vault's secrets merely by being open.
 */

export interface HostItem {
  id: string;
  name: string;
  username: string;
  password: string;
  urls: readonly string[];
}

export interface VaultHostDeps {
  serverUrl: string | null;
  unlock(input: { email: string; masterPassword: string }): Promise<void>;
  loadVault(): Promise<void>;
  readItems(): readonly HostItem[];
  isUnlocked(): boolean;
  lock(): void;
  rememberedEmail(): string | null;
}

export interface VaultHost {
  handle(request: Request): Promise<Response>;
}

const locked: Response = { ok: false, error: "The vault is locked", code: "locked" };

/** Classified by error name, not message: the vault layer states that codes
 *  are stable and messages are for humans and may change. A network blip must
 *  never read as a wrong password. */
function classify(error: unknown): Response {
  const name = error instanceof Error ? error.name : "";
  if (name === "WrongMasterPasswordError") {
    return { ok: false, error: "Wrong master password", code: "credentials" };
  }
  if (name === "NetworkError") {
    return { ok: false, error: "Could not reach your Keyhole server", code: "network" };
  }
  return { ok: false, error: "Something went wrong", code: "internal" };
}

function summarise(item: HostItem, pageUrl: string | null): ItemSummary {
  return {
    id: item.id,
    name: item.name,
    username: item.username,
    matchesCurrentSite: pageUrl !== null && matchesSite(item.urls, pageUrl),
  };
}

export function createVaultHost(deps: VaultHostDeps): VaultHost {
  return {
    async handle(request) {
      switch (request.kind) {
        case "vault/status":
          return {
            ok: true,
            kind: "vault/status",
            unlocked: deps.isUnlocked(),
            email: deps.rememberedEmail(),
            serverUrl: deps.serverUrl,
          };

        case "vault/unlock":
          try {
            await deps.unlock({
              email: request.email,
              masterPassword: request.masterPassword,
            });
            await deps.loadVault();
            return { ok: true, kind: "ack" };
          } catch (error) {
            return classify(error);
          }

        case "vault/lock":
          deps.lock();
          return { ok: true, kind: "ack" };

        case "vault/items": {
          if (!deps.isUnlocked()) return locked;
          const query = request.query.trim().toLowerCase();
          const items = deps
            .readItems()
            .filter(
              (item) =>
                query === "" ||
                `${item.name} ${item.username}`.toLowerCase().includes(query),
            )
            .map((item) => summarise(item, request.pageUrl));
          return { ok: true, kind: "vault/items", items };
        }

        case "vault/credential": {
          if (!deps.isUnlocked()) return locked;
          const item = deps.readItems().find((candidate) => candidate.id === request.itemId);
          // Refuse rather than fall back to anything: returning a neighbouring
          // item would fill the wrong password into a real login form.
          if (item === undefined) {
            return { ok: false, error: "No such item", code: "internal" };
          }
          return {
            ok: true,
            kind: "vault/credential",
            credential: { username: item.username, password: item.password },
          };
        }

        default:
          return { ok: false, error: "Unsupported request", code: "internal" };
      }
    },
  };
}
```

- [ ] **Step 4: Run to confirm it passes**

```bash
pnpm --filter @keyhole/extension test -- src/offscreen/vaultHost.test.ts
```

Expected: PASS, 10 tests.

- [ ] **Step 5: Wire the real vault into the offscreen entry point**

Replace `src/offscreen/offscreen.ts`:

```ts
import {
  createApiClient,
  createPreferences,
  createSession,
  createVaultStore,
  unlock as vaultUnlock,
} from "@keyhole/vault";
import { hydratedPreferenceStore } from "../platform/chromePreferences.js";
import { readServerUrl } from "../platform/serverUrl.js";
import { isRequest } from "../messages.js";
import { createVaultHost, type HostItem } from "./vaultHost.js";

/**
 * The only context in this extension that holds key material.
 *
 * It exists because MV3 terminates the service worker after roughly thirty
 * seconds idle, which would drop the keys and demand the master password
 * constantly. An offscreen document persists, so the session lives in a real
 * closure here exactly as it does in the web app — no key is ever written to
 * any storage API, including chrome.storage.session.
 */
async function main(): Promise<void> {
  const store = await hydratedPreferenceStore();
  const prefs = createPreferences(store);
  const serverUrl = readServerUrl(store);
  const session = createSession();
  const vault = createVaultStore();

  const api = createApiClient({
    ...(serverUrl === null ? {} : { baseUrl: serverUrl }),
    getAccessToken: () => session.getAccessToken(),
    onUnauthorized: async () => false,
  });

  const host = createVaultHost({
    serverUrl,
    unlock: (input) =>
      vaultUnlock(
        { api, session, rememberEmail: prefs.rememberEmail },
        { ...input, deviceLabel: "Keyhole extension" },
      ),
    loadVault: () => vault.load({ api, session }),
    readItems: (): readonly HostItem[] =>
      vault
        .getState()
        .items.flatMap((record) => {
          const plaintext = record.plaintext;
          if (plaintext === null || plaintext.type !== "login") return [];
          return [
            {
              id: record.id,
              name: plaintext.name,
              username: plaintext.username,
              password: plaintext.password,
              urls: plaintext.urls,
            },
          ];
        }),
    isUnlocked: () => session.isUnlocked,
    lock: () => {
      vault.clear();
      session.lock();
    },
    rememberedEmail: prefs.rememberedEmail,
  });

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (!isRequest(message)) return false;
    void host.handle(message).then(sendResponse);
    // `true` keeps the message channel open for the async reply. Without it
    // every response is dropped silently.
    return true;
  });
}

void main();
```

> If `createApiClient` rejects an absent `baseUrl` under `exactOptionalPropertyTypes`, that is the spread guard above doing its job — the option is genuinely optional and must not be passed as `undefined`.

- [ ] **Step 6: Typecheck and build**

```bash
pnpm --filter @keyhole/extension typecheck && pnpm --filter @keyhole/extension build
```

Expected: both clean.

- [ ] **Step 7: Commit**

```bash
git add apps/extension/src/offscreen
git commit -m "feat(extension): offscreen vault host, the only context holding keys

MV3 kills the service worker on idle; an offscreen document persists, so the
session lives in a closure exactly as it does in the web app. Summaries carry
no password -- one crosses only in reply to vault/credential naming one item."
```

---

### Task 11: The service worker router

**Files:**
- Modify: `apps/extension/src/worker/worker.ts`
- Create: `apps/extension/src/worker/router.ts`
- Create: `apps/extension/src/worker/router.test.ts`

**Interfaces:**
- Consumes: `Request`, `Response`, `classifyCapture`, `shouldLock`.
- Produces: `function createRouter(deps: RouterDeps): { handle(request: Request, senderTabId: number | null): Promise<Response> }`

- [ ] **Step 1: Write the failing tests**

`src/worker/router.test.ts`:

```ts
import { describe, expect, it, vi } from "vitest";
import { createRouter } from "./router.js";

function router(over: Partial<Parameters<typeof createRouter>[0]> = {}) {
  return createRouter({
    askOffscreen: vi.fn(async () => ({ ok: true, kind: "ack" }) as const),
    fillTab: vi.fn(async () => undefined),
    setBadge: vi.fn(),
    knownLogins: async () => [],
    now: () => 1000,
    ...over,
  });
}

describe("capture/report", () => {
  it("badges the icon when a new credential is submitted", async () => {
    const setBadge = vi.fn();
    const r = router({ setBadge });
    await r.handle(
      {
        kind: "capture/report",
        capture: { url: "https://github.com/x", username: "me", password: "pw" },
      },
      7,
    );
    expect(setBadge).toHaveBeenCalledWith("save");
  });

  it("stays silent when the credential is already known", async () => {
    const setBadge = vi.fn();
    const r = router({
      setBadge,
      knownLogins: async () => [
        { id: "a", urls: ["https://github.com"], username: "me", password: "pw" },
      ],
    });
    await r.handle(
      {
        kind: "capture/report",
        capture: { url: "https://github.com/x", username: "me", password: "pw" },
      },
      7,
    );
    expect(setBadge).not.toHaveBeenCalledWith("save");
  });

  it("serves the pending capture to the popup", async () => {
    const r = router();
    const capture = { url: "https://github.com/x", username: "me", password: "pw" };
    await r.handle({ kind: "capture/report", capture }, 7);
    const response = await r.handle({ kind: "capture/pending" }, null);
    expect(response).toMatchObject({ ok: true, kind: "capture/pending", capture });
  });

  // The bound the spec puts on the one plaintext password the worker holds.
  it("forgets a pending capture after five minutes", async () => {
    let clock = 1000;
    const r = router({ now: () => clock });
    await r.handle(
      {
        kind: "capture/report",
        capture: { url: "https://github.com/x", username: "me", password: "pw" },
      },
      7,
    );
    clock += 5 * 60_000 + 1;
    const response = await r.handle({ kind: "capture/pending" }, null);
    expect(response).toMatchObject({ capture: null });
  });

  it("forgets a pending capture on lock", async () => {
    const r = router();
    await r.handle(
      {
        kind: "capture/report",
        capture: { url: "https://github.com/x", username: "me", password: "pw" },
      },
      7,
    );
    await r.handle({ kind: "vault/lock" }, null);
    const response = await r.handle({ kind: "capture/pending" }, null);
    expect(response).toMatchObject({ capture: null });
  });

  it("forgets a pending capture when dismissed", async () => {
    const r = router();
    await r.handle(
      {
        kind: "capture/report",
        capture: { url: "https://github.com/x", username: "me", password: "pw" },
      },
      7,
    );
    await r.handle({ kind: "capture/dismiss" }, null);
    const response = await r.handle({ kind: "capture/pending" }, null);
    expect(response).toMatchObject({ capture: null });
  });
});

describe("tab/fill", () => {
  it("asks the offscreen document for the credential and sends it to the tab", async () => {
    const askOffscreen = vi.fn(async () => ({
      ok: true as const,
      kind: "vault/credential" as const,
      credential: { username: "me", password: "pw" },
    }));
    const fillTab = vi.fn(async () => undefined);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const r = router({ askOffscreen: askOffscreen as any, fillTab });
    await r.handle({ kind: "tab/fill", itemId: "a" }, 7);
    expect(fillTab).toHaveBeenCalledWith(7, { username: "me", password: "pw" });
  });

  it("does not fill when the vault refuses the credential", async () => {
    const fillTab = vi.fn(async () => undefined);
    const r = router({
      askOffscreen: vi.fn(async () => ({ ok: false, error: "locked", code: "locked" }) as const),
      fillTab,
    });
    const response = await r.handle({ kind: "tab/fill", itemId: "a" }, 7);
    expect(fillTab).not.toHaveBeenCalled();
    expect(response).toMatchObject({ ok: false });
  });

  it("refuses a fill with no originating tab", async () => {
    const fillTab = vi.fn(async () => undefined);
    const r = router({ fillTab });
    const response = await r.handle({ kind: "tab/fill", itemId: "a" }, null);
    expect(fillTab).not.toHaveBeenCalled();
    expect(response).toMatchObject({ ok: false });
  });
});
```

- [ ] **Step 2: Run to confirm failure**

```bash
pnpm --filter @keyhole/extension test -- src/worker/router.test.ts
```

Expected: FAIL — unresolved import.

- [ ] **Step 3: Implement the router**

`src/worker/router.ts`:

```ts
import type { CaptureCandidate, Request, Response } from "../messages.js";
import { classifyCapture, type KnownLogin } from "./capture.js";

/**
 * The message router. Holds no key material.
 *
 * The one exception, stated plainly rather than hidden behind "nothing
 * sensitive": a pending save capture contains a plaintext password. It is
 * bounded to five minutes, cleared on lock and on dismissal, and never
 * written to storage — the window exists because the user has to be given a
 * chance to confirm, and it is kept short and explicit.
 */

const CAPTURE_TTL_MS = 5 * 60_000;

export interface RouterDeps {
  askOffscreen(request: Request): Promise<Response>;
  fillTab(tabId: number, credential: { username: string; password: string }): Promise<void>;
  setBadge(state: "save" | "none"): void;
  knownLogins(): Promise<readonly KnownLogin[]>;
  now(): number;
}

interface Pending {
  capture: CaptureCandidate;
  suggestedName: string;
  at: number;
}

export function createRouter(deps: RouterDeps) {
  let pending: Pending | null = null;

  const clearPending = (): void => {
    pending = null;
    deps.setBadge("none");
  };

  /** Read-with-expiry, so the TTL is enforced on access rather than by a timer
   *  the worker's own termination would cancel. */
  const readPending = (): Pending | null => {
    if (pending === null) return null;
    if (deps.now() - pending.at > CAPTURE_TTL_MS) {
      clearPending();
      return null;
    }
    return pending;
  };

  return {
    async handle(request: Request, senderTabId: number | null): Promise<Response> {
      switch (request.kind) {
        case "capture/report": {
          const verdict = classifyCapture({
            capture: request.capture,
            existing: await deps.knownLogins(),
          });
          if (verdict.action === "ignore") return { ok: true, kind: "ack" };
          pending = {
            capture: request.capture,
            suggestedName: verdict.action === "create" ? verdict.suggestedName : "",
            at: deps.now(),
          };
          deps.setBadge("save");
          return { ok: true, kind: "ack" };
        }

        case "capture/pending": {
          const current = readPending();
          return {
            ok: true,
            kind: "capture/pending",
            capture: current?.capture ?? null,
            suggestedName: current?.suggestedName ?? "",
          };
        }

        case "capture/dismiss":
          clearPending();
          return { ok: true, kind: "ack" };

        case "vault/lock":
          clearPending();
          return deps.askOffscreen(request);

        case "tab/fill": {
          // No tab means no page to fill. Refusing beats guessing at the
          // active tab, which could be a different site entirely.
          if (senderTabId === null) {
            return { ok: false, error: "No active tab", code: "internal" };
          }
          const answer = await deps.askOffscreen({
            kind: "vault/credential",
            itemId: request.itemId,
          });
          if (!answer.ok || answer.kind !== "vault/credential") return answer;
          await deps.fillTab(senderTabId, answer.credential);
          return { ok: true, kind: "ack" };
        }

        default:
          return deps.askOffscreen(request);
      }
    },
  };
}
```

- [ ] **Step 4: Run to confirm it passes**

```bash
pnpm --filter @keyhole/extension test -- src/worker/router.test.ts
```

Expected: PASS, 9 tests.

- [ ] **Step 5: Wire the worker entry point**

Replace `src/worker/worker.ts`:

```ts
import { isRequest, type Request, type Response } from "../messages.js";
import { createRouter } from "./router.js";
import { LOCK_ALARM_NAME, LOCK_ALARM_PERIOD_MINUTES, shouldLock } from "./lock.js";
import { hydratedPreferenceStore } from "../platform/chromePreferences.js";
import { createPreferences } from "@keyhole/vault";

const OFFSCREEN_PATH = "src/offscreen/offscreen.html";

/** Creating an offscreen document twice throws. Chrome offers no "ensure", so
 *  the existence check and the creation are serialised behind one promise. */
let creating: Promise<void> | null = null;
async function ensureOffscreen(): Promise<void> {
  const existing = await chrome.runtime.getContexts({
    contextTypes: [chrome.runtime.ContextType.OFFSCREEN_DOCUMENT],
  });
  if (existing.length > 0) return;
  creating ??= chrome.offscreen.createDocument({
    url: OFFSCREEN_PATH,
    // WORKERS is the closest documented reason: the document exists to run a
    // long-lived session the service worker cannot hold.
    reasons: [chrome.offscreen.Reason.WORKERS],
    justification: "Holds the unlocked vault session in memory.",
  });
  await creating;
  creating = null;
}

async function askOffscreen(request: Request): Promise<Response> {
  await ensureOffscreen();
  return (await chrome.runtime.sendMessage(request)) as Response;
}

let lastActivity = Date.now();

const router = createRouter({
  askOffscreen,
  async fillTab(tabId, credential) {
    await chrome.tabs.sendMessage(tabId, { kind: "content/fill", credential });
  },
  setBadge(state) {
    void chrome.action.setBadgeText({ text: state === "save" ? "1" : "" });
    void chrome.action.setBadgeBackgroundColor({ color: "#b45309" });
  },
  async knownLogins() {
    const answer = await askOffscreen({ kind: "vault/items", pageUrl: null, query: "" });
    // Summaries carry no password, so a full comparison is impossible here by
    // design; the offscreen document does the real classification during save.
    if (!answer.ok || answer.kind !== "vault/items") return [];
    return answer.items.map((item) => ({
      id: item.id,
      urls: [],
      username: item.username,
      password: "",
    }));
  },
  now: () => Date.now(),
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Messages from the offscreen document are its replies, not requests.
  if (!isRequest(message) || sender.url?.includes(OFFSCREEN_PATH) === true) return false;
  if (message.kind === "activity/ping") lastActivity = Date.now();
  void router.handle(message, sender.tab?.id ?? null).then(sendResponse);
  return true;
});

chrome.alarms.create(LOCK_ALARM_NAME, { periodInMinutes: LOCK_ALARM_PERIOD_MINUTES });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== LOCK_ALARM_NAME) return;
  void (async () => {
    const prefs = createPreferences(await hydratedPreferenceStore());
    if (shouldLock({ setting: prefs.readAutoLock(), lastActivity, now: Date.now() })) {
      await router.handle({ kind: "vault/lock" }, null);
    }
  })();
});
```

> `knownLogins` is deliberately lossy here: the worker cannot see passwords, so it cannot distinguish "changed" from "known". Task 12 moves the classification into the offscreen document, which can. Leaving it here would mean either a false prompt on every login or a password in the worker — both worse.

- [ ] **Step 6: Typecheck and build**

```bash
pnpm --filter @keyhole/extension typecheck && pnpm --filter @keyhole/extension build
```

Expected: both clean.

- [ ] **Step 7: Commit**

```bash
git add apps/extension/src/worker
git commit -m "feat(extension): service worker router, offscreen lifecycle, lock alarm"
```

---

### Task 12: Move capture classification into the offscreen document

Task 11 left a real gap: the worker cannot compare passwords because it cannot see them, so it cannot tell "changed" from "known". This task closes it.

**Files:**
- Modify: `apps/extension/src/offscreen/vaultHost.ts`
- Modify: `apps/extension/src/offscreen/vaultHost.test.ts`
- Modify: `apps/extension/src/worker/router.ts`
- Modify: `apps/extension/src/worker/router.test.ts`

**Interfaces:**
- Consumes: `classifyCapture`, `CaptureVerdict` (Task 8).
- Produces: a new request `{ kind: "capture/classify"; capture: CaptureCandidate }` and response `{ ok: true; kind: "capture/classify"; verdict: CaptureVerdict }`; `RouterDeps.knownLogins` is removed.

- [ ] **Step 1: Add the request and response to the protocol**

In `src/messages.ts`, add to the `Request` union and to `KINDS`:

```ts
  | { kind: "capture/classify"; capture: CaptureCandidate }
```

and to the `Response` union:

```ts
  | { ok: true; kind: "capture/classify"; verdict: import("./worker/capture.js").CaptureVerdict }
```

Prefer a top-level `import type { CaptureVerdict } from "./worker/capture.js";` over the inline import if it does not create a cycle; `capture.ts` imports only from `match/site.js`, so it does not.

- [ ] **Step 2: Write the failing test in the vault host**

Append to `src/offscreen/vaultHost.test.ts`:

```ts
describe("capture/classify", () => {
  it("reports an exact match as known, which the worker could not determine", async () => {
    const response = await host().handle({
      kind: "capture/classify",
      capture: {
        url: "https://github.com/session",
        username: "me@example.com",
        password: "hunter2",
      },
    });
    if (!response.ok || response.kind !== "capture/classify") throw new Error("wrong shape");
    expect(response.verdict).toEqual({ action: "ignore" });
  });

  it("reports a changed password as an update", async () => {
    const response = await host().handle({
      kind: "capture/classify",
      capture: {
        url: "https://github.com/session",
        username: "me@example.com",
        password: "a-new-password",
      },
    });
    if (!response.ok || response.kind !== "capture/classify") throw new Error("wrong shape");
    expect(response.verdict).toEqual({ action: "update", itemId: "a" });
  });

  it("refuses when locked", async () => {
    const response = await host({ isUnlocked: () => false }).handle({
      kind: "capture/classify",
      capture: { url: "https://github.com/x", username: "me", password: "pw" },
    });
    expect(response).toMatchObject({ ok: false, code: "locked" });
  });
});
```

- [ ] **Step 3: Run to confirm failure**

```bash
pnpm --filter @keyhole/extension test -- src/offscreen/vaultHost.test.ts
```

Expected: FAIL — the default branch returns `Unsupported request`.

- [ ] **Step 4: Implement the branch**

In `src/offscreen/vaultHost.ts`, import `classifyCapture` from `../worker/capture.js` and add before `default:`:

```ts
        case "capture/classify": {
          if (!deps.isUnlocked()) return locked;
          // Classification happens here rather than in the worker because it
          // requires comparing passwords, and this is the only context that
          // may hold one.
          const verdict = classifyCapture({
            capture: request.capture,
            existing: deps.readItems().map((item) => ({
              id: item.id,
              urls: item.urls,
              username: item.username,
              password: item.password,
            })),
          });
          return { ok: true, kind: "capture/classify", verdict };
        }
```

- [ ] **Step 5: Run to confirm it passes**

```bash
pnpm --filter @keyhole/extension test -- src/offscreen/vaultHost.test.ts
```

Expected: PASS, 13 tests.

- [ ] **Step 6: Rewire the router**

In `src/worker/router.ts`, delete `knownLogins` from `RouterDeps`, drop the `classifyCapture` and `KnownLogin` imports, and replace the `capture/report` branch:

```ts
        case "capture/report": {
          const answer = await deps.askOffscreen({
            kind: "capture/classify",
            capture: request.capture,
          });
          // A locked vault cannot classify, so there is nothing to offer. This
          // is not an error worth surfacing on a page the user just left.
          if (!answer.ok || answer.kind !== "capture/classify") return { ok: true, kind: "ack" };
          if (answer.verdict.action === "ignore") return { ok: true, kind: "ack" };
          pending = {
            capture: request.capture,
            suggestedName:
              answer.verdict.action === "create" ? answer.verdict.suggestedName : "",
            at: deps.now(),
          };
          deps.setBadge("save");
          return { ok: true, kind: "ack" };
        }
```

- [ ] **Step 7: Update the router tests**

In `src/worker/router.test.ts`, remove `knownLogins` from the `router` helper and drive the two capture cases through `askOffscreen` instead:

```ts
const classifying = (verdict: unknown) =>
  vi.fn(async (request: { kind: string }) =>
    request.kind === "capture/classify"
      ? ({ ok: true, kind: "capture/classify", verdict } as never)
      : ({ ok: true, kind: "ack" } as never),
  );
```

Then in "badges the icon when a new credential is submitted" pass `askOffscreen: classifying({ action: "create", suggestedName: "github.com" })`, and in "stays silent when the credential is already known" pass `askOffscreen: classifying({ action: "ignore" })`. Every other test keeps the default.

- [ ] **Step 8: Run the whole extension suite**

```bash
pnpm --filter @keyhole/extension test && pnpm --filter @keyhole/extension typecheck
```

Expected: PASS, and clean.

- [ ] **Step 9: Commit**

```bash
git add apps/extension/src
git commit -m "fix(extension): classify captures where passwords are visible

The worker cannot see passwords, so it could not distinguish a changed
password from a known one and would have prompted on every login. Moves the
decision into the offscreen document, the only context allowed to compare."
```

---

### Task 13: The content script entry point

**Files:**
- Modify: `apps/extension/src/content/content.ts`
- Create: `apps/extension/src/content/content.test.ts`

**Interfaces:**
- Consumes: `detectForm`, `applyFill`, `isFillableUrl`.
- Produces: `function createContentScript(deps: ContentDeps): { onMessage(message: unknown): boolean; onSubmit(event: Event): void; }`

- [ ] **Step 1: Write the failing tests**

`src/content/content.test.ts`:

```ts
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createContentScript } from "./content.js";

function page(html: string): void {
  document.body.innerHTML = html;
}

const LOGIN_FORM = `
  <form>
    <input type="text" name="user" />
    <input type="password" name="pass" />
  </form>`;

beforeEach(() => {
  document.body.innerHTML = "";
});

describe("fill messages", () => {
  it("fills on a content/fill message", () => {
    page(LOGIN_FORM);
    const script = createContentScript({ send: vi.fn(), pageUrl: () => "https://github.com" });
    script.onMessage({ kind: "content/fill", credential: { username: "me", password: "pw" } });
    expect((document.querySelector("input[type=password]") as HTMLInputElement).value).toBe("pw");
  });

  // Anything on the page can postMessage. An unrecognised shape must not reach
  // the filler.
  it.each([null, {}, { kind: "other" }, { kind: "content/fill" }])(
    "ignores the malformed message %s",
    (message) => {
      page(LOGIN_FORM);
      const script = createContentScript({ send: vi.fn(), pageUrl: () => "https://github.com" });
      expect(script.onMessage(message)).toBe(false);
      expect((document.querySelector("input[type=password]") as HTMLInputElement).value).toBe("");
    },
  );

  it("refuses to fill on a page it must never fill", () => {
    page(LOGIN_FORM);
    const script = createContentScript({ send: vi.fn(), pageUrl: () => "http://github.com" });
    script.onMessage({ kind: "content/fill", credential: { username: "me", password: "pw" } });
    expect((document.querySelector("input[type=password]") as HTMLInputElement).value).toBe("");
  });
});

describe("submit observation", () => {
  it("reports a submitted credential", () => {
    page(LOGIN_FORM);
    const send = vi.fn();
    const script = createContentScript({ send, pageUrl: () => "https://github.com/session" });
    (document.querySelector("input[name=user]") as HTMLInputElement).value = "me";
    (document.querySelector("input[name=pass]") as HTMLInputElement).value = "pw";
    script.onSubmit(new Event("submit"));
    expect(send).toHaveBeenCalledWith({
      kind: "capture/report",
      capture: { url: "https://github.com/session", username: "me", password: "pw" },
    });
  });

  it("reports nothing when the password field is empty", () => {
    page(LOGIN_FORM);
    const send = vi.fn();
    const script = createContentScript({ send, pageUrl: () => "https://github.com/session" });
    script.onSubmit(new Event("submit"));
    expect(send).not.toHaveBeenCalled();
  });

  it("reports nothing on a page it would never fill", () => {
    page(LOGIN_FORM);
    const send = vi.fn();
    const script = createContentScript({ send, pageUrl: () => "http://github.com/session" });
    (document.querySelector("input[name=pass]") as HTMLInputElement).value = "pw";
    script.onSubmit(new Event("submit"));
    expect(send).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run to confirm failure**

```bash
pnpm --filter @keyhole/extension test -- src/content/content.test.ts
```

Expected: FAIL — unresolved import.

- [ ] **Step 3: Implement**

`src/content/content.ts`:

```ts
import { isFillableUrl } from "../match/site.js";
import { detectForm } from "./detect.js";
import { applyFill } from "./fill.js";

/**
 * The only code this extension runs inside a page.
 *
 * It holds no credential until one is sent, and one is sent only after the
 * user picks an item in the popup. It never reads the vault, never receives a
 * list, and never asks for anything — the traffic is one-way except for
 * submit reports.
 *
 * The core is a factory over injected dependencies so it can be tested in
 * jsdom without any `chrome.*` surface; the wiring at the bottom is the only
 * part that touches the real runtime.
 */

interface FillMessage {
  kind: "content/fill";
  credential: { username: string; password: string };
}

function isFillMessage(value: unknown): value is FillMessage {
  if (typeof value !== "object" || value === null) return false;
  const message = value as { kind?: unknown; credential?: unknown };
  if (message.kind !== "content/fill") return false;
  const credential = message.credential as { username?: unknown; password?: unknown } | undefined;
  return (
    typeof credential === "object" &&
    credential !== null &&
    typeof credential.username === "string" &&
    typeof credential.password === "string"
  );
}

export interface ContentDeps {
  send(message: unknown): void;
  pageUrl(): string;
}

export function createContentScript(deps: ContentDeps) {
  return {
    onMessage(message: unknown): boolean {
      if (!isFillMessage(message)) return false;
      // Re-checked here even though the popup checked too: this is the last
      // point before a password enters the page, and it is the only check an
      // attacker cannot route around by talking to the content script.
      if (!isFillableUrl(deps.pageUrl())) return false;
      return applyFill(detectForm(document), message.credential);
    },

    onSubmit(_event: Event): void {
      const url = deps.pageUrl();
      if (!isFillableUrl(url)) return;
      const form = detectForm(document);
      if (form.password === null || form.password.value === "") return;
      deps.send({
        kind: "capture/report",
        capture: {
          url,
          username: form.username?.value ?? "",
          password: form.password.value,
        },
      });
    },
  };
}

// Guarded so importing this module in a test does not touch chrome.*.
if (typeof chrome !== "undefined" && chrome.runtime?.id !== undefined) {
  const script = createContentScript({
    send: (message) => void chrome.runtime.sendMessage(message),
    pageUrl: () => window.location.href,
  });
  chrome.runtime.onMessage.addListener((message) => script.onMessage(message));
  // Capture phase, because a page handler that calls stopPropagation would
  // otherwise hide every submission from us.
  window.addEventListener("submit", (event) => script.onSubmit(event), true);
}
```

- [ ] **Step 4: Run to confirm it passes**

```bash
pnpm --filter @keyhole/extension test -- src/content/content.test.ts
```

Expected: PASS, 9 tests.

- [ ] **Step 5: Commit**

```bash
git add apps/extension/src/content/content.ts apps/extension/src/content/content.test.ts
git commit -m "feat(extension): content script entry, fill on demand and submit reports"
```

---

### Task 14: The popup

**Files:**
- Create: `apps/extension/src/popup/usePopup.ts`, `usePopup.test.ts`
- Create: `apps/extension/src/popup/Popup.tsx`, `Popup.test.tsx`
- Create: `apps/extension/src/popup/clipboard.ts`, `clipboard.test.ts`
- Modify: `apps/extension/src/popup/main.tsx`
- Create: `apps/extension/src/popup/popup.css`

**Interfaces:**
- Consumes: the message protocol; `generatePassword` from `@keyhole/vault`.
- Produces: `function usePopup(send: Send): PopupModel` and the `Popup` component.

- [ ] **Step 1: Write the failing clipboard test**

`src/popup/clipboard.test.ts`:

```ts
import { describe, expect, it, vi } from "vitest";
import { copyWithExpiry } from "./clipboard.js";

describe("copyWithExpiry", () => {
  it("writes the value", async () => {
    const write = vi.fn(async () => undefined);
    await copyWithExpiry("secret", { write, delay: vi.fn() });
    expect(write).toHaveBeenCalledWith("secret");
  });

  // A password left on the clipboard is a password any app can read, forever.
  it("schedules a clear 20 seconds later", async () => {
    const delay = vi.fn();
    await copyWithExpiry("secret", { write: vi.fn(async () => undefined), delay });
    expect(delay).toHaveBeenCalledWith(expect.any(Function), 20_000);
  });

  it("clears by overwriting rather than emptying", async () => {
    const write = vi.fn(async () => undefined);
    let scheduled: (() => void) | null = null;
    await copyWithExpiry("secret", {
      write,
      delay: (fn) => void (scheduled = fn),
    });
    scheduled?.();
    expect(write).toHaveBeenLastCalledWith("");
  });
});
```

- [ ] **Step 2: Run to confirm failure, then implement**

```bash
pnpm --filter @keyhole/extension test -- src/popup/clipboard.test.ts
```

Expected: FAIL. Then create `src/popup/clipboard.ts`:

```ts
/** How long a copied secret may sit on the clipboard. Long enough to paste,
 *  short enough that it is not still there at the end of the day. */
export const CLIPBOARD_TTL_MS = 20_000;

export interface ClipboardDeps {
  write(value: string): Promise<void>;
  delay(fn: () => void, ms: number): void;
}

export async function copyWithExpiry(value: string, deps: ClipboardDeps): Promise<void> {
  await deps.write(value);
  deps.delay(() => void deps.write(""), CLIPBOARD_TTL_MS);
}
```

Re-run: PASS, 3 tests.

- [ ] **Step 3: Write the failing popup-model tests**

`src/popup/usePopup.test.ts`:

```ts
import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { usePopup } from "./usePopup.js";

const status = (over: Record<string, unknown> = {}) => ({
  ok: true,
  kind: "vault/status",
  unlocked: true,
  email: "me@example.com",
  serverUrl: "https://vault.example.com",
  ...over,
});

function sender(responses: Record<string, unknown>) {
  return vi.fn(async (request: { kind: string }) => {
    const response = responses[request.kind];
    if (response === undefined) return { ok: true, kind: "ack" };
    return response;
  });
}

describe("usePopup", () => {
  it("starts on setup when no server is configured", async () => {
    const send = sender({ "vault/status": status({ serverUrl: null, unlocked: false }) });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { result } = renderHook(() => usePopup(send as any));
    await waitFor(() => expect(result.current.screen).toBe("setup"));
  });

  it("starts on unlock when configured but locked", async () => {
    const send = sender({ "vault/status": status({ unlocked: false }) });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { result } = renderHook(() => usePopup(send as any));
    await waitFor(() => expect(result.current.screen).toBe("unlock"));
  });

  it("starts on the list when unlocked", async () => {
    const send = sender({
      "vault/status": status(),
      "vault/items": { ok: true, kind: "vault/items", items: [] },
      "capture/pending": { ok: true, kind: "capture/pending", capture: null, suggestedName: "" },
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { result } = renderHook(() => usePopup(send as any));
    await waitFor(() => expect(result.current.screen).toBe("list"));
  });

  // The badge exists to bring the user here; landing on the list would waste it.
  it("opens straight to the save prompt when a capture is pending", async () => {
    const send = sender({
      "vault/status": status(),
      "vault/items": { ok: true, kind: "vault/items", items: [] },
      "capture/pending": {
        ok: true,
        kind: "capture/pending",
        capture: { url: "https://github.com/x", username: "me", password: "pw" },
        suggestedName: "github.com",
      },
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { result } = renderHook(() => usePopup(send as any));
    await waitFor(() => expect(result.current.screen).toBe("save"));
  });

  it("surfaces a wrong password without leaving the unlock screen", async () => {
    const send = sender({
      "vault/status": status({ unlocked: false }),
      "vault/unlock": { ok: false, error: "Wrong master password", code: "credentials" },
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { result } = renderHook(() => usePopup(send as any));
    await waitFor(() => expect(result.current.screen).toBe("unlock"));
    await act(async () => void (await result.current.unlock("me@example.com", "wrong")));
    expect(result.current.error).toBe("Wrong master password");
    expect(result.current.screen).toBe("unlock");
  });

  // Spec section 6: a network blip must never read as a wrong password.
  it("distinguishes an unreachable server from a wrong password", async () => {
    const send = sender({
      "vault/status": status({ unlocked: false }),
      "vault/unlock": {
        ok: false,
        error: "Could not reach your Keyhole server",
        code: "network",
      },
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { result } = renderHook(() => usePopup(send as any));
    await waitFor(() => expect(result.current.screen).toBe("unlock"));
    await act(async () => void (await result.current.unlock("me@example.com", "right")));
    expect(result.current.error).toBe("Could not reach your Keyhole server");
  });
});
```

- [ ] **Step 4: Run to confirm failure**

```bash
pnpm --filter @keyhole/extension test -- src/popup/usePopup.test.ts
```

Expected: FAIL — unresolved import.

- [ ] **Step 5: Implement the model**

`src/popup/usePopup.ts`:

```ts
import { useCallback, useEffect, useState } from "react";
import type { CaptureCandidate, ItemSummary, Request, Response } from "../messages.js";

/**
 * Every piece of popup state, kept out of the components.
 *
 * The popup is the shortest-lived context in the extension — it is destroyed
 * whenever it loses focus — so all state is derived from the worker on open
 * and nothing is cached across openings.
 */

export type Send = (request: Request) => Promise<Response>;

export type Screen = "loading" | "setup" | "unlock" | "list" | "save";

export interface PopupModel {
  screen: Screen;
  items: ItemSummary[];
  query: string;
  error: string | null;
  email: string | null;
  pendingCapture: CaptureCandidate | null;
  suggestedName: string;
  setQuery(query: string): void;
  unlock(email: string, masterPassword: string): Promise<void>;
  fill(itemId: string): Promise<void>;
  dismissCapture(): Promise<void>;
}

export function usePopup(send: Send): PopupModel {
  const [screen, setScreen] = useState<Screen>("loading");
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [email, setEmail] = useState<string | null>(null);
  const [pendingCapture, setPendingCapture] = useState<CaptureCandidate | null>(null);
  const [suggestedName, setSuggestedName] = useState("");

  const refresh = useCallback(async () => {
    const status = await send({ kind: "vault/status" });
    if (!status.ok || status.kind !== "vault/status") {
      setError("Could not reach the extension background");
      return;
    }
    setEmail(status.email);
    if (status.serverUrl === null) return void setScreen("setup");
    if (!status.unlocked) return void setScreen("unlock");

    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const pageUrl = tabs[0]?.url ?? null;
    const list = await send({ kind: "vault/items", pageUrl, query });
    if (list.ok && list.kind === "vault/items") setItems(list.items);

    // Checked after the list so the badge's promise is kept: the user clicked
    // the icon because it was badged, and landing on the list would waste it.
    const pending = await send({ kind: "capture/pending" });
    if (pending.ok && pending.kind === "capture/pending" && pending.capture !== null) {
      setPendingCapture(pending.capture);
      setSuggestedName(pending.suggestedName);
      return void setScreen("save");
    }
    setScreen("list");
  }, [send, query]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return {
    screen,
    items,
    query,
    error,
    email,
    pendingCapture,
    suggestedName,
    setQuery,
    async unlock(inputEmail, masterPassword) {
      setError(null);
      const response = await send({ kind: "vault/unlock", email: inputEmail, masterPassword });
      // The message carries the distinction the vault layer drew; the popup
      // shows it verbatim rather than re-deciding what went wrong.
      if (!response.ok) return void setError(response.error);
      await refresh();
    },
    async fill(itemId) {
      const response = await send({ kind: "tab/fill", itemId });
      if (!response.ok) return void setError(response.error);
      window.close();
    },
    async dismissCapture() {
      await send({ kind: "capture/dismiss" });
      setPendingCapture(null);
      setScreen("list");
    },
  };
}
```

- [ ] **Step 6: Run to confirm it passes**

```bash
pnpm --filter @keyhole/extension test -- src/popup/usePopup.test.ts
```

Expected: PASS, 6 tests. Install `@testing-library/react` and `@testing-library/jest-dom` as devDependencies if the import fails, matching the versions in `apps/web/package.json`.

- [ ] **Step 7: Build the components**

Create `src/popup/Popup.tsx` rendering one screen per `model.screen` value: `setup` (server address form calling `normaliseServerUrl` then `chrome.permissions.request({ origins: [originPattern(url)] })`), `unlock` (email prefilled from `model.email`, password, error alert), `list` (search box bound to `model.query`, matching items first with a "for this site" heading, then the rest; per-item Fill, Copy username, Copy password, and a generator disclosure calling `generatePassword` from `@keyhole/vault`), and `save` (item name prefilled from `model.suggestedName`, Save and Not now).

Reuse the web app's visual language by copying `apps/web/src/ui/tokens.css` into `src/popup/popup.css` and using the same `kh-` class names, so the popup does not become a second design system.

Write `src/popup/Popup.test.tsx` covering, at minimum: the unlock error renders as an alert with `role="alert"`; the list separates site matches from the rest; clicking Fill calls `model.fill` with the right id; the save screen prefills the suggested name; and no rendered DOM ever contains a password string.

- [ ] **Step 8: Wire `main.tsx`**

```tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { Popup } from "./Popup.js";
import type { Request, Response } from "../messages.js";
import "./popup.css";

const send = async (request: Request): Promise<Response> =>
  (await chrome.runtime.sendMessage(request)) as Response;

const root = document.getElementById("root");
if (root === null) throw new Error("No #root element");
createRoot(root).render(
  <StrictMode>
    <Popup send={send} />
  </StrictMode>,
);
```

- [ ] **Step 9: Full suite, typecheck, lint, build**

```bash
pnpm --filter @keyhole/extension test && pnpm --filter @keyhole/extension typecheck && pnpm --filter @keyhole/extension lint && pnpm --filter @keyhole/extension build
```

Expected: all clean.

- [ ] **Step 10: Commit**

```bash
git add apps/extension/src/popup
git commit -m "feat(extension): popup UI -- setup, unlock, list, fill, save, generate"
```

---

### Task 15: End-to-end verification and packaging

**Files:**
- Create: `apps/extension/e2e/extension.spec.ts`
- Create: `apps/extension/playwright.config.ts`
- Modify: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: the built `dist/`.
- Produces: a packaged `keyhole-extension-<version>.zip` release asset.

- [ ] **Step 1: Write the Playwright config**

`apps/extension/playwright.config.ts`:

```ts
import { defineConfig } from "@playwright/test";

// An extension cannot be loaded in a normal Playwright browser: MV3 requires a
// persistent context with the unpacked directory passed on the command line.
export default defineConfig({
  testDir: "./e2e",
  // One worker: the tests share a persistent Chrome profile directory.
  workers: 1,
  use: { channel: "chromium" },
});
```

- [ ] **Step 2: Write the end-to-end test**

`apps/extension/e2e/extension.spec.ts` must, against a real Chrome with `dist/` loaded via `--disable-extensions-except` and `--load-extension`:

1. Launch a persistent context and read the service worker's extension id from `context.serviceWorkers()`.
2. Open the popup at `chrome-extension://<id>/src/popup/index.html`, complete setup against a test server, and unlock with a seeded account.
3. Navigate a page to a local HTTPS fixture serving a login form, open the popup, click Fill, and assert both fields are populated and **the form was not submitted**.
4. Submit the form manually with a new password and assert the toolbar badge appears.
5. Reopen the popup and assert it lands on the save screen.

Reuse `apps/web/e2e/server.ts` to stand up the Go server and seed an account, rather than writing a second harness. If you need vault fixtures or builders, `@keyhole/vault/testing` is a real subpath export — use it rather than reaching in by relative path, which is the fragility the extraction plan removed.

Note: this suite runs a Vite build first, which empties `internal/webui/dist` and deletes the tracked `placeholder.html` stub that `go:embed` needs. Restore it with `git checkout -- internal/webui/dist/placeholder.html` before committing, and do not commit the deletion.

- [ ] **Step 3: Run it**

```bash
pnpm --filter @keyhole/extension build && pnpm --filter @keyhole/extension exec playwright test
```

Expected: PASS. This is the only check that the four contexts actually talk to each other; everything before it tested them in isolation.

- [ ] **Step 4: Package in the release workflow**

In `.github/workflows/release.yml`, after the existing web build, add a step that builds the extension and zips `apps/extension/dist` to `keyhole-extension-${VERSION}.zip`, then attach it to the release alongside the existing assets. Set the extension's `manifest.json` version from the release tag in the same step, so a published zip can never disagree with the server it was cut with.

- [ ] **Step 5: Full workspace verification**

```bash
pnpm -r test && pnpm -r typecheck && pnpm -r lint && go build ./... && go vet ./...
```

Expected: all clean, and the unit total is at or above the floor recorded in the extraction plan.

- [ ] **Step 6: Commit**

```bash
git add apps/extension/e2e apps/extension/playwright.config.ts .github/workflows/release.yml
git commit -m "test(extension): end-to-end fill and save; package in the release workflow"
```

---

## Self-Review

**Spec coverage.** Every section of the design spec maps to a task: §3 architecture (Tasks 1, 10, 11, 13), §3.2 the `PreferenceStore` (Task 3, on the extraction plan's interface), §4.1 setup (Tasks 4, 14), §4.2 unlock (Tasks 10, 14), §4.3 fill (Tasks 6, 7, 13, 14), §4.4 save (Tasks 8, 11, 12, 14), §4.5 generator (Task 14), §5 matching and security rules (Tasks 1, 2, 7, 13), §6 error handling (Tasks 10, 14), §7 testing (throughout, plus Task 15), §8 distribution (Task 15).

**Placeholders.** Task 14 Step 7 and Task 15 Step 2 describe components and an end-to-end scenario in prose rather than full source. That is deliberate and bounded — the required behaviours are enumerated as specific assertions — but they are the two least prescriptive steps in the plan and the likeliest to need a second pass during execution.

**Type consistency.** `Request`, `Response`, `ItemSummary`, `Credential`, and `CaptureCandidate` are defined once in Task 5 and used unchanged in Tasks 10-14. `CaptureVerdict` and `KnownLogin` are defined in Task 8; Task 12 moves the *caller* without changing the types. `PreferenceStore` matches the extraction plan's definition exactly. `matchesSite`, `registrableDomain`, and `isFillableUrl` keep their Task 2 signatures in Tasks 8 and 13.

**Known sharp edge, resolved deliberately.** Task 11 ships a `knownLogins` that cannot compare passwords, and Task 12 removes it. That ordering is intentional: it keeps the worker's message plumbing reviewable on its own before the classification move complicates it. The gap never reaches a release — but if only part of this plan is executed, Task 11 alone would prompt to save on every successful login, so **Tasks 11 and 12 must land together.**
