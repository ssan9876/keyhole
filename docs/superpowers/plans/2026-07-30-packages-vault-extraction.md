# packages/vault Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move `apps/web/src/vault/**` into a new `packages/vault` workspace package consumed by the web app, with zero behaviour change, so the browser extension and later native clients share one tested vault layer.

**Architecture:** A pure refactor in four commits. First the two modules that touch `localStorage` grow an injected `PreferenceStore` so they no longer require a DOM. Then an empty package is scaffolded and wired. Then the files move in a single `git mv` with imports rewritten. Then everything is verified end to end.

**Tech Stack:** TypeScript 5.8, pnpm workspaces, vitest, ESLint (typescript-eslint), Vite 6.

## Global Constraints

- **The test total must not change.** 907 tests pass as of 2026-07-30 — 744 in `apps/web`, 163 in `packages/crypto`. Per-package totals shift as vault tests relocate; the sum must stay 907 and all must pass.
- **No test file may be edited except its import paths.** A test needing a rewrite means behaviour changed, which is a defect in this refactor, not an expected cost.
- **No key material may be persisted.** `PreferenceStore` carries `keyhole.email` and `keyhole.autolock` only. Adding any other key to it is out of scope and forbidden.
- **`PreferenceStore` is synchronous.** `App.tsx:73` calls `readAutoLock` inside `useState(...)`. An async interface would force UI churn across the web app for no gain; the extension hydrates `chrome.storage.local` into memory once at startup instead.
- TypeScript settings are inherited from `tsconfig.base.json` and are strict: `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, and `verbatimModuleSyntax` are all on. `verbatimModuleSyntax` means type-only imports **must** be written `import type { … }`.
- All relative imports carry a `.js` extension, matching the existing code, because `moduleResolution` is `bundler` over ESM source.
- Run all commands from the repository root unless stated otherwise.

## File Structure

| File | Responsibility |
|---|---|
| `packages/vault/package.json` | Declares `@keyhole/vault`, depends on `@keyhole/crypto` |
| `packages/vault/tsconfig.json` | Extends the base config; no DOM-only types |
| `packages/vault/vitest.config.ts` | `environment: "node"` — the moved modules are framework-free |
| `packages/vault/eslint.config.js` | Lints the package; no crypto ban here, this is the layer allowed to import it |
| `packages/vault/src/index.ts` | The barrel; the only entry point the web app and extension import from |
| `packages/vault/src/preferences.ts` | `PreferenceStore` interface + `createPreferences` factory |
| `packages/vault/src/**` | Everything moved from `apps/web/src/vault/**` |
| `apps/web/src/platform/localStoragePreferences.ts` | The web app's `localStorage` adapter — DOM-specific, so it stays here |
| `apps/web/src/vault/autolock.ts` | Keeps `startAutoLock` only; DOM-event-driven, so it does not move |

**Why `startAutoLock` stays:** it listens to `pointerdown`, `keydown`, `focus`, and `visibilitychange` on `window`/`document`. A service worker has none of those. The extension will implement an alarms-driven equivalent against the same `AutoLockSetting` type. Only the type and its read/write cross into the shared package.

---

### Task 1: Inject a PreferenceStore into the storage-touching modules

Five `localStorage` call sites exist outside tests, all in two files: `autolock.ts:16,26` and `session.ts:75,79,83`. This task replaces them with an injected interface, in place, before anything moves.

**Files:**
- Create: `apps/web/src/vault/preferences.ts`
- Create: `apps/web/src/vault/preferences.test.ts`
- Create: `apps/web/src/platform/localStoragePreferences.ts`
- Create: `apps/web/src/platform/localStoragePreferences.test.ts`
- Modify: `apps/web/src/vault/session.ts:72-84` (remove the three email functions)
- Modify: `apps/web/src/vault/autolock.ts:1-27` (remove the setting read/write)
- Modify: `apps/web/src/ui/App.tsx:73,81,192`
- Modify: `apps/web/src/ui/useSettingsPanel.ts:74`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `interface PreferenceStore { get(key: string): string | null; set(key: string, value: string): void; remove(key: string): void; }`
  - `function createPreferences(store: PreferenceStore): Preferences`
  - `interface Preferences { rememberEmail(email: string): void; rememberedEmail(): string | null; forgetEmail(): void; readAutoLock(): AutoLockSetting; writeAutoLock(setting: AutoLockSetting): void; }`
  - `function localStoragePreferences(): PreferenceStore`
  - `const EMAIL_STORAGE_KEY = "keyhole.email"` and `const AUTO_LOCK_STORAGE_KEY = "keyhole.autolock"` move to `preferences.ts` and are re-exported from there.

- [ ] **Step 1: Write the failing test for `createPreferences`**

Create `apps/web/src/vault/preferences.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import {
  AUTO_LOCK_STORAGE_KEY,
  EMAIL_STORAGE_KEY,
  createPreferences,
  type PreferenceStore,
} from "./preferences.js";

/** An in-memory PreferenceStore. The point of the interface is that these
 *  tests need no DOM at all — which is what makes the module movable. */
function fakeStore(initial: Record<string, string> = {}): PreferenceStore {
  const map = new Map(Object.entries(initial));
  return {
    get: (key) => map.get(key) ?? null,
    set: (key, value) => void map.set(key, value),
    remove: (key) => void map.delete(key),
  };
}

describe("email", () => {
  it("round-trips a remembered address", () => {
    const prefs = createPreferences(fakeStore());
    prefs.rememberEmail("a@b.c");
    expect(prefs.rememberedEmail()).toBe("a@b.c");
  });

  it("reports null when nothing is remembered", () => {
    expect(createPreferences(fakeStore()).rememberedEmail()).toBeNull();
  });

  it("forgets", () => {
    const prefs = createPreferences(fakeStore({ [EMAIL_STORAGE_KEY]: "a@b.c" }));
    prefs.forgetEmail();
    expect(prefs.rememberedEmail()).toBeNull();
  });
});

describe("auto-lock", () => {
  it("defaults to 15 when unset", () => {
    expect(createPreferences(fakeStore()).readAutoLock()).toBe(15);
  });

  it("reads a stored numeric setting as a number, not a string", () => {
    const prefs = createPreferences(fakeStore({ [AUTO_LOCK_STORAGE_KEY]: "30" }));
    expect(prefs.readAutoLock()).toBe(30);
  });

  it("reads a stored string setting", () => {
    const prefs = createPreferences(fakeStore({ [AUTO_LOCK_STORAGE_KEY]: "on-close" }));
    expect(prefs.readAutoLock()).toBe("on-close");
  });

  // Guards the existing behaviour: "0" would otherwise mean either a
  // zero-length timeout or an unbounded one depending on how it is read.
  it("falls back to the default for an unrecognised value", () => {
    const prefs = createPreferences(fakeStore({ [AUTO_LOCK_STORAGE_KEY]: "0" }));
    expect(prefs.readAutoLock()).toBe(15);
  });

  it("writes a setting as a string", () => {
    const store = fakeStore();
    createPreferences(store).writeAutoLock("never");
    expect(store.get(AUTO_LOCK_STORAGE_KEY)).toBe("never");
  });
});
```

- [ ] **Step 2: Run it to confirm it fails**

```bash
pnpm --filter @keyhole/web test -- src/vault/preferences.test.ts
```

Expected: FAIL — `Failed to resolve import "./preferences.js"`.

- [ ] **Step 3: Write `preferences.ts`**

Create `apps/web/src/vault/preferences.ts`:

```ts
import type { AutoLockSetting } from "./autolock.js";

/**
 * The whole of this application's persistence, behind three methods.
 *
 * It exists so that `session` and the auto-lock setting stop naming
 * `localStorage`, which a service worker does not have — that is what lets
 * this layer be shared with the browser extension.
 *
 * Deliberately synchronous. `chrome.storage.local` is async, so the extension
 * hydrates it into memory once at context startup and writes through; the
 * alternative was an async interface, which would force `App.tsx`'s
 * `useState(readAutoLock)` and every caller like it into an effect for no gain.
 *
 * It carries two keys and must never carry a third that is secret. The
 * prohibition on persisting key material is unchanged by this indirection.
 */
export interface PreferenceStore {
  get(key: string): string | null;
  set(key: string, value: string): void;
  remove(key: string): void;
}

/**
 * An email address is not a secret to the server — it is the account identity,
 * already known to anyone holding the device. Persisting it buys a
 * password-only unlock screen. Persisting the refresh token would buy nothing
 * beyond that, because the wrapped keys come back only from
 * POST /api/auth/login and never from refresh, while handing a device thief
 * working API access.
 */
export const EMAIL_STORAGE_KEY = "keyhole.email";
export const AUTO_LOCK_STORAGE_KEY = "keyhole.autolock";

export const DEFAULT_AUTO_LOCK: AutoLockSetting = 15;

const SETTINGS: readonly AutoLockSetting[] = [1, 5, 15, 30, 60, "on-close", "never"];

export interface Preferences {
  rememberEmail(email: string): void;
  rememberedEmail(): string | null;
  forgetEmail(): void;
  readAutoLock(): AutoLockSetting;
  writeAutoLock(setting: AutoLockSetting): void;
}

export function createPreferences(store: PreferenceStore): Preferences {
  return {
    rememberEmail(email) {
      store.set(EMAIL_STORAGE_KEY, email);
    },
    rememberedEmail() {
      return store.get(EMAIL_STORAGE_KEY);
    },
    forgetEmail() {
      store.remove(EMAIL_STORAGE_KEY);
    },
    readAutoLock() {
      const raw = store.get(AUTO_LOCK_STORAGE_KEY);
      if (raw === null) return DEFAULT_AUTO_LOCK;
      const parsed: AutoLockSetting = /^\d+$/.test(raw)
        ? (Number(raw) as AutoLockSetting)
        : (raw as AutoLockSetting);
      // An unrecognised value falls back rather than passing through.
      return SETTINGS.includes(parsed) ? parsed : DEFAULT_AUTO_LOCK;
    },
    writeAutoLock(setting) {
      store.set(AUTO_LOCK_STORAGE_KEY, String(setting));
    },
  };
}
```

- [ ] **Step 4: Run the test to confirm it passes**

```bash
pnpm --filter @keyhole/web test -- src/vault/preferences.test.ts
```

Expected: PASS, 8 tests.

- [ ] **Step 5: Strip the moved code out of `autolock.ts`**

In `apps/web/src/vault/autolock.ts`, delete `AUTO_LOCK_STORAGE_KEY`, `DEFAULT_AUTO_LOCK`, `SETTINGS`, `readAutoLock`, and `writeAutoLock`. Keep the `AutoLockSetting` type and `startAutoLock` exactly as they are. Replace the file's header comment with:

```ts
/**
 * Idle auto-lock, DOM half.
 *
 * The setting itself lives in `preferences.ts` because the browser extension
 * shares it. This module does not, and must not, move with it: it listens to
 * pointer, key, focus, and visibility events, none of which exist in a service
 * worker. The extension drives the same setting from `chrome.alarms` instead.
 */

export type AutoLockSetting = 1 | 5 | 15 | 30 | 60 | "on-close" | "never";
```

- [ ] **Step 6: Strip the moved code out of `session.ts`**

In `apps/web/src/vault/session.ts`, delete `EMAIL_STORAGE_KEY`, `rememberEmail`, `rememberedEmail`, and `forgetEmail` (lines 62-84, including the block comment, which has already been relocated into `preferences.ts`). Leave everything else untouched — `createSession` and the `Session` interface do not change.

- [ ] **Step 7: Update the importers**

`apps/web/src/vault/unlock.ts` imports `rememberEmail` from `./session.js`. Change `unlock` to accept it rather than import it, so the vault layer stays free of a storage singleton:

```ts
// in unlock.ts, replace the session.js import line
import type { Session, SessionUser } from "./session.js";
```

and widen the deps parameter:

```ts
export async function unlock(
  deps: { api: ApiClient; session: Session; rememberEmail: (email: string) => void },
  input: { email: string; masterPassword: string; deviceLabel: string },
): Promise<void> {
```

Inside the function body, the existing `rememberEmail(input.email)` call becomes `deps.rememberEmail(input.email)`.

- [ ] **Step 8: Write the failing test for the `localStorage` adapter**

Create `apps/web/src/platform/localStoragePreferences.test.ts`:

```ts
import { beforeEach, describe, expect, it } from "vitest";
import { localStoragePreferences } from "./localStoragePreferences.js";

describe("localStoragePreferences", () => {
  beforeEach(() => localStorage.clear());

  it("writes through to localStorage", () => {
    localStoragePreferences().set("k", "v");
    expect(localStorage.getItem("k")).toBe("v");
  });

  it("reads through from localStorage", () => {
    localStorage.setItem("k", "v");
    expect(localStoragePreferences().get("k")).toBe("v");
  });

  it("reports null for an absent key", () => {
    expect(localStoragePreferences().get("nope")).toBeNull();
  });

  it("removes", () => {
    localStorage.setItem("k", "v");
    localStoragePreferences().remove("k");
    expect(localStorage.getItem("k")).toBeNull();
  });
});
```

- [ ] **Step 9: Run it to confirm it fails**

```bash
pnpm --filter @keyhole/web test -- src/platform/localStoragePreferences.test.ts
```

Expected: FAIL — unresolved import.

- [ ] **Step 10: Write the adapter**

Create `apps/web/src/platform/localStoragePreferences.ts`:

```ts
import type { PreferenceStore } from "../vault/preferences.js";

/**
 * The web app's binding of PreferenceStore to the browser.
 *
 * It lives outside `vault/` on purpose: `localStorage` is a DOM global, and
 * keeping it out of the shared layer is what allows that layer to run in a
 * service worker unchanged.
 */
export function localStoragePreferences(): PreferenceStore {
  return {
    get: (key) => localStorage.getItem(key),
    set: (key, value) => localStorage.setItem(key, value),
    remove: (key) => localStorage.removeItem(key),
  };
}
```

- [ ] **Step 11: Run it to confirm it passes**

```bash
pnpm --filter @keyhole/web test -- src/platform/localStoragePreferences.test.ts
```

Expected: PASS, 4 tests.

- [ ] **Step 12: Wire the composition root**

In `apps/web/src/ui/App.tsx`, create the preferences object once at module scope, above the component:

```ts
import { createPreferences } from "../vault/preferences.js";
import { localStoragePreferences } from "../platform/localStoragePreferences.js";

const prefs = createPreferences(localStoragePreferences());
```

Then replace the three existing call sites: `useState(readAutoLock)` at line 73 becomes `useState(prefs.readAutoLock)`; `rememberedEmail()` at lines 81 and 192 becomes `prefs.rememberedEmail()`. Remove the now-dead imports of `readAutoLock` and `rememberedEmail`. Wherever `App.tsx` calls `unlock(...)`, add `rememberEmail: prefs.rememberEmail` to the deps object.

In `apps/web/src/ui/useSettingsPanel.ts`, the hook must not reach a module singleton — take the writer as a parameter instead. Add `writeAutoLock: (setting: AutoLockSetting) => void` to its existing input object type, replace the bare `writeAutoLock(setting)` call at line 74 with the injected one, drop the import, and pass `prefs.writeAutoLock` from `App.tsx` where the hook is called.

- [ ] **Step 13: Run the whole web suite**

```bash
pnpm --filter @keyhole/web test
```

Expected: PASS. The total rises from 744 to 756 (12 new tests across the two new files). Any pre-existing test that now fails is a real regression — fix the source, not the test.

Two existing test files reach `localStorage` directly for the functions this task moved: `apps/web/src/vault/session.test.ts` and `apps/web/src/vault/autolock.test.ts`. Per the Global Constraints, delete only the blocks covering the five relocated functions — `preferences.test.ts` now covers that behaviour and duplicating it would leave two sources of truth. Do not alter any other assertion in either file. `startAutoLock`'s tests stay exactly as they are.

- [ ] **Step 14: Typecheck and lint**

```bash
pnpm --filter @keyhole/web typecheck && pnpm --filter @keyhole/web lint
```

Expected: both clean.

- [ ] **Step 15: Commit**

```bash
git add apps/web/src/vault/preferences.ts apps/web/src/vault/preferences.test.ts apps/web/src/platform apps/web/src/vault/session.ts apps/web/src/vault/autolock.ts apps/web/src/vault/unlock.ts apps/web/src/vault/session.test.ts apps/web/src/vault/autolock.test.ts apps/web/src/ui/App.tsx apps/web/src/ui/useSettingsPanel.ts
git commit -m "refactor(web): inject a PreferenceStore instead of naming localStorage

The vault layer is about to be shared with a browser extension, whose
service worker has no localStorage. Behaviour is unchanged; the five call
sites move behind a three-method interface, and the DOM binding lives in
apps/web where it belongs."
```

---

### Task 2: Scaffold the empty package

Nothing moves in this task. It exists so the workspace wiring can be proven correct before any file is in motion — a broken `pnpm` link and a broken import graph are much easier to tell apart when they cannot happen at the same time.

**Files:**
- Create: `packages/vault/package.json`
- Create: `packages/vault/tsconfig.json`
- Create: `packages/vault/vitest.config.ts`
- Create: `packages/vault/eslint.config.js`
- Create: `packages/vault/src/index.ts`
- Create: `packages/vault/src/placeholder.test.ts`
- Modify: `apps/web/package.json` (add the dependency)

**Interfaces:**
- Consumes: nothing.
- Produces: the package name `@keyhole/vault`, importable as `workspace:*`.

- [ ] **Step 1: Write `packages/vault/package.json`**

Mirrors `packages/crypto/package.json`, which is consumed as raw TypeScript source via `"main": "./src/index.ts"` — there is no build step for workspace packages here, and adding one would be a new pattern.

```json
{
  "name": "@keyhole/vault",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "main": "./src/index.ts",
  "types": "./src/index.ts",
  "exports": { ".": "./src/index.ts" },
  "scripts": {
    "test": "vitest run",
    "test:watch": "vitest",
    "typecheck": "tsc --noEmit",
    "lint": "eslint ."
  },
  "dependencies": {
    "@keyhole/crypto": "workspace:*"
  },
  "devDependencies": {
    "eslint": "^9.26.0",
    "typescript-eslint": "^8.32.0",
    "vitest": "^3.1.4"
  }
}
```

- [ ] **Step 2: Write `packages/vault/tsconfig.json`**

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "types": ["vitest/globals"]
  },
  "include": ["src"]
}
```

- [ ] **Step 3: Write `packages/vault/vitest.config.ts`**

```ts
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    // Node, not jsdom: every module in this package is framework-free and
    // DOM-free by construction. If a test here ever needs jsdom, something
    // that belongs in apps/web has been moved in by mistake.
    environment: "node",
    include: ["src/**/*.test.ts"],
    // Argon2id at 64 MiB is deliberately slow; anything touching the crypto
    // package needs headroom.
    testTimeout: 30_000,
  },
});
```

- [ ] **Step 4: Write `packages/vault/eslint.config.js`**

```js
import tseslint from "typescript-eslint";

// No `@keyhole/crypto` restriction here, deliberately. This is the layer that
// is *supposed* to import it; the ban belongs to apps/web/src/ui, which is
// where it remains.
export default tseslint.config({
  files: ["src/**/*.ts"],
  extends: [tseslint.configs.recommended],
  rules: {
    "@typescript-eslint/no-unused-vars": [
      "error",
      { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
    ],
  },
});
```

- [ ] **Step 5: Write a placeholder barrel and test**

`packages/vault/src/index.ts`:

```ts
// Populated by Task 3. Kept non-empty so `main` resolves before the move.
export const PACKAGE_NAME = "@keyhole/vault";
```

`packages/vault/src/placeholder.test.ts`:

```ts
import { expect, it } from "vitest";
import { PACKAGE_NAME } from "./index.js";

it("resolves the package entry point", () => {
  expect(PACKAGE_NAME).toBe("@keyhole/vault");
});
```

- [ ] **Step 6: Add the dependency to the web app**

In `apps/web/package.json`, add to `dependencies`, keeping alphabetical order:

```json
"@keyhole/vault": "workspace:*",
```

- [ ] **Step 7: Install and verify the link**

```bash
pnpm install
```

Expected: succeeds and reports `@keyhole/vault` linked into `apps/web`.

> If `pnpm` is unavailable, do not reach for `corepack` — it is known to fail in this environment. Use the `pnpm` already on `PATH`.

- [ ] **Step 8: Verify the whole workspace is still green**

```bash
pnpm -r test && pnpm -r typecheck
```

Expected: PASS, 920 total — 756 in `apps/web`, 163 in `packages/crypto`, 1 in `packages/vault`. Record the number you actually observe; Task 3 asserts it does not drop.

- [ ] **Step 9: Commit**

```bash
git add packages/vault apps/web/package.json pnpm-lock.yaml
git commit -m "chore(vault): scaffold the @keyhole/vault package

Empty but wired, so the workspace link is proven before any file moves."
```

---

### Task 3: Move the modules

One `git mv`, then rewrite imports. Doing this in a single commit is deliberate: the vault modules form a connected import graph, so a piecemeal move produces broken intermediate states with no useful review value.

**Files:**
- Move: `apps/web/src/vault/**` → `packages/vault/src/**`, except `autolock.ts` and `autolock.test.ts`
- Modify: `packages/vault/src/index.ts` (the real barrel)
- Modify: every file under `apps/web/src/ui/**` that imports from `../vault/`
- Modify: `apps/web/eslint.config.js`
- Delete: `packages/vault/src/placeholder.test.ts`

**Interfaces:**
- Consumes: `@keyhole/vault` from Task 2; `PreferenceStore` and `createPreferences` from Task 1.
- Produces: every existing vault export, re-exported from `@keyhole/vault`. Import sites change; **no signature changes.**

- [ ] **Step 1: Move the files**

```bash
git mv apps/web/src/vault/import packages/vault/src/import
git mv apps/web/src/vault/preferences.ts apps/web/src/vault/preferences.test.ts packages/vault/src/
git mv apps/web/src/vault/test-helpers.ts apps/web/src/vault/types.ts packages/vault/src/
```

Then move the remaining pairs, which are every file in `apps/web/src/vault` except `autolock.ts` and `autolock.test.ts`:

```bash
for m in account admin api collections directory enroll folders generator items recover session store unlock; do
  git mv "apps/web/src/vault/$m.ts" "packages/vault/src/$m.ts"
  git mv "apps/web/src/vault/$m.test.ts" "packages/vault/src/$m.test.ts"
done
```

Confirm only the auto-lock pair remains:

```bash
ls apps/web/src/vault
```

Expected: `autolock.ts` and `autolock.test.ts`, nothing else.

- [ ] **Step 2: Break the one import that now points the wrong way**

`packages/vault/src/preferences.ts` imports `AutoLockSetting` from `./autolock.js`, which did not move. The type must move to the package while `startAutoLock` stays behind. Move the type declaration into `preferences.ts` — put it directly above the `SETTINGS` constant:

```ts
export type AutoLockSetting = 1 | 5 | 15 | 30 | 60 | "on-close" | "never";
```

Delete the `import type { AutoLockSetting } from "./autolock.js";` line at the top of `preferences.ts`.

Then in `apps/web/src/vault/autolock.ts`, replace its own `export type AutoLockSetting = …` declaration with a re-export, so existing UI imports of the type keep resolving:

```ts
export type { AutoLockSetting } from "@keyhole/vault";
import type { AutoLockSetting } from "@keyhole/vault";
```

- [ ] **Step 3: Write the real barrel**

Replace `packages/vault/src/index.ts` entirely:

```ts
/**
 * The single entry point for the vault layer.
 *
 * Consumers — the web app today, the browser extension next — import from
 * `@keyhole/vault` and never reach into `src/` directly. That is what makes
 * the internal file layout changeable without touching a client.
 */
export * from "./account.js";
export * from "./admin.js";
export * from "./api.js";
export * from "./collections.js";
export * from "./directory.js";
export * from "./enroll.js";
export * from "./folders.js";
export * from "./generator.js";
export * from "./items.js";
export * from "./preferences.js";
export * from "./recover.js";
export * from "./session.js";
export * from "./store.js";
export * from "./types.js";
export * from "./unlock.js";

export * from "./import/csv.js";
export * from "./import/dedupe.js";
export * from "./import/detect.js";
export * from "./import/map.js";
export * from "./import/types.js";
export * from "./import/upload.js";
export * from "./import/zip.js";
```

`test-helpers.ts` is deliberately absent — it is for tests inside this package and must not become part of the public surface.

- [ ] **Step 4: Delete the placeholder test**

```bash
git rm packages/vault/src/placeholder.test.ts
```

- [ ] **Step 5: Rewrite the web app's imports**

Every file under `apps/web/src/ui/**` that imports from `"../vault/<module>.js"` or `"../../vault/<module>.js"` must now import from `"@keyhole/vault"`, except imports of `startAutoLock`, which still come from `"../vault/autolock.js"`.

Find them:

```bash
grep -rln "\.\./vault/\|\.\./\.\./vault/" apps/web/src/ui apps/web/src/main.tsx
```

For each hit, merge its vault imports into one `import { … } from "@keyhole/vault";`. Preserve `import type` for type-only imports — `verbatimModuleSyntax` is on and will reject a value import used only as a type.

- [ ] **Step 6: Move the ESLint gate**

In `apps/web/eslint.config.js`, the first config object's comment describes `src/vault/` as living in this app; it no longer does. Update the `files` glob of the second object to keep banning direct crypto imports from the UI, and add the now-shared package to the ban so the UI cannot route around it:

```js
  {
    // Narrower than the object above, and it must stay that way. The vault
    // layer now lives in packages/vault, which is the layer allowed to import
    // crypto; this ban applies to the UI only.
    files: ["src/ui/**/*.{ts,tsx}"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          paths: [
            {
              name: "@keyhole/crypto",
              message:
                "UI code must not touch crypto directly. Go through " +
                "@keyhole/vault, which is the only layer allowed to hold key " +
                "material.",
            },
          ],
        },
      ],
    },
  },
```

Also change the first object's `files` from `["src/**/*.{ts,tsx}"]` — it stays as is, since `src/ui`, `src/sw`, `src/platform`, and `main.tsx` all still need linting.

- [ ] **Step 6a: Prove the gate still fires**

A moved gate that no longer fires is worse than no gate. Verify it by hand:

```bash
printf 'import { zeroize } from "@keyhole/crypto";\nexport const x = zeroize;\n' > apps/web/src/ui/__gate-probe.ts
pnpm --filter @keyhole/web lint
```

Expected: FAIL, naming `no-restricted-imports` on `__gate-probe.ts`. Then remove it:

```bash
rm apps/web/src/ui/__gate-probe.ts
```

- [ ] **Step 7: Typecheck the workspace**

```bash
pnpm -r typecheck
```

Expected: clean. Unresolved-import errors here are missed call sites from Step 5 — fix and repeat.

- [ ] **Step 8: Run everything and check the total**

```bash
pnpm -r test
```

Expected: PASS, and the sum across all three packages equals the number recorded in Task 2 Step 8, minus 1 for the deleted placeholder. `packages/vault` now carries the bulk of what `apps/web` used to.

- [ ] **Step 9: Lint**

```bash
pnpm --filter @keyhole/web lint && pnpm --filter @keyhole/vault lint
```

Expected: both clean.

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "refactor: move the vault layer into packages/vault

git mv plus import rewrites, no signature changes. startAutoLock stays in
apps/web because it is driven by DOM events a service worker does not have;
only AutoLockSetting and its read/write cross over.

The crypto-import ban moves with the UI it constrains, and was re-verified
by probe rather than assumed."
```

---

### Task 4: Verify end to end

The unit suite can pass while the app is broken — the Vite build resolves imports differently from vitest, and the service-worker build is a nested second build that the test run never touches.

**Files:** none modified. This task is a gate.

**Interfaces:**
- Consumes: everything from Tasks 1-3.
- Produces: confidence, and a recorded test total for the extension plan to gate against.

- [ ] **Step 1: Build the web app**

```bash
pnpm --filter @keyhole/web build
```

Expected: succeeds, writing to `internal/webui/dist`, including a generated `sw.js`. A failure here that the unit tests missed is almost certainly a barrel export the bundler resolves differently.

- [ ] **Step 2: Confirm the Go build still embeds a real bundle**

```bash
go build ./... && go vet ./...
```

Expected: both clean.

- [ ] **Step 3: Run the end-to-end suite**

```bash
pnpm --filter @keyhole/web test:e2e
```

Expected: PASS. These drive a real browser against a real server and are the only check that the moved layer still works when actually executed.

- [ ] **Step 4: Record the final totals**

```bash
pnpm -r test 2>&1 | grep -E "Tests +[0-9]+ passed"
```

Observed totals (2026-07-31, branch `claude/extension-design`): `packages/crypto` 163 passed (14 files), `packages/vault` 562 passed (30 files), `apps/web` 190 passed (24 files) — 915 total, all green. The Vite build and `go build`/`go vet` were also clean. The Playwright e2e run surfaced one real regression from the extraction: `apps/web/e2e/import.spec.ts` still points `FIXTURE` at `apps/web/src/vault/import/fixtures/bitwarden-export.json`, but that fixture moved to `packages/vault/src/import/fixtures/bitwarden-export.json` during the extraction, so the import spec fails with `ENOENT` (11/12 e2e specs passed). This needs a follow-up fix to the e2e spec's fixture path before this plan can be considered fully verified.

- [ ] **Step 5: Commit if anything changed, otherwise confirm clean**

```bash
git status --porcelain
```

Expected: empty. If the build wrote artifacts that belong in the repo, commit them; if it wrote artifacts that do not, confirm `.gitignore` already covers them rather than adding an exception.

---

## Self-Review

**Spec coverage.** This plan implements §3.1 (repository layout) and §3.2 (the extraction) of the design spec, plus the §7 extraction gate. Everything else in the spec belongs to the extension plan, which is a separate document.

**Placeholders.** Task 4 Step 4 deliberately asks the implementer to record an observed number rather than inventing one, which is a measurement, not a placeholder. No other step defers work.

**Type consistency.** `PreferenceStore`, `Preferences`, `createPreferences`, `localStoragePreferences`, `AutoLockSetting`, `EMAIL_STORAGE_KEY`, and `AUTO_LOCK_STORAGE_KEY` are used with identical names and signatures in Tasks 1 and 3. `AutoLockSetting` is declared once in `preferences.ts` after Task 3 Step 2 and re-exported from `apps/web/src/vault/autolock.ts`, so there is exactly one definition.

**Known sharp edge.** Task 3 Step 2 has an ordering hazard: `preferences.ts` is moved in Step 1 while still importing from `autolock.ts`, so the tree does not typecheck between Step 1 and Step 2. That is accepted — the steps are one commit, and splitting them would mean moving a file twice.
