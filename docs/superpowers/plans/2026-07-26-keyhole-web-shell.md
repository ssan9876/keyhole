# Keyhole Web Shell (Plan 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first usable Keyhole client — enrol with an invite, unlock with a master password, list items, read and edit a login or secure note, and generate a password — against the server completed in Plan 2b.

**Architecture:** A framework-free `vault/` core in plain TypeScript holds every key, token, and API call; React under `ui/` only renders and calls into it. That boundary exists because design spec §6.3 makes "decrypted keys in memory only" a code-review gate, and the realistic ways that rule breaks are all React-shaped — persistence middleware, devtools serialisers, an error boundary logging props. Keeping key material out of the component tree makes the gate checkable by grep.

**Tech Stack:** React 19 + TypeScript + Vite, styled with CSS custom properties; Vitest + Testing Library; Playwright for end-to-end. `@keyhole/crypto` (already built) for all cryptography. No state-management library, and — deliberately, see Task 1 — no Tailwind or Radix in this slice, though design spec §2 names both for the finished web app.

---

## Global Constraints

Every task's requirements implicitly include this section.

### Environment — you cannot discover this, so it is stated

- **Node 24.18, pnpm 11.17.** `corepack enable` **fails with EPERM** on
  `C:\Program Files\nodejs`. pnpm is already installed globally via npm. Do not
  retry corepack.
- **pnpm 11 gates postinstall build scripts.** A dependency with a build step
  must be listed under `allowBuilds` in `pnpm-workspace.yaml` or a
  non-interactive install stalls forever. `esbuild` is already listed;
  **this plan adds `@playwright/test`**.
- **Go is installed but NOT on the tool shells' PATH.** Needed for the
  end-to-end harness. Prefix every command:
  - Git Bash: `export PATH="/c/Program Files/Go/bin:$PATH"; go build ./...`
  - PowerShell: `$env:Path = "C:\Program Files\Go\bin;" + $env:Path`
- Repo root is `D:\password-manager`. The workspace globs are `packages/*` and
  `apps/*`; `apps/` does not exist yet.

### TypeScript — settled traps, do not rediscover

`tsconfig.base.json` sets `strict`, `noUncheckedIndexedAccess`,
`exactOptionalPropertyTypes`, and `verbatimModuleSyntax`. Consequences that have
already cost this project time:

- **`verbatimModuleSyntax` rejects named imports of ambient const enums**
  (TS2748). Use a namespace import if you hit one.
- **A bare `Uint8Array` will not assign to WebCrypto's `BufferSource`** (TS2769),
  because `ArrayBufferLike` includes `SharedArrayBuffer`. Cast
  `as BufferSource`.
- **`noUncheckedIndexedAccess`** makes string indexing yield `string | undefined`
  (use `.charAt()`) and breaks compound assignment to an array element
  (`bytes[0] ^= x` does not compile).
- **`exactOptionalPropertyTypes`** means `{ x?: string }` will not accept
  `{ x: undefined }`. Omit the key instead.
- Type-only imports must be written `import type { … }`.

### Security rules — these are gates, not preferences

- **No key material or plaintext in `localStorage`, `sessionStorage`, or
  IndexedDB.** The only permitted persisted value in this entire plan is the
  user's email address, under the key `keyhole.email`.
- **`ui/` must never import `@keyhole/crypto`.** Only `vault/` may. Enforced by
  ESLint in Task 1.
- **`vault/session.ts` is the only module that retains key material.**
- **`params` on enrolment must be `DEFAULT_KDF_PARAMS_JSON` sent verbatim.** The
  server rejects anything not byte-equal (Plan 2b, Task 6). Never
  `JSON.stringify` an object into that field.
- **The UI branches on the error `code`, never the `message`.**
  `internal/httpapi/errors.go` states codes are stable and messages may change.

### Server API — exact shapes, verified against the source

```
POST /api/auth/prelogin   {email}
  → 200 {kdfSalt: string(base64), params: string(json)}

POST /api/auth/login      {email, authHash, deviceLabel}
  → 200 {accessToken, refreshToken, expiresAt,
         protectedUserKey, encryptedPrivateKey,
         user: {id, email, name, role}}
  → 401 {error:{code:"unauthorized", …}}   (wrong password OR unknown account)

POST /api/auth/refresh    {refreshToken}
  → 200 {accessToken, refreshToken, expiresAt}      ← NO wrapped keys

POST /api/enroll/{token}  {kdfSalt, params, authHash, protectedUserKey,
                           publicKey, encryptedPrivateKey, recoverySalt,
                           recoveryProtectedUserKey, recoveryKdfParams}
  → 200 {id, email, name, role}                     ← NO tokens, NO key material

GET  /api/sync[?since=N]  → 200 {revision, items[], folders[], collections[]}
POST /api/items           {collectionId?, ciphertext, wrappedItemKey} → 201 item
PUT  /api/items/{id}      {ciphertext, wrappedItemKey, revision}
  → 200 item
  → 409 {error:{code:"conflict", …}, item: <winning item>}
DELETE /api/items/{id}    → 200 tombstoned item
```

Item wire shape: `{id, collectionId, ownerUserId, ciphertext, wrappedItemKey,
revision, createdAt, updatedAt, deletedAt}`.

**Error envelope, always:** `{"error":{"code":"…","message":"…"}}`. Codes:
`bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`,
`rate_limited`, `internal`.

**`authHash` encoding:** the client sends `toBase64(authHash)` — the same string
at enrolment and at login. The server hashes whatever string it receives, so the
two must agree; base64 of the 32 raw bytes is the convention.

---

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `apps/web/package.json` | Workspace package `@keyhole/web` |
| `apps/web/tsconfig.json` | Extends the base; DOM + vitest globals |
| `apps/web/vite.config.ts` | Dev server, `/api` proxy to `127.0.0.1:8477` |
| `apps/web/vitest.config.ts` | jsdom environment, `src/**/*.test.ts(x)` |
| `apps/web/eslint.config.js` | The `ui/` → crypto import ban |
| `apps/web/index.html` | Vite entry |
| `apps/web/src/vault/api.ts` | Typed fetch client, error union, token refresh |
| `apps/web/src/vault/session.ts` | The only holder of keys and tokens |
| `apps/web/src/vault/unlock.ts` | prelogin → beginUnlock → login → finish |
| `apps/web/src/vault/enroll.ts` | enrollUser → recovery blob → enrol → login |
| `apps/web/src/vault/items.ts` | Item encrypt/decrypt orchestration |
| `apps/web/src/vault/store.ts` | Subscribable in-memory vault state |
| `apps/web/src/vault/generator.ts` | Password generator (pure) |
| `apps/web/src/ui/tokens.css` | Mono design tokens |
| `apps/web/src/ui/App.tsx` | Boot path check + screen switch |
| `apps/web/src/ui/screens/*.tsx` | Unlock, Enrol, Vault, ItemEditor |
| `apps/web/src/ui/components/*.tsx` | Field, Button, Dialog, PasswordStrength |
| `apps/web/src/main.tsx` | React root |
| `apps/web/e2e/*.spec.ts` | Playwright journeys |
| `apps/web/e2e/server.ts` | Real-server harness (build, migrate, admin create) |
| `apps/web/playwright.config.ts` | Playwright config |

**Modified:**

| File | Change |
|---|---|
| `pnpm-workspace.yaml` | Add `@playwright/test` to `allowBuilds` |

---

## Task 1: Scaffold `apps/web` and the API client

**Files:**
- Create: `apps/web/package.json`, `apps/web/tsconfig.json`,
  `apps/web/vite.config.ts`, `apps/web/vitest.config.ts`,
  `apps/web/eslint.config.js`, `apps/web/index.html`,
  `apps/web/src/vault/api.ts`
- Test: `apps/web/src/vault/api.test.ts`
- Modify: `pnpm-workspace.yaml`

**Interfaces:**
- Consumes: nothing (first task).
- Produces, and every later task uses these:
  ```ts
  export type ApiErrorCode =
    | "bad_request" | "unauthorized" | "forbidden" | "not_found"
    | "conflict" | "rate_limited" | "internal";

  export class ApiError extends Error {
    readonly code: ApiErrorCode;
    readonly status: number;
    readonly body: unknown;   // the whole parsed envelope, so 409 keeps `item`
  }
  export class NetworkError extends Error {}

  export interface ApiClient {
    get<T>(path: string): Promise<T>;
    post<T>(path: string, body?: unknown): Promise<T>;
    put<T>(path: string, body: unknown): Promise<T>;
    del<T>(path: string): Promise<T>;
  }

  export function createApiClient(opts: {
    baseUrl?: string;
    getAccessToken: () => string | null;
    onUnauthorized: () => Promise<boolean>;  // refresh once; true if retryable
    fetchImpl?: typeof fetch;
  }): ApiClient;
  ```

- [ ] **Step 1: Add the workspace package files**

Create `apps/web/package.json`:

```json
{
  "name": "@keyhole/web",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "test": "vitest run",
    "test:watch": "vitest",
    "test:e2e": "playwright test",
    "typecheck": "tsc --noEmit",
    "lint": "eslint ."
  },
  "dependencies": {
    "@keyhole/crypto": "workspace:*",
    "react": "^19.1.0",
    "react-dom": "^19.1.0"
  },
  "devDependencies": {
    "@playwright/test": "^1.52.0",
    "@testing-library/jest-dom": "^6.6.0",
    "@testing-library/react": "^16.3.0",
    "@testing-library/user-event": "^14.6.0",
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

**Two dependencies from design spec §2 are deliberately absent, and the reviewer
should not add them back:**

- **Tailwind.** Mono is type, spacing, and hairline rules — expressed here as
  CSS custom properties in one token file (Task 7). Adding Tailwind for four
  screens would mean two styling systems and a build step, to save nothing.
- **Radix.** Its value is dialog and menu behaviour — focus traps, escape
  handling, roving tabindex. This slice has no dialog and no menu. Task 4's
  settings and admin screens are where that behaviour is actually needed.

Both arrive with the next plan, against a real component inventory rather than a
guess. Adding an unused dependency now is the kind of decision that is never
revisited.

Create `apps/web/tsconfig.json`:

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "jsx": "react-jsx",
    "types": ["vitest/globals", "@testing-library/jest-dom"]
  },
  "include": ["src", "e2e", "*.config.ts"]
}
```

Create `apps/web/vite.config.ts`:

```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The Go server owns /api. Proxying rather than enabling CORS keeps the browser
// on one origin, which is what production looks like behind the tunnel — so the
// dev setup cannot pass while a same-origin assumption is broken.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8477",
        changeOrigin: false,
      },
    },
  },
});
```

Create `apps/web/vitest.config.ts`:

```ts
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["./src/test-setup.ts"],
    // Argon2id at 64 MiB is deliberately slow; anything touching the crypto
    // package needs headroom.
    testTimeout: 30_000,
  },
});
```

Create `apps/web/src/test-setup.ts`:

```ts
import "@testing-library/jest-dom/vitest";
```

Create `apps/web/index.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Keyhole</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 2: Add the import ban and the allowBuilds entry**

Create `apps/web/eslint.config.js`:

```js
import tseslint from "typescript-eslint";

export default tseslint.config({
  files: ["src/ui/**/*.{ts,tsx}"],
  rules: {
    // Design spec 6.3 calls the memory-only rule "a code-review gate, not a
    // guideline". This is that gate, mechanised: if the UI cannot reach the
    // crypto package, it cannot hold a key by accident, and a violation fails
    // the build instead of depending on a reviewer noticing.
    "no-restricted-imports": [
      "error",
      {
        paths: [
          {
            name: "@keyhole/crypto",
            message:
              "UI code must not touch crypto directly. Go through src/vault/, " +
              "which is the only layer allowed to hold key material.",
          },
        ],
      },
    ],
  },
});
```

In `pnpm-workspace.yaml`, extend `allowBuilds` — pnpm 11 stalls
non-interactively on a package with an ungated postinstall, and Playwright
downloads browsers in one:

```yaml
packages:
  - "packages/*"
  - "apps/*"
allowBuilds:
  esbuild: true
  "@playwright/test": true
```

Then install:

```bash
pnpm install
```

- [ ] **Step 3: Write the failing API client tests**

Create `apps/web/src/vault/api.test.ts`:

```ts
import { describe, expect, it, vi } from "vitest";
import { ApiError, NetworkError, createApiClient } from "./api.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function clientWith(fetchImpl: typeof fetch, token: string | null = "tok") {
  return createApiClient({
    getAccessToken: () => token,
    onUnauthorized: async () => false,
    fetchImpl,
  });
}

describe("createApiClient", () => {
  it("sends the bearer token and parses a successful body", async () => {
    const fetchImpl = vi.fn(async (_url, init) => {
      expect((init?.headers as Record<string, string>).Authorization).toBe(
        "Bearer tok",
      );
      return jsonResponse(200, { revision: 7, items: [] });
    }) as unknown as typeof fetch;

    const api = clientWith(fetchImpl);
    await expect(api.get<{ revision: number }>("/api/sync")).resolves.toEqual({
      revision: 7,
      items: [],
    });
  });

  it("sends no Authorization header when there is no token", async () => {
    // Prelogin and enrolment are unauthenticated. Sending "Bearer null" would
    // be rejected as a malformed credential rather than treated as absent.
    const fetchImpl = vi.fn(async (_url, init) => {
      expect((init?.headers as Record<string, string>).Authorization).toBeUndefined();
      return jsonResponse(200, {});
    }) as unknown as typeof fetch;

    await clientWith(fetchImpl, null).post("/api/auth/prelogin", { email: "a@b.c" });
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("turns an error envelope into an ApiError carrying the code", async () => {
    const fetchImpl = (async () =>
      jsonResponse(404, {
        error: { code: "not_found", message: "not found" },
      })) as unknown as typeof fetch;

    const error = await clientWith(fetchImpl)
      .get("/api/items/abc")
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    // The UI branches on code, never message: errors.go states codes are
    // stable and messages are for humans and may change.
    expect((error as ApiError).code).toBe("not_found");
    expect((error as ApiError).status).toBe(404);
  });

  it("keeps the whole body on a conflict so the winning item survives", async () => {
    const winner = { id: "abc", ciphertext: "winner", revision: 9 };
    const fetchImpl = (async () =>
      jsonResponse(409, {
        error: { code: "conflict", message: "changed" },
        item: winner,
      })) as unknown as typeof fetch;

    const error = (await clientWith(fetchImpl)
      .put("/api/items/abc", {})
      .catch((e: unknown) => e)) as ApiError;

    // Without the sibling `item` the client has nothing to reconcile against
    // and its only option is to discard one of the two edits.
    expect(error.code).toBe("conflict");
    expect((error.body as { item: unknown }).item).toEqual(winner);
  });

  it("reports an unreachable server as a NetworkError, not an auth failure", async () => {
    const fetchImpl = (async () => {
      throw new TypeError("Failed to fetch");
    }) as unknown as typeof fetch;

    // Design spec 9: a network blip must never read as a wrong password.
    await expect(clientWith(fetchImpl).get("/api/sync")).rejects.toBeInstanceOf(
      NetworkError,
    );
  });

  it("retries once after a successful refresh, and only once", async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls += 1;
      if (calls === 1) {
        return jsonResponse(401, {
          error: { code: "unauthorized", message: "nope" },
        });
      }
      return jsonResponse(200, { ok: true });
    }) as unknown as typeof fetch;

    const onUnauthorized = vi.fn(async () => true);
    const api = createApiClient({
      getAccessToken: () => "tok",
      onUnauthorized,
      fetchImpl,
    });

    await expect(api.get<{ ok: boolean }>("/api/sync")).resolves.toEqual({ ok: true });
    expect(calls).toBe(2);
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });

  it("does not loop when the refresh itself fails", async () => {
    // A refresh token is single-use server-side (RotateSession replaces the
    // hash), so retrying in a loop burns the session and produces a cascade.
    let calls = 0;
    const fetchImpl = (async () => {
      calls += 1;
      return jsonResponse(401, {
        error: { code: "unauthorized", message: "nope" },
      });
    }) as unknown as typeof fetch;

    const api = createApiClient({
      getAccessToken: () => "tok",
      onUnauthorized: async () => false,
      fetchImpl,
    });

    await expect(api.get("/api/sync")).rejects.toBeInstanceOf(ApiError);
    expect(calls).toBe(1);
  });

  it("treats a 204 as an empty success rather than a parse failure", async () => {
    const fetchImpl = (async () =>
      new Response(null, { status: 204 })) as unknown as typeof fetch;
    await expect(clientWith(fetchImpl).del("/api/items/abc")).resolves.toBeNull();
  });
});
```

- [ ] **Step 4: Run and watch it fail**

```bash
pnpm --filter @keyhole/web test
```

Expected: FAIL — `Cannot find module './api.js'`.

- [ ] **Step 5: Implement the API client**

Create `apps/web/src/vault/api.ts`:

```ts
/**
 * The one place a server response becomes a typed result or a typed failure.
 *
 * Everything above this module branches on `ApiError.code`, never on the
 * message: internal/httpapi/errors.go states that codes are stable and messages
 * are for humans and may change.
 */

export type ApiErrorCode =
  | "bad_request"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "rate_limited"
  | "internal";

export class ApiError extends Error {
  readonly code: ApiErrorCode;
  readonly status: number;
  /** The whole parsed envelope. A 409 carries a sibling `item`; discarding it
   *  would leave the client unable to build a conflicted copy. */
  readonly body: unknown;

  constructor(code: ApiErrorCode, status: number, message: string, body: unknown) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.body = body;
  }
}

/** The server was not reached at all. Distinct from every ApiError, because
 *  design spec 9 forbids a network blip reading as a wrong password. */
export class NetworkError extends Error {
  constructor(cause: unknown) {
    super("Could not reach the server");
    this.name = "NetworkError";
    this.cause = cause;
  }
}

export interface ApiClient {
  get<T>(path: string): Promise<T>;
  post<T>(path: string, body?: unknown): Promise<T>;
  put<T>(path: string, body: unknown): Promise<T>;
  del<T>(path: string): Promise<T>;
}

export interface ApiClientOptions {
  baseUrl?: string;
  getAccessToken: () => string | null;
  /** Attempt to refresh. Resolves true if the request is worth retrying.
   *  Called at most once per request — see the loop note below. */
  onUnauthorized: () => Promise<boolean>;
  fetchImpl?: typeof fetch;
}

const KNOWN_CODES: readonly string[] = [
  "bad_request",
  "unauthorized",
  "forbidden",
  "not_found",
  "conflict",
  "rate_limited",
  "internal",
];

function toApiError(status: number, body: unknown): ApiError {
  const envelope = body as { error?: { code?: string; message?: string } } | null;
  const rawCode = envelope?.error?.code;
  // An unrecognised or absent code is treated as `internal` rather than trusted:
  // a proxy error page or a truncated body must not be reported as the caller's
  // fault, and must not crash the branch that reads it.
  const code = (rawCode && KNOWN_CODES.includes(rawCode) ? rawCode : "internal") as ApiErrorCode;
  const message = envelope?.error?.message ?? "The server returned an error";
  return new ApiError(code, status, message, body);
}

export function createApiClient(opts: ApiClientOptions): ApiClient {
  const baseUrl = opts.baseUrl ?? "";
  const doFetch = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);

  async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const send = async (): Promise<Response> => {
      const headers: Record<string, string> = {};
      const token = opts.getAccessToken();
      if (token !== null) {
        headers.Authorization = `Bearer ${token}`;
      }
      const init: RequestInit = { method, headers };
      if (body !== undefined) {
        headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(body);
      }
      try {
        return await doFetch(`${baseUrl}${path}`, init);
      } catch (cause) {
        throw new NetworkError(cause);
      }
    };

    let response = await send();

    // Exactly one retry. The refresh token is single-use server-side —
    // RotateSession matches on the old hash and replaces it — so a loop would
    // spend the session and turn one expiry into a confusing cascade.
    if (response.status === 401 && (await opts.onUnauthorized())) {
      response = await send();
    }

    if (response.status === 204 || response.headers.get("Content-Length") === "0") {
      return null as T;
    }

    let parsed: unknown = null;
    const text = await response.text();
    if (text.length > 0) {
      try {
        parsed = JSON.parse(text);
      } catch {
        // A non-JSON body from a proxy or gateway. Not the caller's fault.
        if (response.ok) {
          throw new ApiError("internal", response.status, "Malformed response", text);
        }
      }
    }

    if (!response.ok) {
      throw toApiError(response.status, parsed);
    }
    return parsed as T;
  }

  return {
    get: (path) => request("GET", path),
    post: (path, body) => request("POST", path, body),
    put: (path, body) => request("PUT", path, body),
    del: (path) => request("DELETE", path),
  };
}
```

- [ ] **Step 6: Run the tests**

```bash
pnpm --filter @keyhole/web test
pnpm --filter @keyhole/web typecheck
pnpm --filter @keyhole/web lint
```

Expected: PASS, all eight. Typecheck and lint silent.

- [ ] **Step 7: Prove the retry cap is load-bearing**

In `api.ts`, temporarily change the single retry to a loop:

```ts
    while (response.status === 401 && (await opts.onUnauthorized())) {
      response = await send();
    }
```

Run: `pnpm --filter @keyhole/web test -t "does not loop"`

Expected: the test still passes (its `onUnauthorized` returns false), which
shows the *existing* test does not cover the loop. Now also change that test's
`onUnauthorized` to `async () => true` and re-run: expected HANG or timeout.
Revert both. **Record this in the report** — it is the reason the retry is a
single `if` and not a `while`.

- [ ] **Step 8: Commit**

```bash
git add apps/web pnpm-workspace.yaml pnpm-lock.yaml
git commit -m "feat(web): scaffold the web app and its API client"
```

---

## Task 2: The session — the only holder of keys

**Files:**
- Create: `apps/web/src/vault/session.ts`
- Test: `apps/web/src/vault/session.test.ts`

**Interfaces:**
- Consumes: `zeroize` from `@keyhole/crypto`.
- Produces:
  ```ts
  export interface SessionTokens { accessToken: string; refreshToken: string }
  export interface SessionUser { id: string; email: string; name: string; role: string }

  export interface Session {
    readonly isUnlocked: boolean;
    readonly user: SessionUser | null;
    getAccessToken(): string | null;
    getKeys(): { userKey: Uint8Array; privateKey: Uint8Array };  // throws when locked
    open(input: { tokens: SessionTokens; user: SessionUser;
                  userKey: Uint8Array; privateKey: Uint8Array }): void;
    replaceTokens(tokens: SessionTokens): void;
    lock(): void;
    subscribe(listener: () => void): () => void;
  }

  export function createSession(): Session;
  export const EMAIL_STORAGE_KEY = "keyhole.email";
  export function rememberEmail(email: string): void;
  export function rememberedEmail(): string | null;
  export function forgetEmail(): void;
  ```

- [ ] **Step 1: Write the failing session tests**

Create `apps/web/src/vault/session.test.ts`:

```ts
import { beforeEach, describe, expect, it } from "vitest";
import {
  EMAIL_STORAGE_KEY,
  createSession,
  forgetEmail,
  rememberEmail,
  rememberedEmail,
} from "./session.js";

const USER = { id: "u1", email: "a@b.c", name: "A", role: "user" };
const TOKENS = { accessToken: "access", refreshToken: "refresh" };

function openSession() {
  const session = createSession();
  session.open({
    tokens: TOKENS,
    user: USER,
    userKey: new Uint8Array([1, 2, 3, 4]),
    privateKey: new Uint8Array([5, 6, 7, 8]),
  });
  return session;
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
});

describe("session", () => {
  it("is locked before open and unlocked after", () => {
    const session = createSession();
    expect(session.isUnlocked).toBe(false);
    expect(session.getAccessToken()).toBeNull();
    expect(() => session.getKeys()).toThrow();

    session.open({
      tokens: TOKENS,
      user: USER,
      userKey: new Uint8Array(4),
      privateKey: new Uint8Array(4),
    });
    expect(session.isUnlocked).toBe(true);
    expect(session.getAccessToken()).toBe("access");
    expect(session.user).toEqual(USER);
  });

  it("zeroizes the key material on lock", () => {
    const userKey = new Uint8Array([1, 2, 3, 4]);
    const privateKey = new Uint8Array([5, 6, 7, 8]);
    const session = createSession();
    session.open({ tokens: TOKENS, user: USER, userKey, privateKey });

    session.lock();

    // The caller's arrays are the same objects the session holds, so this
    // asserts the bytes are actually gone from memory rather than merely
    // dereferenced and left for the garbage collector to maybe reclaim.
    expect(Array.from(userKey)).toEqual([0, 0, 0, 0]);
    expect(Array.from(privateKey)).toEqual([0, 0, 0, 0]);
    expect(session.isUnlocked).toBe(false);
    expect(session.getAccessToken()).toBeNull();
    expect(() => session.getKeys()).toThrow();
  });

  it("writes nothing but the email to storage, ever", () => {
    const session = openSession();
    rememberEmail("a@b.c");

    const dump = JSON.stringify({
      local: { ...localStorage },
      session: { ...sessionStorage },
    });

    // Design spec 6.3, stated as a code-review gate: no key material and no
    // plaintext outside memory. A stringified dump catches a value written
    // under any key, which an assertion on known keys would not.
    for (const forbidden of ["access", "refresh", "1,2,3,4", "5,6,7,8"]) {
      expect(dump).not.toContain(forbidden);
    }
    expect(Object.keys(localStorage)).toEqual([EMAIL_STORAGE_KEY]);
    expect(Object.keys(sessionStorage)).toHaveLength(0);
    session.lock();
  });

  it("survives a remembered email across a fresh session", () => {
    rememberEmail("person@example.com");
    expect(rememberedEmail()).toBe("person@example.com");
    forgetEmail();
    expect(rememberedEmail()).toBeNull();
  });

  it("notifies subscribers on open and lock, and stops after unsubscribe", () => {
    const session = createSession();
    let calls = 0;
    const unsubscribe = session.subscribe(() => {
      calls += 1;
    });

    session.open({
      tokens: TOKENS,
      user: USER,
      userKey: new Uint8Array(4),
      privateKey: new Uint8Array(4),
    });
    expect(calls).toBe(1);

    session.lock();
    expect(calls).toBe(2);

    unsubscribe();
    session.open({
      tokens: TOKENS,
      user: USER,
      userKey: new Uint8Array(4),
      privateKey: new Uint8Array(4),
    });
    expect(calls).toBe(2);
  });

  it("replaces tokens without disturbing the keys", () => {
    const session = openSession();
    const before = session.getKeys();

    session.replaceTokens({ accessToken: "fresh", refreshToken: "fresh-r" });

    expect(session.getAccessToken()).toBe("fresh");
    // A token refresh must not cost the user their unlocked vault.
    expect(session.getKeys().userKey).toBe(before.userKey);
    expect(session.isUnlocked).toBe(true);
  });

  it("is safe to lock twice", () => {
    const session = openSession();
    session.lock();
    expect(() => session.lock()).not.toThrow();
  });
});
```

- [ ] **Step 2: Run and watch it fail**

```bash
pnpm --filter @keyhole/web test -t session
```

Expected: FAIL — `Cannot find module './session.js'`.

- [ ] **Step 3: Implement the session**

Create `apps/web/src/vault/session.ts`:

```ts
import { zeroize } from "@keyhole/crypto";

/**
 * The only module in this application that retains key material.
 *
 * Everything else receives what it needs as an argument and does not hold it.
 * That is deliberate and load-bearing: design spec 6.3 makes "decrypted keys in
 * memory only" a code-review gate, and a gate is only checkable if there is one
 * place to look. This module has no serializer, no storage call for anything but
 * the email, and nothing that could reach one.
 */

export interface SessionTokens {
  accessToken: string;
  refreshToken: string;
}

export interface SessionUser {
  id: string;
  email: string;
  name: string;
  role: string;
}

export interface Session {
  readonly isUnlocked: boolean;
  readonly user: SessionUser | null;
  getAccessToken(): string | null;
  getRefreshToken(): string | null;
  getKeys(): { userKey: Uint8Array; privateKey: Uint8Array };
  open(input: {
    tokens: SessionTokens;
    user: SessionUser;
    userKey: Uint8Array;
    privateKey: Uint8Array;
  }): void;
  replaceTokens(tokens: SessionTokens): void;
  lock(): void;
  subscribe(listener: () => void): () => void;
}

/**
 * The single permitted persisted value in this entire application.
 *
 * An email address is not a secret to the server — it is the account identity,
 * already known to anyone holding the device. Persisting it buys a password-only
 * unlock screen. Persisting the refresh token would buy nothing beyond that,
 * because the wrapped keys come back only from POST /api/auth/login
 * (internal/httpapi/auth.go:184) and never from refresh — so an unlock is a full
 * login regardless — while handing a device thief working API access.
 */
export const EMAIL_STORAGE_KEY = "keyhole.email";

export function rememberEmail(email: string): void {
  localStorage.setItem(EMAIL_STORAGE_KEY, email);
}

export function rememberedEmail(): string | null {
  return localStorage.getItem(EMAIL_STORAGE_KEY);
}

export function forgetEmail(): void {
  localStorage.removeItem(EMAIL_STORAGE_KEY);
}

export function createSession(): Session {
  let tokens: SessionTokens | null = null;
  let user: SessionUser | null = null;
  let userKey: Uint8Array | null = null;
  let privateKey: Uint8Array | null = null;
  const listeners = new Set<() => void>();

  const notify = (): void => {
    for (const listener of listeners) listener();
  };

  return {
    get isUnlocked() {
      return userKey !== null && privateKey !== null;
    },
    get user() {
      return user;
    },
    getAccessToken() {
      return tokens?.accessToken ?? null;
    },
    getRefreshToken() {
      return tokens?.refreshToken ?? null;
    },
    getKeys() {
      if (userKey === null || privateKey === null) {
        // Throwing beats returning null: a caller that forgot to check would
        // otherwise encrypt with `undefined` and produce a blob nothing can
        // ever open, which surfaces months later as an unreadable item.
        throw new Error("The vault is locked");
      }
      return { userKey, privateKey };
    },
    open(input) {
      tokens = input.tokens;
      user = input.user;
      userKey = input.userKey;
      privateKey = input.privateKey;
      notify();
    },
    replaceTokens(next) {
      tokens = next;
    },
    lock() {
      zeroize(userKey, privateKey);
      userKey = null;
      privateKey = null;
      tokens = null;
      user = null;
      notify();
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
}
```

`zeroize` already accepts `null` and `undefined`, which is what makes the
double-lock case safe without a guard.

- [ ] **Step 4: Run the tests**

```bash
pnpm --filter @keyhole/web test -t session
```

Expected: PASS, all seven.

- [ ] **Step 5: Prove the zeroize is load-bearing**

In `session.ts`, temporarily drop the zeroize call:

```ts
    lock() {
      userKey = null;
      privateKey = null;
```

Run: `pnpm --filter @keyhole/web test -t "zeroizes"`

Expected: FAIL — the arrays still read `[1,2,3,4]` and `[5,6,7,8]`. Revert and
confirm PASS. Record both in the report: dereferencing is not erasing, and the
difference is whether key bytes linger in a heap snapshot.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/vault/session.ts apps/web/src/vault/session.test.ts
git commit -m "feat(web): the session, and the one value allowed on disk"
```

---

## Task 3: Unlock

**Files:**
- Create: `apps/web/src/vault/unlock.ts`
- Test: `apps/web/src/vault/unlock.test.ts`

**Interfaces:**
- Consumes: `ApiClient`, `ApiError` (Task 1); `Session`, `SessionUser`,
  `rememberEmail`, `rememberedEmail` (Task 2); `beginUnlock`, `fromBase64`,
  `toBase64`, `DEFAULT_KDF_PARAMS`, type `KdfParams` from `@keyhole/crypto`.
- Produces:
  ```ts
  export class WrongMasterPasswordError extends Error {}
  export async function unlock(
    deps: { api: ApiClient; session: Session },
    input: { email: string; masterPassword: string; deviceLabel: string },
  ): Promise<void>;
  ```

- [ ] **Step 1: Write the failing unlock tests**

Create `apps/web/src/vault/unlock.test.ts`:

```ts
import { beforeEach, describe, expect, it } from "vitest";
import { DEFAULT_KDF_PARAMS_JSON, enrollUser, toBase64 } from "@keyhole/crypto";
import { ApiError, type ApiClient } from "./api.js";
import { createSession, rememberedEmail } from "./session.js";
import { WrongMasterPasswordError, unlock } from "./unlock.js";

// 16 bytes, the length assertKdfSalt requires.
const SALT_B64 = toBase64(new Uint8Array(16).fill(7));

interface FakeOptions {
  loginThrows?: unknown;
  protectedUserKey?: string;
  encryptedPrivateKey?: string;
  loginBodies?: unknown[];
}

function fakeApi(options: FakeOptions = {}): { api: ApiClient; calls: string[] } {
  const calls: string[] = [];
  const api: ApiClient = {
    async get<T>(path: string): Promise<T> {
      throw new Error(`unexpected GET ${path}`);
    },
    async post<T>(path: string, body?: unknown): Promise<T> {
      calls.push(`POST ${path}`);
      if (path === "/api/auth/prelogin") {
        return { kdfSalt: SALT_B64, params: DEFAULT_KDF_PARAMS_JSON } as T;
      }
      if (path === "/api/auth/login") {
        if (options.loginThrows !== undefined) throw options.loginThrows;
        options.loginBodies?.push(body);
        return {
          accessToken: "access",
          refreshToken: "refresh",
          protectedUserKey: options.protectedUserKey ?? "puk",
          encryptedPrivateKey: options.encryptedPrivateKey ?? "epk",
          user: { id: "u1", email: "a@b.c", name: "A", role: "user" },
        } as T;
      }
      throw new Error(`unexpected POST ${path}`);
    },
    async put<T>(): Promise<T> {
      throw new Error("unexpected PUT");
    },
    async del<T>(): Promise<T> {
      throw new Error("unexpected DELETE");
    },
  };
  return { api, calls };
}

beforeEach(() => {
  localStorage.clear();
});

describe("unlock", () => {
  it("preloginss, derives, logs in, and unwraps the enrolled keys", async () => {
    // A round trip against the real crypto. Stubbing it here would leave the
    // one thing worth testing untested: that the key which comes out is the
    // key that went in.
    const enrolled = await enrollUser("correct horse battery staple");
    const { api, calls } = fakeApi({
      protectedUserKey: enrolled.protectedUserKey,
      encryptedPrivateKey: enrolled.encryptedPrivateKey,
    });
    const session = createSession();

    await unlock(
      { api, session },
      {
        email: "a@b.c",
        masterPassword: "correct horse battery staple",
        deviceLabel: "test",
      },
    );

    expect(calls).toEqual(["POST /api/auth/prelogin", "POST /api/auth/login"]);
    expect(session.isUnlocked).toBe(true);
    expect(session.getAccessToken()).toBe("access");
    expect(Array.from(session.getKeys().userKey)).toEqual(
      Array.from(enrolled.userKey),
    );
  }, 60_000);

  it("sends the auth hash base64-encoded, never as raw bytes", async () => {
    const enrolled = await enrollUser("pw");
    const loginBodies: unknown[] = [];
    const { api } = fakeApi({
      loginBodies,
      protectedUserKey: enrolled.protectedUserKey,
      encryptedPrivateKey: enrolled.encryptedPrivateKey,
    });

    await unlock(
      { api, session: createSession() },
      { email: "a@b.c", masterPassword: "pw", deviceLabel: "test" },
    );

    // The server hashes whatever string arrives, so enrolment and login only
    // have to agree with each other. That is exactly why a wrong encoding is
    // invisible: a JSON-serialised Uint8Array would authenticate consistently
    // and never be noticed until another client tried to log in.
    const body = loginBodies[0] as { authHash: string };
    expect(typeof body.authHash).toBe("string");
    expect(body.authHash).toMatch(/^[A-Za-z0-9+/]+=*$/);
  }, 60_000);

  it("reports a 401 as a wrong master password", async () => {
    const { api } = fakeApi({
      loginThrows: new ApiError("unauthorized", 401, "invalid credentials", {}),
    });

    // Design spec 9: unlock failure is honestly worded. The server answers a
    // wrong password and an unknown account identically, which is correct —
    // both are the same thing to the person typing.
    await expect(
      unlock(
        { api, session: createSession() },
        { email: "a@b.c", masterPassword: "wrong", deviceLabel: "test" },
      ),
    ).rejects.toBeInstanceOf(WrongMasterPasswordError);
  }, 60_000);

  it("leaves the session locked and the email unremembered when login fails", async () => {
    const { api } = fakeApi({
      loginThrows: new ApiError("unauthorized", 401, "nope", {}),
    });
    const session = createSession();

    await unlock(
      { api, session },
      { email: "typo@example.com", masterPassword: "wrong", deviceLabel: "test" },
    ).catch(() => undefined);

    expect(session.isUnlocked).toBe(false);
    // A failed attempt must not pin a mistyped address into the unlock screen.
    expect(rememberedEmail()).toBeNull();
  }, 60_000);

  it("remembers the email after a successful unlock", async () => {
    const enrolled = await enrollUser("pw");
    const { api } = fakeApi({
      protectedUserKey: enrolled.protectedUserKey,
      encryptedPrivateKey: enrolled.encryptedPrivateKey,
    });

    await unlock(
      { api, session: createSession() },
      { email: "a@b.c", masterPassword: "pw", deviceLabel: "test" },
    );

    expect(rememberedEmail()).toBe("a@b.c");
  }, 60_000);
});
```

- [ ] **Step 2: Run and watch it fail**

```bash
pnpm --filter @keyhole/web test -t unlock
```

Expected: FAIL — `Cannot find module './unlock.js'`.

- [ ] **Step 3: Implement unlock**

Create `apps/web/src/vault/unlock.ts`:

```ts
import {
  beginUnlock,
  fromBase64,
  toBase64,
  type KdfParams,
} from "@keyhole/crypto";
import { ApiError, type ApiClient } from "./api.js";
import { rememberEmail, type Session, type SessionUser } from "./session.js";

/**
 * The password did not open the vault.
 *
 * Distinct from every other failure because design spec 9 requires unlock
 * failure to be honestly worded: a network blip must never read as a wrong
 * password, and a wrong password must not read as a server fault.
 */
export class WrongMasterPasswordError extends Error {
  constructor() {
    super("Wrong master password");
    this.name = "WrongMasterPasswordError";
  }
}

interface PreloginResponse {
  kdfSalt: string;
  params: string;
}

interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  protectedUserKey: string;
  encryptedPrivateKey: string;
  user: SessionUser;
}

/**
 * prelogin then login, with exactly one Argon2id pass between them.
 *
 * The order is forced by the protocol: login is authHash out and the wrapped
 * keys back, so the client must produce the hash before it holds the blobs.
 * beginUnlock exists precisely so that costs one derivation rather than two — a
 * second is another second on a phone, on the screen where the user is already
 * waiting.
 */
export async function unlock(
  deps: { api: ApiClient; session: Session },
  input: { email: string; masterPassword: string; deviceLabel: string },
): Promise<void> {
  const prelogin = await deps.api.post<PreloginResponse>("/api/auth/prelogin", {
    email: input.email,
  });

  // An unknown address gets a decoy salt and the default params, shaped exactly
  // like a real answer. That is the enumeration defence, and it means this path
  // is identical either way right up to the 401.
  const params = JSON.parse(prelogin.params) as KdfParams;
  const unlockSession = await beginUnlock(
    input.masterPassword,
    fromBase64(prelogin.kdfSalt),
    params,
  );

  try {
    let login: LoginResponse;
    try {
      login = await deps.api.post<LoginResponse>("/api/auth/login", {
        email: input.email,
        authHash: toBase64(unlockSession.authHash),
        deviceLabel: input.deviceLabel,
      });
    } catch (error) {
      if (error instanceof ApiError && error.code === "unauthorized") {
        throw new WrongMasterPasswordError();
      }
      throw error;
    }

    const keys = await unlockSession.finish(
      login.protectedUserKey,
      login.encryptedPrivateKey,
    );

    deps.session.open({
      tokens: {
        accessToken: login.accessToken,
        refreshToken: login.refreshToken,
      },
      user: login.user,
      userKey: keys.userKey,
      privateKey: keys.privateKey,
    });
    // Only after success: a failed attempt must not pin a typo into the screen.
    rememberEmail(input.email);
  } finally {
    // Zeroizes the derived master and wrapping keys whichever way this went.
    unlockSession.destroy();
  }
}
```

- [ ] **Step 4: Run the tests**

```bash
pnpm --filter @keyhole/web test -t unlock
```

Expected: PASS, all five. They are slow — real Argon2id at 64 MiB, roughly half a
second per derivation. That cost is the feature.

- [ ] **Step 5: Prove the 401 mapping is load-bearing**

In `unlock.ts`, temporarily remove the `ApiError` branch so the raw error
propagates:

```ts
    login = await deps.api.post<LoginResponse>("/api/auth/login", { /* … */ });
```

Run: `pnpm --filter @keyhole/web test -t "wrong master password"`

Expected: FAIL — an `ApiError` arrives where `WrongMasterPasswordError` was
required. In the UI that is the difference between "Wrong master password" and a
generic failure the user cannot act on. Revert and confirm PASS. Record both.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/vault/unlock.ts apps/web/src/vault/unlock.test.ts
git commit -m "feat(web): unlock, and the honest wrong-password error"
```

---

## Task 4: Enrolment

**Files:**
- Create: `apps/web/src/vault/enroll.ts`
- Test: `apps/web/src/vault/enroll.test.ts`

**Interfaces:**
- Consumes: `ApiClient` (Task 1); `Session`, `rememberEmail` (Task 2);
  `enrollUser`, `generateRecoveryCode`, `createRecoveryBlob`,
  `DEFAULT_KDF_PARAMS`, `DEFAULT_KDF_PARAMS_JSON`, `toBase64` from
  `@keyhole/crypto`.
- Produces:
  ```ts
  export interface EnrolmentOutcome { recoveryCode: string }
  export async function enroll(
    deps: { api: ApiClient; session: Session },
    input: {
      inviteToken: string; email: string;
      masterPassword: string; deviceLabel: string;
    },
  ): Promise<EnrolmentOutcome>;
  ```

- [ ] **Step 1: Write the failing enrolment tests**

Create `apps/web/src/vault/enroll.test.ts`:

```ts
import { beforeEach, describe, expect, it } from "vitest";
import {
  DEFAULT_KDF_PARAMS_JSON,
  fromBase64,
  recoverUserKey,
} from "@keyhole/crypto";
import type { ApiClient } from "./api.js";
import { createSession } from "./session.js";
import { enroll } from "./enroll.js";

interface EnrolBody {
  kdfSalt: string;
  params: string;
  authHash: string;
  protectedUserKey: string;
  publicKey: string;
  encryptedPrivateKey: string;
  recoverySalt: string;
  recoveryProtectedUserKey: string;
  recoveryKdfParams: string;
}

function recordingApi(): { api: ApiClient; bodies: Map<string, unknown> } {
  const bodies = new Map<string, unknown>();
  const api: ApiClient = {
    async get<T>(): Promise<T> {
      throw new Error("unexpected GET");
    },
    async post<T>(path: string, body?: unknown): Promise<T> {
      const key = path.startsWith("/api/enroll/") ? "/api/enroll" : path;
      bodies.set(key, body);
      if (key === "/api/enroll") {
        // Deliberately minimal, matching the server: no tokens, no key material.
        return { id: "u1", email: "a@b.c", name: "A", role: "user" } as T;
      }
      if (path === "/api/auth/login") {
        const enrolled = bodies.get("/api/enroll") as EnrolBody;
        return {
          accessToken: "access",
          refreshToken: "refresh",
          protectedUserKey: enrolled.protectedUserKey,
          encryptedPrivateKey: enrolled.encryptedPrivateKey,
          user: { id: "u1", email: "a@b.c", name: "A", role: "user" },
        } as T;
      }
      throw new Error(`unexpected POST ${path}`);
    },
    async put<T>(): Promise<T> {
      throw new Error("unexpected PUT");
    },
    async del<T>(): Promise<T> {
      throw new Error("unexpected DELETE");
    },
  };
  return { api, bodies };
}

const INPUT = {
  inviteToken: "tok",
  email: "a@b.c",
  masterPassword: "pw",
  deviceLabel: "test",
};

beforeEach(() => {
  localStorage.clear();
});

describe("enroll", () => {
  it("sends params as the pinned constant, byte for byte", async () => {
    const { api, bodies } = recordingApi();

    await enroll({ api, session: createSession() }, INPUT);

    const body = bodies.get("/api/enroll") as EnrolBody;
    // The server rejects anything not byte-equal (Plan 2b Task 6). A
    // JSON.stringify here happens to produce the right bytes today only because
    // the object literal is declared in that key order — one reordering away
    // from a 400 nobody can explain.
    expect(body.params).toBe(DEFAULT_KDF_PARAMS_JSON);
  }, 60_000);

  it("produces a recovery code that actually opens the vault", async () => {
    const { api, bodies } = recordingApi();
    const session = createSession();

    const { recoveryCode } = await enroll({ api, session }, INPUT);
    const body = bodies.get("/api/enroll") as EnrolBody;

    // The recovery code matters on exactly one day: the day the master password
    // is gone. A blob that does not open is a promise this product cannot keep,
    // and nothing else would discover it until then.
    const recovered = await recoverUserKey(
      body.recoveryProtectedUserKey,
      recoveryCode,
      fromBase64(body.recoverySalt),
      JSON.parse(body.recoveryKdfParams) as never,
    );
    expect(Array.from(recovered)).toEqual(
      Array.from(session.getKeys().userKey),
    );
  }, 60_000);

  it("never uploads the user key or the private key", async () => {
    const { api, bodies } = recordingApi();
    const session = createSession();

    await enroll({ api, session }, INPUT);

    const dump = JSON.stringify(bodies.get("/api/enroll"));
    const keys = session.getKeys();
    // Uploading either would hand the server the ability to decrypt everything,
    // which is the one thing this whole design exists to prevent.
    expect(dump).not.toContain(Array.from(keys.userKey).join(","));
    expect(dump).not.toContain(Array.from(keys.privateKey).join(","));
  }, 60_000);

  it("leaves the vault unlocked without a second password prompt", async () => {
    const { api } = recordingApi();
    const session = createSession();

    await enroll({ api, session }, INPUT);

    // enrollUser already returned the authHash, so the follow-up login needs no
    // prelogin and no second Argon2id pass. Asking someone to log in again
    // moments after setting a password would be a self-inflicted wound.
    expect(session.isUnlocked).toBe(true);
    expect(session.getAccessToken()).toBe("access");
  }, 60_000);
});
```

- [ ] **Step 2: Run and watch it fail**

```bash
pnpm --filter @keyhole/web test -t enroll
```

Expected: FAIL — `Cannot find module './enroll.js'`.

- [ ] **Step 3: Implement enrolment**

Create `apps/web/src/vault/enroll.ts`:

```ts
import {
  DEFAULT_KDF_PARAMS,
  DEFAULT_KDF_PARAMS_JSON,
  createRecoveryBlob,
  enrollUser,
  generateRecoveryCode,
  toBase64,
} from "@keyhole/crypto";
import type { ApiClient } from "./api.js";
import { rememberEmail, type Session, type SessionUser } from "./session.js";

export interface EnrolmentOutcome {
  /** Shown exactly once. It cannot be recovered afterwards — not by an admin,
   *  not by anyone holding the database. */
  recoveryCode: string;
}

interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  protectedUserKey: string;
  encryptedPrivateKey: string;
  user: SessionUser;
}

/**
 * Everything that happens when someone sets a master password for the first
 * time.
 *
 * POST /api/enroll/:token returns only {id, email, name, role} — deliberately,
 * per its own comment: "never echo key material, not even the caller's own". So
 * a login follows. But enrollUser already produced the authHash, so that login
 * needs no prelogin and no second Argon2id pass; the whole flow costs one
 * derivation.
 */
export async function enroll(
  deps: { api: ApiClient; session: Session },
  input: {
    inviteToken: string;
    email: string;
    masterPassword: string;
    deviceLabel: string;
  },
): Promise<EnrolmentOutcome> {
  const enrolled = await enrollUser(input.masterPassword, DEFAULT_KDF_PARAMS);
  const recoveryCode = generateRecoveryCode();
  const recovery = await createRecoveryBlob(
    enrolled.userKey,
    recoveryCode,
    DEFAULT_KDF_PARAMS,
  );

  await deps.api.post(`/api/enroll/${encodeURIComponent(input.inviteToken)}`, {
    kdfSalt: toBase64(enrolled.kdfSalt),
    // The pinned constant, verbatim. Never JSON.stringify an object into this
    // field: key order is part of the contract and the server compares bytes.
    params: DEFAULT_KDF_PARAMS_JSON,
    authHash: toBase64(enrolled.authHash),
    protectedUserKey: enrolled.protectedUserKey,
    publicKey: toBase64(enrolled.publicKey),
    encryptedPrivateKey: enrolled.encryptedPrivateKey,
    recoverySalt: toBase64(recovery.recoverySalt),
    recoveryProtectedUserKey: recovery.recoveryProtectedUserKey,
    // NOT pinned: no endpoint returns it, so it leaks nothing, and recording
    // the params the blob was actually made under is what keeps a correct
    // recovery code from failing later — at the moment it is the last resort.
    recoveryKdfParams: JSON.stringify(recovery.params),
  });

  const login = await deps.api.post<LoginResponse>("/api/auth/login", {
    email: input.email,
    authHash: toBase64(enrolled.authHash),
    deviceLabel: input.deviceLabel,
  });

  deps.session.open({
    tokens: {
      accessToken: login.accessToken,
      refreshToken: login.refreshToken,
    },
    user: login.user,
    // These are the objects enrollUser produced. The keys never left memory and
    // were never round-tripped through the server.
    userKey: enrolled.userKey,
    privateKey: enrolled.keyPair.privateKey,
  });
  rememberEmail(input.email);

  return { recoveryCode };
}
```

- [ ] **Step 4: Run the tests**

```bash
pnpm --filter @keyhole/web test -t enroll
```

Expected: PASS, all four.

- [ ] **Step 5: Prove the pinning test can fail**

In `enroll.ts`, temporarily send a stringified object instead of the constant:

```ts
    params: JSON.stringify({ ...DEFAULT_KDF_PARAMS, iterations: 4 }),
```

Run: `pnpm --filter @keyhole/web test -t "byte for byte"`

Expected: FAIL, printing both strings. Revert and confirm PASS. This is the
client half of the enumeration defence closed in Plan 2b Task 6; record both.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/vault/enroll.ts apps/web/src/vault/enroll.test.ts
git commit -m "feat(web): enrolment, with a recovery code proven to open the vault"
```

---

## Task 5: Items and the vault store

**Files:**
- Create: `apps/web/src/vault/items.ts`, `apps/web/src/vault/store.ts`
- Test: `apps/web/src/vault/items.test.ts`, `apps/web/src/vault/store.test.ts`

**Interfaces:**
- Consumes: `ApiClient`, `ApiError` (Task 1); `Session` (Task 2);
  `encryptItem`, `decryptItem`, type `ItemPlaintext`, type `LoginItem`,
  type `NoteItem` from `@keyhole/crypto`.
- Produces:
  ```ts
  // items.ts
  export interface ItemRecord {
    id: string;
    revision: number;
    collectionId: string | null;
    deletedAt: string | null;
    /** null when this row could not be decrypted. */
    plaintext: ItemPlaintext | null;
  }
  export interface WireItem {
    id: string; collectionId: string | null; ownerUserId: string;
    ciphertext: string; wrappedItemKey: string; revision: number;
    createdAt: string; updatedAt: string; deletedAt: string | null;
  }
  export class ItemConflictError extends Error {
    readonly current: WireItem;
  }
  export async function decryptRecords(
    wire: WireItem[], userKey: Uint8Array,
  ): Promise<ItemRecord[]>;
  export async function createItem(
    deps: { api: ApiClient; session: Session }, plaintext: ItemPlaintext,
  ): Promise<ItemRecord>;
  export async function updateItem(
    deps: { api: ApiClient; session: Session },
    id: string, revision: number, plaintext: ItemPlaintext,
  ): Promise<ItemRecord>;
  export async function deleteItem(
    deps: { api: ApiClient; session: Session }, id: string,
  ): Promise<void>;

  // store.ts
  export interface VaultState {
    revision: number;
    items: ItemRecord[];
    status: "empty" | "loading" | "ready" | "error";
    error: string | null;
  }
  export interface VaultStore {
    getState(): VaultState;
    subscribe(listener: () => void): () => void;
    load(deps: { api: ApiClient; session: Session }): Promise<void>;
    resync(deps: { api: ApiClient; session: Session }): Promise<void>;
    upsert(record: ItemRecord): void;
    remove(id: string): void;
    clear(): void;
  }
  export function createVaultStore(): VaultStore;
  ```

- [ ] **Step 1: Write the failing item tests**

Create `apps/web/src/vault/items.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { encryptItem, generateUserKey, type LoginItem } from "@keyhole/crypto";
import { ApiError, type ApiClient } from "./api.js";
import { createSession } from "./session.js";
import {
  ItemConflictError,
  createItem,
  decryptRecords,
  updateItem,
  type WireItem,
} from "./items.js";

const LOGIN: LoginItem = {
  type: "login",
  name: "Example",
  username: "person@example.com",
  password: "hunter2",
  urls: ["https://example.com"],
  notes: "",
  favorite: false,
  folderId: null,
  passwordHistory: [],
};

function wire(overrides: Partial<WireItem> = {}): WireItem {
  return {
    id: "i1",
    collectionId: null,
    ownerUserId: "u1",
    ciphertext: "",
    wrappedItemKey: "",
    revision: 1,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    deletedAt: null,
    ...overrides,
  };
}

function sessionWith(userKey: Uint8Array) {
  const session = createSession();
  session.open({
    tokens: { accessToken: "a", refreshToken: "r" },
    user: { id: "u1", email: "a@b.c", name: "A", role: "user" },
    userKey,
    privateKey: new Uint8Array(32),
  });
  return session;
}

describe("decryptRecords", () => {
  it("decrypts what it can", async () => {
    const userKey = generateUserKey();
    const encrypted = await encryptItem(LOGIN, userKey);
    const records = await decryptRecords(
      [wire({ ciphertext: encrypted.ciphertext, wrappedItemKey: encrypted.wrappedItemKey })],
      userKey,
    );

    expect(records).toHaveLength(1);
    expect(records[0]?.plaintext).toEqual(LOGIN);
  });

  it("survives one undecryptable row without failing the vault", async () => {
    const userKey = generateUserKey();
    const good = await encryptItem(LOGIN, userKey);

    const records = await decryptRecords(
      [
        wire({ id: "bad", ciphertext: "not-ciphertext", wrappedItemKey: "junk" }),
        wire({ id: "good", ciphertext: good.ciphertext, wrappedItemKey: good.wrappedItemKey }),
      ],
      userKey,
    );

    // One corrupt blob making every password unreachable is a far worse failure
    // than one visibly broken row. The UI renders plaintext === null as
    // "couldn't decrypt" and carries on.
    expect(records).toHaveLength(2);
    expect(records.find((r) => r.id === "bad")?.plaintext).toBeNull();
    expect(records.find((r) => r.id === "good")?.plaintext).toEqual(LOGIN);
  });

  it("skips tombstones rather than trying to decrypt an emptied row", async () => {
    // DeleteItem blanks ciphertext and wrapped_item_key, so a tombstone has
    // nothing to decrypt and must not be reported as a decryption failure.
    const records = await decryptRecords(
      [wire({ deletedAt: "2026-01-02T00:00:00Z" })],
      generateUserKey(),
    );
    expect(records[0]?.plaintext).toBeNull();
    expect(records[0]?.deletedAt).not.toBeNull();
  });
});

describe("createItem and updateItem", () => {
  it("uploads ciphertext and never plaintext", async () => {
    const userKey = generateUserKey();
    let sent: unknown = null;
    const api: ApiClient = {
      async get<T>(): Promise<T> {
        throw new Error("unexpected");
      },
      async post<T>(_path: string, body?: unknown): Promise<T> {
        sent = body;
        const b = body as { ciphertext: string; wrappedItemKey: string };
        return wire({ ciphertext: b.ciphertext, wrappedItemKey: b.wrappedItemKey }) as T;
      },
      async put<T>(): Promise<T> {
        throw new Error("unexpected");
      },
      async del<T>(): Promise<T> {
        throw new Error("unexpected");
      },
    };

    await createItem({ api, session: sessionWith(userKey) }, LOGIN);

    const dump = JSON.stringify(sent);
    // The server stores an opaque string. If any of these appear, the vault is
    // not end-to-end encrypted and every other guarantee is decoration.
    expect(dump).not.toContain("hunter2");
    expect(dump).not.toContain("person@example.com");
    expect(dump).not.toContain("Example");
  });

  it("raises a typed conflict carrying the winning copy", async () => {
    const userKey = generateUserKey();
    const winner = wire({ revision: 9, ciphertext: "theirs" });
    const api: ApiClient = {
      async get<T>(): Promise<T> {
        throw new Error("unexpected");
      },
      async post<T>(): Promise<T> {
        throw new Error("unexpected");
      },
      async put<T>(): Promise<T> {
        throw new ApiError("conflict", 409, "changed", {
          error: { code: "conflict", message: "changed" },
          item: winner,
        });
      },
      async del<T>(): Promise<T> {
        throw new Error("unexpected");
      },
    };

    const error = (await updateItem(
      { api, session: sessionWith(userKey) },
      "i1",
      1,
      LOGIN,
    ).catch((e: unknown) => e)) as ItemConflictError;

    // Without the winning row the client has nothing to reconcile against and
    // its only option is to discard one of the two edits — the data loss design
    // spec 9 forbids.
    expect(error).toBeInstanceOf(ItemConflictError);
    expect(error.current.revision).toBe(9);
  });
});
```

- [ ] **Step 2: Run and watch it fail**

```bash
pnpm --filter @keyhole/web test -t decryptRecords
```

Expected: FAIL — `Cannot find module './items.js'`.

- [ ] **Step 3: Implement items**

Create `apps/web/src/vault/items.ts`:

```ts
import {
  decryptItem,
  encryptItem,
  type ItemPlaintext,
} from "@keyhole/crypto";
import { ApiError, type ApiClient } from "./api.js";
import type { Session } from "./session.js";

/** The server's wire shape for an item. Every field is opaque to it. */
export interface WireItem {
  id: string;
  collectionId: string | null;
  ownerUserId: string;
  ciphertext: string;
  wrappedItemKey: string;
  revision: number;
  createdAt: string;
  updatedAt: string;
  deletedAt: string | null;
}

/** A wire item after this client tried to open it. */
export interface ItemRecord {
  id: string;
  revision: number;
  collectionId: string | null;
  deletedAt: string | null;
  /** null when the row is a tombstone, or when decryption failed. */
  plaintext: ItemPlaintext | null;
}

export class ItemConflictError extends Error {
  readonly current: WireItem;
  constructor(current: WireItem) {
    super("This item changed on the server since you last synced");
    this.name = "ItemConflictError";
    this.current = current;
  }
}

function toRecord(item: WireItem, plaintext: ItemPlaintext | null): ItemRecord {
  return {
    id: item.id,
    revision: item.revision,
    collectionId: item.collectionId,
    deletedAt: item.deletedAt,
    plaintext,
  };
}

/**
 * Decrypts a batch, one row at a time, and never lets one failure sink the rest.
 *
 * A corrupt or unopenable blob is a bad row; it is not a bad vault. Throwing
 * here would turn one damaged item into a password manager that shows nothing
 * at all, which is the worse failure by a wide margin.
 */
export async function decryptRecords(
  wire: WireItem[],
  userKey: Uint8Array,
): Promise<ItemRecord[]> {
  const records: ItemRecord[] = [];
  for (const item of wire) {
    // A tombstone has had its ciphertext and wrapped key blanked by the server,
    // so there is nothing to open and nothing to report as a failure.
    if (item.deletedAt !== null) {
      records.push(toRecord(item, null));
      continue;
    }
    try {
      const plaintext = await decryptItem(
        { ciphertext: item.ciphertext, wrappedItemKey: item.wrappedItemKey },
        userKey,
      );
      records.push(toRecord(item, plaintext));
    } catch {
      records.push(toRecord(item, null));
    }
  }
  return records;
}

export async function createItem(
  deps: { api: ApiClient; session: Session },
  plaintext: ItemPlaintext,
): Promise<ItemRecord> {
  const { userKey } = deps.session.getKeys();
  const encrypted = await encryptItem(plaintext, userKey);
  const created = await deps.api.post<WireItem>("/api/items", {
    ciphertext: encrypted.ciphertext,
    wrappedItemKey: encrypted.wrappedItemKey,
  });
  // The plaintext is already in hand — decrypting the echo would be work to
  // learn something we just encrypted.
  return toRecord(created, plaintext);
}

export async function updateItem(
  deps: { api: ApiClient; session: Session },
  id: string,
  revision: number,
  plaintext: ItemPlaintext,
): Promise<ItemRecord> {
  const { userKey } = deps.session.getKeys();
  const encrypted = await encryptItem(plaintext, userKey);
  try {
    const updated = await deps.api.put<WireItem>(`/api/items/${id}`, {
      ciphertext: encrypted.ciphertext,
      wrappedItemKey: encrypted.wrappedItemKey,
      revision,
    });
    return toRecord(updated, plaintext);
  } catch (error) {
    if (error instanceof ApiError && error.code === "conflict") {
      const body = error.body as { item?: WireItem };
      if (body.item !== undefined) {
        throw new ItemConflictError(body.item);
      }
    }
    throw error;
  }
}

export async function deleteItem(
  deps: { api: ApiClient; session: Session },
  id: string,
): Promise<void> {
  await deps.api.del(`/api/items/${id}`);
}
```

- [ ] **Step 4: Write the failing store tests**

Create `apps/web/src/vault/store.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { encryptItem, generateUserKey, type LoginItem } from "@keyhole/crypto";
import type { ApiClient } from "./api.js";
import { createSession } from "./session.js";
import { createVaultStore } from "./store.js";
import type { WireItem } from "./items.js";

const LOGIN: LoginItem = {
  type: "login",
  name: "Example",
  username: "u",
  password: "p",
  urls: [],
  notes: "",
  favorite: false,
  folderId: null,
  passwordHistory: [],
};

function sessionWith(userKey: Uint8Array) {
  const session = createSession();
  session.open({
    tokens: { accessToken: "a", refreshToken: "r" },
    user: { id: "u1", email: "a@b.c", name: "A", role: "user" },
    userKey,
    privateKey: new Uint8Array(32),
  });
  return session;
}

function syncApi(pages: Record<string, unknown>): ApiClient {
  return {
    async get<T>(path: string): Promise<T> {
      const body = pages[path];
      if (body === undefined) throw new Error(`no stub for ${path}`);
      return body as T;
    },
    async post<T>(): Promise<T> {
      throw new Error("unexpected");
    },
    async put<T>(): Promise<T> {
      throw new Error("unexpected");
    },
    async del<T>(): Promise<T> {
      throw new Error("unexpected");
    },
  };
}

describe("vault store", () => {
  it("loads, decrypts, and records the cursor", async () => {
    const userKey = generateUserKey();
    const encrypted = await encryptItem(LOGIN, userKey);
    const item: WireItem = {
      id: "i1",
      collectionId: null,
      ownerUserId: "u1",
      ciphertext: encrypted.ciphertext,
      wrappedItemKey: encrypted.wrappedItemKey,
      revision: 4,
      createdAt: "2026-01-01T00:00:00Z",
      updatedAt: "2026-01-01T00:00:00Z",
      deletedAt: null,
    };
    const api = syncApi({ "/api/sync": { revision: 4, items: [item], folders: [], collections: [] } });
    const store = createVaultStore();

    await store.load({ api, session: sessionWith(userKey) });

    expect(store.getState().status).toBe("ready");
    expect(store.getState().revision).toBe(4);
    expect(store.getState().items[0]?.plaintext).toEqual(LOGIN);
  });

  it("re-syncs from the cursor and drops tombstoned rows", async () => {
    const userKey = generateUserKey();
    const encrypted = await encryptItem(LOGIN, userKey);
    const base: WireItem = {
      id: "i1",
      collectionId: null,
      ownerUserId: "u1",
      ciphertext: encrypted.ciphertext,
      wrappedItemKey: encrypted.wrappedItemKey,
      revision: 4,
      createdAt: "2026-01-01T00:00:00Z",
      updatedAt: "2026-01-01T00:00:00Z",
      deletedAt: null,
    };
    const api = syncApi({
      "/api/sync": { revision: 4, items: [base], folders: [], collections: [] },
      "/api/sync?since=4": {
        revision: 5,
        // The server blanks ciphertext on delete; the tombstone is an id and a
        // revision, which is exactly enough to remove the row here.
        items: [{ ...base, revision: 5, deletedAt: "2026-01-02T00:00:00Z", ciphertext: "", wrappedItemKey: "" }],
        folders: [],
        collections: [],
      },
    });
    const store = createVaultStore();
    const session = sessionWith(userKey);

    await store.load({ api, session });
    expect(store.getState().items).toHaveLength(1);

    await store.resync({ api, session });

    // A delete on another device has to reach this one, or the item lingers
    // forever on a screen its owner believes is empty.
    expect(store.getState().items).toHaveLength(0);
    expect(store.getState().revision).toBe(5);
  });

  it("notifies subscribers and clears on lock", async () => {
    const store = createVaultStore();
    let calls = 0;
    store.subscribe(() => {
      calls += 1;
    });

    store.upsert({ id: "x", revision: 1, collectionId: null, deletedAt: null, plaintext: LOGIN });
    expect(store.getState().items).toHaveLength(1);
    expect(calls).toBeGreaterThan(0);

    store.clear();
    // Plaintext must not outlive the unlocked session — this is the store half
    // of the memory-only rule.
    expect(store.getState().items).toHaveLength(0);
    expect(store.getState().status).toBe("empty");
  });
});
```

- [ ] **Step 5: Implement the store**

Create `apps/web/src/vault/store.ts`:

```ts
import type { ApiClient } from "./api.js";
import type { Session } from "./session.js";
import { decryptRecords, type ItemRecord, type WireItem } from "./items.js";

/**
 * The in-memory vault for one unlocked session.
 *
 * This is the one module that holds decrypted plaintext, which is a deliberate
 * and bounded concession: a vault list has to render names. Its lifetime is tied
 * to `clear()`, which the UI calls whenever the session locks.
 *
 * Deliberately hand-rolled rather than a state library. TanStack Query's
 * devtools serialise cache contents and its persist plugin writes to storage —
 * the two behaviours design spec 6.3 forbids, shipped as headline features.
 */
export interface VaultState {
  revision: number;
  items: ItemRecord[];
  status: "empty" | "loading" | "ready" | "error";
  error: string | null;
}

interface SyncResponse {
  revision: number;
  items: WireItem[];
}

export interface VaultStore {
  getState(): VaultState;
  subscribe(listener: () => void): () => void;
  load(deps: { api: ApiClient; session: Session }): Promise<void>;
  resync(deps: { api: ApiClient; session: Session }): Promise<void>;
  upsert(record: ItemRecord): void;
  remove(id: string): void;
  clear(): void;
}

const EMPTY: VaultState = { revision: 0, items: [], status: "empty", error: null };

export function createVaultStore(): VaultStore {
  let state: VaultState = EMPTY;
  const listeners = new Set<() => void>();

  const set = (next: Partial<VaultState>): void => {
    // A new object every time: useSyncExternalStore compares by identity, and
    // mutating in place would render nothing.
    state = { ...state, ...next };
    for (const listener of listeners) listener();
  };

  const merge = (existing: ItemRecord[], incoming: ItemRecord[]): ItemRecord[] => {
    const byId = new Map(existing.map((item) => [item.id, item]));
    for (const item of incoming) {
      if (item.deletedAt !== null) {
        byId.delete(item.id);
      } else {
        byId.set(item.id, item);
      }
    }
    return [...byId.values()];
  };

  async function fetchInto(
    deps: { api: ApiClient; session: Session },
    since: number | null,
  ): Promise<void> {
    const path = since === null ? "/api/sync" : `/api/sync?since=${since}`;
    try {
      const response = await deps.api.get<SyncResponse>(path);
      const records = await decryptRecords(
        response.items,
        deps.session.getKeys().userKey,
      );
      set({
        revision: response.revision,
        items: since === null ? merge([], records) : merge(state.items, records),
        status: "ready",
        error: null,
      });
    } catch (error) {
      set({
        status: "error",
        error: error instanceof Error ? error.message : "Could not sync",
      });
      throw error;
    }
  }

  return {
    getState: () => state,
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    async load(deps) {
      set({ status: "loading", error: null });
      await fetchInto(deps, null);
    },
    async resync(deps) {
      await fetchInto(deps, state.revision);
    },
    upsert(record) {
      set({ items: merge(state.items, [record]), status: "ready" });
    },
    remove(id) {
      set({ items: state.items.filter((item) => item.id !== id) });
    },
    clear() {
      state = EMPTY;
      for (const listener of listeners) listener();
    },
  };
}
```

- [ ] **Step 6: Run the tests**

```bash
pnpm --filter @keyhole/web test -t "decryptRecords|createItem|vault store"
```

Expected: PASS, all eight.

- [ ] **Step 7: Prove the per-row isolation is load-bearing**

In `items.ts`, temporarily let a decryption failure escape:

```ts
      const plaintext = await decryptItem(/* … */);
      records.push(toRecord(item, plaintext));
      // (delete the catch block)
```

Run: `pnpm --filter @keyhole/web test -t "survives one undecryptable row"`

Expected: FAIL — the whole batch rejects, which in the UI is an empty password
manager. Revert and confirm PASS. Record both.

- [ ] **Step 8: Commit**

```bash
git add apps/web/src/vault/items.ts apps/web/src/vault/items.test.ts \
        apps/web/src/vault/store.ts apps/web/src/vault/store.test.ts
git commit -m "feat(web): item encryption, conflict handling, and the vault store"
```

---

## Task 6: Password generator

**Files:**
- Create: `apps/web/src/vault/generator.ts`
- Test: `apps/web/src/vault/generator.test.ts`

**Interfaces:**
- Consumes: `randomBytes` from `@keyhole/crypto`.
- Produces:
  ```ts
  export interface GeneratorOptions {
    length: number; lowercase: boolean; uppercase: boolean;
    digits: boolean; symbols: boolean;
  }
  export const DEFAULT_GENERATOR_OPTIONS: GeneratorOptions;
  export function generatePassword(options?: Partial<GeneratorOptions>): string;
  ```

- [ ] **Step 1: Write the failing generator tests**

Create `apps/web/src/vault/generator.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { DEFAULT_GENERATOR_OPTIONS, generatePassword } from "./generator.js";

describe("generatePassword", () => {
  it("honours the requested length", () => {
    for (const length of [8, 20, 64, 128]) {
      expect(generatePassword({ length })).toHaveLength(length);
    }
  });

  it("uses only the enabled character classes", () => {
    const digitsOnly = generatePassword({
      length: 200,
      lowercase: false,
      uppercase: false,
      digits: true,
      symbols: false,
    });
    expect(digitsOnly).toMatch(/^[0-9]+$/);
  });

  it("includes at least one character from every enabled class", () => {
    // A generator that merely samples the union will, often enough to matter,
    // emit a "symbols on" password with no symbol — which fails the site's own
    // policy check and reads to the user as the generator being broken.
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const password = generatePassword({ length: 8 });
      expect(password).toMatch(/[a-z]/);
      expect(password).toMatch(/[A-Z]/);
      expect(password).toMatch(/[0-9]/);
      expect(password).toMatch(/[^a-zA-Z0-9]/);
    }
  });

  it("does not repeat itself", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 100; i += 1) seen.add(generatePassword());
    // 100 collisions-free draws at the default length is not proof of entropy,
    // but a stuck or seeded generator fails it immediately.
    expect(seen.size).toBe(100);
  });

  it("refuses a length shorter than the number of enabled classes", () => {
    // Four classes cannot each appear in three characters. Silently returning
    // three would break the guarantee the test above depends on.
    expect(() => generatePassword({ length: 3 })).toThrow();
  });

  it("refuses when every class is disabled", () => {
    expect(() =>
      generatePassword({
        lowercase: false,
        uppercase: false,
        digits: false,
        symbols: false,
      }),
    ).toThrow();
  });

  it("defaults to a length and classes worth having", () => {
    expect(DEFAULT_GENERATOR_OPTIONS.length).toBeGreaterThanOrEqual(16);
    expect(DEFAULT_GENERATOR_OPTIONS.lowercase).toBe(true);
    expect(DEFAULT_GENERATOR_OPTIONS.uppercase).toBe(true);
    expect(DEFAULT_GENERATOR_OPTIONS.digits).toBe(true);
    expect(DEFAULT_GENERATOR_OPTIONS.symbols).toBe(true);
  });
});
```

- [ ] **Step 2: Run and watch it fail**

```bash
pnpm --filter @keyhole/web test -t generatePassword
```

Expected: FAIL — `Cannot find module './generator.js'`.

- [ ] **Step 3: Implement the generator**

Create `apps/web/src/vault/generator.ts`:

```ts
import { randomBytes } from "@keyhole/crypto";

export interface GeneratorOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
}

export const DEFAULT_GENERATOR_OPTIONS: GeneratorOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
};

const CLASSES = {
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  // No quotes or backslashes: they are the characters most likely to be mangled
  // by a shell, a CSV export, or a site's own escaping.
  symbols: "!#$%&()*+,-.:;<=>?@[]^_{|}~",
} as const;

/**
 * Draws an index below `limit` without modulo bias.
 *
 * Taking `byte % limit` skews toward the low end whenever 256 is not a multiple
 * of limit, which is every alphabet here. Rejection sampling costs a handful of
 * extra bytes and removes the skew entirely.
 */
function randomIndex(limit: number): number {
  const ceiling = Math.floor(256 / limit) * limit;
  for (;;) {
    const byte = randomBytes(1)[0] as number;
    if (byte < ceiling) return byte % limit;
  }
}

function pick(alphabet: string): string {
  return alphabet.charAt(randomIndex(alphabet.length));
}

export function generatePassword(options: Partial<GeneratorOptions> = {}): string {
  const settings: GeneratorOptions = { ...DEFAULT_GENERATOR_OPTIONS, ...options };

  const enabled: string[] = [];
  if (settings.lowercase) enabled.push(CLASSES.lowercase);
  if (settings.uppercase) enabled.push(CLASSES.uppercase);
  if (settings.digits) enabled.push(CLASSES.digits);
  if (settings.symbols) enabled.push(CLASSES.symbols);

  if (enabled.length === 0) {
    throw new Error("At least one character class must be enabled");
  }
  if (settings.length < enabled.length) {
    // Returning a shorter password, or one missing a class, would quietly break
    // the guarantee callers rely on to satisfy a site's password policy.
    throw new Error(
      `Length must be at least ${enabled.length} to include every enabled class`,
    );
  }

  // One from each class first, so "symbols on" always means a symbol is present.
  const characters = enabled.map((alphabet) => pick(alphabet));
  const union = enabled.join("");
  while (characters.length < settings.length) {
    characters.push(pick(union));
  }

  // Fisher-Yates, or the guaranteed characters would always sit at the front in
  // a fixed class order — a pattern worth nothing to an attacker but obvious to
  // a user, and a real weakness if anyone ever truncated the output.
  for (let i = characters.length - 1; i > 0; i -= 1) {
    const j = randomIndex(i + 1);
    const a = characters[i] as string;
    const b = characters[j] as string;
    characters[i] = b;
    characters[j] = a;
  }
  return characters.join("");
}
```

Note the swap is written with two temporaries rather than destructuring —
`noUncheckedIndexedAccess` types an indexed read as `string | undefined`, so
`[a[i], a[j]] = [a[j], a[i]]` does not typecheck.

- [ ] **Step 4: Run the tests**

```bash
pnpm --filter @keyhole/web test -t generatePassword
```

Expected: PASS, all seven.

- [ ] **Step 5: Prove the class guarantee is load-bearing**

In `generator.ts`, temporarily replace the guaranteed-characters block with a
plain sample of the union:

```ts
  const characters: string[] = [];
  const union = enabled.join("");
  while (characters.length < settings.length) characters.push(pick(union));
```

Run: `pnpm --filter @keyhole/web test -t "at least one character"`

Expected: FAIL within the 40 attempts — an 8-character draw from 89 symbols
misses a class often. Revert and confirm PASS. Record both, including how many
attempts it took: that number is the answer to "would a single-draw test have
caught this?" (it would not).

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/vault/generator.ts apps/web/src/vault/generator.test.ts
git commit -m "feat(web): password generator with unbiased sampling"
```

---

## Task 7: The React shell — boot, unlock, and enrolment

**Files:**
- Create: `apps/web/src/ui/tokens.css`, `apps/web/src/ui/App.tsx`,
  `apps/web/src/ui/useVault.ts`, `apps/web/src/ui/components/Field.tsx`,
  `apps/web/src/ui/components/Button.tsx`,
  `apps/web/src/ui/screens/UnlockScreen.tsx`,
  `apps/web/src/ui/screens/EnrolScreen.tsx`, `apps/web/src/main.tsx`
- Test: `apps/web/src/ui/App.test.tsx`,
  `apps/web/src/ui/screens/UnlockScreen.test.tsx`,
  `apps/web/src/ui/screens/EnrolScreen.test.tsx`

**Interfaces:**
- Consumes: everything from Tasks 1–6.
- Produces:
  ```ts
  export function inviteTokenFromPath(pathname: string): string | null;
  export interface VaultContextValue {
    api: ApiClient; session: Session; store: VaultStore;
  }
  export function useSession(session: Session): { isUnlocked: boolean; user: SessionUser | null };
  export function useVaultState(store: VaultStore): VaultState;
  ```

- [ ] **Step 1: Write the failing boot-path test**

Create `apps/web/src/ui/App.test.tsx`:

```tsx
import { describe, expect, it } from "vitest";
import { inviteTokenFromPath } from "./App.js";

describe("inviteTokenFromPath", () => {
  it("extracts the token from a setup link", () => {
    // This is the shape keyhole admin create prints, so it is the shape a real
    // invite arrives in.
    expect(inviteTokenFromPath("/enroll/bgeu3hr9bRZJ6tHrG9iPcrOeInVFkZHiQvM")).toBe(
      "bgeu3hr9bRZJ6tHrG9iPcrOeInVFkZHiQvM",
    );
  });

  it("decodes a percent-encoded token", () => {
    expect(inviteTokenFromPath("/enroll/a%2Fb")).toBe("a/b");
  });

  it("returns null for every other path", () => {
    for (const path of ["/", "/vault", "/enroll", "/enroll/", "/enroll/a/b"]) {
      expect(inviteTokenFromPath(path)).toBeNull();
    }
  });
});
```

- [ ] **Step 2: Write the failing unlock-screen tests**

Create `apps/web/src/ui/screens/UnlockScreen.test.tsx`:

```tsx
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { UnlockScreen } from "./UnlockScreen.js";

describe("UnlockScreen", () => {
  it("asks for an email when none is remembered", () => {
    render(<UnlockScreen rememberedEmail={null} onUnlock={vi.fn()} />);
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/master password/i)).toBeInTheDocument();
  });

  it("asks only for the password when an email is remembered", () => {
    render(<UnlockScreen rememberedEmail="a@b.c" onUnlock={vi.fn()} />);
    // The whole benefit of persisting the email is this screen.
    expect(screen.queryByLabelText(/email/i)).not.toBeInTheDocument();
    expect(screen.getByText("a@b.c")).toBeInTheDocument();
  });

  it("shows a wrong-password message that does not blame the network", async () => {
    const onUnlock = vi.fn().mockRejectedValue(new Error("Wrong master password"));
    render(<UnlockScreen rememberedEmail="a@b.c" onUnlock={onUnlock} />);

    await userEvent.type(screen.getByLabelText(/master password/i), "nope");
    await userEvent.click(screen.getByRole("button", { name: /unlock/i }));

    // Design spec 9 requires these to read differently. A user who mistypes a
    // password and is told the server is unreachable will go looking in
    // entirely the wrong place.
    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/wrong master password/i);
    });
  });

  it("disables the button while unlocking so one press is one attempt", async () => {
    let release: (() => void) | undefined;
    const onUnlock = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    render(<UnlockScreen rememberedEmail="a@b.c" onUnlock={onUnlock} />);

    await userEvent.type(screen.getByLabelText(/master password/i), "pw");
    await userEvent.click(screen.getByRole("button", { name: /unlock/i }));

    // Argon2id takes about a second. Without this, an impatient double-click
    // spends two of the five free login attempts before the rate limiter starts
    // adding delay.
    expect(screen.getByRole("button", { name: /unlocking/i })).toBeDisabled();
    release?.();
    await waitFor(() => expect(onUnlock).toHaveBeenCalledOnce());
  });
});
```

- [ ] **Step 3: Write the failing enrolment-screen tests**

Create `apps/web/src/ui/screens/EnrolScreen.test.tsx`:

```tsx
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { EnrolScreen } from "./EnrolScreen.js";

describe("EnrolScreen", () => {
  it("refuses to submit when the confirmation does not match", async () => {
    const onEnrol = vi.fn();
    render(<EnrolScreen inviteToken="tok" onEnrol={onEnrol} onFinish={vi.fn()} />);

    await userEvent.type(screen.getByLabelText(/email/i), "a@b.c");
    await userEvent.type(screen.getByLabelText(/^master password/i), "correct horse");
    await userEvent.type(screen.getByLabelText(/confirm/i), "corrent horse");
    await userEvent.click(screen.getByRole("button", { name: /set master password/i }));

    // A typo here is unrecoverable: the vault would be encrypted under a
    // password nobody knows, and the server cannot help by design.
    expect(onEnrol).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(/do not match/i);
  });

  it("shows the recovery code and will not continue until it is acknowledged", async () => {
    const onEnrol = vi.fn().mockResolvedValue({ recoveryCode: "ABCD-EFGH-IJKL" });
    const onFinish = vi.fn();
    render(<EnrolScreen inviteToken="tok" onEnrol={onEnrol} onFinish={onFinish} />);

    await userEvent.type(screen.getByLabelText(/email/i), "a@b.c");
    await userEvent.type(screen.getByLabelText(/^master password/i), "correct horse");
    await userEvent.type(screen.getByLabelText(/confirm/i), "correct horse");
    await userEvent.click(screen.getByRole("button", { name: /set master password/i }));

    await waitFor(() => {
      expect(screen.getByText("ABCD-EFGH-IJKL")).toBeInTheDocument();
    });

    // The code cannot be recovered afterwards by anyone. Letting the user click
    // past it is handing them a vault with no second way in, silently.
    const continueButton = screen.getByRole("button", { name: /continue/i });
    expect(continueButton).toBeDisabled();

    await userEvent.click(screen.getByLabelText(/saved/i));
    expect(continueButton).toBeEnabled();
    await userEvent.click(continueButton);
    expect(onFinish).toHaveBeenCalledOnce();
  });

  it("never shows the recovery code again after it is acknowledged", async () => {
    const onEnrol = vi.fn().mockResolvedValue({ recoveryCode: "ABCD-EFGH-IJKL" });
    render(<EnrolScreen inviteToken="tok" onEnrol={onEnrol} onFinish={vi.fn()} />);

    await userEvent.type(screen.getByLabelText(/email/i), "a@b.c");
    await userEvent.type(screen.getByLabelText(/^master password/i), "pw");
    await userEvent.type(screen.getByLabelText(/confirm/i), "pw");
    await userEvent.click(screen.getByRole("button", { name: /set master password/i }));
    await waitFor(() => screen.getByText("ABCD-EFGH-IJKL"));

    await userEvent.click(screen.getByLabelText(/saved/i));
    await userEvent.click(screen.getByRole("button", { name: /continue/i }));

    expect(screen.queryByText("ABCD-EFGH-IJKL")).not.toBeInTheDocument();
  });
});
```

- [ ] **Step 4: Run and watch them fail**

```bash
pnpm --filter @keyhole/web test -t "inviteTokenFromPath|UnlockScreen|EnrolScreen"
```

Expected: FAIL — modules not found.

- [ ] **Step 5: Write the Mono tokens**

Create `apps/web/src/ui/tokens.css`:

```css
/*
 * Mono — Swiss and typographic. Design spec 6.4.
 *
 * Every value lives here so the warmth dial (paper-white ground and softer
 * rules versus pure white and black hairlines) is a token change rather than a
 * redesign. Dark is the same layout with inverted values and hairlines at 12%
 * white, not a separate theme.
 */
:root {
  --ground: #fdfdfc;
  --ink: #14140f;
  --ink-muted: #6b6b63;
  --rule: rgba(20, 20, 15, 0.14);
  --rule-strong: rgba(20, 20, 15, 0.28);
  --focus: #1f4fd8;
  /* Colour is reserved for meaning: destructive, strength, shared. */
  --danger: #a3241c;
  --strength-weak: #a3241c;
  --strength-fair: #8a6a12;
  --strength-strong: #1f6b32;

  --font-sans: ui-sans-serif, system-ui, "Helvetica Neue", Arial, sans-serif;
  --font-mono: ui-monospace, "SF Mono", "Cascadia Mono", Menlo, monospace;

  --space-1: 0.25rem;
  --space-2: 0.5rem;
  --space-3: 0.75rem;
  --space-4: 1rem;
  --space-6: 1.5rem;
  --space-8: 2rem;
}

@media (prefers-color-scheme: dark) {
  :root {
    --ground: #111110;
    --ink: #f2f2ef;
    --ink-muted: #9a9a92;
    --rule: rgba(255, 255, 255, 0.12);
    --rule-strong: rgba(255, 255, 255, 0.24);
    --focus: #7aa2ff;
    --danger: #ef6b62;
    --strength-weak: #ef6b62;
    --strength-fair: #d9b23a;
    --strength-strong: #63c07f;
  }
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: var(--ground);
  color: var(--ink);
  font-family: var(--font-sans);
  /* Mobile-first: a list of rule-separated rows is naturally a good phone
     layout, so there is no separate mobile design to maintain. */
  font-size: 16px;
  line-height: 1.5;
}

:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
}
```

- [ ] **Step 6: Implement the shared components and hooks**

Create `apps/web/src/ui/components/Button.tsx`:

```tsx
import type { ButtonHTMLAttributes, ReactNode } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  children: ReactNode;
  variant?: "primary" | "quiet" | "danger";
}

export function Button({ children, variant = "primary", ...rest }: ButtonProps) {
  return (
    <button
      {...rest}
      data-variant={variant}
      style={{
        font: "inherit",
        padding: "var(--space-2) var(--space-4)",
        border: `1px solid ${variant === "quiet" ? "var(--rule)" : "var(--rule-strong)"}`,
        background: "transparent",
        color: variant === "danger" ? "var(--danger)" : "var(--ink)",
        cursor: rest.disabled === true ? "default" : "pointer",
        opacity: rest.disabled === true ? 0.55 : 1,
      }}
    >
      {children}
    </button>
  );
}
```

Create `apps/web/src/ui/components/Field.tsx`:

```tsx
import { useId } from "react";
import type { InputHTMLAttributes } from "react";

interface FieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "id"> {
  label: string;
}

/**
 * A labelled input. The label is bound by id rather than wrapping, so screen
 * readers and Testing Library's getByLabelText agree on what this control is —
 * design spec 6.4 lists labelled form controls as a requirement, not a polish
 * pass.
 */
export function Field({ label, ...rest }: FieldProps) {
  const id = useId();
  return (
    <div style={{ display: "grid", gap: "var(--space-1)", marginBottom: "var(--space-4)" }}>
      <label htmlFor={id} style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
        {label}
      </label>
      <input
        {...rest}
        id={id}
        style={{
          font: "inherit",
          padding: "var(--space-2)",
          border: "1px solid var(--rule)",
          background: "transparent",
          color: "var(--ink)",
        }}
      />
    </div>
  );
}
```

Create `apps/web/src/ui/useVault.ts`:

```ts
import { useSyncExternalStore } from "react";
import type { Session, SessionUser } from "../vault/session.js";
import type { VaultState, VaultStore } from "../vault/store.js";

/**
 * The bridge between the framework-free core and React.
 *
 * useSyncExternalStore rather than a context holding the values: the store owns
 * its state, React only observes it, and no key material is ever placed in the
 * component tree.
 */
export function useSession(session: Session): {
  isUnlocked: boolean;
  user: SessionUser | null;
} {
  // The snapshot is a boolean, deliberately. getSnapshot must return a
  // referentially stable value between changes — returning a fresh object here
  // would give React a new identity on every call and loop forever.
  const isUnlocked = useSyncExternalStore(
    (listener) => session.subscribe(listener),
    () => session.isUnlocked,
  );
  return { isUnlocked, user: isUnlocked ? session.user : null };
}

export function useVaultState(store: VaultStore): VaultState {
  return useSyncExternalStore(
    (listener) => store.subscribe(listener),
    () => store.getState(),
  );
}
```

- [ ] **Step 7: Implement the screens and the app shell**

Create `apps/web/src/ui/screens/UnlockScreen.tsx`:

```tsx
import { useState } from "react";
import type { FormEvent } from "react";
import { Button } from "../components/Button.js";
import { Field } from "../components/Field.js";

interface UnlockScreenProps {
  rememberedEmail: string | null;
  onUnlock(input: { email: string; masterPassword: string }): Promise<void>;
}

export function UnlockScreen({ rememberedEmail, onUnlock }: UnlockScreenProps) {
  const [email, setEmail] = useState(rememberedEmail ?? "");
  const [masterPassword, setMasterPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onUnlock({ email, masterPassword });
    } catch (failure) {
      // The message is produced by the vault layer, which already distinguishes
      // a wrong password from an unreachable server. This only renders it.
      setError(failure instanceof Error ? failure.message : "Could not unlock");
    } finally {
      setBusy(false);
      setMasterPassword("");
    }
  }

  return (
    <main style={{ maxWidth: "22rem", margin: "0 auto", padding: "var(--space-8) var(--space-4)" }}>
      <h1 style={{ fontSize: "1.25rem", fontWeight: 600, marginBottom: "var(--space-6)" }}>
        Unlock your vault
      </h1>
      <form onSubmit={submit}>
        {rememberedEmail === null ? (
          <Field
            label="Email"
            type="email"
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        ) : (
          <p style={{ color: "var(--ink-muted)", marginBottom: "var(--space-4)" }}>
            {rememberedEmail}
          </p>
        )}
        <Field
          label="Master password"
          type="password"
          autoComplete="current-password"
          value={masterPassword}
          onChange={(e) => setMasterPassword(e.target.value)}
          required
        />
        {error !== null && (
          <p role="alert" style={{ color: "var(--danger)", marginBottom: "var(--space-4)" }}>
            {error}
          </p>
        )}
        {/* Disabled while working: Argon2id takes about a second, and an
            impatient double-click would otherwise spend two of the five free
            login attempts before the limiter starts adding delay. */}
        <Button type="submit" disabled={busy}>
          {busy ? "Unlocking…" : "Unlock"}
        </Button>
      </form>
    </main>
  );
}
```

Create `apps/web/src/ui/screens/EnrolScreen.tsx`:

```tsx
import { useState } from "react";
import type { FormEvent } from "react";
import { Button } from "../components/Button.js";
import { Field } from "../components/Field.js";

interface EnrolScreenProps {
  inviteToken: string;
  onEnrol(input: {
    inviteToken: string;
    email: string;
    masterPassword: string;
  }): Promise<{ recoveryCode: string }>;
  onFinish(): void;
}

export function EnrolScreen({ inviteToken, onEnrol, onFinish }: EnrolScreenProps) {
  const [email, setEmail] = useState("");
  const [masterPassword, setMasterPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    if (masterPassword !== confirm) {
      // A typo here is unrecoverable: the vault would be encrypted under a
      // password nobody knows, and the server cannot help, by design.
      setError("The passwords do not match");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const outcome = await onEnrol({ inviteToken, email, masterPassword });
      setRecoveryCode(outcome.recoveryCode);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not set up the account");
    } finally {
      setBusy(false);
    }
  }

  if (recoveryCode !== null) {
    return (
      <main style={{ maxWidth: "28rem", margin: "0 auto", padding: "var(--space-8) var(--space-4)" }}>
        <h1 style={{ fontSize: "1.25rem", fontWeight: 600 }}>Save your recovery code</h1>
        <p style={{ color: "var(--ink-muted)" }}>
          This is the only way back into your vault if you forget your master
          password. It is shown once and cannot be recovered afterwards — not by
          an administrator, and not by anyone with the database.
        </p>
        <p
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "1.125rem",
            padding: "var(--space-4)",
            border: "1px solid var(--rule-strong)",
            margin: "var(--space-6) 0",
          }}
        >
          {recoveryCode}
        </p>
        <label style={{ display: "flex", gap: "var(--space-2)", marginBottom: "var(--space-6)" }}>
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
          />
          I have saved this code somewhere safe
        </label>
        {/* Gated deliberately. Letting someone click past this hands them a
            vault with no second way in, silently. */}
        <Button type="button" disabled={!acknowledged} onClick={onFinish}>
          Continue to my vault
        </Button>
      </main>
    );
  }

  return (
    <main style={{ maxWidth: "22rem", margin: "0 auto", padding: "var(--space-8) var(--space-4)" }}>
      <h1 style={{ fontSize: "1.25rem", fontWeight: 600, marginBottom: "var(--space-6)" }}>
        Set your master password
      </h1>
      <form onSubmit={submit}>
        <Field
          label="Email"
          type="email"
          autoComplete="username"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <Field
          label="Master password"
          type="password"
          autoComplete="new-password"
          value={masterPassword}
          onChange={(e) => setMasterPassword(e.target.value)}
          required
        />
        <Field
          label="Confirm master password"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          required
        />
        {error !== null && (
          <p role="alert" style={{ color: "var(--danger)", marginBottom: "var(--space-4)" }}>
            {error}
          </p>
        )}
        <Button type="submit" disabled={busy}>
          {busy ? "Setting up…" : "Set master password"}
        </Button>
      </form>
    </main>
  );
}
```

Create `apps/web/src/ui/App.tsx`:

```tsx
import { useCallback, useMemo, useState } from "react";
import { createApiClient } from "../vault/api.js";
import { createSession, rememberedEmail } from "../vault/session.js";
import { createVaultStore } from "../vault/store.js";
import { enroll } from "../vault/enroll.js";
import { unlock } from "../vault/unlock.js";
import { EnrolScreen } from "./screens/EnrolScreen.js";
import { UnlockScreen } from "./screens/UnlockScreen.js";
import { VaultScreen } from "./screens/VaultScreen.js";
import { useSession } from "./useVault.js";

/**
 * Reads the one URL this application cares about.
 *
 * Deferring a router does not mean ignoring the address bar: the invite token is
 * the only way the enrolment screen knows which invite it is completing. This is
 * a single string match — no history integration, no route table.
 */
export function inviteTokenFromPath(pathname: string): string | null {
  const parts = pathname.split("/").filter((part) => part.length > 0);
  if (parts.length !== 2 || parts[0] !== "enroll") return null;
  const token = parts[1] as string;
  return token.length > 0 ? decodeURIComponent(token) : null;
}

const DEVICE_LABEL = "Web";

export function App() {
  const session = useMemo(() => createSession(), []);
  const store = useMemo(() => createVaultStore(), []);
  const [refreshFailed, setRefreshFailed] = useState(false);

  const api = useMemo(
    () =>
      createApiClient({
        getAccessToken: () => session.getAccessToken(),
        // Exactly one refresh attempt, then lock. The refresh token is
        // single-use server-side, so a loop would burn the session.
        onUnauthorized: async () => {
          const refreshToken = session.getRefreshToken();
          if (refreshToken === null) return false;
          try {
            const response = await fetch("/api/auth/refresh", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ refreshToken }),
            });
            if (!response.ok) throw new Error("refresh failed");
            const tokens = (await response.json()) as {
              accessToken: string;
              refreshToken: string;
            };
            session.replaceTokens(tokens);
            return true;
          } catch {
            setRefreshFailed(true);
            store.clear();
            session.lock();
            return false;
          }
        },
      }),
    [session, store],
  );

  const { isUnlocked } = useSession(session);
  const inviteToken = useMemo(() => inviteTokenFromPath(window.location.pathname), []);
  const [enrolled, setEnrolled] = useState(false);

  const handleUnlock = useCallback(
    async (input: { email: string; masterPassword: string }) => {
      setRefreshFailed(false);
      await unlock({ api, session }, { ...input, deviceLabel: DEVICE_LABEL });
      await store.load({ api, session });
    },
    [api, session, store],
  );

  const handleEnrol = useCallback(
    async (input: { inviteToken: string; email: string; masterPassword: string }) => {
      const outcome = await enroll({ api, session }, { ...input, deviceLabel: DEVICE_LABEL });
      await store.load({ api, session });
      return outcome;
    },
    [api, session, store],
  );

  if (inviteToken !== null && !enrolled) {
    return (
      <EnrolScreen
        inviteToken={inviteToken}
        onEnrol={handleEnrol}
        onFinish={() => setEnrolled(true)}
      />
    );
  }

  if (!isUnlocked) {
    return (
      <>
        {refreshFailed && (
          <p role="status" style={{ textAlign: "center", color: "var(--ink-muted)" }}>
            Your session expired. Unlock to continue.
          </p>
        )}
        <UnlockScreen rememberedEmail={rememberedEmail()} onUnlock={handleUnlock} />
      </>
    );
  }

  return <VaultScreen api={api} session={session} store={store} />;
}
```

Create `apps/web/src/main.tsx`:

```tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./ui/App.js";
import "./ui/tokens.css";

const root = document.getElementById("root");
if (root === null) throw new Error("No #root element");
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
```

- [ ] **Step 8: Run the tests**

`VaultScreen` does not exist yet, so `App.test.tsx` imports would fail. Create a
placeholder that Task 8 replaces wholesale — it is referenced by `App.tsx` above:

```tsx
// apps/web/src/ui/screens/VaultScreen.tsx — replaced in Task 8
import type { ApiClient } from "../../vault/api.js";
import type { Session } from "../../vault/session.js";
import type { VaultStore } from "../../vault/store.js";

export function VaultScreen(_props: {
  api: ApiClient;
  session: Session;
  store: VaultStore;
}) {
  return <main>Vault</main>;
}
```

```bash
pnpm --filter @keyhole/web test
pnpm --filter @keyhole/web typecheck
pnpm --filter @keyhole/web lint
```

Expected: PASS. Lint must be silent — if it reports the crypto-import ban, a
screen is reaching past `vault/` and that is the bug.

- [ ] **Step 9: Prove the recovery-code gate is load-bearing**

In `EnrolScreen.tsx`, temporarily un-gate the button:

```tsx
        <Button type="button" onClick={onFinish}>
```

Run: `pnpm --filter @keyhole/web test -t "will not continue"`

Expected: FAIL — the button is enabled before acknowledgement. Revert and
confirm PASS. Record both: this gate is the difference between a user who has
their recovery code and one who finds out they do not on the day it matters.

- [ ] **Step 10: Commit**

```bash
git add apps/web/src/ui apps/web/src/main.tsx
git commit -m "feat(web): Mono tokens, the app shell, unlock and enrolment screens"
```

---

## Task 8: Vault list and item editor

**Files:**
- Create: `apps/web/src/ui/screens/VaultScreen.tsx` (replaces the placeholder),
  `apps/web/src/ui/screens/ItemEditor.tsx`

The conflict is surfaced inline in the editor as a `role="alert"`, not in a
dialog. The user is already looking at the form holding their edit; interrupting
them with a modal to say "this changed elsewhere" moves their work further away
rather than closer.
- Test: `apps/web/src/ui/screens/VaultScreen.test.tsx`,
  `apps/web/src/ui/screens/ItemEditor.test.tsx`

**Interfaces:**
- Consumes: everything from Tasks 1–7.
- Produces: no new exported contract — this is the last UI layer.

- [ ] **Step 1: Write the failing vault-list tests**

Create `apps/web/src/ui/screens/VaultScreen.test.tsx`:

```tsx
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { LoginItem } from "@keyhole/crypto";
import type { ItemRecord } from "../../vault/items.js";
import { VaultList } from "./VaultScreen.js";

const LOGIN: LoginItem = {
  type: "login",
  name: "Example",
  username: "person@example.com",
  password: "hunter2",
  urls: [],
  notes: "",
  favorite: false,
  folderId: null,
  passwordHistory: [],
};

function record(overrides: Partial<ItemRecord> = {}): ItemRecord {
  return {
    id: "i1",
    revision: 1,
    collectionId: null,
    deletedAt: null,
    plaintext: LOGIN,
    ...overrides,
  };
}

describe("VaultList", () => {
  it("lists item names and usernames", () => {
    render(<VaultList items={[record()]} onSelect={vi.fn()} onNew={vi.fn()} />);
    expect(screen.getByText("Example")).toBeInTheDocument();
    expect(screen.getByText("person@example.com")).toBeInTheDocument();
  });

  it("never renders a password in the list", () => {
    render(<VaultList items={[record()]} onSelect={vi.fn()} onNew={vi.fn()} />);
    // A shoulder-surfable list defeats the point of a vault. Passwords appear
    // only in the editor, behind a reveal.
    expect(screen.queryByText("hunter2")).not.toBeInTheDocument();
  });

  it("shows an undecryptable row as broken rather than hiding it", () => {
    render(
      <VaultList items={[record({ id: "bad", plaintext: null })]} onSelect={vi.fn()} onNew={vi.fn()} />,
    );
    // Hiding it would be worse: the user would believe an item they created is
    // gone, with nothing anywhere saying otherwise.
    expect(screen.getByText(/couldn.t decrypt/i)).toBeInTheDocument();
  });

  it("filters as the user types", async () => {
    render(
      <VaultList
        items={[record(), record({ id: "i2", plaintext: { ...LOGIN, name: "Bank" } })]}
        onSelect={vi.fn()}
        onNew={vi.fn()}
      />,
    );
    await userEvent.type(screen.getByLabelText(/search/i), "ban");
    expect(screen.getByText("Bank")).toBeInTheDocument();
    expect(screen.queryByText("Example")).not.toBeInTheDocument();
  });

  it("offers an empty state that explains what to do", () => {
    render(<VaultList items={[]} onSelect={vi.fn()} onNew={vi.fn()} />);
    expect(screen.getByRole("button", { name: /add.*item/i })).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Write the failing editor tests**

Create `apps/web/src/ui/screens/ItemEditor.test.tsx`:

```tsx
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { LoginItem } from "@keyhole/crypto";
import { ItemEditor } from "./ItemEditor.js";

const LOGIN: LoginItem = {
  type: "login",
  name: "Example",
  username: "person@example.com",
  password: "hunter2",
  urls: ["https://example.com"],
  notes: "",
  favorite: false,
  folderId: null,
  passwordHistory: [],
};

describe("ItemEditor", () => {
  it("masks the password until it is revealed", async () => {
    render(<ItemEditor initial={LOGIN} onSave={vi.fn()} onCancel={vi.fn()} />);

    const field = screen.getByLabelText(/^password/i);
    expect(field).toHaveAttribute("type", "password");
    await userEvent.click(screen.getByRole("button", { name: /reveal|show/i }));
    expect(field).toHaveAttribute("type", "text");
  });

  it("fills the password field from the generator", async () => {
    render(<ItemEditor initial={LOGIN} onSave={vi.fn()} onCancel={vi.fn()} />);

    await userEvent.click(screen.getByRole("button", { name: /generate/i }));

    const field = screen.getByLabelText(/^password/i) as HTMLInputElement;
    expect(field.value).not.toBe("hunter2");
    expect(field.value.length).toBeGreaterThanOrEqual(16);
  });

  it("saves the edited plaintext", async () => {
    const onSave = vi.fn().mockResolvedValue(undefined);
    render(<ItemEditor initial={LOGIN} onSave={onSave} onCancel={vi.fn()} />);

    await userEvent.clear(screen.getByLabelText(/name/i));
    await userEvent.type(screen.getByLabelText(/name/i), "Renamed");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    await waitFor(() => {
      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({ type: "login", name: "Renamed" }),
      );
    });
  });

  it("surfaces a conflict with both versions rather than overwriting", async () => {
    const onSave = vi.fn().mockRejectedValue(
      Object.assign(new Error("This item changed on the server since you last synced"), {
        name: "ItemConflictError",
      }),
    );
    render(<ItemEditor initial={LOGIN} onSave={onSave} onCancel={vi.fn()} />);

    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    // Design spec 9: concurrent edits never silently lose data. The server
    // refuses the overwrite precisely so the client can put this choice in
    // front of the person who made the edit.
    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/changed on the server/i);
    });
  });
});
```

- [ ] **Step 3: Run and watch them fail**

```bash
pnpm --filter @keyhole/web test -t "VaultList|ItemEditor"
```

Expected: FAIL — `VaultList` and `ItemEditor` are not exported.

- [ ] **Step 4: Implement the editor**

Create `apps/web/src/ui/screens/ItemEditor.tsx`:

```tsx
import { useState } from "react";
import type { FormEvent } from "react";
import type { ItemPlaintext, LoginItem } from "@keyhole/crypto";
import { generatePassword } from "../../vault/generator.js";
import { Button } from "../components/Button.js";
import { Field } from "../components/Field.js";

interface ItemEditorProps {
  initial: ItemPlaintext;
  onSave(next: ItemPlaintext): Promise<void>;
  onCancel(): void;
}

function isLogin(item: ItemPlaintext): item is LoginItem {
  return item.type === "login";
}

export function ItemEditor({ initial, onSave, onCancel }: ItemEditorProps) {
  const [name, setName] = useState(initial.name);
  const [notes, setNotes] = useState(initial.notes);
  const [username, setUsername] = useState(isLogin(initial) ? initial.username : "");
  const [password, setPassword] = useState(isLogin(initial) ? initial.password : "");
  const [revealed, setRevealed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const next: ItemPlaintext = isLogin(initial)
      ? { ...initial, name, notes, username, password }
      : { ...initial, name, notes };
    try {
      await onSave(next);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not save");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} style={{ padding: "var(--space-4)" }}>
      <Field label="Name" value={name} onChange={(e) => setName(e.target.value)} required />
      {isLogin(initial) && (
        <>
          <Field
            label="Username"
            autoComplete="off"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <Field
            label="Password"
            // Masked by default: an editor left open on a desk is the ordinary
            // case, not the exception.
            type={revealed ? "text" : "password"}
            autoComplete="off"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <div style={{ display: "flex", gap: "var(--space-2)", marginBottom: "var(--space-4)" }}>
            <Button type="button" variant="quiet" onClick={() => setRevealed(!revealed)}>
              {revealed ? "Hide" : "Reveal"}
            </Button>
            <Button type="button" variant="quiet" onClick={() => setPassword(generatePassword())}>
              Generate
            </Button>
          </div>
        </>
      )}
      <Field label="Notes" value={notes} onChange={(e) => setNotes(e.target.value)} />
      {error !== null && (
        <p role="alert" style={{ color: "var(--danger)", marginBottom: "var(--space-4)" }}>
          {error}
        </p>
      )}
      <div style={{ display: "flex", gap: "var(--space-2)" }}>
        <Button type="submit" disabled={busy}>
          {busy ? "Saving…" : "Save"}
        </Button>
        <Button type="button" variant="quiet" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}
```

- [ ] **Step 5: Implement the vault screen**

Replace `apps/web/src/ui/screens/VaultScreen.tsx`:

```tsx
import { useCallback, useEffect, useMemo, useState } from "react";
import type { ItemPlaintext, LoginItem } from "@keyhole/crypto";
import type { ApiClient } from "../../vault/api.js";
import type { Session } from "../../vault/session.js";
import type { VaultStore } from "../../vault/store.js";
import {
  createItem,
  deleteItem,
  updateItem,
  type ItemRecord,
} from "../../vault/items.js";
import { Button } from "../components/Button.js";
import { Field } from "../components/Field.js";
import { useVaultState } from "../useVault.js";
import { ItemEditor } from "./ItemEditor.js";

const BLANK_LOGIN: LoginItem = {
  type: "login",
  name: "",
  username: "",
  password: "",
  urls: [],
  notes: "",
  favorite: false,
  folderId: null,
  passwordHistory: [],
};

interface VaultListProps {
  items: ItemRecord[];
  onSelect(record: ItemRecord): void;
  onNew(): void;
}

export function VaultList({ items, onSelect, onNew }: VaultListProps) {
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (needle.length === 0) return items;
    return items.filter((item) => {
      const name = item.plaintext?.name ?? "";
      const username =
        item.plaintext !== null && item.plaintext.type === "login"
          ? item.plaintext.username
          : "";
      return (
        name.toLowerCase().includes(needle) || username.toLowerCase().includes(needle)
      );
    });
  }, [items, query]);

  return (
    <section>
      <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "end" }}>
        <div style={{ flex: 1 }}>
          <Field
            label="Search"
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <Button type="button" onClick={onNew}>
          Add an item
        </Button>
      </div>

      {filtered.length === 0 ? (
        <p style={{ color: "var(--ink-muted)" }}>
          {items.length === 0 ? "Your vault is empty." : "Nothing matches that search."}
        </p>
      ) : (
        <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
          {filtered.map((item) => (
            <li key={item.id} style={{ borderTop: "1px solid var(--rule)" }}>
              <button
                type="button"
                onClick={() => onSelect(item)}
                style={{
                  font: "inherit",
                  width: "100%",
                  textAlign: "left",
                  background: "transparent",
                  border: "none",
                  color: "var(--ink)",
                  padding: "var(--space-3) 0",
                  cursor: "pointer",
                }}
              >
                {/* A row that failed to decrypt is shown, not hidden: the user
                    would otherwise believe an item they created is gone, with
                    nothing anywhere saying otherwise. */}
                {item.plaintext === null ? (
                  <span style={{ color: "var(--danger)" }}>
                    Couldn&rsquo;t decrypt this item
                  </span>
                ) : (
                  <>
                    <span style={{ display: "block" }}>{item.plaintext.name}</span>
                    {item.plaintext.type === "login" && (
                      <span style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
                        {item.plaintext.username}
                      </span>
                    )}
                  </>
                )}
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function VaultScreen({
  api,
  session,
  store,
}: {
  api: ApiClient;
  session: Session;
  store: VaultStore;
}) {
  const state = useVaultState(store);
  const [editing, setEditing] = useState<ItemRecord | "new" | null>(null);

  // Re-sync on focus rather than a timer: it catches the realistic case — you
  // edited on your phone, you come back to this tab — with no polling, no
  // battery cost, and no timer to leak.
  useEffect(() => {
    const onFocus = (): void => {
      void store.resync({ api, session }).catch(() => undefined);
    };
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [api, session, store]);

  const save = useCallback(
    async (next: ItemPlaintext): Promise<void> => {
      if (editing === "new") {
        store.upsert(await createItem({ api, session }, next));
      } else if (editing !== null) {
        store.upsert(await updateItem({ api, session }, editing.id, editing.revision, next));
      }
      setEditing(null);
    },
    [api, editing, session, store],
  );

  const remove = useCallback(async (): Promise<void> => {
    if (editing === null || editing === "new") return;
    await deleteItem({ api, session }, editing.id);
    store.remove(editing.id);
    setEditing(null);
  }, [api, editing, session, store]);

  return (
    <main style={{ maxWidth: "40rem", margin: "0 auto", padding: "var(--space-4)" }}>
      <header
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "baseline",
          borderBottom: "1px solid var(--rule-strong)",
          paddingBottom: "var(--space-2)",
          marginBottom: "var(--space-4)",
        }}
      >
        <h1 style={{ fontSize: "1.125rem", fontWeight: 600, margin: 0 }}>Keyhole</h1>
        <Button
          type="button"
          variant="quiet"
          onClick={() => {
            store.clear();
            session.lock();
          }}
        >
          Lock
        </Button>
      </header>

      {state.status === "error" && (
        <p role="alert" style={{ color: "var(--danger)" }}>
          {state.error}
        </p>
      )}

      {editing === null ? (
        <VaultList
          items={state.items}
          onSelect={setEditing}
          onNew={() => setEditing("new")}
        />
      ) : (
        <>
          <ItemEditor
            initial={editing === "new" ? BLANK_LOGIN : (editing.plaintext ?? BLANK_LOGIN)}
            onSave={save}
            onCancel={() => setEditing(null)}
          />
          {editing !== "new" && (
            <Button type="button" variant="danger" onClick={() => void remove()}>
              Delete this item
            </Button>
          )}
        </>
      )}
    </main>
  );
}
```

- [ ] **Step 6: Run the whole suite**

```bash
pnpm --filter @keyhole/web test
pnpm --filter @keyhole/web typecheck
pnpm --filter @keyhole/web lint
```

Expected: PASS. Lint silent.

- [ ] **Step 7: Prove the list does not leak passwords**

In `VaultScreen.tsx`, temporarily render the password in the row:

```tsx
                      <span>{item.plaintext.password}</span>
```

Run: `pnpm --filter @keyhole/web test -t "never renders a password"`

Expected: FAIL. Revert and confirm PASS. Record both.

- [ ] **Step 8: Commit**

```bash
git add apps/web/src/ui/screens apps/web/src/ui/components
git commit -m "feat(web): vault list and item editor"
```

---

## Task 9: End-to-end against a real server

**Files:**
- Create: `apps/web/playwright.config.ts`, `apps/web/e2e/server.ts`,
  `apps/web/e2e/vault.spec.ts`

**Interfaces:**
- Consumes: the built app and a real `keyhole` binary.
- Produces: nothing importable — this is the outermost gate.

- [ ] **Step 1: Write the server harness**

Create `apps/web/e2e/server.ts`:

```ts
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const REPO_ROOT = resolve(import.meta.dirname, "../../..");
// Go is installed but not on this machine's PATH for tool shells.
const GO = process.platform === "win32" ? "C:\\Program Files\\Go\\bin\\go.exe" : "go";

export interface RunningServer {
  baseUrl: string;
  /** A working invite URL for a fresh admin account. */
  inviteUrl: string;
  email: string;
  stop(): void;
}

/**
 * Boots a real keyhole server on a temporary database, bootstrapped exactly the
 * way an operator does it: build, migrate, admin create, then read the setup
 * link off stdout.
 *
 * The invite reaching the test as a printed URL is the point. A fixture that
 * injected a token straight into the database would skip the one step that
 * proves an operator can actually onboard someone.
 */
export function startServer(port = 8477): RunningServer {
  const dataDir = mkdtempSync(join(tmpdir(), "keyhole-e2e-"));
  const binary = join(dataDir, process.platform === "win32" ? "keyhole.exe" : "keyhole");
  const configPath = join(dataDir, "config.yml");

  writeFileSync(
    configPath,
    [
      `addr: 127.0.0.1:${port}`,
      `data_dir: ${dataDir}`,
      `base_url: http://127.0.0.1:5173`,
      `log_level: warn`,
      "",
    ].join("\n"),
  );

  execFileSync(GO, ["build", "-o", binary, "./cmd/keyhole"], { cwd: REPO_ROOT });
  execFileSync(binary, ["migrate", "--config", configPath]);

  const email = "e2e@example.com";
  const created = execFileSync(binary, [
    "admin",
    "create",
    "--email",
    email,
    "--config",
    configPath,
  ]).toString();

  const match = /(http:\/\/\S+\/enroll\/\S+)/.exec(created);
  if (match === null) {
    throw new Error(`No setup link in admin create output:\n${created}`);
  }

  const child: ChildProcess = spawn(binary, ["serve", "--config", configPath], {
    stdio: "ignore",
  });

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    inviteUrl: match[1] as string,
    email,
    stop: () => {
      child.kill();
    },
  };
}
```

- [ ] **Step 2: Write the Playwright config**

Create `apps/web/playwright.config.ts`:

```ts
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  // Argon2id at 64 MiB is roughly half a second per derivation, and these
  // journeys do several. The cost is the feature; the timeout accommodates it.
  timeout: 120_000,
  expect: { timeout: 20_000 },
  // One worker: every journey drives the same server on the same port, and the
  // whole point is a real single-writer SQLite database.
  workers: 1,
  use: {
    baseURL: "http://127.0.0.1:5173",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "pnpm dev --port 5173",
    url: "http://127.0.0.1:5173",
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
```

- [ ] **Step 3: Write the journeys**

Create `apps/web/e2e/vault.spec.ts`:

```ts
import { expect, test } from "@playwright/test";
import { startServer, type RunningServer } from "./server.js";

let server: RunningServer;

test.beforeAll(() => {
  server = startServer();
});

test.afterAll(() => {
  server.stop();
});

const MASTER_PASSWORD = "correct horse battery staple";

test("enrol, create an item, reload, and read it back decrypted", async ({ page }) => {
  // The one journey that can catch a broken crypto-server contract: byte-exact
  // KDF params, base64 handling, the revision cursor. A mocked test would pass
  // with every one of them wrong.
  const invitePath = new URL(server.inviteUrl).pathname;
  await page.goto(invitePath);

  await page.getByLabel(/email/i).fill(server.email);
  await page.getByLabel(/^master password/i).fill(MASTER_PASSWORD);
  await page.getByLabel(/confirm/i).fill(MASTER_PASSWORD);
  await page.getByRole("button", { name: /set master password/i }).click();

  // The recovery code is shown once and gated behind an acknowledgement.
  await expect(page.getByText(/save your recovery code/i)).toBeVisible();
  await page.getByLabel(/saved/i).check();
  await page.getByRole("button", { name: /continue/i }).click();

  await page.getByRole("button", { name: /add an item/i }).click();
  // Anchored: /name/i would also match "Username" and trip Playwright's strict
  // mode with two candidates.
  await page.getByLabel(/^name$/i).fill("Example Service");
  await page.getByLabel(/username/i).fill("person@example.com");
  await page.getByLabel(/^password/i).fill("s3cr3t-value");
  await page.getByRole("button", { name: /save/i }).click();
  await expect(page.getByText("Example Service")).toBeVisible();

  // A reload throws away every key: they were memory-only, by design.
  await page.reload();
  await expect(page.getByLabel(/master password/i)).toBeVisible();

  await page.getByLabel(/master password/i).fill(MASTER_PASSWORD);
  await page.getByRole("button", { name: /^unlock$/i }).click();

  await expect(page.getByText("Example Service")).toBeVisible();
  await page.getByText("Example Service").click();
  await page.getByRole("button", { name: /reveal|show/i }).click();
  // The round trip completed: encrypted here, stored opaque, decrypted here.
  await expect(page.getByLabel(/^password/i)).toHaveValue("s3cr3t-value");
});

test("a wrong master password is reported honestly", async ({ page }) => {
  await page.goto("/");
  // Each Playwright test gets a fresh browser context, so localStorage is empty
  // and the email field is present. Filling only the password would fail the
  // form's own required check and never reach the server.
  await page.getByLabel(/email/i).fill(server.email);
  await page.getByLabel(/master password/i).fill("not the password");
  await page.getByRole("button", { name: /^unlock$/i }).click();

  // Design spec 9: a network blip must never read as a wrong password, and a
  // wrong password must not read as a server fault.
  await expect(page.getByRole("alert")).toContainText(/wrong master password/i);
});

test("the vault survives a locked and re-unlocked session", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel(/email/i).fill(server.email);
  await page.getByLabel(/master password/i).fill(MASTER_PASSWORD);
  await page.getByRole("button", { name: /^unlock$/i }).click();
  await expect(page.getByText("Example Service")).toBeVisible();

  await page.getByRole("button", { name: /^lock$/i }).click();
  await expect(page.getByLabel(/master password/i)).toBeVisible();
  // Locking must clear the list, not merely navigate away from it.
  await expect(page.getByText("Example Service")).not.toBeVisible();

  await page.getByLabel(/master password/i).fill(MASTER_PASSWORD);
  await page.getByRole("button", { name: /^unlock$/i }).click();
  await expect(page.getByText("Example Service")).toBeVisible();
});
```

- [ ] **Step 4: Install browsers and run**

```bash
pnpm --filter @keyhole/web exec playwright install chromium
pnpm --filter @keyhole/web test:e2e
```

Expected: PASS, all three. The first is slow — several Argon2id derivations plus
a Go build.

If journey 1 fails at enrolment with a 400, the params are not byte-equal:
check that `enroll.ts` sends `DEFAULT_KDF_PARAMS_JSON` and not a stringified
object. That is the failure this journey exists to catch.

- [ ] **Step 5: Prove the e2e catches a contract break**

In `apps/web/src/vault/enroll.ts`, temporarily send a stringified object:

```ts
    params: JSON.stringify(DEFAULT_KDF_PARAMS),
```

Run: `pnpm --filter @keyhole/web test:e2e -g "read it back"`

Expected: the unit tests would still pass here — `JSON.stringify` of that
literal happens to produce the right bytes — so **record what actually happens**.
Then make it unambiguous by reordering:

```ts
    params: JSON.stringify({ iterations: 3, algorithm: "argon2id", memoryKiB: 65536, parallelism: 4 }),
```

Expected: FAIL at enrolment with a 400. Revert and confirm PASS. **This is the
headline result of the whole plan**: a semantically identical payload, rejected,
caught only because the test ran against a real server. Record both outputs.

- [ ] **Step 6: Full verification**

```bash
pnpm --filter @keyhole/web test
pnpm --filter @keyhole/web typecheck
pnpm --filter @keyhole/web lint
pnpm --filter @keyhole/web test:e2e
pnpm -r test
pnpm -r typecheck
```

Expected: all PASS. The Go suite is untouched by this plan but should still be
confirmed green:

```bash
export PATH="/c/Program Files/Go/bin:$PATH"; go test ./...
```

- [ ] **Step 7: Commit**

```bash
git add apps/web/e2e apps/web/playwright.config.ts
git commit -m "test(web): end-to-end journeys against a real keyhole server"
```

---

## Definition of done

- [ ] A person can open an invite link, set a master password, record a recovery
      code, and land in their vault.
- [ ] They can create a login, reload the page, unlock, and read the password
      back decrypted — proven end-to-end against a real server, not a mock.
- [ ] They can edit and delete an item; a concurrent edit surfaces a conflict
      rather than a silent overwrite.
- [ ] They can generate a password, and every enabled character class is present
      in it.
- [ ] A wrong master password, an unreachable server, and an expired session
      each produce a distinct, accurate message.
- [ ] Nothing but `keyhole.email` is written to `localStorage`, and nothing at
      all to `sessionStorage` or IndexedDB — asserted by test.
- [ ] `session.lock()` zeroizes the key material, asserted by reading the arrays
      back.
- [ ] `ui/` contains no import of `@keyhole/crypto` — enforced by lint, not by
      review.
- [ ] An item that fails to decrypt shows as one broken row; the rest of the
      vault works.
- [ ] `pnpm -r test`, `pnpm -r typecheck`, and the Playwright suite all pass.
- [ ] Every mutation test named in the tasks above has been run, its failure
      recorded, and the mutation reverted.
