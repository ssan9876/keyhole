# Keyhole Web Shell — Design Spec

> Scope: the first slice of design spec §6 (Web app). Collections, settings,
> admin screens, and import (§7) follow in a later plan.

**Goal:** the shortest path to a vault a person can actually use — enrol with an
invite, unlock with a master password, list items, read and edit one, and
generate a password. Everything built so far is a server with 261 tests and no
way to touch it except `curl`; this is what makes it a product.

**Stack:** already settled in design spec §2 — React + TypeScript + Vite +
Tailwind + Radix primitives, "Mono" visual direction. No new framework
decisions are open.

---

## 1. Scope

**In:**

- Invite enrolment, including the one-time recovery-code screen
- Login and unlock
- Vault list
- Item detail and editor (logins and secure notes — the two v1 item types)
- Password generator

**Out, deliberately:**

| Deferred | Why |
|---|---|
| Collections, settings, admin screens | Design spec §6.2 lists them; they are the next plan |
| Import (§7) | Needs the editor and vault list to exist first |
| Offline cache, service worker, install manifest (§6.5) | Adds a persistence layer that §6.3 constrains heavily; online-only first |
| URL routing | ~6 screens behind an unlock gate. A `screen` value is enough. Routing earns its keep once collections and admin arrive — easy to add, hard to remove. **Not the same as ignoring the URL**: see §1.1 |
| Serving the built app | The Go binary has no static-asset handler today. See §1.2 |

### 1.1 One URL is still read

Deferring a router does not mean ignoring the address bar. The invite link is
`<base-url>/enroll/<token>`, and that token is the only way the enrolment screen
knows which invite it is completing.

So at boot the app reads `window.location.pathname` **once**: if it matches
`/enroll/<token>`, the initial screen is enrolment with that token; otherwise it is
unlock. That is a single string match, not routing — there is no history
integration, no back-button handling, and no route table.

### 1.2 How the app is served — deferred, deliberately

`keyhole serve` currently serves the API and nothing else; `routes()` answers every
unmatched path with a JSON 404. There is no static-asset handler, so today the
built web app has no delivery mechanism in production.

That is left to the deployment plan (design spec §8), not this one, for two
reasons. Packaging is what §8 is about — the installer, the single binary, the
update flow. And embedding `apps/web/dist` with `go:embed` couples the Go build to
a prior web build, which would break `go build ./...` on a fresh clone; solving
that properly belongs with the release process rather than bolted onto a UI plan.

**For this plan**, development and the end-to-end suite both run the Vite dev
server with `/api` proxied to `keyhole serve` on `127.0.0.1:8477`. The app is real
and fully exercised against the real server; only the production packaging of it
is out of scope.
| Real-time push | Focus-based re-sync covers the realistic case (see §4.4) |

**Online-only** means the app fetches `GET /api/sync` on unlock and holds the
result for the session. Nothing is written to disk except the user's email.

---

## 2. Architecture

```
apps/web/src/
  vault/                 plain TypeScript — no React imports anywhere
    session.ts           the ONLY module holding key material or tokens
    api.ts               typed client for the server API; error mapping
    unlock.ts            prelogin → beginUnlock → login → finish
    enroll.ts            enrollUser → POST /api/enroll/:token
    items.ts             encrypt/decrypt orchestration over @keyhole/crypto
    generator.ts         password generator (pure, no state)
    store.ts             subscribable vault state; useSyncExternalStore-compatible
  ui/                    React only
    screens/
    components/
    tokens.css           Mono design tokens
  main.tsx
```

### 2.1 Why the core is framework-free

`packages/crypto` already has no React, no network, and no storage — design spec
§6.1 says that is what makes it independently testable. `vault/` extends the same
boundary one layer up.

The concrete reason is design spec §6.3, which is written as **"a code-review gate,
not a guideline"**: decrypted keys and plaintext live in memory only, never
`localStorage`, `sessionStorage`, or IndexedDB. The realistic ways that rule gets
broken are all React-shaped — a persistence middleware serialising a store, devtools
snapshotting state, an error boundary logging props, a component putting `userKey`
in `useState` where the next reader treats it as ordinary data.

If key material never enters the component tree, the gate is checkable by grep
rather than by vigilance. It also means `unlock → list → decrypt` is testable with
no DOM at all.

This is also why no state library is used. TanStack Query's devtools serialise
cache contents and its persist plugin writes to storage; those are the two
behaviours §6.3 forbids, shipped as headline features. The vault is one endpoint
fetched whole, so the library would be earning its dependency on caching we do not
need.

### 2.2 Two enforceable boundaries

1. **`ui/` never imports `@keyhole/crypto`** — only `vault/`. An ESLint
   `no-restricted-imports` rule makes a violation fail the build rather than
   depend on a reviewer noticing.
2. **`session.ts` is the only module that retains a `Uint8Array` of key
   material.** Everything else receives what it needs as an argument and does not
   hold it.

`session.ts` holds `userKey`, `privateKey`, and both tokens, and exposes `lock()`,
which zeroizes through the crypto package's existing `zeroize()`. It has no
serialiser and nothing that could reach one.

`store.ts` holds **decrypted** items for the session. That is the deliberate
concession — a vault list has to render plaintext names — but it is one module with
a lifetime explicitly tied to `lock()`.

---

## 3. Session and persistence

**Only the user's email is persisted.** Both tokens and all key material live in
memory.

This differs from the obvious design, and the reason is a property of the server
worth stating plainly:

> `internal/httpapi/auth.go:184` returns `protectedUserKey` and
> `encryptedPrivateKey` from **`POST /api/auth/login` only**. `/api/auth/refresh`
> returns tokens alone, and `/api/account` deliberately excludes them — that
> exclusion is an asserted security property (design spec §10, closed in Plan 2b
> Task 6).

So the wrapped keys are unreachable except by logging in, which means **unlocking
always costs a full login round trip**. A persisted refresh token cannot shortcut
it. It would therefore be nearly all cost and no benefit: a stolen token grants API
access — list item ids, delete items, never plaintext — while saving the user
nothing but typing their email.

Persisting the email alone gives the same password-only unlock screen with nothing
on disk worth stealing. And because keys are memory-only regardless, memory-only
tokens cost nothing extra: a page refresh already forces a re-unlock.

**Auto-lock on an idle timer is out of scope** — design spec §6.2 lists it under
Settings, which is the next plan. Closing the tab locks the vault, which is the
guarantee §6.3 already provides.

---

## 4. Data flow

### 4.1 Enrolment

Entered when the boot-time path check in §1.1 matches `/enroll/<token>`.

1. `enrollUser(masterPassword)` → salt, params, `authHash`, wrapped blobs, and
   `userKey` / `keyPair` held in memory
2. `generateRecoveryCode()` → `createRecoveryBlob(userKey, code, params)`
3. `POST /api/enroll/:token`, sending `params: DEFAULT_KDF_PARAMS_JSON`
   **verbatim** — the server rejects anything not byte-equal (Plan 2b Task 6) —
   and `recoveryKdfParams: JSON.stringify(recovery.params)`, which is not pinned
4. **The recovery-code screen, shown exactly once**, behind an explicit "I have
   saved this" confirmation. The code cannot be recovered afterwards by anyone
5. `POST /api/auth/login` → tokens
6. Into the vault; keys never left memory

`POST /api/enroll/:token` returns only `{id, email, name, role}` — deliberately,
per its own comment: *"never echo key material, not even the caller's own."* So a
login is required after enrolling. But `enrollUser()` already returned `authHash`,
so that login needs **no prelogin and no second Argon2id pass** — the whole
enrol-and-enter flow costs one derivation.

### 4.2 Unlock

`prelogin(email)` → `beginUnlock(password, salt, params)` → `POST /api/auth/login`
→ `session.finish(protectedUserKey, encryptedPrivateKey)` → `destroy()` on the
unlock session to zeroize the intermediate master and wrapping keys →
`GET /api/sync` → decrypt into the store.

A wrong password fails at login with a 401; `finish()` is never reached. This
matters for design spec §9's honesty rule: the client reports "wrong master
password" from an authentication failure, not by guessing at a GCM tag mismatch.

### 4.3 Item writes

- **Create:** `encryptItem(plaintext, userKey)` → `POST /api/items`
- **Edit:** `PUT /api/items/{id}` carrying the revision the user edited from
- **Delete:** `DELETE /api/items/{id}`

On **409** the server returns the winning copy alongside the error. The shell shows
"this item changed on another device", displays both versions, and lets the user
re-apply their edit against the new revision. No silent overwrite — design spec §9
requires that concurrent edits never lose data, and the server refuses the
overwrite precisely so the client can resolve it.

### 4.4 Staying current

Writes patch the store directly from the response; no refetch.

Beyond that the shell re-syncs with `GET /api/sync?since=N` **on window focus**
rather than on a timer. It catches the realistic case — you edited on your phone,
you come back to the laptop tab — with no background polling, no battery cost, and
no timer to leak. Real-time push is a later question if it is ever wanted.

---

## 5. Error handling

`api.ts` converts every failure into one typed union. The UI branches on **`code`,
never `message`**: `internal/httpapi/errors.go` states that codes are stable and
messages are for humans and may change.

| Condition | Client behaviour |
|---|---|
| fetch rejects | "Can't reach the server" — never worded as a password problem |
| 401 during unlock | "Wrong master password" |
| 401 during use | Refresh **once**; if that fails, lock and return to unlock |
| 409 | Carries the winning item; drives the conflict UI in §4.3 |
| 400 | Echo the server's message — safe by design, it is the caller's own payload |
| 429 | "Too many attempts", with the wait |
| 5xx | Generic message; the detail is already in the server log under a request ID |

Design spec §9 requires the client to distinguish network, authentication, and
decryption failures, and that a network blip must never read as a wrong password.
The table above is that requirement made concrete.

Two choices worth calling out:

**A single item that fails to decrypt does not fail the vault.** That row renders
as "couldn't decrypt" and the rest of the list works. One corrupt blob making every
password unreachable is a worse failure than one visibly broken row.

**The 401-during-use refresh is one attempt, not a loop.** A refresh token is
single-use server-side — `RotateSession` matches on the old hash and replaces it —
so a retry loop would burn the session and produce a confusing cascade.

---

## 6. Visual direction

"Mono" is already selected (design spec §2, from four mockups) and specified in
§6.4: Swiss and typographic, hairline rules, no decorative shadow or gradient,
colour reserved for meaning. Light and dark from one token set; dark is the same
layout with inverted values and hairlines at 12% white. Mobile-first.

Design tokens live in one file (`ui/tokens.css`) so the warmth dial — paper-white
ground and softer rules versus pure white and black hairlines — is a token change
rather than a redesign.

Accessibility is a requirement, not a polish pass: full keyboard navigation,
visible focus rings, WCAG AA contrast, labelled form controls, focus-trapped
dialogs. Radix primitives are used for the dialog and menu behaviours precisely so
this is not hand-rolled.

---

## 7. Testing

**Component and unit:** Vitest + Testing Library for screens, and for the `vault/`
modules, which need no DOM.

**End-to-end:** a small Playwright suite driving the Vite dev server with `/api`
proxied to a real `keyhole serve` on a temporary SQLite database (§1.2). The
harness bootstraps the way an operator does: build the binary, `migrate`,
`admin create`, then parse the invite token out of the printed setup URL — which
is exactly how the invite reaches the app in production, so the enrolment journey
starts from a genuine link rather than a fixture.

The e2e set stays **small and journey-shaped** rather than exhaustive. Argon2id at
64 MiB is roughly half a second per derivation by design, so these are inherently
slow. The journeys that earn the cost:

1. enrol → recovery code → vault → create item → **reload** → unlock → read it
   back decrypted
2. wrong password → an honest error, not a network-shaped one
3. concurrent edit → 409 → conflict UI

Journey 1 is the one that can catch a broken crypto↔server contract, including the
byte-exact params pinning, base64 handling, and the revision cursor. **A mocked
test cannot**: it would pass with the client sending malformed params.

That is not a hypothetical concern in this repository. Eight tests have now shipped
here that passed while verifying nothing like their names — most recently a spec
§10 security assertion that missed every wrapped key it existed to catch, because
Go marshals an untagged struct in PascalCase and the assertion only checked
camelCase and snake_case. Tests that cannot fail are the recurring defect in this
project, and the e2e journeys exist to make the contract falsifiable.

---

## 8. Definition of done

- A person can open an invite link, set a master password, record a recovery code,
  and land in their vault
- They can create a login and a secure note, reload the page, unlock, and read both
  back decrypted
- They can edit and delete an item, and a concurrent edit produces a conflict the
  user resolves rather than a silent overwrite
- They can generate a password from the editor
- A wrong master password, an unreachable server, and an expired session each
  produce a distinct, accurate message
- No key material or plaintext reaches `localStorage`, `sessionStorage`, or
  IndexedDB — asserted by test, not only by review
- `ui/` contains no import of `@keyhole/crypto`, enforced by lint
- Vitest and Playwright suites pass; typecheck is clean
