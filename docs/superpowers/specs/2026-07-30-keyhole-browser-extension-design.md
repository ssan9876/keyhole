# Keyhole Browser Extension — Design Spec

**Date:** 2026-07-30
**Status:** Approved
**Milestone:** 2 (of 3), first half

---

## 1. Overview

A Chromium (Chrome and Edge) browser extension that fills Keyhole credentials into
web pages on the desktop, and offers to save new ones. It is a full Keyhole client:
it authenticates to the server itself, syncs and decrypts the whole vault locally,
and matches sites client-side. The server gains no new endpoints and learns nothing
new.

### Goals

- Fill a saved login into the page you are on, from the toolbar popup, in two clicks.
- Offer to save a login you just typed, and to update one whose password changed.
- Generate a password at signup time without leaving the page.
- Reach the vault without opening the web app.
- Extract `apps/web/src/vault/*` into a shared package, so the later native clients
  inherit a tested vault layer instead of a third reimplementation.

### Non-goals

Deliberately excluded from v1, each because it is a project in itself:

- **Inline dropdowns in the page.** The 1Password-style suggestion list anchored to a
  focused field. Rejected for v1 as the largest and most fragile component in any
  password extension — shadow DOM, iframes, SPA re-renders, and permanent per-site
  breakage.
- **Firefox and Safari.** The household uses Chrome and Edge. Firefox is a plausible
  later addition (the MV3 differences are modest); Safari needs a native wrapper and
  an Apple Developer account, the same gate as iOS.
- **Cross-origin iframe filling.** See §4.
- **TOTP, passkeys, card and identity autofill.** Not in the v1 item model.
- **Offline use.** The extension requires the server to unlock, exactly as the PWA does.

### Relationship to mobile autofill

This spec exists because of a request for autofill on phones, and it does not deliver
that. The reasoning is recorded here so it is not relitigated:

Autofill on iOS and Android is an operating-system service. Registering as a provider
requires a signed native binary declaring a platform extension point — iOS
`ASCredentialProviderExtension`, Android `AutofillService` or a Credential Manager
provider. No web API exists or is proposed. A PWA cannot participate.

A browser extension fills web pages, not applications. On Android it would reach only
Firefox, which supports extensions; Chrome for Android does not. The household uses
Chrome, so **this extension covers desktop only**. Phone coverage requires the native
Android client (Milestone 2, second half) and the native iOS client (Milestone 3).
That sequencing was chosen with the tradeoff explicit: desktop value ships sooner,
phones stay on the PWA and copy-paste until the native work lands.

---

## 2. Decisions

| Decision | Choice | Reason |
|---|---|---|
| Client model | Standalone full client | See §2.1 |
| Key residence | Offscreen document | MV3 kills the service worker on idle; an offscreen document persists and keeps keys in a closure |
| Fill trigger | Toolbar popup only | Smallest surface, no injected UI, nothing to break per-site |
| Save prompt | Toolbar badge, then popup | Consequence of popup-only: no in-page bar exists to host it |
| Auto-lock | Existing `AutoLockSetting`, own value, default 15 min | One mental model with the web app; the code exists and is tested |
| Domain matching | Registrable domain (eTLD+1) via bundled PSL | Substring matching is how autofillers leak credentials |
| Auto-submit | Never | Rules out invisible-form harvesting |
| Server address | Configured at setup, `optional_host_permissions` | A self-hosted install cannot hardcode a host in the manifest |
| Shared code | Extract `packages/vault` | Two clients today, four later; a second copy would drift |
| Distribution | Chrome Web Store, unlisted | Household gets automatic updates; unlisted keeps it private |
| Browser targets | Chrome and Edge | What the household actually uses |

### 2.1 Why a standalone client

Two alternatives were considered and rejected.

**Proxy an open PWA tab.** The extension would ask a running web-app tab to do the
crypto and return credentials, avoiding a second unlock and duplicated session logic.
Rejected: it works only while a tab is open, it makes the PWA a credential oracle
reachable over a message channel, and it places plaintext passwords on `postMessage`
for every fill.

**Ask the server for the current domain's items.** Impossible by construction, and
the reason shapes the whole design. Design spec §3.4 places item names and URLs
*inside* the encrypted blob, so all search and URL matching happen client-side. The
server cannot identify which items belong to a domain — it cannot read them. The
extension must therefore sync and decrypt the **entire vault** before answering "what
do I have for this site?". At household scale this is not a performance concern, but
it means the extension is necessarily a heavyweight client rather than a thin lookup.

---

## 3. Architecture

Four execution contexts, separated by what each is permitted to know.

| Context | Holds | Responsibility |
|---|---|---|
| Service worker | No key material; a pending save capture, briefly (§4.4) | Message routing, sync scheduling, `chrome.alarms`, badge state |
| Offscreen document | All key material | `createSession()` and the vault store; the only place keys exist |
| Popup (React) | Render-time plaintext | Unlock, item list, search, generator, save confirmation, settings |
| Content script | One credential, on demand | Form detection, fill execution, submit observation |

The service worker never sees a key. That is deliberate: it is the most
message-exposed context, and excluding it from key custody means a routing bug cannot
leak one. It does briefly hold one plaintext password — a pending save capture — and
§4.4 bounds that window explicitly rather than letting it hide behind "nothing
sensitive". `session.ts` states that it is the only module retaining key material and
that this is a code-review gate; hosting it in the offscreen document preserves both
the property and the single place to look.

### 3.1 Repository layout

```
packages/crypto      unchanged
packages/vault       NEW — lifted from apps/web/src/vault
apps/web             now consumes packages/vault
apps/extension       NEW — MV3, consumes packages/vault
```

### 3.2 The extraction

`vault/*` is already framework-free: the modules take `ApiClient` and `Session` as
arguments and import no React. Two obstacles to a clean lift, and their fixes:

1. **`session.ts` and `autolock.ts` call `localStorage` directly**, which does not
   exist in a service worker. Introduce a `PreferenceStore` interface with two
   methods (`get`, `set`) and inject it: `localStorage` in the web app,
   `chrome.storage.local` in the extension. It carries preferences only —
   `keyhole.email` and `keyhole.autolock` — and never key material. The prohibition
   on persisting keys is unchanged and unweakened.

2. **`ApiClient` has no meaningful base URL in the web app**, which is served
   same-origin. The extension collects the server address at setup, stores it as a
   preference, and requests host permission for it at runtime via
   `chrome.permissions.request`.

`autolock.ts` additionally depends on DOM activity events. The extension substitutes
a `chrome.alarms` tick against a last-activity timestamp updated on popup interaction
and fill. The wall-clock re-check that the existing implementation performs on wake
is retained for the same reason it exists there: a timer alone leaves a vault
unlocked across a sleeping machine.

---

## 4. Flows

### 4.1 Setup

First run collects the server address, requests host permission for it, and stores
the address. No account creation — Keyhole has no self-signup path, by design.

### 4.2 Unlock

Popup collects email and password. The offscreen document derives `masterKey` via
Argon2id, calls `POST /api/auth/login`, unwraps `userKey` and the private key,
performs a full sync, and holds the decrypted vault in memory. This is byte-for-byte
the web app's unlock; it is the same code.

### 4.3 Fill

1. Popup asks the service worker for the active tab's URL.
2. Offscreen returns items whose stored URLs match by registrable domain (§5).
3. The user clicks an item. Search across the whole vault is available for sites
   whose saved URL does not match.
4. The chosen credential is delivered to the content script, which sets the fields
   and dispatches `input` and `change` events so controlled React and Vue inputs
   register the value.
5. Nothing is submitted. The user presses the button.

### 4.4 Save and update

The content script observes form submissions and reports `{url, username, password}`
to the service worker, which asks the offscreen document whether the vault already
holds it. Three outcomes: unknown credential, known username with a changed password,
or no action. In the first two the toolbar icon is badged and the capture is held in
memory; clicking the icon opens the popup to confirm, name, and file the item.

The badge-then-popup sequence follows from the popup-only decision. With no injected
UI there is no in-page surface to host a save bar, and a browser notification
containing a password is a worse answer. The cost is one extra click relative to
commercial managers, and the benefit is zero extension UI on any page.

A pending capture is discarded on lock, on browser close, and after 5 minutes. It
holds a plaintext password in service-worker memory for that window, which is the
one place outside the offscreen document where that is true; the bound exists to
keep the window short and explicit.

### 4.5 Generator

The popup exposes the existing generator from `vault/generator.ts`, so a password can
be created at signup without opening the web app. Generated values flow into the save
prompt.

---

## 5. Matching and security rules

The rules that keep an autofiller from becoming a phishing amplifier.

- **Match on the registrable domain (eTLD+1), never on a substring.** `github.com`
  matches `gist.github.com`; it must not match `github.com.evil.tk` or
  `evil-github.com`. Chrome exposes no eTLD+1 API to extensions, so a Public Suffix
  List (~30 KB gzipped) is bundled. This is the most security-critical code in the
  project and is tested adversarially, not for the happy path.
- **Never fill over plain `http://`**, except `localhost`. A password filled onto a
  cleartext page is a password disclosed.
- **Never fill into cross-origin iframes.** Legitimate on some checkout pages and the
  classic exfiltration path. Excluded until there is both a reason and a design.
- **Never fill on page load; never auto-submit.** Filling occurs only on explicit
  user action, which rules out invisible-form harvesting.
- **One credential per fill.** The content script receives only the chosen item,
  never the vault and never a candidate list. The page's own scripts can read a
  filled field — true of every password manager and unavoidable — so the blast radius
  is bounded to the single credential deliberately used on that site.
- **Clipboard copies clear after 20 seconds** and are never written to a syncing
  clipboard.
- **Excluded surfaces:** `file://`, `chrome://`, `edge://`, the Chrome Web Store, and
  the extension's own pages.

### 5.1 Threat model deltas from the web app

The extension is exposed to every site the user visits, which the web app is not.
Three consequences are accepted explicitly:

1. A content script runs on all pages. It holds no credential until one is sent, and
   receives one only on explicit user action.
2. A malicious page can read a field after it is filled. Bounded per §5.
3. A compromised extension update would be a total vault compromise. Mitigated by
   unlisted distribution, a pinned build in the existing release workflow, and no
   runtime-loaded code — the CSP forbids remote script, and no dependency is fetched
   at runtime.

---

## 6. Error handling

`ApiError` and `NetworkError` are reused unchanged, including the existing rule that
a network failure must never be presented as a wrong password. The extension adds two
states the web app cannot have, and each needs its own message:

- **Server unreachable.** Routine for a self-hosted deployment behind a tunnel.
- **Host permission not granted.** Recoverable with one click, and indistinguishable
  from a network failure unless explicitly checked — so it is checked first.

---

## 7. Testing

**The extraction gate.** The suite stands at 907 passing tests as of 2026-07-30 — 744
in `apps/web`, 163 in `packages/crypto`. All 907 must still pass after `vault/*` moves
to `packages/vault`, with no edits beyond import paths. The per-package totals will
shift as the vault tests relocate; the total must not. A test requiring a rewrite
means the extraction changed behavior, which is a defect and not an expected cost.

New coverage, test-first as the repository does throughout:

| Area | Approach |
|---|---|
| Domain matching | Property tests over the phishing cases in §5; adversarial by default |
| Form detection and fill | jsdom fixtures: two-step logins, hidden honeypots, `autocomplete` hints, React-controlled inputs |
| Save capture | New vs. changed vs. unchanged vs. ignored |
| Lock behavior | Alarm-driven expiry, including the sleeping-machine wall-clock case |
| End-to-end | Playwright with a real Chrome and the extension loaded: unlock, fill, save |

---

## 8. Distribution

Unpacked dev-mode loading during development. For the household, an **unlisted**
Chrome Web Store listing (one-time $5 developer fee), so updates arrive automatically
rather than by manual reinstall. The extension version tracks the server release, and
the existing `.github/workflows/release.yml` builds and attaches the packaged archive.

Note for the record: Firefox, if added later, requires signing through
addons.mozilla.org even for self-hosted distribution. The unlisted option makes this
free and private, but it is not zero-ceremony.

---

## 9. Open items

None. Items deferred by decision are listed under Non-goals (§1) and are out of scope
rather than unresolved.
