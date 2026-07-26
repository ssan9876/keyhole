# Keyhole — Design Spec

**Date:** 2026-07-25
**Status:** Approved
**Milestone:** 1 (of 3)

---

## 1. Overview

Keyhole is a self-hosted, end-to-end-encrypted password manager for a household or
small team. Accounts exist only because an administrator created them; there is no
public registration path. The server stores ciphertext and never possesses a key
capable of decrypting it.

This spec covers **Milestone 1**: crypto core, server, web app (PWA), Proxmox LXC
deployment, and importers. It is the complete, deployable product minus the native
clients.

### Goals

- A vault the server operator cannot read, enforced by cryptography rather than policy.
- Admin-created accounts only; no self-signup endpoint exists in the codebase.
- Shared collections, so a household can share credentials.
- One-command install on a Proxmox LXC; one-word update from inside the container.
- Import from every mainstream password manager, performed entirely client-side.
- A web UI good enough to be the primary client on desktop and phone.

### Non-goals for Milestone 1

- Browser extension (Milestone 2), Android app (Milestone 2), iOS app (Milestone 3).
- TOTP storage, credit cards, identities, file attachments. The item model is
  extensible so these are additive later, not migrations.
- Login-time second factor. Deferred; not required for the crypto design.
- Offline editing. Offline is read-only in v1.
- Email delivery. Invites are handed over out-of-band; SMTP is a later option.

### Later milestones (context only, not specced here)

| Milestone | Contents |
|---|---|
| 2 | Browser extension (Chrome/Edge/Firefox) + Android app with `AutofillService` |
| 3 | iOS app with `ASCredentialProviderExtension` — gated on an Apple Developer account, decision deferred |

---

## 2. Decisions

Settled during design; recorded so they are not relitigated.

| Decision | Choice | Reason |
|---|---|---|
| Build vs. adapt | Fully custom, top to bottom | User's explicit choice after being shown the Vaultwarden alternative and its cost difference |
| Server stack | Go + SQLite (`modernc.org/sqlite`) | Static single binary; makes install/update/backup trivial. Pure-Go driver because cgo would forfeit that |
| Web stack | React + TypeScript + Vite + Tailwind + Radix primitives | Mono is type and spacing, so a heavy component library would fight it |
| Sharing | Shared collections, in v1 | Retrofitting requires re-encrypting every item |
| Access | Cloudflare Tunnel | No open ports, works behind CGNAT. TLS terminates at Cloudflare, which therefore sees request metadata and the auth hash, but no vault plaintext and no key capable of producing it |
| Item types (v1) | Logins, secure notes | Deliberate narrowing |
| Recovery | Recovery code **and** admin reset-and-wipe | Self-service first, destructive last resort |
| Login 2FA | None in v1 | Vault stays E2E encrypted regardless |
| Visual direction | Mono — Swiss, typographic, hairline rules | Selected from four mockups |
| Mobile web | Fully responsive installable PWA | Only phone client until Milestone 2 |
| Name | Keyhole | Repo, CLI command, package id |
| `update` shim | Installed at `/usr/local/bin/update` | Single-purpose container, so claiming the name is acceptable |
| Collection names | Stored plaintext | Admin must manage membership without being a member; the leak is a folder name |

---

## 3. Crypto core

Implemented in `packages/crypto` (TypeScript). The Go server performs **no vault
crypto** — only Argon2id over the auth hash, and `crypto/rand`.

### 3.1 Libraries

- `@noble/curves` (X25519) and `@noble/hashes` (HKDF-SHA256) — audited, dependency-free,
  and avoids the uneven browser support for X25519 in WebCrypto.
- WebCrypto `AES-GCM` for symmetric encryption.
- `hash-wasm` for Argon2id.

### 3.2 Derivation

```
salt        = 16 random bytes, per user, stored server-side
masterKey   = Argon2id(masterPassword, salt, m=64MiB, t=3, p=4, len=32)
wrappingKey = HKDF-SHA256(masterKey, info="keyhole:wrap:v1", len=32)
authHash    = HKDF-SHA256(masterKey, info="keyhole:auth:v1", len=32)
```

`wrappingKey` never leaves the device. `authHash` is the login credential and decrypts
nothing. KDF parameters are stored per user so they can be raised later without a
flag day.

**Prelogin.** `POST /api/auth/prelogin {email}` returns the salt and KDF params. For
an unknown email it returns a deterministic decoy derived as
`HMAC-SHA256(serverSecret, normalizedEmail)`, so the endpoint cannot be used to
enumerate accounts. Response shape and timing are identical in both cases.

**Server-side storage.** The server stores `Argon2id(authHash, serverSideSalt)`, so a
database dump yields neither login ability nor plaintext.

### 3.3 Key hierarchy

```
userKey        32 random bytes — root of the vault
               wrapped by wrappingKey            -> protectedUserKey
               wrapped by recoveryKey        -> recoveryProtectedUserKey

keypair        X25519; public key stored in the clear
               private key wrapped by userKey

itemKey        32 random bytes, one per item
               personal item  -> wrapped by userKey
               collection item-> wrapped by collectionKey

collectionKey  32 random bytes, one per collection
               sealed individually to each member's X25519 public key
```

The `userKey` indirection means changing a master password re-wraps one 32-byte key
instead of re-encrypting the vault.

### 3.4 Ciphertext envelope

All symmetric ciphertext uses one JSON envelope:

```json
{ "v": 1, "alg": "A256GCM", "n": "<base64 96-bit nonce>", "ct": "<base64>" }
```

A fresh random nonce per encryption operation; nonces are never reused with a key.
Item plaintext is a JSON object before encryption:

```json
{
  "type": "login" | "note",
  "name": "GitHub",
  "username": "…",
  "password": "…",
  "urls": ["https://github.com"],
  "notes": "…",
  "favorite": false,
  "folderId": "…" | null,
  "passwordHistory": [{ "password": "…", "changedAt": "…" }]
}
```

Name, URLs, and password history are inside the encrypted blob. Consequently **all
search, sort, and URL matching happen client-side** over the decrypted vault. At
household scale the whole vault is synced and held in memory, so this is not a
performance concern.

### 3.5 Sealing to a user (sharing)

`sealToUser(collectionKey, recipientPublicKey)` is an HPKE-style construction:
ephemeral X25519 keypair, ECDH against the recipient's public key, HKDF-SHA256 to an
AES-256-GCM key, then encrypt. Output carries the ephemeral public key. Only the
recipient's private key — itself wrapped by their `userKey` — can open it.

**Consequence, by design:** the server cannot grant collection access, because it
never holds a `collectionKey`. When an admin adds a member, a `pending_grants` row is
created; the next unlocked client belonging to an existing member of that collection
seals the key to the new member and uploads it. The admin UI shows pending grants
explicitly rather than pretending the grant is instant.

### 3.6 Recovery

At enrollment the client generates a 125-bit recovery code — 25 Crockford Base32
characters, shown as five hyphenated groups of five. The alphabet omits `I`, `L`,
`O`, and `U`, and the client maps those back on input, so a user transcribing the
code by hand cannot lock themselves out by writing `l` for `1`.
`recoveryKey = Argon2id(recoveryCode, recoverySalt)` wraps a second copy of `userKey`.
The code is displayed once and requires an explicit "I have saved this"
acknowledgement. The server never sees it.

Recovery flow: enter email + recovery code → unwrap `userKey` → set a new master
password → re-wrap → issue a new recovery code and invalidate the old.

### 3.7 Admin reset (destructive)

Deletes `protected_user_key`, `recovery_protected_user_key`, the keypair, and all
personal items; revokes collection memberships; returns the account to `pending` with
a fresh invite. The user re-enrolls with a new master password and a new keypair, so
collection access must be re-granted. The confirmation dialog states all of this
explicitly and requires typing the user's email to proceed.

### 3.8 Auto-lock

Default 15 minutes idle; options 1 / 5 / 15 / 30 / 60 minutes, on-close, or never
(with a warning). Lock zeroes `wrappingKey`, `userKey`, decrypted item keys, and the
plaintext cache. The IndexedDB ciphertext cache is retained for offline reads.

### 3.9 Accepted limitations

Documented in the README, not just here.

1. **Public-key substitution.** The server distributes public keys; a compromised
   server could substitute its own to intercept *future* shares. Mitigated by a
   comparable fingerprint shown in the UI. Existing shares are unaffected.
2. **Web app code delivery.** The server serves the JavaScript that handles the
   master password, so a compromised server could serve malicious code. Inherent to
   all browser-delivered E2EE. The Milestone 2 extension is not subject to this,
   which is an argument for making it the primary desktop client.
3. **Metadata.** Item counts, blob sizes, modification times, collection names, and
   the membership graph are visible to the server and to Cloudflare. Item contents,
   names, and URLs are not.
4. **Endpoint compromise.** No defence against a keylogger or a compromised device.

---

## 4. Server

### 4.1 Layout

```
cmd/keyhole/          serve · admin · migrate · backup · restore · update
internal/http/        router, middleware, handlers
internal/auth/        prelogin, login, sessions, rate limiting
internal/store/       SQLite access, migrations (embedded)
internal/admin/       user + collection administration
internal/audit/       audit log
```

Migrations and the built web assets are embedded via `embed.FS`. The production
artifact is one file plus a SQLite database.

### 4.2 Schema

| Table | Columns of note |
|---|---|
| `users` | `id`, `email`, `name`, `role`, `status` (pending/active/disabled), `kdf_salt`, `kdf_params`, `auth_hash`, `protected_user_key`, `recovery_protected_user_key`, `recovery_salt`, `recovery_kdf_params`, `public_key`, `encrypted_private_key`, `revision`, timestamps |
| `invites` | `user_id`, `token_hash`, `expires_at`, `used_at` |
| `sessions` | `user_id`, `token_hash`, `refresh_hash`, `device_label`, `last_seen_at`, `expires_at`, `revoked_at` |
| `items` | `id`, `owner_user_id`, `collection_id` (nullable), `ciphertext`, `wrapped_item_key`, `folder_id`, `revision`, `deleted_at` |
| `folders` | `user_id`, `encrypted_name` |
| `collections` | `id`, `name` (plaintext), `created_by` |
| `collection_memberships` | `collection_id`, `user_id`, `sealed_collection_key`, `role` (member/manager), `granted_by`, `granted_at` |
| `pending_grants` | `collection_id`, `user_id`, `requested_by`, `created_at` |
| `audit_log` | `actor_user_id`, `action`, `target`, `metadata`, `created_at` |
| `server_settings` | `key`, `value` |

Deletes are tombstones (`deleted_at`) so sync can propagate them; a retention job
purges tombstones after 90 days.

**Item `type` is deliberately not a column.** It lives inside the encrypted body, so
the server cannot tell a login from a secure note, or count how many of each a user
holds. Filtering by type happens client-side over the decrypted vault, which is free
at this scale because the whole vault is synced anyway.

**`recovery_kdf_params` is stored separately from `kdf_params`** and is not assumed to
equal it. If an account's KDF parameters are ever raised, the existing recovery blob
was wrapped under the *old* parameters, and deriving the recovery key with the new
ones yields a different key. Recording the parameters the blob was actually made with
is what prevents a correct recovery code from failing — a failure that would surface
only at the moment recovery was the user's last resort.

### 4.3 API

```
POST   /api/auth/prelogin           email -> salt, kdf params (decoy if unknown)
POST   /api/auth/login              email + authHash -> tokens + wrapped keys
POST   /api/auth/refresh
POST   /api/auth/logout

GET    /api/sync?since=<revision>   items, tombstones, collections, memberships
POST   /api/items
PUT    /api/items/:id
DELETE /api/items/:id
POST   /api/items/bulk              import

GET    /api/collections
POST   /api/collections
POST   /api/collections/:id/members
DELETE /api/collections/:id/members/:userId
GET    /api/collections/pending-grants
POST   /api/collections/:id/grants  fulfil pending grants

GET    /api/account
POST   /api/account/password        rotate: new authHash + re-wrapped userKey
POST   /api/account/recovery        regenerate recovery code
GET    /api/account/sessions
DELETE /api/account/sessions/:id

POST   /api/enroll/:token           complete an invite

GET    /api/admin/users
POST   /api/admin/users
PATCH  /api/admin/users/:id         disable / enable
POST   /api/admin/users/:id/reset   destructive
DELETE /api/admin/users/:id
GET    /api/admin/audit

GET    /healthz
```

### 4.4 Sessions

Opaque 256-bit random tokens, SHA-256 hashed at rest. Access token 30 minutes with
sliding expiry; refresh token 30 days. Sessions are listed and individually
revocable by the user and by an admin. The session is independent of vault unlock —
holding a session grants no ability to decrypt.

### 4.5 Hardening

- Per-IP and per-account login rate limits with exponential backoff.
- Identical response body and timing for unknown email and wrong password.
- Constant-time comparison on all token and hash checks.
- `CF-Connecting-IP` is trusted **only** from the tunnel's loopback connection.
  Trusting it unconditionally would make rate limiting bypassable.
- Strict CSP, `X-Content-Type-Options`, `Referrer-Policy: no-referrer`.
- Server secret generated on first run, stored `0600`.

---

## 5. Admin flow

1. Installer runs `keyhole admin create --email <you>` and prints a one-time setup URL.
2. Admin opens it, sets a master password; the client generates `userKey`, keypair,
   and recovery code locally and uploads only wrapped blobs.
3. Admin creates a user (name + email). Account is `pending`; the UI displays a
   one-time invite link to hand over out-of-band. No mail server required.
4. The invitee opens the link, sets their own master password, and receives their own
   recovery code. The account becomes `active`.

There is no self-registration endpoint. Admins have ordinary vaults; an admin cannot
read another user's vault, and that is enforced cryptographically rather than by a
permission check.

### 5.1 Collection roles and permissions

- **Only admins create or delete collections.** This keeps the membership graph, the
  one structure an admin must be able to reason about, from sprawling.
- **`manager`** — may add and remove members of that collection, and fulfils pending
  grants. A collection's creator is its first manager. Managers are members, so they
  hold the `collectionKey`.
- **`member`** — may read, create, edit, and delete items within the collection, but
  cannot change membership.
- Any member may edit any item in a collection; `items.owner_user_id` records who
  created it, for the audit log, and does not confer exclusive rights.
- Removing a member deletes their `sealed_collection_key`. This revokes future
  access but **does not rotate the collection key**, so a removed member who kept a
  copy retains what they already had. Rotating on removal — re-keying every item and
  re-sealing to every remaining member — is deliberately deferred; the admin UI states
  plainly that removal is not retroactive and that shared credentials should be
  changed if the removal is adversarial.

---

## 6. Web app

### 6.1 Structure

```
packages/crypto/     deriveKeys · wrapKey · encryptItem · sealToUser · test vectors
apps/web/            React PWA
```

`packages/crypto` has no React, no network, and no storage — that is what makes it
independently testable and reusable by the Milestone 2 clients.

### 6.2 Screens

Invite enrollment · login and unlock · vault list · item detail and editor ·
password generator · collections · settings (auto-lock, change master password,
sessions, recovery) · admin (users, collections, pending grants, audit) · import.

### 6.3 Key handling rule

Decrypted keys and plaintext live in memory only — never `localStorage`,
`sessionStorage`, or IndexedDB. The IndexedDB cache holds ciphertext only. This is a
code-review gate, not a guideline.

### 6.4 Visual direction — Mono

Swiss and typographic: hairline rules, no decorative shadow or gradient, colour
reserved for meaning (destructive actions, strength indicators, shared badges).
Light and dark themes from one token set; dark is the same layout with inverted
values and hairlines at 12% white. Mobile-first — a list of rule-separated rows is
naturally a good phone layout.

Design tokens live in one file so the warmth dial (paper-white ground and softer
rules versus pure white and black hairlines) is a token change, not a redesign.

Accessibility: full keyboard navigation, visible focus rings, WCAG AA contrast,
labelled form controls, focus-trapped dialogs.

### 6.5 PWA

Web app manifest, service worker, home-screen install, offline read against the
encrypted cache. Offline is read-only in v1.

---

## 7. Import

Entirely client-side: parse → map → encrypt → upload ciphertext. Plaintext never
reaches the server.

**Formats:** Bitwarden (json, csv), LastPass, 1Password (1pux, csv), Chrome / Edge /
Brave, Firefox, Safari, Dashlane (csv, json), KeePass and KeePassXC, NordPass,
Proton Pass, Keeper, plus a generic CSV with manual column mapping.

**Flow:** upload → auto-detect format → map columns → preview with duplicate
detection → import → completion screen instructing the user to delete the export
file. That last step matters: an unencrypted CSV of every password sitting in
Downloads is the most likely real-world compromise of this system.

Rows are all-or-nothing individually, with a per-row error report; a malformed row
cannot produce a half-encrypted record.

---

## 8. Deployment

### 8.1 Install

Run on the Proxmox host shell (`OWNER` is the GitHub account the repo is published
under, and `VERSION` the release tag — both fixed at first release, not open
questions):

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/OWNER/keyhole/VERSION/scripts/install.sh)"
```

Steps: verify it is running on a PVE host → prompt for CTID, hostname, cores, RAM,
disk, storage, bridge (flags available for every prompt) → create an unprivileged
Debian 12 container → install the verified binary, a `keyhole` service user, a
systemd unit, `/var/lib/keyhole`, `/etc/keyhole/config.yml` → install `cloudflared`
and register the tunnel token as a service → run `keyhole admin create` → print the
setup URL and next steps.

**Supply-chain handling.** Piping a script to a shell is the risk this product exists
to defend against, so: the URL pins a release tag rather than `main`; the installer
verifies the binary against a published SHA-256 and a minisign signature before
installing; and it prints its plan before acting. The README leads with the
download-inspect-run two-step and presents the one-liner as the convenience option.

### 8.2 Update

`keyhole update`, plus a `/usr/local/bin/update` shim so bare `update` works:

1. Check the release feed; show current → new plus changelog.
2. Download binary and signature; **verify** before proceeding.
3. Snapshot the database (`VACUUM INTO`).
4. Stop service → atomically swap the binary (write-temp-then-rename) → run
   migrations → start.
5. Poll `/healthz`. **On failure, automatically roll back** binary and database, and
   report that it did so.

`keyhole update --check` dry-runs it.

### 8.3 Backup

`keyhole backup` writes a timestamped `VACUUM INTO` snapshot; a nightly systemd timer
with configurable retention. `keyhole restore <file>` reverses it. The snapshot is
entirely ciphertext, so it can be replicated off-box — including somewhere not fully
trusted — without exposing a password.

---

## 9. Error handling

- Uniform envelope `{"error": {"code": "...", "message": "..."}}` with stable codes.
- **Sync conflicts never silently lose data.** Concurrent edits produce a conflicted
  copy for the user to resolve rather than a last-writer-wins overwrite.
- **Unlock failure is honestly worded.** A GCM tag mismatch cannot distinguish a wrong
  password from a corrupt blob; the message says wrong master password and links to
  recovery rather than inventing certainty.
- Logs never contain ciphertext, tokens, or email addresses above debug level.
  Structured `slog` with request IDs.
- The client distinguishes network, authentication, and decryption failures in what
  it tells the user; a network blip must never read as a wrong password.

---

## 10. Testing

Written test-first.

- **`packages/crypto`:** pinned known-answer vectors as JSON for Argon2id, HKDF,
  AES-GCM, and X25519 sealing; round-trip property tests. These vectors are the
  contract the future Kotlin and Swift ports are proven against.
- **Go:** store and auth unit tests; `httptest` integration across the API; migration
  up/down tests.
- **Security tests:** user-enumeration parity on prelogin and login; rate-limit
  behaviour; session revocation; and an assertion that no admin endpoint can return
  another user's wrapped keys.
- **Importers:** golden-file tests against a real sample export of every supported
  format.
- **E2E (Playwright):** admin bootstrap → invite → set master password → add item →
  share to a collection → second user unlocks and sees it → recovery-code restore →
  admin reset-and-wipe.
- **Update:** rollback verified by pointing the updater at a deliberately broken
  binary and asserting the service returns healthy.
- **CI:** GitHub Actions builds static binaries and publishes releases with checksums
  and signatures.
