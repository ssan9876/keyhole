# Keyhole Recovery-Code Redemption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the recovery code actually work — enter your email and your 25-character code, set a new master password, get back into your vault.

**Architecture:** The recovery code becomes a second credential with the same shape as the master password. Today `recoveryKey = Argon2id(code, salt)` wraps the userKey directly, with nothing the server can check; this plan splits that key by HKDF into a *wrap* half and an *auth* half — exactly as `deriveWrapKey`/`deriveAuthHash` already split the master key — so the server can verify possession of the code before handing back a blob, and the enumeration defence stays identical to prelogin's. Three new unauthenticated endpoints mirror `prelogin` → `login` → rotate.

**Tech Stack:** Go 1.25 (`modernc.org/sqlite`, stdlib `net/http`), `packages/crypto` (hash-wasm Argon2id, `@noble/hashes` HKDF), React 19 in `apps/web`.

## Why this exists

Design spec §3.6 describes the flow: *"enter email + recovery code → unwrap `userKey` → set a new master password → re-wrap → issue a new recovery code and invalidate the old."* **None of it is implemented.** `POST /api/account/recovery` only rotates the blob for a user who is already authenticated. No endpoint returns `recovery_protected_user_key` to someone who cannot log in.

So the product shows every new user a code, tells them to save it somewhere safe, and cannot redeem it. The enrolment screen and the README currently say so out loud. This plan is what lets them stop saying it.

## Global Constraints

- **The new prelogin must be indistinguishable for an unknown address.** `auth.DecoySalt(s.secret, normalizedEmail)` is the existing deterministic decoy, and `auth.DefaultKDFParamsJSON` the decoy params. Any difference — a 404, a different field set, a different salt length, a different params string — turns the endpoint into an account-enumeration oracle. This is the single most important constraint in the plan.
- **A recovery blob made before this plan cannot be redeemed.** It was wrapped under the undifferentiated `recoveryKey` and no auth hash was ever stored. `recovery_auth_hash IS NULL` marks those, and they must be treated exactly like an unknown address by the prelogin endpoint — *not* answered with a real salt and then rejected later, which would leak that the account exists.
- **`recoveryAuthHash` is stored hashed**, via `auth.HashAuthHash`, exactly as `auth_hash` is. A database leak must not hand over a directly replayable credential.
- **Rate-limit the redeem endpoint on the account, not only the IP.** 125 bits of recovery code is not brute-forceable, but the endpoint performs a database lookup and a hash per call.
- **Completing a recovery revokes every session.** Someone who just proved they lost their password should not leave a stale session alive on a device they may no longer control.
- KDF parameter pinning still applies to the new master password: `params` must be byte-equal to `auth.DefaultKDFParamsJSON`. `recoveryKdfParams` remains unpinned, for the reason `internal/httpapi/account.go:122` gives.
- New crypto goes in `packages/crypto` with **pinned test vectors** — `packages/crypto/vectors/vectors.json` is the contract the future Kotlin and Swift ports are proven against, and a derivation with no vector is a derivation those ports will get wrong.
- `src/ui/**` must never import `@keyhole/crypto`; the ban fires on type-only imports.
- Every task ends with a mutation check: break it, watch the named test fail, revert, put the output in the report. **This repository has now produced eight prescribed mutations that did not fail**, each a real hole — if one does not fail, say so plainly and fix the test.
- Go: `go build ./... && go vet ./... && gofmt -l . && go test ./...` clean. `gofmt -l` prints offending files and exits 0 — its *output* is the signal.
- `go` may not be on PATH; it is at `C:\Program Files\Go\bin\go.exe`.

## Verification commands

```bash
export PATH="$PATH:/c/Program Files/Go/bin"
go build ./... && go vet ./... && gofmt -l . && go test ./...
cd apps/web && pnpm -r test && pnpm typecheck && pnpm lint
cd apps/web && pnpm test:e2e
```

---

## File Structure

**Created:**

| Path | Responsibility |
|---|---|
| `internal/store/migrations/0004_recovery_auth.sql` | `recovery_auth_hash` column |
| `internal/httpapi/recover.go` | The three endpoints |
| `internal/httpapi/recover_test.go` | Including the enumeration-parity tests |
| `apps/web/src/vault/recover.ts` | Client flow |
| `apps/web/src/vault/recover.test.ts` | |
| `apps/web/src/ui/screens/RecoverScreen.tsx` | |
| `apps/web/src/ui/screens/RecoverScreen.test.tsx` | |

**Modified:**

| Path | Change |
|---|---|
| `packages/crypto/src/recovery.ts` | HKDF split; `createRecoveryBlob` returns an auth hash |
| `packages/crypto/scripts/generate-vectors.ts`, `vectors/vectors.json` | New pinned vectors |
| `internal/store/account.go` | `RecoveryRotation` carries the auth hash |
| `internal/store/enroll.go` | Enrolment stores it |
| `internal/store/users.go` | Scan the new column |
| `internal/httpapi/enroll.go`, `account.go` | Accept `recoveryAuthHash` |
| `internal/httpapi/server.go` | Three routes |
| `apps/web/src/vault/enroll.ts`, `account.ts` | Send the auth hash |
| `apps/web/src/ui/screens/UnlockScreen.tsx` | "Forgot your master password?" |
| `apps/web/src/ui/App.tsx` | Route to the recovery screen |
| `apps/web/src/ui/screens/EnrolScreen.tsx`, `README.md` | Drop the "not implemented" caveat |

---

## Task 1: Split the recovery key

**Files:** Modify `packages/crypto/src/recovery.ts`; test `packages/crypto/src/recovery.test.ts`

**Produces:**
```ts
function deriveRecoveryWrapKey(recoveryKey: Uint8Array): Uint8Array
function deriveRecoveryAuthHash(recoveryKey: Uint8Array): Uint8Array
interface RecoveryBlob { recoverySalt; recoveryProtectedUserKey; recoveryAuthHash: Uint8Array; params }
```

`createRecoveryBlob` wraps under the **wrap half** and returns the auth half. `recoverUserKey` unwraps with the wrap half.

- [ ] **Step 1: Write the failing tests**

```ts
it("derives a wrap key and an auth hash that are different from each other and from the recovery key", async () => {
  const key = await deriveRecoveryKey("ABCDE-FGHJK-MNPQR-STVWX-YZ123", salt, DEFAULT_KDF_PARAMS);
  const wrap = deriveRecoveryWrapKey(key);
  const auth = deriveRecoveryAuthHash(key);
  expect(wrap).not.toEqual(auth);
  expect(wrap).not.toEqual(key);
  expect(auth).not.toEqual(key);
  expect(wrap.length).toBe(32);
  expect(auth.length).toBe(32);
});

it("round-trips the userKey through a blob and its code", async () => {
  const userKey = generateUserKey();
  const code = generateRecoveryCode();
  const blob = await createRecoveryBlob(userKey, code, DEFAULT_KDF_PARAMS);
  await expect(recoverUserKey(blob.recoveryProtectedUserKey, code, blob.recoverySalt, blob.params))
    .resolves.toEqual(userKey);
});

it("produces an auth hash the blob cannot be opened with", async () => {
  // The whole point of the split: the value sent to the server must not be
  // the value that unwraps the key. If it were, the server could open every
  // vault whose owner ever redeemed a code.
  const blob = await createRecoveryBlob(userKey, code, DEFAULT_KDF_PARAMS);
  await expect(unwrapKey(blob.recoveryProtectedUserKey, blob.recoveryAuthHash)).rejects.toThrow();
});

it("rejects a wrong recovery code", async () => { /* different code -> DecryptionError */ });

it("derives the same values from the same code and salt, twice", async () => { /* determinism */ });
```

- [ ] **Step 2: Run to verify failure**

```bash
cd packages/crypto && pnpm vitest run src/recovery.test.ts
```

- [ ] **Step 3: Implement**

In `recovery.ts`, mirroring `kdf.ts`'s `expand`:

```ts
const RECOVERY_WRAP_INFO = utf8Encode("keyhole:recovery-wrap:v1");
const RECOVERY_AUTH_INFO = utf8Encode("keyhole:recovery-auth:v1");

function expandRecovery(recoveryKey: Uint8Array, info: Uint8Array): Uint8Array {
  if (recoveryKey.length !== 32) {
    throw new InvalidKeyError(`Recovery key must be 32 bytes, received ${recoveryKey.length}`);
  }
  return hkdf(sha256, recoveryKey, undefined, info, 32);
}

/** Unwraps the userKey. Never leaves the device. */
export function deriveRecoveryWrapKey(recoveryKey: Uint8Array): Uint8Array {
  return expandRecovery(recoveryKey, RECOVERY_WRAP_INFO);
}

/**
 * Sent to the server as proof the caller holds the code. Decrypts nothing.
 *
 * The split is what makes remote redemption safe: without it the only value
 * derivable from the code is the one that opens the blob, so proving
 * possession to the server would mean handing the server the key.
 */
export function deriveRecoveryAuthHash(recoveryKey: Uint8Array): Uint8Array {
  return expandRecovery(recoveryKey, RECOVERY_AUTH_INFO);
}
```

`createRecoveryBlob` derives both, wraps under the wrap half, returns `recoveryAuthHash`, and zeroizes the recovery key and the wrap half in a `finally`. `recoverUserKey` unwraps with `deriveRecoveryWrapKey`.

- [ ] **Step 4: Run the tests** — `pnpm vitest run src/recovery.test.ts`

- [ ] **Step 5: Mutation check**

Make `createRecoveryBlob` wrap under the raw `recoveryKey` instead of the wrap half. "round-trips the userKey through a blob and its code" must fail. Then make `deriveRecoveryAuthHash` return the wrap key: "produces an auth hash the blob cannot be opened with" must fail. Revert both.

- [ ] **Step 6: Commit**

```bash
git add packages/crypto/src/recovery.ts packages/crypto/src/recovery.test.ts
git commit -m "feat(crypto): split the recovery key into a wrap half and an auth half"
```

---

## Task 2: Pin the new derivations as vectors

`packages/crypto/vectors/vectors.json` is the contract the future Kotlin and Swift clients are proven against. A derivation with no vector is one those ports will get wrong, and the failure appears as "your recovery code does not work on your phone".

**Files:** Modify `packages/crypto/scripts/generate-vectors.ts`, `vectors/vectors.json`, `src/vectors.test.ts`

- [ ] **Step 1:** Read all three first. Follow the existing entry shape exactly — do not invent a new one.
- [ ] **Step 2:** Add a `recoverySplit` case: a fixed code, a fixed salt, fixed params, and the expected `wrapKey`, `authHash`, and `recoveryProtectedUserKey` for a fixed userKey. Every input hex/base64 must be a literal, never computed at test time — a vector that computes its own expectation asserts nothing.
- [ ] **Step 3:** Regenerate, then **read the diff**. Confirm only additions.
- [ ] **Step 4: Mutation** — change one byte of the expected `authHash` in `vectors.json`; the vector test must fail. Revert.
- [ ] **Step 5:** Commit: `test(crypto): pin the recovery key split as cross-client vectors`

---

## Task 3: The `recovery_auth_hash` column

**Files:** Create `internal/store/migrations/0004_recovery_auth.sql`; modify `internal/store/users.go`, `account.go`, `enroll.go`; tests alongside.

```sql
-- A recovery blob created before this migration was wrapped under the
-- undifferentiated recovery key, with no auth hash to check, so it cannot be
-- redeemed remotely. NULL marks exactly those, and the redeem endpoints treat
-- a NULL here identically to an unknown address.
ALTER TABLE users ADD COLUMN recovery_auth_hash TEXT;
```

- [ ] **Step 1:** Write the failing tests — the migration applies; `RecoveryRotation` round-trips the auth hash; enrolment stores it; **an incomplete payload is rejected** (`validate()` must require the auth hash alongside the other three recovery fields, or a client could store a blob nothing can ever redeem).
- [ ] **Step 2:** Run: `go test ./internal/store/`
- [ ] **Step 3:** Implement. `RecoveryRotation` gains `RecoveryAuthHash string`; `validate()` requires it; `RotateRecovery` writes it; `users.go`'s column list and scan gain it as `sql.NullString`; `enroll.go` stores it.
- [ ] **Step 4:** Run again, plus `go test ./...`
- [ ] **Step 5: Mutation** — drop the auth hash from `validate()`'s required set. The incomplete-payload test must fail. Revert.
- [ ] **Step 6:** Commit: `feat(store): record a recovery auth hash so a code can be checked`

---

## Task 4: `POST /api/auth/recover/prelogin`

**This is the enumeration-critical endpoint.** Model it on `handlePrelogin` (`internal/httpapi/auth.go:44`) line by line.

**Files:** Create `internal/httpapi/recover.go`, `recover_test.go`; modify `server.go`.

- [ ] **Step 1: Write the failing tests**

```go
// The test that matters most in this plan.
func TestRecoverPreloginAnswersIdenticallyForUnknownAndRedeemableAccounts(t *testing.T)
// Same status, same field set, same salt length, same params string. Compare
// the whole decoded body shape, not just one field.

func TestRecoverPreloginAnswersAnOldFormatBlobLikeAnUnknownAddress(t *testing.T)
// recovery_auth_hash IS NULL. Answering with the real salt and rejecting
// later would leak that the account exists.

func TestRecoverPreloginIsDeterministicForTheSameUnknownAddress(t *testing.T)
// Two calls, byte-identical bodies. A random decoy per call is a tell.

func TestRecoverPreloginReturnsTheRealSaltAndParamsForARedeemableAccount(t *testing.T)
func TestRecoverPreloginIsRateLimited(t *testing.T)
```

- [ ] **Step 2:** Run to verify failure.
- [ ] **Step 3:** Implement, reusing `s.preloginLimiter`, `auth.DecoySalt(s.secret, normalized)`, and `auth.DefaultKDFParamsJSON`. The real branch requires `user.Status == "active"` **and** `user.RecoveryAuthHash.Valid` **and** the salt and params valid.

  For `recoveryKdfParams` on the decoy path, return `auth.DefaultKDFParamsJSON` — it is what a blob made today records, so it is the honest decoy.

- [ ] **Step 4:** Run the tests.
- [ ] **Step 5: Mutation** — return 404 when the account is unknown. The parity test must fail. Then make the real branch ignore `RecoveryAuthHash.Valid`: the old-format test must fail. Revert both.
- [ ] **Step 6:** Commit: `feat(api): recovery prelogin, decoyed exactly like login's`

---

## Task 5: `POST /api/auth/recover` and `/complete`

**Files:** Modify `internal/httpapi/recover.go`, `recover_test.go`, `server.go`; add a short-lived token to `internal/store`.

**Shape:**

`POST /api/auth/recover {email, recoveryAuthHash}` → 200 `{recoveryProtectedUserKey, encryptedPrivateKey, recoveryToken, expiresIn}`, or 401 with the same body shape and timing as a wrong code. Rate-limited on **both** the account and the IP.

`POST /api/auth/recover/complete {recoveryToken, kdfSalt, params, authHash, protectedUserKey, recoverySalt, recoveryKdfParams, recoveryProtectedUserKey, recoveryAuthHash}` → 204. Single-use token. Revokes every session.

- [ ] **Step 1: Write the failing tests**

```go
func TestRecoverReturnsTheBlobsForACorrectRecoveryAuthHash(t *testing.T)
func TestRecoverRejectsAWrongRecoveryAuthHash(t *testing.T)
func TestRecoverRejectsAnAccountWithNoRecoveryAuthHash(t *testing.T)
func TestRecoverNeverReturnsTheProtectedUserKeyWrappedByTheMasterPassword(t *testing.T)
// Use the normalizing assertion from helpers_test.go. The master-password
// blob has no business on this path, and Go marshals untagged structs in
// PascalCase, which is how the same class of test failed before.

func TestRecoverCompleteRotatesBothCredentialsAndRevokesEverySession(t *testing.T)
func TestRecoverCompleteRejectsAReusedToken(t *testing.T)
func TestRecoverCompleteRejectsAnExpiredToken(t *testing.T)
func TestRecoverCompletePinsTheKDFParams(t *testing.T)
// Byte-equality against auth.DefaultKDFParamsJSON, for the same enumeration
// reason the other two rotation endpoints pin it.
func TestRecoverCompleteRejectsATokenForADifferentUser(t *testing.T)
```

- [ ] **Step 2:** Run to verify failure.
- [ ] **Step 3:** Implement. Reuse the invite-token shape in `internal/store/invites.go` — a hashed, single-use, expiring token — rather than inventing a second mechanism. TTL 10 minutes: long enough to type a password twice, short enough that a token left in a closed laptop is not a spare key.

  Verify with `auth.VerifyAuthHash(req.RecoveryAuthHash, user.RecoveryAuthHash.String)`. Record an audit entry on success.

- [ ] **Step 4:** Run, plus `go test ./...`
- [ ] **Step 5: Mutation** — make the token reusable (skip consuming it): the reuse test must fail. Then skip the session revocation: that test must fail. Then drop the params pinning: that test must fail. Revert all three.
- [ ] **Step 6:** Commit: `feat(api): redeem a recovery code and rotate both credentials`

---

## Task 6: Send the auth hash from the existing client paths

Enrolment and the settings "new recovery code" button both create blobs. Both must now upload the auth hash, or a code created after this plan is as unredeemable as one created before it.

**Files:** Modify `apps/web/src/vault/enroll.ts`, `account.ts`, and their tests.

- [ ] **Step 1:** Failing tests — both paths send `recoveryAuthHash`, and it is `toBase64(blob.recoveryAuthHash)`, recomputed in the test from the returned code rather than read back from the request.
- [ ] **Step 2–4:** Implement and run.
- [ ] **Step 5: Mutation** — drop the field from the enrolment payload; its test must fail. Revert.
- [ ] **Step 6:** Commit: `feat(web): upload the recovery auth hash when a code is issued`

---

## Task 7: The client recovery flow

**Files:** Create `apps/web/src/vault/recover.ts`, `recover.test.ts`.

**Produces:**
```ts
class WrongRecoveryCodeError extends Error {}
async function recoverAccount(deps: {api}, input: {email; recoveryCode}): Promise<RecoverySession>
// RecoverySession holds the recovered userKey and privateKey in memory and a token.
async function completeRecovery(deps: {api}, session: RecoverySession, newMasterPassword: string): Promise<string>
// Returns the NEW recovery code, shown once.
```

Steps: recover-prelogin → `deriveRecoveryKey` → `deriveRecoveryAuthHash` → POST recover → `recoverUserKey` with the wrap half → unwrap `encryptedPrivateKey` with the userKey → `rotateMasterPassword` → new `createRecoveryBlob` → POST complete.

- [ ] **Step 1: Failing tests**

```ts
it("recovers the userKey the blob was made from", async () => { /* byte equality */ });
it("reports a wrong code as a wrong code, not a server error", async () => {
  // Design spec 9. A 401 here means the code is wrong; a NetworkError must
  // read as a connection problem.
});
it("reports an unreachable server as a connection problem", async () => { /* not /code/i */ });
it("sends the pinned params verbatim on complete", async () => {
  expect(body["params"]).toBe(DEFAULT_KDF_PARAMS_JSON);
});
it("never sends the recovery code, in grouped or ungrouped form", async () => { /* both */ });
it("re-wraps the SAME userKey under the new master password", async () => {
  // Unwrap the uploaded protectedUserKey with a wrap key derived from the new
  // password and the uploaded salt; compare to the recovered userKey. A
  // regenerated userKey would orphan every item in the vault.
});
it("returns a new code that opens the new blob", async () => { /* recoverUserKey end to end */ });
```

Argon2id at 64 MiB is ~0.5s per derivation and this flow runs three. Use 30s timeouts. **Do not lower the parameters.**

- [ ] **Step 2–4:** Implement and run.
- [ ] **Step 5: Mutation** — pass a fresh `generateUserKey()` to `rotateMasterPassword`. The re-wrap test must fail while the others pass. Revert.
- [ ] **Step 6:** Commit: `feat(web): redeem a recovery code and set a new master password`

---

## Task 8: The recovery screen

**Files:** Create `apps/web/src/ui/screens/RecoverScreen.tsx` and its test; modify `UnlockScreen.tsx`, `App.tsx`, `EnrolScreen.tsx`.

Three steps in one screen: email + code → new password + confirm → the new code, behind the same "I have saved this" acknowledgement as enrolment, cleared from component state on acknowledgement.

- **Copy that must be honest:** the screen states up front that recovery replaces the master password and **signs out every other device**. It also states that a wrong code cannot be distinguished from an account that has none — because the endpoint deliberately answers identically.
- **`UnlockScreen`** gains a "Forgot your master password?" link. **`EnrolScreen`** loses the "redeeming this code is not built yet" paragraph added earlier — check the exact wording in the file rather than assuming.
- The mismatch check on the new password runs **before** any Argon2id.
- Watch the label trap: this screen has "Recovery code", "New master password", "Confirm new master password". `getByLabelText(/code/i)` and `/password/i` are both ambiguous. Use exact strings.

- [ ] **Steps 1–4:** TDD as above; include a test that the new code is cleared from state on acknowledgement, and one that a wrong code shows the wrong-code message rather than a server error.
- [ ] **Step 5: Mutation** — collapse the error branches to one message; the network-error test must fail. Revert.
- [ ] **Step 6:** Commit: `feat(web): a recovery screen reachable from unlock`

---

## Task 9: End to end, and stop saying it does not work

**Files:** Create `apps/web/e2e/recovery.spec.ts`; modify `README.md`.

- [ ] **Step 1:** One journey against the real server: enrol → save the code → add an item with a distinctive password → **lock and reload** → "Forgot your master password?" → email + code → new master password → land in the vault → **the item's password is still readable**. That last assertion is the point: it proves the same userKey survived the rotation.
- [ ] **Step 2:** A second test: an unknown address and a real address produce **byte-identical** `recover/prelogin` responses. This is the enumeration property, and only a real server can demonstrate it.
- [ ] **Step 3:** Run. Expect the first run to fail and expect at least one failure to be an application bug. Fix the application, not the assertion — unless the assertion is wrong, in which case say so and why.
- [ ] **Step 4:** Update `README.md` §6: recovery now works. State what it does — replaces the master password, issues a new code, signs out every other device — and that codes issued **before** this change cannot be redeemed and should be regenerated from Settings. Verify against the code, not this plan.
- [ ] **Step 5:** Commit: `test(web): end-to-end recovery, and a README that no longer disclaims it`

---

## Task 10: Final pass

- [ ] Full verification: Go, `pnpm -r test`, typecheck, lint, e2e.
- [ ] Confirm `localStorage` still holds at most `keyhole.email` and `keyhole.autolock` — the recovery flow must not persist a token or a code. The e2e storage assertion added in the previous plan covers this; extend it to run after a recovery.
- [ ] Confirm the ESLint crypto-import ban still fires on the new `.tsx` file — probe it, do not assume. A `.ts` probe proves nothing about `.tsx`.
- [ ] Report anything that failed rather than fixing it silently.

---

## Self-review

**Spec coverage.** §3.6's flow → Tasks 4–8. §3.6's "invalidate the old" → Task 5's complete endpoint uploading a new blob. §4.2's separate `recovery_kdf_params` → preserved, still unpinned. §9's honest failure wording → Tasks 7–8. §10's enumeration-parity security test → Tasks 4 and 9.

**Deliberately not covered.** Recovery for an account whose blob predates this plan — it cannot be, since no auth hash was ever stored; Task 9's README change tells those users to regenerate. Admin-assisted recovery — that is the existing destructive reset, unchanged.

**The risk this plan carries.** It adds an unauthenticated endpoint that returns wrapped key material to anyone who can prove possession of a code. The defences are: 125 bits of entropy in the code, Argon2id at 64 MiB between the code and the auth hash, a hashed auth hash server-side, rate limiting on both account and IP, and answering an unknown address identically to a known one. Task 4's parity test and Task 9's e2e are what keep the last of those honest.
