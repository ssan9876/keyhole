# @keyhole/crypto

Every cryptographic operation Keyhole performs on the client. No React, no
network, no storage — that is what makes it independently testable and reusable
by the Milestone 2 Kotlin and Swift clients.

The server performs **no vault crypto**. It stores ciphertext and never holds a
key capable of decrypting it.

`src/index.ts` is eleven `export *` lines and teaches you nothing about
ordering. This file is the ordering.

---

## Conventions

**Arguments are key-last.** `encryptBytes(plaintext, key)`,
`wrapKey(keyToWrap, wrappingKey)`, `encryptItem(item, parentKey)`,
`sealToUser(secret, recipientPublicKey)`. Every argument is a `Uint8Array`, so
the compiler cannot catch a transposition — the convention is the only defence.

**A `WithNonce` or `WithEphemeral` suffix means "never call this in
production".** See [Deterministic variants](#deterministic-variants-test-only).

**Nothing here persists anything.** Every function returns values; storing them,
and clearing them at lock time, is the application's job.

---

## Enrollment

Setting a master password for the first time — a new admin, or an invitee
completing an invite.

```ts
import { enrollUser, createRecoveryBlob, generateRecoveryCode } from "@keyhole/crypto";

const enrolled = await enrollUser(masterPassword);
// -> kdfSalt, params, authHash, protectedUserKey, publicKey,
//    encryptedPrivateKey  ... plus userKey and keyPair, in-memory only.

const recoveryCode = generateRecoveryCode();          // show once, get an ack
const recovery = await createRecoveryBlob(
  enrolled.userKey,
  recoveryCode,
  enrolled.params,                                     // required, not defaulted
);
// -> recoverySalt, recoveryProtectedUserKey, params
```

Upload: `kdfSalt`, `params`, `authHash`, `protectedUserKey`, `publicKey`,
`encryptedPrivateKey`, `recoverySalt`, `recoveryProtectedUserKey`, and
`recovery.params` as **`recoveryKdfParams`**.

That last name is the *wire* field. `POST /api/enroll/{token}` rejects unknown
fields, so sending the database column name — `recovery_kdf_params`, which is
what spec §4.2 calls it — gets you a 400 and no account. The column and the
JSON field are spelled differently on purpose; only the JSON spelling ever
leaves the client.

### `params` goes on the wire as a string

`enrollUser` and `createRecoveryBlob` return `params` as a `KdfParams` **object**,
but the server stores it as an opaque TEXT column and hands it back verbatim at
prelogin. The wire representation is a JSON-encoded **string**, not a nested
object:

```ts
// Enrollment and password rotation: send the pinned constant verbatim.
body.params            = DEFAULT_KDF_PARAMS_JSON;
// recoveryKdfParams is NOT pinned — stringify the params you actually used.
body.recoveryKdfParams = JSON.stringify(recovery.params);

// Prelogin: parse on the way back in.
const { kdfSalt, params } = await preloginResponse.json();
const session = await beginUnlock(masterPassword, kdfSalt, JSON.parse(params));
```

The server never parses the contents, so it will happily store `"[object Object]"`
and give it back to you months later, at unlock, when the vault is the only copy
of anything.

### `params` must be `DEFAULT_KDF_PARAMS_JSON`, not a stringified object

`POST /api/enroll/:token` and `POST /api/account/password` **reject** a `params`
value that is not byte-equal to the server's default, with a 400. This is not
pedantry: prelogin answers an address with no account using that exact string,
so the first account whose params serialize differently makes itself
enumerable — ask prelogin for an address, compare the field, learn whether
someone is registered here.

`JSON.stringify(DEFAULT_KDF_PARAMS)` happens to produce the right bytes today,
because the object literal is declared in that key order. That is a coincidence
one reordering away from a 400 nobody can explain. Send the constant:

```ts
import { DEFAULT_KDF_PARAMS_JSON } from "@keyhole/crypto";

body.params = DEFAULT_KDF_PARAMS_JSON; // not JSON.stringify(...)
```

Raising the parameters is therefore a deliberate server-side migration that
forces re-derivation at next login, not a per-client choice.

Never upload: `userKey`, `keyPair.privateKey`, the master password, or the
recovery code.

> **The recovery code is a separate call, and nothing warns you.**
> `enrollUser` completes successfully without it and returns a fully usable
> vault. Skip `createRecoveryBlob` and the user simply has no recovery path —
> discovered months later, when they have forgotten their master password and
> the only remaining option is the destructive admin reset. If your enrollment
> screen can reach a success state without having called `createRecoveryBlob`,
> that is a bug.

### Persist the params, always

`enrollUser`, `rotateMasterPassword` and `createRecoveryBlob` all return the
`params` they used. Store them next to the salt they belong to.

Spec §4.2 keeps `recovery_kdf_params` in its own column and does **not** assume
it equals `kdf_params`. If an account's params are ever raised, the existing
recovery blob was wrapped under the *old* ones, and deriving with the new ones
produces a different key. That is why `createRecoveryBlob`, `recoverUserKey` and
`deriveRecoveryKey` take `params` as a required argument: a caller forced to
state which params it used is a caller that has them to persist.

---

## Login and unlock

The protocol (spec §4.3) is `POST /api/auth/login` with `email + authHash`; the
response carries the tokens **and** the wrapped keys. So the client must produce
the auth hash *before* it holds the blobs. `beginUnlock` derives once and hands
back a session:

```ts
import { beginUnlock } from "@keyhole/crypto";

// 1. POST /api/auth/prelogin {email} -> kdfSalt, params
const session = await beginUnlock(masterPassword, kdfSalt, params);

try {
  // 2. POST /api/auth/login {email, authHash: session.authHash}
  //    -> tokens, protectedUserKey, encryptedPrivateKey
  const { userKey, privateKey } = await session.finish(
    protectedUserKey,
    encryptedPrivateKey,
  );
  // 3. userKey and privateKey are yours until lock.
} finally {
  session.destroy();   // zeroizes the masterKey and wrappingKey it holds
}
```

Call `destroy()` on every path, including a failed login. `finish` after
`destroy` throws a `KeyholeCryptoError` rather than deriving from zeroed bytes —
which would otherwise surface as a `DecryptionError` and read to the user as a
wrong password.

Running Argon2id twice for one login costs an extra second or more on a phone,
on the exact screen where the user is already waiting. That is what the session
exists to avoid; do not reach for a one-shot convenience wrapper.

### Rotation and recovery

```ts
// Change master password. The userKey is unchanged, so nothing is re-encrypted.
const rotated = await rotateMasterPassword(newPassword, userKey);
// -> kdfSalt, params, authHash, protectedUserKey

// Recover with the code. params MUST be the account's recovery_kdf_params.
const recoveredUserKey = await recoverUserKey(
  recoveryProtectedUserKey,
  codeAsTyped,          // normalized for you: case, spaces, hyphens, I/L/O
  recoverySalt,
  recoveryKdfParams,
);
```

After a successful recovery: set a new master password, re-wrap, issue a new
recovery code, and invalidate the old one.

---

## Errors

Every failure this package can raise is a `KeyholeCryptoError`. Catching that
one type is sufficient; it is a promise, and the test suite holds it.

| Type | Means | What the caller should do |
|---|---|---|
| `DecryptionError` | AEAD verification failed, or a decrypted item did not have a valid shape | Show "wrong master password" and link to recovery. **Do not** claim more: a GCM tag mismatch cannot distinguish a wrong key from a corrupt blob, and the error deliberately carries no detail |
| `MalformedEnvelopeError` | Stored ciphertext is not a well-formed envelope or sealed key — bad JSON, unknown version or algorithm, missing field, invalid base64 | Data corruption or a server bug, not a user error. Report it as such; retrying with the same blob will not help |
| `InvalidKeyError` | Key material is the wrong length — a 16-byte AES key, a nonce that is not 96 bits, a salt that is not 16 bytes | A programming error or attacker-supplied data. **Never** show a lock screen for this; it is not a wrong password |
| `InvalidRecoveryCodeError` | The recovery code is not 25 Crockford characters, or contains a character outside the alphabet | Inline validation on the recovery form, before any Argon2id work |

`decryptItem` raises `DecryptionError` for a well-decrypted body of the wrong
shape, deliberately: the caller's recovery is identical either way — the item
cannot be shown — so a separate type would buy nothing. The check itself is not
optional, because `parentKey` can be attacker-chosen (see limitation 1).

---

## Deterministic variants (test only)

> **`encryptBytesWithNonce` and `sealToUserWithEphemeral` are for tests and
> vector generation only. Calling either in production is a vulnerability, not
> a style problem.**
>
> `encryptBytesWithNonce` lets the caller supply the AES-GCM nonce. Reusing a
> nonce with a key destroys the confidentiality *and* the integrity of every
> message under that key. `sealToUserWithEphemeral` lets the caller supply the
> ephemeral X25519 private key; reusing one across seals breaks the
> construction.
>
> **The `WithNonce` / `WithEphemeral` suffix is the package's naming convention
> for "this hands you a knob that randomness should be turning".** If a new
> function needs a deterministic variant, name it the same way. If you are
> reading a call site and see either suffix outside a test or
> `scripts/generate-vectors.ts`, it is a bug.

Production callers use `encryptBytes`, `encryptString`, `encryptItem`, and
`sealToUser`, all of which draw fresh randomness internally.

---

## Accepted limitations

Real, known, and not fixed. Spec §3.9 requires them documented here rather than
buried in a design doc.

**1. Public-key substitution.** The server distributes public keys. A
compromised server could hand out its own in place of a real member's and
intercept *future* shares to that member. Mitigated, not solved, by the
comparable fingerprint (`publicKeyFingerprint`) shown in the UI, which two
people can read aloud over a channel the server does not control. Existing
shares are unaffected, because they were sealed to the real key.

This is also why `decryptItem` validates its output: a substituted key means a
compromised server can choose the `parentKey` a client decrypts under, so the
AEAD tag alone proves nothing about the plaintext's provenance.

**2. Web app code delivery.** The server serves the JavaScript that handles the
master password. A compromised server could serve malicious JavaScript that
exfiltrates it. This is inherent to all browser-delivered end-to-end encryption
and cannot be fixed from inside this package. The Milestone 2 browser extension
is not subject to it, which is the main argument for making it the primary
desktop client.

**3. Metadata.** Item counts, blob sizes, modification times, collection names,
and the full membership graph are visible to the server and to Cloudflare, which
terminates TLS. Item contents, item names, usernames, passwords, and URLs are
not. If the existence of a shared collection called "Mum's house" is itself
sensitive, this system does not hide it.

**4. Endpoint compromise.** No defence against a keylogger, a malicious browser
extension, or a compromised device. Zeroization narrows the window in which a
heap snapshot yields a key; it does not close it, because a JavaScript engine
may already have copied the bytes during garbage collection. It is worth doing.
It is not a security boundary.

---

## Test vectors

`vectors/vectors.json` is the frozen cross-language contract every Keyhole
client must satisfy — this one today, the Kotlin and Swift ports later. It pins
the KDF chain, the AES-GCM envelope, sealing, recovery, fingerprints, item
plaintext, and a composed chain from master password to item key, plus a
`params` block stating the rules the arithmetic alone does not reveal.

Regenerate with `pnpm --filter @keyhole/crypto vectors`. Output is
byte-for-byte reproducible; a diff means the wire format changed and existing
vaults will not open. Treat that as a migration, not a patch.

Non-ASCII in that file is written as `\u` escapes on purpose. The normalization
vectors depend on a precomposed and a decomposed string staying distinct, and a
literal character gets silently normalized by editors and file writers — which
is exactly how a test can come to assert nothing.
