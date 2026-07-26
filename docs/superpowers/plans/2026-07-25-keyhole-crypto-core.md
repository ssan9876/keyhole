# Keyhole Crypto Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `@keyhole/crypto`, the TypeScript package implementing every cryptographic operation in Keyhole, verified against independent implementations and frozen into test vectors that future Kotlin and Swift ports must reproduce.

**Architecture:** A pure library — no React, no network, no storage, no DOM. It exposes key derivation, symmetric encryption in a versioned envelope, key wrapping, X25519 sealing for shared collections, item encryption, recovery codes, and public-key fingerprints. Correctness is established by cross-checking against independent implementations (native Rust Argon2id, Node/OpenSSL AES-GCM and X25519, RFC 5869 HKDF vectors), then freezing the verified outputs as committed vectors.

**Tech Stack:** TypeScript 5.8, Node 20+, pnpm workspaces, Vitest, fast-check, `@noble/curves`, `@noble/hashes`, `hash-wasm`, WebCrypto (`globalThis.crypto.subtle`).

**Spec:** `docs/superpowers/specs/2026-07-25-keyhole-design.md` §3.

## Global Constraints

- **Runtime:** Node 20+ for tests and tooling. All runtime code must also work unmodified in a browser — no `node:` imports outside `scripts/` and `*.test.ts`.
- **Argon2id parameters:** `m = 65536 KiB (64 MiB)`, `t = 3`, `p = 4`, output length `32` bytes.
- **HKDF:** HKDF-SHA256, empty salt, output length `32` bytes.
- **Domain separation strings, exact and never changed:** `"keyhole:wrap:v1"`, `"keyhole:auth:v1"`, `"keyhole:seal:v1"`.
- **Symmetric encryption:** AES-256-GCM, fresh random 96-bit nonce per operation, 128-bit tag.
- **Envelope format:** `{"v":1,"alg":"A256GCM","n":"<base64 nonce>","ct":"<base64 ciphertext||tag>"}`.
- **Key sizes:** `userKey`, `itemKey`, `collectionKey`, `wrapKey`, `authKey` are all exactly 32 bytes. X25519 keys are 32 bytes.
- **No secret may be written to any persistent store by this package.** It has no storage APIs at all; this is structural, not a guideline.
- **Recovery code alphabet:** Crockford Base32 — `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no `I`, `L`, `O`, `U`).
- **Every exported symbol must appear in `packages/crypto/src/index.ts`.** The web app and future clients import only from the package root.

---

### Task 1: Workspace scaffolding, encoding, and randomness

**Files:**
- Create: `pnpm-workspace.yaml`
- Create: `package.json`
- Create: `tsconfig.base.json`
- Create: `packages/crypto/package.json`
- Create: `packages/crypto/tsconfig.json`
- Create: `packages/crypto/vitest.config.ts`
- Create: `packages/crypto/src/errors.ts`
- Create: `packages/crypto/src/encoding.ts`
- Create: `packages/crypto/src/random.ts`
- Create: `packages/crypto/src/memory.ts`
- Create: `packages/crypto/src/index.ts`
- Test: `packages/crypto/src/encoding.test.ts`
- Test: `packages/crypto/src/random.test.ts`
- Test: `packages/crypto/src/memory.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `class KeyholeCryptoError extends Error`
  - `class DecryptionError extends KeyholeCryptoError`
  - `class MalformedEnvelopeError extends KeyholeCryptoError`
  - `class InvalidRecoveryCodeError extends KeyholeCryptoError`
  - `toBase64(bytes: Uint8Array): string`
  - `fromBase64(text: string): Uint8Array`
  - `utf8Encode(text: string): Uint8Array`
  - `utf8Decode(bytes: Uint8Array): string`
  - `concatBytes(...parts: Uint8Array[]): Uint8Array`
  - `constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean`
  - `randomBytes(length: number): Uint8Array`
  - `zeroize(...buffers: (Uint8Array | null | undefined)[]): void`

- [ ] **Step 1: Create the workspace root**

`pnpm-workspace.yaml`:

```yaml
packages:
  - "packages/*"
  - "apps/*"
```

`package.json`:

```json
{
  "name": "keyhole",
  "private": true,
  "type": "module",
  "engines": { "node": ">=20" },
  "scripts": {
    "test": "pnpm -r test",
    "typecheck": "pnpm -r typecheck"
  },
  "devDependencies": {
    "typescript": "^5.8.3"
  }
}
```

`tsconfig.base.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "lib": ["ES2022", "DOM"],
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "verbatimModuleSyntax": true,
    "resolveJsonModule": true,
    "skipLibCheck": true,
    "noEmit": true,
    "types": []
  }
}
```

- [ ] **Step 2: Create the crypto package manifest**

`packages/crypto/package.json`:

```json
{
  "name": "@keyhole/crypto",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "main": "./src/index.ts",
  "types": "./src/index.ts",
  "exports": {
    ".": "./src/index.ts",
    "./vectors": "./vectors/vectors.json"
  },
  "scripts": {
    "test": "vitest run",
    "test:watch": "vitest",
    "typecheck": "tsc --noEmit",
    "vectors": "tsx scripts/generate-vectors.ts"
  },
  "dependencies": {
    "@noble/curves": "^1.9.0",
    "@noble/hashes": "^1.8.0",
    "hash-wasm": "^4.12.0"
  },
  "devDependencies": {
    "@node-rs/argon2": "^2.0.2",
    "@types/node": "^22.15.0",
    "fast-check": "^4.1.1",
    "tsx": "^4.19.4",
    "vitest": "^3.1.4"
  }
}
```

The package is consumed as TypeScript source — Vite and Vitest both handle that — so there is no build step to keep in sync.

`packages/crypto/tsconfig.json`:

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "types": ["node", "vitest/globals"]
  },
  "include": ["src", "scripts", "vectors"]
}
```

`packages/crypto/vitest.config.ts`:

```typescript
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["src/**/*.test.ts"],
    testTimeout: 30_000,
  },
});
```

The 30-second timeout matters: Argon2id at 64 MiB is deliberately slow, and the default 5 s will fail tests that are working correctly.

- [ ] **Step 3: Install dependencies**

Run: `pnpm install`
Expected: completes without error, creates `pnpm-lock.yaml` and `node_modules/`.

- [ ] **Step 4: Write the failing tests for encoding and randomness**

`packages/crypto/src/encoding.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  concatBytes,
  constantTimeEqual,
  fromBase64,
  toBase64,
  utf8Decode,
  utf8Encode,
} from "./encoding.js";

describe("base64", () => {
  it("encodes known values", () => {
    expect(toBase64(new Uint8Array([0, 1, 2, 253, 254, 255]))).toBe("AAEC/f7/");
    expect(toBase64(new Uint8Array([]))).toBe("");
  });

  it("decodes known values", () => {
    expect(Array.from(fromBase64("AAEC/f7/"))).toEqual([0, 1, 2, 253, 254, 255]);
    expect(fromBase64("")).toHaveLength(0);
  });

  it("round-trips arbitrary bytes", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 512 }), (bytes) => {
        expect(Array.from(fromBase64(toBase64(bytes)))).toEqual(Array.from(bytes));
      }),
    );
  });
});

describe("utf8", () => {
  it("round-trips non-ASCII text", () => {
    const text = "pässwörd — 日本語 🔑";
    expect(utf8Decode(utf8Encode(text))).toBe(text);
  });
});

describe("concatBytes", () => {
  it("joins in order", () => {
    const joined = concatBytes(new Uint8Array([1, 2]), new Uint8Array([]), new Uint8Array([3]));
    expect(Array.from(joined)).toEqual([1, 2, 3]);
  });
});

describe("constantTimeEqual", () => {
  it("is true for identical arrays", () => {
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
  });

  it("is false for differing arrays of equal length", () => {
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
  });

  it("is false for differing lengths", () => {
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
  });
});
```

`packages/crypto/src/random.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { randomBytes } from "./random.js";

describe("randomBytes", () => {
  it("returns the requested length", () => {
    expect(randomBytes(32)).toHaveLength(32);
    expect(randomBytes(1)).toHaveLength(1);
  });

  it("does not repeat across calls", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 100; i += 1) {
      seen.add(randomBytes(32).join(","));
    }
    expect(seen.size).toBe(100);
  });

  it("rejects non-positive and non-integer lengths", () => {
    expect(() => randomBytes(0)).toThrow(/positive integer/);
    expect(() => randomBytes(-1)).toThrow(/positive integer/);
    expect(() => randomBytes(1.5)).toThrow(/positive integer/);
  });
});
```

`packages/crypto/src/memory.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { zeroize } from "./memory.js";
import { randomBytes } from "./random.js";

describe("zeroize", () => {
  it("overwrites the buffer in place", () => {
    const secret = randomBytes(32);
    zeroize(secret);
    expect(Array.from(secret)).toEqual(new Array(32).fill(0));
  });

  it("clears several buffers at once", () => {
    const a = randomBytes(8);
    const b = randomBytes(16);
    zeroize(a, b);
    expect(Array.from(a)).toEqual(new Array(8).fill(0));
    expect(Array.from(b)).toEqual(new Array(16).fill(0));
  });

  it("ignores null and undefined so callers need no guards", () => {
    expect(() => zeroize(null, undefined, randomBytes(4))).not.toThrow();
  });
});
```

- [ ] **Step 5: Run the tests to verify they fail**

Run: `pnpm --filter @keyhole/crypto test`
Expected: FAIL — `Failed to resolve import "./encoding.js"` and `"./random.js"`.

- [ ] **Step 6: Implement errors, encoding, and randomness**

`packages/crypto/src/errors.ts`:

```typescript
export class KeyholeCryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** Raised when authenticated decryption fails. Deliberately carries no detail:
 *  a GCM tag mismatch cannot distinguish a wrong key from a corrupted blob,
 *  and pretending otherwise would mislead callers. */
export class DecryptionError extends KeyholeCryptoError {
  constructor() {
    super("Decryption failed: wrong key or corrupted data");
  }
}

export class MalformedEnvelopeError extends KeyholeCryptoError {}

export class InvalidRecoveryCodeError extends KeyholeCryptoError {}
```

`packages/crypto/src/encoding.ts`:

```typescript
const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** `noUncheckedIndexedAccess` makes every string index `string | undefined`.
 *  These lookups are masked to 6 bits against a 64-character alphabet, so they
 *  cannot miss — this helper documents that rather than scattering `!`. */
function alphabetAt(alphabet: string, index: number): string {
  return alphabet.charAt(index);
}

/** Base64 without Node's Buffer, so the same code runs in a browser. */
export function toBase64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] as number;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += alphabetAt(BASE64_ALPHABET, b0 >> 2);
    out += alphabetAt(BASE64_ALPHABET, ((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4));
    out += b1 === undefined ? "=" : alphabetAt(BASE64_ALPHABET, ((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6));
    out += b2 === undefined ? "=" : alphabetAt(BASE64_ALPHABET, b2 & 0x3f);
  }
  return out;
}

export function fromBase64(text: string): Uint8Array {
  const clean = text.replace(/=+$/u, "");
  const out = new Uint8Array(Math.floor((clean.length * 6) / 8));
  let bits = 0;
  let acc = 0;
  let index = 0;
  for (const char of clean) {
    const value = BASE64_ALPHABET.indexOf(char);
    if (value < 0) throw new Error(`Invalid base64 character: ${char}`);
    acc = (acc << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[index] = (acc >> bits) & 0xff;
      index += 1;
    }
  }
  return out;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function utf8Encode(text: string): Uint8Array {
  return encoder.encode(text);
}

export function utf8Decode(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Comparison whose running time does not depend on where the first
 *  difference occurs. Length difference short-circuits, which is fine —
 *  the lengths of our tokens and hashes are public. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= (a[i] as number) ^ (b[i] as number);
  }
  return diff === 0;
}
```

`packages/crypto/src/random.ts`:

```typescript
export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error("randomBytes length must be a positive integer");
  }
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}
```

`packages/crypto/src/memory.ts`:

```typescript
/**
 * Overwrite key material once it is no longer needed — this is what auto-lock
 * calls to clear wrapKey, userKey, and any decrypted item keys.
 *
 * An honest caveat: JavaScript gives no guarantee the engine has not already
 * copied these bytes elsewhere (during GC compaction, for example), so this
 * narrows the window in which a heap snapshot yields a key rather than closing
 * it. It is worth doing regardless; it is not a security boundary.
 */
export function zeroize(...buffers: (Uint8Array | null | undefined)[]): void {
  for (const buffer of buffers) {
    buffer?.fill(0);
  }
}
```

`packages/crypto/src/index.ts`:

```typescript
export * from "./errors.js";
export * from "./encoding.js";
export * from "./random.js";
export * from "./memory.js";
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `pnpm --filter @keyhole/crypto test`
Expected: PASS — 3 test files, 14 tests.

- [ ] **Step 8: Verify types**

Run: `pnpm --filter @keyhole/crypto typecheck`
Expected: no output, exit code 0.

- [ ] **Step 9: Commit**

```bash
git add pnpm-workspace.yaml package.json tsconfig.base.json pnpm-lock.yaml packages/crypto
git commit -m "feat(crypto): scaffold workspace with encoding, randomness, and zeroize"
```

---

### Task 2: Key derivation — Argon2id and HKDF

**Files:**
- Create: `packages/crypto/src/kdf.ts`
- Modify: `packages/crypto/src/index.ts`
- Test: `packages/crypto/src/kdf.test.ts`

**Interfaces:**
- Consumes: `randomBytes`, `utf8Encode`, `concatBytes` from Task 1.
- Produces:
  - `interface KdfParams { algorithm: "argon2id"; memoryKiB: number; iterations: number; parallelism: number }`
  - `const DEFAULT_KDF_PARAMS: KdfParams`
  - `deriveMasterKey(masterPassword: string, salt: Uint8Array, params?: KdfParams): Promise<Uint8Array>` — 32 bytes
  - `deriveWrapKey(masterKey: Uint8Array): Uint8Array` — 32 bytes
  - `deriveAuthHash(masterKey: Uint8Array): Uint8Array` — 32 bytes
  - `generateKdfSalt(): Uint8Array` — 16 bytes

- [ ] **Step 1: Write the failing tests**

`packages/crypto/src/kdf.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { Algorithm, Version, hashRaw } from "@node-rs/argon2";
import { hkdf as nobleHkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import {
  DEFAULT_KDF_PARAMS,
  deriveAuthHash,
  deriveMasterKey,
  deriveWrapKey,
  generateKdfSalt,
} from "./kdf.js";
import { toBase64, utf8Encode } from "./encoding.js";

const SALT = new Uint8Array(16).fill(0x42);
const PASSWORD = "correct horse battery staple";

describe("DEFAULT_KDF_PARAMS", () => {
  it("matches the values fixed in the spec", () => {
    expect(DEFAULT_KDF_PARAMS).toEqual({
      algorithm: "argon2id",
      memoryKiB: 65536,
      iterations: 3,
      parallelism: 4,
    });
  });
});

describe("deriveMasterKey", () => {
  it("produces 32 bytes", async () => {
    const key = await deriveMasterKey(PASSWORD, SALT);
    expect(key).toHaveLength(32);
  });

  it("is deterministic", async () => {
    const a = await deriveMasterKey(PASSWORD, SALT);
    const b = await deriveMasterKey(PASSWORD, SALT);
    expect(toBase64(a)).toBe(toBase64(b));
  });

  it("changes with the password and with the salt", async () => {
    const base = toBase64(await deriveMasterKey(PASSWORD, SALT));
    const otherPassword = toBase64(await deriveMasterKey(`${PASSWORD}!`, SALT));
    const otherSalt = toBase64(await deriveMasterKey(PASSWORD, new Uint8Array(16).fill(0x43)));
    expect(otherPassword).not.toBe(base);
    expect(otherSalt).not.toBe(base);
  });

  // The point of this test: our WASM Argon2id must agree byte-for-byte with a
  // completely independent native Rust implementation. That is what makes the
  // frozen vectors meaningful for a future Kotlin or Swift port.
  it("agrees with an independent native Argon2id implementation", async () => {
    const ours = await deriveMasterKey(PASSWORD, SALT);
    const theirs = await hashRaw(PASSWORD, {
      salt: Buffer.from(SALT),
      memoryCost: DEFAULT_KDF_PARAMS.memoryKiB,
      timeCost: DEFAULT_KDF_PARAMS.iterations,
      parallelism: DEFAULT_KDF_PARAMS.parallelism,
      outputLen: 32,
      algorithm: Algorithm.Argon2id,
      version: Version.V0x13,
    });
    expect(toBase64(ours)).toBe(toBase64(new Uint8Array(theirs)));
  });

  it("normalizes Unicode passwords to NFC so equivalent inputs agree", async () => {
    // U+00E9 (precomposed é) vs. "e" + U+0301 (combining acute) — different byte
    // sequences a user cannot tell apart, and different platforms emit different
    // ones for the same keystrokes. The decomposed form MUST stay a \u escape:
    // editors and file writers silently normalize the literal, which makes this
    // test vacuously pass while verifying nothing.
    const composed = await deriveMasterKey("caf\u00e9", SALT);
    const decomposed = await deriveMasterKey("cafe\u0301", SALT);
    expect(toBase64(composed)).toBe(toBase64(decomposed));
  });

  it("rejects a salt that is not 16 bytes", async () => {
    await expect(deriveMasterKey(PASSWORD, new Uint8Array(8))).rejects.toThrow(/16 bytes/);
  });

  it("rejects an empty password", async () => {
    await expect(deriveMasterKey("", SALT)).rejects.toThrow(/empty/);
  });
});

describe("HKDF derivation", () => {
  const masterKey = new Uint8Array(32).fill(0x11);

  it("produces 32-byte keys", () => {
    expect(deriveWrapKey(masterKey)).toHaveLength(32);
    expect(deriveAuthHash(masterKey)).toHaveLength(32);
  });

  it("separates the two domains", () => {
    expect(toBase64(deriveWrapKey(masterKey))).not.toBe(toBase64(deriveAuthHash(masterKey)));
  });

  it("uses exactly the info strings the spec fixes", () => {
    const expectedWrap = nobleHkdf(sha256, masterKey, undefined, utf8Encode("keyhole:wrap:v1"), 32);
    const expectedAuth = nobleHkdf(sha256, masterKey, undefined, utf8Encode("keyhole:auth:v1"), 32);
    expect(toBase64(deriveWrapKey(masterKey))).toBe(toBase64(expectedWrap));
    expect(toBase64(deriveAuthHash(masterKey))).toBe(toBase64(expectedAuth));
  });

  it("matches RFC 5869 test case 1, proving the HKDF construction itself", () => {
    const ikm = new Uint8Array(22).fill(0x0b);
    const salt = Uint8Array.from([
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ]);
    const info = Uint8Array.from([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]);
    const okm = nobleHkdf(sha256, ikm, salt, info, 42);
    const hex = Array.from(okm)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(hex).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
  });

  it("rejects a master key that is not 32 bytes", () => {
    expect(() => deriveWrapKey(new Uint8Array(16))).toThrow(/32 bytes/);
    expect(() => deriveAuthHash(new Uint8Array(16))).toThrow(/32 bytes/);
  });
});

describe("generateKdfSalt", () => {
  it("returns 16 unpredictable bytes", () => {
    expect(generateKdfSalt()).toHaveLength(16);
    expect(toBase64(generateKdfSalt())).not.toBe(toBase64(generateKdfSalt()));
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pnpm --filter @keyhole/crypto test src/kdf.test.ts`
Expected: FAIL — `Failed to resolve import "./kdf.js"`.

- [ ] **Step 3: Implement the KDF module**

`packages/crypto/src/kdf.ts`:

```typescript
import { argon2id } from "hash-wasm";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "./random.js";
import { utf8Encode } from "./encoding.js";

export interface KdfParams {
  algorithm: "argon2id";
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

/** Fixed by the spec. Stored per user so they can be raised later without a flag day. */
export const DEFAULT_KDF_PARAMS: KdfParams = {
  algorithm: "argon2id",
  memoryKiB: 65536,
  iterations: 3,
  parallelism: 4,
};

const KDF_SALT_BYTES = 16;
const DERIVED_KEY_BYTES = 32;

const WRAP_INFO = utf8Encode("keyhole:wrap:v1");
const AUTH_INFO = utf8Encode("keyhole:auth:v1");

export function generateKdfSalt(): Uint8Array {
  return randomBytes(KDF_SALT_BYTES);
}

/**
 * Argon2id over the master password. The password is normalized to Unicode NFC
 * first: a user typing "é" on one platform and "e"+combining-acute on another
 * must derive the same key, or they are locked out of their own vault by an
 * invisible difference.
 */
export async function deriveMasterKey(
  masterPassword: string,
  salt: Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<Uint8Array> {
  if (masterPassword.length === 0) {
    throw new Error("Master password must not be empty");
  }
  if (salt.length !== KDF_SALT_BYTES) {
    throw new Error(`KDF salt must be ${KDF_SALT_BYTES} bytes, received ${salt.length}`);
  }
  const hash = await argon2id({
    password: masterPassword.normalize("NFC"),
    salt,
    memorySize: params.memoryKiB,
    iterations: params.iterations,
    parallelism: params.parallelism,
    hashLength: DERIVED_KEY_BYTES,
    outputType: "binary",
  });
  return new Uint8Array(hash);
}

function expand(masterKey: Uint8Array, info: Uint8Array): Uint8Array {
  if (masterKey.length !== DERIVED_KEY_BYTES) {
    throw new Error(`Master key must be ${DERIVED_KEY_BYTES} bytes, received ${masterKey.length}`);
  }
  return hkdf(sha256, masterKey, undefined, info, DERIVED_KEY_BYTES);
}

/** Unwraps the userKey. Never leaves the device. */
export function deriveWrapKey(masterKey: Uint8Array): Uint8Array {
  return expand(masterKey, WRAP_INFO);
}

/** Sent to the server as the login credential. Decrypts nothing. */
export function deriveAuthHash(masterKey: Uint8Array): Uint8Array {
  return expand(masterKey, AUTH_INFO);
}
```

- [ ] **Step 4: Export from the package root**

Append to `packages/crypto/src/index.ts`:

```typescript
export * from "./kdf.js";
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pnpm --filter @keyhole/crypto test src/kdf.test.ts`
Expected: PASS — 13 tests. Expect this file to take 10–20 seconds; Argon2id at 64 MiB is slow on purpose.

- [ ] **Step 6: Commit**

```bash
git add packages/crypto/src/kdf.ts packages/crypto/src/kdf.test.ts packages/crypto/src/index.ts
git commit -m "feat(crypto): derive master key with Argon2id and split it with HKDF"
```

---

### Task 3: Symmetric encryption envelope

**Files:**
- Create: `packages/crypto/src/symmetric.ts`
- Modify: `packages/crypto/src/index.ts`
- Test: `packages/crypto/src/symmetric.test.ts`

**Interfaces:**
- Consumes: `randomBytes`, `toBase64`, `fromBase64`, `DecryptionError`, `MalformedEnvelopeError` from Task 1.
- Produces:
  - `interface Envelope { v: 1; alg: "A256GCM"; n: string; ct: string }`
  - `encryptBytes(key: Uint8Array, plaintext: Uint8Array): Promise<Envelope>`
  - `encryptBytesWithNonce(key: Uint8Array, plaintext: Uint8Array, nonce: Uint8Array): Promise<Envelope>` — deterministic, for tests and vector generation only
  - `decryptBytes(key: Uint8Array, envelope: Envelope): Promise<Uint8Array>`
  - `encryptString(key: Uint8Array, plaintext: string): Promise<string>`
  - `decryptString(key: Uint8Array, serialized: string): Promise<string>`
  - `serializeEnvelope(envelope: Envelope): string`
  - `parseEnvelope(serialized: string): Envelope`

- [ ] **Step 1: Write the failing tests**

`packages/crypto/src/symmetric.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { createCipheriv } from "node:crypto";
import fc from "fast-check";
import {
  decryptBytes,
  decryptString,
  encryptBytes,
  encryptBytesWithNonce,
  encryptString,
  parseEnvelope,
  serializeEnvelope,
} from "./symmetric.js";
import { DecryptionError, MalformedEnvelopeError } from "./errors.js";
import { fromBase64, toBase64, utf8Encode } from "./encoding.js";

const KEY = new Uint8Array(32).fill(0x07);
const NONCE = new Uint8Array(12).fill(0x09);

describe("encryptBytes", () => {
  it("produces a v1 A256GCM envelope with a 12-byte nonce", async () => {
    const envelope = await encryptBytes(KEY, utf8Encode("hello"));
    expect(envelope.v).toBe(1);
    expect(envelope.alg).toBe("A256GCM");
    expect(fromBase64(envelope.n)).toHaveLength(12);
  });

  it("never reuses a nonce", async () => {
    const nonces = new Set<string>();
    for (let i = 0; i < 50; i += 1) {
      nonces.add((await encryptBytes(KEY, utf8Encode("same"))).n);
    }
    expect(nonces.size).toBe(50);
  });

  it("appends the 16-byte GCM tag to the ciphertext", async () => {
    const plaintext = utf8Encode("hello");
    const envelope = await encryptBytes(KEY, plaintext);
    expect(fromBase64(envelope.ct)).toHaveLength(plaintext.length + 16);
  });

  it("rejects a key that is not 32 bytes", async () => {
    await expect(encryptBytes(new Uint8Array(16), utf8Encode("x"))).rejects.toThrow(/32 bytes/);
  });
});

describe("cross-implementation agreement", () => {
  // WebCrypto AES-GCM must match OpenSSL via Node's crypto for the same
  // key, nonce, and plaintext. Two independent implementations agreeing is
  // what makes the frozen vector worth anything.
  it("matches Node/OpenSSL AES-256-GCM", async () => {
    const plaintext = utf8Encode("attack at dawn");
    const ours = await encryptBytesWithNonce(KEY, plaintext, NONCE);

    const cipher = createCipheriv("aes-256-gcm", Buffer.from(KEY), Buffer.from(NONCE));
    const body = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
    const theirs = Buffer.concat([body, cipher.getAuthTag()]);

    expect(ours.ct).toBe(toBase64(new Uint8Array(theirs)));
  });
});

describe("decryptBytes", () => {
  it("round-trips", async () => {
    const plaintext = utf8Encode("round trip");
    const envelope = await encryptBytes(KEY, plaintext);
    expect(Array.from(await decryptBytes(KEY, envelope))).toEqual(Array.from(plaintext));
  });

  it("round-trips arbitrary byte lengths", async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 2048 }), async (bytes) => {
        const envelope = await encryptBytes(KEY, bytes);
        expect(Array.from(await decryptBytes(KEY, envelope))).toEqual(Array.from(bytes));
      }),
      { numRuns: 25 },
    );
  });

  it("throws DecryptionError under the wrong key", async () => {
    const envelope = await encryptBytes(KEY, utf8Encode("secret"));
    await expect(decryptBytes(new Uint8Array(32).fill(0x08), envelope)).rejects.toThrow(
      DecryptionError,
    );
  });

  it("throws DecryptionError when the ciphertext is tampered with", async () => {
    const envelope = await encryptBytes(KEY, utf8Encode("secret"));
    const bytes = fromBase64(envelope.ct);
    bytes[0] ^= 0xff;
    await expect(decryptBytes(KEY, { ...envelope, ct: toBase64(bytes) })).rejects.toThrow(
      DecryptionError,
    );
  });

  it("throws DecryptionError when the tag is tampered with", async () => {
    const envelope = await encryptBytes(KEY, utf8Encode("secret"));
    const bytes = fromBase64(envelope.ct);
    bytes[bytes.length - 1] ^= 0xff;
    await expect(decryptBytes(KEY, { ...envelope, ct: toBase64(bytes) })).rejects.toThrow(
      DecryptionError,
    );
  });

  it("reveals nothing about why decryption failed", async () => {
    const envelope = await encryptBytes(KEY, utf8Encode("secret"));
    await expect(decryptBytes(new Uint8Array(32).fill(0x08), envelope)).rejects.toThrow(
      "Decryption failed: wrong key or corrupted data",
    );
  });
});

describe("serializeEnvelope / parseEnvelope", () => {
  it("round-trips", async () => {
    const envelope = await encryptBytes(KEY, utf8Encode("x"));
    expect(parseEnvelope(serializeEnvelope(envelope))).toEqual(envelope);
  });

  it("rejects malformed JSON", () => {
    expect(() => parseEnvelope("not json")).toThrow(MalformedEnvelopeError);
  });

  it("rejects an unknown version", () => {
    expect(() => parseEnvelope('{"v":2,"alg":"A256GCM","n":"AA","ct":"AA"}')).toThrow(
      MalformedEnvelopeError,
    );
  });

  it("rejects an unknown algorithm", () => {
    expect(() => parseEnvelope('{"v":1,"alg":"AES-CBC","n":"AA","ct":"AA"}')).toThrow(
      MalformedEnvelopeError,
    );
  });

  it("rejects missing fields", () => {
    expect(() => parseEnvelope('{"v":1,"alg":"A256GCM"}')).toThrow(MalformedEnvelopeError);
  });
});

describe("string helpers", () => {
  it("round-trip non-ASCII text", async () => {
    const text = "pässwörd 🔑";
    expect(await decryptString(KEY, await encryptString(KEY, text))).toBe(text);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pnpm --filter @keyhole/crypto test src/symmetric.test.ts`
Expected: FAIL — `Failed to resolve import "./symmetric.js"`.

- [ ] **Step 3: Implement the symmetric module**

`packages/crypto/src/symmetric.ts`:

```typescript
import { DecryptionError, MalformedEnvelopeError } from "./errors.js";
import { fromBase64, toBase64, utf8Decode, utf8Encode } from "./encoding.js";
import { randomBytes } from "./random.js";

export interface Envelope {
  v: 1;
  alg: "A256GCM";
  n: string;
  ct: string;
}

const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BITS = 128;

async function importKey(key: Uint8Array): Promise<CryptoKey> {
  if (key.length !== KEY_BYTES) {
    throw new Error(`Symmetric key must be ${KEY_BYTES} bytes, received ${key.length}`);
  }
  return globalThis.crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt", "decrypt"]);
}

/** Deterministic encryption. Exported only for tests and vector generation —
 *  production callers must use encryptBytes so the nonce is always fresh. */
export async function encryptBytesWithNonce(
  key: Uint8Array,
  plaintext: Uint8Array,
  nonce: Uint8Array,
): Promise<Envelope> {
  if (nonce.length !== NONCE_BYTES) {
    throw new Error(`Nonce must be ${NONCE_BYTES} bytes, received ${nonce.length}`);
  }
  const cryptoKey = await importKey(key);
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, tagLength: TAG_BITS },
    cryptoKey,
    plaintext,
  );
  return { v: 1, alg: "A256GCM", n: toBase64(nonce), ct: toBase64(new Uint8Array(ciphertext)) };
}

export async function encryptBytes(key: Uint8Array, plaintext: Uint8Array): Promise<Envelope> {
  return encryptBytesWithNonce(key, plaintext, randomBytes(NONCE_BYTES));
}

export async function decryptBytes(key: Uint8Array, envelope: Envelope): Promise<Uint8Array> {
  const cryptoKey = await importKey(key);
  try {
    const plaintext = await globalThis.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64(envelope.n), tagLength: TAG_BITS },
      cryptoKey,
      fromBase64(envelope.ct),
    );
    return new Uint8Array(plaintext);
  } catch {
    // Swallow the underlying error deliberately: a GCM failure cannot tell a
    // wrong key from a corrupt blob, and inventing a distinction would mislead.
    throw new DecryptionError();
  }
}

export function serializeEnvelope(envelope: Envelope): string {
  return JSON.stringify(envelope);
}

export function parseEnvelope(serialized: string): Envelope {
  let raw: unknown;
  try {
    raw = JSON.parse(serialized);
  } catch {
    throw new MalformedEnvelopeError("Envelope is not valid JSON");
  }
  if (typeof raw !== "object" || raw === null) {
    throw new MalformedEnvelopeError("Envelope must be an object");
  }
  const { v, alg, n, ct } = raw as Record<string, unknown>;
  if (v !== 1) throw new MalformedEnvelopeError(`Unsupported envelope version: ${String(v)}`);
  if (alg !== "A256GCM") {
    throw new MalformedEnvelopeError(`Unsupported algorithm: ${String(alg)}`);
  }
  if (typeof n !== "string" || typeof ct !== "string") {
    throw new MalformedEnvelopeError("Envelope is missing 'n' or 'ct'");
  }
  return { v: 1, alg: "A256GCM", n, ct };
}

export async function encryptString(key: Uint8Array, plaintext: string): Promise<string> {
  return serializeEnvelope(await encryptBytes(key, utf8Encode(plaintext)));
}

export async function decryptString(key: Uint8Array, serialized: string): Promise<string> {
  return utf8Decode(await decryptBytes(key, parseEnvelope(serialized)));
}
```

- [ ] **Step 4: Export from the package root**

Append to `packages/crypto/src/index.ts`:

```typescript
export * from "./symmetric.js";
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pnpm --filter @keyhole/crypto test src/symmetric.test.ts`
Expected: PASS — 17 tests.

- [ ] **Step 6: Commit**

```bash
git add packages/crypto/src/symmetric.ts packages/crypto/src/symmetric.test.ts packages/crypto/src/index.ts
git commit -m "feat(crypto): add versioned AES-256-GCM envelope"
```

---

### Task 4: User key, keypair, and wrapping

**Files:**
- Create: `packages/crypto/src/keys.ts`
- Modify: `packages/crypto/src/index.ts`
- Test: `packages/crypto/src/keys.test.ts`

**Interfaces:**
- Consumes: `randomBytes` (Task 1), `encryptBytes`/`decryptBytes`/`Envelope`/`serializeEnvelope`/`parseEnvelope` (Task 3), `deriveMasterKey`/`deriveWrapKey`/`generateKdfSalt` (Task 2).
- Produces:
  - `interface KeyPair { publicKey: Uint8Array; privateKey: Uint8Array }`
  - `generateUserKey(): Uint8Array`
  - `generateCollectionKey(): Uint8Array`
  - `generateKeyPair(): KeyPair`
  - `publicKeyFor(privateKey: Uint8Array): Uint8Array`
  - `wrapKey(keyToWrap: Uint8Array, wrappingKey: Uint8Array): Promise<string>`
  - `unwrapKey(wrapped: string, wrappingKey: Uint8Array): Promise<Uint8Array>`
  - `interface EnrollmentResult { kdfSalt: Uint8Array; authHash: Uint8Array; protectedUserKey: string; publicKey: Uint8Array; encryptedPrivateKey: string; userKey: Uint8Array; keyPair: KeyPair }`
  - `enrollUser(masterPassword: string, params?: KdfParams): Promise<EnrollmentResult>`
  - `unlockUser(masterPassword: string, kdfSalt: Uint8Array, protectedUserKey: string, encryptedPrivateKey: string, params?: KdfParams): Promise<{ userKey: Uint8Array; privateKey: Uint8Array }>`
  - `interface RotationResult { kdfSalt: Uint8Array; authHash: Uint8Array; protectedUserKey: string }`
  - `rotateMasterPassword(newMasterPassword: string, userKey: Uint8Array, params?: KdfParams): Promise<RotationResult>`

- [ ] **Step 1: Write the failing tests**

`packages/crypto/src/keys.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { createPrivateKey, createPublicKey, diffieHellman } from "node:crypto";
import { x25519 } from "@noble/curves/ed25519";
import {
  enrollUser,
  generateCollectionKey,
  generateKeyPair,
  generateUserKey,
  publicKeyFor,
  rotateMasterPassword,
  unlockUser,
  unwrapKey,
  wrapKey,
} from "./keys.js";
import { DecryptionError } from "./errors.js";
import { toBase64 } from "./encoding.js";

const PASSWORD = "correct horse battery staple";

describe("key generation", () => {
  it("produces 32-byte symmetric keys", () => {
    expect(generateUserKey()).toHaveLength(32);
    expect(generateCollectionKey()).toHaveLength(32);
  });

  it("does not repeat", () => {
    expect(toBase64(generateUserKey())).not.toBe(toBase64(generateUserKey()));
  });

  it("produces 32-byte X25519 keypairs whose public key derives from the private key", () => {
    const pair = generateKeyPair();
    expect(pair.privateKey).toHaveLength(32);
    expect(pair.publicKey).toHaveLength(32);
    expect(toBase64(publicKeyFor(pair.privateKey))).toBe(toBase64(pair.publicKey));
  });

  // Independent implementation check: an X25519 shared secret computed by
  // @noble/curves must equal the one OpenSSL computes via Node.
  it("agrees with Node/OpenSSL on X25519 shared secrets", () => {
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const ours = x25519.getSharedSecret(alice.privateKey, bob.publicKey);

    const pkcs8Prefix = Buffer.from("302e020100300506032b656e04220420", "hex");
    const spkiPrefix = Buffer.from("302a300506032b656e032100", "hex");
    const alicePrivate = createPrivateKey({
      key: Buffer.concat([pkcs8Prefix, Buffer.from(alice.privateKey)]),
      format: "der",
      type: "pkcs8",
    });
    const bobPublic = createPublicKey({
      key: Buffer.concat([spkiPrefix, Buffer.from(bob.publicKey)]),
      format: "der",
      type: "spki",
    });
    const theirs = diffieHellman({ privateKey: alicePrivate, publicKey: bobPublic });

    expect(toBase64(ours)).toBe(toBase64(new Uint8Array(theirs)));
  });
});

describe("wrapKey / unwrapKey", () => {
  it("round-trips a key", async () => {
    const key = generateUserKey();
    const wrapping = generateUserKey();
    expect(toBase64(await unwrapKey(await wrapKey(key, wrapping), wrapping))).toBe(toBase64(key));
  });

  it("fails under the wrong wrapping key", async () => {
    const wrapped = await wrapKey(generateUserKey(), generateUserKey());
    await expect(unwrapKey(wrapped, generateUserKey())).rejects.toThrow(DecryptionError);
  });
});

describe("enrollUser", () => {
  it("returns everything the server needs and nothing it must not have", async () => {
    const result = await enrollUser(PASSWORD);
    expect(result.kdfSalt).toHaveLength(16);
    expect(result.authHash).toHaveLength(32);
    expect(result.publicKey).toHaveLength(32);
    expect(typeof result.protectedUserKey).toBe("string");
    expect(typeof result.encryptedPrivateKey).toBe("string");
    // The wrapped blobs must not contain the plaintext key material.
    expect(result.protectedUserKey).not.toContain(toBase64(result.userKey));
    expect(result.encryptedPrivateKey).not.toContain(toBase64(result.keyPair.privateKey));
  });

  it("produces different key material for two users with the same password", async () => {
    const a = await enrollUser(PASSWORD);
    const b = await enrollUser(PASSWORD);
    expect(toBase64(a.userKey)).not.toBe(toBase64(b.userKey));
    expect(toBase64(a.authHash)).not.toBe(toBase64(b.authHash));
  });
});

describe("unlockUser", () => {
  it("recovers the same userKey and private key", async () => {
    const enrolled = await enrollUser(PASSWORD);
    const unlocked = await unlockUser(
      PASSWORD,
      enrolled.kdfSalt,
      enrolled.protectedUserKey,
      enrolled.encryptedPrivateKey,
    );
    expect(toBase64(unlocked.userKey)).toBe(toBase64(enrolled.userKey));
    expect(toBase64(unlocked.privateKey)).toBe(toBase64(enrolled.keyPair.privateKey));
  });

  it("throws DecryptionError under the wrong master password", async () => {
    const enrolled = await enrollUser(PASSWORD);
    await expect(
      unlockUser("wrong password", enrolled.kdfSalt, enrolled.protectedUserKey, enrolled.encryptedPrivateKey),
    ).rejects.toThrow(DecryptionError);
  });
});

describe("rotateMasterPassword", () => {
  it("keeps the same userKey and private key under the new password", async () => {
    const enrolled = await enrollUser(PASSWORD);
    const rotated = await rotateMasterPassword("a brand new password", enrolled.userKey);

    const unlocked = await unlockUser(
      "a brand new password",
      rotated.kdfSalt,
      rotated.protectedUserKey,
      enrolled.encryptedPrivateKey,
    );
    expect(toBase64(unlocked.userKey)).toBe(toBase64(enrolled.userKey));
    expect(toBase64(unlocked.privateKey)).toBe(toBase64(enrolled.keyPair.privateKey));
  });

  it("issues a fresh salt and auth hash so the old password stops working", async () => {
    const enrolled = await enrollUser(PASSWORD);
    const rotated = await rotateMasterPassword("a brand new password", enrolled.userKey);

    expect(toBase64(rotated.kdfSalt)).not.toBe(toBase64(enrolled.kdfSalt));
    expect(toBase64(rotated.authHash)).not.toBe(toBase64(enrolled.authHash));
    await expect(
      unlockUser(PASSWORD, rotated.kdfSalt, rotated.protectedUserKey, enrolled.encryptedPrivateKey),
    ).rejects.toThrow(DecryptionError);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pnpm --filter @keyhole/crypto test src/keys.test.ts`
Expected: FAIL — `Failed to resolve import "./keys.js"`.

- [ ] **Step 3: Implement the keys module**

`packages/crypto/src/keys.ts`:

```typescript
import { x25519 } from "@noble/curves/ed25519";
import { randomBytes } from "./random.js";
import { decryptBytes, encryptBytes, parseEnvelope, serializeEnvelope } from "./symmetric.js";
import {
  DEFAULT_KDF_PARAMS,
  deriveAuthHash,
  deriveMasterKey,
  deriveWrapKey,
  generateKdfSalt,
  type KdfParams,
} from "./kdf.js";

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

const SYMMETRIC_KEY_BYTES = 32;

export function generateUserKey(): Uint8Array {
  return randomBytes(SYMMETRIC_KEY_BYTES);
}

export function generateCollectionKey(): Uint8Array {
  return randomBytes(SYMMETRIC_KEY_BYTES);
}

export function publicKeyFor(privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(privateKey);
}

export function generateKeyPair(): KeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  return { privateKey, publicKey: publicKeyFor(privateKey) };
}

export async function wrapKey(keyToWrap: Uint8Array, wrappingKey: Uint8Array): Promise<string> {
  return serializeEnvelope(await encryptBytes(wrappingKey, keyToWrap));
}

export async function unwrapKey(wrapped: string, wrappingKey: Uint8Array): Promise<Uint8Array> {
  return decryptBytes(wrappingKey, parseEnvelope(wrapped));
}

export interface EnrollmentResult {
  kdfSalt: Uint8Array;
  authHash: Uint8Array;
  protectedUserKey: string;
  publicKey: Uint8Array;
  encryptedPrivateKey: string;
  /** In-memory only. Never send to the server. */
  userKey: Uint8Array;
  /** In-memory only. Never send the private half to the server. */
  keyPair: KeyPair;
}

/**
 * Everything that happens when a user first sets a master password. Runs
 * entirely on the client; only the wrapped blobs and the auth hash are ever
 * uploaded.
 */
export async function enrollUser(
  masterPassword: string,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<EnrollmentResult> {
  const kdfSalt = generateKdfSalt();
  const masterKey = await deriveMasterKey(masterPassword, kdfSalt, params);
  const wrappingKey = deriveWrapKey(masterKey);
  const authHash = deriveAuthHash(masterKey);

  const userKey = generateUserKey();
  const keyPair = generateKeyPair();

  return {
    kdfSalt,
    authHash,
    protectedUserKey: await wrapKey(userKey, wrappingKey),
    publicKey: keyPair.publicKey,
    encryptedPrivateKey: await wrapKey(keyPair.privateKey, userKey),
    userKey,
    keyPair,
  };
}

export async function unlockUser(
  masterPassword: string,
  kdfSalt: Uint8Array,
  protectedUserKey: string,
  encryptedPrivateKey: string,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<{ userKey: Uint8Array; privateKey: Uint8Array }> {
  const masterKey = await deriveMasterKey(masterPassword, kdfSalt, params);
  const wrappingKey = deriveWrapKey(masterKey);
  const userKey = await unwrapKey(protectedUserKey, wrappingKey);
  const privateKey = await unwrapKey(encryptedPrivateKey, userKey);
  return { userKey, privateKey };
}

export interface RotationResult {
  kdfSalt: Uint8Array;
  authHash: Uint8Array;
  protectedUserKey: string;
}

/**
 * Changing the master password. The userKey is deliberately unchanged — only
 * its wrapping is redone — so no item, folder, or collection key is touched and
 * nothing needs re-encrypting. A fresh KDF salt is generated because the old one
 * belongs to the old password.
 *
 * The caller must already hold the userKey, which means the vault must be
 * unlocked. There is no way to rotate a password you cannot currently use.
 */
export async function rotateMasterPassword(
  newMasterPassword: string,
  userKey: Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<RotationResult> {
  const kdfSalt = generateKdfSalt();
  const masterKey = await deriveMasterKey(newMasterPassword, kdfSalt, params);
  return {
    kdfSalt,
    authHash: deriveAuthHash(masterKey),
    protectedUserKey: await wrapKey(userKey, deriveWrapKey(masterKey)),
  };
}
```

- [ ] **Step 4: Export from the package root**

Append to `packages/crypto/src/index.ts`:

```typescript
export * from "./keys.js";
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pnpm --filter @keyhole/crypto test src/keys.test.ts`
Expected: PASS — 12 tests.

- [ ] **Step 6: Commit**

```bash
git add packages/crypto/src/keys.ts packages/crypto/src/keys.test.ts packages/crypto/src/index.ts
git commit -m "feat(crypto): add user key hierarchy, X25519 keypairs, and enrollment"
```

---

### Task 5: Sealing a key to a recipient (collection sharing)

**Files:**
- Create: `packages/crypto/src/seal.ts`
- Modify: `packages/crypto/src/index.ts`
- Test: `packages/crypto/src/seal.test.ts`

**Interfaces:**
- Consumes: `generateKeyPair`/`KeyPair`/`generateCollectionKey` (Task 4), `encryptBytesWithNonce`/`decryptBytes` (Task 3), `concatBytes`/`toBase64`/`fromBase64`/`utf8Encode` (Task 1), `DecryptionError`/`MalformedEnvelopeError` (Task 1).
- Produces:
  - `interface SealedKey { v: 1; alg: "X25519-HKDF-SHA256-A256GCM"; epk: string; n: string; ct: string }`
  - `sealToUser(secret: Uint8Array, recipientPublicKey: Uint8Array): Promise<string>`
  - `sealToUserWithEphemeral(secret: Uint8Array, recipientPublicKey: Uint8Array, ephemeralPrivateKey: Uint8Array, nonce: Uint8Array): Promise<string>` — deterministic, for tests and vector generation only
  - `openSealed(sealed: string, recipientPrivateKey: Uint8Array): Promise<Uint8Array>`

- [ ] **Step 1: Write the failing tests**

`packages/crypto/src/seal.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import {
  openSealed,
  sealToUser,
  sealToUserWithEphemeral,
} from "./seal.js";
import { generateCollectionKey, generateKeyPair } from "./keys.js";
import { DecryptionError, MalformedEnvelopeError } from "./errors.js";
import { toBase64 } from "./encoding.js";

describe("sealToUser / openSealed", () => {
  it("lets only the holder of the private key recover the secret", async () => {
    const recipient = generateKeyPair();
    const secret = generateCollectionKey();
    const sealed = await sealToUser(secret, recipient.publicKey);
    expect(toBase64(await openSealed(sealed, recipient.privateKey))).toBe(toBase64(secret));
  });

  it("cannot be opened by a different private key", async () => {
    const recipient = generateKeyPair();
    const stranger = generateKeyPair();
    const sealed = await sealToUser(generateCollectionKey(), recipient.publicKey);
    await expect(openSealed(sealed, stranger.privateKey)).rejects.toThrow(DecryptionError);
  });

  it("produces a fresh ephemeral key every time, so sealing twice differs", async () => {
    const recipient = generateKeyPair();
    const secret = generateCollectionKey();
    const first = JSON.parse(await sealToUser(secret, recipient.publicKey));
    const second = JSON.parse(await sealToUser(secret, recipient.publicKey));
    expect(first.epk).not.toBe(second.epk);
    expect(first.ct).not.toBe(second.ct);
  });

  it("seals the same collection key to several members independently", async () => {
    const secret = generateCollectionKey();
    const members = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
    const sealedPerMember = await Promise.all(
      members.map((member) => sealToUser(secret, member.publicKey)),
    );
    for (const [index, member] of members.entries()) {
      const opened = await openSealed(sealedPerMember[index] as string, member.privateKey);
      expect(toBase64(opened)).toBe(toBase64(secret));
    }
  });

  it("is deterministic when the ephemeral key and nonce are fixed", async () => {
    const recipient = generateKeyPair();
    const ephemeral = generateKeyPair();
    const secret = new Uint8Array(32).fill(0x5a);
    const nonce = new Uint8Array(12).fill(0x01);
    const a = await sealToUserWithEphemeral(secret, recipient.publicKey, ephemeral.privateKey, nonce);
    const b = await sealToUserWithEphemeral(secret, recipient.publicKey, ephemeral.privateKey, nonce);
    expect(a).toBe(b);
  });

  it("rejects tampering with the ephemeral public key", async () => {
    const recipient = generateKeyPair();
    const sealed = JSON.parse(await sealToUser(generateCollectionKey(), recipient.publicKey));
    const other = generateKeyPair();
    const tampered = JSON.stringify({ ...sealed, epk: toBase64(other.publicKey) });
    await expect(openSealed(tampered, recipient.privateKey)).rejects.toThrow(DecryptionError);
  });

  it("rejects a malformed sealed blob", async () => {
    const recipient = generateKeyPair();
    await expect(openSealed("not json", recipient.privateKey)).rejects.toThrow(
      MalformedEnvelopeError,
    );
    await expect(
      openSealed('{"v":1,"alg":"wrong","epk":"AA","n":"AA","ct":"AA"}', recipient.privateKey),
    ).rejects.toThrow(MalformedEnvelopeError);
  });

  it("rejects a recipient public key that is not 32 bytes", async () => {
    await expect(sealToUser(generateCollectionKey(), new Uint8Array(16))).rejects.toThrow(
      /32 bytes/,
    );
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pnpm --filter @keyhole/crypto test src/seal.test.ts`
Expected: FAIL — `Failed to resolve import "./seal.js"`.

- [ ] **Step 3: Implement the seal module**

`packages/crypto/src/seal.ts`:

```typescript
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { concatBytes, fromBase64, toBase64, utf8Encode } from "./encoding.js";
import { DecryptionError, MalformedEnvelopeError } from "./errors.js";
import { decryptBytes, encryptBytesWithNonce } from "./symmetric.js";
import { generateKeyPair } from "./keys.js";
import { randomBytes } from "./random.js";

export interface SealedKey {
  v: 1;
  alg: "X25519-HKDF-SHA256-A256GCM";
  epk: string;
  n: string;
  ct: string;
}

const SEAL_ALG = "X25519-HKDF-SHA256-A256GCM";
const SEAL_INFO_PREFIX = utf8Encode("keyhole:seal:v1");
const PUBLIC_KEY_BYTES = 32;
const NONCE_BYTES = 12;

/**
 * The HKDF info binds both public keys into the derived key. Without that
 * binding, a shared secret could be reinterpreted in a different context;
 * with it, a blob sealed for one recipient cannot be replayed at another.
 */
function deriveSealKey(sharedSecret: Uint8Array, ephemeralPublicKey: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array {
  const info = concatBytes(SEAL_INFO_PREFIX, ephemeralPublicKey, recipientPublicKey);
  return hkdf(sha256, sharedSecret, undefined, info, 32);
}

export async function sealToUserWithEphemeral(
  secret: Uint8Array,
  recipientPublicKey: Uint8Array,
  ephemeralPrivateKey: Uint8Array,
  nonce: Uint8Array,
): Promise<string> {
  if (recipientPublicKey.length !== PUBLIC_KEY_BYTES) {
    throw new Error(
      `Recipient public key must be ${PUBLIC_KEY_BYTES} bytes, received ${recipientPublicKey.length}`,
    );
  }
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);
  const sharedSecret = x25519.getSharedSecret(ephemeralPrivateKey, recipientPublicKey);
  const sealKey = deriveSealKey(sharedSecret, ephemeralPublicKey, recipientPublicKey);
  const envelope = await encryptBytesWithNonce(sealKey, secret, nonce);
  const sealed: SealedKey = {
    v: 1,
    alg: SEAL_ALG,
    epk: toBase64(ephemeralPublicKey),
    n: envelope.n,
    ct: envelope.ct,
  };
  return JSON.stringify(sealed);
}

export async function sealToUser(
  secret: Uint8Array,
  recipientPublicKey: Uint8Array,
): Promise<string> {
  const ephemeral = generateKeyPair();
  return sealToUserWithEphemeral(
    secret,
    recipientPublicKey,
    ephemeral.privateKey,
    randomBytes(NONCE_BYTES),
  );
}

function parseSealed(serialized: string): SealedKey {
  let raw: unknown;
  try {
    raw = JSON.parse(serialized);
  } catch {
    throw new MalformedEnvelopeError("Sealed key is not valid JSON");
  }
  if (typeof raw !== "object" || raw === null) {
    throw new MalformedEnvelopeError("Sealed key must be an object");
  }
  const { v, alg, epk, n, ct } = raw as Record<string, unknown>;
  if (v !== 1) throw new MalformedEnvelopeError(`Unsupported sealed key version: ${String(v)}`);
  if (alg !== SEAL_ALG) {
    throw new MalformedEnvelopeError(`Unsupported sealed key algorithm: ${String(alg)}`);
  }
  if (typeof epk !== "string" || typeof n !== "string" || typeof ct !== "string") {
    throw new MalformedEnvelopeError("Sealed key is missing 'epk', 'n', or 'ct'");
  }
  // A sealed blob is stored on the server, so treat it as attacker-influenceable.
  // Validate epk here rather than letting a bad value reach the curve library,
  // which would throw a raw error outside this package's error taxonomy.
  let ephemeralPublicKey: Uint8Array;
  try {
    ephemeralPublicKey = fromBase64(epk);
  } catch {
    throw new MalformedEnvelopeError("Sealed key 'epk' is not valid base64");
  }
  if (ephemeralPublicKey.length !== PUBLIC_KEY_BYTES) {
    throw new MalformedEnvelopeError(
      `Sealed key 'epk' must be ${PUBLIC_KEY_BYTES} bytes, received ${ephemeralPublicKey.length}`,
    );
  }
  return { v: 1, alg: SEAL_ALG, epk, n, ct };
}

export async function openSealed(
  sealed: string,
  recipientPrivateKey: Uint8Array,
): Promise<Uint8Array> {
  // Parse OUTSIDE the try: a MalformedEnvelopeError must not be recaught and
  // re-emitted as a DecryptionError. The two mean different things.
  const parsed = parseSealed(sealed);
  const ephemeralPublicKey = fromBase64(parsed.epk);
  const recipientPublicKey = x25519.getPublicKey(recipientPrivateKey);

  let sealKey: Uint8Array;
  try {
    const sharedSecret = x25519.getSharedSecret(recipientPrivateKey, ephemeralPublicKey);
    sealKey = deriveSealKey(sharedSecret, ephemeralPublicKey, recipientPublicKey);
  } catch {
    throw new DecryptionError();
  }

  return decryptBytes(sealKey, { v: 1, alg: "A256GCM", n: parsed.n, ct: parsed.ct });
}
```

- [ ] **Step 4: Export from the package root**

Append to `packages/crypto/src/index.ts`:

```typescript
export * from "./seal.js";
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pnpm --filter @keyhole/crypto test src/seal.test.ts`
Expected: PASS — 10 tests.

- [ ] **Step 6: Commit**

```bash
git add packages/crypto/src/seal.ts packages/crypto/src/seal.test.ts packages/crypto/src/index.ts
git commit -m "feat(crypto): seal collection keys to recipients over X25519"
```

---

### Task 6: Item encryption

**Files:**
- Create: `packages/crypto/src/item.ts`
- Modify: `packages/crypto/src/index.ts`
- Test: `packages/crypto/src/item.test.ts`

**Interfaces:**
- Consumes: `randomBytes` (Task 1), `encryptString`/`decryptString` (Task 3), `wrapKey`/`unwrapKey` (Task 4).
- Produces:
  - `interface PasswordHistoryEntry { password: string; changedAt: string }`
  - `interface LoginItem { type: "login"; name: string; username: string; password: string; urls: string[]; notes: string; favorite: boolean; folderId: string | null; passwordHistory: PasswordHistoryEntry[] }`
  - `interface NoteItem { type: "note"; name: string; notes: string; favorite: boolean; folderId: string | null }`
  - `type ItemPlaintext = LoginItem | NoteItem`
  - `interface EncryptedItem { ciphertext: string; wrappedItemKey: string }`
  - `generateItemKey(): Uint8Array`
  - `encryptItem(item: ItemPlaintext, parentKey: Uint8Array): Promise<EncryptedItem>`
  - `decryptItem(encrypted: EncryptedItem, parentKey: Uint8Array): Promise<ItemPlaintext>`
  - `rewrapItem(encrypted: EncryptedItem, fromParentKey: Uint8Array, toParentKey: Uint8Array): Promise<EncryptedItem>`

- [ ] **Step 1: Write the failing tests**

`packages/crypto/src/item.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import {
  decryptItem,
  encryptItem,
  generateItemKey,
  rewrapItem,
  type LoginItem,
  type NoteItem,
} from "./item.js";
import { generateCollectionKey, generateUserKey } from "./keys.js";
import { DecryptionError } from "./errors.js";

const login: LoginItem = {
  type: "login",
  name: "GitHub",
  username: "seth@gmail.com",
  password: "hunter2-but-better",
  urls: ["https://github.com"],
  notes: "personal account",
  favorite: true,
  folderId: null,
  passwordHistory: [{ password: "old-one", changedAt: "2026-01-01T00:00:00.000Z" }],
};

const note: NoteItem = {
  type: "note",
  name: "Wifi recovery codes",
  notes: "1234-5678\n9012-3456",
  favorite: false,
  folderId: "folder-1",
};

describe("generateItemKey", () => {
  it("produces a distinct 32-byte key each call", () => {
    expect(generateItemKey()).toHaveLength(32);
    expect(generateItemKey().join()).not.toBe(generateItemKey().join());
  });
});

describe("encryptItem / decryptItem", () => {
  it("round-trips a login", async () => {
    const userKey = generateUserKey();
    expect(await decryptItem(await encryptItem(login, userKey), userKey)).toEqual(login);
  });

  it("round-trips a note", async () => {
    const userKey = generateUserKey();
    expect(await decryptItem(await encryptItem(note, userKey), userKey)).toEqual(note);
  });

  it("leaks no plaintext field into the ciphertext", async () => {
    const encrypted = await encryptItem(login, generateUserKey());
    const blob = encrypted.ciphertext + encrypted.wrappedItemKey;
    for (const secret of ["GitHub", "seth@gmail.com", "hunter2-but-better", "github.com", "old-one"]) {
      expect(blob).not.toContain(secret);
    }
  });

  it("gives every item its own key, so two identical items differ", async () => {
    const userKey = generateUserKey();
    const a = await encryptItem(login, userKey);
    const b = await encryptItem(login, userKey);
    expect(a.wrappedItemKey).not.toBe(b.wrappedItemKey);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });

  it("cannot be decrypted with the wrong parent key", async () => {
    const encrypted = await encryptItem(login, generateUserKey());
    await expect(decryptItem(encrypted, generateUserKey())).rejects.toThrow(DecryptionError);
  });
});

describe("rewrapItem", () => {
  // Moving a personal item into a shared collection must not re-encrypt the
  // item body — only the wrapped item key changes.
  it("moves an item between parent keys without touching the ciphertext", async () => {
    const userKey = generateUserKey();
    const collectionKey = generateCollectionKey();
    const personal = await encryptItem(login, userKey);
    const shared = await rewrapItem(personal, userKey, collectionKey);

    expect(shared.ciphertext).toBe(personal.ciphertext);
    expect(shared.wrappedItemKey).not.toBe(personal.wrappedItemKey);
    expect(await decryptItem(shared, collectionKey)).toEqual(login);
    await expect(decryptItem(shared, userKey)).rejects.toThrow(DecryptionError);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pnpm --filter @keyhole/crypto test src/item.test.ts`
Expected: FAIL — `Failed to resolve import "./item.js"`.

- [ ] **Step 3: Implement the item module**

`packages/crypto/src/item.ts`:

```typescript
import { randomBytes } from "./random.js";
import { decryptString, encryptString } from "./symmetric.js";
import { unwrapKey, wrapKey } from "./keys.js";

export interface PasswordHistoryEntry {
  password: string;
  changedAt: string;
}

export interface LoginItem {
  type: "login";
  name: string;
  username: string;
  password: string;
  urls: string[];
  notes: string;
  favorite: boolean;
  folderId: string | null;
  passwordHistory: PasswordHistoryEntry[];
}

export interface NoteItem {
  type: "note";
  name: string;
  notes: string;
  favorite: boolean;
  folderId: string | null;
}

export type ItemPlaintext = LoginItem | NoteItem;

export interface EncryptedItem {
  ciphertext: string;
  wrappedItemKey: string;
}

const ITEM_KEY_BYTES = 32;

export function generateItemKey(): Uint8Array {
  return randomBytes(ITEM_KEY_BYTES);
}

/**
 * `parentKey` is the userKey for a personal item, or the collectionKey for a
 * shared one. The item body is encrypted under its own key so that moving an
 * item between the two only re-wraps 32 bytes.
 */
export async function encryptItem(
  item: ItemPlaintext,
  parentKey: Uint8Array,
): Promise<EncryptedItem> {
  const itemKey = generateItemKey();
  return {
    ciphertext: await encryptString(itemKey, JSON.stringify(item)),
    wrappedItemKey: await wrapKey(itemKey, parentKey),
  };
}

export async function decryptItem(
  encrypted: EncryptedItem,
  parentKey: Uint8Array,
): Promise<ItemPlaintext> {
  const itemKey = await unwrapKey(encrypted.wrappedItemKey, parentKey);
  return JSON.parse(await decryptString(itemKey, encrypted.ciphertext)) as ItemPlaintext;
}

export async function rewrapItem(
  encrypted: EncryptedItem,
  fromParentKey: Uint8Array,
  toParentKey: Uint8Array,
): Promise<EncryptedItem> {
  const itemKey = await unwrapKey(encrypted.wrappedItemKey, fromParentKey);
  return {
    ciphertext: encrypted.ciphertext,
    wrappedItemKey: await wrapKey(itemKey, toParentKey),
  };
}
```

- [ ] **Step 4: Export from the package root**

Append to `packages/crypto/src/index.ts`:

```typescript
export * from "./item.js";
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pnpm --filter @keyhole/crypto test src/item.test.ts`
Expected: PASS — 7 tests.

- [ ] **Step 6: Commit**

```bash
git add packages/crypto/src/item.ts packages/crypto/src/item.test.ts packages/crypto/src/index.ts
git commit -m "feat(crypto): encrypt vault items under per-item keys"
```

---

### Task 7: Recovery codes

**Files:**
- Create: `packages/crypto/src/crockford.ts`
- Create: `packages/crypto/src/recovery.ts`
- Modify: `packages/crypto/src/index.ts`
- Test: `packages/crypto/src/crockford.test.ts`
- Test: `packages/crypto/src/recovery.test.ts`

**Interfaces:**
- Consumes: `randomBytes` (Task 1), `deriveMasterKey`-style Argon2id via `hash-wasm`, `generateKdfSalt`/`KdfParams`/`DEFAULT_KDF_PARAMS` (Task 2), `wrapKey`/`unwrapKey` (Task 4), `InvalidRecoveryCodeError` (Task 1).
- Produces, from `crockford.ts` — **internal module, deliberately NOT re-exported from `index.ts`**, because it is an implementation detail shared by Tasks 7 and 8 rather than part of the package's public surface:
  - `const CROCKFORD_ALPHABET: string`
  - `encodeCrockford(bytes: Uint8Array): string` — one character per byte, from the low 5 bits
  - `groupChars(text: string, size: number): string` — hyphen-separated groups
  - `normalizeCrockford(input: string): string` — uppercase, strip spaces and hyphens, map `I`/`L`→`1` and `O`→`0`
- Produces, from `recovery.ts`:
  - `generateRecoveryCode(): string` — 25 Crockford Base32 characters, formatted `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`
  - `normalizeRecoveryCode(input: string): string` — 25 unformatted characters
  - `deriveRecoveryKey(code: string, salt: Uint8Array, params?: KdfParams): Promise<Uint8Array>`
  - `createRecoveryBlob(userKey: Uint8Array, code: string): Promise<{ recoverySalt: Uint8Array; recoveryProtectedUserKey: string }>`
  - `recoverUserKey(recoveryProtectedUserKey: string, code: string, recoverySalt: Uint8Array, params?: KdfParams): Promise<Uint8Array>`

- [ ] **Step 1: Write the failing tests**

`packages/crypto/src/crockford.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import {
  CROCKFORD_ALPHABET,
  encodeCrockford,
  groupChars,
  normalizeCrockford,
} from "./crockford.js";

describe("CROCKFORD_ALPHABET", () => {
  it("is 32 characters and excludes the ambiguous ones", () => {
    expect(CROCKFORD_ALPHABET).toHaveLength(32);
    expect(CROCKFORD_ALPHABET).not.toMatch(/[ILOU]/u);
  });
});

describe("encodeCrockford", () => {
  // Alphabet index 0 is "0", index 1 is "1", index 31 is "Z".
  it("emits one alphabet character per input byte", () => {
    expect(encodeCrockford(new Uint8Array([0, 1, 31]))).toBe("01Z");
  });

  it("uses only the low five bits, so 0 and 32 collide", () => {
    expect(encodeCrockford(new Uint8Array([0]))).toBe(encodeCrockford(new Uint8Array([32])));
  });
});

describe("groupChars", () => {
  it("splits into hyphenated groups", () => {
    expect(groupChars("ABCDEFGH", 4)).toBe("ABCD-EFGH");
    expect(groupChars("ABCDE", 5)).toBe("ABCDE");
  });
});

describe("normalizeCrockford", () => {
  it("uppercases and strips spaces and hyphens", () => {
    expect(normalizeCrockford("ab cd-ef")).toBe("ABCDEF");
  });

  it("maps the transcription-ambiguous characters", () => {
    expect(normalizeCrockford("ILOilo")).toBe("110110");
  });
});
```

`packages/crypto/src/recovery.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import {
  createRecoveryBlob,
  deriveRecoveryKey,
  generateRecoveryCode,
  normalizeRecoveryCode,
  recoverUserKey,
} from "./recovery.js";
import { generateUserKey } from "./keys.js";
import { DecryptionError, InvalidRecoveryCodeError } from "./errors.js";
import { toBase64 } from "./encoding.js";

describe("generateRecoveryCode", () => {
  it("is five groups of five Crockford characters", () => {
    expect(generateRecoveryCode()).toMatch(/^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{5}(-[0-9ABCDEFGHJKMNPQRSTVWXYZ]{5}){4}$/u);
  });

  it("never contains the ambiguous letters I, L, O, or U", () => {
    for (let i = 0; i < 200; i += 1) {
      expect(generateRecoveryCode()).not.toMatch(/[ILOU]/u);
    }
  });

  it("does not repeat", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i += 1) seen.add(generateRecoveryCode());
    expect(seen.size).toBe(200);
  });
});

describe("normalizeRecoveryCode", () => {
  it("strips formatting and uppercases", () => {
    expect(normalizeRecoveryCode("abcde-fghjk-mnpqr-stvwx-yz234")).toBe("ABCDEFGHJKMNPQRSTVWXYZ234");
    expect(normalizeRecoveryCode("ABCDE FGHJK MNPQR STVWX YZ234")).toBe("ABCDEFGHJKMNPQRSTVWXYZ234");
  });

  // Crockford's whole purpose: a human transcribing by hand cannot tell these apart.
  it("maps the ambiguous characters the way Crockford specifies", () => {
    expect(normalizeRecoveryCode("IIIII-lllll-OOOOO-00000-11111")).toBe("1111111111000000000011111");
  });

  it("rejects a code of the wrong length", () => {
    expect(() => normalizeRecoveryCode("ABCDE")).toThrow(InvalidRecoveryCodeError);
  });

  it("rejects characters outside the alphabet", () => {
    expect(() => normalizeRecoveryCode("ABCDE-FGHJK-MNPQR-STVWX-YZ23!")).toThrow(
      InvalidRecoveryCodeError,
    );
  });
});

describe("deriveRecoveryKey", () => {
  it("is insensitive to how the user typed the code", async () => {
    const salt = new Uint8Array(16).fill(0x21);
    const formatted = await deriveRecoveryKey("ABCDE-FGHJK-MNPQR-STVWX-YZ234", salt);
    const messy = await deriveRecoveryKey("abcde fghjk mnpqr stvwx yz234", salt);
    expect(toBase64(formatted)).toBe(toBase64(messy));
  });
});

describe("recovery round trip", () => {
  it("recovers the userKey from the code alone", async () => {
    const userKey = generateUserKey();
    const code = generateRecoveryCode();
    const blob = await createRecoveryBlob(userKey, code);
    const recovered = await recoverUserKey(
      blob.recoveryProtectedUserKey,
      code,
      blob.recoverySalt,
    );
    expect(toBase64(recovered)).toBe(toBase64(userKey));
  });

  it("accepts the code typed in lower case without separators", async () => {
    const userKey = generateUserKey();
    const code = generateRecoveryCode();
    const blob = await createRecoveryBlob(userKey, code);
    const messy = code.replace(/-/gu, "").toLowerCase();
    const recovered = await recoverUserKey(blob.recoveryProtectedUserKey, messy, blob.recoverySalt);
    expect(toBase64(recovered)).toBe(toBase64(userKey));
  });

  it("fails on the wrong code", async () => {
    const blob = await createRecoveryBlob(generateUserKey(), generateRecoveryCode());
    await expect(
      recoverUserKey(blob.recoveryProtectedUserKey, generateRecoveryCode(), blob.recoverySalt),
    ).rejects.toThrow(DecryptionError);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pnpm --filter @keyhole/crypto test src/recovery.test.ts`
Expected: FAIL — `Failed to resolve import "./recovery.js"`.

- [ ] **Step 3: Implement the recovery module**

`packages/crypto/src/crockford.ts`:

```typescript
/**
 * Crockford Base32 — the alphabet omits I, L, O, and U so that a human reading
 * a code off a screen and typing it somewhere else cannot confuse characters.
 *
 * Internal module: shared by recovery codes and key fingerprints, and
 * deliberately not re-exported from index.ts. It is an implementation detail,
 * not part of the package's public surface.
 */
export const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** One character per byte, taken from the low five bits. 256 is divisible by
 *  32, so masking is uniform — there is no modulo bias to correct for. */
export function encodeCrockford(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) {
    // charAt, not [], because noUncheckedIndexedAccess types [] as possibly undefined.
    out += CROCKFORD_ALPHABET.charAt(byte & 0x1f);
  }
  return out;
}

export function groupChars(text: string, size: number): string {
  const groups: string[] = [];
  for (let i = 0; i < text.length; i += size) {
    groups.push(text.slice(i, i + size));
  }
  return groups.join("-");
}

/** Undoes formatting and the transcription substitutions Crockford anticipates. */
export function normalizeCrockford(input: string): string {
  return input
    .toUpperCase()
    .replace(/[\s-]/gu, "")
    .replace(/[IL]/gu, "1")
    .replace(/O/gu, "0");
}
```

`packages/crypto/src/recovery.ts`:

```typescript
import { argon2id } from "hash-wasm";
import { InvalidRecoveryCodeError } from "./errors.js";
import { randomBytes } from "./random.js";
import { DEFAULT_KDF_PARAMS, generateKdfSalt, type KdfParams } from "./kdf.js";
import { unwrapKey, wrapKey } from "./keys.js";
import {
  CROCKFORD_ALPHABET,
  encodeCrockford,
  groupChars,
  normalizeCrockford,
} from "./crockford.js";

const CODE_LENGTH = 25; // 25 chars x 5 bits = 125 bits of entropy
const GROUP_SIZE = 5;

export function generateRecoveryCode(): string {
  return groupChars(encodeCrockford(randomBytes(CODE_LENGTH)), GROUP_SIZE);
}

export function normalizeRecoveryCode(input: string): string {
  const cleaned = normalizeCrockford(input);
  if (cleaned.length !== CODE_LENGTH) {
    throw new InvalidRecoveryCodeError(
      `Recovery code must be ${CODE_LENGTH} characters, received ${cleaned.length}`,
    );
  }
  for (const char of cleaned) {
    if (!CROCKFORD_ALPHABET.includes(char)) {
      throw new InvalidRecoveryCodeError(`Invalid character in recovery code: ${char}`);
    }
  }
  return cleaned;
}

export async function deriveRecoveryKey(
  code: string,
  salt: Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<Uint8Array> {
  const hash = await argon2id({
    password: normalizeRecoveryCode(code),
    salt,
    memorySize: params.memoryKiB,
    iterations: params.iterations,
    parallelism: params.parallelism,
    hashLength: 32,
    outputType: "binary",
  });
  return new Uint8Array(hash);
}

export async function createRecoveryBlob(
  userKey: Uint8Array,
  code: string,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<{ recoverySalt: Uint8Array; recoveryProtectedUserKey: string }> {
  const recoverySalt = generateKdfSalt();
  const recoveryKey = await deriveRecoveryKey(code, recoverySalt, params);
  return {
    recoverySalt,
    recoveryProtectedUserKey: await wrapKey(userKey, recoveryKey),
  };
}

export async function recoverUserKey(
  recoveryProtectedUserKey: string,
  code: string,
  recoverySalt: Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<Uint8Array> {
  const recoveryKey = await deriveRecoveryKey(code, recoverySalt, params);
  return unwrapKey(recoveryProtectedUserKey, recoveryKey);
}
```

- [ ] **Step 4: Export from the package root**

Append to `packages/crypto/src/index.ts`:

```typescript
export * from "./recovery.js";
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pnpm --filter @keyhole/crypto test src/crockford.test.ts src/recovery.test.ts`
Expected: PASS — 17 tests (6 crockford, 11 recovery).

- [ ] **Step 6: Commit**

```bash
git add packages/crypto/src/crockford.ts packages/crypto/src/crockford.test.ts packages/crypto/src/recovery.ts packages/crypto/src/recovery.test.ts packages/crypto/src/index.ts
git commit -m "feat(crypto): add Crockford Base32 recovery codes"
```

---

### Task 8: Public key fingerprints

**Files:**
- Create: `packages/crypto/src/fingerprint.ts`
- Modify: `packages/crypto/src/index.ts`
- Test: `packages/crypto/src/fingerprint.test.ts`

**Interfaces:**
- Consumes: `concatBytes`/`utf8Encode` (Task 1), `encodeCrockford`/`groupChars` from `./crockford.js` (Task 7), `sha256` from `@noble/hashes`.
- Produces:
  - `publicKeyFingerprint(publicKey: Uint8Array, email: string): string` — `XXXX-XXXX-XXXX-XXXX`

- [ ] **Step 1: Write the failing tests**

`packages/crypto/src/fingerprint.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { publicKeyFingerprint } from "./fingerprint.js";
import { generateKeyPair } from "./keys.js";

const KEY = new Uint8Array(32).fill(0x33);

describe("publicKeyFingerprint", () => {
  it("is four groups of four Crockford characters", () => {
    expect(publicKeyFingerprint(KEY, "seth@gmail.com")).toMatch(
      /^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{4}(-[0-9ABCDEFGHJKMNPQRSTVWXYZ]{4}){3}$/u,
    );
  });

  it("is deterministic", () => {
    expect(publicKeyFingerprint(KEY, "seth@gmail.com")).toBe(
      publicKeyFingerprint(KEY, "seth@gmail.com"),
    );
  });

  // The email is bound in so an attacker cannot present a legitimate user's
  // key under a different identity and have the fingerprint still match.
  it("changes when the email changes", () => {
    expect(publicKeyFingerprint(KEY, "seth@gmail.com")).not.toBe(
      publicKeyFingerprint(KEY, "someone@else.com"),
    );
  });

  it("normalizes email case and surrounding whitespace", () => {
    expect(publicKeyFingerprint(KEY, "  Seth@Gmail.com ")).toBe(
      publicKeyFingerprint(KEY, "seth@gmail.com"),
    );
  });

  it("differs between distinct keys", () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    expect(publicKeyFingerprint(a.publicKey, "x@y.z")).not.toBe(
      publicKeyFingerprint(b.publicKey, "x@y.z"),
    );
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pnpm --filter @keyhole/crypto test src/fingerprint.test.ts`
Expected: FAIL — `Failed to resolve import "./fingerprint.js"`.

- [ ] **Step 3: Implement the fingerprint module**

`packages/crypto/src/fingerprint.ts`:

```typescript
import { sha256 } from "@noble/hashes/sha256";
import { concatBytes, utf8Encode } from "./encoding.js";
import { encodeCrockford, groupChars } from "./crockford.js";

const FINGERPRINT_CHARS = 16;
const GROUP_SIZE = 4;

/**
 * A short, human-readable identifier for a public key, shown so two people can
 * read it aloud and confirm the server handed them the right key. Binding the
 * email in means a substituted key under a different identity will not match.
 */
export function publicKeyFingerprint(publicKey: Uint8Array, email: string): string {
  const normalizedEmail = utf8Encode(email.trim().toLowerCase());
  const digest = sha256(concatBytes(normalizedEmail, publicKey));
  return groupChars(encodeCrockford(digest.slice(0, FINGERPRINT_CHARS)), GROUP_SIZE);
}
```

- [ ] **Step 4: Export from the package root**

Append to `packages/crypto/src/index.ts`:

```typescript
export * from "./fingerprint.js";
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pnpm --filter @keyhole/crypto test src/fingerprint.test.ts`
Expected: PASS — 5 tests.

- [ ] **Step 6: Commit**

```bash
git add packages/crypto/src/fingerprint.ts packages/crypto/src/fingerprint.test.ts packages/crypto/src/index.ts
git commit -m "feat(crypto): add public key fingerprints for out-of-band verification"
```

---

### Task 9: Frozen test vectors and the full lifecycle test

**Files:**
- Create: `packages/crypto/scripts/generate-vectors.ts`
- Create: `packages/crypto/vectors/vectors.json` (generated)
- Create: `packages/crypto/vectors/README.md`
- Test: `packages/crypto/src/vectors.test.ts`
- Test: `packages/crypto/src/lifecycle.test.ts`

**Interfaces:**
- Consumes: every module from Tasks 1–8.
- Produces: `packages/crypto/vectors/vectors.json`, the cross-language contract. No new runtime exports.

- [ ] **Step 1: Write the vector generator**

`packages/crypto/scripts/generate-vectors.ts`:

```typescript
/**
 * Regenerates the frozen cross-language test vectors.
 *
 * Run deliberately — `pnpm --filter @keyhole/crypto vectors` — and review the
 * resulting diff with care. A change here is a change to the wire format that
 * every client, present and future, must follow. All inputs are fixed so the
 * output is byte-for-byte reproducible.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { deriveAuthHash, deriveMasterKey, deriveWrapKey } from "../src/kdf.js";
import { encryptBytesWithNonce } from "../src/symmetric.js";
import { sealToUserWithEphemeral } from "../src/seal.js";
import { publicKeyFor } from "../src/keys.js";
import { publicKeyFingerprint } from "../src/fingerprint.js";
import { deriveRecoveryKey } from "../src/recovery.js";
import { toBase64, utf8Encode } from "../src/encoding.js";

const here = dirname(fileURLToPath(import.meta.url));

const MASTER_PASSWORD = "correct horse battery staple";
const KDF_SALT = new Uint8Array(16).fill(0x42);
const RECOVERY_CODE = "ABCDE-FGHJK-MNPQR-STVWX-YZ234";
const RECOVERY_SALT = new Uint8Array(16).fill(0x21);
const AES_KEY = new Uint8Array(32).fill(0x07);
const AES_NONCE = new Uint8Array(12).fill(0x09);
const AES_PLAINTEXT = utf8Encode("attack at dawn");
const RECIPIENT_PRIVATE = new Uint8Array(32).fill(0x0a);
const EPHEMERAL_PRIVATE = new Uint8Array(32).fill(0x0b);
const SEAL_SECRET = new Uint8Array(32).fill(0x5a);
const SEAL_NONCE = new Uint8Array(12).fill(0x01);
const FINGERPRINT_EMAIL = "seth@gmail.com";

async function main(): Promise<void> {
  const masterKey = await deriveMasterKey(MASTER_PASSWORD, KDF_SALT);
  const recipientPublic = publicKeyFor(RECIPIENT_PRIVATE);

  const vectors = {
    _comment:
      "Frozen cross-language test vectors for Keyhole. Any client implementation " +
      "must reproduce these exactly. Regenerate only with a deliberate format change.",
    kdf: {
      masterPassword: MASTER_PASSWORD,
      kdfSaltBase64: toBase64(KDF_SALT),
      params: { algorithm: "argon2id", memoryKiB: 65536, iterations: 3, parallelism: 4 },
      masterKeyBase64: toBase64(masterKey),
      wrapKeyBase64: toBase64(deriveWrapKey(masterKey)),
      authHashBase64: toBase64(deriveAuthHash(masterKey)),
    },
    aesGcm: {
      keyBase64: toBase64(AES_KEY),
      nonceBase64: toBase64(AES_NONCE),
      plaintextUtf8: "attack at dawn",
      envelope: await encryptBytesWithNonce(AES_KEY, AES_PLAINTEXT, AES_NONCE),
    },
    seal: {
      recipientPrivateKeyBase64: toBase64(RECIPIENT_PRIVATE),
      recipientPublicKeyBase64: toBase64(recipientPublic),
      ephemeralPrivateKeyBase64: toBase64(EPHEMERAL_PRIVATE),
      nonceBase64: toBase64(SEAL_NONCE),
      secretBase64: toBase64(SEAL_SECRET),
      sealed: JSON.parse(
        await sealToUserWithEphemeral(SEAL_SECRET, recipientPublic, EPHEMERAL_PRIVATE, SEAL_NONCE),
      ) as unknown,
    },
    recovery: {
      code: RECOVERY_CODE,
      recoverySaltBase64: toBase64(RECOVERY_SALT),
      recoveryKeyBase64: toBase64(await deriveRecoveryKey(RECOVERY_CODE, RECOVERY_SALT)),
    },
    fingerprint: {
      email: FINGERPRINT_EMAIL,
      publicKeyBase64: toBase64(recipientPublic),
      fingerprint: publicKeyFingerprint(recipientPublic, FINGERPRINT_EMAIL),
    },
  };

  const outDir = join(here, "..", "vectors");
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "vectors.json"), `${JSON.stringify(vectors, null, 2)}\n`, "utf8");
  console.log("Wrote vectors/vectors.json");
}

await main();
```

- [ ] **Step 2: Generate the vectors**

Run: `pnpm --filter @keyhole/crypto vectors`
Expected: `Wrote vectors/vectors.json`, and the file exists with populated base64 values (no empty strings).

- [ ] **Step 3: Write the vector conformance test**

`packages/crypto/src/vectors.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import vectors from "../vectors/vectors.json" with { type: "json" };
import { deriveAuthHash, deriveMasterKey, deriveWrapKey } from "./kdf.js";
import { decryptBytes, encryptBytesWithNonce } from "./symmetric.js";
import { openSealed, sealToUserWithEphemeral } from "./seal.js";
import { publicKeyFor } from "./keys.js";
import { publicKeyFingerprint } from "./fingerprint.js";
import { deriveRecoveryKey } from "./recovery.js";
import { fromBase64, toBase64, utf8Decode } from "./encoding.js";

// These assertions are the contract every Keyhole client must satisfy — the
// TypeScript one today, the Kotlin and Swift ones later. A failure here means
// the wire format changed and existing vaults will not open.
describe("frozen vectors", () => {
  it("reproduces the KDF chain", async () => {
    const masterKey = await deriveMasterKey(
      vectors.kdf.masterPassword,
      fromBase64(vectors.kdf.kdfSaltBase64),
    );
    expect(toBase64(masterKey)).toBe(vectors.kdf.masterKeyBase64);
    expect(toBase64(deriveWrapKey(masterKey))).toBe(vectors.kdf.wrapKeyBase64);
    expect(toBase64(deriveAuthHash(masterKey))).toBe(vectors.kdf.authHashBase64);
  });

  it("reproduces the AES-GCM envelope", async () => {
    const envelope = await encryptBytesWithNonce(
      fromBase64(vectors.aesGcm.keyBase64),
      new TextEncoder().encode(vectors.aesGcm.plaintextUtf8),
      fromBase64(vectors.aesGcm.nonceBase64),
    );
    expect(envelope).toEqual(vectors.aesGcm.envelope);
  });

  it("decrypts the frozen envelope back to the original plaintext", async () => {
    const plaintext = await decryptBytes(
      fromBase64(vectors.aesGcm.keyBase64),
      vectors.aesGcm.envelope,
    );
    expect(utf8Decode(plaintext)).toBe(vectors.aesGcm.plaintextUtf8);
  });

  it("reproduces the sealed key and opens it", async () => {
    const recipientPublic = publicKeyFor(fromBase64(vectors.seal.recipientPrivateKeyBase64));
    expect(toBase64(recipientPublic)).toBe(vectors.seal.recipientPublicKeyBase64);

    const sealed = await sealToUserWithEphemeral(
      fromBase64(vectors.seal.secretBase64),
      recipientPublic,
      fromBase64(vectors.seal.ephemeralPrivateKeyBase64),
      fromBase64(vectors.seal.nonceBase64),
    );
    expect(JSON.parse(sealed)).toEqual(vectors.seal.sealed);

    const opened = await openSealed(sealed, fromBase64(vectors.seal.recipientPrivateKeyBase64));
    expect(toBase64(opened)).toBe(vectors.seal.secretBase64);
  });

  it("reproduces the recovery key", async () => {
    const key = await deriveRecoveryKey(
      vectors.recovery.code,
      fromBase64(vectors.recovery.recoverySaltBase64),
    );
    expect(toBase64(key)).toBe(vectors.recovery.recoveryKeyBase64);
  });

  it("reproduces the fingerprint", () => {
    expect(
      publicKeyFingerprint(fromBase64(vectors.fingerprint.publicKeyBase64), vectors.fingerprint.email),
    ).toBe(vectors.fingerprint.fingerprint);
  });
});
```

- [ ] **Step 4: Write the full lifecycle test**

`packages/crypto/src/lifecycle.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { enrollUser, generateCollectionKey, rotateMasterPassword, unlockUser } from "./keys.js";
import { openSealed, sealToUser } from "./seal.js";
import { decryptItem, encryptItem, type LoginItem } from "./item.js";
import { createRecoveryBlob, generateRecoveryCode, recoverUserKey } from "./recovery.js";
import { DecryptionError } from "./errors.js";
import { toBase64 } from "./encoding.js";

const netflix: LoginItem = {
  type: "login",
  name: "Netflix",
  username: "household@example.com",
  password: "s3cret-household-pw",
  urls: ["https://netflix.com"],
  notes: "",
  favorite: false,
  folderId: null,
  passwordHistory: [],
};

describe("end-to-end lifecycle", () => {
  it("shares a collection item from one user to another", async () => {
    const alice = await enrollUser("alice-master-password");
    const bob = await enrollUser("bob-master-password");

    // Alice creates the Household collection and puts Netflix in it.
    const collectionKey = generateCollectionKey();
    const encryptedItem = await encryptItem(netflix, collectionKey);
    const aliceSealed = await sealToUser(collectionKey, alice.publicKey);

    // Alice, unlocked, fulfils the pending grant for Bob.
    const aliceCollectionKey = await openSealed(aliceSealed, alice.keyPair.privateKey);
    const bobSealed = await sealToUser(aliceCollectionKey, bob.publicKey);

    // Bob logs in on a fresh device and reads the item.
    const bobUnlocked = await unlockUser(
      "bob-master-password",
      bob.kdfSalt,
      bob.protectedUserKey,
      bob.encryptedPrivateKey,
    );
    const bobCollectionKey = await openSealed(bobSealed, bobUnlocked.privateKey);
    expect(await decryptItem(encryptedItem, bobCollectionKey)).toEqual(netflix);
  });

  it("keeps a non-member out of the collection", async () => {
    const alice = await enrollUser("alice-master-password");
    const carol = await enrollUser("carol-master-password");
    const collectionKey = generateCollectionKey();
    const aliceSealed = await sealToUser(collectionKey, alice.publicKey);

    await expect(openSealed(aliceSealed, carol.keyPair.privateKey)).rejects.toThrow(
      DecryptionError,
    );
  });

  it("survives a master password change without re-encrypting items", async () => {
    const user = await enrollUser("original-password");
    const item = await encryptItem(netflix, user.userKey);

    const rotated = await rotateMasterPassword("brand-new-password", user.userKey);

    // Unlocking with the new password must reach the same userKey, and the item
    // ciphertext must be byte-identical — nothing was re-encrypted.
    const unlocked = await unlockUser(
      "brand-new-password",
      rotated.kdfSalt,
      rotated.protectedUserKey,
      user.encryptedPrivateKey,
    );
    expect(toBase64(unlocked.userKey)).toBe(toBase64(user.userKey));
    expect(await decryptItem(item, unlocked.userKey)).toEqual(netflix);
  });

  it("recovers a vault from the recovery code after the master password is lost", async () => {
    const user = await enrollUser("forgotten-password");
    const code = generateRecoveryCode();
    const blob = await createRecoveryBlob(user.userKey, code);
    const item = await encryptItem(netflix, user.userKey);

    const recoveredUserKey = await recoverUserKey(
      blob.recoveryProtectedUserKey,
      code,
      blob.recoverySalt,
    );
    expect(toBase64(recoveredUserKey)).toBe(toBase64(user.userKey));
    expect(await decryptItem(item, recoveredUserKey)).toEqual(netflix);
  });
});
```

- [ ] **Step 5: Document the vectors**

`packages/crypto/vectors/README.md`:

```markdown
# Frozen test vectors

`vectors.json` is the cross-language contract for Keyhole's cryptography.

Every client implementation — the TypeScript one in this repo, and the Kotlin
and Swift ones that come with the Android and iOS apps — must reproduce these
values exactly. If a port cannot, it is wrong, and shipping it would produce
vaults that cannot be opened.

## Regenerating

```bash
pnpm --filter @keyhole/crypto vectors
```

Do this only when deliberately changing the wire format. A diff in this file is
a breaking change to every existing vault: review it as such. All inputs in
`scripts/generate-vectors.ts` are hardcoded, so an unchanged format produces a
byte-identical file.

## Why these values are trustworthy

The vectors are generated by this codebase, but the operations that produce them
are independently verified in the unit tests:

- **Argon2id** is checked against `@node-rs/argon2`, a native Rust implementation.
- **AES-256-GCM** is checked against Node's OpenSSL bindings.
- **X25519** shared secrets are checked against Node's OpenSSL bindings.
- **HKDF-SHA256** is checked against RFC 5869 test case 1.

So the frozen values are not merely self-consistent — each was produced by an
operation that at least one independent implementation agrees with.
```

- [ ] **Step 6: Run the whole suite**

Run: `pnpm --filter @keyhole/crypto test`
Expected: PASS — 13 test files, all green. Total runtime 60–120 seconds, dominated by Argon2id.

- [ ] **Step 7: Verify types across the package**

Run: `pnpm --filter @keyhole/crypto typecheck`
Expected: no output, exit code 0.

- [ ] **Step 8: Commit**

```bash
git add packages/crypto/scripts packages/crypto/vectors packages/crypto/src/vectors.test.ts packages/crypto/src/lifecycle.test.ts packages/crypto/package.json
git commit -m "test(crypto): freeze cross-language vectors and cover the full lifecycle"
```

---

## Definition of done

- `pnpm --filter @keyhole/crypto test` passes with every test file green.
- `pnpm --filter @keyhole/crypto typecheck` is clean.
- `packages/crypto/vectors/vectors.json` is committed and contains no empty or placeholder values.
- No `node:` import exists in `packages/crypto/src/*.ts` other than in `*.test.ts` — verify with:
  `grep -rn "node:" packages/crypto/src --include="*.ts" | grep -v ".test.ts"` → expect no output.
- Every exported symbol is reachable from `packages/crypto/src/index.ts`.

## What comes next

Plan 2 (Go server) is written after this one is built, so it can be written against the real shapes of `EnrollmentResult`, `EncryptedItem`, and the sealed-key format rather than predicted ones.
