# Keyhole Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let someone move their whole vault into Keyhole from whatever they use now — upload the export, map the columns, see what will happen, import, and be told to delete the file.

**Architecture:** Entirely client-side: parse → map → encrypt → upload ciphertext. Plaintext never reaches the server. Each format is a pure function from file text to a common intermediate shape, so a format is a data file plus a small adapter rather than a branch in a growing conditional. `POST /api/items/bulk` already exists, is tested, and caps a batch at 1000 items and 8 MiB.

**Tech Stack:** TypeScript in `apps/web`, `@keyhole/crypto` for encryption, React 19 for the four-step flow.

## Global Constraints

- **Plaintext never leaves the browser.** The parsers, the mapper, and the encrypt step all run client-side; only `encryptItem` output is uploaded. A test asserts no request body contains a known plaintext password.
- **Parsing lives in `src/vault/import/`, not in `src/ui/`.** `src/ui/**` cannot import `@keyhole/crypto` at all, so the encrypt-and-upload step must sit below the UI boundary.
- **A malformed row cannot produce a half-encrypted record.** Rows are all-or-nothing individually, with a per-row error report (spec §7).
- **Batches are chunked to 1000 items**, because `internal/httpapi/items.go:15` rejects more and the server is single-writer SQLite; an unbounded batch blocks every other write for as long as it runs.
- **The completion screen tells the user to delete the export file.** Spec §7 is explicit that this matters: *"an unencrypted CSV of every password sitting in Downloads is the most likely real-world compromise of this system."*
- Every format gets a **golden-file test against a real sample export** (spec §10), not a hand-written approximation of one. A fixture invented from documentation tests the documentation.
- No fixture may contain a real credential. Generate them, and say so in a header comment inside each fixture.
- Test names must describe what the body actually verifies. Mutation step mandatory per task.

## The formats (spec §7)

Bitwarden (json, csv), LastPass, 1Password (1pux, csv), Chrome / Edge / Brave, Firefox, Safari, Dashlane (csv, json), KeePass and KeePassXC, NordPass, Proton Pass, Keeper, plus a generic CSV with manual column mapping.

**Group them by shape rather than by vendor** — Chrome, Edge, Brave, Safari, and Firefox all export near-identical `url,username,password` CSVs, and treating them as five formats is five times the code for one behaviour. Detection distinguishes them; parsing should not.

---

## Task 1: The intermediate shape and the CSV reader

`src/vault/import/types.ts` and `csv.ts`.

A real CSV reader, not `split(",")`: quoted fields, embedded commas, embedded newlines inside quotes, doubled quotes as an escape, CRLF, and a UTF-8 BOM — every one of which appears in a real password export, and each of which silently corrupts a password if mishandled. **A password containing a comma or a quote is the case that matters**, and it is the one a naive splitter destroys without any error.

Tests: each of those cases explicitly, plus a row with fewer fields than the header and a row with more.

Mutation: remove the doubled-quote handling; the embedded-quote test must fail.

## Task 2: Detection

`detect.ts` — from filename and content, return a format id or `"unknown"`. Header-signature based. `"unknown"` routes to the generic CSV mapper rather than failing; a user with an unlisted manager should still get somewhere.

Tests: every fixture detects as itself. **Plus the negative: no fixture detects as a different format.** That second one is what catches an over-broad signature, and it is the one a per-format test suite never runs.

## The parser tasks (3–7), and what they all share

Every parser in Tasks 3–7 obeys the same contract, so it is stated once here rather than five times:

- **Returns the intermediate shape from Task 1**, never `ItemPlaintext` directly. An export carries things Keyhole has no field for — a folder *name* rather than an id, a vendor-specific type — and dropping them at the parser is where information goes missing silently.
- **Never throws for a bad row.** A malformed row returns as a per-row error alongside the rows that parsed. Spec §7: rows are all-or-nothing individually, and a malformed row cannot produce a half-encrypted record.
- **Never guesses at a password.** If a row's password column is absent, empty, or unparseable, that is an error row, not an item with an empty password. Importing a blank password over a real one is the failure mode with no undo.
- **Preserves the password byte for byte.** No trimming, no unescaping beyond what the format's own quoting requires, no Unicode normalization. A trailing space in a password is part of the password.
- **Has a golden test against its fixture**, asserting the full parsed output — not a spot check of two fields.
- **Has a per-row-error test**: a fixture row that is malformed in that format's characteristic way, asserting the good rows still come through.
- **Has a mutation** that breaks exactly one field mapping (swap two columns, or drop one) and fails exactly one assertion. If it fails none, the golden test is comparing too little; if it fails everything, it is comparing a blob and will not localize a real regression.

**On fixtures.** Task 2 created a fixture per format, and four of them are reconstructions rather than real exports — `1password-export.csv`, `safari-passwords.csv`, `dashlane-credentials.csv`, `keeper-export.json`. Where you are working from one of those, say so in your report and prefer a parser that tolerates column-order variation over one that assumes the reconstruction is exact. No fixture may contain a real credential.

---

## Task 3: Browser CSVs — Chrome, Edge, Brave, Safari, Firefox

**Files:** Create `apps/web/src/vault/import/parsers/browser.ts` and its test.

One parser, five detections. Chrome, Edge and Brave emit `name,url,username,password,note`; Firefox emits `"url","username","password","httpRealm","formActionOrigin","guid","timeCreated",…`; Safari emits `Title,URL,Username,Password,Notes,OTPAuth`.

- Map each to the common shape. Firefox has no name column — derive a display name from the URL's host, and say in a comment that it is derived rather than exported.
- Firefox rows for the same host with different usernames are distinct items, not duplicates. Deduplication is Task 8's job; do not do it here.
- Safari's `OTPAuth` column carries a TOTP secret. Keyhole has no TOTP field in v1 (spec §1 non-goals). **Do not silently drop it** — carry it into the intermediate shape's notes or an explicit `unsupported` channel so the user can be told, and say which you chose and why.

**Tests:** golden per browser; a URL with a port and a path; a row whose password contains a comma and a quote; a Firefox row with an empty `username`; a Safari row with an `OTPAuth` value.

---

## Task 4: Bitwarden — json and csv

**Files:** `parsers/bitwarden.ts` and its test.

The JSON export is the richest format supported and the one most likely to be used by someone migrating deliberately.

- Handle both `folders` (id → name) and per-item `folderId`; the intermediate shape carries the folder **name**.
- Handle `type: 1` (login) and `type: 2` (secure note). Ignore card and identity types for now — but as an **error row naming the type**, not a silent skip, so the count the user sees adds up.
- `login.uris[]` is an array of objects with a `uri` field, not strings.
- The CSV export is a different, flatter shape with a `folder` column and `type` as a word.
- An encrypted Bitwarden export (`encrypted: true`) cannot be read without the user's Bitwarden password. Detect it and return a clear error saying to re-export unencrypted — not a parse failure.

**Tests:** golden for both; a note item; a login with three URIs; an item in a nested folder (`Parent/Child`); the encrypted-export error.

---

## Task 5: LastPass, KeePass, KeePassXC, NordPass

**Files:** `parsers/lastpass.ts`, `parsers/keepass.ts`, `parsers/nordpass.ts` and tests.

CSV variants that differ mainly in column names.

- LastPass: `url,username,password,totp,extra,name,grouping,fav`. `grouping` is the folder and uses `\` as a separator. A row with `url` of `http://sn` is a **secure note**, not a login — that is LastPass's marker and missing it turns every note into a broken login.
- KeePass 1.x CSV: `"Account","Login Name","Password","Web Site","Comments"`. KeePassXC: `"Group","Title","Username","Password","URL","Notes"`. Different enough to keep separate.
- NordPass: `name,url,username,password,note,cardholdername,…` — many trailing columns for types Keyhole does not support; treat non-login rows as error rows naming the type.

**Tests:** golden each; the LastPass `http://sn` note case; a KeePassXC group path; a NordPass card row becoming a named error.

---

## Task 6: 1Password — 1pux and csv

**Files:** `parsers/onepassword.ts` and its test.

**A `.1pux` is a ZIP containing `export.data` (JSON).** Reading it needs a ZIP reader.

**Stop and report before adding a dependency.** Options in order of preference: the browser's own `DecompressionStream` (present in modern browsers, but ZIP is a container format, not a raw deflate stream, so this needs a small central-directory parser); a tiny vendored inflate; or a dependency. This is a password manager — every dependency is supply chain, and the plan's constraint is that no runtime dependency is added without reporting first. Say what you chose and what it costs.

If the ZIP work looks like it will dominate the task, **split it**: implement the 1Password CSV path, report the ZIP question, and let the controller decide.

The 1Password CSV fixture is one of Task 2's reconstructions. Prefer column-name lookup over positional access.

---

## Task 7: Dashlane, Proton Pass, Keeper

**Files:** `parsers/dashlane.ts`, `parsers/protonpass.ts`, `parsers/keeper.ts` and tests.

- Dashlane ships both CSV and JSON, and its ZIP export contains several CSVs (`credentials.csv`, `securenotes.csv`). Handle the credentials CSV and the JSON; report what you find about the ZIP rather than guessing.
- Proton Pass JSON nests items under vaults; the vault name is the folder.
- **Keeper's CSV has no header row** — Task 2 established it is not content-detectable at all. It is positional: `folder,title,login,password,url,notes,…`. That means a Keeper import can only be reached by the user explicitly choosing the format, so the generic-CSV mapper in Task 8 must let them.

Three of these four fixtures are reconstructions. Say clearly in your report which behaviours you are confident in and which need verification against a real export.

## Task 8: Duplicate detection and the mapper

`dedupe.ts`, `map.ts`. A duplicate is same normalized URL host + same username. Report, never auto-merge — the user chooses skip or import-anyway per group. Generic-CSV column mapping lives here too.

Mutation: compare full URLs instead of hosts; a test with `https://x.com/login` vs `https://x.com/` must fail.

## Task 9: Encrypt and upload

`upload.ts`. Chunk at 1000, encrypt each item under the userKey (or a chosen collection's key), `POST /api/items/bulk`, report progress, and stop on the first failed chunk with an accurate count of what did land — a resumable failure is fine, a lying one is not.

Tests: chunking at the boundary (1000 and 1001), a mid-run failure reporting the true count, and the leak assertion — no request body contains a known plaintext password, searched as **base64 of the raw bytes and as the literal string**, because a decimal or hex needle would pass while the value sat in plain sight.

## Task 10: The four-step screen

Upload → map → preview with duplicates → import → completion. The completion screen's instruction to delete the export file is not a footnote; it is the last thing the user reads.

## Task 11: End to end

One journey: import a real Bitwarden export against a real server, then confirm one item's password is readable from a fresh unlock. Plus: the storage invariant still holds after an import — nothing has been written to `localStorage`, `sessionStorage`, or IndexedDB.

---

## Self-review

Spec §7's formats, flow, and per-row errors → Tasks 1–10. §10's golden-file tests per format → each parser task. §10's e2e → Task 11.

**The risk this plan carries:** it is the first feature that handles a large volume of other people's plaintext at once. Every parser is a place a password can be silently truncated, mis-mapped into the wrong field, or dropped. That is why every task pins a real export rather than an invented one, and why the leak assertion searches for the encodings a leak would actually take.
