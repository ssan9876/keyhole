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

## Tasks 3–7: The parsers, grouped

- **T3** Browser CSVs (Chrome/Edge/Brave/Safari/Firefox) — one parser, five detections.
- **T4** Bitwarden json + csv, including folder names and `type` (login vs note).
- **T5** LastPass, KeePass/KeePassXC, NordPass — CSV variants with different column names and LastPass's `grouping` field.
- **T6** 1Password 1pux (a zip containing JSON — needs a zip reader; if that pulls in a dependency, report it before adding one) and 1Password csv.
- **T7** Dashlane (csv + json), Proton Pass, Keeper.

Each task: real sample export as a fixture, golden test, per-row errors, and a mutation that breaks one field mapping and watches exactly one assertion fail.

Every parser returns the same intermediate shape and never throws for a bad row — it returns the row's error alongside the rows that parsed.

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
