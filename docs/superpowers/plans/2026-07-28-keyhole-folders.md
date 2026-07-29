# Keyhole Folders UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Let someone create a folder, rename it, delete it, put items in it, and filter the vault by it — from the browser.

**Architecture:** Entirely client-side; the server already has folder CRUD (`POST/PUT/DELETE /api/folders`) and already returns every folder in each `/api/sync`, which the client currently discards. A folder's name is **symmetric ciphertext under the userKey** (`encryptString`/`decryptString`), exactly like an item body, so the vault store decrypts folder names the same way it decrypts items. Items already carry `folderId` in their plaintext (`ItemPlaintext.folderId`) — the editor just needs to set it.

**Tech Stack:** TypeScript, React 19, `@keyhole/crypto`, the existing vault-core / thin-UI split.

## Global Constraints

- **A folder name is plaintext the server never sees.** It is `encryptString(name, userKey)` on the way out and `decryptString(..., userKey)` on the way in. The server stores `encryptedName` and nothing else about the name.
- **Key material lives only in `src/vault/session.ts`.** `folders.ts` takes the userKey as an argument and retains nothing.
- **`src/ui/**` must never import `@keyhole/crypto`**; the ban fires on type-only imports. Route types through `src/vault/types.ts`.
- **A folder whose name will not decrypt is shown, not dropped** — `"Couldn't decrypt this folder"` — for the same reason an undecryptable item is shown: a silently missing folder reads as data loss.
- **Deleting a folder does not delete its items, and the server does not touch them.** Confirmed in `internal/store/folders.go:169` — folder membership lives inside each item's *encrypted body*, which the server cannot read, so it tombstones the folder and leaves every item's `folderId` pointing at a folder that no longer exists. **The client is responsible for reconciling orphaned items.** An item whose `folderId` is not among the live (non-tombstone, in-state) folders must be treated as folder-less — shown under Personal, not hidden, and not crashing a lookup. This is the one genuinely load-bearing rule in the plan; a filter that assumes every `folderId` resolves will drop every item whose folder was ever deleted.
- **Folders are personal.** There is no shared-folder concept; a collection item has no folder.
- Colour from `src/ui/tokens.css`; every control labelled; `Confirm` for the destructive delete. Test names describe what the body verifies. Every task ends with a mutation check.

## Verification

```bash
cd apps/web && pnpm test && pnpm typecheck && pnpm lint
cd apps/web && pnpm test:e2e   # Task 5 only
```

---

## Task 1: The folders vault module

**Files:** Create `apps/web/src/vault/folders.ts`, `folders.test.ts`.

**Produces:**
```ts
interface WireFolder { id: string; encryptedName: string; revision: number; deletedAt: string | null }
interface FolderRecord { id: string; revision: number; deletedAt: string | null; name: string | null } // null = undecryptable
async function decryptFolders(wire: WireFolder[], userKey: Uint8Array): Promise<FolderRecord[]>
async function createFolder(deps: {api; session}, name: string): Promise<FolderRecord>
async function renameFolder(deps, id: string, revision: number, name: string): Promise<FolderRecord>
async function deleteFolder(deps, id: string): Promise<void>
```

Mirror `items.ts`: `decryptFolders` works folder by folder and never lets one failure sink the rest; a tombstone (`deletedAt !== null`) has no name to decrypt. `createFolder`/`renameFolder` `encryptString` the name under `session.getKeys().userKey` and send `{encryptedName, revision}`. Handle the 409 conflict shape the folder handler returns (`{error, folder}`) the way `updateItem` handles an item conflict.

- [ ] Write the failing tests: a name round-trips through create; an undecryptable folder becomes `name: null` and is still returned; a tombstone is returned with `name: null` and no decrypt attempt; rename sends the revision; the plaintext folder name never appears in a create request body (searched as the literal string and as base64 of the bytes).
- [ ] Run to verify failure; implement; run to pass.
- [ ] **Mutation:** in `decryptFolders`, `throw` instead of catching a decryption failure. The "undecryptable folder is still returned" test must fail. Revert, capture output.
- [ ] Commit: `feat(web): create, rename, delete, and decrypt folders`

---

## Task 2: Folders in the vault store

**Files:** Modify `apps/web/src/vault/store.ts`, `store.test.ts`.

`/api/sync` already returns `folders`. Carry them like items — **incrementally, with tombstones**, unlike collections which are replaced wholesale. Read how the store merges items and do the same for folders. Expose `VaultState.folders: FolderRecord[]` (non-tombstone, decryptable-or-not).

- [ ] Failing tests: a folder arrives on sync and appears in state decrypted; a folder tombstone on a later incremental sync removes it; `clear()` empties folders.
- [ ] Implement; run.
- [ ] **Mutation:** merge folders wholesale (replace) instead of incrementally. The tombstone-on-resync test must fail (a wholesale replace from an incremental sync that omits unchanged folders would drop them). Revert, capture output.
- [ ] Commit: `feat(web): carry folders through sync and decrypt their names`

---

## Task 3: Assign a folder in the item editor

**Files:** Modify `apps/web/src/ui/screens/VaultScreen.tsx` (or `ItemEditor.tsx`), tests.

The editor gains a folder `<select>` — Personal (no folder) plus every decryptable folder, defaulting to the item's current `folderId`. Saving sets `plaintext.folderId`. An undecryptable folder is not an assignable option, but if the item is *already* in one, do not silently move it to Personal — show the current assignment as an un-selectable "Couldn't decrypt this folder" and keep the id unless the user changes it.

- [ ] Failing tests: saving an item with a folder selected sets `folderId` (assert on the value reaching `updateItem`, not on the select rendering); an item already in an undecryptable folder keeps its id when saved unchanged.
- [ ] Implement; run.
- [ ] **Mutation:** on save, always write `folderId: null`. The first test must fail. Revert, capture.
- [ ] Commit: `feat(web): assign an item to a folder in the editor`

---

## Task 4: Folder sidebar — filter, create, rename, delete

**Files:** Modify `VaultScreen.tsx` and/or a small `FolderList` component, tests.

The vault list gains a folder filter: All items · Personal · each folder · (a folder with an undecryptable name shown but labelled). Selecting one filters to items whose `folderId` matches. Plus create (a name field), rename, and delete-behind-`Confirm` whose copy states that deleting the folder does **not** delete its items (confirm the server's behaviour first, per the Global Constraints).

Watch the label trap: "New folder name" and "Rename folder" and "Search" must not collide under `getByLabelText`.

- [ ] Failing tests: selecting a folder filters the list to its items; creating a folder calls `createFolder` with the typed name; the delete confirmation states items are kept; an item with no folder appears under Personal and not under any named folder.
- [ ] Implement; run.
- [ ] **Mutation:** make the filter match items whose `folderId` does **not** equal the selected folder. The filter test must fail. Revert, capture.
- [ ] Commit: `feat(web): a folder sidebar to filter, create, rename, and delete`

---

## Task 5: End to end

**Files:** Create or extend `apps/web/e2e/` — a folders journey.

Enrol → create a folder → add an item assigned to it → filter to the folder and see the item → **reload, unlock, and confirm the folder name decrypted and the item is still in it.** That last step proves the encrypted folder name made the round trip. Then delete the folder and confirm the item survives with no folder.

- [ ] Write the journey. Expect the first run to fail and at least one failure to be an application bug; fix the app, not the assertion, unless the assertion is wrong. If zero app bugs, say so plainly.
- [ ] Also assert the storage invariant still holds after using folders.
- [ ] Commit: `test(web): end-to-end folder create, assign, filter, and delete`

---

## Self-review

Spec §4.2 (folders in the item model) and §6.2 (the folders screen) → Tasks 1–4. §10 e2e → Task 5. The server side was built and tested in an earlier plan; this is the client that was never written.

**Deliberately not covered:** nested folders (the server model is flat — a folder has a name, not a parent); sharing a folder (folders are personal by design). The import feature files folder *paths* into item notes rather than creating folders, because it predates this UI; that stays as-is — reconciling import with real folders is a later, optional refinement, not part of this plan.
