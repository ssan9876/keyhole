# Keyhole Vault API (Plan 2b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the Keyhole server's API surface — items, folders, sync, shared collections and grants, account self-service, and administration — on top of the merged Plan 2a foundation.

**Architecture:** One monotonic revision sequence shared by every syncable row is the spine of the whole plan: `GET /api/sync?since=N` is a single query per table filtered on `revision > N`, and every write advances the sequence inside its own transaction. Authorization is a two-level check — a session identifies the user, and visibility of a row is derived from ownership (personal items) or collection membership (shared items). The server continues to perform no vault crypto: every ciphertext, wrapped item key, and sealed collection key is an opaque string it stores verbatim.

**Tech Stack:** Go 1.25+, `modernc.org/sqlite`, stdlib `net/http.ServeMux`, `log/slog`, `embed.FS` migrations. No new dependencies.

---

## Global Constraints

Every task's requirements implicitly include this section.

- **Go 1.25.0 or newer.** `go.mod` declares `go 1.25.0` — not a preference:
  `modernc.org/sqlite` v1.54.0 declares that floor in its own `go.mod`.
- **No new module dependencies.** Everything in this plan is stdlib plus what
  `go.mod` already lists.
- **SQLite driver is `modernc.org/sqlite`, registered as `"sqlite"`.**
- **The server performs no vault crypto.** It never parses, validates the
  structure of, or derives anything from a ciphertext, a wrapped key, or a
  sealed key. It checks they are non-empty strings and stores them.
- **Timestamps are RFC3339 TEXT.** `sql.NullTime` **cannot** scan them under
  modernc's driver — it fails with "unsupported Scan, storing driver.Value
  type string into type *time.Time". Scan into `sql.NullString` and
  `time.Parse` it, exactly as `scanSession` in `internal/store/sessions.go`
  already does. This bit the project once already.
- **Error envelope, exactly:** `{"error":{"code":"...","message":"..."}}`.
  Use `WriteError(w, status, code, message)`. The one permitted extension is
  the 409 conflict body in Task 3, which adds a sibling `item` field.
- **Store errors reaching a handler are classified, never echoed.**
  `store.ErrNotFound` → 404. `*store.ValidationError` → 400 with `err.Error()`.
  Anything else → log server-side with the request ID, return a generic 500.
  A raw SQLite error text must never reach a client.
- **A row the caller cannot see is a 404, not a 403.** 403 is reserved for a
  row the caller can see but may not act on (a member trying to change
  membership). Otherwise the API tells a caller which item ids exist.
- **`gofmt -l ./internal ./cmd` must print nothing.**
- **There is no registration endpoint**, and no endpoint added by this plan
  may return another user's `protected_user_key`,
  `recovery_protected_user_key`, `encrypted_private_key`, `auth_hash`,
  `kdf_salt`, or `recovery_salt`. `public_key` is public by design.
- **Every state-changing admin or collection action appends an audit entry**
  in the same transaction as the change where the store call supports it, and
  immediately after otherwise.

### Environment — you cannot discover this, so it is stated

- **Go is installed but NOT on the tool shells' PATH.** Prefix every command:
  - PowerShell: `$env:Path = "C:\Program Files\Go\bin;" + $env:Path; go test ./...`
  - Git Bash: `export PATH="/c/Program Files/Go/bin:$PATH"; go test ./...`
- **`go test -race` needs cgo and a C compiler**, at `D:\_mingw64`:
  `$env:Path = "D:\_mingw64\bin;C:\Program Files\Go\bin;" + $env:Path; $env:CGO_ENABLED = "1"`
- Module path is `github.com/ssan9876/keyhole`. Repo root is `D:\password-manager`.

---

## Decisions this plan makes, and why

Three of these amend the approved spec. They are recorded here so a reviewer
does not have to rediscover the reasoning.

**1. KDF params are pinned to the server default.** Spec §3.2 stores params
per user "so they can be raised later without a flag day". That flexibility is
what breaks the prelogin decoy: an unknown address gets
`auth.DefaultKDFParamsJSON`, so the first account whose params differ is
trivially enumerable — ask prelogin for an address and compare the params.
`/api/account/password` would ship that hole the day it landed. So enrollment
and password rotation now **reject** params that are not byte-equal to
`auth.DefaultKDFParamsJSON`. Raising params later becomes a deliberate
migration that forces re-derivation at next login — a real flag day, but a
scheduled one, which is strictly better than a permanent enumeration oracle.
`recovery_kdf_params` is **not** pinned: it is never returned by any endpoint,
so it leaks nothing, and spec §4.2's reasoning for recording it separately
still holds.

**2. `items.folder_id` is removed from the schema.** It is the same decision
already made for `items.type`, for the same reason: a plaintext column
recording which items are grouped together tells the server something the
encrypted body already carries. `folderId` lives inside the encrypted item
body (spec §3.4), the client reads it after decrypting, and the server never
needs it. Migration 0002 rebuilds the table without it. Spec §3.9's
metadata list is thereby *not* extended.

**3. Two endpoints exist that spec §4.3 does not list.** `GET /api/directory`
returns active users' id, name, email, public key, and fingerprint — without
it a client cannot seal a collection key to anyone, so sharing is impossible.
`POST /api/folders` and siblings exist because the `folders` table and the
`folderId` field in the item body are otherwise unreachable. Both are
completions of specced features, not new ones.

### The sync contract

- **Items and folders are incremental**, filtered on `revision > since`,
  tombstones included so deletes propagate.
- **Collections and pending grants are sent in full on every sync.** At
  household scale that is a handful of rows, and it means a revoked membership
  or a deleted collection simply disappears from the list — no membership
  tombstone table, no revision column on two more tables.
- **A delete destroys the ciphertext.** `DeleteItem` sets `deleted_at` and
  blanks `ciphertext` and `wrapped_item_key`, so the tombstone is an id and a
  revision. A delete that leaves the data recoverable is not a delete.
- **Conflicts are detected, not resolved.** `PUT /api/items/{id}` carries the
  revision the client edited from; a newer stored revision returns 409 with
  the current server copy attached. The client makes the conflicted copy —
  the server cannot, because it cannot decrypt or re-encrypt. Spec §9's "never
  silently lose data" is satisfied by the server refusing the overwrite.

---

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `internal/store/migrations/0002_vault.sql` | Revision sequence, `items` rebuild without `folder_id`, `pending_grants.role`, sync indexes |
| `internal/store/revision.go` | `nextRevision(ctx, tx)` and `CurrentRevision(ctx)` |
| `internal/store/items.go` | Item CRUD, tombstones, optimistic revision check, bulk insert |
| `internal/store/folders.go` | Folder CRUD and tombstones |
| `internal/store/sync.go` | The one visibility query: what this user may see since revision N |
| `internal/store/collections.go` | Collections, memberships, pending grants |
| `internal/store/audit.go` | Append and read the audit log |
| `internal/store/account.go` | Password rotation, recovery rotation, session listing |
| `internal/store/admin.go` | User listing, status changes, destructive reset, delete |
| `internal/store/retention.go` | Tombstone purge |
| `internal/httpapi/items.go` | `POST/PUT/DELETE /api/items`, `POST /api/items/bulk` |
| `internal/httpapi/folders.go` | Folder endpoints |
| `internal/httpapi/sync.go` | `GET /api/sync` |
| `internal/httpapi/collections.go` | Collection and grant endpoints |
| `internal/httpapi/directory.go` | `GET /api/directory` |
| `internal/httpapi/account.go` | `/api/account/*` |
| `internal/httpapi/admin.go` | `/api/admin/*` and `requireAdmin` |

Each gets a `_test.go` beside it.

**Modified:**

| File | Change |
|---|---|
| `internal/store/enroll.go` | Pin KDF params to the default |
| `internal/store/ids.go` | Add `ErrRevisionConflict`, `ErrUserReferenced` |
| `internal/httpapi/errors.go` | Add `DecodeJSONLimit`, export `errorBody` use for the conflict envelope |
| `internal/httpapi/server.go` | Register every new route; start the retention ticker |
| `cmd/keyhole/serve.go` | Nothing — the ticker lives in `httpapi.New` beside the sweeper |

---

## Task 1: Revision sequence, schema migration, item store

**Files:**
- Create: `internal/store/migrations/0002_vault.sql`
- Create: `internal/store/revision.go`
- Create: `internal/store/items.go`
- Test: `internal/store/revision_test.go`, `internal/store/items_test.go`
- Modify: `internal/store/ids.go` (add `ErrRevisionConflict`)
- Modify: `internal/store/store_test.go` (migration 0002 assertions)

**Interfaces:**
- Consumes: `Store.db`, `NewID()`, `ErrNotFound`, the `openTemp(t)` test helper in `internal/store/store_test.go`.
- Produces:
  ```go
  func (s *Store) CurrentRevision(ctx context.Context) (int64, error)
  func nextRevision(ctx context.Context, tx *sql.Tx) (int64, error) // unexported

  type Item struct {
      ID             string
      OwnerUserID    string
      CollectionID   sql.NullString
      Ciphertext     string
      WrappedItemKey string
      Revision       int64
      CreatedAt      time.Time
      UpdatedAt      time.Time
      DeletedAt      sql.NullTime
  }

  type ItemInput struct {
      CollectionID   string // "" means a personal item
      Ciphertext     string
      WrappedItemKey string
  }

  func (s *Store) CreateItem(ctx context.Context, ownerUserID string, in ItemInput) (Item, error)
  func (s *Store) CreateItemsBulk(ctx context.Context, ownerUserID string, ins []ItemInput) ([]Item, error)
  func (s *Store) UpdateItem(ctx context.Context, id string, expectedRevision int64, in ItemInput) (Item, error)
  func (s *Store) DeleteItem(ctx context.Context, id string) (Item, error)
  func (s *Store) ItemByID(ctx context.Context, id string) (Item, error)

  var ErrRevisionConflict = errors.New("row was modified by someone else")
  ```
  On `ErrRevisionConflict`, `UpdateItem` returns the **current stored item**
  alongside the error, so the handler can attach it to the 409.

- [ ] **Step 1: Write the migration**

Create `internal/store/migrations/0002_vault.sql`:

```sql
-- Plan 2b. Sync needs one monotonic sequence shared by every syncable row.
--
-- A per-table counter cannot work: a shared collection's items are visible to
-- several users at once, so "what changed since I last synced" has to be a
-- single ordering across the whole database, not per user and not per table.
-- SQLite tolerates one writer, so a single-row counter advanced inside each
-- write transaction is exactly as concurrent as the database already is.
CREATE TABLE revision_sequence (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    value INTEGER NOT NULL
);

INSERT INTO revision_sequence (id, value)
VALUES (1, (
    SELECT COALESCE(MAX(revision), 0)
    FROM (SELECT revision FROM items UNION ALL SELECT revision FROM folders)
));

-- items.folder_id is removed for the same reason `type` never became a column:
-- a plaintext column recording which items are grouped together tells the
-- server something the encrypted body already carries. folderId lives inside
-- the encrypted item body and the client reads it after decrypting.
--
-- This is a table rebuild rather than ALTER TABLE ... DROP COLUMN because
-- SQLite refuses to drop a column named in a FOREIGN KEY clause, and
-- folder_id is one. Nothing references items, so the drop-and-rename is safe.
CREATE TABLE items_new (
    id               TEXT PRIMARY KEY,
    owner_user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    collection_id    TEXT REFERENCES collections(id) ON DELETE CASCADE,
    ciphertext       TEXT NOT NULL,
    wrapped_item_key TEXT NOT NULL,
    revision         INTEGER NOT NULL,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    deleted_at       TEXT
);

INSERT INTO items_new (id, owner_user_id, collection_id, ciphertext,
                       wrapped_item_key, revision, created_at, updated_at, deleted_at)
SELECT id, owner_user_id, collection_id, ciphertext,
       wrapped_item_key, revision, created_at, updated_at, deleted_at
FROM items;

DROP TABLE items;
ALTER TABLE items_new RENAME TO items;

-- Both sync paths: personal items are found by owner, collection items by
-- collection, and both are filtered on revision > since.
CREATE INDEX items_owner_revision ON items (owner_user_id, revision);
CREATE INDEX items_collection_revision ON items (collection_id, revision);
CREATE INDEX folders_user_revision ON folders (user_id, revision);

-- A pending grant has to record which role it will confer. Without this the
-- fulfilling client has to guess, and every grant silently becomes a member.
ALTER TABLE pending_grants ADD COLUMN role TEXT NOT NULL DEFAULT 'member';
```

- [ ] **Step 2: Write the failing migration test**

Append to `internal/store/store_test.go`, beside the existing
`TestMigrateCreatesEveryTable`. That test uses an inclusion list, so the new
`revision_sequence` table does not disturb it; add `"revision_sequence"` to
its `want` slice as well.

```go
func TestMigration0002RemovesFolderIDAndSeedsTheSequence(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()

	version, err := st.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if version < 2 {
		t.Fatalf("schema version = %d, want at least 2", version)
	}

	// folder_id in the clear would tell the server which items are grouped
	// together — exactly what keeping `type` out of the schema avoided.
	rows, err := st.DB().QueryContext(ctx, `SELECT name FROM pragma_table_info('items')`)
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if name == "folder_id" {
			t.Error("items.folder_id still exists; migration 0002 must remove it")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	var seq int64
	if err := st.DB().QueryRowContext(ctx,
		`SELECT value FROM revision_sequence WHERE id = 1`).Scan(&seq); err != nil {
		t.Fatalf("the sequence row must exist after migration: %v", err)
	}
	if seq != 0 {
		t.Errorf("seeded sequence = %d, want 0 on a fresh database", seq)
	}

	// A second row would make "the" sequence ambiguous and let two writers
	// hand out the same revision.
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO revision_sequence (id, value) VALUES (2, 0)`); err == nil {
		t.Error("a second sequence row was accepted; the CHECK (id = 1) is missing")
	}
}
```

- [ ] **Step 3: Run it and watch it fail**

```bash
go test ./internal/store/ -run TestMigration0002 -v
```

Expected: FAIL — `no such table: revision_sequence`.

- [ ] **Step 4: Confirm the migration applies**

Re-run the same command. Expected: PASS. The migration file is picked up by
`loadMigrations` automatically from `//go:embed migrations/*.sql`.

- [ ] **Step 5: Write the failing revision-sequence test**

Create `internal/store/revision_test.go`:

```go
package store

import (
	"context"
	"sync"
	"testing"
)

func TestCurrentRevisionStartsAtZero(t *testing.T) {
	st := openTemp(t)

	rev, err := st.CurrentRevision(context.Background())
	if err != nil {
		t.Fatalf("CurrentRevision: %v", err)
	}
	if rev != 0 {
		t.Errorf("CurrentRevision = %d, want 0 on a fresh database", rev)
	}
}

func TestNextRevisionNeverRepeatsUnderConcurrency(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()

	// The sequence is the sync cursor. A repeated value means two rows share a
	// revision, and a client that syncs at exactly that number silently never
	// sees one of them again — a lost item that no error ever reports.
	const writers = 8
	const perWriter = 25

	var mu sync.Mutex
	seen := make(map[int64]bool)

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				tx, err := st.db.BeginTx(ctx, nil)
				if err != nil {
					t.Errorf("BeginTx: %v", err)
					return
				}
				rev, err := nextRevision(ctx, tx)
				if err != nil {
					_ = tx.Rollback()
					t.Errorf("nextRevision: %v", err)
					return
				}
				if err := tx.Commit(); err != nil {
					t.Errorf("Commit: %v", err)
					return
				}
				mu.Lock()
				if seen[rev] {
					t.Errorf("revision %d was handed out twice", rev)
				}
				seen[rev] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(seen) != writers*perWriter {
		t.Errorf("got %d distinct revisions, want %d", len(seen), writers*perWriter)
	}
	final, err := st.CurrentRevision(ctx)
	if err != nil {
		t.Fatalf("CurrentRevision: %v", err)
	}
	if final != int64(writers*perWriter) {
		t.Errorf("CurrentRevision = %d, want %d", final, writers*perWriter)
	}
}

func TestARolledBackTransactionDoesNotConsumeARevision(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()

	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if _, err := nextRevision(ctx, tx); err != nil {
		t.Fatalf("nextRevision: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	// A failed write must not leave a gap the client interprets as a change it
	// missed, and must not burn a number nothing will ever be stored under.
	rev, err := st.CurrentRevision(ctx)
	if err != nil {
		t.Fatalf("CurrentRevision: %v", err)
	}
	if rev != 0 {
		t.Errorf("CurrentRevision = %d after rollback, want 0", rev)
	}
}
```

- [ ] **Step 6: Run it and watch it fail**

```bash
go test ./internal/store/ -run Revision -v
```

Expected: FAIL — `undefined: nextRevision`, `st.CurrentRevision undefined`.

- [ ] **Step 7: Implement the revision sequence**

Create `internal/store/revision.go`:

```go
package store

import (
	"context"
	"database/sql"
	"fmt"
)

// nextRevision advances the shared sequence and returns the new value. It must
// be called inside the same transaction as the row it is numbering: the
// increment and the write then commit or roll back together, so a failed write
// never burns a revision the client would read as a change it missed.
//
// UPDATE-then-SELECT rather than RETURNING, because two statements inside one
// SQLite transaction are already atomic against a database that tolerates a
// single writer, and this needs no minimum SQLite version to be true.
func nextRevision(ctx context.Context, tx *sql.Tx) (int64, error) {
	if _, err := tx.ExecContext(ctx,
		`UPDATE revision_sequence SET value = value + 1 WHERE id = 1`); err != nil {
		return 0, fmt.Errorf("advance revision sequence: %w", err)
	}
	var value int64
	if err := tx.QueryRowContext(ctx,
		`SELECT value FROM revision_sequence WHERE id = 1`).Scan(&value); err != nil {
		return 0, fmt.Errorf("read revision sequence: %w", err)
	}
	return value, nil
}

// CurrentRevision is the high-water mark a sync response reports back to the
// client as its next cursor.
func (s *Store) CurrentRevision(ctx context.Context) (int64, error) {
	var value int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT value FROM revision_sequence WHERE id = 1`).Scan(&value); err != nil {
		return 0, fmt.Errorf("read revision sequence: %w", err)
	}
	return value, nil
}
```

- [ ] **Step 8: Run the revision tests**

```bash
go test ./internal/store/ -run Revision -v
```

Expected: PASS, all three.

- [ ] **Step 9: Add the conflict error**

In `internal/store/ids.go`, below `ErrEmailTaken`:

```go
// ErrRevisionConflict means the caller edited from a revision that is no
// longer current. The write is refused rather than applied: the losing edit
// still exists on the client that made it, which is what lets it become a
// conflicted copy instead of silently vanishing.
var ErrRevisionConflict = errors.New("row was modified by someone else")
```

- [ ] **Step 10: Write the failing item-store tests**

Create `internal/store/items_test.go`:

```go
package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// enrolledUserID is enrolledUser -- which already exists in sessions_test.go
// and returns a User -- for the callers that want only the id.
//
// It delegates rather than seeding its own row, so there is one definition of
// what an enrolled account looks like. That matters beyond tidiness: several
// store methods added by this plan carry `AND status = 'active'` and would
// report a misleading ErrNotFound for a pending row, and Task 6 asserts that a
// password rotation leaves the recovery blob alone -- which proves nothing
// unless a real enrollment put one there.
//
// NOTE: `enrolledUser` is taken. Naming this one the same is a compile error.
func enrolledUserID(t *testing.T, st *Store, email string) string {
	t.Helper()
	return enrolledUser(t, st, email).ID
}

func TestCreateItemStoresCiphertextVerbatimAndNumbersIt(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	// A ciphertext the server must not touch: it is the crypto package's
	// envelope, and anything the server did to it would corrupt the item.
	const ct = `{"v":1,"alg":"A256GCM","n":"AAAAAAAAAAAAAAAA","ct":"3q2+7w=="}`
	item, err := st.CreateItem(ctx, userID, ItemInput{
		Ciphertext:     ct,
		WrappedItemKey: "wrapped-key-blob",
	})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	if item.Ciphertext != ct {
		t.Errorf("Ciphertext = %q, want it stored verbatim (%q)", item.Ciphertext, ct)
	}
	if item.WrappedItemKey != "wrapped-key-blob" {
		t.Errorf("WrappedItemKey = %q", item.WrappedItemKey)
	}
	if item.CollectionID.Valid {
		t.Error("an item created with no collection must be personal")
	}
	if item.Revision != 1 {
		t.Errorf("Revision = %d, want 1 as the first write to a fresh database", item.Revision)
	}
	if item.DeletedAt.Valid {
		t.Error("a new item must not be a tombstone")
	}
	if item.OwnerUserID != userID {
		t.Errorf("OwnerUserID = %q, want %q", item.OwnerUserID, userID)
	}
}

func TestCreateItemRejectsEmptyCiphertextAndKey(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	// The server cannot check that a ciphertext decrypts — that is the whole
	// point — so the one check it can make is that the client sent something.
	// An item with an empty body is unrecoverable data loss the user would
	// discover only on unlocking.
	cases := []struct {
		name string
		in   ItemInput
	}{
		{"no ciphertext", ItemInput{WrappedItemKey: "k"}},
		{"no wrapped key", ItemInput{Ciphertext: "c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := st.CreateItem(ctx, userID, tc.in)
			var validation *ValidationError
			if !errors.As(err, &validation) {
				t.Fatalf("err = %v, want a *ValidationError", err)
			}
		})
	}
}

func TestUpdateItemAdvancesTheRevisionAndReplacesTheBody(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "v1", WrappedItemKey: "k1"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	updated, err := st.UpdateItem(ctx, created.ID, created.Revision,
		ItemInput{Ciphertext: "v2", WrappedItemKey: "k2"})
	if err != nil {
		t.Fatalf("UpdateItem: %v", err)
	}

	if updated.Ciphertext != "v2" || updated.WrappedItemKey != "k2" {
		t.Errorf("update did not replace the body: %+v", updated)
	}
	if updated.Revision <= created.Revision {
		t.Errorf("Revision = %d, want greater than %d — a sync at the old cursor "+
			"would never see this edit", updated.Revision, created.Revision)
	}
	if !updated.UpdatedAt.After(created.CreatedAt) && !updated.UpdatedAt.Equal(created.CreatedAt) {
		t.Error("UpdatedAt went backwards")
	}
}

func TestUpdateItemRefusesAStaleRevisionAndReturnsTheCurrentRow(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "base", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	// Someone else's edit lands first.
	winner, err := st.UpdateItem(ctx, created.ID, created.Revision,
		ItemInput{Ciphertext: "theirs", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("first UpdateItem: %v", err)
	}

	// Ours was written against the pre-edit revision.
	current, err := st.UpdateItem(ctx, created.ID, created.Revision,
		ItemInput{Ciphertext: "ours", WrappedItemKey: "k"})
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("err = %v, want ErrRevisionConflict", err)
	}
	// The current row rides along so the handler can hand it to the client,
	// which is what lets the client keep BOTH edits as a conflicted copy.
	if current.Ciphertext != "theirs" {
		t.Errorf("returned Ciphertext = %q, want the winning row %q", current.Ciphertext, "theirs")
	}
	if current.Revision != winner.Revision {
		t.Errorf("returned Revision = %d, want the current %d", current.Revision, winner.Revision)
	}

	// And the losing write must not have landed.
	stored, err := st.ItemByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("ItemByID: %v", err)
	}
	if stored.Ciphertext != "theirs" {
		t.Errorf("stored Ciphertext = %q; the stale write overwrote the winner", stored.Ciphertext)
	}
}

func TestDeleteItemTombstonesAndDestroysTheCiphertext(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID,
		ItemInput{Ciphertext: "secret-ciphertext", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	deleted, err := st.DeleteItem(ctx, created.ID)
	if err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}
	if !deleted.DeletedAt.Valid {
		t.Error("DeletedAt is not set; the delete will not propagate to other devices")
	}
	if deleted.Revision <= created.Revision {
		t.Errorf("Revision = %d, want greater than %d", deleted.Revision, created.Revision)
	}

	// A delete that leaves the data readable in the database is not a delete.
	// The row survives only as a tombstone so other devices learn about it.
	stored, err := st.ItemByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("ItemByID after delete: %v", err)
	}
	if stored.Ciphertext != "" {
		t.Errorf("Ciphertext = %q after delete, want it destroyed", stored.Ciphertext)
	}
	if stored.WrappedItemKey != "" {
		t.Errorf("WrappedItemKey = %q after delete, want it destroyed", stored.WrappedItemKey)
	}
}

func TestDeletingAnAlreadyDeletedItemIsNotFound(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "c", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	if _, err := st.DeleteItem(ctx, created.ID); err != nil {
		t.Fatalf("first DeleteItem: %v", err)
	}

	// Without this, a retried delete burns a revision and re-broadcasts a
	// tombstone every client already has.
	if _, err := st.DeleteItem(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteItem err = %v, want ErrNotFound", err)
	}
}

func TestUpdatingATombstoneIsNotFound(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "c", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	if _, err := st.DeleteItem(ctx, created.ID); err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}

	// A device that was offline during the delete must not be able to
	// resurrect the item by pushing its cached copy.
	_, err = st.UpdateItem(ctx, created.ID, created.Revision,
		ItemInput{Ciphertext: "resurrected", WrappedItemKey: "k"})
	if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("err = %v, want ErrNotFound or ErrRevisionConflict", err)
	}
	stored, err := st.ItemByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("ItemByID: %v", err)
	}
	if stored.Ciphertext != "" || !stored.DeletedAt.Valid {
		t.Error("a tombstone was resurrected by an update")
	}
}

func TestCreateItemsBulkIsAllOrNothing(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	// An import of a thousand passwords that half-lands leaves the user with
	// no way to tell which half. One transaction, or none.
	_, err := st.CreateItemsBulk(ctx, userID, []ItemInput{
		{Ciphertext: "ok-1", WrappedItemKey: "k"},
		{Ciphertext: "", WrappedItemKey: "k"}, // invalid
		{Ciphertext: "ok-2", WrappedItemKey: "k"},
	})
	if err == nil {
		t.Fatal("CreateItemsBulk accepted a batch containing an invalid row")
	}

	var count int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM items`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("%d items survived a rejected batch, want 0", count)
	}

	rev, err := st.CurrentRevision(ctx)
	if err != nil {
		t.Fatalf("CurrentRevision: %v", err)
	}
	if rev != 0 {
		t.Errorf("CurrentRevision = %d after a rejected batch, want 0", rev)
	}
}

func TestCreateItemsBulkNumbersEveryRowDistinctly(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	ins := make([]ItemInput, 50)
	for i := range ins {
		ins[i] = ItemInput{Ciphertext: strings.Repeat("c", i+1), WrappedItemKey: "k"}
	}
	items, err := st.CreateItemsBulk(ctx, userID, ins)
	if err != nil {
		t.Fatalf("CreateItemsBulk: %v", err)
	}
	if len(items) != len(ins) {
		t.Fatalf("returned %d items, want %d", len(items), len(ins))
	}

	// Sharing a revision across a batch would mean a client syncing mid-import
	// records a cursor that skips the rest of the batch forever.
	seen := make(map[int64]bool, len(items))
	for _, item := range items {
		if seen[item.Revision] {
			t.Fatalf("revision %d appears twice in one batch", item.Revision)
		}
		seen[item.Revision] = true
	}
}

func TestItemByIDReportsAMissingItemAsNotFound(t *testing.T) {
	st := openTemp(t)

	if _, err := st.ItemByID(context.Background(), "0123456789abcdef0123456789abcdef"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
```

- [ ] **Step 11: Run them and watch them fail**

```bash
go test ./internal/store/ -run Item -v
```

Expected: FAIL — `undefined: ItemInput`, `st.CreateItem undefined`.

- [ ] **Step 12: Implement the item store**

Create `internal/store/items.go`:

```go
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Item mirrors the items table. CollectionID is NULL for a personal item;
// a non-NULL value moves visibility from the owner to that collection's
// members. There is deliberately no type column and no folder column — both
// live inside the encrypted body, so the server cannot tell a login from a
// note or see which items are grouped together.
type Item struct {
	ID             string
	OwnerUserID    string
	CollectionID   sql.NullString
	Ciphertext     string
	WrappedItemKey string
	Revision       int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      sql.NullTime
}

// ItemInput is what a client uploads. Both blobs are opaque: the server checks
// they are present and stores them byte for byte.
type ItemInput struct {
	CollectionID   string // "" means a personal item
	Ciphertext     string
	WrappedItemKey string
}

func (in ItemInput) validate() error {
	if in.Ciphertext == "" {
		return &ValidationError{Field: "ciphertext"}
	}
	if in.WrappedItemKey == "" {
		return &ValidationError{Field: "wrappedItemKey"}
	}
	return nil
}

func (in ItemInput) collection() sql.NullString {
	if in.CollectionID == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: in.CollectionID, Valid: true}
}

const itemColumns = `id, owner_user_id, collection_id, ciphertext,
	wrapped_item_key, revision, created_at, updated_at, deleted_at`

// scanItem parses the RFC3339 TEXT timestamps by hand. sql.NullTime cannot
// scan a TEXT column under modernc's driver — it fails with "unsupported
// Scan, storing driver.Value type string into type *time.Time" — and a
// deleted_at that cannot be scanned is a tombstone that never syncs.
func scanItem(row interface{ Scan(...any) error }) (Item, error) {
	var item Item
	var createdAt, updatedAt string
	var deletedAt sql.NullString

	err := row.Scan(&item.ID, &item.OwnerUserID, &item.CollectionID,
		&item.Ciphertext, &item.WrappedItemKey, &item.Revision,
		&createdAt, &updatedAt, &deletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Item{}, ErrNotFound
	}
	if err != nil {
		return Item{}, fmt.Errorf("scan item: %w", err)
	}
	if item.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return Item{}, fmt.Errorf("parse created_at: %w", err)
	}
	if item.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt); err != nil {
		return Item{}, fmt.Errorf("parse updated_at: %w", err)
	}
	if deletedAt.Valid {
		parsed, err := time.Parse(time.RFC3339, deletedAt.String)
		if err != nil {
			return Item{}, fmt.Errorf("parse deleted_at: %w", err)
		}
		item.DeletedAt = sql.NullTime{Time: parsed, Valid: true}
	}
	return item, nil
}

func (s *Store) ItemByID(ctx context.Context, id string) (Item, error) {
	return scanItem(s.db.QueryRowContext(ctx,
		`SELECT `+itemColumns+` FROM items WHERE id = ?`, id))
}

// CreateItem stores one item. The revision and the row commit together, so a
// client can never read a revision whose row is not there yet.
func (s *Store) CreateItem(ctx context.Context, ownerUserID string, in ItemInput) (Item, error) {
	items, err := s.CreateItemsBulk(ctx, ownerUserID, []ItemInput{in})
	if err != nil {
		return Item{}, err
	}
	return items[0], nil
}

// CreateItemsBulk writes a whole batch in one transaction. An import that
// half-lands leaves the user unable to tell which half arrived, so validation
// runs over every row before any row is written.
func (s *Store) CreateItemsBulk(ctx context.Context, ownerUserID string, ins []ItemInput) ([]Item, error) {
	if len(ins) == 0 {
		return nil, &ValidationError{Field: "items"}
	}
	for _, in := range ins {
		if err := in.validate(); err != nil {
			return nil, err
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin item insert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339)
	items := make([]Item, 0, len(ins))

	for _, in := range ins {
		id, err := NewID()
		if err != nil {
			return nil, err
		}
		revision, err := nextRevision(ctx, tx)
		if err != nil {
			return nil, err
		}
		collection := in.collection()

		if _, err := tx.ExecContext(ctx,
			`INSERT INTO items (id, owner_user_id, collection_id, ciphertext,
				wrapped_item_key, revision, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			id, ownerUserID, collection, in.Ciphertext, in.WrappedItemKey,
			revision, stamp, stamp); err != nil {
			return nil, fmt.Errorf("insert item: %w", err)
		}

		items = append(items, Item{
			ID: id, OwnerUserID: ownerUserID, CollectionID: collection,
			Ciphertext: in.Ciphertext, WrappedItemKey: in.WrappedItemKey,
			Revision: revision, CreatedAt: now, UpdatedAt: now,
		})
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit item insert: %w", err)
	}
	return items, nil
}

// UpdateItem replaces an item's body if, and only if, expectedRevision is
// still the stored one.
//
// On a conflict it returns the CURRENT row alongside ErrRevisionConflict. That
// row is what lets the client keep both edits: it has its own losing version in
// memory and now has the winner, so it can write a conflicted copy. Discarding
// either one is the data loss spec section 9 forbids.
func (s *Store) UpdateItem(ctx context.Context, id string, expectedRevision int64, in ItemInput) (Item, error) {
	if err := in.validate(); err != nil {
		return Item{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Item{}, fmt.Errorf("begin item update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	current, err := scanItem(tx.QueryRowContext(ctx,
		`SELECT `+itemColumns+` FROM items WHERE id = ?`, id))
	if err != nil {
		return Item{}, err
	}
	// A tombstone is gone, not stale. Reporting it as a conflict would invite
	// the client to "resolve" it by re-uploading the item it just deleted.
	if current.DeletedAt.Valid {
		return Item{}, ErrNotFound
	}
	if current.Revision != expectedRevision {
		return current, ErrRevisionConflict
	}

	revision, err := nextRevision(ctx, tx)
	if err != nil {
		return Item{}, err
	}
	now := time.Now().UTC()

	if _, err := tx.ExecContext(ctx,
		`UPDATE items SET collection_id = ?, ciphertext = ?, wrapped_item_key = ?,
			revision = ?, updated_at = ?
		 WHERE id = ? AND revision = ? AND deleted_at IS NULL`,
		in.collection(), in.Ciphertext, in.WrappedItemKey,
		revision, now.Format(time.RFC3339), id, expectedRevision); err != nil {
		return Item{}, fmt.Errorf("update item: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Item{}, fmt.Errorf("commit item update: %w", err)
	}

	current.CollectionID = in.collection()
	current.Ciphertext = in.Ciphertext
	current.WrappedItemKey = in.WrappedItemKey
	current.Revision = revision
	current.UpdatedAt = now
	return current, nil
}

// DeleteItem tombstones the row and destroys its contents. The row survives
// only so other devices learn the item is gone; the ciphertext and the wrapped
// key are cleared, because a delete that leaves the data readable in the
// database is not a delete.
func (s *Store) DeleteItem(ctx context.Context, id string) (Item, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Item{}, fmt.Errorf("begin item delete: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	current, err := scanItem(tx.QueryRowContext(ctx,
		`SELECT `+itemColumns+` FROM items WHERE id = ?`, id))
	if err != nil {
		return Item{}, err
	}
	// Already a tombstone. Re-deleting would burn a revision and rebroadcast a
	// tombstone every client already holds.
	if current.DeletedAt.Valid {
		return Item{}, ErrNotFound
	}

	revision, err := nextRevision(ctx, tx)
	if err != nil {
		return Item{}, err
	}
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339)

	if _, err := tx.ExecContext(ctx,
		`UPDATE items SET ciphertext = '', wrapped_item_key = '',
			revision = ?, updated_at = ?, deleted_at = ?
		 WHERE id = ? AND deleted_at IS NULL`,
		revision, stamp, stamp, id); err != nil {
		return Item{}, fmt.Errorf("delete item: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Item{}, fmt.Errorf("commit item delete: %w", err)
	}

	current.Ciphertext = ""
	current.WrappedItemKey = ""
	current.Revision = revision
	current.UpdatedAt = now
	current.DeletedAt = sql.NullTime{Time: now, Valid: true}
	return current, nil
}
```

- [ ] **Step 13: Run the item tests**

```bash
go test ./internal/store/ -run Item -v
```

Expected: PASS, all ten.

- [ ] **Step 14: Prove the conflict check is load-bearing**

Temporarily change `UpdateItem` so the conflict branch never fires:

```go
	if false && current.Revision != expectedRevision {
```

Run `go test ./internal/store/ -run TestUpdateItemRefusesAStaleRevision -v`.
Expected: FAIL — the stale write lands and overwrites the winner. Revert the
mutation and confirm PASS again. Record both outputs in the report.

- [ ] **Step 15: Full suite and race**

```bash
go test ./... && gofmt -l ./internal ./cmd && go vet ./...
```

Expected: all packages PASS, `gofmt -l` prints nothing, vet is silent.

```bash
go test -race ./internal/store/
```

Expected: PASS with no race reports. `TestNextRevisionNeverRepeatsUnderConcurrency`
is the reason this matters.

- [ ] **Step 16: Commit**

```bash
git add internal/store/ && git commit -m "feat(store): revision sequence, item CRUD, and the 0002 vault migration"
```

---

## Task 2: Folder store and the sync visibility query

**Files:**
- Create: `internal/store/folders.go`
- Create: `internal/store/sync.go`
- Test: `internal/store/folders_test.go`, `internal/store/sync_test.go`

**Interfaces:**
- Consumes: `nextRevision`, `CurrentRevision`, `Item`, `ItemInput`, `scanItem`,
  `itemColumns`, `ErrRevisionConflict`, `ValidationError`, `ErrNotFound`, and
  the `enrolledUser` test helper (all Task 1).
- Produces:
  ```go
  type Folder struct {
      ID            string
      UserID        string
      EncryptedName string
      Revision      int64
      CreatedAt     time.Time
      UpdatedAt     time.Time
      DeletedAt     sql.NullTime
  }

  func (s *Store) CreateFolder(ctx context.Context, userID, encryptedName string) (Folder, error)
  func (s *Store) UpdateFolder(ctx context.Context, id string, expectedRevision int64, encryptedName string) (Folder, error)
  func (s *Store) DeleteFolder(ctx context.Context, id string) (Folder, error)
  func (s *Store) FolderByID(ctx context.Context, id string) (Folder, error)

  type SyncResult struct {
      Revision int64
      Items    []Item
      Folders  []Folder
  }

  func (s *Store) SyncSince(ctx context.Context, userID string, since int64) (SyncResult, error)
  func (s *Store) CanAccessItem(ctx context.Context, userID string, item Item) (bool, error)

  const folderColumns = `id, user_id, encrypted_name, revision, created_at, updated_at, deleted_at`
  const visibleItemsClause = /* see Step 7 */
  ```
  `SyncResult` gains a `Collections` field in Task 4, once
  `CollectionWithMembership` exists. Do not add it now.

- [ ] **Step 1: Write the failing folder tests**

Create `internal/store/folders_test.go`:

```go
package store

import (
	"context"
	"errors"
	"testing"
)

func TestCreateFolderStoresTheEncryptedNameVerbatim(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	// The folder name is ciphertext. A server that could read "Banking" would
	// know more about the vault than the design permits.
	const name = `{"v":1,"alg":"A256GCM","n":"BBBBBBBBBBBBBBBB","ct":"YmFua2luZw=="}`
	folder, err := st.CreateFolder(ctx, userID, name)
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	if folder.EncryptedName != name {
		t.Errorf("EncryptedName = %q, want it stored verbatim", folder.EncryptedName)
	}
	if folder.Revision != 1 {
		t.Errorf("Revision = %d, want 1", folder.Revision)
	}
	if folder.UserID != userID {
		t.Errorf("UserID = %q, want %q", folder.UserID, userID)
	}
}

func TestCreateFolderRejectsAnEmptyName(t *testing.T) {
	st := openTemp(t)
	userID := enrolledUserID(t, st, "owner@example.com")

	_, err := st.CreateFolder(context.Background(), userID, "")
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("err = %v, want a *ValidationError", err)
	}
}

func TestFoldersAndItemsDrawFromTheSameRevisionSequence(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	item, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "c", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	folder, err := st.CreateFolder(ctx, userID, "encrypted-name")
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	// One cursor covers both tables. If folders had their own counter, a client
	// storing a single `since` value would either re-download every folder each
	// sync or skip folders entirely.
	if folder.Revision <= item.Revision {
		t.Errorf("folder revision %d does not follow item revision %d; the two tables "+
			"are not sharing one sequence", folder.Revision, item.Revision)
	}
}

func TestUpdateFolderRefusesAStaleRevision(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateFolder(ctx, userID, "v1")
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	if _, err := st.UpdateFolder(ctx, created.ID, created.Revision, "v2"); err != nil {
		t.Fatalf("first UpdateFolder: %v", err)
	}

	current, err := st.UpdateFolder(ctx, created.ID, created.Revision, "v3")
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("err = %v, want ErrRevisionConflict", err)
	}
	if current.EncryptedName != "v2" {
		t.Errorf("returned EncryptedName = %q, want the winning row %q", current.EncryptedName, "v2")
	}
}

func TestDeleteFolderTombstonesAndDestroysTheName(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateFolder(ctx, userID, "encrypted-name")
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	deleted, err := st.DeleteFolder(ctx, created.ID)
	if err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
	if !deleted.DeletedAt.Valid {
		t.Error("DeletedAt is not set; the delete will not propagate")
	}

	stored, err := st.FolderByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("FolderByID: %v", err)
	}
	if stored.EncryptedName != "" {
		t.Errorf("EncryptedName = %q after delete, want it destroyed", stored.EncryptedName)
	}
}
```

- [ ] **Step 2: Run and watch it fail**

```bash
go test ./internal/store/ -run Folder -v
```

Expected: FAIL — `st.CreateFolder undefined`.

- [ ] **Step 3: Implement the folder store**

Create `internal/store/folders.go`:

```go
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Folder is a client-side grouping. The name is ciphertext; the server holds
// only the row and its owner. Folders draw from the same revision sequence as
// items so one sync cursor covers both.
type Folder struct {
	ID            string
	UserID        string
	EncryptedName string
	Revision      int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     sql.NullTime
}

const folderColumns = `id, user_id, encrypted_name, revision, created_at, updated_at, deleted_at`

func scanFolder(row interface{ Scan(...any) error }) (Folder, error) {
	var folder Folder
	var createdAt, updatedAt string
	var deletedAt sql.NullString

	err := row.Scan(&folder.ID, &folder.UserID, &folder.EncryptedName,
		&folder.Revision, &createdAt, &updatedAt, &deletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Folder{}, ErrNotFound
	}
	if err != nil {
		return Folder{}, fmt.Errorf("scan folder: %w", err)
	}
	if folder.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return Folder{}, fmt.Errorf("parse created_at: %w", err)
	}
	if folder.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt); err != nil {
		return Folder{}, fmt.Errorf("parse updated_at: %w", err)
	}
	if deletedAt.Valid {
		parsed, err := time.Parse(time.RFC3339, deletedAt.String)
		if err != nil {
			return Folder{}, fmt.Errorf("parse deleted_at: %w", err)
		}
		folder.DeletedAt = sql.NullTime{Time: parsed, Valid: true}
	}
	return folder, nil
}

func (s *Store) FolderByID(ctx context.Context, id string) (Folder, error) {
	return scanFolder(s.db.QueryRowContext(ctx,
		`SELECT `+folderColumns+` FROM folders WHERE id = ?`, id))
}

func (s *Store) CreateFolder(ctx context.Context, userID, encryptedName string) (Folder, error) {
	if encryptedName == "" {
		return Folder{}, &ValidationError{Field: "encryptedName"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Folder{}, fmt.Errorf("begin folder insert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	id, err := NewID()
	if err != nil {
		return Folder{}, err
	}
	revision, err := nextRevision(ctx, tx)
	if err != nil {
		return Folder{}, err
	}
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339)

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO folders (id, user_id, encrypted_name, revision, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, userID, encryptedName, revision, stamp, stamp); err != nil {
		return Folder{}, fmt.Errorf("insert folder: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Folder{}, fmt.Errorf("commit folder insert: %w", err)
	}

	return Folder{
		ID: id, UserID: userID, EncryptedName: encryptedName,
		Revision: revision, CreatedAt: now, UpdatedAt: now,
	}, nil
}

// UpdateFolder renames a folder under the same optimistic check items use, and
// returns the current row alongside ErrRevisionConflict when it loses.
func (s *Store) UpdateFolder(ctx context.Context, id string, expectedRevision int64, encryptedName string) (Folder, error) {
	if encryptedName == "" {
		return Folder{}, &ValidationError{Field: "encryptedName"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Folder{}, fmt.Errorf("begin folder update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	current, err := scanFolder(tx.QueryRowContext(ctx,
		`SELECT `+folderColumns+` FROM folders WHERE id = ?`, id))
	if err != nil {
		return Folder{}, err
	}
	if current.DeletedAt.Valid {
		return Folder{}, ErrNotFound
	}
	if current.Revision != expectedRevision {
		return current, ErrRevisionConflict
	}

	revision, err := nextRevision(ctx, tx)
	if err != nil {
		return Folder{}, err
	}
	now := time.Now().UTC()

	if _, err := tx.ExecContext(ctx,
		`UPDATE folders SET encrypted_name = ?, revision = ?, updated_at = ?
		 WHERE id = ? AND revision = ? AND deleted_at IS NULL`,
		encryptedName, revision, now.Format(time.RFC3339), id, expectedRevision); err != nil {
		return Folder{}, fmt.Errorf("update folder: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Folder{}, fmt.Errorf("commit folder update: %w", err)
	}

	current.EncryptedName = encryptedName
	current.Revision = revision
	current.UpdatedAt = now
	return current, nil
}

// DeleteFolder tombstones the folder and destroys its encrypted name. Items
// are not touched: folder membership lives inside each item's encrypted body,
// so the client reconciles orphaned items after it decrypts them.
func (s *Store) DeleteFolder(ctx context.Context, id string) (Folder, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Folder{}, fmt.Errorf("begin folder delete: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	current, err := scanFolder(tx.QueryRowContext(ctx,
		`SELECT `+folderColumns+` FROM folders WHERE id = ?`, id))
	if err != nil {
		return Folder{}, err
	}
	if current.DeletedAt.Valid {
		return Folder{}, ErrNotFound
	}

	revision, err := nextRevision(ctx, tx)
	if err != nil {
		return Folder{}, err
	}
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339)

	if _, err := tx.ExecContext(ctx,
		`UPDATE folders SET encrypted_name = '', revision = ?, updated_at = ?, deleted_at = ?
		 WHERE id = ? AND deleted_at IS NULL`,
		revision, stamp, stamp, id); err != nil {
		return Folder{}, fmt.Errorf("delete folder: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Folder{}, fmt.Errorf("commit folder delete: %w", err)
	}

	current.EncryptedName = ""
	current.Revision = revision
	current.UpdatedAt = now
	current.DeletedAt = sql.NullTime{Time: now, Valid: true}
	return current, nil
}
```

- [ ] **Step 4: Run the folder tests**

```bash
go test ./internal/store/ -run Folder -v
```

Expected: PASS, all five.

- [ ] **Step 5: Write the failing sync tests**

Create `internal/store/sync_test.go`. `seedCollection` is a local helper
because Task 4's `CreateCollection` does not exist yet; it writes the two rows
directly, and the visibility rules under test depend only on the rows existing.

```go
package store

import (
	"context"
	"testing"
	"time"
)

// seedCollection inserts a collection and its memberships directly. Task 4
// replaces this with CreateCollection.
func seedCollection(t *testing.T, st *Store, createdBy string, memberIDs ...string) string {
	t.Helper()
	ctx := context.Background()
	id, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO collections (id, name, created_by, created_at) VALUES (?, ?, ?, ?)`,
		id, "Household", createdBy, now); err != nil {
		t.Fatalf("insert collection: %v", err)
	}
	for _, member := range memberIDs {
		if _, err := st.DB().ExecContext(ctx,
			`INSERT INTO collection_memberships
			 (collection_id, user_id, sealed_collection_key, role, granted_by, granted_at)
			 VALUES (?, ?, ?, 'member', ?, ?)`,
			id, member, "sealed-blob", createdBy, now); err != nil {
			t.Fatalf("insert membership: %v", err)
		}
	}
	return id
}

func TestSyncReturnsOnlyTheCallersPersonalItems(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	mine := enrolledUserID(t, st, "mine@example.com")
	theirs := enrolledUserID(t, st, "theirs@example.com")

	own, err := st.CreateItem(ctx, mine, ItemInput{Ciphertext: "mine", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	if _, err := st.CreateItem(ctx, theirs, ItemInput{Ciphertext: "theirs", WrappedItemKey: "k"}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	result, err := st.SyncSince(ctx, mine, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("got %d items, want exactly 1 — another user's vault is visible", len(result.Items))
	}
	if result.Items[0].ID != own.ID {
		t.Errorf("returned item %q, want %q", result.Items[0].ID, own.ID)
	}
}

func TestSyncReturnsItemsInCollectionsTheCallerBelongsTo(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	owner := enrolledUserID(t, st, "owner@example.com")
	member := enrolledUserID(t, st, "member@example.com")
	outsider := enrolledUserID(t, st, "outsider@example.com")

	collectionID := seedCollection(t, st, owner, owner, member)
	shared, err := st.CreateItem(ctx, owner, ItemInput{
		CollectionID: collectionID, Ciphertext: "shared", WrappedItemKey: "k",
	})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	// A member sees it even though they did not create it: spec section 5.1,
	// owner_user_id records who made the item and confers no exclusive rights.
	memberView, err := st.SyncSince(ctx, member, 0)
	if err != nil {
		t.Fatalf("SyncSince(member): %v", err)
	}
	if len(memberView.Items) != 1 || memberView.Items[0].ID != shared.ID {
		t.Fatalf("member got %d items, want the shared one", len(memberView.Items))
	}

	// Membership is the whole access rule. Someone outside the collection must
	// see nothing, not even that the row exists.
	outsiderView, err := st.SyncSince(ctx, outsider, 0)
	if err != nil {
		t.Fatalf("SyncSince(outsider): %v", err)
	}
	if len(outsiderView.Items) != 0 {
		t.Errorf("a non-member received %d shared items, want 0", len(outsiderView.Items))
	}
}

func TestSyncIsIncrementalFromTheReturnedCursor(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	if _, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "first", WrappedItemKey: "k"}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	first, err := st.SyncSince(ctx, userID, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(first.Items) != 1 {
		t.Fatalf("first sync returned %d items, want 1", len(first.Items))
	}

	// Nothing changed, so the same cursor must return nothing. A sync that
	// re-sends the whole vault on every poll is the failure this cursor exists
	// to prevent.
	second, err := st.SyncSince(ctx, userID, first.Revision)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(second.Items) != 0 {
		t.Errorf("an unchanged vault returned %d items, want 0", len(second.Items))
	}
	if second.Revision != first.Revision {
		t.Errorf("cursor moved on an unchanged vault: %d -> %d", first.Revision, second.Revision)
	}

	if _, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "second", WrappedItemKey: "k"}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	third, err := st.SyncSince(ctx, userID, first.Revision)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(third.Items) != 1 || third.Items[0].Ciphertext != "second" {
		t.Errorf("incremental sync returned %d items, want just the new one", len(third.Items))
	}
}

func TestSyncCarriesTombstonesSoDeletesPropagate(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "c", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	afterCreate, err := st.SyncSince(ctx, userID, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if _, err := st.DeleteItem(ctx, created.ID); err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}

	// Omitting tombstones leaves the item on every other device forever, with
	// no event that ever removes it.
	result, err := st.SyncSince(ctx, userID, afterCreate.Revision)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("got %d items after a delete, want the tombstone", len(result.Items))
	}
	if !result.Items[0].DeletedAt.Valid {
		t.Error("the returned row is not marked deleted")
	}
	if result.Items[0].Ciphertext != "" {
		t.Error("a tombstone still carries ciphertext")
	}
}

func TestSyncReturnsFoldersOnTheSameCursor(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	mine := enrolledUserID(t, st, "mine@example.com")
	theirs := enrolledUserID(t, st, "theirs@example.com")

	if _, err := st.CreateFolder(ctx, mine, "mine"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	if _, err := st.CreateFolder(ctx, theirs, "theirs"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	result, err := st.SyncSince(ctx, mine, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(result.Folders) != 1 {
		t.Fatalf("got %d folders, want 1 — folders are personal and another "+
			"user's are visible", len(result.Folders))
	}
	if result.Folders[0].EncryptedName != "mine" {
		t.Errorf("returned the wrong user's folder: %q", result.Folders[0].EncryptedName)
	}
}

func TestSyncNeverReportsACursorAheadOfItsRows(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	// The cursor and the rows must come from one snapshot. Reading the
	// high-water mark outside the read transaction lets a row commit between
	// the two reads: the client then stores a cursor past a row it never
	// received, and that item is invisible to it forever.
	for i := 0; i < 20; i++ {
		if _, err := st.CreateItem(ctx, userID,
			ItemInput{Ciphertext: "c", WrappedItemKey: "k"}); err != nil {
			t.Fatalf("CreateItem: %v", err)
		}
	}
	result, err := st.SyncSince(ctx, userID, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(result.Items) != 20 {
		t.Fatalf("got %d items, want 20", len(result.Items))
	}
	for _, item := range result.Items {
		if item.Revision > result.Revision {
			t.Errorf("item revision %d exceeds the reported cursor %d; a client "+
				"storing that cursor would never see this item again",
				item.Revision, result.Revision)
		}
	}
}

func TestCanAccessItemFollowsOwnershipAndMembership(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	owner := enrolledUserID(t, st, "owner@example.com")
	member := enrolledUserID(t, st, "member@example.com")
	outsider := enrolledUserID(t, st, "outsider@example.com")

	personal, err := st.CreateItem(ctx, owner, ItemInput{Ciphertext: "c", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	collectionID := seedCollection(t, st, owner, owner, member)
	shared, err := st.CreateItem(ctx, owner, ItemInput{
		CollectionID: collectionID, Ciphertext: "c", WrappedItemKey: "k",
	})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	cases := []struct {
		name   string
		userID string
		item   Item
		want   bool
	}{
		{"owner reads their personal item", owner, personal, true},
		{"outsider cannot read a personal item", outsider, personal, false},
		{"member reads a shared item they did not create", member, shared, true},
		{"outsider cannot read a shared item", outsider, shared, false},
		{"owner reads a shared item they created", owner, shared, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := st.CanAccessItem(ctx, tc.userID, tc.item)
			if err != nil {
				t.Fatalf("CanAccessItem: %v", err)
			}
			if got != tc.want {
				t.Errorf("CanAccessItem = %v, want %v", got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 6: Run and watch it fail**

```bash
go test ./internal/store/ -run "Sync|CanAccess" -v
```

Expected: FAIL — `st.SyncSince undefined`.

- [ ] **Step 7: Implement the sync query**

Create `internal/store/sync.go`:

```go
package store

import (
	"context"
	"database/sql"
	"fmt"
)

// SyncResult is everything a client needs to bring itself up to date.
// Collections join it in Task 4 — they are sent in full rather than
// incrementally, so they do not participate in the cursor.
type SyncResult struct {
	// Revision is the cursor to send on the next sync. It is read inside the
	// same transaction as the rows, so it can never be ahead of what was
	// returned.
	Revision int64
	Items    []Item
	Folders  []Folder
}

// visibleItemsClause is the one definition of what a user may see: their own
// personal items, plus every item in every collection they belong to. It lives
// in one place because a divergence between the sync query and the
// single-item access check is exactly how one user ends up reading another's
// vault. It takes the user id twice.
const visibleItemsClause = `(
	(owner_user_id = ? AND collection_id IS NULL)
	OR collection_id IN (SELECT collection_id FROM collection_memberships WHERE user_id = ?)
)`

// SyncSince returns every item and folder visible to userID that changed after
// the given revision, tombstones included.
//
// It all happens inside one transaction. The cursor is read from the same
// snapshot as the rows, so a write committing mid-read cannot produce a cursor
// past a row the client never received — a row that would then be invisible to
// that client forever, with no error to report it.
func (s *Store) SyncSince(ctx context.Context, userID string, since int64) (SyncResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SyncResult{}, fmt.Errorf("begin sync: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var result SyncResult
	if err := tx.QueryRowContext(ctx,
		`SELECT value FROM revision_sequence WHERE id = 1`).Scan(&result.Revision); err != nil {
		return SyncResult{}, fmt.Errorf("read revision sequence: %w", err)
	}

	itemRows, err := tx.QueryContext(ctx,
		`SELECT `+itemColumns+` FROM items
		 WHERE revision > ? AND `+visibleItemsClause+`
		 ORDER BY revision`,
		since, userID, userID)
	if err != nil {
		return SyncResult{}, fmt.Errorf("select items: %w", err)
	}
	if result.Items, err = collectItems(itemRows); err != nil {
		return SyncResult{}, err
	}

	folderRows, err := tx.QueryContext(ctx,
		`SELECT `+folderColumns+` FROM folders
		 WHERE revision > ? AND user_id = ?
		 ORDER BY revision`,
		since, userID)
	if err != nil {
		return SyncResult{}, fmt.Errorf("select folders: %w", err)
	}
	if result.Folders, err = collectFolders(folderRows); err != nil {
		return SyncResult{}, err
	}

	if err := tx.Commit(); err != nil {
		return SyncResult{}, fmt.Errorf("commit sync: %w", err)
	}
	return result, nil
}

func collectItems(rows *sql.Rows) ([]Item, error) {
	defer func() { _ = rows.Close() }()
	items := []Item{}
	for rows.Next() {
		item, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate items: %w", err)
	}
	return items, nil
}

func collectFolders(rows *sql.Rows) ([]Folder, error) {
	defer func() { _ = rows.Close() }()
	folders := []Folder{}
	for rows.Next() {
		folder, err := scanFolder(rows)
		if err != nil {
			return nil, err
		}
		folders = append(folders, folder)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate folders: %w", err)
	}
	return folders, nil
}

// CanAccessItem answers the single-item version of the sync visibility rule.
// Handlers call it before every read, write, and delete of one item.
func (s *Store) CanAccessItem(ctx context.Context, userID string, item Item) (bool, error) {
	if !item.CollectionID.Valid {
		return item.OwnerUserID == userID, nil
	}
	var count int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM collection_memberships WHERE collection_id = ? AND user_id = ?`,
		item.CollectionID.String, userID).Scan(&count); err != nil {
		return false, fmt.Errorf("check membership: %w", err)
	}
	return count > 0, nil
}
```

- [ ] **Step 8: Run the sync tests**

```bash
go test ./internal/store/ -run "Sync|CanAccess" -v
```

Expected: PASS.

- [ ] **Step 9: Prove the visibility filter is load-bearing**

Temporarily replace the body of `visibleItemsClause` with a clause that still
consumes both parameters but admits everything:

```go
const visibleItemsClause = `(? IS NOT NULL OR ? IS NOT NULL)`
```

Run:

```bash
go test ./internal/store/ -run TestSyncReturnsOnlyTheCallersPersonalItems -v
```

Expected: FAIL, reporting 2 items where 1 was wanted. Revert and confirm PASS.
Put both outputs in the report — this test is the only thing between the sync
endpoint and a full cross-user vault leak.

- [ ] **Step 10: Full suite, vet, gofmt**

```bash
go test ./... && gofmt -l ./internal ./cmd && go vet ./...
```

Expected: PASS, no output from `gofmt -l`, vet silent.

- [ ] **Step 11: Commit**

```bash
git add internal/store/ && git commit -m "feat(store): folders and the sync visibility query"
```

---

## Task 3: Item, folder, and sync endpoints

**Files:**
- Create: `internal/httpapi/vault.go` (JSON shapes, shared helpers, `writeStoreError`)
- Create: `internal/httpapi/items.go`
- Create: `internal/httpapi/folders.go`
- Create: `internal/httpapi/sync.go`
- Create: `internal/httpapi/helpers_test.go`
- Test: `internal/httpapi/items_test.go`, `internal/httpapi/folders_test.go`, `internal/httpapi/sync_test.go`
- Modify: `internal/httpapi/errors.go` (add `DecodeJSONLimit`)
- Modify: `internal/httpapi/server.go` (register the routes)

**Interfaces:**
- Consumes: `store.Item`, `store.ItemInput`, `store.Folder`, `store.SyncResult`,
  `store.CanAccessItem`, `store.ErrRevisionConflict`, `store.ErrNotFound`,
  `*store.ValidationError` (Tasks 1–2); `Server.requireAuth`, `UserFrom`,
  `DecodeJSON`, `WriteJSON`, `WriteError`, `RequestIDFrom` (Plan 2a).
- Produces, and every later task uses these:
  ```go
  func (s *Server) writeStoreError(w http.ResponseWriter, r *http.Request, what string, err error)
  func DecodeJSONLimit(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool
  func toItemJSON(item store.Item) itemJSON
  func toFolderJSON(folder store.Folder) folderJSON
  ```
  Test helpers in `helpers_test.go`: `loginTestUser`, `doJSON`, `decodeInto`.

**Routes registered:**

```
POST   /api/items
POST   /api/items/bulk
PUT    /api/items/{id}
DELETE /api/items/{id}
POST   /api/folders
PUT    /api/folders/{id}
DELETE /api/folders/{id}
GET    /api/sync
```

All behind `requireAuth`.

- [ ] **Step 1: Add the body-limit variant**

In `internal/httpapi/errors.go`, replace `DecodeJSON`'s body with a call to a
new limited form, keeping the doc comment where it is:

```go
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	return DecodeJSONLimit(w, r, dst, maxRequestBody)
}

// DecodeJSONLimit is DecodeJSON with an explicit cap. Only the bulk import
// route raises it: a vault export is thousands of items, and forcing the client
// to send them one per request turns an import into thousands of round trips.
// Everything else keeps the 1 MiB default, because a single item is small and
// anything larger is a mistake or an attempt to exhaust memory.
func DecodeJSONLimit(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		var maxBytes *http.MaxBytesError
		switch {
		case errors.As(err, &maxBytes):
			WriteError(w, http.StatusBadRequest, CodeBadRequest, "request body is too large")
		case strings.Contains(err.Error(), "unknown field"):
			WriteError(w, http.StatusBadRequest, CodeBadRequest, "request contains an unrecognized field")
		default:
			WriteError(w, http.StatusBadRequest, CodeBadRequest, "request body is not valid JSON")
		}
		return false
	}

	if decoder.More() {
		WriteError(w, http.StatusBadRequest, CodeBadRequest, "request body must contain a single JSON object")
		return false
	}
	return true
}
```

- [ ] **Step 2: Write the test helpers**

Create `internal/httpapi/helpers_test.go`:

```go
package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ssan9876/keyhole/internal/store"
)

// loginTestUser enrolls an account and signs in, returning the user and a live
// access token. Every vault endpoint is behind requireAuth, so this is the
// starting point of nearly every test from here on.
func loginTestUser(t *testing.T, srv *Server, email string) (store.User, string) {
	t.Helper()

	user, authHash := enrollTestUser(t, srv, email)
	rec := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email":       email,
		"authHash":    authHash,
		"deviceLabel": "test device",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}

	var body struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("login body: %v", err)
	}
	if body.AccessToken == "" {
		t.Fatal("login returned no access token")
	}
	return user, body.AccessToken
}

// doJSON sends an authenticated request. A blank token sends no Authorization
// header at all, which is how the unauthenticated cases are exercised.
func doJSON(t *testing.T, srv *Server, method, path, token string, payload any) *httptest.ResponseRecorder {
	t.Helper()

	var body *bytes.Reader
	if payload == nil {
		body = bytes.NewReader(nil)
	} else {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		body = bytes.NewReader(encoded)
	}

	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func decodeInto(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("response is not valid JSON (%d): %s", rec.Code, rec.Body.String())
	}
}
```

- [ ] **Step 3: Write the failing item endpoint tests**

Create `internal/httpapi/items_test.go`:

```go
package httpapi

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/ssan9876/keyhole/internal/store"
)

type itemResponse struct {
	ID             string  `json:"id"`
	CollectionID   *string `json:"collectionId"`
	OwnerUserID    string  `json:"ownerUserId"`
	Ciphertext     string  `json:"ciphertext"`
	WrappedItemKey string  `json:"wrappedItemKey"`
	Revision       int64   `json:"revision"`
	CreatedAt      string  `json:"createdAt"`
	UpdatedAt      string  `json:"updatedAt"`
	DeletedAt      *string `json:"deletedAt"`
}

// seedTestCollection creates a collection with the given members directly.
// Task 5 adds the endpoint that does this properly.
func seedTestCollection(t *testing.T, srv *Server, createdBy string, memberIDs ...string) string {
	t.Helper()
	ctx := context.Background()
	id, err := store.NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := srv.store.DB().ExecContext(ctx,
		`INSERT INTO collections (id, name, created_by, created_at) VALUES (?, ?, ?, ?)`,
		id, "Household", createdBy, now); err != nil {
		t.Fatalf("insert collection: %v", err)
	}
	for _, member := range memberIDs {
		if _, err := srv.store.DB().ExecContext(ctx,
			`INSERT INTO collection_memberships
			 (collection_id, user_id, sealed_collection_key, role, granted_by, granted_at)
			 VALUES (?, ?, ?, 'member', ?, ?)`,
			id, member, "sealed-blob", createdBy, now); err != nil {
			t.Fatalf("insert membership: %v", err)
		}
	}
	return id
}

func TestCreateItemRequiresAuthentication(t *testing.T) {
	srv := newTestServer(t)

	rec := doJSON(t, srv, http.MethodPost, "/api/items", "", map[string]string{
		"ciphertext": "c", "wrappedItemKey": "k",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d — the vault is readable without a session",
			rec.Code, http.StatusUnauthorized)
	}
}

func TestCreateItemReturnsTheStoredItem(t *testing.T) {
	srv := newTestServer(t)
	user, token := loginTestUser(t, srv, "person@example.com")

	const ct = `{"v":1,"alg":"A256GCM","n":"AAAAAAAAAAAAAAAA","ct":"3q2+7w=="}`
	rec := doJSON(t, srv, http.MethodPost, "/api/items", token, map[string]string{
		"ciphertext": ct, "wrappedItemKey": "wrapped",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var item itemResponse
	decodeInto(t, rec, &item)
	if item.Ciphertext != ct {
		t.Errorf("ciphertext = %q, want it echoed verbatim", item.Ciphertext)
	}
	if item.OwnerUserID != user.ID {
		t.Errorf("ownerUserId = %q, want %q", item.OwnerUserID, user.ID)
	}
	if item.CollectionID != nil {
		t.Errorf("collectionId = %v, want null for a personal item", *item.CollectionID)
	}
	if item.Revision < 1 {
		t.Errorf("revision = %d, want at least 1", item.Revision)
	}
	// The client needs this to send an If-Match-style revision on its next
	// edit; without it every first edit would conflict.
	if item.ID == "" {
		t.Error("response carries no id")
	}
}

func TestCreateItemRejectsAMissingCiphertext(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	rec := doJSON(t, srv, http.MethodPost, "/api/items", token, map[string]string{
		"wrappedItemKey": "k",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCreateItemInAForeignCollectionIsNotFound(t *testing.T) {
	srv := newTestServer(t)
	owner, _ := loginTestUser(t, srv, "owner@example.com")
	_, outsiderToken := loginTestUser(t, srv, "outsider@example.com")

	collectionID := seedTestCollection(t, srv, owner.ID, owner.ID)

	// 404, not 403: a 403 would confirm the collection exists, which is how a
	// caller maps out the membership graph one guess at a time.
	rec := doJSON(t, srv, http.MethodPost, "/api/items", outsiderToken, map[string]string{
		"collectionId": collectionID, "ciphertext": "c", "wrappedItemKey": "k",
	})
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	var count int
	if err := srv.store.DB().QueryRow(`SELECT COUNT(*) FROM items`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("%d items were written into a collection the caller does not belong to", count)
	}
}

func TestUpdateItemRequiresTheCurrentRevisionAndReturnsTheWinnerOnConflict(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/items", token, map[string]string{
		"ciphertext": "v1", "wrappedItemKey": "k",
	})
	var item itemResponse
	decodeInto(t, created, &item)

	ok := doJSON(t, srv, http.MethodPut, "/api/items/"+item.ID, token, map[string]any{
		"ciphertext": "v2", "wrappedItemKey": "k", "revision": item.Revision,
	})
	if ok.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", ok.Code, http.StatusOK, ok.Body.String())
	}

	// The second edit was made from the pre-edit revision.
	conflict := doJSON(t, srv, http.MethodPut, "/api/items/"+item.ID, token, map[string]any{
		"ciphertext": "v3", "wrappedItemKey": "k", "revision": item.Revision,
	})
	if conflict.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", conflict.Code, http.StatusConflict)
	}

	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
		Item itemResponse `json:"item"`
	}
	decodeInto(t, conflict, &body)
	if body.Error.Code != "conflict" {
		t.Errorf("code = %q, want %q", body.Error.Code, "conflict")
	}
	// Without the winning copy in the response the client has nothing to
	// reconcile against and its only option is to discard one of the two edits.
	if body.Item.Ciphertext != "v2" {
		t.Errorf("conflict body item ciphertext = %q, want the winning %q",
			body.Item.Ciphertext, "v2")
	}
	if body.Item.Revision == 0 {
		t.Error("conflict body carries no revision to retry with")
	}
}

func TestUpdatingAnotherUsersItemIsNotFound(t *testing.T) {
	srv := newTestServer(t)
	_, ownerToken := loginTestUser(t, srv, "owner@example.com")
	_, otherToken := loginTestUser(t, srv, "other@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/items", ownerToken, map[string]string{
		"ciphertext": "mine", "wrappedItemKey": "k",
	})
	var item itemResponse
	decodeInto(t, created, &item)

	rec := doJSON(t, srv, http.MethodPut, "/api/items/"+item.ID, otherToken, map[string]any{
		"ciphertext": "theirs", "wrappedItemKey": "k", "revision": item.Revision,
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d — one user can write another's vault",
			rec.Code, http.StatusNotFound)
	}

	stored, err := srv.store.ItemByID(context.Background(), item.ID)
	if err != nil {
		t.Fatalf("ItemByID: %v", err)
	}
	if stored.Ciphertext != "mine" {
		t.Errorf("stored ciphertext = %q; another user's write landed", stored.Ciphertext)
	}
}

func TestAMemberMayEditAnItemTheyDidNotCreate(t *testing.T) {
	srv := newTestServer(t)
	owner, ownerToken := loginTestUser(t, srv, "owner@example.com")
	member, memberToken := loginTestUser(t, srv, "member@example.com")

	collectionID := seedTestCollection(t, srv, owner.ID, owner.ID, member.ID)

	created := doJSON(t, srv, http.MethodPost, "/api/items", ownerToken, map[string]string{
		"collectionId": collectionID, "ciphertext": "v1", "wrappedItemKey": "k",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var item itemResponse
	decodeInto(t, created, &item)

	// Spec section 5.1: any member may edit any item in a collection.
	// owner_user_id records who made it and confers no exclusive rights.
	rec := doJSON(t, srv, http.MethodPut, "/api/items/"+item.ID, memberToken, map[string]any{
		"collectionId": collectionID, "ciphertext": "v2",
		"wrappedItemKey": "k", "revision": item.Revision,
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	_ = member
}

func TestDeleteItemTombstonesAndIsIdempotentlyNotFound(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/items", token, map[string]string{
		"ciphertext": "c", "wrappedItemKey": "k",
	})
	var item itemResponse
	decodeInto(t, created, &item)

	rec := doJSON(t, srv, http.MethodDelete, "/api/items/"+item.ID, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var deleted itemResponse
	decodeInto(t, rec, &deleted)
	if deleted.DeletedAt == nil {
		t.Error("delete response carries no deletedAt")
	}
	if deleted.Ciphertext != "" {
		t.Error("delete response still carries ciphertext")
	}

	again := doJSON(t, srv, http.MethodDelete, "/api/items/"+item.ID, token, nil)
	if again.Code != http.StatusNotFound {
		t.Errorf("second delete status = %d, want %d", again.Code, http.StatusNotFound)
	}
}

func TestDeletingAnotherUsersItemIsNotFound(t *testing.T) {
	srv := newTestServer(t)
	_, ownerToken := loginTestUser(t, srv, "owner@example.com")
	_, otherToken := loginTestUser(t, srv, "other@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/items", ownerToken, map[string]string{
		"ciphertext": "mine", "wrappedItemKey": "k",
	})
	var item itemResponse
	decodeInto(t, created, &item)

	rec := doJSON(t, srv, http.MethodDelete, "/api/items/"+item.ID, otherToken, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	stored, err := srv.store.ItemByID(context.Background(), item.ID)
	if err != nil {
		t.Fatalf("ItemByID: %v", err)
	}
	if stored.DeletedAt.Valid {
		t.Error("another user deleted this item")
	}
}

func TestBulkImportWritesEveryRowOrNone(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	good := doJSON(t, srv, http.MethodPost, "/api/items/bulk", token, map[string]any{
		"items": []map[string]string{
			{"ciphertext": "a", "wrappedItemKey": "k"},
			{"ciphertext": "b", "wrappedItemKey": "k"},
			{"ciphertext": "c", "wrappedItemKey": "k"},
		},
	})
	if good.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", good.Code, http.StatusCreated, good.Body.String())
	}
	var body struct {
		Items []itemResponse `json:"items"`
	}
	decodeInto(t, good, &body)
	if len(body.Items) != 3 {
		t.Fatalf("returned %d items, want 3", len(body.Items))
	}

	// An import that half-lands leaves the user with no way to tell which half.
	bad := doJSON(t, srv, http.MethodPost, "/api/items/bulk", token, map[string]any{
		"items": []map[string]string{
			{"ciphertext": "d", "wrappedItemKey": "k"},
			{"ciphertext": "", "wrappedItemKey": "k"},
		},
	})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", bad.Code, http.StatusBadRequest)
	}

	var count int
	if err := srv.store.DB().QueryRow(`SELECT COUNT(*) FROM items`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 3 {
		t.Errorf("item count = %d, want the 3 from the good batch only", count)
	}
}

func TestBulkImportRejectsAnOversizedBatch(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	// A cap the client can chunk against, rather than an unbounded transaction
	// that holds the single SQLite writer for an unbounded time.
	items := make([]map[string]string, maxBulkItems+1)
	for i := range items {
		items[i] = map[string]string{"ciphertext": "c", "wrappedItemKey": "k"}
	}
	rec := doJSON(t, srv, http.MethodPost, "/api/items/bulk", token, map[string]any{"items": items})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestBulkImportRejectsAnEmptyBatch(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	rec := doJSON(t, srv, http.MethodPost, "/api/items/bulk", token,
		map[string]any{"items": []map[string]string{}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
```

- [ ] **Step 4: Run and watch it fail**

```bash
go test ./internal/httpapi/ -run Item -v
```

Expected: FAIL — `undefined: maxBulkItems`, and every route returns 404.

- [ ] **Step 5: Write the shared vault JSON layer**

Create `internal/httpapi/vault.go`:

```go
package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/ssan9876/keyhole/internal/store"
)

// itemJSON is the wire shape of an item. Pointers for the nullable fields so a
// personal item sends `"collectionId": null` rather than an empty string a
// client would have to special-case.
type itemJSON struct {
	ID             string  `json:"id"`
	CollectionID   *string `json:"collectionId"`
	OwnerUserID    string  `json:"ownerUserId"`
	Ciphertext     string  `json:"ciphertext"`
	WrappedItemKey string  `json:"wrappedItemKey"`
	Revision       int64   `json:"revision"`
	CreatedAt      string  `json:"createdAt"`
	UpdatedAt      string  `json:"updatedAt"`
	DeletedAt      *string `json:"deletedAt"`
}

func toItemJSON(item store.Item) itemJSON {
	out := itemJSON{
		ID:             item.ID,
		OwnerUserID:    item.OwnerUserID,
		Ciphertext:     item.Ciphertext,
		WrappedItemKey: item.WrappedItemKey,
		Revision:       item.Revision,
		CreatedAt:      item.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      item.UpdatedAt.Format(time.RFC3339),
	}
	if item.CollectionID.Valid {
		collection := item.CollectionID.String
		out.CollectionID = &collection
	}
	if item.DeletedAt.Valid {
		deleted := item.DeletedAt.Time.Format(time.RFC3339)
		out.DeletedAt = &deleted
	}
	return out
}

type folderJSON struct {
	ID            string  `json:"id"`
	EncryptedName string  `json:"encryptedName"`
	Revision      int64   `json:"revision"`
	CreatedAt     string  `json:"createdAt"`
	UpdatedAt     string  `json:"updatedAt"`
	DeletedAt     *string `json:"deletedAt"`
}

func toFolderJSON(folder store.Folder) folderJSON {
	out := folderJSON{
		ID:            folder.ID,
		EncryptedName: folder.EncryptedName,
		Revision:      folder.Revision,
		CreatedAt:     folder.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     folder.UpdatedAt.Format(time.RFC3339),
	}
	if folder.DeletedAt.Valid {
		deleted := folder.DeletedAt.Time.Format(time.RFC3339)
		out.DeletedAt = &deleted
	}
	return out
}

// writeStoreError is the one place a store error becomes a response.
//
// The default branch is the important one: a transient SQLite error must not
// reach a client as text, and must not be reported as the caller's fault. Only
// ValidationError is safe to echo, because the client wrote it.
func (s *Server) writeStoreError(w http.ResponseWriter, r *http.Request, what string, err error) {
	var validation *store.ValidationError
	switch {
	case errors.Is(err, store.ErrNotFound):
		WriteError(w, http.StatusNotFound, CodeNotFound, "not found")
	case errors.As(err, &validation):
		WriteError(w, http.StatusBadRequest, CodeBadRequest, validation.Error())
	default:
		s.logger.Error(what, "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not process the request")
	}
}

// isCollectionMember reports whether the user may act inside a collection.
// A caller who is not a member is told the collection does not exist, so the
// endpoint cannot be used to map the membership graph one guess at a time.
func (s *Server) isCollectionMember(r *http.Request, collectionID, userID string) (bool, error) {
	var count int
	err := s.store.DB().QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM collection_memberships WHERE collection_id = ? AND user_id = ?`,
		collectionID, userID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
```

- [ ] **Step 6: Write the item handlers**

Create `internal/httpapi/items.go`:

```go
package httpapi

import (
	"errors"
	"net/http"

	"github.com/ssan9876/keyhole/internal/store"
)

const (
	// maxBulkItems bounds one import transaction. SQLite tolerates a single
	// writer, so an unbounded batch blocks every other write for as long as it
	// runs. The client chunks; a thousand rows per request keeps a full vault
	// import to a handful of requests.
	maxBulkItems = 1000
	// maxBulkBody is the matching body cap. The 1 MiB default would reject a
	// batch well under the row limit.
	maxBulkBody = 8 << 20
)

type itemRequest struct {
	CollectionID   string `json:"collectionId"`
	Ciphertext     string `json:"ciphertext"`
	WrappedItemKey string `json:"wrappedItemKey"`
	Revision       int64  `json:"revision"`
}

func (req itemRequest) input() store.ItemInput {
	return store.ItemInput{
		CollectionID:   req.CollectionID,
		Ciphertext:     req.Ciphertext,
		WrappedItemKey: req.WrappedItemKey,
	}
}

// checkCollectionTarget verifies the caller may place an item in the requested
// collection. It writes the response and returns false when they may not.
func (s *Server) checkCollectionTarget(w http.ResponseWriter, r *http.Request, collectionID, userID string) bool {
	if collectionID == "" {
		return true
	}
	member, err := s.isCollectionMember(r, collectionID, userID)
	if err != nil {
		s.writeStoreError(w, r, "check collection membership", err)
		return false
	}
	if !member {
		WriteError(w, http.StatusNotFound, CodeNotFound, "no such collection")
		return false
	}
	return true
}

func (s *Server) handleCreateItem(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	var req itemRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if !s.checkCollectionTarget(w, r, req.CollectionID, user.ID) {
		return
	}

	item, err := s.store.CreateItem(r.Context(), user.ID, req.input())
	if err != nil {
		s.writeStoreError(w, r, "create item", err)
		return
	}
	WriteJSON(w, http.StatusCreated, toItemJSON(item))
}

type bulkItemsRequest struct {
	Items []itemRequest `json:"items"`
}

func (s *Server) handleBulkItems(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	var req bulkItemsRequest
	if !DecodeJSONLimit(w, r, &req, maxBulkBody) {
		return
	}
	if len(req.Items) == 0 {
		WriteError(w, http.StatusBadRequest, CodeBadRequest, "items must not be empty")
		return
	}
	if len(req.Items) > maxBulkItems {
		WriteError(w, http.StatusBadRequest, CodeBadRequest,
			"too many items in one request; send them in smaller batches")
		return
	}

	inputs := make([]store.ItemInput, 0, len(req.Items))
	for _, item := range req.Items {
		if !s.checkCollectionTarget(w, r, item.CollectionID, user.ID) {
			return
		}
		inputs = append(inputs, item.input())
	}

	items, err := s.store.CreateItemsBulk(r.Context(), user.ID, inputs)
	if err != nil {
		s.writeStoreError(w, r, "bulk create items", err)
		return
	}

	out := make([]itemJSON, 0, len(items))
	for _, item := range items {
		out = append(out, toItemJSON(item))
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"items": out})
}

// writeItemConflict is the one place the error envelope carries a sibling.
// The client needs the winning row to build a conflicted copy; without it the
// only way to resolve a conflict is to throw one of the two edits away.
func writeItemConflict(w http.ResponseWriter, current store.Item) {
	WriteJSON(w, http.StatusConflict, struct {
		Error errorBody `json:"error"`
		Item  itemJSON  `json:"item"`
	}{
		Error: errorBody{
			Code:    CodeConflict,
			Message: "this item changed on the server since you last synced",
		},
		Item: toItemJSON(current),
	})
}

func (s *Server) handleUpdateItem(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())
	id := r.PathValue("id")

	var req itemRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	// Authorize against the item as it stands before authorizing the target
	// collection. Checking only the target would let anyone who is a member of
	// any collection move someone else's item into it.
	existing, err := s.store.ItemByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, "load item", err)
		return
	}
	allowed, err := s.store.CanAccessItem(r.Context(), user.ID, existing)
	if err != nil {
		s.writeStoreError(w, r, "check item access", err)
		return
	}
	if !allowed {
		WriteError(w, http.StatusNotFound, CodeNotFound, "not found")
		return
	}
	if !s.checkCollectionTarget(w, r, req.CollectionID, user.ID) {
		return
	}

	item, err := s.store.UpdateItem(r.Context(), id, req.Revision, req.input())
	if errors.Is(err, store.ErrRevisionConflict) {
		writeItemConflict(w, item)
		return
	}
	if err != nil {
		s.writeStoreError(w, r, "update item", err)
		return
	}
	WriteJSON(w, http.StatusOK, toItemJSON(item))
}

func (s *Server) handleDeleteItem(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())
	id := r.PathValue("id")

	existing, err := s.store.ItemByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, "load item", err)
		return
	}
	allowed, err := s.store.CanAccessItem(r.Context(), user.ID, existing)
	if err != nil {
		s.writeStoreError(w, r, "check item access", err)
		return
	}
	if !allowed {
		WriteError(w, http.StatusNotFound, CodeNotFound, "not found")
		return
	}

	item, err := s.store.DeleteItem(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, "delete item", err)
		return
	}
	WriteJSON(w, http.StatusOK, toItemJSON(item))
}
```

- [ ] **Step 7: Register the item routes**

In `internal/httpapi/server.go`, inside `routes()`, above the catch-all:

```go
	s.mux.HandleFunc("POST /api/items", s.requireAuth(s.handleCreateItem))
	s.mux.HandleFunc("POST /api/items/bulk", s.requireAuth(s.handleBulkItems))
	s.mux.HandleFunc("PUT /api/items/{id}", s.requireAuth(s.handleUpdateItem))
	s.mux.HandleFunc("DELETE /api/items/{id}", s.requireAuth(s.handleDeleteItem))
```

`POST /api/items/bulk` and `PUT /api/items/{id}` cannot collide — different
methods — and stdlib `ServeMux` prefers the literal segment over the wildcard
in any case.

- [ ] **Step 8: Run the item tests**

```bash
go test ./internal/httpapi/ -run Item -v
```

Expected: PASS, all twelve.

- [ ] **Step 9: Write the failing folder endpoint tests**

Create `internal/httpapi/folders_test.go`:

```go
package httpapi

import (
	"context"
	"net/http"
	"testing"
)

type folderResponse struct {
	ID            string  `json:"id"`
	EncryptedName string  `json:"encryptedName"`
	Revision      int64   `json:"revision"`
	DeletedAt     *string `json:"deletedAt"`
}

func TestCreateFolderReturnsTheStoredFolder(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	rec := doJSON(t, srv, http.MethodPost, "/api/folders", token, map[string]string{
		"encryptedName": "encrypted-blob",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var folder folderResponse
	decodeInto(t, rec, &folder)
	if folder.EncryptedName != "encrypted-blob" {
		t.Errorf("encryptedName = %q, want it echoed verbatim", folder.EncryptedName)
	}
}

func TestFolderEndpointsRequireAuthentication(t *testing.T) {
	srv := newTestServer(t)

	rec := doJSON(t, srv, http.MethodPost, "/api/folders", "",
		map[string]string{"encryptedName": "n"})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestUpdatingAnotherUsersFolderIsNotFound(t *testing.T) {
	srv := newTestServer(t)
	_, ownerToken := loginTestUser(t, srv, "owner@example.com")
	_, otherToken := loginTestUser(t, srv, "other@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/folders", ownerToken,
		map[string]string{"encryptedName": "mine"})
	var folder folderResponse
	decodeInto(t, created, &folder)

	rec := doJSON(t, srv, http.MethodPut, "/api/folders/"+folder.ID, otherToken, map[string]any{
		"encryptedName": "theirs", "revision": folder.Revision,
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	stored, err := srv.store.FolderByID(context.Background(), folder.ID)
	if err != nil {
		t.Fatalf("FolderByID: %v", err)
	}
	if stored.EncryptedName != "mine" {
		t.Errorf("stored name = %q; another user's write landed", stored.EncryptedName)
	}
}

func TestDeletingAnotherUsersFolderIsNotFound(t *testing.T) {
	srv := newTestServer(t)
	_, ownerToken := loginTestUser(t, srv, "owner@example.com")
	_, otherToken := loginTestUser(t, srv, "other@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/folders", ownerToken,
		map[string]string{"encryptedName": "mine"})
	var folder folderResponse
	decodeInto(t, created, &folder)

	rec := doJSON(t, srv, http.MethodDelete, "/api/folders/"+folder.ID, otherToken, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	stored, err := srv.store.FolderByID(context.Background(), folder.ID)
	if err != nil {
		t.Fatalf("FolderByID: %v", err)
	}
	if stored.DeletedAt.Valid {
		t.Error("another user deleted this folder")
	}
}

func TestUpdateFolderReportsAConflictWithoutAnItemBody(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/folders", token,
		map[string]string{"encryptedName": "v1"})
	var folder folderResponse
	decodeInto(t, created, &folder)

	if rec := doJSON(t, srv, http.MethodPut, "/api/folders/"+folder.ID, token, map[string]any{
		"encryptedName": "v2", "revision": folder.Revision,
	}); rec.Code != http.StatusOK {
		t.Fatalf("first update: %d %s", rec.Code, rec.Body.String())
	}

	rec := doJSON(t, srv, http.MethodPut, "/api/folders/"+folder.ID, token, map[string]any{
		"encryptedName": "v3", "revision": folder.Revision,
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
		Folder folderResponse `json:"folder"`
	}
	decodeInto(t, rec, &body)
	if body.Error.Code != "conflict" {
		t.Errorf("code = %q, want %q", body.Error.Code, "conflict")
	}
	if body.Folder.EncryptedName != "v2" {
		t.Errorf("conflict body folder = %q, want the winning %q", body.Folder.EncryptedName, "v2")
	}
}
```

- [ ] **Step 10: Implement the folder handlers**

Create `internal/httpapi/folders.go`:

```go
package httpapi

import (
	"errors"
	"net/http"

	"github.com/ssan9876/keyhole/internal/store"
)

type folderRequest struct {
	EncryptedName string `json:"encryptedName"`
	Revision      int64  `json:"revision"`
}

// requireOwnFolder resolves a folder the caller owns. Folders are personal:
// there is no shared-folder concept, so ownership is the whole rule. A folder
// belonging to someone else reports not-found rather than forbidden.
func (s *Server) requireOwnFolder(w http.ResponseWriter, r *http.Request, id, userID string) (store.Folder, bool) {
	folder, err := s.store.FolderByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, "load folder", err)
		return store.Folder{}, false
	}
	if folder.UserID != userID {
		WriteError(w, http.StatusNotFound, CodeNotFound, "not found")
		return store.Folder{}, false
	}
	return folder, true
}

func (s *Server) handleCreateFolder(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	var req folderRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	folder, err := s.store.CreateFolder(r.Context(), user.ID, req.EncryptedName)
	if err != nil {
		s.writeStoreError(w, r, "create folder", err)
		return
	}
	WriteJSON(w, http.StatusCreated, toFolderJSON(folder))
}

func writeFolderConflict(w http.ResponseWriter, current store.Folder) {
	WriteJSON(w, http.StatusConflict, struct {
		Error  errorBody  `json:"error"`
		Folder folderJSON `json:"folder"`
	}{
		Error: errorBody{
			Code:    CodeConflict,
			Message: "this folder changed on the server since you last synced",
		},
		Folder: toFolderJSON(current),
	})
}

func (s *Server) handleUpdateFolder(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())
	id := r.PathValue("id")

	var req folderRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if _, ok := s.requireOwnFolder(w, r, id, user.ID); !ok {
		return
	}

	folder, err := s.store.UpdateFolder(r.Context(), id, req.Revision, req.EncryptedName)
	if errors.Is(err, store.ErrRevisionConflict) {
		writeFolderConflict(w, folder)
		return
	}
	if err != nil {
		s.writeStoreError(w, r, "update folder", err)
		return
	}
	WriteJSON(w, http.StatusOK, toFolderJSON(folder))
}

func (s *Server) handleDeleteFolder(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())
	id := r.PathValue("id")

	if _, ok := s.requireOwnFolder(w, r, id, user.ID); !ok {
		return
	}

	folder, err := s.store.DeleteFolder(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, "delete folder", err)
		return
	}
	WriteJSON(w, http.StatusOK, toFolderJSON(folder))
}
```

Register in `routes()`:

```go
	s.mux.HandleFunc("POST /api/folders", s.requireAuth(s.handleCreateFolder))
	s.mux.HandleFunc("PUT /api/folders/{id}", s.requireAuth(s.handleUpdateFolder))
	s.mux.HandleFunc("DELETE /api/folders/{id}", s.requireAuth(s.handleDeleteFolder))
```

- [ ] **Step 11: Run the folder tests**

```bash
go test ./internal/httpapi/ -run Folder -v
```

Expected: PASS, all five.

- [ ] **Step 12: Write the failing sync endpoint tests**

Create `internal/httpapi/sync_test.go`:

```go
package httpapi

import (
	"fmt"
	"net/http"
	"testing"
)

type syncResponse struct {
	Revision int64            `json:"revision"`
	Items    []itemResponse   `json:"items"`
	Folders  []folderResponse `json:"folders"`
}

func TestSyncRequiresAuthentication(t *testing.T) {
	srv := newTestServer(t)

	rec := doJSON(t, srv, http.MethodGet, "/api/sync", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestSyncReturnsTheVaultAndACursor(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	for i := 0; i < 3; i++ {
		rec := doJSON(t, srv, http.MethodPost, "/api/items", token, map[string]string{
			"ciphertext": fmt.Sprintf("item-%d", i), "wrappedItemKey": "k",
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
		}
	}
	if rec := doJSON(t, srv, http.MethodPost, "/api/folders", token,
		map[string]string{"encryptedName": "f"}); rec.Code != http.StatusCreated {
		t.Fatalf("create folder: %d %s", rec.Code, rec.Body.String())
	}

	rec := doJSON(t, srv, http.MethodGet, "/api/sync", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body syncResponse
	decodeInto(t, rec, &body)
	if len(body.Items) != 3 {
		t.Errorf("got %d items, want 3", len(body.Items))
	}
	if len(body.Folders) != 1 {
		t.Errorf("got %d folders, want 1", len(body.Folders))
	}
	if body.Revision < 4 {
		t.Errorf("revision = %d, want at least 4", body.Revision)
	}
}

func TestSyncSinceTheCursorReturnsOnlyWhatChanged(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	if rec := doJSON(t, srv, http.MethodPost, "/api/items", token, map[string]string{
		"ciphertext": "first", "wrappedItemKey": "k",
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d", rec.Code)
	}

	first := doJSON(t, srv, http.MethodGet, "/api/sync", token, nil)
	var firstBody syncResponse
	decodeInto(t, first, &firstBody)

	if rec := doJSON(t, srv, http.MethodPost, "/api/items", token, map[string]string{
		"ciphertext": "second", "wrappedItemKey": "k",
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d", rec.Code)
	}

	second := doJSON(t, srv, http.MethodGet,
		fmt.Sprintf("/api/sync?since=%d", firstBody.Revision), token, nil)
	var secondBody syncResponse
	decodeInto(t, second, &secondBody)

	if len(secondBody.Items) != 1 {
		t.Fatalf("got %d items, want only the new one", len(secondBody.Items))
	}
	if secondBody.Items[0].Ciphertext != "second" {
		t.Errorf("ciphertext = %q, want %q", secondBody.Items[0].Ciphertext, "second")
	}
}

func TestSyncNeverLeaksAnotherUsersVault(t *testing.T) {
	srv := newTestServer(t)
	_, mineToken := loginTestUser(t, srv, "mine@example.com")
	_, theirsToken := loginTestUser(t, srv, "theirs@example.com")

	if rec := doJSON(t, srv, http.MethodPost, "/api/items", theirsToken, map[string]string{
		"ciphertext": "their-secret", "wrappedItemKey": "k",
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d", rec.Code)
	}

	rec := doJSON(t, srv, http.MethodGet, "/api/sync", mineToken, nil)
	var body syncResponse
	decodeInto(t, rec, &body)
	if len(body.Items) != 0 {
		t.Fatalf("got %d items from an empty vault; another user's items are visible",
			len(body.Items))
	}
}

func TestSyncRejectsAMalformedCursor(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	// A cursor that silently fell back to 0 would re-send the whole vault on
	// every poll and hide the client bug that produced it.
	for _, since := range []string{"abc", "-1", "1.5", ""} {
		rec := doJSON(t, srv, http.MethodGet, "/api/sync?since="+since, token, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("since=%q gave status %d, want %d", since, rec.Code, http.StatusBadRequest)
		}
	}
}

func TestSyncWithNoCursorParameterStartsFromZero(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	if rec := doJSON(t, srv, http.MethodPost, "/api/items", token, map[string]string{
		"ciphertext": "c", "wrappedItemKey": "k",
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d", rec.Code)
	}

	// A first-run client has no cursor at all. That is distinct from sending an
	// empty one, which is a bug.
	rec := doJSON(t, srv, http.MethodGet, "/api/sync", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body syncResponse
	decodeInto(t, rec, &body)
	if len(body.Items) != 1 {
		t.Errorf("got %d items, want the full vault", len(body.Items))
	}
}
```

- [ ] **Step 13: Implement the sync handler**

Create `internal/httpapi/sync.go`:

```go
package httpapi

import (
	"net/http"
	"strconv"
)

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	// An absent cursor is a first run. A present but unparseable one is a
	// client bug: falling back to 0 would silently re-send the entire vault on
	// every poll and hide the bug that caused it.
	var since int64
	if raw := r.URL.Query().Get("since"); raw != "" || r.URL.Query().Has("since") {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			WriteError(w, http.StatusBadRequest, CodeBadRequest,
				"since must be a non-negative integer")
			return
		}
		since = parsed
	}

	result, err := s.store.SyncSince(r.Context(), user.ID, since)
	if err != nil {
		s.writeStoreError(w, r, "sync", err)
		return
	}

	items := make([]itemJSON, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, toItemJSON(item))
	}
	folders := make([]folderJSON, 0, len(result.Folders))
	for _, folder := range result.Folders {
		folders = append(folders, toFolderJSON(folder))
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"revision": result.Revision,
		"items":    items,
		"folders":  folders,
	})
}
```

Register in `routes()`:

```go
	s.mux.HandleFunc("GET /api/sync", s.requireAuth(s.handleSync))
```

- [ ] **Step 14: Run the sync tests**

```bash
go test ./internal/httpapi/ -run Sync -v
```

Expected: PASS, all six.

- [ ] **Step 15: Prove the cross-user guard is load-bearing**

In `handleUpdateItem`, temporarily invert the access check:

```go
	if !allowed {
		allowed = true // mutation: pretend everything is visible
	}
```

Run:

```bash
go test ./internal/httpapi/ -run TestUpdatingAnotherUsersItemIsNotFound -v
```

Expected: FAIL — the write lands and the stored ciphertext becomes `"theirs"`.
Revert and confirm PASS. Record both in the report.

- [ ] **Step 16: Full suite, vet, gofmt, race**

```bash
go test ./... && gofmt -l ./internal ./cmd && go vet ./...
```

Expected: PASS, `gofmt -l` silent, vet silent.

```bash
go test -race ./internal/httpapi/
```

Expected: PASS, no races.

- [ ] **Step 17: Commit**

```bash
git add internal/httpapi/ && git commit -m "feat(api): item, folder, and sync endpoints"
```

---

## Task 4: Collections, memberships, pending grants, and the audit log

**Files:**
- Create: `internal/store/collections.go`
- Create: `internal/store/audit.go`
- Test: `internal/store/collections_test.go`, `internal/store/audit_test.go`
- Modify: `internal/store/sync.go` (add `Collections` to `SyncResult`)
- Modify: `internal/store/sync_test.go` (drop the local `seedCollection` helper in
  favour of `CreateCollection`; keep the tests otherwise unchanged)

**Interfaces:**
- Consumes: `NewID`, `ErrNotFound`, `ValidationError`, `SyncResult` (Tasks 1–2).
- Produces:
  ```go
  type Collection struct {
      ID        string
      Name      string // plaintext by design — spec section 2
      CreatedBy string
      CreatedAt time.Time
  }

  type CollectionWithMembership struct {
      Collection
      Role                string // "member" or "manager"
      SealedCollectionKey string
      GrantedAt           time.Time
  }

  type Membership struct {
      CollectionID        string
      UserID              string
      SealedCollectionKey string
      Role                string
      GrantedBy           string
      GrantedAt           time.Time
  }

  type PendingGrant struct {
      CollectionID   string
      CollectionName string
      UserID         string
      Role           string
      RequestedBy    string
      CreatedAt      time.Time
  }

  func (s *Store) CreateCollection(ctx context.Context, name, createdBy, sealedKeyForCreator string) (Collection, error)
  func (s *Store) CollectionByID(ctx context.Context, id string) (Collection, error)
  func (s *Store) AllCollections(ctx context.Context) ([]Collection, error)
  func (s *Store) DeleteCollection(ctx context.Context, id string) error
  func (s *Store) CollectionsForUser(ctx context.Context, userID string) ([]CollectionWithMembership, error)
  func (s *Store) MembershipsOf(ctx context.Context, collectionID string) ([]Membership, error)
  func (s *Store) MembershipFor(ctx context.Context, collectionID, userID string) (Membership, error)
  func (s *Store) RemoveMember(ctx context.Context, collectionID, userID, removedBy string) error
  func (s *Store) CreatePendingGrant(ctx context.Context, collectionID, userID, role, requestedBy string) error
  func (s *Store) PendingGrantsFulfillableBy(ctx context.Context, userID string) ([]PendingGrant, error)
  func (s *Store) AllPendingGrants(ctx context.Context) ([]PendingGrant, error)
  func (s *Store) FulfilGrant(ctx context.Context, collectionID, userID, sealedKey, grantedBy string) error

  type AuditEntry struct {
      ID          string
      ActorUserID sql.NullString
      Action      string
      Target      string
      Metadata    string
      CreatedAt   time.Time
  }

  func (s *Store) AppendAudit(ctx context.Context, actorUserID, action, target, metadata string) error
  func (s *Store) AuditPage(ctx context.Context, limit int, beforeID string) ([]AuditEntry, error)
  ```
  `SyncResult` gains `Collections []CollectionWithMembership`.

**Note on `internal/audit/`:** spec §4.1's layout sketch names a package for
this. It is one insert and one paged select against a table this package
already owns; a package wrapping that would add an import cycle risk and no
boundary. The audit log lives in `store`. Record the deviation in the report.

- [ ] **Step 1: Write the failing audit tests**

Create `internal/store/audit_test.go`:

```go
package store

import (
	"context"
	"testing"
)

func TestAppendAuditRecordsAnEntry(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	actor := enrolledUserID(t, st, "admin@example.com")

	if err := st.AppendAudit(ctx, actor, "user.create", "user:abc", `{"email":"new@example.com"}`); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	entries, err := st.AuditPage(ctx, 10, "")
	if err != nil {
		t.Fatalf("AuditPage: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Action != "user.create" {
		t.Errorf("Action = %q, want %q", entries[0].Action, "user.create")
	}
	if entries[0].Target != "user:abc" {
		t.Errorf("Target = %q", entries[0].Target)
	}
	if !entries[0].ActorUserID.Valid || entries[0].ActorUserID.String != actor {
		t.Errorf("ActorUserID = %+v, want %q", entries[0].ActorUserID, actor)
	}
}

func TestAppendAuditAcceptsNoActorForSystemActions(t *testing.T) {
	st := openTemp(t)

	// The tombstone purge and the installer's first admin have no signed-in
	// actor. Requiring one would either fabricate an attribution or leave those
	// actions unrecorded.
	if err := st.AppendAudit(context.Background(), "", "retention.purge", "items", `{"purged":12}`); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	entries, err := st.AuditPage(context.Background(), 10, "")
	if err != nil {
		t.Fatalf("AuditPage: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].ActorUserID.Valid {
		t.Error("a system action was attributed to a user")
	}
}

func TestAuditPageIsNewestFirstAndPagesWithoutRepeating(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	actor := enrolledUserID(t, st, "admin@example.com")

	for i := 0; i < 10; i++ {
		if err := st.AppendAudit(ctx, actor, "test.action", "target", ""); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}

	first, err := st.AuditPage(ctx, 4, "")
	if err != nil {
		t.Fatalf("AuditPage: %v", err)
	}
	if len(first) != 4 {
		t.Fatalf("first page has %d entries, want 4", len(first))
	}

	second, err := st.AuditPage(ctx, 4, first[len(first)-1].ID)
	if err != nil {
		t.Fatalf("AuditPage: %v", err)
	}
	if len(second) != 4 {
		t.Fatalf("second page has %d entries, want 4", len(second))
	}

	// Entries written in the same second share a created_at. Ordering on
	// timestamp alone would let a page boundary repeat or skip rows, which in
	// an audit log means an admin can look straight past the entry they are
	// searching for.
	seen := make(map[string]bool)
	for _, entry := range append(append([]AuditEntry{}, first...), second...) {
		if seen[entry.ID] {
			t.Errorf("entry %s appears on two pages", entry.ID)
		}
		seen[entry.ID] = true
	}
	if len(seen) != 8 {
		t.Errorf("saw %d distinct entries across two pages of 4, want 8", len(seen))
	}
}

func TestAuditPageClampsTheLimit(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	actor := enrolledUserID(t, st, "admin@example.com")
	for i := 0; i < 5; i++ {
		if err := st.AppendAudit(ctx, actor, "test.action", "t", ""); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}

	// A caller asking for zero, a negative, or a million rows gets a sane page
	// rather than an empty result or the whole table.
	for _, limit := range []int{0, -1, 1_000_000} {
		entries, err := st.AuditPage(ctx, limit, "")
		if err != nil {
			t.Fatalf("AuditPage(%d): %v", limit, err)
		}
		if len(entries) == 0 || len(entries) > maxAuditPage {
			t.Errorf("AuditPage(%d) returned %d entries, want between 1 and %d",
				limit, len(entries), maxAuditPage)
		}
	}
}
```

- [ ] **Step 2: Run and watch it fail**

```bash
go test ./internal/store/ -run Audit -v
```

Expected: FAIL — `st.AppendAudit undefined`.

- [ ] **Step 3: Implement the audit log**

Create `internal/store/audit.go`:

```go
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const (
	// defaultAuditPage is what a caller gets when it asks for nothing sensible.
	defaultAuditPage = 50
	// maxAuditPage bounds one response so a single request cannot pull the
	// whole table into memory.
	maxAuditPage = 200
)

// AuditEntry is one recorded administrative action. ActorUserID is nullable:
// the retention purge and the installer's first admin have no signed-in actor,
// and fabricating an attribution would be worse than recording none.
type AuditEntry struct {
	ID          string
	ActorUserID sql.NullString
	Action      string
	Target      string
	Metadata    string
	CreatedAt   time.Time
}

// AppendAudit records an action. An empty actorUserID stores NULL.
func (s *Store) AppendAudit(ctx context.Context, actorUserID, action, target, metadata string) error {
	return appendAudit(ctx, s.db, actorUserID, action, target, metadata)
}

// execer is satisfied by both *sql.DB and *sql.Tx, so an audit entry can be
// written inside the same transaction as the change it records.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func appendAudit(ctx context.Context, db execer, actorUserID, action, target, metadata string) error {
	id, err := NewID()
	if err != nil {
		return err
	}
	var actor sql.NullString
	if actorUserID != "" {
		actor = sql.NullString{String: actorUserID, Valid: true}
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO audit_log (id, actor_user_id, action, target, metadata, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, actor, action, target, metadata,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}
	return nil
}

// AuditPage returns entries newest first. beforeID is the id of the last entry
// the caller already has.
//
// The keyset is (created_at, id), not created_at alone: entries written in the
// same second share a timestamp, and a boundary that only compares timestamps
// would repeat or skip those rows. In an audit log a skipped row is an action
// an admin can look straight past.
func (s *Store) AuditPage(ctx context.Context, limit int, beforeID string) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = defaultAuditPage
	}
	if limit > maxAuditPage {
		limit = maxAuditPage
	}

	const columns = `id, actor_user_id, action, target, metadata, created_at`
	var rows *sql.Rows
	var err error

	if beforeID == "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT `+columns+` FROM audit_log
			 ORDER BY created_at DESC, id DESC
			 LIMIT ?`, limit)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT `+columns+` FROM audit_log
			 WHERE (created_at, id) < (SELECT created_at, id FROM audit_log WHERE id = ?)
			 ORDER BY created_at DESC, id DESC
			 LIMIT ?`, beforeID, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("select audit entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	entries := []AuditEntry{}
	for rows.Next() {
		var entry AuditEntry
		var createdAt string
		if err := rows.Scan(&entry.ID, &entry.ActorUserID, &entry.Action,
			&entry.Target, &entry.Metadata, &createdAt); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		if entry.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit entries: %w", err)
	}
	return entries, nil
}
```

- [ ] **Step 4: Run the audit tests**

```bash
go test ./internal/store/ -run Audit -v
```

Expected: PASS, all four.

- [ ] **Step 5: Write the failing collection tests**

Create `internal/store/collections_test.go`:

```go
package store

import (
	"context"
	"errors"
	"testing"
)

func TestCreateCollectionMakesTheCreatorItsFirstManager(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed-to-creator")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if collection.Name != "Household" {
		t.Errorf("Name = %q", collection.Name)
	}

	// Spec section 5.1: a collection's creator is its first manager, and
	// managers are members, so they hold the collection key. A collection
	// created with no member at all would be unreachable — nobody could seal
	// its key to anyone, ever.
	membership, err := st.MembershipFor(ctx, collection.ID, creator)
	if err != nil {
		t.Fatalf("MembershipFor: %v", err)
	}
	if membership.Role != "manager" {
		t.Errorf("Role = %q, want manager", membership.Role)
	}
	if membership.SealedCollectionKey != "sealed-to-creator" {
		t.Errorf("SealedCollectionKey = %q, want it stored verbatim", membership.SealedCollectionKey)
	}
}

func TestCreateCollectionRejectsABlankNameOrMissingSealedKey(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")

	cases := []struct {
		name      string
		collName  string
		sealedKey string
	}{
		{"blank name", "   ", "sealed"},
		// A collection whose creator holds no sealed key is one nobody can ever
		// open or share: the server cannot produce the key, by design.
		{"no sealed key", "Household", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := st.CreateCollection(ctx, tc.collName, creator, tc.sealedKey)
			var validation *ValidationError
			if !errors.As(err, &validation) {
				t.Fatalf("err = %v, want a *ValidationError", err)
			}
		})
	}
}

func TestCreateCollectionIsAtomic(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()

	// A user id that violates the foreign key. The collection row and the
	// membership row must land together or not at all: a collection with no
	// manager cannot be repaired through the API.
	_, err := st.CreateCollection(ctx, "Household", "no-such-user", "sealed")
	if err == nil {
		t.Fatal("CreateCollection accepted a non-existent creator")
	}

	var collections, memberships int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM collections`).Scan(&collections); err != nil {
		t.Fatalf("count collections: %v", err)
	}
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM collection_memberships`).Scan(&memberships); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if collections != 0 || memberships != 0 {
		t.Errorf("left %d collections and %d memberships behind, want 0 and 0",
			collections, memberships)
	}
}

func TestCollectionsForUserCarriesTheirOwnSealedKeyOnly(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")
	member := enrolledUserID(t, st, "member@example.com")
	outsider := enrolledUserID(t, st, "outsider@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed-to-creator")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if err := st.FulfilGrantOrAdd(ctx, collection.ID, member, "sealed-to-member", "member", creator); err != nil {
		t.Fatalf("add member: %v", err)
	}

	forMember, err := st.CollectionsForUser(ctx, member)
	if err != nil {
		t.Fatalf("CollectionsForUser: %v", err)
	}
	if len(forMember) != 1 {
		t.Fatalf("got %d collections, want 1", len(forMember))
	}
	// Each member's copy of the key is sealed to their own public key. Handing
	// a user someone else's sealed blob would be useless at best, and at worst
	// would suggest the server has a key it can redistribute — it does not.
	if forMember[0].SealedCollectionKey != "sealed-to-member" {
		t.Errorf("SealedCollectionKey = %q, want this member's own copy",
			forMember[0].SealedCollectionKey)
	}
	if forMember[0].Role != "member" {
		t.Errorf("Role = %q, want member", forMember[0].Role)
	}

	forOutsider, err := st.CollectionsForUser(ctx, outsider)
	if err != nil {
		t.Fatalf("CollectionsForUser: %v", err)
	}
	if len(forOutsider) != 0 {
		t.Errorf("a non-member sees %d collections, want 0", len(forOutsider))
	}
}

func TestRemoveMemberDeletesTheirSealedKey(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")
	member := enrolledUserID(t, st, "member@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed-to-creator")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if err := st.FulfilGrantOrAdd(ctx, collection.ID, member, "sealed-to-member", "member", creator); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if err := st.RemoveMember(ctx, collection.ID, member, creator); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}

	if _, err := st.MembershipFor(ctx, collection.ID, member); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	// Spec section 5.1: removal deletes the sealed key, revoking future access.
	// It deliberately does not rotate the collection key, so this asserts what
	// the design actually promises rather than what it might appear to.
	var count int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM collection_memberships WHERE collection_id = ? AND user_id = ?`,
		collection.ID, member).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Error("the sealed key row survives removal")
	}
}

func TestRemovingTheLastManagerIsRefused(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")
	member := enrolledUserID(t, st, "member@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed-to-creator")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if err := st.FulfilGrantOrAdd(ctx, collection.ID, member, "sealed", "member", creator); err != nil {
		t.Fatalf("add member: %v", err)
	}

	// With no manager left, nobody can fulfil a pending grant, so the
	// collection can never gain another member — and only an admin deleting it
	// outright can end that state.
	err = st.RemoveMember(ctx, collection.ID, creator, creator)
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("err = %v, want a *ValidationError refusing the removal", err)
	}
}

func TestCreatePendingGrantRecordsTheRoleItWillConfer(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")
	invitee := enrolledUserID(t, st, "invitee@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if err := st.CreatePendingGrant(ctx, collection.ID, invitee, "manager", creator); err != nil {
		t.Fatalf("CreatePendingGrant: %v", err)
	}

	// Without the role on the row, the fulfilling client has to guess, and
	// every grant silently becomes a plain member.
	grants, err := st.PendingGrantsFulfillableBy(ctx, creator)
	if err != nil {
		t.Fatalf("PendingGrantsFulfillableBy: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("got %d grants, want 1", len(grants))
	}
	if grants[0].Role != "manager" {
		t.Errorf("Role = %q, want manager", grants[0].Role)
	}
	if grants[0].CollectionName != "Household" {
		t.Errorf("CollectionName = %q, want the name so the UI can name it", grants[0].CollectionName)
	}
}

func TestPendingGrantsAreVisibleOnlyToMembersWhoCanFulfilThem(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")
	invitee := enrolledUserID(t, st, "invitee@example.com")
	outsider := enrolledUserID(t, st, "outsider@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if err := st.CreatePendingGrant(ctx, collection.ID, invitee, "member", creator); err != nil {
		t.Fatalf("CreatePendingGrant: %v", err)
	}

	// Only someone who already holds the collection key can seal it to the new
	// member, so only they need to see the grant. Showing it more widely leaks
	// the membership graph to people outside the collection.
	forOutsider, err := st.PendingGrantsFulfillableBy(ctx, outsider)
	if err != nil {
		t.Fatalf("PendingGrantsFulfillableBy: %v", err)
	}
	if len(forOutsider) != 0 {
		t.Errorf("an outsider sees %d pending grants, want 0", len(forOutsider))
	}
}

func TestFulfilGrantAddsTheMemberAndClearsTheGrant(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")
	invitee := enrolledUserID(t, st, "invitee@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if err := st.CreatePendingGrant(ctx, collection.ID, invitee, "manager", creator); err != nil {
		t.Fatalf("CreatePendingGrant: %v", err)
	}
	if err := st.FulfilGrant(ctx, collection.ID, invitee, "sealed-to-invitee", creator); err != nil {
		t.Fatalf("FulfilGrant: %v", err)
	}

	membership, err := st.MembershipFor(ctx, collection.ID, invitee)
	if err != nil {
		t.Fatalf("MembershipFor: %v", err)
	}
	// The role comes from the grant, not from the fulfilling client, which
	// otherwise could quietly promote whoever it is sealing to.
	if membership.Role != "manager" {
		t.Errorf("Role = %q, want the manager role recorded on the grant", membership.Role)
	}

	// A grant left behind would show forever in the pending list and invite a
	// second, redundant seal.
	grants, err := st.PendingGrantsFulfillableBy(ctx, creator)
	if err != nil {
		t.Fatalf("PendingGrantsFulfillableBy: %v", err)
	}
	if len(grants) != 0 {
		t.Errorf("%d grants remain after fulfilment, want 0", len(grants))
	}
}

func TestFulfilGrantWithoutAGrantIsNotFound(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")
	stranger := enrolledUserID(t, st, "stranger@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}

	// The pending grant is the authorization record. Without it, any member
	// could add anyone to a collection just by sealing a key at them.
	err = st.FulfilGrant(ctx, collection.ID, stranger, "sealed", creator)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestDeleteCollectionRemovesItsItemsMembershipsAndGrants(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if _, err := st.CreateItem(ctx, creator, ItemInput{
		CollectionID: collection.ID, Ciphertext: "c", WrappedItemKey: "k",
	}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	if err := st.DeleteCollection(ctx, collection.ID); err != nil {
		t.Fatalf("DeleteCollection: %v", err)
	}

	// ON DELETE CASCADE from migration 0001 does the work; this asserts the
	// cascade is real rather than assumed, because foreign_keys is a
	// per-connection pragma that is off by default.
	for _, table := range []string{"collections", "collection_memberships", "items"} {
		var count int
		if err := st.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM `+table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Errorf("%s still has %d rows after the collection was deleted", table, count)
		}
	}
}

func TestSyncCarriesTheCallersCollections(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")
	outsider := enrolledUserID(t, st, "outsider@example.com")

	if _, err := st.CreateCollection(ctx, "Household", creator, "sealed-to-creator"); err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}

	// Collections ride on every sync in full, not incrementally: at household
	// scale that is a handful of rows, and it means a revoked membership simply
	// disappears rather than needing a tombstone table of its own.
	mine, err := st.SyncSince(ctx, creator, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(mine.Collections) != 1 {
		t.Fatalf("got %d collections, want 1", len(mine.Collections))
	}
	if mine.Collections[0].SealedCollectionKey != "sealed-to-creator" {
		t.Errorf("SealedCollectionKey = %q", mine.Collections[0].SealedCollectionKey)
	}

	theirs, err := st.SyncSince(ctx, outsider, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(theirs.Collections) != 0 {
		t.Errorf("a non-member's sync carries %d collections, want 0", len(theirs.Collections))
	}
}
```

- [ ] **Step 6: Run and watch it fail**

```bash
go test ./internal/store/ -run "Collection|Grant|Member" -v
```

Expected: FAIL — `st.CreateCollection undefined`.

- [ ] **Step 7: Implement collections**

Create `internal/store/collections.go`:

```go
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Collection groups shared items. The name is plaintext by design (spec
// section 2): an admin has to manage membership without being a member, and
// the leak is a folder name.
type Collection struct {
	ID        string
	Name      string
	CreatedBy string
	CreatedAt time.Time
}

// CollectionWithMembership is a collection as one member sees it, carrying
// that member's own sealed copy of the collection key.
type CollectionWithMembership struct {
	Collection
	Role                string
	SealedCollectionKey string
	GrantedAt           time.Time
}

type Membership struct {
	CollectionID        string
	UserID              string
	SealedCollectionKey string
	Role                string
	GrantedBy           string
	GrantedAt           time.Time
}

type PendingGrant struct {
	CollectionID   string
	CollectionName string
	UserID         string
	Role           string
	RequestedBy    string
	CreatedAt      time.Time
}

// validRole gates the two roles from spec section 5.1. The role column has no
// CHECK constraint — SQLite's ALTER TABLE ADD COLUMN cannot add one to
// pending_grants — so this function is the constraint.
func validRole(role string) bool {
	return role == "member" || role == "manager"
}

// CreateCollection creates the collection and its creator's membership in one
// transaction.
//
// Both rows must land together. A collection with no manager cannot be
// repaired through the API: nobody holds the key, so nobody can seal it to
// anyone, and the server cannot help because it never had the key.
func (s *Store) CreateCollection(ctx context.Context, name, createdBy, sealedKeyForCreator string) (Collection, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Collection{}, &ValidationError{Field: "name"}
	}
	if sealedKeyForCreator == "" {
		return Collection{}, &ValidationError{Field: "sealedCollectionKey"}
	}

	id, err := NewID()
	if err != nil {
		return Collection{}, err
	}
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Collection{}, fmt.Errorf("begin collection insert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO collections (id, name, created_by, created_at) VALUES (?, ?, ?, ?)`,
		id, name, createdBy, stamp); err != nil {
		return Collection{}, fmt.Errorf("insert collection: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO collection_memberships
		 (collection_id, user_id, sealed_collection_key, role, granted_by, granted_at)
		 VALUES (?, ?, ?, 'manager', ?, ?)`,
		id, createdBy, sealedKeyForCreator, createdBy, stamp); err != nil {
		return Collection{}, fmt.Errorf("insert creator membership: %w", err)
	}
	if err := appendAudit(ctx, tx, createdBy, "collection.create", "collection:"+id,
		fmt.Sprintf(`{"name":%q}`, name)); err != nil {
		return Collection{}, err
	}
	if err := tx.Commit(); err != nil {
		return Collection{}, fmt.Errorf("commit collection insert: %w", err)
	}

	return Collection{ID: id, Name: name, CreatedBy: createdBy, CreatedAt: now}, nil
}

const collectionColumns = `id, name, created_by, created_at`

func scanCollection(row interface{ Scan(...any) error }) (Collection, error) {
	var collection Collection
	var createdAt string
	err := row.Scan(&collection.ID, &collection.Name, &collection.CreatedBy, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Collection{}, ErrNotFound
	}
	if err != nil {
		return Collection{}, fmt.Errorf("scan collection: %w", err)
	}
	if collection.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return Collection{}, fmt.Errorf("parse created_at: %w", err)
	}
	return collection, nil
}

func (s *Store) CollectionByID(ctx context.Context, id string) (Collection, error) {
	return scanCollection(s.db.QueryRowContext(ctx,
		`SELECT `+collectionColumns+` FROM collections WHERE id = ?`, id))
}

// AllCollections is the admin view. It carries no sealed keys, because an
// admin who is not a member holds none and the server has none to give.
func (s *Store) AllCollections(ctx context.Context) ([]Collection, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+collectionColumns+` FROM collections ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("select collections: %w", err)
	}
	defer func() { _ = rows.Close() }()

	collections := []Collection{}
	for rows.Next() {
		collection, err := scanCollection(rows)
		if err != nil {
			return nil, err
		}
		collections = append(collections, collection)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate collections: %w", err)
	}
	return collections, nil
}

// DeleteCollection removes the collection. Memberships, pending grants, and
// the collection's items go with it through ON DELETE CASCADE — the items are
// hard-deleted rather than tombstoned because their key material is gone with
// the memberships, so a tombstone would describe something already unreadable.
func (s *Store) DeleteCollection(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM collections WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete collection: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// CollectionsForUser returns each collection the user belongs to, carrying
// only that user's own sealed copy of the key.
func (s *Store) CollectionsForUser(ctx context.Context, userID string) ([]CollectionWithMembership, error) {
	return collectionsForUser(ctx, s.db, userID)
}

// queryer is satisfied by *sql.DB and *sql.Tx, so SyncSince can read
// collections inside its own read transaction.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func collectionsForUser(ctx context.Context, db queryer, userID string) ([]CollectionWithMembership, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT c.id, c.name, c.created_by, c.created_at,
		        m.role, m.sealed_collection_key, m.granted_at
		 FROM collections c
		 JOIN collection_memberships m ON m.collection_id = c.id
		 WHERE m.user_id = ?
		 ORDER BY c.name`, userID)
	if err != nil {
		return nil, fmt.Errorf("select memberships: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []CollectionWithMembership{}
	for rows.Next() {
		var row CollectionWithMembership
		var createdAt, grantedAt string
		if err := rows.Scan(&row.ID, &row.Name, &row.CreatedBy, &createdAt,
			&row.Role, &row.SealedCollectionKey, &grantedAt); err != nil {
			return nil, fmt.Errorf("scan membership: %w", err)
		}
		if row.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
		if row.GrantedAt, err = time.Parse(time.RFC3339, grantedAt); err != nil {
			return nil, fmt.Errorf("parse granted_at: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate memberships: %w", err)
	}
	return out, nil
}

const membershipColumns = `collection_id, user_id, sealed_collection_key, role, granted_by, granted_at`

func scanMembership(row interface{ Scan(...any) error }) (Membership, error) {
	var m Membership
	var grantedAt string
	err := row.Scan(&m.CollectionID, &m.UserID, &m.SealedCollectionKey,
		&m.Role, &m.GrantedBy, &grantedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Membership{}, ErrNotFound
	}
	if err != nil {
		return Membership{}, fmt.Errorf("scan membership: %w", err)
	}
	if m.GrantedAt, err = time.Parse(time.RFC3339, grantedAt); err != nil {
		return Membership{}, fmt.Errorf("parse granted_at: %w", err)
	}
	return m, nil
}

func (s *Store) MembershipFor(ctx context.Context, collectionID, userID string) (Membership, error) {
	return scanMembership(s.db.QueryRowContext(ctx,
		`SELECT `+membershipColumns+` FROM collection_memberships
		 WHERE collection_id = ? AND user_id = ?`, collectionID, userID))
}

func (s *Store) MembershipsOf(ctx context.Context, collectionID string) ([]Membership, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+membershipColumns+` FROM collection_memberships
		 WHERE collection_id = ? ORDER BY granted_at`, collectionID)
	if err != nil {
		return nil, fmt.Errorf("select memberships: %w", err)
	}
	defer func() { _ = rows.Close() }()

	memberships := []Membership{}
	for rows.Next() {
		m, err := scanMembership(rows)
		if err != nil {
			return nil, err
		}
		memberships = append(memberships, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate memberships: %w", err)
	}
	return memberships, nil
}

// FulfilGrantOrAdd inserts a membership directly, bypassing the pending-grant
// record. It exists for the one caller that legitimately has no grant to
// consume: an existing manager adding a member and sealing the key in the same
// request. Everything else goes through CreatePendingGrant and FulfilGrant.
func (s *Store) FulfilGrantOrAdd(ctx context.Context, collectionID, userID, sealedKey, role, grantedBy string) error {
	if !validRole(role) {
		return &ValidationError{Field: "role"}
	}
	if sealedKey == "" {
		return &ValidationError{Field: "sealedCollectionKey"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin add member: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := addMemberTx(ctx, tx, collectionID, userID, sealedKey, role, grantedBy); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit add member: %w", err)
	}
	return nil
}

func addMemberTx(ctx context.Context, tx *sql.Tx, collectionID, userID, sealedKey, role, grantedBy string) error {
	// A re-seal replaces the stored blob rather than failing. A member whose
	// key material was re-issued needs a fresh seal, and refusing it would
	// leave them permanently unable to open the collection.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO collection_memberships
		 (collection_id, user_id, sealed_collection_key, role, granted_by, granted_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT (collection_id, user_id) DO UPDATE SET
		   sealed_collection_key = excluded.sealed_collection_key,
		   role = excluded.role,
		   granted_by = excluded.granted_by,
		   granted_at = excluded.granted_at`,
		collectionID, userID, sealedKey, role, grantedBy,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("insert membership: %w", err)
	}
	return appendAudit(ctx, tx, grantedBy, "collection.member.add",
		"collection:"+collectionID, fmt.Sprintf(`{"userId":%q,"role":%q}`, userID, role))
}

// RemoveMember deletes a member's sealed key. Per spec section 5.1 this
// revokes future access and deliberately does NOT rotate the collection key: a
// removed member who kept a copy retains what they already had, and the admin
// UI says so.
//
// removedBy is recorded in the audit entry. Removing someone's access to shared
// credentials is exactly the kind of action that gets disputed later, so the
// log has to name who did it rather than storing a NULL actor.
func (s *Store) RemoveMember(ctx context.Context, collectionID, userID, removedBy string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin remove member: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var role string
	err = tx.QueryRowContext(ctx,
		`SELECT role FROM collection_memberships WHERE collection_id = ? AND user_id = ?`,
		collectionID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read membership: %w", err)
	}

	if role == "manager" {
		var managers int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM collection_memberships
			 WHERE collection_id = ? AND role = 'manager'`, collectionID).Scan(&managers); err != nil {
			return fmt.Errorf("count managers: %w", err)
		}
		// With no manager left, nobody can fulfil a pending grant, so the
		// collection can never gain another member and only an admin deleting
		// it outright ends that state.
		if managers <= 1 {
			return &ValidationError{Field: "userId"}
		}
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM collection_memberships WHERE collection_id = ? AND user_id = ?`,
		collectionID, userID); err != nil {
		return fmt.Errorf("delete membership: %w", err)
	}
	if err := appendAudit(ctx, tx, removedBy, "collection.member.remove",
		"collection:"+collectionID, fmt.Sprintf(`{"userId":%q}`, userID)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit remove member: %w", err)
	}
	return nil
}

// CreatePendingGrant records that a user should be given access. The server
// cannot grant it: it never holds a collection key. The next unlocked client
// belonging to a member seals the key and calls FulfilGrant.
func (s *Store) CreatePendingGrant(ctx context.Context, collectionID, userID, role, requestedBy string) error {
	if !validRole(role) {
		return &ValidationError{Field: "role"}
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO pending_grants (collection_id, user_id, requested_by, role, created_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (collection_id, user_id) DO UPDATE SET
		   role = excluded.role,
		   requested_by = excluded.requested_by,
		   created_at = excluded.created_at`,
		collectionID, userID, requestedBy, role,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("insert pending grant: %w", err)
	}
	return s.AppendAudit(ctx, requestedBy, "collection.grant.request",
		"collection:"+collectionID, fmt.Sprintf(`{"userId":%q,"role":%q}`, userID, role))
}

const pendingGrantSelect = `SELECT g.collection_id, c.name, g.user_id, g.role, g.requested_by, g.created_at
	FROM pending_grants g
	JOIN collections c ON c.id = g.collection_id`

// PendingGrantsFulfillableBy lists grants the caller can actually act on:
// only a member holds the collection key, so only a member can seal it to
// someone else. Listing them more widely would leak the membership graph to
// people outside the collection.
func (s *Store) PendingGrantsFulfillableBy(ctx context.Context, userID string) ([]PendingGrant, error) {
	rows, err := s.db.QueryContext(ctx,
		pendingGrantSelect+`
		 WHERE g.collection_id IN (
		     SELECT collection_id FROM collection_memberships WHERE user_id = ?
		 )
		 ORDER BY g.created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("select pending grants: %w", err)
	}
	return collectPendingGrants(rows)
}

// AllPendingGrants is the admin view: an admin needs to see that a grant they
// requested is still waiting on a member, even though they cannot fulfil it.
func (s *Store) AllPendingGrants(ctx context.Context) ([]PendingGrant, error) {
	rows, err := s.db.QueryContext(ctx, pendingGrantSelect+` ORDER BY g.created_at`)
	if err != nil {
		return nil, fmt.Errorf("select pending grants: %w", err)
	}
	return collectPendingGrants(rows)
}

func collectPendingGrants(rows *sql.Rows) ([]PendingGrant, error) {
	defer func() { _ = rows.Close() }()

	grants := []PendingGrant{}
	for rows.Next() {
		var grant PendingGrant
		var createdAt string
		if err := rows.Scan(&grant.CollectionID, &grant.CollectionName, &grant.UserID,
			&grant.Role, &grant.RequestedBy, &createdAt); err != nil {
			return nil, fmt.Errorf("scan pending grant: %w", err)
		}
		parsed, err := time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
		grant.CreatedAt = parsed
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending grants: %w", err)
	}
	return grants, nil
}

// FulfilGrant converts a pending grant into a membership, in one transaction.
//
// The role comes from the grant row, never from the caller: the fulfilling
// client holds the key but did not decide who gets what, and letting it choose
// would let any member quietly promote whoever they were sealing to.
func (s *Store) FulfilGrant(ctx context.Context, collectionID, userID, sealedKey, grantedBy string) error {
	if sealedKey == "" {
		return &ValidationError{Field: "sealedCollectionKey"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin fulfil grant: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var role string
	err = tx.QueryRowContext(ctx,
		`SELECT role FROM pending_grants WHERE collection_id = ? AND user_id = ?`,
		collectionID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		// The pending grant IS the authorization record. Without it any member
		// could add anyone to a collection just by sealing a key at them.
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read pending grant: %w", err)
	}
	if !validRole(role) {
		return &ValidationError{Field: "role"}
	}

	if err := addMemberTx(ctx, tx, collectionID, userID, sealedKey, role, grantedBy); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM pending_grants WHERE collection_id = ? AND user_id = ?`,
		collectionID, userID); err != nil {
		return fmt.Errorf("clear pending grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit fulfil grant: %w", err)
	}
	return nil
}
```

- [ ] **Step 8: Add collections to the sync result**

In `internal/store/sync.go`, add the field:

```go
type SyncResult struct {
	Revision int64
	Items    []Item
	Folders  []Folder
	// Collections are sent in full on every sync rather than incrementally. At
	// household scale that is a handful of rows, and it means a revoked
	// membership or a deleted collection simply disappears from the list — no
	// membership tombstone table and no revision column on two more tables.
	Collections []CollectionWithMembership
}
```

and, in `SyncSince`, before `tx.Commit()`:

```go
	if result.Collections, err = collectionsForUser(ctx, tx, userID); err != nil {
		return SyncResult{}, err
	}
```

- [ ] **Step 9: Replace the local seed helper in the sync tests**

Delete `seedCollection` from `internal/store/sync_test.go` and replace its
three call sites with the real store calls:

```go
	collection, err := st.CreateCollection(ctx, "Household", owner, "sealed-to-owner")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if err := st.FulfilGrantOrAdd(ctx, collection.ID, member, "sealed-to-member", "member", owner); err != nil {
		t.Fatalf("add member: %v", err)
	}
	collectionID := collection.ID
```

Nothing else in those tests changes. Doing this now keeps one definition of
how a collection is created; leaving the raw-SQL helper would let the schema
and the store drift apart silently.

- [ ] **Step 10: Run the collection tests**

```bash
go test ./internal/store/ -run "Collection|Grant|Member|Sync" -v
```

Expected: PASS.

- [ ] **Step 11: Prove the grant-role check is load-bearing**

In `FulfilGrant`, temporarily hard-code the role:

```go
	role = "member"
```

Run `go test ./internal/store/ -run TestFulfilGrantAddsTheMemberAndClearsTheGrant -v`.
Expected: FAIL — Role is `member` where `manager` was granted. Revert and
confirm PASS. Record both.

- [ ] **Step 12: Full suite, vet, gofmt**

```bash
go test ./... && gofmt -l ./internal ./cmd && go vet ./...
```

Expected: PASS, both silent.

- [ ] **Step 13: Commit**

```bash
git add internal/store/ && git commit -m "feat(store): collections, memberships, pending grants, and the audit log"
```

---

## Task 5: Collection, grant, and directory endpoints

**Files:**
- Create: `internal/httpapi/collections.go`
- Create: `internal/httpapi/directory.go`
- Test: `internal/httpapi/collections_test.go`, `internal/httpapi/directory_test.go`
- Modify: `internal/httpapi/auth.go` (add `requireAdmin`)
- Modify: `internal/httpapi/sync.go` (include collections in the response)
- Modify: `internal/httpapi/server.go` (register the routes)
- Modify: `internal/httpapi/items_test.go` (drop `seedTestCollection` for the real endpoints)

**Interfaces:**
- Consumes: everything from Tasks 3 and 4.
- Produces:
  ```go
  func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc
  ```
  Task 7 uses `requireAdmin` for the whole `/api/admin` surface.

**Routes registered:**

```
GET    /api/collections                        any authenticated user
POST   /api/collections                        admin only
DELETE /api/collections/{id}                   admin only
GET    /api/collections/pending-grants         any authenticated user
GET    /api/collections/{id}/members           member or admin
POST   /api/collections/{id}/members           manager of that collection, or admin
DELETE /api/collections/{id}/members/{userId}  manager of that collection, or admin
POST   /api/collections/{id}/grants            manager of that collection
GET    /api/directory                          any authenticated user
```

**Permission model, from spec §5.1:**

| Action | Who |
|---|---|
| Create / delete a collection | Admin only. Keeps the membership graph — the one structure an admin must reason about — from sprawling. |
| Add / remove members, fulfil grants | A **manager** of that collection. |
| Read, create, edit, delete items in it | Any **member**. |

An admin who is not a member may *request* a grant but cannot fulfil it: the
server holds no collection key and neither do they. That asymmetry is the
cryptographic guarantee made visible, and the UI shows pending grants rather
than pretending a grant is instant.

- [ ] **Step 1: Add requireAdmin**

At the end of `internal/httpapi/auth.go`:

```go
// requireAdmin wraps requireAuth and additionally demands the admin role.
//
// 403, not 404: unlike a vault row, the existence of the admin surface is not
// a secret — every client knows the endpoints exist — so hiding it buys
// nothing, and a 403 tells an honest client the truth about why it failed.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFrom(r.Context())
		if !ok || user.Role != "admin" {
			WriteError(w, http.StatusForbidden, CodeForbidden, "this action requires an administrator")
			return
		}
		next(w, r)
	})
}
```

- [ ] **Step 2: Write the failing collection endpoint tests**

Create `internal/httpapi/collections_test.go`:

```go
package httpapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/ssan9876/keyhole/internal/store"
)

type collectionResponse struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Role                string `json:"role"`
	SealedCollectionKey string `json:"sealedCollectionKey"`
	CreatedBy           string `json:"createdBy"`
}

type pendingGrantResponse struct {
	CollectionID   string `json:"collectionId"`
	CollectionName string `json:"collectionName"`
	UserID         string `json:"userId"`
	Role           string `json:"role"`
}

// loginAdmin enrolls an account, promotes it to admin, and signs in. The role
// is set directly because the only route that creates an admin is the
// installer's CLI, which is not reachable from a test server.
func loginAdmin(t *testing.T, srv *Server, email string) (store.User, string) {
	t.Helper()
	user, token := loginTestUser(t, srv, email)
	if _, err := srv.store.DB().ExecContext(context.Background(),
		`UPDATE users SET role = 'admin' WHERE id = ?`, user.ID); err != nil {
		t.Fatalf("promote to admin: %v", err)
	}
	user.Role = "admin"
	return user, token
}

// createCollection is the happy path used as a fixture by later tests.
func createCollection(t *testing.T, srv *Server, adminToken, name string) collectionResponse {
	t.Helper()
	rec := doJSON(t, srv, http.MethodPost, "/api/collections", adminToken, map[string]string{
		"name": name, "sealedCollectionKey": "sealed-to-creator",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create collection: %d %s", rec.Code, rec.Body.String())
	}
	var collection collectionResponse
	decodeInto(t, rec, &collection)
	return collection
}

func TestOnlyAnAdminMayCreateACollection(t *testing.T) {
	srv := newTestServer(t)
	_, userToken := loginTestUser(t, srv, "person@example.com")

	rec := doJSON(t, srv, http.MethodPost, "/api/collections", userToken, map[string]string{
		"name": "Household", "sealedCollectionKey": "sealed",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d — spec 5.1 reserves collection creation to admins",
			rec.Code, http.StatusForbidden)
	}
}

func TestCreateCollectionMakesTheAdminItsManager(t *testing.T) {
	srv := newTestServer(t)
	admin, adminToken := loginAdmin(t, srv, "admin@example.com")

	collection := createCollection(t, srv, adminToken, "Household")
	if collection.Name != "Household" {
		t.Errorf("name = %q", collection.Name)
	}
	if collection.CreatedBy != admin.ID {
		t.Errorf("createdBy = %q, want %q", collection.CreatedBy, admin.ID)
	}

	rec := doJSON(t, srv, http.MethodGet, "/api/collections", adminToken, nil)
	var body struct {
		Collections []collectionResponse `json:"collections"`
	}
	decodeInto(t, rec, &body)
	if len(body.Collections) != 1 {
		t.Fatalf("got %d collections, want 1", len(body.Collections))
	}
	if body.Collections[0].Role != "manager" {
		t.Errorf("role = %q, want manager", body.Collections[0].Role)
	}
	if body.Collections[0].SealedCollectionKey != "sealed-to-creator" {
		t.Errorf("sealedCollectionKey = %q, want the creator's own copy",
			body.Collections[0].SealedCollectionKey)
	}
}

func TestCreateCollectionRequiresASealedKey(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")

	// A collection whose creator holds no sealed key is unreachable forever:
	// the server has no key to hand out, by design.
	rec := doJSON(t, srv, http.MethodPost, "/api/collections", adminToken,
		map[string]string{"name": "Household"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestListCollectionsShowsOnlyTheCallersOwn(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	_, outsiderToken := loginTestUser(t, srv, "outsider@example.com")

	createCollection(t, srv, adminToken, "Household")

	rec := doJSON(t, srv, http.MethodGet, "/api/collections", outsiderToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body struct {
		Collections []collectionResponse `json:"collections"`
	}
	decodeInto(t, rec, &body)
	if len(body.Collections) != 0 {
		t.Errorf("a non-member sees %d collections, want 0", len(body.Collections))
	}
}

func TestAddingAMemberWithoutASealedKeyCreatesAPendingGrant(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	invitee, inviteeToken := loginTestUser(t, srv, "invitee@example.com")

	collection := createCollection(t, srv, adminToken, "Household")

	// The server cannot seal a collection key — it never holds one. So an
	// admin adding a member records an intention, and 202 says exactly that
	// rather than pretending the grant took effect.
	rec := doJSON(t, srv, http.MethodPost, "/api/collections/"+collection.ID+"/members",
		adminToken, map[string]string{"userId": invitee.ID, "role": "member"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}

	// And the invitee genuinely has no access yet.
	list := doJSON(t, srv, http.MethodGet, "/api/collections", inviteeToken, nil)
	var body struct {
		Collections []collectionResponse `json:"collections"`
	}
	decodeInto(t, list, &body)
	if len(body.Collections) != 0 {
		t.Errorf("the invitee already has %d collections; a pending grant granted access",
			len(body.Collections))
	}
}

func TestAManagerSeesAPendingGrantAndCanFulfilIt(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	invitee, inviteeToken := loginTestUser(t, srv, "invitee@example.com")

	collection := createCollection(t, srv, adminToken, "Household")
	if rec := doJSON(t, srv, http.MethodPost, "/api/collections/"+collection.ID+"/members",
		adminToken, map[string]string{"userId": invitee.ID, "role": "member"}); rec.Code != http.StatusAccepted {
		t.Fatalf("request grant: %d %s", rec.Code, rec.Body.String())
	}

	pending := doJSON(t, srv, http.MethodGet, "/api/collections/pending-grants", adminToken, nil)
	var pendingBody struct {
		PendingGrants []pendingGrantResponse `json:"pendingGrants"`
	}
	decodeInto(t, pending, &pendingBody)
	if len(pendingBody.PendingGrants) != 1 {
		t.Fatalf("manager sees %d pending grants, want 1", len(pendingBody.PendingGrants))
	}
	if pendingBody.PendingGrants[0].CollectionName != "Household" {
		t.Errorf("collectionName = %q, want the name so the UI can identify it",
			pendingBody.PendingGrants[0].CollectionName)
	}

	fulfil := doJSON(t, srv, http.MethodPost, "/api/collections/"+collection.ID+"/grants",
		adminToken, map[string]string{
			"userId": invitee.ID, "sealedCollectionKey": "sealed-to-invitee",
		})
	if fulfil.Code != http.StatusCreated {
		t.Fatalf("fulfil: %d %s", fulfil.Code, fulfil.Body.String())
	}

	list := doJSON(t, srv, http.MethodGet, "/api/collections", inviteeToken, nil)
	var body struct {
		Collections []collectionResponse `json:"collections"`
	}
	decodeInto(t, list, &body)
	if len(body.Collections) != 1 {
		t.Fatalf("the invitee has %d collections after fulfilment, want 1", len(body.Collections))
	}
	if body.Collections[0].SealedCollectionKey != "sealed-to-invitee" {
		t.Errorf("sealedCollectionKey = %q, want the copy sealed to this user",
			body.Collections[0].SealedCollectionKey)
	}
}

func TestANonMemberCannotFulfilAGrant(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	invitee, _ := loginTestUser(t, srv, "invitee@example.com")
	_, outsiderToken := loginTestUser(t, srv, "outsider@example.com")

	collection := createCollection(t, srv, adminToken, "Household")
	if rec := doJSON(t, srv, http.MethodPost, "/api/collections/"+collection.ID+"/members",
		adminToken, map[string]string{"userId": invitee.ID, "role": "member"}); rec.Code != http.StatusAccepted {
		t.Fatalf("request grant: %d", rec.Code)
	}

	// An outsider holds no collection key, so any blob they upload is garbage
	// that would lock the invitee out with no error anyone could diagnose.
	rec := doJSON(t, srv, http.MethodPost, "/api/collections/"+collection.ID+"/grants",
		outsiderToken, map[string]string{
			"userId": invitee.ID, "sealedCollectionKey": "garbage",
		})
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestAPlainMemberCannotAddOrRemoveMembers(t *testing.T) {
	srv := newTestServer(t)
	admin, adminToken := loginAdmin(t, srv, "admin@example.com")
	member, memberToken := loginTestUser(t, srv, "member@example.com")
	stranger, _ := loginTestUser(t, srv, "stranger@example.com")

	collection := createCollection(t, srv, adminToken, "Household")
	if err := srv.store.FulfilGrantOrAdd(context.Background(),
		collection.ID, member.ID, "sealed-to-member", "member", admin.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}

	// Spec 5.1: a member may read and edit items, but membership is a manager's
	// business. Otherwise anyone in a collection could quietly widen it.
	add := doJSON(t, srv, http.MethodPost, "/api/collections/"+collection.ID+"/members",
		memberToken, map[string]string{"userId": stranger.ID, "role": "member"})
	if add.Code != http.StatusForbidden {
		t.Errorf("add status = %d, want %d", add.Code, http.StatusForbidden)
	}

	remove := doJSON(t, srv, http.MethodDelete,
		"/api/collections/"+collection.ID+"/members/"+admin.ID, memberToken, nil)
	if remove.Code != http.StatusForbidden {
		t.Errorf("remove status = %d, want %d", remove.Code, http.StatusForbidden)
	}
}

func TestRemovingAMemberRevokesTheirAccessToItems(t *testing.T) {
	srv := newTestServer(t)
	admin, adminToken := loginAdmin(t, srv, "admin@example.com")
	member, memberToken := loginTestUser(t, srv, "member@example.com")

	collection := createCollection(t, srv, adminToken, "Household")
	if err := srv.store.FulfilGrantOrAdd(context.Background(),
		collection.ID, member.ID, "sealed-to-member", "member", admin.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if rec := doJSON(t, srv, http.MethodPost, "/api/items", adminToken, map[string]string{
		"collectionId": collection.ID, "ciphertext": "shared", "wrappedItemKey": "k",
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create item: %d %s", rec.Code, rec.Body.String())
	}

	before := doJSON(t, srv, http.MethodGet, "/api/sync", memberToken, nil)
	var beforeBody syncResponse
	decodeInto(t, before, &beforeBody)
	if len(beforeBody.Items) != 1 {
		t.Fatalf("member sees %d items before removal, want 1", len(beforeBody.Items))
	}

	if rec := doJSON(t, srv, http.MethodDelete,
		"/api/collections/"+collection.ID+"/members/"+member.ID, adminToken, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body.String())
	}

	after := doJSON(t, srv, http.MethodGet, "/api/sync", memberToken, nil)
	var afterBody syncResponse
	decodeInto(t, after, &afterBody)
	if len(afterBody.Items) != 0 {
		t.Errorf("member still sees %d items after removal", len(afterBody.Items))
	}
	if len(afterBody.Collections) != 0 {
		t.Errorf("member still sees %d collections after removal", len(afterBody.Collections))
	}
}

func TestMemberListNeverCarriesSealedKeys(t *testing.T) {
	srv := newTestServer(t)
	admin, adminToken := loginAdmin(t, srv, "admin@example.com")
	member, _ := loginTestUser(t, srv, "member@example.com")

	collection := createCollection(t, srv, adminToken, "Household")
	if err := srv.store.FulfilGrantOrAdd(context.Background(),
		collection.ID, member.ID, "sealed-to-member", "member", admin.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}

	rec := doJSON(t, srv, http.MethodGet, "/api/collections/"+collection.ID+"/members", adminToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	// A member list is a directory, not a key distribution channel. Each
	// member's sealed key opens the collection for them alone, and shipping the
	// whole set to anyone who asks would hand an attacker every blob at once.
	if body := rec.Body.String(); strings.Contains(body, "sealed-to-member") {
		t.Errorf("member list leaks a sealed collection key: %s", body)
	}
}

func TestOnlyAnAdminMayDeleteACollection(t *testing.T) {
	srv := newTestServer(t)
	admin, adminToken := loginAdmin(t, srv, "admin@example.com")
	member, memberToken := loginTestUser(t, srv, "member@example.com")

	collection := createCollection(t, srv, adminToken, "Household")
	if err := srv.store.FulfilGrantOrAdd(context.Background(),
		collection.ID, member.ID, "sealed", "manager", admin.ID); err != nil {
		t.Fatalf("add manager: %v", err)
	}

	// Even a manager cannot delete: managers run membership, admins own the
	// graph's shape.
	if rec := doJSON(t, srv, http.MethodDelete, "/api/collections/"+collection.ID,
		memberToken, nil); rec.Code != http.StatusForbidden {
		t.Errorf("manager delete status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if rec := doJSON(t, srv, http.MethodDelete, "/api/collections/"+collection.ID,
		adminToken, nil); rec.Code != http.StatusNoContent {
		t.Errorf("admin delete status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}
```

The file's imports are `context`, `net/http`, `strings`, `testing`, and
`github.com/ssan9876/keyhole/internal/store`.

- [ ] **Step 3: Run and watch it fail**

```bash
go test ./internal/httpapi/ -run "Collection|Grant|Member" -v
```

Expected: FAIL — every route 404s.

- [ ] **Step 4: Implement the collection handlers**

Create `internal/httpapi/collections.go`:

```go
package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/ssan9876/keyhole/internal/store"
)

type collectionJSON struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Role                string `json:"role"`
	SealedCollectionKey string `json:"sealedCollectionKey"`
	CreatedBy           string `json:"createdBy"`
	CreatedAt           string `json:"createdAt"`
}

func toCollectionJSON(c store.CollectionWithMembership) collectionJSON {
	return collectionJSON{
		ID:                  c.ID,
		Name:                c.Name,
		Role:                c.Role,
		SealedCollectionKey: c.SealedCollectionKey,
		CreatedBy:           c.CreatedBy,
		CreatedAt:           c.CreatedAt.Format(time.RFC3339),
	}
}

type pendingGrantJSON struct {
	CollectionID   string `json:"collectionId"`
	CollectionName string `json:"collectionName"`
	UserID         string `json:"userId"`
	Role           string `json:"role"`
	RequestedBy    string `json:"requestedBy"`
	CreatedAt      string `json:"createdAt"`
}

func toPendingGrantJSON(g store.PendingGrant) pendingGrantJSON {
	return pendingGrantJSON{
		CollectionID:   g.CollectionID,
		CollectionName: g.CollectionName,
		UserID:         g.UserID,
		Role:           g.Role,
		RequestedBy:    g.RequestedBy,
		CreatedAt:      g.CreatedAt.Format(time.RFC3339),
	}
}

// requireManager resolves the caller's authority over one collection.
//
// A manager of the collection, or an admin, may manage its membership. The two
// are not the same power: a manager holds the collection key and can therefore
// complete a grant, while an admin can only request one. That asymmetry is the
// cryptographic guarantee showing through, not an oversight.
//
// A caller with neither standing gets 404 when they are not a member — the
// collection's existence is not theirs to learn — and 403 when they are a
// plain member, since they already know it exists.
func (s *Server) requireManager(w http.ResponseWriter, r *http.Request, collectionID string) bool {
	user, _ := UserFrom(r.Context())

	membership, err := s.store.MembershipFor(r.Context(), collectionID, user.ID)
	switch {
	case err == nil:
		if membership.Role == "manager" || user.Role == "admin" {
			return true
		}
		WriteError(w, http.StatusForbidden, CodeForbidden,
			"only a manager of this collection can change its membership")
		return false
	case errors.Is(err, store.ErrNotFound):
		if user.Role != "admin" {
			WriteError(w, http.StatusNotFound, CodeNotFound, "no such collection")
			return false
		}
		// An admin who is not a member still administers the collection, but
		// only if it exists.
		if _, err := s.store.CollectionByID(r.Context(), collectionID); err != nil {
			s.writeStoreError(w, r, "load collection", err)
			return false
		}
		return true
	default:
		s.writeStoreError(w, r, "load membership", err)
		return false
	}
}

type createCollectionRequest struct {
	Name                string `json:"name"`
	SealedCollectionKey string `json:"sealedCollectionKey"`
}

func (s *Server) handleCreateCollection(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	var req createCollectionRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	collection, err := s.store.CreateCollection(r.Context(), req.Name, user.ID, req.SealedCollectionKey)
	if err != nil {
		s.writeStoreError(w, r, "create collection", err)
		return
	}
	WriteJSON(w, http.StatusCreated, collectionJSON{
		ID:                  collection.ID,
		Name:                collection.Name,
		Role:                "manager",
		SealedCollectionKey: req.SealedCollectionKey,
		CreatedBy:           collection.CreatedBy,
		CreatedAt:           collection.CreatedAt.Format(time.RFC3339),
	})
}

func (s *Server) handleListCollections(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	collections, err := s.store.CollectionsForUser(r.Context(), user.ID)
	if err != nil {
		s.writeStoreError(w, r, "list collections", err)
		return
	}
	grants, err := s.pendingGrantsFor(r, user)
	if err != nil {
		s.writeStoreError(w, r, "list pending grants", err)
		return
	}

	out := make([]collectionJSON, 0, len(collections))
	for _, collection := range collections {
		out = append(out, toCollectionJSON(collection))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"collections":   out,
		"pendingGrants": grants,
	})
}

// pendingGrantsFor returns what this caller should see. A member sees the
// grants they can actually fulfil; an admin sees all of them, because an admin
// needs to know a grant they requested is still waiting on someone else.
func (s *Server) pendingGrantsFor(r *http.Request, user store.User) ([]pendingGrantJSON, error) {
	var grants []store.PendingGrant
	var err error
	if user.Role == "admin" {
		grants, err = s.store.AllPendingGrants(r.Context())
	} else {
		grants, err = s.store.PendingGrantsFulfillableBy(r.Context(), user.ID)
	}
	if err != nil {
		return nil, err
	}
	out := make([]pendingGrantJSON, 0, len(grants))
	for _, grant := range grants {
		out = append(out, toPendingGrantJSON(grant))
	}
	return out, nil
}

func (s *Server) handleListPendingGrants(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	grants, err := s.pendingGrantsFor(r, user)
	if err != nil {
		s.writeStoreError(w, r, "list pending grants", err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"pendingGrants": grants})
}

func (s *Server) handleDeleteCollection(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())
	id := r.PathValue("id")

	if err := s.store.DeleteCollection(r.Context(), id); err != nil {
		s.writeStoreError(w, r, "delete collection", err)
		return
	}
	if err := s.store.AppendAudit(r.Context(), user.ID, "collection.delete", "collection:"+id, ""); err != nil {
		s.logger.Error("audit collection delete", "id", RequestIDFrom(r.Context()), "error", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

type addMemberRequest struct {
	UserID              string `json:"userId"`
	Role                string `json:"role"`
	SealedCollectionKey string `json:"sealedCollectionKey"`
}

// handleAddMember takes one of two paths, and the status code says which.
//
// With a sealed key the caller has done the crypto themselves and membership
// is immediate: 201. Without one the server records an intention it cannot
// carry out — it holds no collection key and never will — so it answers 202
// and waits for a member's client to complete the grant. Answering 201 in that
// case would tell the admin the user has access when they do not.
func (s *Server) handleAddMember(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserFrom(r.Context())
	collectionID := r.PathValue("id")

	var req addMemberRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if !s.requireManager(w, r, collectionID) {
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}

	// The target must be a real, active account. Recording a grant against an
	// id that does not resolve leaves an entry no client can ever fulfil.
	target, err := s.store.UserByID(r.Context(), req.UserID)
	if err != nil || target.Status != "active" {
		WriteError(w, http.StatusNotFound, CodeNotFound, "no such user")
		return
	}

	if req.SealedCollectionKey == "" {
		if err := s.store.CreatePendingGrant(r.Context(), collectionID, req.UserID, req.Role, actor.ID); err != nil {
			s.writeStoreError(w, r, "create pending grant", err)
			return
		}
		WriteJSON(w, http.StatusAccepted, map[string]any{
			"status": "pending",
			"message": "recorded. A member of this collection must seal the key " +
				"to this user before they gain access.",
		})
		return
	}

	// Supplying a sealed key requires actually holding the collection key,
	// which only a member does. An admin who is not a member cannot get here
	// with a real blob, and a fabricated one would lock the target out.
	if _, err := s.store.MembershipFor(r.Context(), collectionID, actor.ID); err != nil {
		s.writeStoreError(w, r, "load membership", err)
		return
	}
	if err := s.store.FulfilGrantOrAdd(r.Context(), collectionID, req.UserID,
		req.SealedCollectionKey, req.Role, actor.ID); err != nil {
		s.writeStoreError(w, r, "add member", err)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "granted"})
}

func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserFrom(r.Context())
	collectionID := r.PathValue("id")
	userID := r.PathValue("userId")

	if !s.requireManager(w, r, collectionID) {
		return
	}
	if err := s.store.RemoveMember(r.Context(), collectionID, userID, actor.ID); err != nil {
		s.writeStoreError(w, r, "remove member", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type fulfilGrantRequest struct {
	UserID              string `json:"userId"`
	SealedCollectionKey string `json:"sealedCollectionKey"`
}

// handleFulfilGrant completes a grant an admin could only request. The caller
// must be a manager AND a member: only a member holds the key to seal.
func (s *Server) handleFulfilGrant(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserFrom(r.Context())
	collectionID := r.PathValue("id")

	var req fulfilGrantRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	membership, err := s.store.MembershipFor(r.Context(), collectionID, actor.ID)
	if errors.Is(err, store.ErrNotFound) {
		WriteError(w, http.StatusNotFound, CodeNotFound, "no such collection")
		return
	}
	if err != nil {
		s.writeStoreError(w, r, "load membership", err)
		return
	}
	if membership.Role != "manager" {
		WriteError(w, http.StatusForbidden, CodeForbidden,
			"only a manager of this collection can fulfil grants")
		return
	}

	if err := s.store.FulfilGrant(r.Context(), collectionID, req.UserID,
		req.SealedCollectionKey, actor.ID); err != nil {
		s.writeStoreError(w, r, "fulfil grant", err)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "granted"})
}

type memberJSON struct {
	UserID    string `json:"userId"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	GrantedAt string `json:"grantedAt"`
}

// handleListMembers is a directory, not a key distribution channel: it
// deliberately omits every sealed_collection_key. Each member's blob opens the
// collection for them alone, and handing the whole set to any caller would put
// every one of them in one response.
func (s *Server) handleListMembers(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())
	collectionID := r.PathValue("id")

	if _, err := s.store.MembershipFor(r.Context(), collectionID, user.ID); err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.writeStoreError(w, r, "load membership", err)
			return
		}
		if user.Role != "admin" {
			WriteError(w, http.StatusNotFound, CodeNotFound, "no such collection")
			return
		}
	}

	memberships, err := s.store.MembershipsOf(r.Context(), collectionID)
	if err != nil {
		s.writeStoreError(w, r, "list members", err)
		return
	}

	out := make([]memberJSON, 0, len(memberships))
	for _, membership := range memberships {
		member, err := s.store.UserByID(r.Context(), membership.UserID)
		if err != nil {
			s.writeStoreError(w, r, "load member", err)
			return
		}
		out = append(out, memberJSON{
			UserID:    member.ID,
			Name:      member.Name,
			Email:     member.Email,
			Role:      membership.Role,
			GrantedAt: membership.GrantedAt.Format(time.RFC3339),
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"members": out})
}
```

- [ ] **Step 5: Register the collection routes**

In `routes()`:

```go
	s.mux.HandleFunc("GET /api/collections", s.requireAuth(s.handleListCollections))
	s.mux.HandleFunc("POST /api/collections", s.requireAdmin(s.handleCreateCollection))
	s.mux.HandleFunc("GET /api/collections/pending-grants", s.requireAuth(s.handleListPendingGrants))
	s.mux.HandleFunc("DELETE /api/collections/{id}", s.requireAdmin(s.handleDeleteCollection))
	s.mux.HandleFunc("GET /api/collections/{id}/members", s.requireAuth(s.handleListMembers))
	s.mux.HandleFunc("POST /api/collections/{id}/members", s.requireAuth(s.handleAddMember))
	s.mux.HandleFunc("DELETE /api/collections/{id}/members/{userId}", s.requireAuth(s.handleRemoveMember))
	s.mux.HandleFunc("POST /api/collections/{id}/grants", s.requireAuth(s.handleFulfilGrant))
```

`GET /api/collections/pending-grants` and `GET /api/collections/{id}/members`
do not conflict — different segment counts. Nothing registers
`GET /api/collections/{id}`, so the literal `pending-grants` path is
unambiguous; stdlib `ServeMux` would prefer it in any case.

Note the membership routes use `requireAuth`, not `requireAdmin`: a manager who
is not an admin must be able to run their own collection, and `requireManager`
inside each handler is what enforces the rest.

- [ ] **Step 6: Include collections in the sync response**

In `handleSync`, build and add the collections list:

```go
	collections := make([]collectionJSON, 0, len(result.Collections))
	for _, collection := range result.Collections {
		collections = append(collections, toCollectionJSON(collection))
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"revision":    result.Revision,
		"items":       items,
		"folders":     folders,
		"collections": collections,
	})
```

and add the field to `syncResponse` in `sync_test.go`:

```go
	Collections []collectionResponse `json:"collections"`
```

- [ ] **Step 7: Replace the raw-SQL collection fixture in the item tests**

Delete `seedTestCollection` from `internal/httpapi/items_test.go`. Rewrite its
two callers to use `loginAdmin` + `createCollection` + `FulfilGrantOrAdd`, so
there is one definition of how a collection comes into being:

```go
func TestCreateItemInAForeignCollectionIsNotFound(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "owner@example.com")
	_, outsiderToken := loginTestUser(t, srv, "outsider@example.com")

	collection := createCollection(t, srv, adminToken, "Household")

	rec := doJSON(t, srv, http.MethodPost, "/api/items", outsiderToken, map[string]string{
		"collectionId": collection.ID, "ciphertext": "c", "wrappedItemKey": "k",
	})
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	var count int
	if err := srv.store.DB().QueryRow(`SELECT COUNT(*) FROM items`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("%d items were written into a collection the caller does not belong to", count)
	}
}

func TestAMemberMayEditAnItemTheyDidNotCreate(t *testing.T) {
	srv := newTestServer(t)
	admin, adminToken := loginAdmin(t, srv, "owner@example.com")
	member, memberToken := loginTestUser(t, srv, "member@example.com")

	collection := createCollection(t, srv, adminToken, "Household")
	if err := srv.store.FulfilGrantOrAdd(context.Background(),
		collection.ID, member.ID, "sealed-to-member", "member", admin.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}

	created := doJSON(t, srv, http.MethodPost, "/api/items", adminToken, map[string]string{
		"collectionId": collection.ID, "ciphertext": "v1", "wrappedItemKey": "k",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var item itemResponse
	decodeInto(t, created, &item)

	// Spec section 5.1: any member may edit any item in a collection.
	// owner_user_id records who made it and confers no exclusive rights.
	rec := doJSON(t, srv, http.MethodPut, "/api/items/"+item.ID, memberToken, map[string]any{
		"collectionId": collection.ID, "ciphertext": "v2",
		"wrappedItemKey": "k", "revision": item.Revision,
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}
```

- [ ] **Step 8: Run the collection tests**

```bash
go test ./internal/httpapi/ -run "Collection|Grant|Member|Item|Sync" -v
```

Expected: PASS.

- [ ] **Step 9: Write the failing directory tests**

Create `internal/httpapi/directory_test.go`:

```go
package httpapi

import (
	"net/http"
	"strings"
	"testing"
)

type directoryEntry struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	PublicKey string `json:"publicKey"`
}

func TestDirectoryListsActiveUsersAndTheirPublicKeys(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")
	loginTestUser(t, srv, "other@example.com")

	rec := doJSON(t, srv, http.MethodGet, "/api/directory", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Users []directoryEntry `json:"users"`
	}
	decodeInto(t, rec, &body)
	if len(body.Users) != 2 {
		t.Fatalf("got %d users, want 2", len(body.Users))
	}
	// Without a public key there is nothing to seal a collection key to, so
	// sharing would be impossible. This is why the endpoint exists.
	for _, user := range body.Users {
		if user.PublicKey == "" {
			t.Errorf("user %s has no public key", user.Email)
		}
	}
}

func TestDirectoryNeverCarriesKeyMaterial(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	rec := doJSON(t, srv, http.MethodGet, "/api/directory", token, nil)
	body := rec.Body.String()

	// Spec section 10 names this as a security test: no endpoint may return
	// another user's wrapped keys. The public key is public by design; every
	// one of these is not.
	for _, field := range []string{
		"protectedUserKey", "protected_user_key",
		"encryptedPrivateKey", "encrypted_private_key",
		"recoveryProtectedUserKey", "recovery_protected_user_key",
		"authHash", "auth_hash", "kdfSalt", "kdf_salt",
		"recoverySalt", "recovery_salt",
	} {
		if strings.Contains(body, field) {
			t.Errorf("directory response contains %q: %s", field, body)
		}
	}
}

func TestDirectoryOmitsPendingAndDisabledAccounts(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")
	seedInvite(t, srv, "pending@example.com") // never enrolled

	rec := doJSON(t, srv, http.MethodGet, "/api/directory", token, nil)
	var body struct {
		Users []directoryEntry `json:"users"`
	}
	decodeInto(t, rec, &body)

	// A pending account has no public key at all, so listing it would offer a
	// share target that can never receive one.
	for _, user := range body.Users {
		if user.Email == "pending@example.com" {
			t.Error("the directory lists an account that has never enrolled")
		}
	}
	if len(body.Users) != 1 {
		t.Errorf("got %d users, want 1", len(body.Users))
	}
}

func TestDirectoryRequiresAuthentication(t *testing.T) {
	srv := newTestServer(t)

	rec := doJSON(t, srv, http.MethodGet, "/api/directory", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d — the user list is not public",
			rec.Code, http.StatusUnauthorized)
	}
}
```

- [ ] **Step 10: Implement the directory**

Create `internal/httpapi/directory.go`:

```go
package httpapi

import (
	"net/http"
)

// handleDirectory lists the accounts a collection key can be sealed to.
//
// Spec section 4.3 does not name this endpoint, but sharing is impossible
// without it: sealToUser needs the recipient's X25519 public key, and the
// server is where public keys live. It returns the public key and nothing
// else that is key material — spec section 3.9's first accepted limitation is
// precisely that the server distributes these, and the mitigation is the
// fingerprint the client renders from this value, not secrecy.
//
// Only active accounts appear. A pending account has no public key at all, so
// offering it as a share target would promise something that cannot happen.
func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.DB().QueryContext(r.Context(),
		`SELECT id, name, email, public_key FROM users
		 WHERE status = 'active' AND public_key IS NOT NULL
		 ORDER BY name`)
	if err != nil {
		s.writeStoreError(w, r, "list directory", err)
		return
	}
	defer func() { _ = rows.Close() }()

	type entry struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		PublicKey string `json:"publicKey"`
	}

	users := []entry{}
	for rows.Next() {
		var user entry
		if err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.PublicKey); err != nil {
			s.writeStoreError(w, r, "scan directory entry", err)
			return
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		s.writeStoreError(w, r, "iterate directory", err)
		return
	}

	WriteJSON(w, http.StatusOK, map[string]any{"users": users})
}
```

Register:

```go
	s.mux.HandleFunc("GET /api/directory", s.requireAuth(s.handleDirectory))
```

- [ ] **Step 11: Run the directory tests**

```bash
go test ./internal/httpapi/ -run Directory -v
```

Expected: PASS, all four.

- [ ] **Step 12: Prove the manager gate is load-bearing**

In `requireManager`, temporarily make the plain-member branch permissive:

```go
		if membership.Role == "manager" || user.Role == "admin" || true {
```

Run `go test ./internal/httpapi/ -run TestAPlainMemberCannotAddOrRemoveMembers -v`.
Expected: FAIL — the add returns 202 and the remove 204 instead of 403. Revert
and confirm PASS. Record both.

- [ ] **Step 13: Full suite, vet, gofmt, race**

```bash
go test ./... && gofmt -l ./internal ./cmd && go vet ./...
```

Expected: PASS, both silent.

```bash
go test -race ./internal/httpapi/
```

Expected: PASS.

- [ ] **Step 14: Commit**

```bash
git add internal/httpapi/ && git commit -m "feat(api): collection, grant, and directory endpoints"
```

---

## Task 6: Account self-service, and pinning the KDF parameters

**Files:**
- Create: `internal/store/account.go`
- Create: `internal/httpapi/account.go`
- Test: `internal/store/account_test.go`, `internal/httpapi/account_test.go`
- Modify: `internal/store/enroll.go` (`ValidationError.Message`; pin `params`)
- Modify: `internal/httpapi/server.go` (register the routes)

**Interfaces:**
- Consumes: `store.Session`, `store.User`, `auth.HashAuthHash`,
  `auth.VerifyAuthHash`, `auth.DefaultKDFParamsJSON`, `writeStoreError`.
- Produces:
  ```go
  type PasswordRotation struct {
      KDFSalt          string
      KDFParams        string
      AuthHash         string // already hashed for storage
      ProtectedUserKey string
  }

  type RecoveryRotation struct {
      RecoverySalt             string
      RecoveryKDFParams        string
      RecoveryProtectedUserKey string
  }

  func (s *Store) RotatePassword(ctx context.Context, userID string, in PasswordRotation, keepSessionID string) error
  func (s *Store) RotateRecovery(ctx context.Context, userID string, in RecoveryRotation) error
  func (s *Store) SessionsForUser(ctx context.Context, userID string) ([]Session, error)
  func (s *Store) RevokeSessionForUser(ctx context.Context, sessionID, userID string) error
  ```

**Routes registered:**

```
GET    /api/account
POST   /api/account/password
POST   /api/account/recovery
GET    /api/account/sessions
DELETE /api/account/sessions/{id}
```

### The KDF pinning change

This closes the enumeration hole the Plan 2a whole-branch review carried
forward. `handlePrelogin` answers an unknown address with
`auth.DefaultKDFParamsJSON`. If any real account holds different params,
comparing prelogin's `params` field against the default tells an attacker
whether an address has an account here — the exact thing the decoy exists to
prevent. `/api/account/password` is where divergence would first appear.

So both enrollment and rotation reject params that are not byte-equal to
`auth.DefaultKDFParamsJSON`. This amends spec §3.2: raising the parameters
later becomes a deliberate migration that forces every user to re-derive at
next login, rather than a silent per-user drift. `recovery_kdf_params` is
**not** pinned — no endpoint returns it, so it leaks nothing, and §4.2's
reason for recording it separately still stands.

- [ ] **Step 1: Give ValidationError a message, and pin params**

In `internal/store/enroll.go`, extend the error type. Note the wording change:
Plan 2a's text was `enrollment field %q is required`, but this type is now
raised by items, folders, collections, and account rotation as well, and
telling a caller that `status` is an "enrollment field" would send them
looking in the wrong place entirely.

```go
// ValidationError means the client's payload was incomplete or malformed. It
// is the caller's fault and is safe to report back to them — unlike a database
// failure, whose text must never reach a client.
type ValidationError struct {
	Field string
	// Message replaces the default "is required" wording when a field is
	// present but unacceptable. A caller told only that a field "is required"
	// when they plainly did send it has nothing to act on.
	Message string
}

func (e *ValidationError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("field %q %s", e.Field, e.Message)
	}
	return fmt.Sprintf("field %q is required", e.Field)
}
```

`internal/httpapi/enroll.go` hard-codes the old wording for its pre-hash
`authHash` check, which runs before the store is ever reached. Update that
literal to match, so the same failure does not get two different messages
depending on which layer caught it:

```go
		WriteError(w, http.StatusBadRequest, CodeBadRequest, "field \"authHash\" is required")
```

Grep for `enrollment field` afterwards and confirm no occurrence remains.

Then, at the end of `EnrollmentInput.validate()`, before `return nil`:

```go
	// The prelogin decoy answers an unknown address with DefaultKDFParamsJSON.
	// The moment one real account holds different parameters, comparing that
	// field against the default tells an attacker whether an address has an
	// account here — which is precisely what the decoy exists to stop. So the
	// parameters are pinned, and raising them becomes a deliberate migration
	// rather than a silent per-user drift.
	//
	// Byte equality, not semantic: the decoy emits this exact string, so
	// anything that serializes differently is distinguishable even when it
	// means the same thing.
	if in.KDFParams != auth.DefaultKDFParamsJSON {
		return &ValidationError{
			Field:   "params",
			Message: "must match the server's current KDF parameters exactly",
		}
	}
```

Add `"github.com/ssan9876/keyhole/internal/auth"` to that file's imports.

- [ ] **Step 2: Write the failing pinning test**

Append to `internal/store/enroll_test.go`:

```go
func TestEnrollmentRejectsNonDefaultKDFParams(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()

	user, err := st.CreatePendingUser(ctx, "person@example.com", "Test Person", "user")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	_, token, err := st.CreateInvite(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}

	in := validEnrollmentInput()
	// Semantically identical, byte-different. That is enough: prelogin's decoy
	// emits one exact string, so any other serialization makes this account
	// distinguishable from an address with no account at all.
	in.KDFParams = `{"algorithm":"argon2id","iterations":3,"memoryKiB":65536,"parallelism":4}`

	_, err = st.CompleteEnrollment(ctx, token, in)
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("err = %v, want a *ValidationError", err)
	}
	if validation.Field != "params" {
		t.Errorf("Field = %q, want %q", validation.Field, "params")
	}
}

func TestEnrollmentAcceptsTheDefaultKDFParams(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()

	user, err := st.CreatePendingUser(ctx, "person@example.com", "Test Person", "user")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	_, token, err := st.CreateInvite(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}

	in := validEnrollmentInput()
	in.KDFParams = auth.DefaultKDFParamsJSON
	if _, err := st.CompleteEnrollment(ctx, token, in); err != nil {
		t.Fatalf("CompleteEnrollment: %v", err)
	}
}
```

`validEnrollmentInput()` is the fixture already in that file. If it does not
exist under that name, use whatever the file's existing complete-input helper
is called; do not add a second one. Its `KDFParams` must already equal
`auth.DefaultKDFParamsJSON`, since Plan 2a's `enrollBody()` fixture does —
verify, and fix the fixture rather than the assertion if it does not.

- [ ] **Step 3: Run the suite and check nothing else broke**

```bash
go test ./... -v 2>&1 | tail -40
```

Expected: the two new tests PASS, and every existing enrollment test still
passes. If an existing test fails because its fixture used different params,
the fixture is what is wrong — the whole point is that only one value is
acceptable.

- [ ] **Step 4: Write the failing account store tests**

Create `internal/store/account_test.go`:

```go
package store

import (
	"context"
	"errors"
	"testing"

	"github.com/ssan9876/keyhole/internal/auth"
)

func TestRotatePasswordReplacesTheCredentialAndTheWrappedKey(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")

	if err := st.RotatePassword(ctx, userID, PasswordRotation{
		KDFSalt:          "bmV3LXNhbHQtMTZieXRlcw==",
		KDFParams:        auth.DefaultKDFParamsJSON,
		AuthHash:         "argon2id$stored$hash",
		ProtectedUserKey: "new-protected-user-key",
	}, ""); err != nil {
		t.Fatalf("RotatePassword: %v", err)
	}

	user, err := st.UserByID(ctx, userID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if user.ProtectedUserKey.String != "new-protected-user-key" {
		t.Errorf("ProtectedUserKey = %q", user.ProtectedUserKey.String)
	}
	if user.AuthHash.String != "argon2id$stored$hash" {
		t.Errorf("AuthHash = %q", user.AuthHash.String)
	}
	// The recovery blob is wrapped by the recovery code, not the master
	// password, so a password change must leave it entirely alone. Clearing it
	// here would silently destroy the user's last way back in.
	if !user.RecoveryProtectedUserKey.Valid || user.RecoveryProtectedUserKey.String == "" {
		t.Error("rotating the password destroyed the recovery blob")
	}
}

func TestRotatePasswordRevokesEveryOtherSession(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")

	keep, keepToken, _, err := st.CreateSession(ctx, userID, "this device")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	_, otherToken, _, err := st.CreateSession(ctx, userID, "other device")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if err := st.RotatePassword(ctx, userID, PasswordRotation{
		KDFSalt:   "s",
		KDFParams: auth.DefaultKDFParamsJSON,
		AuthHash:  "h", ProtectedUserKey: "k",
	}, keep.ID); err != nil {
		t.Fatalf("RotatePassword: %v", err)
	}

	// Changing a master password is what a user does after suspecting a
	// compromise. Leaving other devices signed in makes the action mean far
	// less than the user believes it does.
	if _, err := st.SessionByAccessToken(ctx, otherToken); !errors.Is(err, ErrNotFound) {
		t.Errorf("the other session survived: %v", err)
	}
	// And the device that performed the change stays signed in, or the user is
	// logged out by their own successful action.
	if _, err := st.SessionByAccessToken(ctx, keepToken); err != nil {
		t.Errorf("the current session was revoked too: %v", err)
	}
}

func TestRotateRecoveryReplacesOnlyTheRecoveryBlob(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")

	before, err := st.UserByID(ctx, userID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}

	if err := st.RotateRecovery(ctx, userID, RecoveryRotation{
		RecoverySalt:             "new-recovery-salt",
		RecoveryKDFParams:        `{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4}`,
		RecoveryProtectedUserKey: "new-recovery-blob",
	}); err != nil {
		t.Fatalf("RotateRecovery: %v", err)
	}

	after, err := st.UserByID(ctx, userID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if after.RecoveryProtectedUserKey.String != "new-recovery-blob" {
		t.Errorf("RecoveryProtectedUserKey = %q", after.RecoveryProtectedUserKey.String)
	}
	// Issuing a new recovery code must not disturb the master-password path.
	// A user who regenerates a code and then cannot sign in has lost both.
	if after.AuthHash.String != before.AuthHash.String {
		t.Error("regenerating a recovery code changed the login credential")
	}
	if after.ProtectedUserKey.String != before.ProtectedUserKey.String {
		t.Error("regenerating a recovery code changed the password-wrapped key")
	}
}

func TestRotateRecoveryRejectsAnIncompletePayload(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")

	// A half-written recovery record is worse than none: the UI would show the
	// user a code that cannot open anything.
	err := st.RotateRecovery(ctx, userID, RecoveryRotation{
		RecoverySalt: "salt", RecoveryProtectedUserKey: "blob",
	})
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("err = %v, want a *ValidationError", err)
	}
}

func TestSessionsForUserListsLiveSessionsOnly(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")
	otherID := enrolledUserID(t, st, "other@example.com")

	if _, _, _, err := st.CreateSession(ctx, userID, "laptop"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	revoked, _, _, err := st.CreateSession(ctx, userID, "old phone")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := st.RevokeSession(ctx, revoked.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if _, _, _, err := st.CreateSession(ctx, otherID, "someone else"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := st.SessionsForUser(ctx, userID)
	if err != nil {
		t.Fatalf("SessionsForUser: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("got %d sessions, want 1 live one", len(sessions))
	}
	if sessions[0].DeviceLabel != "laptop" {
		t.Errorf("DeviceLabel = %q", sessions[0].DeviceLabel)
	}
}

func TestRevokeSessionForUserRefusesAnotherUsersSession(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	mine := enrolledUserID(t, st, "mine@example.com")
	theirs := enrolledUserID(t, st, "theirs@example.com")

	session, token, _, err := st.CreateSession(ctx, theirs, "their laptop")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Session ids are opaque, but "sign out my other device" must not become
	// "sign out anyone's device" for a caller who guesses or observes one.
	if err := st.RevokeSessionForUser(ctx, session.ID, mine); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if _, err := st.SessionByAccessToken(ctx, token); err != nil {
		t.Errorf("another user's session was revoked: %v", err)
	}
}
```

- [ ] **Step 5: Run and watch it fail**

```bash
go test ./internal/store/ -run "Rotate|SessionsForUser|RevokeSessionForUser" -v
```

Expected: FAIL — `st.RotatePassword undefined`.

- [ ] **Step 6: Implement the account store**

Create `internal/store/account.go`:

```go
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/ssan9876/keyhole/internal/auth"
)

// PasswordRotation is a master-password change. AuthHash arrives already
// hashed for storage; the server never sees the password or the raw auth hash
// at rest.
//
// ProtectedUserKey is the same userKey re-wrapped under the new wrapping key.
// That indirection is the whole reason a password change is four columns
// rather than a re-encryption of the vault.
type PasswordRotation struct {
	KDFSalt          string
	KDFParams        string
	AuthHash         string
	ProtectedUserKey string
}

func (in PasswordRotation) validate() error {
	for field, value := range map[string]string{
		"kdfSalt":          in.KDFSalt,
		"params":           in.KDFParams,
		"authHash":         in.AuthHash,
		"protectedUserKey": in.ProtectedUserKey,
	} {
		if value == "" {
			return &ValidationError{Field: field}
		}
	}
	// Pinned in the store as well as in the handler, so the invariant holds for
	// every caller rather than only the HTTP one. Enrollment pins it in
	// EnrollmentInput.validate for the same reason: these are the only two
	// paths that ever write kdf_params, and one unguarded path is all it takes
	// to make an account enumerable through prelogin.
	if in.KDFParams != auth.DefaultKDFParamsJSON {
		return &ValidationError{
			Field:   "params",
			Message: "must match the server's current KDF parameters exactly",
		}
	}
	return nil
}

// RotatePassword writes the new credential and revokes every session except
// keepSessionID.
//
// Revoking the others is not optional politeness: changing a master password
// is what a user does when they suspect a compromise, and leaving other
// devices signed in makes the action mean far less than they believe. An empty
// keepSessionID revokes all of them.
func (s *Store) RotatePassword(ctx context.Context, userID string, in PasswordRotation, keepSessionID string) error {
	if err := in.validate(); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin password rotation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339)

	// The recovery columns are deliberately untouched: that blob is wrapped by
	// the recovery code, not the master password, so clearing it here would
	// silently destroy the user's last way back in.
	result, err := tx.ExecContext(ctx,
		`UPDATE users SET kdf_salt = ?, kdf_params = ?, auth_hash = ?,
			protected_user_key = ?, revision = revision + 1, updated_at = ?
		 WHERE id = ? AND status = 'active'`,
		in.KDFSalt, in.KDFParams, in.AuthHash, in.ProtectedUserKey, now, userID)
	if err != nil {
		return fmt.Errorf("rotate password: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ?
		 WHERE user_id = ? AND revoked_at IS NULL AND id != ?`,
		now, userID, keepSessionID); err != nil {
		return fmt.Errorf("revoke other sessions: %w", err)
	}

	if err := appendAudit(ctx, tx, userID, "account.password.rotate", "user:"+userID, ""); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit password rotation: %w", err)
	}
	return nil
}

// RecoveryRotation replaces the recovery blob and the parameters it was made
// with. The parameters are recorded rather than assumed (spec section 4.2):
// deriving a recovery key with parameters other than the ones the blob was
// wrapped under yields a different key, and that failure would surface only at
// the moment recovery was the user's last resort.
type RecoveryRotation struct {
	RecoverySalt             string
	RecoveryKDFParams        string
	RecoveryProtectedUserKey string
}

func (in RecoveryRotation) validate() error {
	for field, value := range map[string]string{
		"recoverySalt":             in.RecoverySalt,
		"recoveryKdfParams":        in.RecoveryKDFParams,
		"recoveryProtectedUserKey": in.RecoveryProtectedUserKey,
	} {
		if value == "" {
			return &ValidationError{Field: field}
		}
	}
	return nil
}

// RotateRecovery issues a new recovery blob, invalidating the old code by
// replacing what it opens. Sessions and the password path are untouched: a
// user regenerating a code has not lost their password, and logging them out
// of everything for it would be gratuitous.
func (s *Store) RotateRecovery(ctx context.Context, userID string, in RecoveryRotation) error {
	if err := in.validate(); err != nil {
		return err
	}

	result, err := s.db.ExecContext(ctx,
		`UPDATE users SET recovery_salt = ?, recovery_kdf_params = ?,
			recovery_protected_user_key = ?, revision = revision + 1, updated_at = ?
		 WHERE id = ? AND status = 'active'`,
		in.RecoverySalt, in.RecoveryKDFParams, in.RecoveryProtectedUserKey,
		time.Now().UTC().Format(time.RFC3339), userID)
	if err != nil {
		return fmt.Errorf("rotate recovery: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return s.AppendAudit(ctx, userID, "account.recovery.rotate", "user:"+userID, "")
}

// SessionsForUser lists a user's live sessions, newest activity first. Revoked
// and expired sessions are omitted: the list exists so a user can end a session
// they do not recognize, and rows they cannot act on are noise.
func (s *Store) SessionsForUser(ctx context.Context, userID string) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions
		 WHERE user_id = ? AND revoked_at IS NULL
		 ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("select sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	now := time.Now().UTC()
	sessions := []Session{}
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		if now.After(session.ExpiresAt) ||
			now.After(session.CreatedAt.Add(RefreshTokenLifetime)) {
			continue
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}
	return sessions, nil
}

// RevokeSessionForUser revokes a session only if it belongs to that user.
// Session ids are opaque, but "sign out my other device" must not become "sign
// out anyone's device" for a caller who guesses or observes one.
func (s *Store) RevokeSessionForUser(ctx context.Context, sessionID, userID string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ?
		 WHERE id = ? AND user_id = ? AND revoked_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339), sessionID, userID)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}
```

- [ ] **Step 7: Run the account store tests**

```bash
go test ./internal/store/ -run "Rotate|SessionsForUser|RevokeSessionForUser" -v
```

Expected: PASS, all six.

- [ ] **Step 8: Write the failing account endpoint tests**

Create `internal/httpapi/account_test.go`:

```go
package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ssan9876/keyhole/internal/auth"
)

func TestGetAccountReturnsTheProfileAndNoKeyMaterial(t *testing.T) {
	srv := newTestServer(t)
	user, token := loginTestUser(t, srv, "person@example.com")

	rec := doJSON(t, srv, http.MethodGet, "/api/account", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		Name      string `json:"name"`
		Role      string `json:"role"`
		PublicKey string `json:"publicKey"`
	}
	decodeInto(t, rec, &body)
	if body.ID != user.ID {
		t.Errorf("id = %q, want %q", body.ID, user.ID)
	}
	if body.PublicKey == "" {
		t.Error("publicKey is empty; the client renders its own fingerprint from it")
	}
	// The wrapped keys are delivered by login, once, with the tokens. Repeating
	// them on a plain profile read widens the blast radius of any endpoint that
	// is ever accidentally cached or logged.
	for _, field := range []string{"authHash", "protectedUserKey", "encryptedPrivateKey"} {
		if strings.Contains(rec.Body.String(), field) {
			t.Errorf("/api/account carries %q", field)
		}
	}
}

func TestRotatingThePasswordRequiresTheCurrentOne(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	// A stolen access token must not be enough to overwrite the wrapped key.
	// An attacker holding one cannot produce a valid new protectedUserKey, but
	// they could write garbage into it and destroy the vault; the current
	// credential is what stops that.
	rec := doJSON(t, srv, http.MethodPost, "/api/account/password", token, map[string]string{
		"currentAuthHash":  "not-the-right-hash",
		"kdfSalt":          "bmV3LXNhbHQtMTZieXRlcw==",
		"params":           auth.DefaultKDFParamsJSON,
		"authHash":         "bmV3LWF1dGgtaGFzaA==",
		"protectedUserKey": "new-protected-user-key",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRotatingThePasswordSucceedsAndInvalidatesTheOldCredential(t *testing.T) {
	srv := newTestServer(t)
	user, authHash := enrollTestUser(t, srv, "person@example.com")
	_ = user

	login := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash, "deviceLabel": "test",
	})
	var loginBody struct {
		AccessToken string `json:"accessToken"`
	}
	decodeInto(t, login, &loginBody)

	rec := doJSON(t, srv, http.MethodPost, "/api/account/password", loginBody.AccessToken,
		map[string]string{
			"currentAuthHash":  authHash,
			"kdfSalt":          "bmV3LXNhbHQtMTZieXRlcw==",
			"params":           auth.DefaultKDFParamsJSON,
			"authHash":         "bmV3LWF1dGgtaGFzaA==",
			"protectedUserKey": "new-protected-user-key",
		})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// The old credential must stop working, or the change achieved nothing.
	old := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash, "deviceLabel": "test",
	})
	if old.Code != http.StatusUnauthorized {
		t.Errorf("the old password still logs in: %d", old.Code)
	}

	// And the new one must work.
	fresh := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": "bmV3LWF1dGgtaGFzaA==", "deviceLabel": "test",
	})
	if fresh.Code != http.StatusOK {
		t.Errorf("the new password does not log in: %d %s", fresh.Code, fresh.Body.String())
	}
}

func TestRotatingThePasswordRejectsNonDefaultParams(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	login := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash, "deviceLabel": "test",
	})
	var loginBody struct {
		AccessToken string `json:"accessToken"`
	}
	decodeInto(t, login, &loginBody)

	// This is the endpoint that would have created the first account whose
	// params differ from the decoy's, making that address enumerable through
	// prelogin.
	rec := doJSON(t, srv, http.MethodPost, "/api/account/password", loginBody.AccessToken,
		map[string]string{
			"currentAuthHash":  authHash,
			"kdfSalt":          "bmV3LXNhbHQtMTZieXRlcw==",
			"params":           `{"algorithm":"argon2id","memoryKiB":131072,"iterations":4,"parallelism":4}`,
			"authHash":         "bmV3LWF1dGgtaGFzaA==",
			"protectedUserKey": "new-protected-user-key",
		})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestPreloginStillCannotDistinguishARealAccountAfterARotation(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	login := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash, "deviceLabel": "test",
	})
	var loginBody struct {
		AccessToken string `json:"accessToken"`
	}
	decodeInto(t, login, &loginBody)

	if rec := doJSON(t, srv, http.MethodPost, "/api/account/password", loginBody.AccessToken,
		map[string]string{
			"currentAuthHash":  authHash,
			"kdfSalt":          "bmV3LXNhbHQtMTZieXRlcw==",
			"params":           auth.DefaultKDFParamsJSON,
			"authHash":         "bmV3LWF1dGgtaGFzaA==",
			"protectedUserKey": "new-protected-user-key",
		}); rec.Code != http.StatusNoContent {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}

	real := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "person@example.com"})
	decoy := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "ghost@example.com"})

	var realBody, decoyBody struct {
		KDFSalt string `json:"kdfSalt"`
		Params  string `json:"params"`
	}
	decodeInto(t, real, &realBody)
	decodeInto(t, decoy, &decoyBody)

	// This is the whole reason params are pinned. The salts differ, as they
	// must; the params must not, or the field itself answers "does this address
	// have an account here".
	if realBody.Params != decoyBody.Params {
		t.Errorf("params differ: real %q, decoy %q — this account is now enumerable",
			realBody.Params, decoyBody.Params)
	}
	if realBody.KDFSalt == decoyBody.KDFSalt {
		t.Error("real and decoy salts are identical; the decoy is not per-address")
	}
}

func TestRotatingTheRecoveryCodeLeavesLoginWorking(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	login := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash, "deviceLabel": "test",
	})
	var loginBody struct {
		AccessToken string `json:"accessToken"`
	}
	decodeInto(t, login, &loginBody)

	rec := doJSON(t, srv, http.MethodPost, "/api/account/recovery", loginBody.AccessToken,
		map[string]string{
			"currentAuthHash":          authHash,
			"recoverySalt":             "bmV3LXJlY292ZXJ5LXNhbHQ=",
			"recoveryKdfParams":        auth.DefaultKDFParamsJSON,
			"recoveryProtectedUserKey": "new-recovery-blob",
		})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// A user who regenerates a recovery code and can then no longer sign in has
	// lost both routes at once.
	again := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash, "deviceLabel": "test",
	})
	if again.Code != http.StatusOK {
		t.Errorf("login broke after a recovery rotation: %d", again.Code)
	}
}

func TestListingSessionsMarksTheCurrentOneAndHidesTokens(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")
	_, _ = loginTestUser(t, srv, "other@example.com")

	rec := doJSON(t, srv, http.MethodGet, "/api/account/sessions", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body struct {
		Sessions []struct {
			ID          string `json:"id"`
			DeviceLabel string `json:"deviceLabel"`
			Current     bool   `json:"current"`
		} `json:"sessions"`
	}
	decodeInto(t, rec, &body)
	if len(body.Sessions) != 1 {
		t.Fatalf("got %d sessions, want 1 — another user's sessions are listed", len(body.Sessions))
	}
	// A user asked to end a session they do not recognize has to be able to
	// tell which one they are using right now.
	if !body.Sessions[0].Current {
		t.Error("the session making the request is not marked current")
	}
	for _, field := range []string{"token", "tokenHash", "refresh"} {
		if strings.Contains(rec.Body.String(), field) {
			t.Errorf("session list carries %q", field)
		}
	}
}

func TestRevokingAnotherUsersSessionIsNotFound(t *testing.T) {
	srv := newTestServer(t)
	_, mineToken := loginTestUser(t, srv, "mine@example.com")
	_, theirsToken := loginTestUser(t, srv, "theirs@example.com")

	list := doJSON(t, srv, http.MethodGet, "/api/account/sessions", theirsToken, nil)
	var theirs struct {
		Sessions []struct {
			ID string `json:"id"`
		} `json:"sessions"`
	}
	decodeInto(t, list, &theirs)
	if len(theirs.Sessions) != 1 {
		t.Fatalf("setup: got %d sessions", len(theirs.Sessions))
	}

	rec := doJSON(t, srv, http.MethodDelete,
		"/api/account/sessions/"+theirs.Sessions[0].ID, mineToken, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	// And the victim is still signed in.
	still := doJSON(t, srv, http.MethodGet, "/api/account", theirsToken, nil)
	if still.Code != http.StatusOK {
		t.Errorf("another user revoked this session: %d", still.Code)
	}
}

func TestRevokingOwnSessionEndsIt(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	list := doJSON(t, srv, http.MethodGet, "/api/account/sessions", token, nil)
	var body struct {
		Sessions []struct {
			ID string `json:"id"`
		} `json:"sessions"`
	}
	decodeInto(t, list, &body)

	if rec := doJSON(t, srv, http.MethodDelete,
		"/api/account/sessions/"+body.Sessions[0].ID, token, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if rec := doJSON(t, srv, http.MethodGet, "/api/account", token, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("the revoked token still works: %d", rec.Code)
	}
}
```

- [ ] **Step 9: Implement the account handlers**

Create `internal/httpapi/account.go`:

```go
package httpapi

import (
	"net/http"
	"time"

	"github.com/ssan9876/keyhole/internal/auth"
	"github.com/ssan9876/keyhole/internal/store"
)

func (s *Server) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	// The wrapped keys are delivered by login, once, alongside the tokens.
	// Repeating them on a plain profile read widens the blast radius of any
	// endpoint that is ever accidentally cached, proxied, or logged. The public
	// key is here because the client renders the user's own fingerprint from
	// it (spec section 3.9).
	WriteJSON(w, http.StatusOK, map[string]any{
		"id":        user.ID,
		"email":     user.Email,
		"name":      user.Name,
		"role":      user.Role,
		"publicKey": user.PublicKey.String,
		"createdAt": user.CreatedAt.Format(time.RFC3339),
	})
}

// verifyCurrentCredential re-checks the master password before a change that
// could destroy key material.
//
// The session already proves who the caller is. What it does not prove is that
// they hold the master password — and both endpoints below overwrite key
// material, so a stolen access token would otherwise be enough to write
// garbage over a wrapped key and destroy the vault. The attacker cannot
// produce a *valid* replacement, which is exactly why they would produce an
// invalid one.
func (s *Server) verifyCurrentCredential(w http.ResponseWriter, user store.User, currentAuthHash string) bool {
	if currentAuthHash == "" || !user.AuthHash.Valid {
		WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "master password is incorrect")
		return false
	}
	if !auth.VerifyAuthHash(currentAuthHash, user.AuthHash.String) {
		WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "master password is incorrect")
		return false
	}
	return true
}

type rotatePasswordRequest struct {
	CurrentAuthHash  string `json:"currentAuthHash"`
	KDFSalt          string `json:"kdfSalt"`
	Params           string `json:"params"`
	AuthHash         string `json:"authHash"`
	ProtectedUserKey string `json:"protectedUserKey"`
}

func (s *Server) handleRotatePassword(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())
	session, _ := sessionFrom(r.Context())

	var req rotatePasswordRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.AuthHash == "" {
		// Hashing an empty string costs exactly as much as hashing a real one,
		// so this is checked before the hash rather than after.
		WriteError(w, http.StatusBadRequest, CodeBadRequest, "authHash is required")
		return
	}
	// Pinned so the prelogin decoy stays indistinguishable from a real account.
	// See the note at the head of this task.
	if req.Params != auth.DefaultKDFParamsJSON {
		WriteError(w, http.StatusBadRequest, CodeBadRequest,
			"params must match the server's current KDF parameters exactly")
		return
	}
	if !s.verifyCurrentCredential(w, user, req.CurrentAuthHash) {
		return
	}

	stored, err := auth.HashAuthHash(req.AuthHash)
	if err != nil {
		s.logger.Error("hash auth hash", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not change the master password")
		return
	}

	if err := s.store.RotatePassword(r.Context(), user.ID, store.PasswordRotation{
		KDFSalt:          req.KDFSalt,
		KDFParams:        req.Params,
		AuthHash:         stored,
		ProtectedUserKey: req.ProtectedUserKey,
	}, session.ID); err != nil {
		s.writeStoreError(w, r, "rotate password", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type rotateRecoveryRequest struct {
	CurrentAuthHash          string `json:"currentAuthHash"`
	RecoverySalt             string `json:"recoverySalt"`
	RecoveryKDFParams        string `json:"recoveryKdfParams"`
	RecoveryProtectedUserKey string `json:"recoveryProtectedUserKey"`
}

func (s *Server) handleRotateRecovery(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	var req rotateRecoveryRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if !s.verifyCurrentCredential(w, user, req.CurrentAuthHash) {
		return
	}

	// recoveryKdfParams is NOT pinned: no endpoint ever returns it, so it
	// cannot be compared against anything and leaks nothing. Recording the
	// parameters the blob was actually made with is what keeps a correct
	// recovery code from failing later (spec section 4.2).
	if err := s.store.RotateRecovery(r.Context(), user.ID, store.RecoveryRotation{
		RecoverySalt:             req.RecoverySalt,
		RecoveryKDFParams:        req.RecoveryKDFParams,
		RecoveryProtectedUserKey: req.RecoveryProtectedUserKey,
	}); err != nil {
		s.writeStoreError(w, r, "rotate recovery", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())
	current, _ := sessionFrom(r.Context())

	sessions, err := s.store.SessionsForUser(r.Context(), user.ID)
	if err != nil {
		s.writeStoreError(w, r, "list sessions", err)
		return
	}

	type sessionJSON struct {
		ID          string `json:"id"`
		DeviceLabel string `json:"deviceLabel"`
		CreatedAt   string `json:"createdAt"`
		LastSeenAt  string `json:"lastSeenAt"`
		Current     bool   `json:"current"`
	}

	out := make([]sessionJSON, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, sessionJSON{
			ID:          session.ID,
			DeviceLabel: session.DeviceLabel,
			CreatedAt:   session.CreatedAt.Format(time.RFC3339),
			LastSeenAt:  session.LastSeenAt.Format(time.RFC3339),
			// A user asked to end a session they do not recognize has to be
			// able to tell which one they are sitting in front of.
			Current: session.ID == current.ID,
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	if err := s.store.RevokeSessionForUser(r.Context(), r.PathValue("id"), user.ID); err != nil {
		s.writeStoreError(w, r, "revoke session", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
```

Register in `routes()`:

```go
	s.mux.HandleFunc("GET /api/account", s.requireAuth(s.handleGetAccount))
	s.mux.HandleFunc("POST /api/account/password", s.requireAuth(s.handleRotatePassword))
	s.mux.HandleFunc("POST /api/account/recovery", s.requireAuth(s.handleRotateRecovery))
	s.mux.HandleFunc("GET /api/account/sessions", s.requireAuth(s.handleListSessions))
	s.mux.HandleFunc("DELETE /api/account/sessions/{id}", s.requireAuth(s.handleRevokeSession))
```

- [ ] **Step 10: Run the account endpoint tests**

```bash
go test ./internal/httpapi/ -run "Account|Rotat|Session|Prelogin" -v
```

Expected: PASS.

- [ ] **Step 11: Prove the pinning actually prevents enumeration**

Temporarily remove the params check from `handleRotatePassword`:

```go
	// if req.Params != auth.DefaultKDFParamsJSON { ... }
```

and from `EnrollmentInput.validate()`. Then run:

```bash
go test ./internal/httpapi/ -run TestPreloginStillCannotDistinguish -v
```

Change the params in that test's rotation call to
`{"algorithm":"argon2id","memoryKiB":131072,"iterations":4,"parallelism":4}`
first. Expected: FAIL — real and decoy params differ, which is the enumeration
oracle in one line of output. Revert both the check and the test, and confirm
PASS. Record both outputs: this is the finding the Plan 2a review carried
forward, and this is the proof it is closed.

- [ ] **Step 12: Full suite, vet, gofmt, race**

```bash
go test ./... && gofmt -l ./internal ./cmd && go vet ./...
```

Expected: PASS, both silent.

```bash
go test -race ./...
```

Expected: PASS.

- [ ] **Step 13: Commit**

```bash
git add internal/ && git commit -m "feat(api): account self-service, and pin KDF params to the server default"
```

---

## Task 7: Administration — users, invites, destructive reset, audit

**Files:**
- Create: `internal/store/admin.go`
- Create: `internal/httpapi/admin.go`
- Test: `internal/store/admin_test.go`, `internal/httpapi/admin_test.go`
- Modify: `internal/store/ids.go` (add `ErrUserReferenced`, `ErrLastAdmin`)
- Modify: `internal/store/invites.go` (add the shared `InviteTTL`)
- Modify: `cmd/keyhole/admin.go` (use `store.InviteTTL`)
- Modify: `internal/httpapi/server.go` (register the routes)

**Interfaces:**
- Consumes: `requireAdmin` (Task 5), `writeStoreError` (Task 3), `store.User`,
  `store.CreatePendingUser`, `store.CreateInvite`, `store.AuditPage`.
- Produces:
  ```go
  const InviteTTL = 72 * time.Hour // in package store

  var ErrUserReferenced = errors.New("user is referenced by other records")
  var ErrLastAdmin = errors.New("this is the last administrator")

  type UserSummary struct {
      User
      HasPendingInvite bool
  }

  func (s *Store) ListUsers(ctx context.Context) ([]UserSummary, error)
  func (s *Store) SetUserStatus(ctx context.Context, userID, status, actorID string) error
  func (s *Store) ResetUser(ctx context.Context, userID, actorID string) (string, error)
  func (s *Store) DeleteUser(ctx context.Context, userID, actorID string) error
  ```
  `ResetUser` returns the raw invite token for the fresh setup link.

**Routes registered:**

```
GET    /api/admin/users
POST   /api/admin/users
POST   /api/admin/users/{id}/invite     reissue a setup link
PATCH  /api/admin/users/{id}            enable / disable
POST   /api/admin/users/{id}/reset      destructive
DELETE /api/admin/users/{id}
GET    /api/admin/audit
GET    /api/admin/collections
```

All behind `requireAdmin`.

**Two items carried forward from Plan 2a's review are closed here:**

1. `keyhole admin create` had no reissue path — a transient failure between
   `CreatePendingUser` and `CreateInvite` left a pending user with no invite and
   no recovery except direct SQL. `POST /api/admin/users/{id}/invite` is that
   path.
2. `collections.created_by`, `collection_memberships.granted_by`, and
   `pending_grants.requested_by` reference `users(id)` with no `ON DELETE`
   action, so deleting a user who ever created a collection hits a raw foreign
   key violation. That default is right — an admin delete must not cascade into
   destroying a shared collection's key material — so `DeleteUser` classifies
   the violation into `ErrUserReferenced` and the handler answers 409 with an
   actionable message.

- [ ] **Step 1: Add the errors and the shared TTL**

In `internal/store/ids.go`:

```go
// ErrUserReferenced means the account cannot be deleted because other records
// point at it — a collection it created, or a membership it granted. Those
// references have no ON DELETE action on purpose: deleting an admin must not
// cascade into destroying a shared collection's key material, which nobody
// could reconstruct.
var ErrUserReferenced = errors.New("user is referenced by other records")

// ErrLastAdmin means the action would leave the installation with no
// administrator, and therefore no way to create one.
var ErrLastAdmin = errors.New("this is the last administrator")
```

In `internal/store/invites.go`, above `CreateInvite`:

```go
// InviteTTL is how long a setup or invite link stays valid. Long enough to
// hand over out of band and act on unhurriedly, short enough that a link found
// later in a chat history is dead.
//
// One definition, used by both the CLI and the admin API. Two would drift, and
// the drift would show up as links that expire sooner than the message telling
// the user how long they have.
const InviteTTL = 72 * time.Hour
```

In `cmd/keyhole/admin.go`, delete the local `inviteTTL` constant and use
`store.InviteTTL` at both its call sites (the `CreateInvite` call and the
printed message).

- [ ] **Step 2: Write the failing admin store tests**

Create `internal/store/admin_test.go`:

```go
package store

import (
	"context"
	"errors"
	"testing"
)

// adminUser creates an active admin account.
func adminUser(t *testing.T, st *Store, email string) string {
	t.Helper()
	ctx := context.Background()
	user, err := st.CreatePendingUser(ctx, email, "Admin Person", "admin")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE users SET status = 'active', public_key = 'pk', auth_hash = 'h' WHERE id = ?`,
		user.ID); err != nil {
		t.Fatalf("activate admin: %v", err)
	}
	return user.ID
}

func TestListUsersFlagsPendingInvites(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	admin := adminUser(t, st, "admin@example.com")

	invited, err := st.CreatePendingUser(ctx, "invited@example.com", "Invited", "user")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	if _, _, err := st.CreateInvite(ctx, invited.ID, InviteTTL); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	stranded, err := st.CreatePendingUser(ctx, "stranded@example.com", "Stranded", "user")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}

	users, err := st.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	byID := map[string]UserSummary{}
	for _, user := range users {
		byID[user.ID] = user
	}
	if len(users) != 3 {
		t.Fatalf("got %d users, want 3", len(users))
	}
	if !byID[invited.ID].HasPendingInvite {
		t.Error("an invited account is not flagged as having a live invite")
	}
	// This is the visible symptom of the failure mode the reissue path exists
	// for: a pending account with no usable link and nothing in the UI saying so.
	if byID[stranded.ID].HasPendingInvite {
		t.Error("an account with no invite is flagged as having one")
	}
	_ = admin
}

func TestSetUserStatusRefusesToDisableTheLastAdmin(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	admin := adminUser(t, st, "admin@example.com")

	// With no admin left, nobody can create one: there is no registration
	// endpoint and the CLI needs shell access to the container.
	if err := st.SetUserStatus(ctx, admin, "disabled", admin); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("err = %v, want ErrLastAdmin", err)
	}

	user, err := st.UserByID(ctx, admin)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if user.Status != "active" {
		t.Errorf("Status = %q, want the account left active", user.Status)
	}
}

func TestSetUserStatusDisablesWhenAnotherAdminRemains(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	first := adminUser(t, st, "first@example.com")
	second := adminUser(t, st, "second@example.com")

	if err := st.SetUserStatus(ctx, second, "disabled", first); err != nil {
		t.Fatalf("SetUserStatus: %v", err)
	}
	user, err := st.UserByID(ctx, second)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if user.Status != "disabled" {
		t.Errorf("Status = %q, want disabled", user.Status)
	}
}

func TestSetUserStatusRejectsAnUnknownStatus(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	admin := adminUser(t, st, "admin@example.com")
	target := enrolledUserID(t, st, "person@example.com")

	// The column has a CHECK, but a raw constraint failure would reach the
	// client as a 500 for what is plainly a bad request.
	err := st.SetUserStatus(ctx, target, "banished", admin)
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("err = %v, want a *ValidationError", err)
	}
}

func TestDisablingAUserRevokesTheirSessions(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	admin := adminUser(t, st, "admin@example.com")
	target := enrolledUserID(t, st, "person@example.com")

	_, token, _, err := st.CreateSession(ctx, target, "their laptop")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := st.SetUserStatus(ctx, target, "disabled", admin); err != nil {
		t.Fatalf("SetUserStatus: %v", err)
	}

	// requireAuth already re-checks status on every request, so this is belt
	// and braces — but "disable this account" that leaves live session rows
	// behind is a claim the sessions list would contradict to the user's face.
	if _, err := st.SessionByAccessToken(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Errorf("a disabled account still has a live session: %v", err)
	}
}

func TestResetUserDestroysKeyMaterialAndReturnsAFreshInvite(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	admin := adminUser(t, st, "admin@example.com")
	target := enrolledUserID(t, st, "person@example.com")

	// Give the account something to lose.
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE users SET status = 'active', auth_hash = 'h', protected_user_key = 'puk',
		 recovery_protected_user_key = 'rpuk', public_key = 'pk', encrypted_private_key = 'epk'
		 WHERE id = ?`, target); err != nil {
		t.Fatalf("seed key material: %v", err)
	}
	if _, err := st.CreateItem(ctx, target, ItemInput{Ciphertext: "c", WrappedItemKey: "k"}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	collection, err := st.CreateCollection(ctx, "Household", admin, "sealed")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if err := st.FulfilGrantOrAdd(ctx, collection.ID, target, "sealed-to-target", "member", admin); err != nil {
		t.Fatalf("add member: %v", err)
	}

	token, err := st.ResetUser(ctx, target, admin)
	if err != nil {
		t.Fatalf("ResetUser: %v", err)
	}
	if token == "" {
		t.Fatal("ResetUser returned no invite token; the user cannot get back in")
	}

	user, err := st.UserByID(ctx, target)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if user.Status != "pending" {
		t.Errorf("Status = %q, want pending", user.Status)
	}
	// Spec section 3.7. Any of these surviving would leave a vault the new
	// master password cannot open but the old key material still could.
	for name, value := range map[string]string{
		"auth_hash":                   user.AuthHash.String,
		"protected_user_key":          user.ProtectedUserKey.String,
		"recovery_protected_user_key": user.RecoveryProtectedUserKey.String,
		"public_key":                  user.PublicKey.String,
		"encrypted_private_key":       user.EncryptedPrivateKey.String,
	} {
		if value != "" {
			t.Errorf("%s survived the reset: %q", name, value)
		}
	}

	// The personal items are gone, not tombstoned: nothing can ever decrypt
	// them again, so a tombstone would describe an item that no longer exists
	// in any meaningful sense.
	var items int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM items WHERE owner_user_id = ?`, target).Scan(&items); err != nil {
		t.Fatalf("count items: %v", err)
	}
	if items != 0 {
		t.Errorf("%d personal items survived the reset", items)
	}

	// The new keypair will be different, so every collection has to re-grant.
	// Leaving the membership row would leave a sealed key only the destroyed
	// private key could open.
	if _, err := st.MembershipFor(ctx, collection.ID, target); !errors.Is(err, ErrNotFound) {
		t.Errorf("collection membership survived the reset: %v", err)
	}

	// And the returned token actually works.
	if _, err := st.InviteByToken(ctx, token); err != nil {
		t.Errorf("the reset invite is not usable: %v", err)
	}
}

func TestResetUserKeepsCollectionItemsOthersStillNeed(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	admin := adminUser(t, st, "admin@example.com")
	target := enrolledUserID(t, st, "person@example.com")

	collection, err := st.CreateCollection(ctx, "Household", admin, "sealed")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if err := st.FulfilGrantOrAdd(ctx, collection.ID, target, "sealed-to-target", "member", admin); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if _, err := st.CreateItem(ctx, target, ItemInput{
		CollectionID: collection.ID, Ciphertext: "shared", WrappedItemKey: "k",
	}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	if _, err := st.ResetUser(ctx, target, admin); err != nil {
		t.Fatalf("ResetUser: %v", err)
	}

	// A collection item is wrapped by the collection key, which every other
	// member still holds. Deleting it because its creator was reset would
	// destroy shared data belonging to people the reset had nothing to do with.
	var items int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM items WHERE collection_id = ? AND deleted_at IS NULL`,
		collection.ID).Scan(&items); err != nil {
		t.Fatalf("count items: %v", err)
	}
	if items != 1 {
		t.Errorf("%d collection items survive the reset, want 1", items)
	}
}

func TestDeleteUserReportsAReferenceRatherThanFailing(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	admin := adminUser(t, st, "admin@example.com")
	creator := adminUser(t, st, "creator@example.com")

	if _, err := st.CreateCollection(ctx, "Household", creator, "sealed"); err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}

	// collections.created_by has no ON DELETE action, deliberately: a delete
	// must not cascade into destroying a shared collection. So this has to be a
	// named error the handler can turn into an actionable 409, not a raw
	// constraint failure that reads as a server fault.
	err := st.DeleteUser(ctx, creator, admin)
	if !errors.Is(err, ErrUserReferenced) {
		t.Fatalf("err = %v, want ErrUserReferenced", err)
	}

	if _, err := st.UserByID(ctx, creator); err != nil {
		t.Errorf("the user was partly deleted anyway: %v", err)
	}
}

func TestDeleteUserRemovesAnUnreferencedAccountAndItsItems(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	admin := adminUser(t, st, "admin@example.com")
	target := enrolledUserID(t, st, "person@example.com")

	if _, err := st.CreateItem(ctx, target, ItemInput{Ciphertext: "c", WrappedItemKey: "k"}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	if _, _, _, err := st.CreateSession(ctx, target, "laptop"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if err := st.DeleteUser(ctx, target, admin); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := st.UserByID(ctx, target); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	for _, table := range []string{"items", "sessions"} {
		var count int
		if err := st.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM `+table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Errorf("%s still has %d rows; the ON DELETE CASCADE did not fire", table, count)
		}
	}
}

func TestDeleteUserRefusesTheLastAdmin(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	admin := adminUser(t, st, "admin@example.com")

	if err := st.DeleteUser(ctx, admin, admin); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("err = %v, want ErrLastAdmin", err)
	}
}
```

- [ ] **Step 3: Run and watch it fail**

```bash
go test ./internal/store/ -run "ListUsers|SetUserStatus|Disabling|ResetUser|DeleteUser" -v
```

Expected: FAIL — `st.ListUsers undefined`.

- [ ] **Step 4: Implement the admin store**

Create `internal/store/admin.go`:

```go
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlited "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// UserSummary is a user plus the one derived fact the admin list needs. An
// account that is pending with no live invite is stranded — nobody can set it
// up — and the list is where that has to be visible.
type UserSummary struct {
	User
	HasPendingInvite bool
}

func (s *Store) ListUsers(ctx context.Context) ([]UserSummary, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+userColumns+`,
		    EXISTS (
		        SELECT 1 FROM invites
		        WHERE invites.user_id = users.id
		          AND invites.used_at IS NULL
		          AND invites.expires_at > ?
		    ) AS has_pending_invite
		 FROM users
		 ORDER BY name`, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("select users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	users := []UserSummary{}
	for rows.Next() {
		var summary UserSummary
		var createdAt, updatedAt string
		if err := rows.Scan(
			&summary.ID, &summary.Email, &summary.Name, &summary.Role, &summary.Status,
			&summary.KDFSalt, &summary.KDFParams, &summary.AuthHash, &summary.ProtectedUserKey,
			&summary.RecoveryProtectedUserKey, &summary.RecoverySalt, &summary.RecoveryKDFParams,
			&summary.PublicKey, &summary.EncryptedPrivateKey,
			&summary.Revision, &createdAt, &updatedAt,
			&summary.HasPendingInvite,
		); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		if summary.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
		if summary.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt); err != nil {
			return nil, fmt.Errorf("parse updated_at: %w", err)
		}
		users = append(users, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	return users, nil
}

// SetUserStatus enables or disables an account.
func (s *Store) SetUserStatus(ctx context.Context, userID, status, actorID string) error {
	if status != "active" && status != "disabled" {
		return &ValidationError{Field: "status", Message: "must be active or disabled"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin status change: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if status == "disabled" {
		var remaining int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM users
			 WHERE role = 'admin' AND status = 'active' AND id != ?`, userID).Scan(&remaining); err != nil {
			return fmt.Errorf("count admins: %w", err)
		}
		var role string
		if err := tx.QueryRowContext(ctx,
			`SELECT role FROM users WHERE id = ?`, userID).Scan(&role); err != nil {
			return fmt.Errorf("read role: %w", err)
		}
		if role == "admin" && remaining == 0 {
			return ErrLastAdmin
		}
	}

	result, err := tx.ExecContext(ctx,
		`UPDATE users SET status = ?, revision = revision + 1, updated_at = ? WHERE id = ?`,
		status, time.Now().UTC().Format(time.RFC3339), userID)
	if err != nil {
		return fmt.Errorf("set status: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}

	if status == "disabled" {
		// requireAuth re-checks status on every request, so this is belt and
		// braces — but "disable this account" that leaves live session rows
		// behind is a claim the sessions list would contradict.
		if _, err := tx.ExecContext(ctx,
			`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
			time.Now().UTC().Format(time.RFC3339), userID); err != nil {
			return fmt.Errorf("revoke sessions: %w", err)
		}
	}

	if err := appendAudit(ctx, tx, actorID, "user.status", "user:"+userID,
		fmt.Sprintf(`{"status":%q}`, status)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit status change: %w", err)
	}
	return nil
}

// ResetUser is the destructive last resort from spec section 3.7.
//
// It destroys every piece of key material, deletes the personal items nothing
// can ever decrypt again, revokes collection memberships (the new keypair will
// be different, so every sealed key becomes junk), revokes sessions, returns
// the account to pending, and mints a fresh invite. It returns the raw token
// for that invite, once.
//
// Collection ITEMS are deliberately kept: they are wrapped by the collection
// key, which every other member still holds. Deleting them because their
// creator was reset would destroy shared data belonging to people the reset
// had nothing to do with.
func (s *Store) ResetUser(ctx context.Context, userID, actorID string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin reset: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339)

	result, err := tx.ExecContext(ctx,
		`UPDATE users SET status = 'pending',
			kdf_salt = NULL, kdf_params = NULL, auth_hash = NULL,
			protected_user_key = NULL, recovery_protected_user_key = NULL,
			recovery_salt = NULL, recovery_kdf_params = NULL,
			public_key = NULL, encrypted_private_key = NULL,
			revision = revision + 1, updated_at = ?
		 WHERE id = ?`, stamp, userID)
	if err != nil {
		return "", fmt.Errorf("reset user: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return "", ErrNotFound
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM items WHERE owner_user_id = ? AND collection_id IS NULL`, userID); err != nil {
		return "", fmt.Errorf("delete personal items: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM folders WHERE user_id = ?`, userID); err != nil {
		return "", fmt.Errorf("delete folders: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM collection_memberships WHERE user_id = ?`, userID); err != nil {
		return "", fmt.Errorf("delete memberships: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM pending_grants WHERE user_id = ?`, userID); err != nil {
		return "", fmt.Errorf("delete pending grants: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		stamp, userID); err != nil {
		return "", fmt.Errorf("revoke sessions: %w", err)
	}

	token, err := createInviteTx(ctx, tx, userID, InviteTTL)
	if err != nil {
		return "", err
	}
	if err := appendAudit(ctx, tx, actorID, "user.reset", "user:"+userID, ""); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit reset: %w", err)
	}
	return token, nil
}

// DeleteUser removes an account outright.
//
// The FK violation is not a bug to be prevented — collections.created_by and
// the two granted_by/requested_by columns have no ON DELETE action on purpose,
// so that deleting an admin cannot cascade into destroying a shared
// collection's key material. What matters is that the operator is told which
// problem they have, in terms they can act on, rather than shown a 500.
func (s *Store) DeleteUser(ctx context.Context, userID, actorID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete user: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var role string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id = ?`, userID).Scan(&role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("read role: %w", err)
	}
	if role == "admin" {
		var remaining int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM users
			 WHERE role = 'admin' AND status = 'active' AND id != ?`, userID).Scan(&remaining); err != nil {
			return fmt.Errorf("count admins: %w", err)
		}
		if remaining == 0 {
			return ErrLastAdmin
		}
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID); err != nil {
		var sqliteErr *sqlited.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY {
			return ErrUserReferenced
		}
		return fmt.Errorf("delete user: %w", err)
	}
	if err := appendAudit(ctx, tx, actorID, "user.delete", "user:"+userID, ""); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete user: %w", err)
	}
	return nil
}
```

`ResetUser` calls `createInviteTx`, which does not exist yet. Refactor
`internal/store/invites.go` so the invite and the reset commit together — a
reset that wiped the account and then failed to mint a link would leave the
user with no way in and no way to ask for one. Extract `CreateInvite`'s body
to take an `execer` (the interface Task 4 added in `audit.go`, satisfied by
both `*sql.DB` and `*sql.Tx`):

```go
// createInviteTx is CreateInvite's body, parameterized over the executor so a
// caller already inside a transaction can mint an invite that commits with the
// rest of its work.
func createInviteTx(ctx context.Context, db execer, userID string, ttl time.Duration) (string, error) {
	raw := make([]byte, inviteTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate invite token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	id, err := NewID()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()

	if _, err := db.ExecContext(ctx,
		`INSERT INTO invites (id, user_id, token_hash, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id, userID, HashToken(token),
		now.Format(time.RFC3339), now.Add(ttl).Format(time.RFC3339)); err != nil {
		return "", fmt.Errorf("insert invite: %w", err)
	}
	return token, nil
}
```

`CreateInvite` keeps its existing signature and becomes a thin caller. It still
has to return the `Invite` struct, so it re-reads nothing — it reconstructs the
same values it just wrote:

```go
func (s *Store) CreateInvite(ctx context.Context, userID string, ttl time.Duration) (Invite, string, error) {
	now := time.Now().UTC()
	token, err := createInviteTx(ctx, s.db, userID, ttl)
	if err != nil {
		return Invite{}, "", err
	}
	var id string
	if err := s.db.QueryRowContext(ctx,
		`SELECT id FROM invites WHERE token_hash = ?`, HashToken(token)).Scan(&id); err != nil {
		return Invite{}, "", fmt.Errorf("read new invite: %w", err)
	}
	return Invite{ID: id, UserID: userID, CreatedAt: now, ExpiresAt: now.Add(ttl)}, token, nil
}
```

- [ ] **Step 4b: Verify the foreign-key result code empirically**

`DeleteUser` branches on `SQLITE_CONSTRAINT_FOREIGNKEY`. Plan 2a established
that guessing modernc's extended result codes is not good enough — the
`classifyUserInsertError` fix was built on codes observed by running the
driver, not read from documentation. Do the same here.

Write a scratch program under the repo (delete it afterwards) that opens a
migrated temp database, creates a user, has them create a collection, then
deletes the user and prints the concrete error type and `Code()`:

```go
_, err := db.Exec(`DELETE FROM users WHERE id = ?`, creatorID)
var sqliteErr *sqlited.Error
fmt.Printf("errors.As=%v code=%d err=%v\n", errors.As(err, &sqliteErr), sqliteErr.Code(), err)
```

Expected: `code=787` (`SQLITE_CONSTRAINT_FOREIGNKEY`). **Record the observed
number in the report.** If it differs, use what the driver actually reports and
say so — the constant name is what matters, not the value this plan predicts.
Note also that the pragma must be on for this to fire at all; `store.Open` sets
`foreign_keys(1)` in the DSN, so a scratch program that opens the file directly
with `sql.Open("sqlite", path)` will *not* reproduce it.

- [ ] **Step 5: Run the admin store tests**

```bash
go test ./internal/store/ -run "ListUsers|SetUserStatus|Disabling|ResetUser|DeleteUser" -v
```

Expected: PASS, all ten.

- [ ] **Step 6: Write the failing admin endpoint tests**

Create `internal/httpapi/admin_test.go`:

```go
package httpapi

import (
	"net/http"
	"strings"
	"testing"
)

func TestAdminRoutesRejectANonAdmin(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	for _, route := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/admin/users"},
		{http.MethodPost, "/api/admin/users"},
		{http.MethodGet, "/api/admin/audit"},
		{http.MethodGet, "/api/admin/collections"},
	} {
		rec := doJSON(t, srv, route.method, route.path, token, map[string]string{})
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d, want %d", route.method, route.path, rec.Code, http.StatusForbidden)
		}
	}
}

func TestAdminUserListNeverCarriesKeyMaterial(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	loginTestUser(t, srv, "person@example.com")

	rec := doJSON(t, srv, http.MethodGet, "/api/admin/users", adminToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// Spec section 10 names this test explicitly: no admin endpoint may return
	// another user's wrapped keys. An admin having ordinary vault access to
	// everyone would make the entire cryptographic design decorative.
	body := rec.Body.String()
	for _, field := range []string{
		"protectedUserKey", "protected_user_key",
		"encryptedPrivateKey", "encrypted_private_key",
		"recoveryProtectedUserKey", "recovery_protected_user_key",
		"authHash", "auth_hash", "kdfSalt", "kdf_salt",
		"recoverySalt", "recovery_salt", "recoveryKdfParams", "recovery_kdf_params",
	} {
		if strings.Contains(body, field) {
			t.Errorf("/api/admin/users carries %q: %s", field, body)
		}
	}
}

func TestCreateUserReturnsAOneTimeSetupLink(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")

	rec := doJSON(t, srv, http.MethodPost, "/api/admin/users", adminToken, map[string]string{
		"email": "new@example.com", "name": "New Person", "role": "user",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var body struct {
		User struct {
			ID     string `json:"id"`
			Email  string `json:"email"`
			Status string `json:"status"`
		} `json:"user"`
		InviteURL string `json:"inviteUrl"`
	}
	decodeInto(t, rec, &body)
	if body.User.Status != "pending" {
		t.Errorf("status = %q, want pending", body.User.Status)
	}
	// No mail server exists (spec section 1). The link has to come back in this
	// response or the admin has nothing to hand over.
	if !strings.HasPrefix(body.InviteURL, srv.cfg.BaseURL+"/enroll/") {
		t.Errorf("inviteUrl = %q, want it under %s/enroll/", body.InviteURL, srv.cfg.BaseURL)
	}
}

func TestCreateUserRejectsADuplicateEmail(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	loginTestUser(t, srv, "taken@example.com")

	rec := doJSON(t, srv, http.MethodPost, "/api/admin/users", adminToken, map[string]string{
		"email": "TAKEN@example.com", "name": "Impostor", "role": "user",
	})
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
}

func TestReissuingAnInviteGivesAWorkingLink(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/admin/users", adminToken, map[string]string{
		"email": "new@example.com", "name": "New Person", "role": "user",
	})
	var body struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	decodeInto(t, created, &body)

	// Plan 2a left a pending user with no invite unrecoverable except by direct
	// SQL, because admin create had no rollback between the two writes. This is
	// the path out of that.
	rec := doJSON(t, srv, http.MethodPost, "/api/admin/users/"+body.User.ID+"/invite", adminToken, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var reissued struct {
		InviteURL string `json:"inviteUrl"`
	}
	decodeInto(t, rec, &reissued)

	token := reissued.InviteURL[strings.LastIndex(reissued.InviteURL, "/")+1:]
	enroll := postJSON(t, srv, "/api/enroll/"+token, enrollBody())
	if enroll.Code != http.StatusOK {
		t.Errorf("the reissued link does not work: %d %s", enroll.Code, enroll.Body.String())
	}
}

func TestDisablingAnAccountEndsItsAccess(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	target, targetToken := loginTestUser(t, srv, "person@example.com")

	rec := doJSON(t, srv, http.MethodPatch, "/api/admin/users/"+target.ID, adminToken,
		map[string]string{"status": "disabled"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if after := doJSON(t, srv, http.MethodGet, "/api/sync", targetToken, nil); after.Code != http.StatusUnauthorized {
		t.Errorf("a disabled account still reads the vault: %d", after.Code)
	}
}

func TestResettingAnAccountRequiresTheEmailTyped(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	target, _ := loginTestUser(t, srv, "person@example.com")

	// Spec section 3.7: the dialog requires typing the user's email. The server
	// enforces it too, because a destructive irreversible action must not hinge
	// on a client-side check alone.
	wrong := doJSON(t, srv, http.MethodPost, "/api/admin/users/"+target.ID+"/reset", adminToken,
		map[string]string{"confirmEmail": "someone-else@example.com"})
	if wrong.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", wrong.Code, http.StatusBadRequest)
	}

	right := doJSON(t, srv, http.MethodPost, "/api/admin/users/"+target.ID+"/reset", adminToken,
		map[string]string{"confirmEmail": "person@example.com"})
	if right.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", right.Code, http.StatusOK, right.Body.String())
	}
	var body struct {
		InviteURL string `json:"inviteUrl"`
	}
	decodeInto(t, right, &body)
	if body.InviteURL == "" {
		t.Error("a reset returned no setup link; the user has no way back in")
	}
}

func TestDeletingAReferencedUserExplainsWhyItCannot(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	creator, creatorToken := loginAdmin(t, srv, "creator@example.com")
	createCollection(t, srv, creatorToken, "Household")

	rec := doJSON(t, srv, http.MethodDelete, "/api/admin/users/"+creator.ID, adminToken, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	decodeInto(t, rec, &body)
	if body.Error.Code != "conflict" {
		t.Errorf("code = %q, want %q", body.Error.Code, "conflict")
	}
	// A bare "conflict" leaves the operator with a database error and no next
	// step. The message has to name the obstacle.
	if !strings.Contains(strings.ToLower(body.Error.Message), "collection") {
		t.Errorf("message = %q; it should say what references the account", body.Error.Message)
	}
}

func TestTheAuditLogRecordsAdministrativeActions(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")

	if rec := doJSON(t, srv, http.MethodPost, "/api/admin/users", adminToken, map[string]string{
		"email": "new@example.com", "name": "New Person", "role": "user",
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create user: %d %s", rec.Code, rec.Body.String())
	}

	rec := doJSON(t, srv, http.MethodGet, "/api/admin/audit", adminToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Entries []struct {
			Action string `json:"action"`
			Target string `json:"target"`
		} `json:"entries"`
	}
	decodeInto(t, rec, &body)

	found := false
	for _, entry := range body.Entries {
		if entry.Action == "user.create" {
			found = true
		}
	}
	if !found {
		t.Errorf("no user.create entry in %d audit entries", len(body.Entries))
	}
}

func TestAnAdminCannotDisableTheirOwnLastAdminAccount(t *testing.T) {
	srv := newTestServer(t)
	admin, adminToken := loginAdmin(t, srv, "admin@example.com")

	// Locking the only administrator out is unrecoverable from the API: there
	// is no registration endpoint and creating one needs shell access.
	rec := doJSON(t, srv, http.MethodPatch, "/api/admin/users/"+admin.ID, adminToken,
		map[string]string{"status": "disabled"})
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
}
```

- [ ] **Step 7: Implement the admin handlers**

Create `internal/httpapi/admin.go`:

```go
package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ssan9876/keyhole/internal/store"
)

// adminUserJSON is the admin's view of an account. Every key-material column
// is absent by construction rather than by filtering: this struct simply has
// no field for them, so a future column cannot leak by being added to User.
//
// Spec section 10 names this as a security test — an admin holds no ability to
// read another user's vault, and that is enforced cryptographically. Returning
// wrapped blobs here would not break the crypto, but it would hand an attacker
// who compromised one admin session every user's material to grind offline.
type adminUserJSON struct {
	ID               string `json:"id"`
	Email            string `json:"email"`
	Name             string `json:"name"`
	Role             string `json:"role"`
	Status           string `json:"status"`
	HasPendingInvite bool   `json:"hasPendingInvite"`
	CreatedAt        string `json:"createdAt"`
}

func toAdminUserJSON(user store.UserSummary) adminUserJSON {
	return adminUserJSON{
		ID:               user.ID,
		Email:            user.Email,
		Name:             user.Name,
		Role:             user.Role,
		Status:           user.Status,
		HasPendingInvite: user.HasPendingInvite,
		CreatedAt:        user.CreatedAt.Format(time.RFC3339),
	}
}

func (s *Server) inviteURL(token string) string {
	return s.cfg.BaseURL + "/enroll/" + token
}

func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.writeStoreError(w, r, "list users", err)
		return
	}
	out := make([]adminUserJSON, 0, len(users))
	for _, user := range users {
		out = append(out, toAdminUserJSON(user))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"users": out})
}

type createUserRequest struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserFrom(r.Context())

	var req createUserRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Role == "" {
		req.Role = "user"
	}

	user, err := s.store.CreatePendingUser(r.Context(), req.Email, req.Name, req.Role)
	if errors.Is(err, store.ErrEmailTaken) {
		WriteError(w, http.StatusConflict, CodeConflict, "an account already exists for that email")
		return
	}
	if err != nil {
		// CreatePendingUser's validation errors are plain errors rather than
		// ValidationError, so they cannot be echoed. A bad role or a malformed
		// address is still the caller's fault.
		WriteError(w, http.StatusBadRequest, CodeBadRequest,
			"email, name, and role must be valid")
		return
	}

	_, token, err := s.store.CreateInvite(r.Context(), user.ID, store.InviteTTL)
	if err != nil {
		s.writeStoreError(w, r, "create invite", err)
		return
	}
	if err := s.store.AppendAudit(r.Context(), actor.ID, "user.create", "user:"+user.ID, ""); err != nil {
		s.logger.Error("audit user create", "id", RequestIDFrom(r.Context()), "error", err)
	}

	// There is no mail server (spec section 1), so the link comes back in this
	// response and the admin hands it over out of band.
	WriteJSON(w, http.StatusCreated, map[string]any{
		"user": toAdminUserJSON(store.UserSummary{User: user, HasPendingInvite: true}),
		// The raw token exists exactly once, here. It cannot be recovered from
		// the database afterwards, by an admin or by anyone who steals it.
		"inviteUrl": s.inviteURL(token),
		"expiresIn": store.InviteTTL.String(),
	})
}

func (s *Server) handleAdminReissueInvite(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserFrom(r.Context())
	id := r.PathValue("id")

	user, err := s.store.UserByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, "load user", err)
		return
	}
	// Reissuing for an active account would hand someone a second route into a
	// vault that is already set up. A reset is the deliberate way to do that,
	// and it says so.
	if user.Status != "pending" {
		WriteError(w, http.StatusConflict, CodeConflict,
			"this account has already been set up; use reset to start it over")
		return
	}

	_, token, err := s.store.CreateInvite(r.Context(), id, store.InviteTTL)
	if err != nil {
		s.writeStoreError(w, r, "create invite", err)
		return
	}
	if err := s.store.AppendAudit(r.Context(), actor.ID, "user.invite.reissue", "user:"+id, ""); err != nil {
		s.logger.Error("audit invite reissue", "id", RequestIDFrom(r.Context()), "error", err)
	}
	WriteJSON(w, http.StatusCreated, map[string]any{
		"inviteUrl": s.inviteURL(token),
		"expiresIn": store.InviteTTL.String(),
	})
}

type patchUserRequest struct {
	Status string `json:"status"`
}

func (s *Server) handleAdminPatchUser(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserFrom(r.Context())
	id := r.PathValue("id")

	var req patchUserRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	if err := s.store.SetUserStatus(r.Context(), id, req.Status, actor.ID); err != nil {
		if errors.Is(err, store.ErrLastAdmin) {
			WriteError(w, http.StatusConflict, CodeConflict,
				"this is the only administrator; promote another account first")
			return
		}
		s.writeStoreError(w, r, "set user status", err)
		return
	}

	user, err := s.store.UserByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, "load user", err)
		return
	}
	WriteJSON(w, http.StatusOK, toAdminUserJSON(store.UserSummary{User: user}))
}

type resetUserRequest struct {
	ConfirmEmail string `json:"confirmEmail"`
}

func (s *Server) handleAdminResetUser(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserFrom(r.Context())
	id := r.PathValue("id")

	var req resetUserRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	user, err := s.store.UserByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, "load user", err)
		return
	}
	// Spec section 3.7 puts the typed-email confirmation in the dialog. It is
	// re-checked here because an irreversible action that destroys a vault must
	// not hinge on a client-side check alone.
	if store.NormalizeEmail(req.ConfirmEmail) != user.Email {
		WriteError(w, http.StatusBadRequest, CodeBadRequest,
			"confirmEmail does not match this account")
		return
	}

	token, err := s.store.ResetUser(r.Context(), id, actor.ID)
	if err != nil {
		s.writeStoreError(w, r, "reset user", err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"inviteUrl": s.inviteURL(token),
		"expiresIn": store.InviteTTL.String(),
		"message": "Key material and personal items destroyed. Collection access " +
			"must be re-granted after the user enrolls again.",
	})
}

func (s *Server) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserFrom(r.Context())

	err := s.store.DeleteUser(r.Context(), r.PathValue("id"), actor.ID)
	switch {
	case errors.Is(err, store.ErrLastAdmin):
		WriteError(w, http.StatusConflict, CodeConflict,
			"this is the only administrator; promote another account first")
		return
	case errors.Is(err, store.ErrUserReferenced):
		// Naming the obstacle matters: without it the operator has a database
		// error and no next step. The references are deliberate — deleting an
		// account must not cascade into destroying a shared collection.
		WriteError(w, http.StatusConflict, CodeConflict,
			"this account created a collection or granted a membership. "+
				"Delete or reassign those collections first, or disable the account instead.")
		return
	case err != nil:
		s.writeStoreError(w, r, "delete user", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			WriteError(w, http.StatusBadRequest, CodeBadRequest, "limit must be an integer")
			return
		}
		limit = parsed
	}

	entries, err := s.store.AuditPage(r.Context(), limit, r.URL.Query().Get("before"))
	if err != nil {
		s.writeStoreError(w, r, "read audit log", err)
		return
	}

	type entryJSON struct {
		ID          string `json:"id"`
		ActorUserID string `json:"actorUserId"`
		Action      string `json:"action"`
		Target      string `json:"target"`
		Metadata    string `json:"metadata"`
		CreatedAt   string `json:"createdAt"`
	}
	out := make([]entryJSON, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entryJSON{
			ID:          entry.ID,
			ActorUserID: entry.ActorUserID.String,
			Action:      entry.Action,
			Target:      entry.Target,
			Metadata:    entry.Metadata,
			CreatedAt:   entry.CreatedAt.Format(time.RFC3339),
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"entries": out})
}

// handleAdminListCollections is the membership-graph view. It carries no
// sealed keys: an admin who is not a member holds none, and the server has
// none to give.
func (s *Server) handleAdminListCollections(w http.ResponseWriter, r *http.Request) {
	collections, err := s.store.AllCollections(r.Context())
	if err != nil {
		s.writeStoreError(w, r, "list collections", err)
		return
	}
	grants, err := s.store.AllPendingGrants(r.Context())
	if err != nil {
		s.writeStoreError(w, r, "list pending grants", err)
		return
	}

	type summary struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		CreatedBy   string `json:"createdBy"`
		CreatedAt   string `json:"createdAt"`
		MemberCount int    `json:"memberCount"`
	}
	out := make([]summary, 0, len(collections))
	for _, collection := range collections {
		members, err := s.store.MembershipsOf(r.Context(), collection.ID)
		if err != nil {
			s.writeStoreError(w, r, "count members", err)
			return
		}
		out = append(out, summary{
			ID:          collection.ID,
			Name:        collection.Name,
			CreatedBy:   collection.CreatedBy,
			CreatedAt:   collection.CreatedAt.Format(time.RFC3339),
			MemberCount: len(members),
		})
	}

	pending := make([]pendingGrantJSON, 0, len(grants))
	for _, grant := range grants {
		pending = append(pending, toPendingGrantJSON(grant))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"collections":   out,
		"pendingGrants": pending,
	})
}
```

Register in `routes()`:

```go
	s.mux.HandleFunc("GET /api/admin/users", s.requireAdmin(s.handleAdminListUsers))
	s.mux.HandleFunc("POST /api/admin/users", s.requireAdmin(s.handleAdminCreateUser))
	s.mux.HandleFunc("POST /api/admin/users/{id}/invite", s.requireAdmin(s.handleAdminReissueInvite))
	s.mux.HandleFunc("PATCH /api/admin/users/{id}", s.requireAdmin(s.handleAdminPatchUser))
	s.mux.HandleFunc("POST /api/admin/users/{id}/reset", s.requireAdmin(s.handleAdminResetUser))
	s.mux.HandleFunc("DELETE /api/admin/users/{id}", s.requireAdmin(s.handleAdminDeleteUser))
	s.mux.HandleFunc("GET /api/admin/audit", s.requireAdmin(s.handleAdminAudit))
	s.mux.HandleFunc("GET /api/admin/collections", s.requireAdmin(s.handleAdminListCollections))
```

- [ ] **Step 8: Run the admin endpoint tests**

```bash
go test ./internal/httpapi/ -run Admin -v
```

Expected: PASS, all ten.

- [ ] **Step 9: Prove the key-material exclusion is load-bearing**

Temporarily change `handleAdminListUsers` to marshal the raw
`store.UserSummary` values instead of `adminUserJSON`. Run:

```bash
go test ./internal/httpapi/ -run TestAdminUserListNeverCarriesKeyMaterial -v
```

Expected: FAIL, naming the leaked fields. Revert and confirm PASS. Record
both: this is the spec §10 security assertion, and the reason
`adminUserJSON` exists as a separate struct rather than a filter.

- [ ] **Step 10: Full suite, vet, gofmt, race**

```bash
go test ./... && gofmt -l ./internal ./cmd && go vet ./...
```

Expected: PASS, both silent.

```bash
go test -race ./...
```

Expected: PASS.

- [ ] **Step 11: Commit**

```bash
git add internal/ cmd/ && git commit -m "feat(api): administration — users, invites, reset, delete, audit"
```

---

## Task 8: Tombstone retention, carried-forward fixes, and the security sweep

**Files:**
- Create: `internal/store/retention.go`
- Create: `internal/httpapi/vault_security_test.go`
- Test: `internal/store/retention_test.go`
- Modify: `internal/httpapi/server.go` (retention ticker)
- Modify: `internal/httpapi/auth.go` (reset the prelogin budget on a successful login)
- Modify: `internal/secret/secret_test.go` (unreadable-file case)
- Modify: `internal/store/invites.go`, `internal/store/users.go`, `internal/httpapi/auth.go` (remove dead code)
- Modify: `packages/crypto/src/kdf.ts`, `packages/crypto/src/index.ts`, `packages/crypto/README.md`
- Modify: `docs/superpowers/specs/2026-07-25-keyhole-design.md`

**Interfaces:**
- Produces:
  ```go
  const TombstoneRetention = 90 * 24 * time.Hour
  func (s *Store) PurgeTombstones(ctx context.Context, olderThan time.Duration) (int64, error)
  ```
  And in `packages/crypto`: `export const DEFAULT_KDF_PARAMS_JSON: string`.

This task closes every item the Plan 2a review carried forward that Tasks 1–7
did not, and adds the cross-surface security assertions spec §10 requires.

- [ ] **Step 1: Write the failing retention tests**

Create `internal/store/retention_test.go`:

```go
package store

import (
	"context"
	"testing"
	"time"
)

func TestPurgeTombstonesRemovesOldOnesAndKeepsRecentOnes(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")

	old, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "old", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	recent, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "recent", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	if _, err := st.DeleteItem(ctx, old.ID); err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}
	if _, err := st.DeleteItem(ctx, recent.ID); err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}

	// Backdate one tombstone past the window.
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE items SET deleted_at = ? WHERE id = ?`,
		time.Now().UTC().Add(-100*24*time.Hour).Format(time.RFC3339), old.ID); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	purged, err := st.PurgeTombstones(ctx, TombstoneRetention)
	if err != nil {
		t.Fatalf("PurgeTombstones: %v", err)
	}
	if purged != 1 {
		t.Fatalf("purged %d rows, want 1", purged)
	}

	if _, err := st.ItemByID(ctx, old.ID); err == nil {
		t.Error("the old tombstone survived the purge")
	}
	// A device offline for a week must still learn about last week's deletes.
	// Purging recent tombstones would leave the item on that device forever.
	if _, err := st.ItemByID(ctx, recent.ID); err != nil {
		t.Errorf("a recent tombstone was purged: %v", err)
	}
}

func TestPurgeTombstonesNeverTouchesLiveRows(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")

	live, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "live", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	folder, err := st.CreateFolder(ctx, userID, "live-folder")
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	// Backdate the live rows' timestamps. A purge keyed on updated_at rather
	// than deleted_at would delete a vault's worth of untouched passwords.
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE items SET created_at = ?, updated_at = ?`,
		"2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z"); err != nil {
		t.Fatalf("backdate items: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE folders SET created_at = ?, updated_at = ?`,
		"2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z"); err != nil {
		t.Fatalf("backdate folders: %v", err)
	}

	purged, err := st.PurgeTombstones(ctx, TombstoneRetention)
	if err != nil {
		t.Fatalf("PurgeTombstones: %v", err)
	}
	if purged != 0 {
		t.Fatalf("purged %d rows, want 0", purged)
	}
	if _, err := st.ItemByID(ctx, live.ID); err != nil {
		t.Errorf("a live item was purged: %v", err)
	}
	if _, err := st.FolderByID(ctx, folder.ID); err != nil {
		t.Errorf("a live folder was purged: %v", err)
	}
}

func TestPurgeTombstonesCoversFoldersToo(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")

	folder, err := st.CreateFolder(ctx, userID, "doomed")
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	if _, err := st.DeleteFolder(ctx, folder.ID); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE folders SET deleted_at = ?`,
		time.Now().UTC().Add(-100*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	purged, err := st.PurgeTombstones(ctx, TombstoneRetention)
	if err != nil {
		t.Fatalf("PurgeTombstones: %v", err)
	}
	if purged != 1 {
		t.Errorf("purged %d rows, want 1 — folder tombstones accumulate forever", purged)
	}
}
```

- [ ] **Step 2: Run and watch it fail**

```bash
go test ./internal/store/ -run Purge -v
```

Expected: FAIL — `undefined: TombstoneRetention`.

- [ ] **Step 3: Implement retention**

Create `internal/store/retention.go`:

```go
package store

import (
	"context"
	"fmt"
	"time"
)

// TombstoneRetention is how long a delete stays visible to sync (spec section
// 4.2). It has to outlast the longest plausible offline period: a device that
// misses the tombstone entirely keeps showing an item its owner deleted, and
// nothing later removes it.
const TombstoneRetention = 90 * 24 * time.Hour

// PurgeTombstones removes tombstones older than the window and reports how
// many rows went.
//
// The predicate is `deleted_at IS NOT NULL AND deleted_at < cutoff` — never
// updated_at, which every live row also carries. A purge keyed on the wrong
// column deletes a vault's worth of untouched passwords, and there is no undo.
func (s *Store) PurgeTombstones(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-olderThan).Format(time.RFC3339)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin purge: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var total int64
	for _, table := range []string{"items", "folders"} {
		result, err := tx.ExecContext(ctx,
			`DELETE FROM `+table+` WHERE deleted_at IS NOT NULL AND deleted_at < ?`, cutoff)
		if err != nil {
			return 0, fmt.Errorf("purge %s: %w", table, err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("rows affected: %w", err)
		}
		total += affected
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit purge: %w", err)
	}
	if total > 0 {
		if err := s.AppendAudit(ctx, "", "retention.purge", "tombstones",
			fmt.Sprintf(`{"purged":%d}`, total)); err != nil {
			return total, err
		}
	}
	return total, nil
}
```

- [ ] **Step 4: Run the retention tests**

```bash
go test ./internal/store/ -run Purge -v
```

Expected: PASS, all three.

- [ ] **Step 5: Run the purge on a schedule**

In `internal/httpapi/server.go`, rename `sweepLimiter` to `background` and give
it the second job, so there is one goroutine and one stop channel rather than
two of each:

```go
// background runs the server's periodic maintenance and exits on Close.
//
// Two jobs on two tickers in one goroutine: discarding stale rate-limit
// entries, without which an attacker cycling source addresses grows the map
// without bound; and purging expired tombstones, without which every delete
// this installation ever performs is stored forever.
func (s *Server) background() {
	limiterTicker := time.NewTicker(10 * time.Minute)
	defer limiterTicker.Stop()
	retentionTicker := time.NewTicker(24 * time.Hour)
	defer retentionTicker.Stop()

	for {
		select {
		case <-limiterTicker.C:
			s.limiter.Sweep(time.Hour)
			s.preloginLimiter.Sweep(time.Hour)
		case <-retentionTicker.C:
			purged, err := s.store.PurgeTombstones(context.Background(), store.TombstoneRetention)
			if err != nil {
				s.logger.Error("purge tombstones", "error", err)
				continue
			}
			if purged > 0 {
				s.logger.Info("purged tombstones", "rows", purged)
			}
		case <-s.stop:
			return
		}
	}
}
```

Update `New` to call `go s.background()`, and update
`TestCloseStopsTheLimiterSweeperAndIsSafeToRepeat` in `server_test.go` if it
names the old function. Add `"context"` to the imports.

- [ ] **Step 6: Fix the prelogin budget carried from Plan 2a**

Plan 2a's review recorded: *"The prelogin limiter never resets, so a household
behind one NAT address past 20 sign-ins in an hour saturates at the one-minute
ceiling with no explanation."*

In `handleLogin`, beside the two existing `Reset` calls on success:

```go
	s.limiter.Reset(ipKey)
	s.limiter.Reset(accountKey)
	// A successful sign-in is proof the traffic from this address is real, so
	// it clears the prelogin budget too. Without this a household behind one
	// NAT address is throttled after twenty sign-ins in an hour and told
	// nothing about why.
	s.preloginLimiter.Reset("prelogin:" + ClientIP(r))
```

Add to `internal/httpapi/security_test.go`:

```go
func TestASuccessfulLoginClearsThePreloginBudget(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	// Spend the whole prelogin allowance from one address.
	for i := 0; i < 25; i++ {
		postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "ghost@example.com"})
	}
	if rec := postJSON(t, srv, "/api/auth/prelogin",
		map[string]string{"email": "ghost@example.com"}); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("setup: prelogin status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}

	if rec := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash, "deviceLabel": "test",
	}); rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}

	// A real household shares one address. Proving the traffic is real must
	// buy back the allowance, or the second person to sign in that hour is
	// throttled for reasons they cannot see.
	if rec := postJSON(t, srv, "/api/auth/prelogin",
		map[string]string{"email": "person@example.com"}); rec.Code != http.StatusOK {
		t.Errorf("prelogin after a successful login = %d, want %d", rec.Code, http.StatusOK)
	}
}
```

- [ ] **Step 7: Remove the dead code Plan 2a's review named**

Three items, all confirmed unreachable in production by that review. Delete
them and their tests:

- `store.MarkInviteUsed` — `CompleteEnrollment` consumes the invite inside its
  own transaction, which is what makes a link one-time under concurrency. The
  standalone function has no caller and would be the wrong thing to reach for.
- `store.CountUsers` — no caller.
- the `!ok` branch in `handleLogout` — it is behind `requireAuth`, which cannot
  invoke a handler without a session in context.

For the last one, replace:

```go
	session, ok := sessionFrom(r.Context())
	if !ok {
		WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "not signed in")
		return
	}
```

with:

```go
	// requireAuth cannot call this handler without a session in context, so
	// the absent case is unreachable rather than merely unlikely.
	session, _ := sessionFrom(r.Context())
```

Run `go build ./... && go vet ./...` after each deletion. If any of the three
turns out to have gained a caller in Tasks 1–7, keep it and say so in the
report — the review's finding was true at the time, not necessarily now.

- [ ] **Step 8: Export the canonical KDF params from the crypto package**

Plan 2a's review recorded that the decoy's params-parity depends on the web
app's `JSON.stringify` producing bytes identical to `auth.DefaultKDFParamsJSON`.
Now that the server *rejects* anything else (Task 6), a client that stringifies
an object at a call site gets a 400 with no obvious cause. Pin it.

In `packages/crypto/src/kdf.ts`:

```ts
/**
 * The exact JSON the server accepts for KDF parameters, byte for byte.
 *
 * The server pins this: enrollment and password rotation reject anything else,
 * because prelogin answers an unknown address with this same string and any
 * divergence would turn the params field into an account-enumeration oracle.
 *
 * A literal, not `JSON.stringify(DEFAULT_KDF_PARAMS)` — key order and spacing
 * are part of the contract, and a stringify at a call site is exactly how they
 * drift.
 */
export const DEFAULT_KDF_PARAMS_JSON =
  '{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4}';
```

Export it from `packages/crypto/src/index.ts`, and add a test in the
kdf test file:

```ts
it("the canonical params string parses to the default params", () => {
  // Two ways of stating the same thing that must never disagree: the object
  // the crypto package derives with, and the exact bytes the server accepts.
  expect(JSON.parse(DEFAULT_KDF_PARAMS_JSON)).toEqual({
    algorithm: "argon2id",
    memoryKiB: 65536,
    iterations: 3,
    parallelism: 4,
  });
});
```

Document it in `packages/crypto/README.md` beside the existing wire-field note:
send `params: DEFAULT_KDF_PARAMS_JSON` verbatim on enrollment and on password
rotation; never stringify an object.

```bash
pnpm --filter @keyhole/crypto test
pnpm --filter @keyhole/crypto typecheck
```

Expected: PASS.

- [ ] **Step 9: Cover the unreadable-secret case**

Plan 2a's review left this Minor open: `internal/secret` has no test for a
genuinely unreadable file, as distinct from a wrong-length one. Add to
`internal/secret/secret_test.go`:

```go
func TestAnUnreadableSecretIsAnErrorNotAFreshSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.secret")

	if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	// Windows ignores POSIX mode bits on files, so verify the chmod actually
	// took effect before asserting on it. A test that silently passes on the
	// development machine and only means something in CI is worse than one
	// that says which it is.
	if data, err := os.ReadFile(path); err == nil && len(data) == 32 {
		t.Skip("this filesystem does not enforce mode 0000; nothing to assert")
	}

	// Generating a fresh secret here would silently invalidate every prelogin
	// decoy salt the installation has ever produced — turning a permissions
	// problem into a change of identity nobody asked for.
	if _, err := Load(path); err == nil {
		t.Error("Load succeeded on an unreadable secret file")
	}
}
```

Adjust the function name if `internal/secret`'s loader is not called `Load`.

- [ ] **Step 10: Write the cross-surface security sweep**

Create `internal/httpapi/vault_security_test.go`:

```go
package httpapi

import (
	"net/http"
	"strings"
	"testing"
)

// vaultRoutes is every route this plan added. Keeping the list in one place
// means a new endpoint that forgets requireAuth fails these tests rather than
// shipping.
var vaultRoutes = []struct {
	method string
	path   string
	body   any
}{
	{http.MethodGet, "/api/sync", nil},
	{http.MethodPost, "/api/items", map[string]string{"ciphertext": "c", "wrappedItemKey": "k"}},
	{http.MethodPost, "/api/items/bulk", map[string]any{"items": []map[string]string{{"ciphertext": "c", "wrappedItemKey": "k"}}}},
	{http.MethodPut, "/api/items/abc", map[string]any{"ciphertext": "c", "wrappedItemKey": "k", "revision": 1}},
	{http.MethodDelete, "/api/items/abc", nil},
	{http.MethodPost, "/api/folders", map[string]string{"encryptedName": "n"}},
	{http.MethodPut, "/api/folders/abc", map[string]any{"encryptedName": "n", "revision": 1}},
	{http.MethodDelete, "/api/folders/abc", nil},
	{http.MethodGet, "/api/collections", nil},
	{http.MethodPost, "/api/collections", map[string]string{"name": "n", "sealedCollectionKey": "s"}},
	{http.MethodGet, "/api/collections/pending-grants", nil},
	{http.MethodDelete, "/api/collections/abc", nil},
	{http.MethodGet, "/api/collections/abc/members", nil},
	{http.MethodPost, "/api/collections/abc/members", map[string]string{"userId": "u"}},
	{http.MethodDelete, "/api/collections/abc/members/u", nil},
	{http.MethodPost, "/api/collections/abc/grants", map[string]string{"userId": "u", "sealedCollectionKey": "s"}},
	{http.MethodGet, "/api/directory", nil},
	{http.MethodGet, "/api/account", nil},
	{http.MethodPost, "/api/account/password", map[string]string{"currentAuthHash": "h"}},
	{http.MethodPost, "/api/account/recovery", map[string]string{"currentAuthHash": "h"}},
	{http.MethodGet, "/api/account/sessions", nil},
	{http.MethodDelete, "/api/account/sessions/abc", nil},
	{http.MethodGet, "/api/admin/users", nil},
	{http.MethodPost, "/api/admin/users", map[string]string{"email": "a@b.c", "name": "n"}},
	{http.MethodPost, "/api/admin/users/abc/invite", nil},
	{http.MethodPatch, "/api/admin/users/abc", map[string]string{"status": "disabled"}},
	{http.MethodPost, "/api/admin/users/abc/reset", map[string]string{"confirmEmail": "a@b.c"}},
	{http.MethodDelete, "/api/admin/users/abc", nil},
	{http.MethodGet, "/api/admin/audit", nil},
	{http.MethodGet, "/api/admin/collections", nil},
}

func TestEveryVaultRouteRejectsAnUnauthenticatedCaller(t *testing.T) {
	srv := newTestServer(t)

	for _, route := range vaultRoutes {
		rec := doJSON(t, srv, route.method, route.path, "", route.body)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d without a token, want %d",
				route.method, route.path, rec.Code, http.StatusUnauthorized)
		}
	}
}

func TestEveryVaultRouteRejectsADisabledAccount(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	target, targetToken := loginTestUser(t, srv, "person@example.com")

	if rec := doJSON(t, srv, http.MethodPatch, "/api/admin/users/"+target.ID, adminToken,
		map[string]string{"status": "disabled"}); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}

	// "Disable this account" has to mean it everywhere at once. One route that
	// still answers is the one an attacker finds.
	for _, route := range vaultRoutes {
		rec := doJSON(t, srv, route.method, route.path, targetToken, route.body)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d for a disabled account, want %d",
				route.method, route.path, rec.Code, http.StatusUnauthorized)
		}
	}
}

func TestNoEndpointReturnsAnotherUsersWrappedKeys(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	loginTestUser(t, srv, "person@example.com")

	// Spec section 10 requires this assertion by name. Both spellings of each
	// field, because a handler that marshals a store struct directly emits the
	// snake_case column names.
	forbidden := []string{
		"protectedUserKey", "protected_user_key",
		"encryptedPrivateKey", "encrypted_private_key",
		"recoveryProtectedUserKey", "recovery_protected_user_key",
		"recoverySalt", "recovery_salt",
		"recoveryKdfParams", "recovery_kdf_params",
		"authHash", "auth_hash",
		"kdfSalt", "kdf_salt",
		"tokenHash", "token_hash", "refreshHash", "refresh_hash",
	}

	readRoutes := []string{
		"/api/sync",
		"/api/collections",
		"/api/collections/pending-grants",
		"/api/directory",
		"/api/account",
		"/api/account/sessions",
		"/api/admin/users",
		"/api/admin/audit",
		"/api/admin/collections",
	}
	for _, path := range readRoutes {
		rec := doJSON(t, srv, http.MethodGet, path, adminToken, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", path, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		for _, field := range forbidden {
			if strings.Contains(body, field) {
				t.Errorf("GET %s carries %q", path, field)
			}
		}
	}
}

func TestTheContentSecurityPolicyIsRestrictive(t *testing.T) {
	srv := newTestServer(t)

	rec := doJSON(t, srv, http.MethodGet, "/healthz", "", nil)
	policy := rec.Header().Get("Content-Security-Policy")

	// Plan 2a's review found the existing assertion only checked the header was
	// non-empty, so replacing the policy with any weaker non-empty string
	// passed. These are the directives that actually matter for a page that
	// handles a master password.
	for _, directive := range []string{
		"default-src 'self'",
		"script-src 'self'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
	} {
		if !strings.Contains(policy, directive) {
			t.Errorf("CSP is missing %q: %s", directive, policy)
		}
	}
	// 'unsafe-inline' or 'unsafe-eval' in script-src would defeat the policy
	// entirely for the one page that must not be defeated.
	for _, unsafe := range []string{"unsafe-inline", "unsafe-eval", "*"} {
		if strings.Contains(policy, unsafe) {
			t.Errorf("CSP contains %q: %s", unsafe, policy)
		}
	}
}

func TestAnItemIdFromAnotherVaultIsIndistinguishableFromANonexistentOne(t *testing.T) {
	srv := newTestServer(t)
	_, ownerToken := loginTestUser(t, srv, "owner@example.com")
	_, otherToken := loginTestUser(t, srv, "other@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/items", ownerToken, map[string]string{
		"ciphertext": "c", "wrappedItemKey": "k",
	})
	var item itemResponse
	decodeInto(t, created, &item)

	real := doJSON(t, srv, http.MethodDelete, "/api/items/"+item.ID, otherToken, nil)
	fake := doJSON(t, srv, http.MethodDelete, "/api/items/0123456789abcdef0123456789abcdef", otherToken, nil)

	// Different answers here would let anyone enumerate which item ids exist
	// across the whole installation, one request at a time.
	if real.Code != fake.Code {
		t.Errorf("existing-but-forbidden = %d, nonexistent = %d; they must match",
			real.Code, fake.Code)
	}
	if real.Body.String() != fake.Body.String() {
		t.Errorf("bodies differ:\n forbidden: %s\n missing:   %s", real.Body.String(), fake.Body.String())
	}
}
```

- [ ] **Step 11: Run the sweep**

```bash
go test ./internal/httpapi/ -run "Every|NoEndpoint|ContentSecurity|Indistinguishable|Prelogin" -v
```

Expected: PASS. If `TestEveryVaultRouteRejectsADisabledAccount` fails on a
route, that route is the bug — fix the route, not the test.

- [ ] **Step 12: Update the spec so it does not lie**

Three amendments in `docs/superpowers/specs/2026-07-25-keyhole-design.md`:

1. **§3.2**, replace *"KDF parameters are stored per user so they can be raised
   later without a flag day"* with:

   > KDF parameters are stored per user, but the server pins them to its
   > current default: enrollment and password rotation reject anything that is
   > not byte-equal to it. The column exists so parameters *can* be raised, and
   > so a future migration knows what each account was using — but divergence
   > is not permitted while an account is live, because prelogin answers an
   > unknown address with the default and any difference would turn the params
   > field into an account-enumeration oracle. Raising the parameters is
   > therefore a deliberate migration that forces re-derivation at next login.

2. **§4.2**, after the item-`type` paragraph, add:

   > **`items` has no `folder_id` column either.** Folder membership lives
   > inside the encrypted body next to `type`, for the same reason: a plaintext
   > column recording which items are grouped together tells the server
   > something it does not need. Migration 0002 removes the column that
   > migration 0001 created.

3. **§4.3**, add the three endpoints this plan adds beyond the original list,
   each with the one-line reason:

   ```
   GET    /api/directory                    active users + public keys (required to seal a collection key)
   POST   /api/folders  PUT/DELETE /api/folders/:id   folder CRUD
   GET    /api/collections/:id/members      membership list, no sealed keys
   POST   /api/admin/users/:id/invite       reissue a setup link
   GET    /api/admin/collections            membership-graph view
   ```

- [ ] **Step 13: Whole-suite verification**

```bash
go build ./... && go vet ./... && gofmt -l ./internal ./cmd && go test ./...
```

Expected: build clean, vet silent, `gofmt -l` prints nothing, all packages PASS.

```bash
go test -race ./...
```

Expected: PASS with no race reports.

```bash
pnpm --filter @keyhole/crypto test && pnpm --filter @keyhole/crypto typecheck
```

Expected: PASS.

- [ ] **Step 14: End-to-end smoke test against a real binary**

Tests use `httptest`; this proves the actual command works.

```bash
go build -o /tmp/keyhole ./cmd/keyhole
/tmp/keyhole migrate --data-dir /tmp/keyhole-data
/tmp/keyhole admin create --email you@example.com --data-dir /tmp/keyhole-data
```

Expected: `migrate` reports the schema version as 2, and `admin create` prints
a setup link. Record both outputs in the report — a passing suite over
`httptest` has never once started the server the way an operator does.

- [ ] **Step 15: Commit**

```bash
git add . && git commit -m "feat(server): tombstone retention, carried-forward fixes, and the security sweep"
```

---

## Definition of done

- [ ] Every route in spec §4.3 exists, plus the five additions listed in §4.3
      as amended, and each is covered by a test.
- [ ] `GET /api/sync` returns items, folders, and collections, is incremental
      on one shared revision sequence, and carries tombstones.
- [ ] No endpoint returns another user's wrapped keys — asserted across the
      whole read surface, not per handler.
- [ ] Every route rejects an unauthenticated caller and a disabled account.
- [ ] An item id belonging to another vault is indistinguishable from one that
      does not exist.
- [ ] KDF params are pinned; prelogin cannot distinguish a real account from a
      decoy after a password rotation.
- [ ] Deleting a user who created a collection returns an actionable 409, not a
      500.
- [ ] `go test -race ./...` is clean; `gofmt -l ./internal ./cmd` prints
      nothing; `go vet ./...` is silent.
- [ ] The built binary migrates to schema version 2 and creates an admin.
- [ ] Every item Plan 2a's review carried to 2b is closed or explicitly
      recorded as deliberately not closed, with the reason.
