package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// openTemp gives each test its own migrated database on disk. A file rather
// than :memory: because the production path is a file and WAL behaviour
// differs between the two.
func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

func TestMigrateCreatesEveryTable(t *testing.T) {
	s := openTemp(t)

	want := []string{
		"users", "invites", "sessions", "items", "folders",
		"collections", "collection_memberships", "pending_grants",
		"audit_log", "server_settings", "schema_migrations",
		"revision_sequence", "recovery_tokens",
	}
	for _, table := range want {
		var name string
		err := s.DB().QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name = ?`, table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %q missing after migrate: %v", table, err)
		}
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	before, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	after, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if before != after {
		t.Errorf("schema version moved on a no-op migrate: %d -> %d", before, after)
	}
	if after < 1 {
		t.Errorf("schema version = %d, want at least 1", after)
	}
}

func TestForeignKeysAreEnforced(t *testing.T) {
	s := openTemp(t)

	// A session for a user that does not exist must be rejected. SQLite
	// silently ignores foreign keys unless the pragma is on per connection,
	// which is exactly the kind of thing that only shows up in production.
	_, err := s.DB().Exec(
		`INSERT INTO sessions (id, user_id, token_hash, refresh_hash, device_label, created_at, last_seen_at, expires_at)
		 VALUES ('a','nonexistent','h','r','dev','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z')`,
	)
	if err == nil {
		t.Error("insert with a dangling user_id succeeded; foreign keys are not enforced")
	}
}

func TestEmailIsUniqueCaseInsensitively(t *testing.T) {
	s := openTemp(t)

	insert := `INSERT INTO users (id, email, name, role, status, created_at, updated_at, revision)
	           VALUES (?, ?, 'Test', 'user', 'pending', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0)`

	if _, err := s.DB().Exec(insert, "id1", "person@example.com"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	// Emails are normalized to lowercase before storage, but the constraint
	// must hold regardless so a bug upstream cannot create two accounts that
	// a user would consider the same address.
	if _, err := s.DB().Exec(insert, "id2", "Person@Example.com"); err == nil {
		t.Error("a second user with the same email in different case was accepted")
	}
}

func TestWALIsEnabled(t *testing.T) {
	s := openTemp(t)

	var mode string
	if err := s.DB().QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want %q", mode, "wal")
	}
}

func TestSchemaVersionOnAnUnmigratedDatabase(t *testing.T) {
	// Deliberately not openTemp: that helper migrates first, which is exactly
	// the ordering that hides this bug. `keyhole migrate` reads the version
	// before creating the tracking table on every first-ever run.
	s, err := Open(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	version, err := s.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion on a fresh database returned an error: %v", err)
	}
	if version != 0 {
		t.Errorf("SchemaVersion = %d on a fresh database, want 0", version)
	}
}

func TestOpenCreatesTheParentDirectory(t *testing.T) {
	nested := filepath.Join(t.TempDir(), "does", "not", "exist", "keyhole.db")

	s, err := Open(nested)
	if err != nil {
		t.Fatalf("Open should create the parent directory, got: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if _, err := os.Stat(nested); err != nil {
		t.Errorf("database file was not created: %v", err)
	}
}

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

// TestMigration0002PreservesExistingRows is the test the schema-shape assertions
// cannot be: migration 0002 rebuilds the items table to drop folder_id, and on a
// fresh database that rebuild copies nothing, so an INSERT...SELECT that dropped
// every row would pass every other check in this file.
//
// A real installation runs this migration against a populated vault. If the copy
// is wrong, the first symptom is a user opening an empty vault after an update.
func TestMigration0002PreservesExistingRows(t *testing.T) {
	ctx := context.Background()

	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// Stop at version 1, so rows can be written against the old schema — the
	// state every existing installation is in when it takes this update.
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			name       TEXT NOT NULL,
			applied_at TEXT NOT NULL
		)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	var second migration
	for _, m := range migrations {
		switch m.version {
		case 1:
			if err := s.applyMigration(ctx, m); err != nil {
				t.Fatalf("apply migration 1: %v", err)
			}
		case 2:
			second = m
		}
	}
	if second.version != 2 {
		t.Fatal("migration 0002 not found")
	}

	// Seeded with raw SQL, not enrolledUser: at version 1 the schema is behind
	// the Go layer, whose column list has since grown recovery_auth_hash, so
	// every store method that scans a user fails here. The items below need an
	// owner row that satisfies the foreign key and nothing more.
	userID, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, name, role, status, revision, created_at, updated_at)
		 VALUES (?, 'owner@example.com', 'Owner', 'user', 'active', 0,
			'2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`, userID); err != nil {
		t.Fatalf("seed owner: %v", err)
	}

	folderID, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO folders (id, user_id, encrypted_name, revision, created_at, updated_at)
		 VALUES (?, ?, 'enc-name', 9, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
		folderID, userID); err != nil {
		t.Fatalf("insert folder: %v", err)
	}
	// A live row that uses folder_id — the column about to be dropped — and a
	// tombstone, whose deleted_at must survive or the delete stops propagating.
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO items (id, owner_user_id, collection_id, folder_id, ciphertext,
			wrapped_item_key, revision, created_at, updated_at, deleted_at)
		 VALUES
		   ('live', ?, NULL, ?, 'CIPHER-ONE', 'WK1', 7, '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z', NULL),
		   ('dead', ?, NULL, NULL, '', '', 4, '2026-01-01T00:00:00Z', '2026-01-03T00:00:00Z', '2026-01-03T00:00:00Z')`,
		userID, folderID, userID); err != nil {
		t.Fatalf("insert items: %v", err)
	}

	if err := s.applyMigration(ctx, second); err != nil {
		t.Fatalf("apply migration 2: %v", err)
	}

	live, err := s.ItemByID(ctx, "live")
	if err != nil {
		t.Fatalf("the live item did not survive the rebuild: %v", err)
	}
	if live.Ciphertext != "CIPHER-ONE" || live.WrappedItemKey != "WK1" {
		t.Errorf("the rebuild altered the payload: ciphertext=%q wrapped=%q",
			live.Ciphertext, live.WrappedItemKey)
	}
	if live.Revision != 7 {
		t.Errorf("Revision = %d, want 7 — a changed revision moves the item "+
			"relative to every client's stored cursor", live.Revision)
	}
	if live.OwnerUserID != userID {
		t.Errorf("OwnerUserID = %q, want %q", live.OwnerUserID, userID)
	}
	if live.DeletedAt.Valid {
		t.Error("a live item came out of the rebuild as a tombstone")
	}

	dead, err := s.ItemByID(ctx, "dead")
	if err != nil {
		t.Fatalf("the tombstone did not survive the rebuild: %v", err)
	}
	if !dead.DeletedAt.Valid {
		t.Error("the tombstone lost its deleted_at; the delete stops propagating")
	}

	// Seeded from the maximum across BOTH tables. Taking it from items alone
	// would hand the folder's revision of 9 out a second time, and a client
	// syncing at 9 would never see whichever row lost.
	var seq int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT value FROM revision_sequence WHERE id = 1`).Scan(&seq); err != nil {
		t.Fatalf("read sequence: %v", err)
	}
	if seq != 9 {
		t.Errorf("revision_sequence = %d, want 9 (max of items 7 and folders 9)", seq)
	}
}

// openAtVersion gives a database migrated only as far as `through`, which is
// the state an existing installation is in the moment before it takes the next
// update. Nothing in the Go layer may be used to write rows at that point: the
// column list scanUser reads has already moved ahead of the schema.
func openAtVersion(t *testing.T, through int) *Store {
	t.Helper()
	ctx := context.Background()

	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			name       TEXT NOT NULL,
			applied_at TEXT NOT NULL
		)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, m := range migrations {
		if m.version > through {
			continue
		}
		if err := s.applyMigration(ctx, m); err != nil {
			t.Fatalf("apply migration %s: %v", m.name, err)
		}
	}
	return s
}

// TestMigration0004LeavesAnExistingRecoveryBlobWithANullAuthHash pins the one
// fact the column's nullability carries. A blob written before this migration
// was wrapped under the undifferentiated recovery key and no auth hash was ever
// derived from it, so there is nothing to check a redeeming caller against. NULL
// is how the redeem endpoints will recognize exactly those rows; a non-NULL
// default of any kind would make an unredeemable account indistinguishable
// from a redeemable one at precisely the moment that distinction has to be made
// without leaking whether the address exists.
func TestMigration0004LeavesAnExistingRecoveryBlobWithANullAuthHash(t *testing.T) {
	ctx := context.Background()
	s := openAtVersion(t, 3)

	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, name, role, status, kdf_salt, kdf_params, auth_hash,
			protected_user_key, recovery_salt, recovery_kdf_params, recovery_protected_user_key,
			public_key, encrypted_private_key, revision, created_at, updated_at)
		 VALUES ('old', 'old@example.com', 'Old Account', 'user', 'active', 'salt', '{}', 'argon2id$x$y',
			'puk', 'recovery-salt', '{}', 'RECOVERY-BLOB',
			'pk', 'epk', 3, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
	); err != nil {
		t.Fatalf("seed a pre-0004 enrolled account: %v", err)
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	version, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if version < 4 {
		t.Fatalf("schema version = %d, want at least 4", version)
	}

	var authHash sql.NullString
	var blob string
	if err := s.db.QueryRowContext(ctx,
		`SELECT recovery_auth_hash, recovery_protected_user_key FROM users WHERE id = 'old'`,
	).Scan(&authHash, &blob); err != nil {
		t.Fatalf("read the migrated row: %v", err)
	}
	if authHash.Valid {
		t.Errorf("recovery_auth_hash = %q on a row that predates the column, want NULL", authHash.String)
	}
	// The migration adds a column; it must not disturb the blob that column
	// describes. A row whose blob was rewritten here has lost its recovery path
	// outright, which is worse than being unredeemable.
	if blob != "RECOVERY-BLOB" {
		t.Errorf("recovery_protected_user_key = %q after the migration, want it untouched", blob)
	}
}
