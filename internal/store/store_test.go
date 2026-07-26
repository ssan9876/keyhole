package store

import (
	"context"
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
		"revision_sequence",
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
