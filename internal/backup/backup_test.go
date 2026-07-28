package backup

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ssan9876/keyhole/internal/store"
)

// openMigratedStore gives a test its own migrated database on disk, the same
// way internal/store's own tests do: a file rather than :memory:, because
// Snapshot and Restore both operate on the file.
func openMigratedStore(t *testing.T, path string) *store.Store {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// Belt and braces: individual tests close explicitly (Restore replaces
	// the file, and a leftover open handle changes rename semantics on
	// Windows), but a t.Fatal before that point should still let TempDir
	// clean up rather than leaking a handle.
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestSnapshotProducesAReadableDatabaseWithTheSameRows(t *testing.T) {
	ctx := context.Background()
	st := openMigratedStore(t, filepath.Join(t.TempDir(), "keyhole.db"))

	user, err := st.CreatePendingUser(ctx, "owner@example.com", "Owner", "admin")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}

	backupDir := filepath.Join(t.TempDir(), "backups")
	at := time.Date(2026, 7, 27, 14, 30, 0, 0, time.UTC)
	path, err := Snapshot(ctx, st.DB(), backupDir, at)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	wantName := "keyhole-20260727T143000Z.db"
	if filepath.Base(path) != wantName {
		t.Errorf("snapshot filename = %q, want %q", filepath.Base(path), wantName)
	}

	// "A file appeared" is not evidence: a zero-byte file appears too. Open
	// the snapshot for real and read the known row back out of it.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat snapshot: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("snapshot file is zero bytes")
	}

	snap, err := store.Open(path)
	if err != nil {
		t.Fatalf("opening the snapshot as a database: %v", err)
	}
	defer snap.Close()

	got, err := snap.UserByEmail(ctx, "owner@example.com")
	if err != nil {
		t.Fatalf("reading the known row back from the snapshot: %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("snapshot user ID = %q, want %q", got.ID, user.ID)
	}
	if got.Name != "Owner" {
		t.Errorf("snapshot user name = %q, want %q", got.Name, "Owner")
	}
}

func TestSnapshotRefusesToOverwriteAnExistingFile(t *testing.T) {
	ctx := context.Background()
	st := openMigratedStore(t, filepath.Join(t.TempDir(), "keyhole.db"))
	backupDir := t.TempDir()
	at := time.Date(2026, 7, 27, 14, 30, 0, 0, time.UTC)

	first, err := Snapshot(ctx, st.DB(), backupDir, at)
	if err != nil {
		t.Fatalf("first Snapshot: %v", err)
	}

	// Two backups in the same second have the same name by construction.
	// The second call must refuse rather than silently overwrite the first.
	if _, err := Snapshot(ctx, st.DB(), backupDir, at); err == nil {
		t.Fatal("second Snapshot in the same second succeeded; it must refuse instead of overwriting")
	}

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("backup directory has %d entries after the refused second snapshot, want exactly 1 (%s)", len(entries), first)
	}
}

func TestPruneKeepsTheNewestAndDeletesTheRest(t *testing.T) {
	dir := t.TempDir()
	names := []string{
		"keyhole-20260101T000000Z.db",
		"keyhole-20260102T000000Z.db",
		"keyhole-20260103T000000Z.db",
		"keyhole-20260104T000000Z.db",
		"keyhole-20260105T000000Z.db",
	}
	for _, n := range names {
		writeFile(t, filepath.Join(dir, n), "x")
	}

	removed, err := Prune(dir, 2)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(removed) != 3 {
		t.Fatalf("Prune removed %d files, want 3: %v", len(removed), removed)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	remaining := map[string]bool{}
	for _, e := range entries {
		remaining[e.Name()] = true
	}
	wantRemaining := []string{"keyhole-20260104T000000Z.db", "keyhole-20260105T000000Z.db"}
	if len(remaining) != len(wantRemaining) {
		t.Fatalf("remaining files = %v, want exactly %v", entries, wantRemaining)
	}
	for _, n := range wantRemaining {
		if !remaining[n] {
			t.Errorf("%s was pruned; it is one of the 2 newest and should have been kept", n)
		}
	}
	wantRemoved := []string{
		"keyhole-20260101T000000Z.db",
		"keyhole-20260102T000000Z.db",
		"keyhole-20260103T000000Z.db",
	}
	for _, n := range wantRemoved {
		if remaining[n] {
			t.Errorf("%s survived Prune; it is older than the 2 newest and should have been removed", n)
		}
	}
}

func TestPruneIgnoresFilesItDidNotWrite(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{
		"keyhole-20260101T000000Z.db",
		"keyhole-20260102T000000Z.db",
		"keyhole-20260103T000000Z.db",
	} {
		writeFile(t, filepath.Join(dir, n), "x")
	}

	// This is a delete loop pointed at an operator-specified directory. The
	// prefix+suffix filter is the only thing between it and their files, so
	// these three must all survive regardless of --keep.
	foreign := []string{
		"notes.txt",
		"keyhole-20260104T000000Z.db.gpg", // right prefix, wrong suffix
		"backup-20260101T000000Z.db",      // right suffix, wrong prefix
	}
	for _, n := range foreign {
		writeFile(t, filepath.Join(dir, n), "do not touch")
	}

	if _, err := Prune(dir, 1); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	for _, n := range foreign {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("%s did not survive Prune: %v", n, err)
		}
	}
}

func TestPruneWithKeepZeroDeletesNothing(t *testing.T) {
	dir := t.TempDir()
	names := []string{"keyhole-20260101T000000Z.db", "keyhole-20260102T000000Z.db"}
	for _, n := range names {
		writeFile(t, filepath.Join(dir, n), "x")
	}

	// keep <= 0 is what a missing --keep would parse to if it were ever
	// misread as "keep none" instead of "use the default." It must delete
	// nothing rather than everything.
	removed, err := Prune(dir, 0)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("Prune(dir, 0) removed %v; a missing --keep must never be read as keep none", removed)
	}
	for _, n := range names {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("%s was deleted by Prune(dir, 0): %v", n, err)
		}
	}
}

func TestRestoreReplacesTheDatabaseAndItOpens(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "keyhole.db")

	// The "live" database gets a row that must NOT survive the restore.
	live := openMigratedStore(t, dbPath)
	if _, err := live.CreatePendingUser(ctx, "live@example.com", "Live", "admin"); err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	if err := live.Close(); err != nil {
		t.Fatalf("closing the live database before restore: %v", err)
	}

	// Build a snapshot from an unrelated database with a distinct row, so a
	// restore that left the old data in place (or wrote nothing) is caught.
	src := openMigratedStore(t, filepath.Join(t.TempDir(), "source.db"))
	if _, err := src.CreatePendingUser(ctx, "snapshot@example.com", "Snap", "admin"); err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	snapPath, err := Snapshot(ctx, src.DB(), t.TempDir(), time.Date(2026, 7, 27, 14, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("closing the source database: %v", err)
	}

	if err := Restore(snapPath, dbPath); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Step 5 of Restore: any -wal/-shm left beside the OLD database must not
	// survive, or they would apply a journal belonging to a database that no
	// longer exists. Checked here, before anything reopens dbPath -- opening
	// a WAL-mode database is itself what recreates fresh -wal/-shm files, so
	// this assertion has to run before that happens or it proves nothing.
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(dbPath + suffix); err == nil {
			t.Errorf("stale %s file present immediately after restore, before anything reopened the database", dbPath+suffix)
		}
	}

	restored, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("opening the restored database: %v", err)
	}
	defer restored.Close()

	if _, err := restored.UserByEmail(ctx, "live@example.com"); err == nil {
		t.Error("the pre-restore row is still present; Restore did not replace the database")
	}
	got, err := restored.UserByEmail(ctx, "snapshot@example.com")
	if err != nil {
		t.Fatalf("the snapshot's row is not present after Restore: %v", err)
	}
	if got.Name != "Snap" {
		t.Errorf("restored user name = %q, want %q", got.Name, "Snap")
	}
}

func TestRestoreRefusesAFileThatIsNotASQLiteDatabase(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "keyhole.db")

	live := openMigratedStore(t, dbPath)
	if _, err := live.CreatePendingUser(ctx, "keep@example.com", "Keep", "admin"); err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	if err := live.Close(); err != nil {
		t.Fatalf("closing the live database: %v", err)
	}

	garbage := filepath.Join(t.TempDir(), "not-a-database.db")
	writeFile(t, garbage, "this is plainly not a sqlite file")

	if err := Restore(garbage, dbPath); err == nil {
		t.Fatal("Restore accepted a file that is not a SQLite database")
	}

	// Verified by reading a row back, not by checking the error alone: a
	// version of Restore that renamed the original aside before validating
	// the snapshot would also return an error here, while leaving the
	// database gone.
	reopened, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("the original database no longer opens after the refused restore: %v", err)
	}
	defer reopened.Close()
	got, err := reopened.UserByEmail(ctx, "keep@example.com")
	if err != nil {
		t.Fatalf("the original row is gone after the refused restore: %v", err)
	}
	if got.Name != "Keep" {
		t.Errorf("original user name = %q, want %q", got.Name, "Keep")
	}
}

func TestRestoreRefusesAnEmptyOrTruncatedFile(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "keyhole.db")

	live := openMigratedStore(t, dbPath)
	if _, err := live.CreatePendingUser(ctx, "keep@example.com", "Keep", "admin"); err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	if err := live.Close(); err != nil {
		t.Fatalf("closing the live database: %v", err)
	}

	truncated := filepath.Join(t.TempDir(), "truncated.db")
	writeFile(t, truncated, "")

	if err := Restore(truncated, dbPath); err == nil {
		t.Fatal("Restore accepted a zero-byte file")
	}

	reopened, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("the original database no longer opens after the refused restore: %v", err)
	}
	defer reopened.Close()
	if _, err := reopened.UserByEmail(ctx, "keep@example.com"); err != nil {
		t.Fatalf("the original row is gone after the refused restore: %v", err)
	}
}

func TestRestoreKeepsTheReplacedDatabaseBesideIt(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "keyhole.db")

	live := openMigratedStore(t, dbPath)
	if _, err := live.CreatePendingUser(ctx, "old@example.com", "Old", "admin"); err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	if err := live.Close(); err != nil {
		t.Fatalf("closing the live database: %v", err)
	}

	src := openMigratedStore(t, filepath.Join(t.TempDir(), "source.db"))
	if _, err := src.CreatePendingUser(ctx, "new@example.com", "New", "admin"); err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	snapPath, err := Snapshot(ctx, src.DB(), t.TempDir(), time.Date(2026, 7, 27, 14, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("closing the source database: %v", err)
	}

	if err := Restore(snapPath, dbPath); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	matches, err := filepath.Glob(dbPath + ".replaced-*")
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("found %d %s.replaced-* files, want exactly 1: %v", len(matches), dbPath, matches)
	}

	// The kept-aside file must be a copy of the ORIGINAL database (deletion
	// is not an option -- restoring the wrong snapshot at 2am must not cost
	// the operator their last copy), not a second copy of the snapshot.
	old, err := store.Open(matches[0])
	if err != nil {
		t.Fatalf("opening the replaced database: %v", err)
	}
	defer old.Close()
	if _, err := old.UserByEmail(ctx, "old@example.com"); err != nil {
		t.Fatalf("the replaced database does not contain the pre-restore row: %v", err)
	}
	if _, err := old.UserByEmail(ctx, "new@example.com"); err == nil {
		t.Error("the replaced database contains the post-restore row; it is a copy of the snapshot, not the original")
	}
}

// TestRestoreRefusesASnapshotThatOpensButFailsIntegrityCheck exists because
// a plain garbage file or an empty file is refused by verifySnapshot no
// matter which query runs first: SQLite reports "file is not a database"
// on the very first query against it, whether that query is
// PRAGMA integrity_check or the schema_migrations lookup. Neither of those
// two tests can tell "Restore runs integrity_check" apart from "Restore
// only confirms schema_migrations exists" -- both checks reject them for
// the same underlying reason.
//
// This test builds a snapshot that IS a well-formed, openable SQLite
// database with a completely legitimate schema_migrations table -- so the
// schema check alone would accept it -- but with one data page deep in an
// unrelated table corrupted so PRAGMA integrity_check specifically detects
// it. That is the actual case integrity_check exists to catch: a download
// that landed mostly intact but got mangled partway through.
func TestRestoreRefusesASnapshotThatOpensButFailsIntegrityCheck(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "keyhole.db")

	live := openMigratedStore(t, dbPath)
	if _, err := live.CreatePendingUser(ctx, "keep@example.com", "Keep", "admin"); err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	if err := live.Close(); err != nil {
		t.Fatalf("closing the live database before restore: %v", err)
	}

	// Build a source database with enough item rows to span many pages, so
	// there is a data page to corrupt that a schema_migrations-only check
	// would never visit.
	src := openMigratedStore(t, filepath.Join(t.TempDir(), "source.db"))
	owner, err := src.CreatePendingUser(ctx, "owner@example.com", "Owner", "admin")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	filler := strings.Repeat("x", 300)
	for i := 0; i < 500; i++ {
		if _, err := src.CreateItem(ctx, owner.ID, store.ItemInput{
			Ciphertext:     fmt.Sprintf("cipher-%d-%s", i, filler),
			WrappedItemKey: "wk",
		}); err != nil {
			t.Fatalf("CreateItem #%d: %v", i, err)
		}
	}
	var pageSize int
	if err := src.DB().QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
		t.Fatalf("PRAGMA page_size: %v", err)
	}
	snapPath, err := Snapshot(ctx, src.DB(), t.TempDir(), time.Now())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("closing source database: %v", err)
	}

	corrupted := corruptADeepDataPage(t, snapPath, pageSize)

	if err := Restore(corrupted, dbPath); err == nil {
		t.Fatal("Restore accepted a snapshot with a corrupted data page deep in the file")
	}

	reopened, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("the original database no longer opens after the refused restore: %v", err)
	}
	defer reopened.Close()
	if _, err := reopened.UserByEmail(ctx, "keep@example.com"); err != nil {
		t.Fatalf("the original row is gone after the refused restore: %v", err)
	}
}

// corruptADeepDataPage copies path into a fresh file with one page's
// leading (page-type) byte flipped, searching forward from page 5 -- past
// the early pages holding sqlite_master and schema_migrations -- for the
// first page where doing so breaks PRAGMA integrity_check while leaving a
// plain "does schema_migrations exist" lookup unaffected. That combination
// is what makes the resulting file distinguish the two checks; an
// arbitrary byte flip usually lands in unused space and breaks neither.
func corruptADeepDataPage(t *testing.T, path string, pageSize int) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	for page := 5; page*pageSize < len(data); page++ {
		offset := page * pageSize
		candidate := append([]byte(nil), data...)
		candidate[offset] = 0xFF

		out := filepath.Join(t.TempDir(), fmt.Sprintf("corrupt-page-%d.db", page))
		if err := os.WriteFile(out, candidate, 0o600); err != nil {
			t.Fatalf("write %s: %v", out, err)
		}

		if hasSchemaMigrationsTable(t, out) && failsIntegrityCheck(t, out) {
			return out
		}
	}

	t.Fatal("could not find a page whose corruption fails integrity_check without breaking the schema_migrations lookup")
	return ""
}

func hasSchemaMigrationsTable(t *testing.T, path string) bool {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return false
	}
	defer db.Close()
	var name string
	err = db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`,
	).Scan(&name)
	return err == nil
}

func failsIntegrityCheck(t *testing.T, path string) bool {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return true
	}
	defer db.Close()
	var result string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		return true
	}
	return result != "ok"
}
