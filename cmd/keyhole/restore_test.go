package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ssan9876/keyhole/internal/backup"
	"github.com/ssan9876/keyhole/internal/store"
)

func TestRestoreReplacesTheConfiguredDatabase(t *testing.T) {
	configPath, cfg := tempConfig(t)
	if err := runMigrate([]string{"--config", configPath}); err != nil {
		t.Fatalf("runMigrate: %v", err)
	}

	// Build a snapshot from an unrelated database with a distinguishable row.
	ctx := context.Background()
	src, err := store.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := src.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := src.CreatePendingUser(ctx, "restored@example.com", "Restored", "admin"); err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	snapPath, err := backup.Snapshot(ctx, src.DB(), t.TempDir(), time.Now())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("closing source database: %v", err)
	}

	if err := runRestore([]string{snapPath, "--config", configPath}); err != nil {
		t.Fatalf("runRestore: %v", err)
	}

	restored := openStore(t, cfg)
	if _, err := restored.UserByEmail(ctx, "restored@example.com"); err != nil {
		t.Fatalf("the snapshot's row is not present after restore: %v", err)
	}
}

// TestRestoreRefusesWhenTheDatabaseIsLockedByTheServer is the safety
// property in the CLI wrapper: Restore itself has no idea the server
// exists, so this check has to live here, and it has to actually attempt a
// write against the live handle rather than just look at whether the file
// is present.
func TestRestoreRefusesWhenTheDatabaseIsLockedByTheServer(t *testing.T) {
	configPath, cfg := tempConfig(t)
	if err := runMigrate([]string{"--config", configPath}); err != nil {
		t.Fatalf("runMigrate: %v", err)
	}

	// Stand in for the running server: a live, open handle on the
	// configured database, exactly what store.Open in cmd/keyhole/serve.go
	// produces.
	live, err := store.Open(cfg.DBPath())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = live.Close() })

	snapPath, err := backup.Snapshot(context.Background(), live.DB(), t.TempDir(), time.Now())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	err = runRestore([]string{snapPath, "--config", configPath})
	if err == nil {
		t.Fatal("runRestore succeeded while the server held the database open")
	}
	if !strings.Contains(err.Error(), "stop the service") {
		t.Errorf("error %q does not tell the operator to stop the service", err)
	}

	// The database must still be the live one, untouched -- verified by
	// reading from it, not just by the error being non-nil.
	if _, err := live.SchemaVersion(context.Background()); err != nil {
		t.Errorf("the live database handle is no longer usable after the refused restore: %v", err)
	}
}

func TestRestoreRequiresExactlyOneFileArgument(t *testing.T) {
	configPath, _ := tempConfig(t)

	if err := runRestore([]string{"--config", configPath}); err == nil {
		t.Error("runRestore succeeded with no snapshot file argument")
	}
	if err := runRestore([]string{"a.db", "b.db", "--config", configPath}); err == nil {
		t.Error("runRestore succeeded with two snapshot file arguments")
	}
}

// TestRestoreAcceptsConfigBeforeOrAfterTheFileArgument guards the reason
// parseRestoreArgs exists instead of flag.FlagSet: the documented usage is
// "keyhole restore <file> [--config PATH]", file first, and the standard
// flag package would otherwise swallow --config into the positional
// arguments whenever it follows the file.
func TestRestoreAcceptsConfigBeforeOrAfterTheFileArgument(t *testing.T) {
	fileFirst, configFirst := "snapshot.db", "config.yml"

	path1, cfg1, err := parseRestoreArgs([]string{fileFirst, "--config", configFirst})
	if err != nil {
		t.Fatalf("file-before-flag: %v", err)
	}
	if path1 != fileFirst || cfg1 != configFirst {
		t.Errorf("file-before-flag parsed (%q, %q), want (%q, %q)", path1, cfg1, fileFirst, configFirst)
	}

	path2, cfg2, err := parseRestoreArgs([]string{"--config", configFirst, fileFirst})
	if err != nil {
		t.Fatalf("flag-before-file: %v", err)
	}
	if path2 != fileFirst || cfg2 != configFirst {
		t.Errorf("flag-before-file parsed (%q, %q), want (%q, %q)", path2, cfg2, fileFirst, configFirst)
	}
}

func TestRestoreRejectsAnUnknownFlag(t *testing.T) {
	if _, _, err := parseRestoreArgs([]string{"snapshot.db", "--bogus"}); err == nil {
		t.Error("parseRestoreArgs accepted an unknown flag instead of reporting it")
	}
}
