package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupWritesASnapshotUnderTheDefaultOutDirectory(t *testing.T) {
	configPath, cfg := tempConfig(t)
	if err := runMigrate([]string{"--config", configPath}); err != nil {
		t.Fatalf("runMigrate: %v", err)
	}

	if err := runBackup([]string{"--config", configPath}); err != nil {
		t.Fatalf("runBackup: %v", err)
	}

	defaultDir := filepath.Join(cfg.DataDir, "backups")
	entries, err := os.ReadDir(defaultDir)
	if err != nil {
		t.Fatalf("default backup directory %s was not created: %v", defaultDir, err)
	}
	if len(entries) != 1 {
		t.Fatalf("backup directory has %d entries, want 1: %v", len(entries), entries)
	}
}

func TestBackupHonorsTheOutFlag(t *testing.T) {
	configPath, cfg := tempConfig(t)
	if err := runMigrate([]string{"--config", configPath}); err != nil {
		t.Fatalf("runMigrate: %v", err)
	}

	customDir := filepath.Join(t.TempDir(), "elsewhere")
	if err := runBackup([]string{"--config", configPath, "--out", customDir}); err != nil {
		t.Fatalf("runBackup: %v", err)
	}

	entries, err := os.ReadDir(customDir)
	if err != nil {
		t.Fatalf("--out directory %s was not created: %v", customDir, err)
	}
	if len(entries) != 1 {
		t.Errorf("--out directory has %d entries, want 1", len(entries))
	}

	// The default directory must NOT also have gained a snapshot: --out
	// replaces the default location rather than adding to it.
	defaultDir := filepath.Join(cfg.DataDir, "backups")
	if _, err := os.Stat(defaultDir); err == nil {
		t.Errorf("a backup was also written under the default directory %s despite --out", defaultDir)
	}
}

// TestBackupPrunesDownToKeep is the test that actually proves --keep is
// wired to Prune rather than merely parsed and discarded: three backups a
// second apart, run with --keep 2 each time, must leave exactly 2 files.
func TestBackupPrunesDownToKeep(t *testing.T) {
	configPath, cfg := tempConfig(t)
	if err := runMigrate([]string{"--config", configPath}); err != nil {
		t.Fatalf("runMigrate: %v", err)
	}
	dir := filepath.Join(cfg.DataDir, "backups")

	for i := 0; i < 3; i++ {
		if err := runBackup([]string{"--config", configPath, "--keep", "2"}); err != nil {
			t.Fatalf("runBackup #%d: %v", i, err)
		}
		if i < 2 {
			// Snapshot names are second-precision; without this the second
			// and third backup in the same wall-clock second would collide
			// and runBackup would fail on the "already exists" guard rather
			// than exercising retention.
			time.Sleep(1100 * time.Millisecond)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 2 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("backup directory has %d entries after 3 backups with --keep 2, want 2: %v", len(entries), names)
	}
}
