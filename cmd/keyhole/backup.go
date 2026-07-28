package main

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"github.com/ssan9876/keyhole/internal/backup"
	"github.com/ssan9876/keyhole/internal/config"
	"github.com/ssan9876/keyhole/internal/store"
)

// defaultBackupKeep is how many snapshots `keyhole backup` retains when
// --keep is not given. It is not zero: Prune(dir, 0) means "delete nothing,"
// so an operator who never passes --keep must still get bounded retention
// rather than an ever-growing backup directory.
const defaultBackupKeep = 14

func runBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config.yml")
	out := fs.String("out", "", "directory to write the snapshot into (default <data_dir>/backups)")
	keep := fs.Int("keep", defaultBackupKeep, "number of snapshots to retain; older ones are pruned (0 keeps them all)")
	// flag.ExitOnError means fs.Parse already calls os.Exit on a bad flag, so
	// there is no error here to handle.
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	dir := *out
	if dir == "" {
		dir = filepath.Join(cfg.DataDir, "backups")
	}

	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer st.Close()

	path, err := backup.Snapshot(context.Background(), st.DB(), dir, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %s\n", path)

	removed, err := backup.Prune(dir, *keep)
	if err != nil {
		return fmt.Errorf("snapshot written to %s, but pruning old snapshots failed: %w", path, err)
	}
	if len(removed) > 0 {
		fmt.Printf("Pruned %d old snapshot(s):\n", len(removed))
		for _, p := range removed {
			fmt.Printf("  %s\n", p)
		}
	}
	return nil
}
