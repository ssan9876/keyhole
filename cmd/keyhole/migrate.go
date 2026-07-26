package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/ssan9876/keyhole/internal/config"
	"github.com/ssan9876/keyhole/internal/store"
)

const defaultConfigPath = "/etc/keyhole/config.yml"

func runMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config.yml")
	// flag.ExitOnError means fs.Parse already calls os.Exit on a bad flag, so
	// there is no error here to handle.
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := context.Background()
	before, err := st.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	after, err := st.SchemaVersion(ctx)
	if err != nil {
		return err
	}

	if before == after {
		fmt.Printf("Schema already at version %d; nothing to do.\n", after)
	} else {
		fmt.Printf("Migrated schema %d -> %d.\n", before, after)
	}
	return nil
}
