package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ssan9876/keyhole/internal/backup"
	"github.com/ssan9876/keyhole/internal/config"
	_ "modernc.org/sqlite" // pure-Go driver, registered as "sqlite"
)

const restoreUsage = "usage: keyhole restore <file> [--config PATH]"

func runRestore(args []string) error {
	snapshotPath, configPath, err := parseRestoreArgs(args)
	if err != nil {
		return err
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	dbPath := cfg.DBPath()

	if err := refuseIfLocked(dbPath); err != nil {
		return err
	}

	if err := backup.Restore(snapshotPath, dbPath); err != nil {
		return err
	}

	fmt.Printf("Restored %s to %s\n", snapshotPath, dbPath)
	return nil
}

// parseRestoreArgs is a small hand-rolled parser rather than flag.FlagSet,
// because the documented usage is "keyhole restore <file> [--config PATH]"
// — the positional file argument before the flag — and the standard flag
// package stops parsing at the first non-flag token, silently swallowing
// --config into the positional args when the file comes first. An operator
// restoring at 2am is exactly who should not have to remember flag
// ordering, so this accepts --config on either side of the file argument.
func parseRestoreArgs(args []string) (snapshotPath, configPath string, err error) {
	configPath = defaultConfigPath
	var positional []string

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-config" || a == "--config":
			i++
			if i >= len(args) {
				return "", "", errors.New("--config requires a value")
			}
			configPath = args[i]
		case a == "-h" || a == "--help" || a == "help":
			return "", "", errors.New(restoreUsage)
		case strings.HasPrefix(a, "-"):
			return "", "", fmt.Errorf("unknown flag %q\n%s", a, restoreUsage)
		default:
			positional = append(positional, a)
		}
	}

	if len(positional) != 1 {
		return "", "", errors.New(restoreUsage)
	}
	return positional[0], configPath, nil
}

// refuseIfLocked reports an error if dbPath is currently open by another
// process, i.e. the server.
//
// Restore replaces the database file wholesale. Doing that while the server
// still holds it open leaves the server serving from a handle to a file that
// no longer has the name anyone else can find it under, and the operator
// ends up debugging what looks like data loss instead of being told the one
// thing that actually fixes it: stop the service first.
//
// PRAGMA locking_mode=EXCLUSIVE only takes effect on the next read or write,
// so a real write is what forces SQLite to actually attempt the exclusive
// lock; a no-op CREATE/DROP of a scratch table is used because the database
// is about to be replaced entirely regardless of whether this check passes.
func refuseIfLocked(dbPath string) error {
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		// Nothing to lock: a first-ever restore into an empty data directory.
		return nil
	} else if err != nil {
		return fmt.Errorf("stat %s: %w", dbPath, err)
	}

	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(200)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open %s to check for a lock: %w", dbPath, err)
	}
	defer db.Close()

	lockedErr := func(cause error) error {
		return fmt.Errorf(
			"%s is in use by another process (likely the keyhole server); stop the service before restoring: %w",
			dbPath, cause)
	}

	if _, err := db.Exec("PRAGMA locking_mode=EXCLUSIVE"); err != nil {
		return lockedErr(err)
	}
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS keyhole_restore_lock_probe (x)"); err != nil {
		return lockedErr(err)
	}
	if _, err := db.Exec("DROP TABLE keyhole_restore_lock_probe"); err != nil {
		return lockedErr(err)
	}
	return nil
}
