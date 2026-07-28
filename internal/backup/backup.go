// Package backup snapshots and restores the Keyhole database.
//
// Every snapshot is ciphertext: item bodies, names, and URLs are encrypted
// under keys the server has never held. That is what makes off-box
// replication to somewhere less trusted a reasonable thing to do, and it is
// worth saying out loud because it is unusual.
package backup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, registered as "sqlite"
)

const snapshotPrefix = "keyhole-"
const snapshotSuffix = ".db"

// snapshotTimeFormat is UTC and second-precision, so names sort
// chronologically by construction (e.g. "keyhole-20260727T143000Z.db"). That
// is what turns Prune into a sort and a slice rather than a date parser.
const snapshotTimeFormat = "20060102T150405Z"

// Snapshot writes a consistent copy of db into dir without stopping the
// server. VACUUM INTO takes its own read transaction, so a write landing
// mid-copy cannot produce a torn file.
func Snapshot(ctx context.Context, db *sql.DB, dir string, at time.Time) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	name := snapshotPrefix + at.UTC().Format(snapshotTimeFormat) + snapshotSuffix
	path := filepath.Join(dir, name)

	// VACUUM INTO fails on an existing target, but checking first turns a
	// driver-specific error into one that names the file -- and guarantees
	// two backups taken in the same second leave exactly one snapshot rather
	// than a torn write racing the check inside SQLite itself.
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("snapshot %s already exists", path)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("stat %s: %w", path, err)
	}

	// VACUUM INTO takes no bind parameters, so the path is interpolated.
	// Doubling any single quote is what keeps a directory named e.g. "Seth's
	// backups" from ending the string literal early.
	quoted := "'" + strings.ReplaceAll(path, "'", "''") + "'"
	if _, err := db.ExecContext(ctx, "VACUUM INTO "+quoted); err != nil {
		return "", fmt.Errorf("vacuum into %s: %w", path, err)
	}
	return path, nil
}

// Prune deletes snapshots in dir past the keep most recent, returning the
// paths it removed.
//
// This is a delete loop pointed at an operator-specified directory: only
// entries matching the snapshotPrefix/snapshotSuffix shape this package
// itself writes are ever candidates, because that filter is the only thing
// standing between this function and a stray file of the operator's own.
//
// keep <= 0 deletes nothing. A missing --keep on the CLI must never be
// misread as "keep none" -- it means "use the default."
func Prune(dir string, keep int) ([]string, error) {
	if keep <= 0 {
		return nil, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read backup directory: %w", err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, snapshotPrefix) && strings.HasSuffix(name, snapshotSuffix) {
			names = append(names, name)
		}
	}

	// Names sort chronologically by construction, so newest-first is a
	// reverse lexical sort, not a date parse.
	sort.Sort(sort.Reverse(sort.StringSlice(names)))

	if len(names) <= keep {
		return nil, nil
	}

	removed := make([]string, 0, len(names)-keep)
	for _, name := range names[keep:] {
		path := filepath.Join(dir, name)
		if err := os.Remove(path); err != nil {
			return removed, fmt.Errorf("remove %s: %w", path, err)
		}
		removed = append(removed, path)
	}
	return removed, nil
}

// Restore replaces the database at dbPath with the contents of snapshotPath.
//
// This overwrites the live database, so every step exists to catch a
// mistake before it becomes permanent:
//
//  1. Open the snapshot read-only and run PRAGMA integrity_check, so a
//     truncated download is caught before it becomes the live database.
//  2. Confirm the file has a schema_migrations table, so restoring some
//     unrelated SQLite file fails loudly instead of silently swapping in
//     junk.
//  3. Rename the existing database aside to keyhole.db.replaced-<stamp>
//     rather than deleting it -- restoring the wrong snapshot is a mistake
//     an operator makes at 2am, and it must not cost them their last copy.
//  4. Copy the snapshot into place at 0o600, then fsync the file and the
//     directory.
//  5. Remove any stale -wal/-shm files beside the old database: leaving them
//     applies a journal belonging to a database that no longer exists.
func Restore(snapshotPath, dbPath string) error {
	if err := verifySnapshot(snapshotPath); err != nil {
		return err
	}

	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create database directory: %w", err)
	}

	if _, err := os.Stat(dbPath); err == nil {
		replaced, err := replacedPath(dbPath)
		if err != nil {
			return err
		}
		if err := os.Rename(dbPath, replaced); err != nil {
			return fmt.Errorf("move existing database aside to %s: %w", replaced, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", dbPath, err)
	}

	if err := copyFileFsync(snapshotPath, dbPath); err != nil {
		return err
	}

	// Any -wal/-shm sitting beside dbPath belonged to the database that was
	// just renamed away; applying them to the freshly-restored file would
	// replay writes from a database that no longer exists at this path.
	for _, suffix := range []string{"-wal", "-shm"} {
		stale := dbPath + suffix
		if err := os.Remove(stale); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale %s: %w", stale, err)
		}
	}

	return nil
}

// replacedPath picks the "moved aside" name for dbPath, walking forward a
// second at a time in the exceedingly unlikely case two restores land in the
// same second: the point of keeping the old database at all is to never
// lose it, so silently overwriting an earlier replaced-<stamp> would defeat
// that.
func replacedPath(dbPath string) (string, error) {
	stamp := time.Now().UTC()
	for i := 0; i < 60; i++ {
		candidate := dbPath + ".replaced-" + stamp.Add(time.Duration(i)*time.Second).Format(snapshotTimeFormat)
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate, nil
		} else if err != nil {
			return "", fmt.Errorf("stat %s: %w", candidate, err)
		}
	}
	return "", fmt.Errorf("could not find a free keyhole.db.replaced-* name beside %s", dbPath)
}

// verifySnapshot opens path read-only and checks that it is an intact
// SQLite database that looks like a Keyhole database, without ever touching
// the live database. Both checks happen before Restore does anything
// destructive.
func verifySnapshot(path string) error {
	// mode=ro is load-bearing: without it, a missing or unreadable path
	// would be silently created as a fresh empty database instead of
	// failing the checks below.
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open snapshot %s: %w", path, err)
	}
	defer db.Close()

	var result string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		return fmt.Errorf("%s does not look like a usable SQLite database: %w", path, err)
	}
	if result != "ok" {
		return fmt.Errorf("%s failed integrity_check: %s", path, result)
	}

	var name string
	err = db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`,
	).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%s has no schema_migrations table; it does not look like a keyhole database", path)
	}
	if err != nil {
		return fmt.Errorf("check %s for schema_migrations: %w", path, err)
	}
	return nil
}

// copyFileFsync copies src to dst at mode 0o600, then fsyncs the file and
// (where supported) its directory so the write is durable before Restore
// reports success.
func copyFileFsync(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("copy %s into place: %w", dst, err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return fmt.Errorf("fsync %s: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dst, err)
	}

	return fsyncDir(filepath.Dir(dst))
}

// fsyncDir fsyncs a directory so a preceding create/rename inside it is
// durable, not just the file's own contents -- an idiom ext4 and friends
// need to guarantee the directory entry itself survives a crash.
//
// Windows has no equivalent: opening a directory with os.Open succeeds (it
// can be listed), but *os.File.Sync on it fails because the underlying
// handle was not opened for the kind of access FlushFileBuffers needs. NTFS
// journals metadata operations itself, so a directory-entry fsync is not
// needed there for the same durability guarantee, and this is a deliberate
// no-op on that platform rather than a masked error.
func fsyncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open %s for fsync: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync %s: %w", dir, err)
	}
	return nil
}
