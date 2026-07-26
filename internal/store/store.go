// Package store owns SQLite access and the embedded schema migrations.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite" // pure-Go driver, registered as "sqlite"
)

type Store struct {
	db *sql.DB
}

// Open connects to the SQLite database at dbPath, creating it if absent.
//
// The pragmas are not optional decoration:
//   - foreign_keys is OFF by default in SQLite and is per-connection, so
//     without it every REFERENCES clause in the schema is documentation.
//   - WAL lets reads proceed during a write, which matters because sync reads
//     are the common case.
//   - busy_timeout turns "database is locked" from an error into a wait.
func Open(dbPath string) (*Store, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create database directory %s: %w", dir, err)
	}

	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", dbPath)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}

	// SQLite tolerates one writer. Capping the pool avoids a thundering herd
	// of writers all waiting on busy_timeout.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)

	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// DB exposes the handle for packages that build their own queries.
func (s *Store) DB() *sql.DB { return s.db }
