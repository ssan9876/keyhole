package store

import (
	"context"
	"database/sql"
	"fmt"
)

// nextRevision advances the shared sequence and returns the new value. It must
// be called inside the same transaction as the row it is numbering: the
// increment and the write then commit or roll back together, so a failed write
// never burns a revision the client would read as a change it missed.
//
// UPDATE-then-SELECT rather than RETURNING, because two statements inside one
// SQLite transaction are already atomic against a database that tolerates a
// single writer, and this needs no minimum SQLite version to be true.
func nextRevision(ctx context.Context, tx *sql.Tx) (int64, error) {
	if _, err := tx.ExecContext(ctx,
		`UPDATE revision_sequence SET value = value + 1 WHERE id = 1`); err != nil {
		return 0, fmt.Errorf("advance revision sequence: %w", err)
	}
	var value int64
	if err := tx.QueryRowContext(ctx,
		`SELECT value FROM revision_sequence WHERE id = 1`).Scan(&value); err != nil {
		return 0, fmt.Errorf("read revision sequence: %w", err)
	}
	return value, nil
}

// CurrentRevision is the high-water mark a sync response reports back to the
// client as its next cursor.
func (s *Store) CurrentRevision(ctx context.Context) (int64, error) {
	var value int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT value FROM revision_sequence WHERE id = 1`).Scan(&value); err != nil {
		return 0, fmt.Errorf("read revision sequence: %w", err)
	}
	return value, nil
}
