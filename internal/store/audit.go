package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const (
	// defaultAuditPage is what a caller gets when it asks for nothing sensible.
	defaultAuditPage = 50
	// maxAuditPage bounds one response so a single request cannot pull the
	// whole table into memory.
	maxAuditPage = 200
)

// AuditEntry is one recorded administrative action. ActorUserID is nullable:
// the retention purge and the installer's first admin have no signed-in actor,
// and fabricating an attribution would be worse than recording none.
type AuditEntry struct {
	ID          string
	ActorUserID sql.NullString
	Action      string
	Target      string
	Metadata    string
	CreatedAt   time.Time
}

// AppendAudit records an action. An empty actorUserID stores NULL.
func (s *Store) AppendAudit(ctx context.Context, actorUserID, action, target, metadata string) error {
	return appendAudit(ctx, s.db, actorUserID, action, target, metadata)
}

// execer is satisfied by both *sql.DB and *sql.Tx, so an audit entry can be
// written inside the same transaction as the change it records.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func appendAudit(ctx context.Context, db execer, actorUserID, action, target, metadata string) error {
	id, err := NewID()
	if err != nil {
		return err
	}
	var actor sql.NullString
	if actorUserID != "" {
		actor = sql.NullString{String: actorUserID, Valid: true}
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO audit_log (id, actor_user_id, action, target, metadata, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, actor, action, target, metadata,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}
	return nil
}

// AuditPage returns entries newest first. beforeID is the id of the last entry
// the caller already has.
//
// The keyset is (created_at, id), not created_at alone: entries written in the
// same second share a timestamp, and a boundary that only compares timestamps
// would repeat or skip those rows. In an audit log a skipped row is an action
// an admin can look straight past.
func (s *Store) AuditPage(ctx context.Context, limit int, beforeID string) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = defaultAuditPage
	}
	if limit > maxAuditPage {
		limit = maxAuditPage
	}

	const columns = `id, actor_user_id, action, target, metadata, created_at`
	var rows *sql.Rows
	var err error

	if beforeID == "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT `+columns+` FROM audit_log
			 ORDER BY created_at DESC, id DESC
			 LIMIT ?`, limit)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT `+columns+` FROM audit_log
			 WHERE (created_at, id) < (SELECT created_at, id FROM audit_log WHERE id = ?)
			 ORDER BY created_at DESC, id DESC
			 LIMIT ?`, beforeID, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("select audit entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	entries := []AuditEntry{}
	for rows.Next() {
		var entry AuditEntry
		var createdAt string
		if err := rows.Scan(&entry.ID, &entry.ActorUserID, &entry.Action,
			&entry.Target, &entry.Metadata, &createdAt); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		if entry.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit entries: %w", err)
	}
	return entries, nil
}
