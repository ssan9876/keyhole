package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Folder is a client-side grouping. The name is ciphertext; the server holds
// only the row and its owner. Folders draw from the same revision sequence as
// items so one sync cursor covers both.
type Folder struct {
	ID            string
	UserID        string
	EncryptedName string
	Revision      int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     sql.NullTime
}

const folderColumns = `id, user_id, encrypted_name, revision, created_at, updated_at, deleted_at`

func scanFolder(row interface{ Scan(...any) error }) (Folder, error) {
	var folder Folder
	var createdAt, updatedAt string
	var deletedAt sql.NullString

	err := row.Scan(&folder.ID, &folder.UserID, &folder.EncryptedName,
		&folder.Revision, &createdAt, &updatedAt, &deletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Folder{}, ErrNotFound
	}
	if err != nil {
		return Folder{}, fmt.Errorf("scan folder: %w", err)
	}
	if folder.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return Folder{}, fmt.Errorf("parse created_at: %w", err)
	}
	if folder.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt); err != nil {
		return Folder{}, fmt.Errorf("parse updated_at: %w", err)
	}
	if deletedAt.Valid {
		parsed, err := time.Parse(time.RFC3339, deletedAt.String)
		if err != nil {
			return Folder{}, fmt.Errorf("parse deleted_at: %w", err)
		}
		folder.DeletedAt = sql.NullTime{Time: parsed, Valid: true}
	}
	return folder, nil
}

func (s *Store) FolderByID(ctx context.Context, id string) (Folder, error) {
	return scanFolder(s.db.QueryRowContext(ctx,
		`SELECT `+folderColumns+` FROM folders WHERE id = ?`, id))
}

func (s *Store) CreateFolder(ctx context.Context, userID, encryptedName string) (Folder, error) {
	if encryptedName == "" {
		return Folder{}, &ValidationError{Field: "encryptedName"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Folder{}, fmt.Errorf("begin folder insert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// First statement, same reasoning as CreateItem/UpdateItem/DeleteItem: it
	// takes the write lock before any read snapshot is taken, so busy_timeout
	// applies if another writer is mid-transaction.
	revision, err := nextRevision(ctx, tx)
	if err != nil {
		return Folder{}, err
	}

	id, err := NewID()
	if err != nil {
		return Folder{}, err
	}
	// Truncated to the second: RFC3339 storage has no sub-second resolution, and
	// an untruncated value here would disagree with what a later read produces.
	now := time.Now().UTC().Truncate(time.Second)
	stamp := now.Format(time.RFC3339)

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO folders (id, user_id, encrypted_name, revision, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, userID, encryptedName, revision, stamp, stamp); err != nil {
		return Folder{}, fmt.Errorf("insert folder: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Folder{}, fmt.Errorf("commit folder insert: %w", err)
	}

	return Folder{
		ID: id, UserID: userID, EncryptedName: encryptedName,
		Revision: revision, CreatedAt: now, UpdatedAt: now,
	}, nil
}

// UpdateFolder renames a folder under the same optimistic check items use, and
// returns the current row alongside ErrRevisionConflict when it loses.
func (s *Store) UpdateFolder(ctx context.Context, id string, expectedRevision int64, encryptedName string) (Folder, error) {
	if encryptedName == "" {
		return Folder{}, &ValidationError{Field: "encryptedName"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Folder{}, fmt.Errorf("begin folder update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// nextRevision MUST be the first statement in this transaction, not after
	// the SELECT as the brief's listing shows. BeginTx opens a deferred
	// transaction: a SELECT taken first grabs a WAL read snapshot, and if
	// another connection commits before this transaction's first write, that
	// write fails with SQLITE_BUSY_SNAPSHOT — a code the busy handler does NOT
	// retry, so busy_timeout(5000) never applies. Task 1 hit this directly: 11
	// of 12 concurrent item writes failed until nextRevision moved to the top.
	// The deferred Rollback below discards the increment on every not-found and
	// conflict path, so nothing leaks from bumping early.
	revision, err := nextRevision(ctx, tx)
	if err != nil {
		return Folder{}, err
	}

	current, err := scanFolder(tx.QueryRowContext(ctx,
		`SELECT `+folderColumns+` FROM folders WHERE id = ?`, id))
	if err != nil {
		return Folder{}, err
	}
	if current.DeletedAt.Valid {
		return Folder{}, ErrNotFound
	}
	if current.Revision != expectedRevision {
		return current, ErrRevisionConflict
	}

	now := time.Now().UTC().Truncate(time.Second)

	result, err := tx.ExecContext(ctx,
		`UPDATE folders SET encrypted_name = ?, revision = ?, updated_at = ?
		 WHERE id = ? AND revision = ? AND deleted_at IS NULL`,
		encryptedName, revision, now.Format(time.RFC3339), id, expectedRevision)
	if err != nil {
		return Folder{}, fmt.Errorf("update folder: %w", err)
	}
	// The in-transaction SELECT above guarantees a match today, so this is a
	// guard against a future edit to either the SELECT or the WHERE clause
	// silently diverging. See requireOneRow in items.go for the same guard on
	// item writes.
	if err := requireOneRow(result, "update folder"); err != nil {
		return Folder{}, err
	}
	if err := tx.Commit(); err != nil {
		return Folder{}, fmt.Errorf("commit folder update: %w", err)
	}

	current.EncryptedName = encryptedName
	current.Revision = revision
	current.UpdatedAt = now
	return current, nil
}

// DeleteFolder tombstones the folder and destroys its encrypted name. Items
// are not touched: folder membership lives inside each item's encrypted body,
// so the client reconciles orphaned items after it decrypts them.
func (s *Store) DeleteFolder(ctx context.Context, id string) (Folder, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Folder{}, fmt.Errorf("begin folder delete: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// First statement, for the same reason as UpdateFolder: taking the write
	// lock before any read snapshot avoids SQLITE_BUSY_SNAPSHOT, which the busy
	// handler does not retry. This deviates from the brief's listing, which
	// shows nextRevision after the SELECT.
	revision, err := nextRevision(ctx, tx)
	if err != nil {
		return Folder{}, err
	}

	current, err := scanFolder(tx.QueryRowContext(ctx,
		`SELECT `+folderColumns+` FROM folders WHERE id = ?`, id))
	if err != nil {
		return Folder{}, err
	}
	if current.DeletedAt.Valid {
		return Folder{}, ErrNotFound
	}

	now := time.Now().UTC().Truncate(time.Second)
	stamp := now.Format(time.RFC3339)

	result, err := tx.ExecContext(ctx,
		`UPDATE folders SET encrypted_name = '', revision = ?, updated_at = ?, deleted_at = ?
		 WHERE id = ? AND deleted_at IS NULL`,
		revision, stamp, stamp, id)
	if err != nil {
		return Folder{}, fmt.Errorf("delete folder: %w", err)
	}
	if err := requireOneRow(result, "delete folder"); err != nil {
		return Folder{}, err
	}
	if err := tx.Commit(); err != nil {
		return Folder{}, fmt.Errorf("commit folder delete: %w", err)
	}

	current.EncryptedName = ""
	current.Revision = revision
	current.UpdatedAt = now
	current.DeletedAt = sql.NullTime{Time: now, Valid: true}
	return current, nil
}
