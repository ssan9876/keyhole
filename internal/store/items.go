package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Item mirrors the items table. CollectionID is NULL for a personal item;
// a non-NULL value moves visibility from the owner to that collection's
// members. There is deliberately no type column and no folder column — both
// live inside the encrypted body, so the server cannot tell a login from a
// note or see which items are grouped together.
type Item struct {
	ID             string
	OwnerUserID    string
	CollectionID   sql.NullString
	Ciphertext     string
	WrappedItemKey string
	Revision       int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      sql.NullTime
}

// ItemInput is what a client uploads. Both blobs are opaque: the server checks
// they are present and stores them byte for byte.
//
// CollectionID is a pointer because "not supplied" and "supplied as empty" have
// to be distinguishable. A plain string cannot tell them apart, and the
// indistinguishable case is a data-loss bug: a client that PUTs a new body
// without echoing collectionId would silently move a shared item back to
// personal, and every other member's next sync would drop it with no error.
//
//   - nil means "no opinion": a personal item on create, and no change to the
//     item's sharing on update.
//   - a non-nil pointer is an explicit statement of intent and must name a
//     collection. A pointer to "" is neither, so it is rejected rather than
//     guessed at.
type ItemInput struct {
	CollectionID   *string
	Ciphertext     string
	WrappedItemKey string
}

func (in ItemInput) validate() error {
	if in.Ciphertext == "" {
		return &ValidationError{Field: "ciphertext"}
	}
	if in.WrappedItemKey == "" {
		return &ValidationError{Field: "wrappedItemKey"}
	}
	if in.CollectionID != nil && *in.CollectionID == "" {
		return &ValidationError{
			Field:   "collectionId",
			Message: "must name a collection; omit it entirely to leave the item personal",
		}
	}
	return nil
}

func (in ItemInput) collection() sql.NullString {
	if in.CollectionID == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *in.CollectionID, Valid: true}
}

// requireOneRow turns a guarded UPDATE that matched nothing into an error
// instead of a silent success. Both item writes select the row inside their own
// transaction first, so a mismatch is not reachable today — which is exactly
// why it needs a check: if it ever becomes reachable, the failure mode is a
// committed transaction that burned a revision, changed no row, and returned a
// struct describing a write that did not happen.
func requireOneRow(result sql.Result, what string) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: rows affected: %w", what, err)
	}
	if affected != 1 {
		return fmt.Errorf("%s: %d rows affected, want 1", what, affected)
	}
	return nil
}

const itemColumns = `id, owner_user_id, collection_id, ciphertext,
	wrapped_item_key, revision, created_at, updated_at, deleted_at`

// scanItem parses the RFC3339 TEXT timestamps by hand. sql.NullTime cannot
// scan a TEXT column under modernc's driver — it fails with "unsupported
// Scan, storing driver.Value type string into type *time.Time" — and a
// deleted_at that cannot be scanned is a tombstone that never syncs.
func scanItem(row interface{ Scan(...any) error }) (Item, error) {
	var item Item
	var createdAt, updatedAt string
	var deletedAt sql.NullString

	err := row.Scan(&item.ID, &item.OwnerUserID, &item.CollectionID,
		&item.Ciphertext, &item.WrappedItemKey, &item.Revision,
		&createdAt, &updatedAt, &deletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Item{}, ErrNotFound
	}
	if err != nil {
		return Item{}, fmt.Errorf("scan item: %w", err)
	}
	if item.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return Item{}, fmt.Errorf("parse created_at: %w", err)
	}
	if item.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt); err != nil {
		return Item{}, fmt.Errorf("parse updated_at: %w", err)
	}
	if deletedAt.Valid {
		parsed, err := time.Parse(time.RFC3339, deletedAt.String)
		if err != nil {
			return Item{}, fmt.Errorf("parse deleted_at: %w", err)
		}
		item.DeletedAt = sql.NullTime{Time: parsed, Valid: true}
	}
	return item, nil
}

func (s *Store) ItemByID(ctx context.Context, id string) (Item, error) {
	return scanItem(s.db.QueryRowContext(ctx,
		`SELECT `+itemColumns+` FROM items WHERE id = ?`, id))
}

// CreateItem stores one item. The revision and the row commit together, so a
// client can never read a revision whose row is not there yet.
func (s *Store) CreateItem(ctx context.Context, ownerUserID string, in ItemInput) (Item, error) {
	items, err := s.CreateItemsBulk(ctx, ownerUserID, []ItemInput{in})
	if err != nil {
		return Item{}, err
	}
	return items[0], nil
}

// CreateItemsBulk writes a whole batch in one transaction. An import that
// half-lands leaves the user unable to tell which half arrived, so validation
// runs over every row before any row is written.
func (s *Store) CreateItemsBulk(ctx context.Context, ownerUserID string, ins []ItemInput) ([]Item, error) {
	if len(ins) == 0 {
		return nil, &ValidationError{Field: "items"}
	}
	for _, in := range ins {
		if err := in.validate(); err != nil {
			return nil, err
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin item insert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339)
	items := make([]Item, 0, len(ins))

	for _, in := range ins {
		id, err := NewID()
		if err != nil {
			return nil, err
		}
		revision, err := nextRevision(ctx, tx)
		if err != nil {
			return nil, err
		}
		collection := in.collection()

		if _, err := tx.ExecContext(ctx,
			`INSERT INTO items (id, owner_user_id, collection_id, ciphertext,
				wrapped_item_key, revision, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			id, ownerUserID, collection, in.Ciphertext, in.WrappedItemKey,
			revision, stamp, stamp); err != nil {
			return nil, fmt.Errorf("insert item: %w", err)
		}

		items = append(items, Item{
			ID: id, OwnerUserID: ownerUserID, CollectionID: collection,
			Ciphertext: in.Ciphertext, WrappedItemKey: in.WrappedItemKey,
			Revision: revision, CreatedAt: now, UpdatedAt: now,
		})
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit item insert: %w", err)
	}
	return items, nil
}

// UpdateItem replaces an item's body if, and only if, expectedRevision is
// still the stored one.
//
// On a conflict it returns the CURRENT row alongside ErrRevisionConflict. That
// row is what lets the client keep both edits: it has its own losing version in
// memory and now has the winner, so it can write a conflicted copy. Discarding
// either one is the data loss spec section 9 forbids.
func (s *Store) UpdateItem(ctx context.Context, id string, expectedRevision int64, in ItemInput) (Item, error) {
	if err := in.validate(); err != nil {
		return Item{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Item{}, fmt.Errorf("begin item update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// The revision bump is deliberately the FIRST statement. BeginTx opens a
	// deferred transaction: a SELECT would take a WAL read snapshot, and if
	// another connection commits before this transaction's first write, SQLite
	// fails that write with SQLITE_BUSY_SNAPSHOT — a code for which the busy
	// handler is NOT invoked, so busy_timeout(5000) never applies. Writing
	// first takes the write lock up front, where busy_timeout does apply.
	//
	// Nothing is leaked by bumping early: the deferred Rollback below discards
	// the increment on every not-found and conflict path.
	revision, err := nextRevision(ctx, tx)
	if err != nil {
		return Item{}, err
	}

	current, err := scanItem(tx.QueryRowContext(ctx,
		`SELECT `+itemColumns+` FROM items WHERE id = ?`, id))
	if err != nil {
		return Item{}, err
	}
	// A tombstone is gone, not stale. Reporting it as a conflict would invite
	// the client to "resolve" it by re-uploading the item it just deleted.
	if current.DeletedAt.Valid {
		return Item{}, ErrNotFound
	}
	if current.Revision != expectedRevision {
		return current, ErrRevisionConflict
	}

	now := time.Now().UTC()

	// collection_id is written only when the client said something about it.
	// Writing it unconditionally makes a body-only edit un-share the item, and
	// the owner never sees an error — the other members' items simply vanish on
	// their next sync.
	setCollection := ""
	args := []any{in.Ciphertext, in.WrappedItemKey, revision, now.Format(time.RFC3339)}
	if in.CollectionID != nil {
		setCollection = "collection_id = ?, "
		args = append([]any{in.collection()}, args...)
	}
	args = append(args, id, expectedRevision)

	result, err := tx.ExecContext(ctx,
		`UPDATE items SET `+setCollection+`ciphertext = ?, wrapped_item_key = ?,
			revision = ?, updated_at = ?
		 WHERE id = ? AND revision = ? AND deleted_at IS NULL`, args...)
	if err != nil {
		return Item{}, fmt.Errorf("update item: %w", err)
	}
	// The in-transaction SELECT above guarantees a match today, so this is a
	// guard against a future edit to either the SELECT or the WHERE clause
	// silently diverging. Committing a zero-row update would burn a revision
	// and hand the client a success struct describing a row that never changed.
	if err := requireOneRow(result, "update item"); err != nil {
		return Item{}, err
	}

	if err := tx.Commit(); err != nil {
		return Item{}, fmt.Errorf("commit item update: %w", err)
	}

	if in.CollectionID != nil {
		current.CollectionID = in.collection()
	}
	current.Ciphertext = in.Ciphertext
	current.WrappedItemKey = in.WrappedItemKey
	current.Revision = revision
	current.UpdatedAt = now
	return current, nil
}

// DeleteItem tombstones the row and destroys its contents. The row survives
// only so other devices learn the item is gone; the ciphertext and the wrapped
// key are cleared, because a delete that leaves the data readable in the
// database is not a delete.
func (s *Store) DeleteItem(ctx context.Context, id string) (Item, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Item{}, fmt.Errorf("begin item delete: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// First statement, for the same reason as UpdateItem: a deferred
	// transaction whose first statement is a SELECT takes a read snapshot and
	// then fails its first write with SQLITE_BUSY_SNAPSHOT, which the busy
	// handler does not retry. The deferred Rollback discards the increment on
	// the not-found path.
	revision, err := nextRevision(ctx, tx)
	if err != nil {
		return Item{}, err
	}

	current, err := scanItem(tx.QueryRowContext(ctx,
		`SELECT `+itemColumns+` FROM items WHERE id = ?`, id))
	if err != nil {
		return Item{}, err
	}
	// Already a tombstone. Re-deleting would burn a revision and rebroadcast a
	// tombstone every client already holds.
	if current.DeletedAt.Valid {
		return Item{}, ErrNotFound
	}

	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339)

	result, err := tx.ExecContext(ctx,
		`UPDATE items SET ciphertext = '', wrapped_item_key = '',
			revision = ?, updated_at = ?, deleted_at = ?
		 WHERE id = ? AND deleted_at IS NULL`,
		revision, stamp, stamp, id)
	if err != nil {
		return Item{}, fmt.Errorf("delete item: %w", err)
	}
	// See UpdateItem: a zero-row delete that commits would report a tombstone
	// the database does not have, and the client would stop showing an item
	// that is still there.
	if err := requireOneRow(result, "delete item"); err != nil {
		return Item{}, err
	}

	if err := tx.Commit(); err != nil {
		return Item{}, fmt.Errorf("commit item delete: %w", err)
	}

	current.Ciphertext = ""
	current.WrappedItemKey = ""
	current.Revision = revision
	current.UpdatedAt = now
	current.DeletedAt = sql.NullTime{Time: now, Valid: true}
	return current, nil
}
