package store

import (
	"context"
	"database/sql"
	"fmt"
)

// SyncResult is everything a client needs to bring itself up to date.
// Collections join it in Task 4 — they are sent in full rather than
// incrementally, so they do not participate in the cursor.
type SyncResult struct {
	// Revision is the cursor to send on the next sync. It is read inside the
	// same transaction as the rows, so it can never be ahead of what was
	// returned.
	Revision int64
	Items    []Item
	Folders  []Folder
}

// visibleItemsClause is the one definition of what a user may see: their own
// personal items, plus every item in every collection they belong to. It lives
// in one place because a divergence between the sync query and the
// single-item access check is exactly how one user ends up reading another's
// vault. It takes the user id twice.
const visibleItemsClause = `(
	(owner_user_id = ? AND collection_id IS NULL)
	OR collection_id IN (SELECT collection_id FROM collection_memberships WHERE user_id = ?)
)`

// SyncSince returns every item and folder visible to userID that changed after
// the given revision, tombstones included.
//
// It all happens inside one transaction. The cursor is read from the same
// snapshot as the rows, so a write committing mid-read cannot produce a cursor
// past a row the client never received — a row that would then be invisible to
// that client forever, with no error to report it.
func (s *Store) SyncSince(ctx context.Context, userID string, since int64) (SyncResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SyncResult{}, fmt.Errorf("begin sync: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var result SyncResult
	if err := tx.QueryRowContext(ctx,
		`SELECT value FROM revision_sequence WHERE id = 1`).Scan(&result.Revision); err != nil {
		return SyncResult{}, fmt.Errorf("read revision sequence: %w", err)
	}

	itemRows, err := tx.QueryContext(ctx,
		`SELECT `+itemColumns+` FROM items
		 WHERE revision > ? AND `+visibleItemsClause+`
		 ORDER BY revision`,
		since, userID, userID)
	if err != nil {
		return SyncResult{}, fmt.Errorf("select items: %w", err)
	}
	if result.Items, err = collectItems(itemRows); err != nil {
		return SyncResult{}, err
	}

	folderRows, err := tx.QueryContext(ctx,
		`SELECT `+folderColumns+` FROM folders
		 WHERE revision > ? AND user_id = ?
		 ORDER BY revision`,
		since, userID)
	if err != nil {
		return SyncResult{}, fmt.Errorf("select folders: %w", err)
	}
	if result.Folders, err = collectFolders(folderRows); err != nil {
		return SyncResult{}, err
	}

	if err := tx.Commit(); err != nil {
		return SyncResult{}, fmt.Errorf("commit sync: %w", err)
	}
	return result, nil
}

func collectItems(rows *sql.Rows) ([]Item, error) {
	defer func() { _ = rows.Close() }()
	items := []Item{}
	for rows.Next() {
		item, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate items: %w", err)
	}
	return items, nil
}

func collectFolders(rows *sql.Rows) ([]Folder, error) {
	defer func() { _ = rows.Close() }()
	folders := []Folder{}
	for rows.Next() {
		folder, err := scanFolder(rows)
		if err != nil {
			return nil, err
		}
		folders = append(folders, folder)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate folders: %w", err)
	}
	return folders, nil
}

// CanAccessItem answers the single-item version of the sync visibility rule.
// Handlers call it before every read, write, and delete of one item.
func (s *Store) CanAccessItem(ctx context.Context, userID string, item Item) (bool, error) {
	if !item.CollectionID.Valid {
		return item.OwnerUserID == userID, nil
	}
	var count int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM collection_memberships WHERE collection_id = ? AND user_id = ?`,
		item.CollectionID.String, userID).Scan(&count); err != nil {
		return false, fmt.Errorf("check membership: %w", err)
	}
	return count > 0, nil
}
