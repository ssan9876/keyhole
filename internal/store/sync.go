package store

import (
	"context"
	"database/sql"
	"fmt"
)

// SyncResult is everything a client needs to bring itself up to date.
type SyncResult struct {
	// Revision is the cursor to send on the next sync. It is read inside the
	// same transaction as the rows, so it can never be ahead of what was
	// returned.
	Revision int64
	Items    []Item
	Folders  []Folder
	// Collections are sent in full on every sync rather than incrementally. At
	// household scale that is a handful of rows, and it means a revoked
	// membership or a deleted collection simply disappears from the list — no
	// membership tombstone table and no revision column on two more tables.
	Collections []CollectionWithMembership
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

// changedSinceClause is the cursor filter, and it is deliberately not a plain
// `revision > ?`.
//
// The cursor is global and monotonic, but visibility is evaluated at query
// time. An item that was already in a collection carries a revision BELOW the
// cursor a newly-granted member's device already holds, so `revision > since`
// alone matches nothing and the shared passwords they were just given are
// invisible — with no error and no empty-state signal — until that device wipes
// its local state. Measured during Task 2's review: cursor 1, shared item at
// revision 1, the new member's sync returned 0 items.
//
// The second disjunct delivers that backlog exactly once, to exactly the person
// who needs it: their membership's granted_revision is above their cursor on
// the first sync after the grant and below it forever after. Existing members
// are untouched, because their own granted_revision is long past. It takes the
// user id once more.
const changedSinceClause = `(
	revision > ?
	OR collection_id IN (
	    SELECT collection_id FROM collection_memberships
	    WHERE user_id = ? AND granted_revision > ?
	)
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
		 WHERE `+changedSinceClause+` AND `+visibleItemsClause+`
		 ORDER BY revision`,
		since, userID, since, userID, userID)
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

	// Read inside the same transaction as the items, so a membership added
	// mid-read cannot yield items whose collection is absent from this list.
	if result.Collections, err = collectionsForUser(ctx, tx, userID); err != nil {
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
//
// The item MUST be one returned by ItemByID (or another store read) for the id
// the handler is acting on. It judges the struct it is handed and does not
// re-read the row, so a caller that assembles an Item from request data gets
// the answer for that fabricated struct, not for the stored row:
// CanAccessItem(ctx, u, Item{OwnerUserID: u}) is true for every u. Load first,
// then check, then act on the loaded row.
//
// The membership lookup runs on s.db rather than inside the caller's
// transaction, so a membership could in principle change between this check and
// the write it guards. That is benign here: SQLite admits one writer at a time,
// so the guarded write and any membership change are serialised, and the worst
// case is a decision made against state one write old — the same window a
// client's own request already races. Documented so it is not rediscovered as a
// bug; it becomes real only if this store ever moves to a concurrent-writer
// engine, at which point the check belongs in the caller's transaction.
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

// CanAccessFolder answers the folder counterpart of CanAccessItem. Folders are
// personal — there is no shared-folder concept, so ownership is the whole rule
// and no membership lookup exists to do. It is a function rather than an
// inlined folder.UserID == userID at each call site for the same reason
// CanAccessItem is: FolderByID, UpdateFolder and DeleteFolder take no userID,
// so three handlers would otherwise hand-roll the owner check with nothing
// keeping them consistent. One definition, one place to change if folders ever
// become shareable.
//
// Like CanAccessItem, the folder MUST be one returned by FolderByID: this
// judges the struct it is handed and does not re-read the row. It never
// consults the database today, and returns an error only so call sites and a
// future shared-folder rule need no signature change.
//
// A tombstoned folder answers exactly as a live one does — deletion does not
// change who owns the row. Handlers decide separately whether a tombstone is
// actionable; they must not read "not accessible" as "deleted", nor treat a
// tombstone as unowned.
func (s *Store) CanAccessFolder(ctx context.Context, userID string, folder Folder) (bool, error) {
	return folder.UserID == userID, nil
}
