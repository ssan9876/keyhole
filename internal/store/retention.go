package store

import (
	"context"
	"fmt"
	"time"
)

// TombstoneRetention is how long a delete stays visible to sync (spec section
// 4.2). It has to outlast the longest plausible offline period: a device that
// misses the tombstone entirely keeps showing an item its owner deleted, and
// nothing later removes it.
const TombstoneRetention = 90 * 24 * time.Hour

// PurgeTombstones removes tombstones older than the window and reports how
// many rows went.
//
// The predicate is `deleted_at IS NOT NULL AND deleted_at < cutoff` — never
// updated_at, which every live row also carries. A purge keyed on the wrong
// column deletes a vault's worth of untouched passwords, and there is no undo.
func (s *Store) PurgeTombstones(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-olderThan).Format(time.RFC3339)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin purge: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var total int64
	for _, table := range []string{"items", "folders"} {
		result, err := tx.ExecContext(ctx,
			`DELETE FROM `+table+` WHERE deleted_at IS NOT NULL AND deleted_at < ?`, cutoff)
		if err != nil {
			return 0, fmt.Errorf("purge %s: %w", table, err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("rows affected: %w", err)
		}
		total += affected
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit purge: %w", err)
	}
	if total > 0 {
		if err := s.AppendAudit(ctx, "", "retention.purge", "tombstones",
			fmt.Sprintf(`{"purged":%d}`, total)); err != nil {
			return total, err
		}
	}
	return total, nil
}
