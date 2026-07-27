package store

import (
	"context"
	"testing"
	"time"
)

func TestPurgeTombstonesRemovesOldOnesAndKeepsRecentOnes(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")

	old, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "old", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	recent, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "recent", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	if _, err := st.DeleteItem(ctx, old.ID); err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}
	if _, err := st.DeleteItem(ctx, recent.ID); err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}

	// Backdate one tombstone past the window.
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE items SET deleted_at = ? WHERE id = ?`,
		time.Now().UTC().Add(-100*24*time.Hour).Format(time.RFC3339), old.ID); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	purged, err := st.PurgeTombstones(ctx, TombstoneRetention)
	if err != nil {
		t.Fatalf("PurgeTombstones: %v", err)
	}
	if purged != 1 {
		t.Fatalf("purged %d rows, want 1", purged)
	}

	if _, err := st.ItemByID(ctx, old.ID); err == nil {
		t.Error("the old tombstone survived the purge")
	}
	// A device offline for a week must still learn about last week's deletes.
	// Purging recent tombstones would leave the item on that device forever.
	if _, err := st.ItemByID(ctx, recent.ID); err != nil {
		t.Errorf("a recent tombstone was purged: %v", err)
	}
}

func TestPurgeTombstonesNeverTouchesLiveRows(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")

	live, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "live", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	folder, err := st.CreateFolder(ctx, userID, "live-folder")
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	// Backdate the live rows' timestamps. A purge keyed on updated_at rather
	// than deleted_at would delete a vault's worth of untouched passwords.
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE items SET created_at = ?, updated_at = ?`,
		"2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z"); err != nil {
		t.Fatalf("backdate items: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE folders SET created_at = ?, updated_at = ?`,
		"2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z"); err != nil {
		t.Fatalf("backdate folders: %v", err)
	}

	purged, err := st.PurgeTombstones(ctx, TombstoneRetention)
	if err != nil {
		t.Fatalf("PurgeTombstones: %v", err)
	}
	if purged != 0 {
		t.Fatalf("purged %d rows, want 0", purged)
	}
	if _, err := st.ItemByID(ctx, live.ID); err != nil {
		t.Errorf("a live item was purged: %v", err)
	}
	if _, err := st.FolderByID(ctx, folder.ID); err != nil {
		t.Errorf("a live folder was purged: %v", err)
	}
}

func TestPurgeTombstonesCoversFoldersToo(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")

	folder, err := st.CreateFolder(ctx, userID, "doomed")
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	if _, err := st.DeleteFolder(ctx, folder.ID); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE folders SET deleted_at = ?`,
		time.Now().UTC().Add(-100*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	purged, err := st.PurgeTombstones(ctx, TombstoneRetention)
	if err != nil {
		t.Fatalf("PurgeTombstones: %v", err)
	}
	if purged != 1 {
		t.Errorf("purged %d rows, want 1 — folder tombstones accumulate forever", purged)
	}
}
