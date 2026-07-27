package store

import (
	"context"
	"testing"
	"time"
)

// seedCollectionWithMembers inserts a collection and its memberships
// directly. Task 4 replaces this with CreateCollection.
//
// Named distinctly from items_test.go's seedCollection (Task 1), which takes
// an explicit name and inserts no membership rows — that helper only needs a
// foreign-key-valid collection id, while the sync visibility tests need real
// membership rows to exercise the access rule. Both existing under the same
// name would not compile.
func seedCollectionWithMembers(t *testing.T, st *Store, createdBy string, memberIDs ...string) string {
	t.Helper()
	ctx := context.Background()
	id, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO collections (id, name, created_by, created_at) VALUES (?, ?, ?, ?)`,
		id, "Household", createdBy, now); err != nil {
		t.Fatalf("insert collection: %v", err)
	}
	for _, member := range memberIDs {
		if _, err := st.DB().ExecContext(ctx,
			`INSERT INTO collection_memberships
			 (collection_id, user_id, sealed_collection_key, role, granted_by, granted_at)
			 VALUES (?, ?, ?, 'member', ?, ?)`,
			id, member, "sealed-blob", createdBy, now); err != nil {
			t.Fatalf("insert membership: %v", err)
		}
	}
	return id
}

func TestSyncReturnsOnlyTheCallersPersonalItems(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	mine := enrolledUserID(t, st, "mine@example.com")
	theirs := enrolledUserID(t, st, "theirs@example.com")

	own, err := st.CreateItem(ctx, mine, ItemInput{Ciphertext: "mine", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	if _, err := st.CreateItem(ctx, theirs, ItemInput{Ciphertext: "theirs", WrappedItemKey: "k"}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	result, err := st.SyncSince(ctx, mine, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("got %d items, want exactly 1 — another user's vault is visible", len(result.Items))
	}
	if result.Items[0].ID != own.ID {
		t.Errorf("returned item %q, want %q", result.Items[0].ID, own.ID)
	}
}

func TestSyncReturnsItemsInCollectionsTheCallerBelongsTo(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	owner := enrolledUserID(t, st, "owner@example.com")
	member := enrolledUserID(t, st, "member@example.com")
	outsider := enrolledUserID(t, st, "outsider@example.com")

	collectionID := seedCollectionWithMembers(t, st, owner, owner, member)
	shared, err := st.CreateItem(ctx, owner, ItemInput{
		CollectionID: &collectionID, Ciphertext: "shared", WrappedItemKey: "k",
	})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	// A member sees it even though they did not create it: spec section 5.1,
	// owner_user_id records who made the item and confers no exclusive rights.
	memberView, err := st.SyncSince(ctx, member, 0)
	if err != nil {
		t.Fatalf("SyncSince(member): %v", err)
	}
	if len(memberView.Items) != 1 || memberView.Items[0].ID != shared.ID {
		t.Fatalf("member got %d items, want the shared one", len(memberView.Items))
	}

	// Membership is the whole access rule. Someone outside the collection must
	// see nothing, not even that the row exists.
	outsiderView, err := st.SyncSince(ctx, outsider, 0)
	if err != nil {
		t.Fatalf("SyncSince(outsider): %v", err)
	}
	if len(outsiderView.Items) != 0 {
		t.Errorf("a non-member received %d shared items, want 0", len(outsiderView.Items))
	}
}

func TestSyncIsIncrementalFromTheReturnedCursor(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	if _, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "first", WrappedItemKey: "k"}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	first, err := st.SyncSince(ctx, userID, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(first.Items) != 1 {
		t.Fatalf("first sync returned %d items, want 1", len(first.Items))
	}

	// Nothing changed, so the same cursor must return nothing. A sync that
	// re-sends the whole vault on every poll is the failure this cursor exists
	// to prevent.
	second, err := st.SyncSince(ctx, userID, first.Revision)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(second.Items) != 0 {
		t.Errorf("an unchanged vault returned %d items, want 0", len(second.Items))
	}
	if second.Revision != first.Revision {
		t.Errorf("cursor moved on an unchanged vault: %d -> %d", first.Revision, second.Revision)
	}

	if _, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "second", WrappedItemKey: "k"}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	third, err := st.SyncSince(ctx, userID, first.Revision)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(third.Items) != 1 || third.Items[0].Ciphertext != "second" {
		t.Errorf("incremental sync returned %d items, want just the new one", len(third.Items))
	}
}

func TestSyncCarriesTombstonesSoDeletesPropagate(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "c", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	afterCreate, err := st.SyncSince(ctx, userID, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if _, err := st.DeleteItem(ctx, created.ID); err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}

	// Omitting tombstones leaves the item on every other device forever, with
	// no event that ever removes it.
	result, err := st.SyncSince(ctx, userID, afterCreate.Revision)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("got %d items after a delete, want the tombstone", len(result.Items))
	}
	if !result.Items[0].DeletedAt.Valid {
		t.Error("the returned row is not marked deleted")
	}
	if result.Items[0].Ciphertext != "" {
		t.Error("a tombstone still carries ciphertext")
	}
}

func TestSyncReturnsFoldersOnTheSameCursor(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	mine := enrolledUserID(t, st, "mine@example.com")
	theirs := enrolledUserID(t, st, "theirs@example.com")

	if _, err := st.CreateFolder(ctx, mine, "mine"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	if _, err := st.CreateFolder(ctx, theirs, "theirs"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	result, err := st.SyncSince(ctx, mine, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(result.Folders) != 1 {
		t.Fatalf("got %d folders, want 1 — folders are personal and another "+
			"user's are visible", len(result.Folders))
	}
	if result.Folders[0].EncryptedName != "mine" {
		t.Errorf("returned the wrong user's folder: %q", result.Folders[0].EncryptedName)
	}
}

func TestSyncNeverReportsACursorAheadOfItsRows(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	// The cursor and the rows must come from one snapshot. Reading the
	// high-water mark outside the read transaction lets a row commit between
	// the two reads: the client then stores a cursor past a row it never
	// received, and that item is invisible to it forever.
	for i := 0; i < 20; i++ {
		if _, err := st.CreateItem(ctx, userID,
			ItemInput{Ciphertext: "c", WrappedItemKey: "k"}); err != nil {
			t.Fatalf("CreateItem: %v", err)
		}
	}
	result, err := st.SyncSince(ctx, userID, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(result.Items) != 20 {
		t.Fatalf("got %d items, want 20", len(result.Items))
	}
	for _, item := range result.Items {
		if item.Revision > result.Revision {
			t.Errorf("item revision %d exceeds the reported cursor %d; a client "+
				"storing that cursor would never see this item again",
				item.Revision, result.Revision)
		}
	}
}

func TestCanAccessItemFollowsOwnershipAndMembership(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	owner := enrolledUserID(t, st, "owner@example.com")
	member := enrolledUserID(t, st, "member@example.com")
	outsider := enrolledUserID(t, st, "outsider@example.com")

	personal, err := st.CreateItem(ctx, owner, ItemInput{Ciphertext: "c", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	collectionID := seedCollectionWithMembers(t, st, owner, owner, member)
	shared, err := st.CreateItem(ctx, owner, ItemInput{
		CollectionID: &collectionID, Ciphertext: "c", WrappedItemKey: "k",
	})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	cases := []struct {
		name   string
		userID string
		item   Item
		want   bool
	}{
		{"owner reads their personal item", owner, personal, true},
		{"outsider cannot read a personal item", outsider, personal, false},
		{"member reads a shared item they did not create", member, shared, true},
		{"outsider cannot read a shared item", outsider, shared, false},
		{"owner reads a shared item they created", owner, shared, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := st.CanAccessItem(ctx, tc.userID, tc.item)
			if err != nil {
				t.Fatalf("CanAccessItem: %v", err)
			}
			if got != tc.want {
				t.Errorf("CanAccessItem = %v, want %v", got, tc.want)
			}
		})
	}
}
