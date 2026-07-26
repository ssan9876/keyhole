package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ssan9876/keyhole/internal/auth"
)

// enrolledUser creates an ACTIVE account with key material in place, and
// returns its id.
//
// Active, not pending, because several store methods added by this plan carry
// `AND status = 'active'` in their WHERE clause and would silently report
// ErrNotFound for a pending row. The key-material columns are populated for the
// same reason: Task 6 asserts that rotating a password leaves the recovery
// blob alone, which proves nothing if the blob was never there.
func enrolledUserID(t *testing.T, st *Store, email string) string {
	t.Helper()
	ctx := context.Background()

	user, err := st.CreatePendingUser(ctx, email, "Test Person", "user")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE users SET status = 'active',
			kdf_salt = 'c2FsdA==', kdf_params = ?, auth_hash = 'argon2id$stored$hash',
			protected_user_key = 'puk', recovery_protected_user_key = 'rpuk',
			recovery_salt = 'rsalt', recovery_kdf_params = ?,
			public_key = 'pk', encrypted_private_key = 'epk'
		 WHERE id = ?`,
		auth.DefaultKDFParamsJSON, auth.DefaultKDFParamsJSON, user.ID); err != nil {
		t.Fatalf("activate user: %v", err)
	}
	return user.ID
}

func TestCreateItemStoresCiphertextVerbatimAndNumbersIt(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	// A ciphertext the server must not touch: it is the crypto package's
	// envelope, and anything the server did to it would corrupt the item.
	const ct = `{"v":1,"alg":"A256GCM","n":"AAAAAAAAAAAAAAAA","ct":"3q2+7w=="}`
	item, err := st.CreateItem(ctx, userID, ItemInput{
		Ciphertext:     ct,
		WrappedItemKey: "wrapped-key-blob",
	})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	if item.Ciphertext != ct {
		t.Errorf("Ciphertext = %q, want it stored verbatim (%q)", item.Ciphertext, ct)
	}
	if item.WrappedItemKey != "wrapped-key-blob" {
		t.Errorf("WrappedItemKey = %q", item.WrappedItemKey)
	}
	if item.CollectionID.Valid {
		t.Error("an item created with no collection must be personal")
	}
	if item.Revision != 1 {
		t.Errorf("Revision = %d, want 1 as the first write to a fresh database", item.Revision)
	}
	if item.DeletedAt.Valid {
		t.Error("a new item must not be a tombstone")
	}
	if item.OwnerUserID != userID {
		t.Errorf("OwnerUserID = %q, want %q", item.OwnerUserID, userID)
	}
}

func TestCreateItemRejectsEmptyCiphertextAndKey(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	// The server cannot check that a ciphertext decrypts — that is the whole
	// point — so the one check it can make is that the client sent something.
	// An item with an empty body is unrecoverable data loss the user would
	// discover only on unlocking.
	cases := []struct {
		name string
		in   ItemInput
	}{
		{"no ciphertext", ItemInput{WrappedItemKey: "k"}},
		{"no wrapped key", ItemInput{Ciphertext: "c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := st.CreateItem(ctx, userID, tc.in)
			var validation *ValidationError
			if !errors.As(err, &validation) {
				t.Fatalf("err = %v, want a *ValidationError", err)
			}
		})
	}
}

func TestUpdateItemAdvancesTheRevisionAndReplacesTheBody(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "v1", WrappedItemKey: "k1"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	updated, err := st.UpdateItem(ctx, created.ID, created.Revision,
		ItemInput{Ciphertext: "v2", WrappedItemKey: "k2"})
	if err != nil {
		t.Fatalf("UpdateItem: %v", err)
	}

	if updated.Ciphertext != "v2" || updated.WrappedItemKey != "k2" {
		t.Errorf("update did not replace the body: %+v", updated)
	}
	if updated.Revision <= created.Revision {
		t.Errorf("Revision = %d, want greater than %d — a sync at the old cursor "+
			"would never see this edit", updated.Revision, created.Revision)
	}
	if !updated.UpdatedAt.After(created.CreatedAt) && !updated.UpdatedAt.Equal(created.CreatedAt) {
		t.Error("UpdatedAt went backwards")
	}
}

func TestUpdateItemRefusesAStaleRevisionAndReturnsTheCurrentRow(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "base", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	// Someone else's edit lands first.
	winner, err := st.UpdateItem(ctx, created.ID, created.Revision,
		ItemInput{Ciphertext: "theirs", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("first UpdateItem: %v", err)
	}

	// Ours was written against the pre-edit revision.
	current, err := st.UpdateItem(ctx, created.ID, created.Revision,
		ItemInput{Ciphertext: "ours", WrappedItemKey: "k"})
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("err = %v, want ErrRevisionConflict", err)
	}
	// The current row rides along so the handler can hand it to the client,
	// which is what lets the client keep BOTH edits as a conflicted copy.
	if current.Ciphertext != "theirs" {
		t.Errorf("returned Ciphertext = %q, want the winning row %q", current.Ciphertext, "theirs")
	}
	if current.Revision != winner.Revision {
		t.Errorf("returned Revision = %d, want the current %d", current.Revision, winner.Revision)
	}

	// And the losing write must not have landed.
	stored, err := st.ItemByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("ItemByID: %v", err)
	}
	if stored.Ciphertext != "theirs" {
		t.Errorf("stored Ciphertext = %q; the stale write overwrote the winner", stored.Ciphertext)
	}
}

func TestDeleteItemTombstonesAndDestroysTheCiphertext(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID,
		ItemInput{Ciphertext: "secret-ciphertext", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	deleted, err := st.DeleteItem(ctx, created.ID)
	if err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}
	if !deleted.DeletedAt.Valid {
		t.Error("DeletedAt is not set; the delete will not propagate to other devices")
	}
	if deleted.Revision <= created.Revision {
		t.Errorf("Revision = %d, want greater than %d", deleted.Revision, created.Revision)
	}

	// A delete that leaves the data readable in the database is not a delete.
	// The row survives only as a tombstone so other devices learn about it.
	stored, err := st.ItemByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("ItemByID after delete: %v", err)
	}
	if stored.Ciphertext != "" {
		t.Errorf("Ciphertext = %q after delete, want it destroyed", stored.Ciphertext)
	}
	if stored.WrappedItemKey != "" {
		t.Errorf("WrappedItemKey = %q after delete, want it destroyed", stored.WrappedItemKey)
	}
}

func TestDeletingAnAlreadyDeletedItemIsNotFound(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "c", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	if _, err := st.DeleteItem(ctx, created.ID); err != nil {
		t.Fatalf("first DeleteItem: %v", err)
	}

	// Without this, a retried delete burns a revision and re-broadcasts a
	// tombstone every client already has.
	if _, err := st.DeleteItem(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteItem err = %v, want ErrNotFound", err)
	}
}

func TestUpdatingATombstoneIsNotFound(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "c", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	if _, err := st.DeleteItem(ctx, created.ID); err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}

	// A device that was offline during the delete must not be able to
	// resurrect the item by pushing its cached copy.
	_, err = st.UpdateItem(ctx, created.ID, created.Revision,
		ItemInput{Ciphertext: "resurrected", WrappedItemKey: "k"})
	if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("err = %v, want ErrNotFound or ErrRevisionConflict", err)
	}
	stored, err := st.ItemByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("ItemByID: %v", err)
	}
	if stored.Ciphertext != "" || !stored.DeletedAt.Valid {
		t.Error("a tombstone was resurrected by an update")
	}
}

func TestCreateItemsBulkIsAllOrNothing(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	// An import of a thousand passwords that half-lands leaves the user with
	// no way to tell which half. One transaction, or none.
	_, err := st.CreateItemsBulk(ctx, userID, []ItemInput{
		{Ciphertext: "ok-1", WrappedItemKey: "k"},
		{Ciphertext: "", WrappedItemKey: "k"}, // invalid
		{Ciphertext: "ok-2", WrappedItemKey: "k"},
	})
	if err == nil {
		t.Fatal("CreateItemsBulk accepted a batch containing an invalid row")
	}

	var count int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM items`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("%d items survived a rejected batch, want 0", count)
	}

	rev, err := st.CurrentRevision(ctx)
	if err != nil {
		t.Fatalf("CurrentRevision: %v", err)
	}
	if rev != 0 {
		t.Errorf("CurrentRevision = %d after a rejected batch, want 0", rev)
	}
}

func TestCreateItemsBulkNumbersEveryRowDistinctly(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	ins := make([]ItemInput, 50)
	for i := range ins {
		ins[i] = ItemInput{Ciphertext: strings.Repeat("c", i+1), WrappedItemKey: "k"}
	}
	items, err := st.CreateItemsBulk(ctx, userID, ins)
	if err != nil {
		t.Fatalf("CreateItemsBulk: %v", err)
	}
	if len(items) != len(ins) {
		t.Fatalf("returned %d items, want %d", len(items), len(ins))
	}

	// Sharing a revision across a batch would mean a client syncing mid-import
	// records a cursor that skips the rest of the batch forever.
	seen := make(map[int64]bool, len(items))
	for _, item := range items {
		if seen[item.Revision] {
			t.Fatalf("revision %d appears twice in one batch", item.Revision)
		}
		seen[item.Revision] = true
	}
}

func TestItemByIDReportsAMissingItemAsNotFound(t *testing.T) {
	st := openTemp(t)

	if _, err := st.ItemByID(context.Background(), "0123456789abcdef0123456789abcdef"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
