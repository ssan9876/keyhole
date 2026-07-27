package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func TestCreateFolderStoresTheEncryptedNameVerbatim(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	// The folder name is ciphertext. A server that could read "Banking" would
	// know more about the vault than the design permits.
	const name = `{"v":1,"alg":"A256GCM","n":"BBBBBBBBBBBBBBBB","ct":"YmFua2luZw=="}`
	folder, err := st.CreateFolder(ctx, userID, name)
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	// Read the row back rather than trusting the struct CreateFolder assembled
	// in memory: the returned value is built from the arguments, so it agrees
	// with itself no matter what the INSERT actually wrote. Only the stored
	// column proves the server neither rewrote nor re-encoded the ciphertext.
	var storedName, storedUserID string
	var storedRevision int64
	if err := st.DB().QueryRowContext(ctx,
		`SELECT encrypted_name, user_id, revision FROM folders WHERE id = ?`, folder.ID).
		Scan(&storedName, &storedUserID, &storedRevision); err != nil {
		t.Fatalf("read folder row back: %v", err)
	}
	if storedName != name {
		t.Errorf("stored encrypted_name = %q, want it stored verbatim as %q", storedName, name)
	}
	if storedUserID != userID {
		t.Errorf("stored user_id = %q, want %q", storedUserID, userID)
	}
	if storedRevision != folder.Revision {
		t.Errorf("stored revision = %d, but CreateFolder returned %d", storedRevision, folder.Revision)
	}

	if folder.EncryptedName != name {
		t.Errorf("EncryptedName = %q, want it stored verbatim", folder.EncryptedName)
	}
	if folder.Revision != 1 {
		t.Errorf("Revision = %d, want 1", folder.Revision)
	}
	if folder.UserID != userID {
		t.Errorf("UserID = %q, want %q", folder.UserID, userID)
	}
}

func TestCreateFolderRejectsAnEmptyName(t *testing.T) {
	st := openTemp(t)
	userID := enrolledUserID(t, st, "owner@example.com")

	_, err := st.CreateFolder(context.Background(), userID, "")
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("err = %v, want a *ValidationError", err)
	}
}

func TestFoldersAndItemsDrawFromTheSameRevisionSequence(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	item, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "c", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	folder, err := st.CreateFolder(ctx, userID, "encrypted-name")
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	// One cursor covers both tables. If folders had their own counter, a client
	// storing a single `since` value would either re-download every folder each
	// sync or skip folders entirely.
	if folder.Revision <= item.Revision {
		t.Errorf("folder revision %d does not follow item revision %d; the two tables "+
			"are not sharing one sequence", folder.Revision, item.Revision)
	}
}

func TestUpdateFolderRefusesAStaleRevision(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateFolder(ctx, userID, "v1")
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	if _, err := st.UpdateFolder(ctx, created.ID, created.Revision, "v2"); err != nil {
		t.Fatalf("first UpdateFolder: %v", err)
	}

	current, err := st.UpdateFolder(ctx, created.ID, created.Revision, "v3")
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("err = %v, want ErrRevisionConflict", err)
	}
	if current.EncryptedName != "v2" {
		t.Errorf("returned EncryptedName = %q, want the winning row %q", current.EncryptedName, "v2")
	}
}

func TestDeleteFolderTombstonesAndDestroysTheName(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateFolder(ctx, userID, "encrypted-name")
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	deleted, err := st.DeleteFolder(ctx, created.ID)
	if err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
	if !deleted.DeletedAt.Valid {
		t.Error("returned DeletedAt is not set; the delete will not propagate")
	}

	// The struct above was assembled in memory by DeleteFolder and agrees with
	// itself whatever the UPDATE wrote. The tombstone only exists if the column
	// is non-NULL in the database: without it the delete is a rename-to-empty,
	// SyncSince ships a live blank-named folder to every device forever, and a
	// later UpdateFolder resurrects the folder.
	stored, err := st.FolderByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("FolderByID: %v", err)
	}
	if !stored.DeletedAt.Valid {
		t.Error("deleted_at is NULL in the database; the row was renamed to empty, not tombstoned")
	}
	if stored.EncryptedName != "" {
		t.Errorf("EncryptedName = %q after delete, want it destroyed", stored.EncryptedName)
	}

	// Belt and braces on the column itself, so a future change to scanFolder
	// cannot make this pass by fabricating a DeletedAt the row does not have.
	var rawDeletedAt sql.NullString
	if err := st.DB().QueryRowContext(ctx,
		`SELECT deleted_at FROM folders WHERE id = ?`, created.ID).Scan(&rawDeletedAt); err != nil {
		t.Fatalf("read deleted_at back: %v", err)
	}
	if !rawDeletedAt.Valid || rawDeletedAt.String == "" {
		t.Errorf("folders.deleted_at = %v, want a timestamp", rawDeletedAt)
	}
}

func TestCanAccessFolderFollowsOwnershipOnly(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	owner := enrolledUserID(t, st, "owner@example.com")
	other := enrolledUserID(t, st, "other@example.com")

	mine, err := st.CreateFolder(ctx, owner, "mine")
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	doomed, err := st.CreateFolder(ctx, owner, "doomed")
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	tombstone, err := st.DeleteFolder(ctx, doomed.ID)
	if err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
	if !tombstone.DeletedAt.Valid {
		t.Fatalf("DeleteFolder did not tombstone; the tombstone cases below prove nothing")
	}

	cases := []struct {
		name   string
		userID string
		folder Folder
		want   bool
	}{
		{"owner reaches their own folder", owner, mine, true},
		{"a stranger holding the id cannot", other, mine, false},
		// A tombstone must answer exactly as a live row does, or a handler that
		// checks access before checking deletion reports "not found" where it
		// should report "gone" — and worse, treats another user's tombstone as
		// unowned and therefore fair game.
		{"owner still owns their tombstone", owner, tombstone, true},
		{"a stranger cannot claim a tombstone", other, tombstone, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := st.CanAccessFolder(ctx, tc.userID, tc.folder)
			if err != nil {
				t.Fatalf("CanAccessFolder: %v", err)
			}
			if got != tc.want {
				t.Errorf("CanAccessFolder = %v, want %v", got, tc.want)
			}
		})
	}

	// The live and tombstoned answers must agree for the same user, which is the
	// property a handler relies on and which the cases above would still satisfy
	// if both were wrong in the same direction for the owner.
	for _, userID := range []string{owner, other} {
		live, err := st.CanAccessFolder(ctx, userID, mine)
		if err != nil {
			t.Fatalf("CanAccessFolder(live): %v", err)
		}
		dead, err := st.CanAccessFolder(ctx, userID, tombstone)
		if err != nil {
			t.Fatalf("CanAccessFolder(tombstone): %v", err)
		}
		if live != dead {
			t.Errorf("deletion changed the access answer for the same user: live=%v tombstone=%v",
				live, dead)
		}
	}
}
