package store

import (
	"context"
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
		t.Error("DeletedAt is not set; the delete will not propagate")
	}

	stored, err := st.FolderByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("FolderByID: %v", err)
	}
	if stored.EncryptedName != "" {
		t.Errorf("EncryptedName = %q after delete, want it destroyed", stored.EncryptedName)
	}
}
