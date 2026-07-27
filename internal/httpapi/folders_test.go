package httpapi

import (
	"context"
	"net/http"
	"testing"
)

type folderResponse struct {
	ID            string  `json:"id"`
	EncryptedName string  `json:"encryptedName"`
	Revision      int64   `json:"revision"`
	DeletedAt     *string `json:"deletedAt"`
}

func TestCreateFolderReturnsTheStoredFolder(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	rec := doJSON(t, srv, http.MethodPost, "/api/folders", token, map[string]string{
		"encryptedName": "encrypted-blob",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var folder folderResponse
	decodeInto(t, rec, &folder)
	if folder.EncryptedName != "encrypted-blob" {
		t.Errorf("encryptedName = %q, want it echoed verbatim", folder.EncryptedName)
	}
}

func TestFolderEndpointsRequireAuthentication(t *testing.T) {
	srv := newTestServer(t)

	rec := doJSON(t, srv, http.MethodPost, "/api/folders", "",
		map[string]string{"encryptedName": "n"})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestUpdatingAnotherUsersFolderIsNotFound(t *testing.T) {
	srv := newTestServer(t)
	_, ownerToken := loginTestUser(t, srv, "owner@example.com")
	_, otherToken := loginTestUser(t, srv, "other@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/folders", ownerToken,
		map[string]string{"encryptedName": "mine"})
	var folder folderResponse
	decodeInto(t, created, &folder)

	rec := doJSON(t, srv, http.MethodPut, "/api/folders/"+folder.ID, otherToken, map[string]any{
		"encryptedName": "theirs", "revision": folder.Revision,
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	stored, err := srv.store.FolderByID(context.Background(), folder.ID)
	if err != nil {
		t.Fatalf("FolderByID: %v", err)
	}
	if stored.EncryptedName != "mine" {
		t.Errorf("stored name = %q; another user's write landed", stored.EncryptedName)
	}
}

func TestDeletingAnotherUsersFolderIsNotFound(t *testing.T) {
	srv := newTestServer(t)
	_, ownerToken := loginTestUser(t, srv, "owner@example.com")
	_, otherToken := loginTestUser(t, srv, "other@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/folders", ownerToken,
		map[string]string{"encryptedName": "mine"})
	var folder folderResponse
	decodeInto(t, created, &folder)

	rec := doJSON(t, srv, http.MethodDelete, "/api/folders/"+folder.ID, otherToken, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	stored, err := srv.store.FolderByID(context.Background(), folder.ID)
	if err != nil {
		t.Fatalf("FolderByID: %v", err)
	}
	if stored.DeletedAt.Valid {
		t.Error("another user deleted this folder")
	}
}

func TestUpdateFolderReportsAConflictWithoutAnItemBody(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/folders", token,
		map[string]string{"encryptedName": "v1"})
	var folder folderResponse
	decodeInto(t, created, &folder)

	if rec := doJSON(t, srv, http.MethodPut, "/api/folders/"+folder.ID, token, map[string]any{
		"encryptedName": "v2", "revision": folder.Revision,
	}); rec.Code != http.StatusOK {
		t.Fatalf("first update: %d %s", rec.Code, rec.Body.String())
	}

	rec := doJSON(t, srv, http.MethodPut, "/api/folders/"+folder.ID, token, map[string]any{
		"encryptedName": "v3", "revision": folder.Revision,
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
		Folder folderResponse `json:"folder"`
	}
	decodeInto(t, rec, &body)
	if body.Error.Code != "conflict" {
		t.Errorf("code = %q, want %q", body.Error.Code, "conflict")
	}
	if body.Folder.EncryptedName != "v2" {
		t.Errorf("conflict body folder = %q, want the winning %q", body.Folder.EncryptedName, "v2")
	}
}
