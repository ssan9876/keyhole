package httpapi

import (
	"fmt"
	"net/http"
	"testing"
)

type syncResponse struct {
	Revision    int64                `json:"revision"`
	Items       []itemResponse       `json:"items"`
	Folders     []folderResponse     `json:"folders"`
	Collections []collectionResponse `json:"collections"`
}

func TestSyncRequiresAuthentication(t *testing.T) {
	srv := newTestServer(t)

	rec := doJSON(t, srv, http.MethodGet, "/api/sync", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestSyncReturnsTheVaultAndACursor(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	for i := 0; i < 3; i++ {
		rec := doJSON(t, srv, http.MethodPost, "/api/items", token, map[string]string{
			"ciphertext": fmt.Sprintf("item-%d", i), "wrappedItemKey": "k",
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
		}
	}
	if rec := doJSON(t, srv, http.MethodPost, "/api/folders", token,
		map[string]string{"encryptedName": "f"}); rec.Code != http.StatusCreated {
		t.Fatalf("create folder: %d %s", rec.Code, rec.Body.String())
	}

	rec := doJSON(t, srv, http.MethodGet, "/api/sync", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body syncResponse
	decodeInto(t, rec, &body)
	if len(body.Items) != 3 {
		t.Errorf("got %d items, want 3", len(body.Items))
	}
	if len(body.Folders) != 1 {
		t.Errorf("got %d folders, want 1", len(body.Folders))
	}
	if body.Revision < 4 {
		t.Errorf("revision = %d, want at least 4", body.Revision)
	}
}

func TestSyncSinceTheCursorReturnsOnlyWhatChanged(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	if rec := doJSON(t, srv, http.MethodPost, "/api/items", token, map[string]string{
		"ciphertext": "first", "wrappedItemKey": "k",
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d", rec.Code)
	}

	first := doJSON(t, srv, http.MethodGet, "/api/sync", token, nil)
	var firstBody syncResponse
	decodeInto(t, first, &firstBody)

	if rec := doJSON(t, srv, http.MethodPost, "/api/items", token, map[string]string{
		"ciphertext": "second", "wrappedItemKey": "k",
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d", rec.Code)
	}

	second := doJSON(t, srv, http.MethodGet,
		fmt.Sprintf("/api/sync?since=%d", firstBody.Revision), token, nil)
	var secondBody syncResponse
	decodeInto(t, second, &secondBody)

	if len(secondBody.Items) != 1 {
		t.Fatalf("got %d items, want only the new one", len(secondBody.Items))
	}
	if secondBody.Items[0].Ciphertext != "second" {
		t.Errorf("ciphertext = %q, want %q", secondBody.Items[0].Ciphertext, "second")
	}
}

func TestSyncNeverLeaksAnotherUsersVault(t *testing.T) {
	srv := newTestServer(t)
	_, mineToken := loginTestUser(t, srv, "mine@example.com")
	_, theirsToken := loginTestUser(t, srv, "theirs@example.com")

	if rec := doJSON(t, srv, http.MethodPost, "/api/items", theirsToken, map[string]string{
		"ciphertext": "their-secret", "wrappedItemKey": "k",
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d", rec.Code)
	}

	rec := doJSON(t, srv, http.MethodGet, "/api/sync", mineToken, nil)
	var body syncResponse
	decodeInto(t, rec, &body)
	if len(body.Items) != 0 {
		t.Fatalf("got %d items from an empty vault; another user's items are visible",
			len(body.Items))
	}
}

func TestSyncRejectsAMalformedCursor(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	// A cursor that silently fell back to 0 would re-send the whole vault on
	// every poll and hide the client bug that produced it.
	for _, since := range []string{"abc", "-1", "1.5", ""} {
		rec := doJSON(t, srv, http.MethodGet, "/api/sync?since="+since, token, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("since=%q gave status %d, want %d", since, rec.Code, http.StatusBadRequest)
		}
	}
}

func TestSyncWithNoCursorParameterStartsFromZero(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	if rec := doJSON(t, srv, http.MethodPost, "/api/items", token, map[string]string{
		"ciphertext": "c", "wrappedItemKey": "k",
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d", rec.Code)
	}

	// A first-run client has no cursor at all. That is distinct from sending an
	// empty one, which is a bug.
	rec := doJSON(t, srv, http.MethodGet, "/api/sync", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body syncResponse
	decodeInto(t, rec, &body)
	if len(body.Items) != 1 {
		t.Errorf("got %d items, want the full vault", len(body.Items))
	}
}
