package httpapi

import (
	"context"
	"net/http"
	"testing"
)

type itemResponse struct {
	ID             string  `json:"id"`
	CollectionID   *string `json:"collectionId"`
	OwnerUserID    string  `json:"ownerUserId"`
	Ciphertext     string  `json:"ciphertext"`
	WrappedItemKey string  `json:"wrappedItemKey"`
	Revision       int64   `json:"revision"`
	CreatedAt      string  `json:"createdAt"`
	UpdatedAt      string  `json:"updatedAt"`
	DeletedAt      *string `json:"deletedAt"`
}

func TestCreateItemRequiresAuthentication(t *testing.T) {
	srv := newTestServer(t)

	rec := doJSON(t, srv, http.MethodPost, "/api/items", "", map[string]string{
		"ciphertext": "c", "wrappedItemKey": "k",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d — the vault is readable without a session",
			rec.Code, http.StatusUnauthorized)
	}
}

func TestCreateItemReturnsTheStoredItem(t *testing.T) {
	srv := newTestServer(t)
	user, token := loginTestUser(t, srv, "person@example.com")

	const ct = `{"v":1,"alg":"A256GCM","n":"AAAAAAAAAAAAAAAA","ct":"3q2+7w=="}`
	rec := doJSON(t, srv, http.MethodPost, "/api/items", token, map[string]string{
		"ciphertext": ct, "wrappedItemKey": "wrapped",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var item itemResponse
	decodeInto(t, rec, &item)
	if item.Ciphertext != ct {
		t.Errorf("ciphertext = %q, want it echoed verbatim", item.Ciphertext)
	}
	if item.OwnerUserID != user.ID {
		t.Errorf("ownerUserId = %q, want %q", item.OwnerUserID, user.ID)
	}
	if item.CollectionID != nil {
		t.Errorf("collectionId = %v, want null for a personal item", *item.CollectionID)
	}
	if item.Revision < 1 {
		t.Errorf("revision = %d, want at least 1", item.Revision)
	}
	// The client needs this to send an If-Match-style revision on its next
	// edit; without it every first edit would conflict.
	if item.ID == "" {
		t.Error("response carries no id")
	}
}

func TestCreateItemRejectsAMissingCiphertext(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	rec := doJSON(t, srv, http.MethodPost, "/api/items", token, map[string]string{
		"wrappedItemKey": "k",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCreateItemInAForeignCollectionIsNotFound(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "owner@example.com")
	_, outsiderToken := loginTestUser(t, srv, "outsider@example.com")

	collection := createCollection(t, srv, adminToken, "Household")

	// 404, not 403: a 403 would confirm the collection exists, which is how a
	// caller maps out the membership graph one guess at a time.
	rec := doJSON(t, srv, http.MethodPost, "/api/items", outsiderToken, map[string]string{
		"collectionId": collection.ID, "ciphertext": "c", "wrappedItemKey": "k",
	})
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	var count int
	if err := srv.store.DB().QueryRow(`SELECT COUNT(*) FROM items`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("%d items were written into a collection the caller does not belong to", count)
	}
}

func TestUpdateItemRequiresTheCurrentRevisionAndReturnsTheWinnerOnConflict(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/items", token, map[string]string{
		"ciphertext": "v1", "wrappedItemKey": "k",
	})
	var item itemResponse
	decodeInto(t, created, &item)

	ok := doJSON(t, srv, http.MethodPut, "/api/items/"+item.ID, token, map[string]any{
		"ciphertext": "v2", "wrappedItemKey": "k", "revision": item.Revision,
	})
	if ok.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", ok.Code, http.StatusOK, ok.Body.String())
	}

	// The second edit was made from the pre-edit revision.
	conflict := doJSON(t, srv, http.MethodPut, "/api/items/"+item.ID, token, map[string]any{
		"ciphertext": "v3", "wrappedItemKey": "k", "revision": item.Revision,
	})
	if conflict.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", conflict.Code, http.StatusConflict)
	}

	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
		Item itemResponse `json:"item"`
	}
	decodeInto(t, conflict, &body)
	if body.Error.Code != "conflict" {
		t.Errorf("code = %q, want %q", body.Error.Code, "conflict")
	}
	// Without the winning copy in the response the client has nothing to
	// reconcile against and its only option is to discard one of the two edits.
	if body.Item.Ciphertext != "v2" {
		t.Errorf("conflict body item ciphertext = %q, want the winning %q",
			body.Item.Ciphertext, "v2")
	}
	if body.Item.Revision == 0 {
		t.Error("conflict body carries no revision to retry with")
	}
}

func TestUpdatingAnotherUsersItemIsNotFound(t *testing.T) {
	srv := newTestServer(t)
	_, ownerToken := loginTestUser(t, srv, "owner@example.com")
	_, otherToken := loginTestUser(t, srv, "other@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/items", ownerToken, map[string]string{
		"ciphertext": "mine", "wrappedItemKey": "k",
	})
	var item itemResponse
	decodeInto(t, created, &item)

	rec := doJSON(t, srv, http.MethodPut, "/api/items/"+item.ID, otherToken, map[string]any{
		"ciphertext": "theirs", "wrappedItemKey": "k", "revision": item.Revision,
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d — one user can write another's vault",
			rec.Code, http.StatusNotFound)
	}

	stored, err := srv.store.ItemByID(context.Background(), item.ID)
	if err != nil {
		t.Fatalf("ItemByID: %v", err)
	}
	if stored.Ciphertext != "mine" {
		t.Errorf("stored ciphertext = %q; another user's write landed", stored.Ciphertext)
	}
}

func TestAMemberMayEditAnItemTheyDidNotCreate(t *testing.T) {
	srv := newTestServer(t)
	admin, adminToken := loginAdmin(t, srv, "owner@example.com")
	member, memberToken := loginTestUser(t, srv, "member@example.com")

	collection := createCollection(t, srv, adminToken, "Household")
	if err := srv.store.FulfilGrantOrAdd(context.Background(),
		collection.ID, member.ID, "sealed-to-member", "member", admin.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}

	created := doJSON(t, srv, http.MethodPost, "/api/items", adminToken, map[string]string{
		"collectionId": collection.ID, "ciphertext": "v1", "wrappedItemKey": "k",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var item itemResponse
	decodeInto(t, created, &item)

	// Spec section 5.1: any member may edit any item in a collection.
	// owner_user_id records who made it and confers no exclusive rights.
	rec := doJSON(t, srv, http.MethodPut, "/api/items/"+item.ID, memberToken, map[string]any{
		"collectionId": collection.ID, "ciphertext": "v2",
		"wrappedItemKey": "k", "revision": item.Revision,
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestDeleteItemTombstonesAndIsIdempotentlyNotFound(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/items", token, map[string]string{
		"ciphertext": "c", "wrappedItemKey": "k",
	})
	var item itemResponse
	decodeInto(t, created, &item)

	rec := doJSON(t, srv, http.MethodDelete, "/api/items/"+item.ID, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var deleted itemResponse
	decodeInto(t, rec, &deleted)
	if deleted.DeletedAt == nil {
		t.Error("delete response carries no deletedAt")
	}
	if deleted.Ciphertext != "" {
		t.Error("delete response still carries ciphertext")
	}

	again := doJSON(t, srv, http.MethodDelete, "/api/items/"+item.ID, token, nil)
	if again.Code != http.StatusNotFound {
		t.Errorf("second delete status = %d, want %d", again.Code, http.StatusNotFound)
	}
}

func TestDeletingAnotherUsersItemIsNotFound(t *testing.T) {
	srv := newTestServer(t)
	_, ownerToken := loginTestUser(t, srv, "owner@example.com")
	_, otherToken := loginTestUser(t, srv, "other@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/items", ownerToken, map[string]string{
		"ciphertext": "mine", "wrappedItemKey": "k",
	})
	var item itemResponse
	decodeInto(t, created, &item)

	rec := doJSON(t, srv, http.MethodDelete, "/api/items/"+item.ID, otherToken, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	stored, err := srv.store.ItemByID(context.Background(), item.ID)
	if err != nil {
		t.Fatalf("ItemByID: %v", err)
	}
	if stored.DeletedAt.Valid {
		t.Error("another user deleted this item")
	}
}

func TestBulkImportWritesEveryRowOrNone(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	good := doJSON(t, srv, http.MethodPost, "/api/items/bulk", token, map[string]any{
		"items": []map[string]string{
			{"ciphertext": "a", "wrappedItemKey": "k"},
			{"ciphertext": "b", "wrappedItemKey": "k"},
			{"ciphertext": "c", "wrappedItemKey": "k"},
		},
	})
	if good.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", good.Code, http.StatusCreated, good.Body.String())
	}
	var body struct {
		Items []itemResponse `json:"items"`
	}
	decodeInto(t, good, &body)
	if len(body.Items) != 3 {
		t.Fatalf("returned %d items, want 3", len(body.Items))
	}

	// An import that half-lands leaves the user with no way to tell which half.
	bad := doJSON(t, srv, http.MethodPost, "/api/items/bulk", token, map[string]any{
		"items": []map[string]string{
			{"ciphertext": "d", "wrappedItemKey": "k"},
			{"ciphertext": "", "wrappedItemKey": "k"},
		},
	})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", bad.Code, http.StatusBadRequest)
	}

	var count int
	if err := srv.store.DB().QueryRow(`SELECT COUNT(*) FROM items`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 3 {
		t.Errorf("item count = %d, want the 3 from the good batch only", count)
	}
}

func TestBulkImportRejectsAnOversizedBatch(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	// A cap the client can chunk against, rather than an unbounded transaction
	// that holds the single SQLite writer for an unbounded time.
	items := make([]map[string]string, maxBulkItems+1)
	for i := range items {
		items[i] = map[string]string{"ciphertext": "c", "wrappedItemKey": "k"}
	}
	rec := doJSON(t, srv, http.MethodPost, "/api/items/bulk", token, map[string]any{"items": items})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestBulkImportRejectsAnEmptyBatch(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	rec := doJSON(t, srv, http.MethodPost, "/api/items/bulk", token,
		map[string]any{"items": []map[string]string{}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
