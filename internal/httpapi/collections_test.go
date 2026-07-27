package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ssan9876/keyhole/internal/store"
)

type collectionResponse struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Role                string `json:"role"`
	SealedCollectionKey string `json:"sealedCollectionKey"`
	CreatedBy           string `json:"createdBy"`
}

type pendingGrantResponse struct {
	CollectionID   string `json:"collectionId"`
	CollectionName string `json:"collectionName"`
	UserID         string `json:"userId"`
	Role           string `json:"role"`
}

// loginAdmin enrolls an account, promotes it to admin, and signs in. The role
// is set directly because the only route that creates an admin is the
// installer's CLI, which is not reachable from a test server.
func loginAdmin(t *testing.T, srv *Server, email string) (store.User, string) {
	t.Helper()
	user, token := loginTestUser(t, srv, email)
	if _, err := srv.store.DB().ExecContext(context.Background(),
		`UPDATE users SET role = 'admin' WHERE id = ?`, user.ID); err != nil {
		t.Fatalf("promote to admin: %v", err)
	}
	user.Role = "admin"
	return user, token
}

// createCollection is the happy path used as a fixture by later tests.
func createCollection(t *testing.T, srv *Server, adminToken, name string) collectionResponse {
	t.Helper()
	rec := doJSON(t, srv, http.MethodPost, "/api/collections", adminToken, map[string]string{
		"name": name, "sealedCollectionKey": "sealed-to-creator",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create collection: %d %s", rec.Code, rec.Body.String())
	}
	var collection collectionResponse
	decodeInto(t, rec, &collection)
	return collection
}

func TestOnlyAnAdminMayCreateACollection(t *testing.T) {
	srv := newTestServer(t)
	_, userToken := loginTestUser(t, srv, "person@example.com")

	rec := doJSON(t, srv, http.MethodPost, "/api/collections", userToken, map[string]string{
		"name": "Household", "sealedCollectionKey": "sealed",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d — spec 5.1 reserves collection creation to admins",
			rec.Code, http.StatusForbidden)
	}
}

func TestCreateCollectionMakesTheAdminItsManager(t *testing.T) {
	srv := newTestServer(t)
	admin, adminToken := loginAdmin(t, srv, "admin@example.com")

	collection := createCollection(t, srv, adminToken, "Household")
	if collection.Name != "Household" {
		t.Errorf("name = %q", collection.Name)
	}
	if collection.CreatedBy != admin.ID {
		t.Errorf("createdBy = %q, want %q", collection.CreatedBy, admin.ID)
	}

	rec := doJSON(t, srv, http.MethodGet, "/api/collections", adminToken, nil)
	var body struct {
		Collections []collectionResponse `json:"collections"`
	}
	decodeInto(t, rec, &body)
	if len(body.Collections) != 1 {
		t.Fatalf("got %d collections, want 1", len(body.Collections))
	}
	if body.Collections[0].Role != "manager" {
		t.Errorf("role = %q, want manager", body.Collections[0].Role)
	}
	if body.Collections[0].SealedCollectionKey != "sealed-to-creator" {
		t.Errorf("sealedCollectionKey = %q, want the creator's own copy",
			body.Collections[0].SealedCollectionKey)
	}
}

func TestCreateCollectionRequiresASealedKey(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")

	// A collection whose creator holds no sealed key is unreachable forever:
	// the server has no key to hand out, by design.
	rec := doJSON(t, srv, http.MethodPost, "/api/collections", adminToken,
		map[string]string{"name": "Household"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestListCollectionsShowsOnlyTheCallersOwn(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	_, outsiderToken := loginTestUser(t, srv, "outsider@example.com")

	createCollection(t, srv, adminToken, "Household")

	rec := doJSON(t, srv, http.MethodGet, "/api/collections", outsiderToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body struct {
		Collections []collectionResponse `json:"collections"`
	}
	decodeInto(t, rec, &body)
	if len(body.Collections) != 0 {
		t.Errorf("a non-member sees %d collections, want 0", len(body.Collections))
	}
}

func TestAddingAMemberWithoutASealedKeyCreatesAPendingGrant(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	invitee, inviteeToken := loginTestUser(t, srv, "invitee@example.com")

	collection := createCollection(t, srv, adminToken, "Household")

	// The server cannot seal a collection key — it never holds one. So an
	// admin adding a member records an intention, and 202 says exactly that
	// rather than pretending the grant took effect.
	rec := doJSON(t, srv, http.MethodPost, "/api/collections/"+collection.ID+"/members",
		adminToken, map[string]string{"userId": invitee.ID, "role": "member"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}

	// And the invitee genuinely has no access yet.
	list := doJSON(t, srv, http.MethodGet, "/api/collections", inviteeToken, nil)
	var body struct {
		Collections []collectionResponse `json:"collections"`
	}
	decodeInto(t, list, &body)
	if len(body.Collections) != 0 {
		t.Errorf("the invitee already has %d collections; a pending grant granted access",
			len(body.Collections))
	}
}

func TestAManagerSeesAPendingGrantAndCanFulfilIt(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	invitee, inviteeToken := loginTestUser(t, srv, "invitee@example.com")

	collection := createCollection(t, srv, adminToken, "Household")
	if rec := doJSON(t, srv, http.MethodPost, "/api/collections/"+collection.ID+"/members",
		adminToken, map[string]string{"userId": invitee.ID, "role": "member"}); rec.Code != http.StatusAccepted {
		t.Fatalf("request grant: %d %s", rec.Code, rec.Body.String())
	}

	pending := doJSON(t, srv, http.MethodGet, "/api/collections/pending-grants", adminToken, nil)
	var pendingBody struct {
		PendingGrants []pendingGrantResponse `json:"pendingGrants"`
	}
	decodeInto(t, pending, &pendingBody)
	if len(pendingBody.PendingGrants) != 1 {
		t.Fatalf("manager sees %d pending grants, want 1", len(pendingBody.PendingGrants))
	}
	if pendingBody.PendingGrants[0].CollectionName != "Household" {
		t.Errorf("collectionName = %q, want the name so the UI can identify it",
			pendingBody.PendingGrants[0].CollectionName)
	}

	fulfil := doJSON(t, srv, http.MethodPost, "/api/collections/"+collection.ID+"/grants",
		adminToken, map[string]string{
			"userId": invitee.ID, "sealedCollectionKey": "sealed-to-invitee",
		})
	if fulfil.Code != http.StatusCreated {
		t.Fatalf("fulfil: %d %s", fulfil.Code, fulfil.Body.String())
	}

	list := doJSON(t, srv, http.MethodGet, "/api/collections", inviteeToken, nil)
	var body struct {
		Collections []collectionResponse `json:"collections"`
	}
	decodeInto(t, list, &body)
	if len(body.Collections) != 1 {
		t.Fatalf("the invitee has %d collections after fulfilment, want 1", len(body.Collections))
	}
	if body.Collections[0].SealedCollectionKey != "sealed-to-invitee" {
		t.Errorf("sealedCollectionKey = %q, want the copy sealed to this user",
			body.Collections[0].SealedCollectionKey)
	}
}

func TestANonMemberCannotFulfilAGrant(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	invitee, _ := loginTestUser(t, srv, "invitee@example.com")
	_, outsiderToken := loginTestUser(t, srv, "outsider@example.com")

	collection := createCollection(t, srv, adminToken, "Household")
	if rec := doJSON(t, srv, http.MethodPost, "/api/collections/"+collection.ID+"/members",
		adminToken, map[string]string{"userId": invitee.ID, "role": "member"}); rec.Code != http.StatusAccepted {
		t.Fatalf("request grant: %d", rec.Code)
	}

	// An outsider holds no collection key, so any blob they upload is garbage
	// that would lock the invitee out with no error anyone could diagnose.
	rec := doJSON(t, srv, http.MethodPost, "/api/collections/"+collection.ID+"/grants",
		outsiderToken, map[string]string{
			"userId": invitee.ID, "sealedCollectionKey": "garbage",
		})
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestAPlainMemberCannotAddOrRemoveMembers(t *testing.T) {
	srv := newTestServer(t)
	admin, adminToken := loginAdmin(t, srv, "admin@example.com")
	member, memberToken := loginTestUser(t, srv, "member@example.com")
	stranger, _ := loginTestUser(t, srv, "stranger@example.com")

	collection := createCollection(t, srv, adminToken, "Household")
	if err := srv.store.FulfilGrantOrAdd(context.Background(),
		collection.ID, member.ID, "sealed-to-member", "member", admin.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}

	// Spec 5.1: a member may read and edit items, but membership is a manager's
	// business. Otherwise anyone in a collection could quietly widen it.
	add := doJSON(t, srv, http.MethodPost, "/api/collections/"+collection.ID+"/members",
		memberToken, map[string]string{"userId": stranger.ID, "role": "member"})
	if add.Code != http.StatusForbidden {
		t.Errorf("add status = %d, want %d", add.Code, http.StatusForbidden)
	}

	remove := doJSON(t, srv, http.MethodDelete,
		"/api/collections/"+collection.ID+"/members/"+admin.ID, memberToken, nil)
	if remove.Code != http.StatusForbidden {
		t.Errorf("remove status = %d, want %d", remove.Code, http.StatusForbidden)
	}
}

func TestRemovingAMemberRevokesTheirAccessToItems(t *testing.T) {
	srv := newTestServer(t)
	admin, adminToken := loginAdmin(t, srv, "admin@example.com")
	member, memberToken := loginTestUser(t, srv, "member@example.com")

	collection := createCollection(t, srv, adminToken, "Household")
	if err := srv.store.FulfilGrantOrAdd(context.Background(),
		collection.ID, member.ID, "sealed-to-member", "member", admin.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if rec := doJSON(t, srv, http.MethodPost, "/api/items", adminToken, map[string]string{
		"collectionId": collection.ID, "ciphertext": "shared", "wrappedItemKey": "k",
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create item: %d %s", rec.Code, rec.Body.String())
	}

	before := doJSON(t, srv, http.MethodGet, "/api/sync", memberToken, nil)
	var beforeBody syncResponse
	decodeInto(t, before, &beforeBody)
	if len(beforeBody.Items) != 1 {
		t.Fatalf("member sees %d items before removal, want 1", len(beforeBody.Items))
	}

	if rec := doJSON(t, srv, http.MethodDelete,
		"/api/collections/"+collection.ID+"/members/"+member.ID, adminToken, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body.String())
	}

	after := doJSON(t, srv, http.MethodGet, "/api/sync", memberToken, nil)
	var afterBody syncResponse
	decodeInto(t, after, &afterBody)
	if len(afterBody.Items) != 0 {
		t.Errorf("member still sees %d items after removal", len(afterBody.Items))
	}
	if len(afterBody.Collections) != 0 {
		t.Errorf("member still sees %d collections after removal", len(afterBody.Collections))
	}
}

func TestMemberListNeverCarriesSealedKeys(t *testing.T) {
	srv := newTestServer(t)
	admin, adminToken := loginAdmin(t, srv, "admin@example.com")
	member, _ := loginTestUser(t, srv, "member@example.com")

	collection := createCollection(t, srv, adminToken, "Household")
	if err := srv.store.FulfilGrantOrAdd(context.Background(),
		collection.ID, member.ID, "sealed-to-member", "member", admin.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}

	rec := doJSON(t, srv, http.MethodGet, "/api/collections/"+collection.ID+"/members", adminToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	// A member list is a directory, not a key distribution channel. Each
	// member's sealed key opens the collection for them alone, and shipping the
	// whole set to anyone who asks would hand an attacker every blob at once.
	if body := rec.Body.String(); strings.Contains(body, "sealed-to-member") {
		t.Errorf("member list leaks a sealed collection key: %s", body)
	}
}

func TestOnlyAnAdminMayDeleteACollection(t *testing.T) {
	srv := newTestServer(t)
	admin, adminToken := loginAdmin(t, srv, "admin@example.com")
	member, memberToken := loginTestUser(t, srv, "member@example.com")

	collection := createCollection(t, srv, adminToken, "Household")
	if err := srv.store.FulfilGrantOrAdd(context.Background(),
		collection.ID, member.ID, "sealed", "manager", admin.ID); err != nil {
		t.Fatalf("add manager: %v", err)
	}

	// Even a manager cannot delete: managers run membership, admins own the
	// graph's shape.
	if rec := doJSON(t, srv, http.MethodDelete, "/api/collections/"+collection.ID,
		memberToken, nil); rec.Code != http.StatusForbidden {
		t.Errorf("manager delete status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if rec := doJSON(t, srv, http.MethodDelete, "/api/collections/"+collection.ID,
		adminToken, nil); rec.Code != http.StatusNoContent {
		t.Errorf("admin delete status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}
