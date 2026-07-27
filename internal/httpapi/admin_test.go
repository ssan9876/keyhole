package httpapi

import (
	"net/http"
	"strings"
	"testing"
)

func TestAdminRoutesRejectANonAdmin(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	for _, route := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/admin/users"},
		{http.MethodPost, "/api/admin/users"},
		{http.MethodGet, "/api/admin/audit"},
		{http.MethodGet, "/api/admin/collections"},
	} {
		rec := doJSON(t, srv, route.method, route.path, token, map[string]string{})
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d, want %d", route.method, route.path, rec.Code, http.StatusForbidden)
		}
	}
}

func TestAdminUserListNeverCarriesKeyMaterial(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	loginTestUser(t, srv, "person@example.com")

	rec := doJSON(t, srv, http.MethodGet, "/api/admin/users", adminToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// Spec section 10 names this test explicitly: no admin endpoint may return
	// another user's wrapped keys. An admin having ordinary vault access to
	// everyone would make the entire cryptographic design decorative.
	//
	// The check is case- and underscore-insensitive because the realistic way
	// this breaks is a handler marshalling store.UserSummary directly, which
	// emits PascalCase field names an exact-match assertion would miss.
	assertNoKeyMaterial(t, "/api/admin/users", rec.Body.String())
}

func TestCreateUserReturnsAOneTimeSetupLink(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")

	rec := doJSON(t, srv, http.MethodPost, "/api/admin/users", adminToken, map[string]string{
		"email": "new@example.com", "name": "New Person", "role": "user",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var body struct {
		User struct {
			ID     string `json:"id"`
			Email  string `json:"email"`
			Status string `json:"status"`
		} `json:"user"`
		InviteURL string `json:"inviteUrl"`
	}
	decodeInto(t, rec, &body)
	if body.User.Status != "pending" {
		t.Errorf("status = %q, want pending", body.User.Status)
	}
	// No mail server exists (spec section 1). The link has to come back in this
	// response or the admin has nothing to hand over.
	if !strings.HasPrefix(body.InviteURL, srv.cfg.BaseURL+"/enroll/") {
		t.Errorf("inviteUrl = %q, want it under %s/enroll/", body.InviteURL, srv.cfg.BaseURL)
	}
}

func TestCreateUserRejectsADuplicateEmail(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	loginTestUser(t, srv, "taken@example.com")

	rec := doJSON(t, srv, http.MethodPost, "/api/admin/users", adminToken, map[string]string{
		"email": "TAKEN@example.com", "name": "Impostor", "role": "user",
	})
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
}

func TestReissuingAnInviteGivesAWorkingLink(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/admin/users", adminToken, map[string]string{
		"email": "new@example.com", "name": "New Person", "role": "user",
	})
	var body struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	decodeInto(t, created, &body)

	// Plan 2a left a pending user with no invite unrecoverable except by direct
	// SQL, because admin create had no rollback between the two writes. This is
	// the path out of that.
	rec := doJSON(t, srv, http.MethodPost, "/api/admin/users/"+body.User.ID+"/invite", adminToken, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var reissued struct {
		InviteURL string `json:"inviteUrl"`
	}
	decodeInto(t, rec, &reissued)

	token := reissued.InviteURL[strings.LastIndex(reissued.InviteURL, "/")+1:]
	enroll := postJSON(t, srv, "/api/enroll/"+token, enrollBody())
	if enroll.Code != http.StatusOK {
		t.Errorf("the reissued link does not work: %d %s", enroll.Code, enroll.Body.String())
	}
}

func TestDisablingAnAccountEndsItsAccess(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	target, targetToken := loginTestUser(t, srv, "person@example.com")

	rec := doJSON(t, srv, http.MethodPatch, "/api/admin/users/"+target.ID, adminToken,
		map[string]string{"status": "disabled"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if after := doJSON(t, srv, http.MethodGet, "/api/sync", targetToken, nil); after.Code != http.StatusUnauthorized {
		t.Errorf("a disabled account still reads the vault: %d", after.Code)
	}
}

func TestResettingAnAccountRequiresTheEmailTyped(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	target, _ := loginTestUser(t, srv, "person@example.com")

	// Spec section 3.7: the dialog requires typing the user's email. The server
	// enforces it too, because a destructive irreversible action must not hinge
	// on a client-side check alone.
	wrong := doJSON(t, srv, http.MethodPost, "/api/admin/users/"+target.ID+"/reset", adminToken,
		map[string]string{"confirmEmail": "someone-else@example.com"})
	if wrong.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", wrong.Code, http.StatusBadRequest)
	}

	right := doJSON(t, srv, http.MethodPost, "/api/admin/users/"+target.ID+"/reset", adminToken,
		map[string]string{"confirmEmail": "person@example.com"})
	if right.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", right.Code, http.StatusOK, right.Body.String())
	}
	var body struct {
		InviteURL string `json:"inviteUrl"`
	}
	decodeInto(t, right, &body)
	if body.InviteURL == "" {
		t.Error("a reset returned no setup link; the user has no way back in")
	}
}

func TestDeletingAReferencedUserExplainsWhyItCannot(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	creator, creatorToken := loginAdmin(t, srv, "creator@example.com")
	createCollection(t, srv, creatorToken, "Household")

	rec := doJSON(t, srv, http.MethodDelete, "/api/admin/users/"+creator.ID, adminToken, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	decodeInto(t, rec, &body)
	if body.Error.Code != "conflict" {
		t.Errorf("code = %q, want %q", body.Error.Code, "conflict")
	}
	// A bare "conflict" leaves the operator with a database error and no next
	// step. The message has to name the obstacle.
	if !strings.Contains(strings.ToLower(body.Error.Message), "collection") {
		t.Errorf("message = %q; it should say what references the account", body.Error.Message)
	}
}

func TestTheAuditLogRecordsAdministrativeActions(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")

	if rec := doJSON(t, srv, http.MethodPost, "/api/admin/users", adminToken, map[string]string{
		"email": "new@example.com", "name": "New Person", "role": "user",
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create user: %d %s", rec.Code, rec.Body.String())
	}

	rec := doJSON(t, srv, http.MethodGet, "/api/admin/audit", adminToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Entries []struct {
			Action string `json:"action"`
			Target string `json:"target"`
		} `json:"entries"`
	}
	decodeInto(t, rec, &body)

	found := false
	for _, entry := range body.Entries {
		if entry.Action == "user.create" {
			found = true
		}
	}
	if !found {
		t.Errorf("no user.create entry in %d audit entries", len(body.Entries))
	}
}

func TestAnAdminCannotDisableTheirOwnLastAdminAccount(t *testing.T) {
	srv := newTestServer(t)
	admin, adminToken := loginAdmin(t, srv, "admin@example.com")

	// Locking the only administrator out is unrecoverable from the API: there
	// is no registration endpoint and creating one needs shell access.
	rec := doJSON(t, srv, http.MethodPatch, "/api/admin/users/"+admin.ID, adminToken,
		map[string]string{"status": "disabled"})
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
}
