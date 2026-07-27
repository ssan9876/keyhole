package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ssan9876/keyhole/internal/auth"
)

func TestGetAccountReturnsTheProfileAndNoKeyMaterial(t *testing.T) {
	srv := newTestServer(t)
	user, token := loginTestUser(t, srv, "person@example.com")

	rec := doJSON(t, srv, http.MethodGet, "/api/account", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		Name      string `json:"name"`
		Role      string `json:"role"`
		PublicKey string `json:"publicKey"`
	}
	decodeInto(t, rec, &body)
	if body.ID != user.ID {
		t.Errorf("id = %q, want %q", body.ID, user.ID)
	}
	if body.PublicKey == "" {
		t.Error("publicKey is empty; the client renders its own fingerprint from it")
	}
	// The wrapped keys are delivered by login, once, with the tokens. Repeating
	// them on a plain profile read widens the blast radius of any endpoint that
	// is ever accidentally cached or logged.
	for _, field := range []string{"authHash", "protectedUserKey", "encryptedPrivateKey"} {
		if strings.Contains(rec.Body.String(), field) {
			t.Errorf("/api/account carries %q", field)
		}
	}
}

func TestRotatingThePasswordRequiresTheCurrentOne(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	// A stolen access token must not be enough to overwrite the wrapped key.
	// An attacker holding one cannot produce a valid new protectedUserKey, but
	// they could write garbage into it and destroy the vault; the current
	// credential is what stops that.
	rec := doJSON(t, srv, http.MethodPost, "/api/account/password", token, map[string]string{
		"currentAuthHash":  "not-the-right-hash",
		"kdfSalt":          "bmV3LXNhbHQtMTZieXRlcw==",
		"params":           auth.DefaultKDFParamsJSON,
		"authHash":         "bmV3LWF1dGgtaGFzaA==",
		"protectedUserKey": "new-protected-user-key",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRotatingThePasswordSucceedsAndInvalidatesTheOldCredential(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	login := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash, "deviceLabel": "test",
	})
	var loginBody struct {
		AccessToken string `json:"accessToken"`
	}
	decodeInto(t, login, &loginBody)

	rec := doJSON(t, srv, http.MethodPost, "/api/account/password", loginBody.AccessToken,
		map[string]string{
			"currentAuthHash":  authHash,
			"kdfSalt":          "bmV3LXNhbHQtMTZieXRlcw==",
			"params":           auth.DefaultKDFParamsJSON,
			"authHash":         "bmV3LWF1dGgtaGFzaA==",
			"protectedUserKey": "new-protected-user-key",
		})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// The old credential must stop working, or the change achieved nothing.
	old := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash, "deviceLabel": "test",
	})
	if old.Code != http.StatusUnauthorized {
		t.Errorf("the old password still logs in: %d", old.Code)
	}

	// And the new one must work.
	fresh := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": "bmV3LWF1dGgtaGFzaA==", "deviceLabel": "test",
	})
	if fresh.Code != http.StatusOK {
		t.Errorf("the new password does not log in: %d %s", fresh.Code, fresh.Body.String())
	}
}

func TestRotatingThePasswordRejectsNonDefaultParams(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	login := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash, "deviceLabel": "test",
	})
	var loginBody struct {
		AccessToken string `json:"accessToken"`
	}
	decodeInto(t, login, &loginBody)

	// This is the endpoint that would have created the first account whose
	// params differ from the decoy's, making that address enumerable through
	// prelogin.
	rec := doJSON(t, srv, http.MethodPost, "/api/account/password", loginBody.AccessToken,
		map[string]string{
			"currentAuthHash":  authHash,
			"kdfSalt":          "bmV3LXNhbHQtMTZieXRlcw==",
			"params":           `{"algorithm":"argon2id","memoryKiB":131072,"iterations":4,"parallelism":4}`,
			"authHash":         "bmV3LWF1dGgtaGFzaA==",
			"protectedUserKey": "new-protected-user-key",
		})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestPreloginStillCannotDistinguishARealAccountAfterARotation(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	login := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash, "deviceLabel": "test",
	})
	var loginBody struct {
		AccessToken string `json:"accessToken"`
	}
	decodeInto(t, login, &loginBody)

	if rec := doJSON(t, srv, http.MethodPost, "/api/account/password", loginBody.AccessToken,
		map[string]string{
			"currentAuthHash":  authHash,
			"kdfSalt":          "bmV3LXNhbHQtMTZieXRlcw==",
			"params":           auth.DefaultKDFParamsJSON,
			"authHash":         "bmV3LWF1dGgtaGFzaA==",
			"protectedUserKey": "new-protected-user-key",
		}); rec.Code != http.StatusNoContent {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}

	real := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "person@example.com"})
	decoy := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "ghost@example.com"})

	var realBody, decoyBody struct {
		KDFSalt string `json:"kdfSalt"`
		Params  string `json:"params"`
	}
	decodeInto(t, real, &realBody)
	decodeInto(t, decoy, &decoyBody)

	// This is the whole reason params are pinned. The salts differ, as they
	// must; the params must not, or the field itself answers "does this address
	// have an account here".
	if realBody.Params != decoyBody.Params {
		t.Errorf("params differ: real %q, decoy %q — this account is now enumerable",
			realBody.Params, decoyBody.Params)
	}
	if realBody.KDFSalt == decoyBody.KDFSalt {
		t.Error("real and decoy salts are identical; the decoy is not per-address")
	}
}

func TestRotatingTheRecoveryCodeLeavesLoginWorking(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	login := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash, "deviceLabel": "test",
	})
	var loginBody struct {
		AccessToken string `json:"accessToken"`
	}
	decodeInto(t, login, &loginBody)

	rec := doJSON(t, srv, http.MethodPost, "/api/account/recovery", loginBody.AccessToken,
		map[string]string{
			"currentAuthHash":          authHash,
			"recoverySalt":             "bmV3LXJlY292ZXJ5LXNhbHQ=",
			"recoveryKdfParams":        auth.DefaultKDFParamsJSON,
			"recoveryProtectedUserKey": "new-recovery-blob",
		})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// A user who regenerates a recovery code and can then no longer sign in has
	// lost both routes at once.
	again := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash, "deviceLabel": "test",
	})
	if again.Code != http.StatusOK {
		t.Errorf("login broke after a recovery rotation: %d", again.Code)
	}
}

func TestListingSessionsMarksTheCurrentOneAndHidesTokens(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")
	_, _ = loginTestUser(t, srv, "other@example.com")

	rec := doJSON(t, srv, http.MethodGet, "/api/account/sessions", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body struct {
		Sessions []struct {
			ID          string `json:"id"`
			DeviceLabel string `json:"deviceLabel"`
			Current     bool   `json:"current"`
		} `json:"sessions"`
	}
	decodeInto(t, rec, &body)
	if len(body.Sessions) != 1 {
		t.Fatalf("got %d sessions, want 1 — another user's sessions are listed", len(body.Sessions))
	}
	// A user asked to end a session they do not recognize has to be able to
	// tell which one they are using right now.
	if !body.Sessions[0].Current {
		t.Error("the session making the request is not marked current")
	}
	for _, field := range []string{"token", "tokenHash", "refresh"} {
		if strings.Contains(rec.Body.String(), field) {
			t.Errorf("session list carries %q", field)
		}
	}
}

func TestRevokingAnotherUsersSessionIsNotFound(t *testing.T) {
	srv := newTestServer(t)
	_, mineToken := loginTestUser(t, srv, "mine@example.com")
	_, theirsToken := loginTestUser(t, srv, "theirs@example.com")

	list := doJSON(t, srv, http.MethodGet, "/api/account/sessions", theirsToken, nil)
	var theirs struct {
		Sessions []struct {
			ID string `json:"id"`
		} `json:"sessions"`
	}
	decodeInto(t, list, &theirs)
	if len(theirs.Sessions) != 1 {
		t.Fatalf("setup: got %d sessions", len(theirs.Sessions))
	}

	rec := doJSON(t, srv, http.MethodDelete,
		"/api/account/sessions/"+theirs.Sessions[0].ID, mineToken, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	// And the victim is still signed in.
	still := doJSON(t, srv, http.MethodGet, "/api/account", theirsToken, nil)
	if still.Code != http.StatusOK {
		t.Errorf("another user revoked this session: %d", still.Code)
	}
}

func TestRevokingOwnSessionEndsIt(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	list := doJSON(t, srv, http.MethodGet, "/api/account/sessions", token, nil)
	var body struct {
		Sessions []struct {
			ID string `json:"id"`
		} `json:"sessions"`
	}
	decodeInto(t, list, &body)

	if rec := doJSON(t, srv, http.MethodDelete,
		"/api/account/sessions/"+body.Sessions[0].ID, token, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if rec := doJSON(t, srv, http.MethodGet, "/api/account", token, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("the revoked token still works: %d", rec.Code)
	}
}
