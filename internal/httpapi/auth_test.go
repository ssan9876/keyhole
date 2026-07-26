package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ssan9876/keyhole/internal/store"
)

// enrollUser seeds an active account and returns the raw auth hash it enrolled
// with, so tests can log in as that user.
func enrollTestUser(t *testing.T, srv *Server, email string) (store.User, string) {
	t.Helper()

	_, token := seedInvite(t, srv, email)
	body := enrollBody()
	if rec := postJSON(t, srv, "/api/enroll/"+token, body); rec.Code != http.StatusOK {
		t.Fatalf("enrollment failed: %d %s", rec.Code, rec.Body.String())
	}
	user, err := srv.store.UserByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	return user, body["authHash"]
}

func TestPreloginReturnsRealSaltForKnownAccount(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	rec := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "PERSON@example.com"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		KDFSalt string `json:"kdfSalt"`
		Params  string `json:"params"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.KDFSalt != enrollBody()["kdfSalt"] {
		t.Errorf("kdfSalt = %q, want the enrolled %q", body.KDFSalt, enrollBody()["kdfSalt"])
	}
	if body.Params == "" {
		t.Error("params is empty")
	}
}

func TestPreloginDecoyIsStableAndShapedLikeARealResponse(t *testing.T) {
	srv := newTestServer(t)

	first := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "ghost@example.com"})
	second := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "ghost@example.com"})

	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("status codes %d and %d, want 200 for an unknown address", first.Code, second.Code)
	}
	// An address that answered differently on retry would announce, by that
	// inconsistency alone, that no account exists.
	if first.Body.String() != second.Body.String() {
		t.Error("prelogin gave two different answers for the same unknown address")
	}

	var decoy, real struct {
		KDFSalt string `json:"kdfSalt"`
		Params  string `json:"params"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &decoy); err != nil {
		t.Fatal(err)
	}
	enrollTestUser(t, srv, "person@example.com")
	realRec := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "person@example.com"})
	if err := json.Unmarshal(realRec.Body.Bytes(), &real); err != nil {
		t.Fatal(err)
	}
	if len(decoy.KDFSalt) != len(real.KDFSalt) {
		t.Errorf("decoy salt is %d characters, real is %d; the length distinguishes them",
			len(decoy.KDFSalt), len(real.KDFSalt))
	}
	if decoy.Params != real.Params {
		t.Errorf("decoy params %q differ from real params %q", decoy.Params, real.Params)
	}
}

func TestPreloginDecoyDiffersBetweenAddresses(t *testing.T) {
	srv := newTestServer(t)

	a := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "a@example.com"})
	b := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "b@example.com"})
	if a.Body.String() == b.Body.String() {
		t.Error("two unknown addresses produced an identical salt; the decoy is not keyed by address")
	}
}

func TestLoginReturnsTokensAndWrappedKeys(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	rec := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email":       "person@example.com",
		"authHash":    authHash,
		"deviceLabel": "Test Browser",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		AccessToken         string `json:"accessToken"`
		RefreshToken        string `json:"refreshToken"`
		ProtectedUserKey    string `json:"protectedUserKey"`
		EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	// The client cannot unlock without these arriving in the login response —
	// that is the whole reason beginUnlock derives before it has them.
	if body.AccessToken == "" || body.RefreshToken == "" {
		t.Error("login did not return both tokens")
	}
	if body.ProtectedUserKey != enrollBody()["protectedUserKey"] {
		t.Error("login did not return the protected user key verbatim")
	}
	if body.EncryptedPrivateKey != enrollBody()["encryptedPrivateKey"] {
		t.Error("login did not return the encrypted private key verbatim")
	}
}

func TestLoginRejectsWrongAuthHashAndUnknownAccountIdentically(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	wrong := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": "wrong-value",
	})
	unknown := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "ghost@example.com", "authHash": "wrong-value",
	})

	if wrong.Code != http.StatusUnauthorized {
		t.Errorf("wrong auth hash status = %d, want %d", wrong.Code, http.StatusUnauthorized)
	}
	// Identical bodies and codes: otherwise the endpoint is an oracle for
	// which addresses have accounts on this server.
	if wrong.Code != unknown.Code {
		t.Errorf("status codes differ: %d for a real account, %d for an unknown one", wrong.Code, unknown.Code)
	}
	if wrong.Body.String() != unknown.Body.String() {
		t.Errorf("response bodies differ:\n real:    %s\n unknown: %s", wrong.Body.String(), unknown.Body.String())
	}
}

func TestLoginRejectsADisabledAccount(t *testing.T) {
	srv := newTestServer(t)
	user, authHash := enrollTestUser(t, srv, "person@example.com")

	if _, err := srv.store.DB().Exec(`UPDATE users SET status = 'disabled' WHERE id = ?`, user.ID); err != nil {
		t.Fatal(err)
	}
	rec := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d for a disabled account", rec.Code, http.StatusUnauthorized)
	}
}

func TestRefreshRotatesAndInvalidatesTheOldToken(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	login := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash,
	})
	var first struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}

	rec := postJSON(t, srv, "/api/auth/refresh", map[string]string{"refreshToken": first.RefreshToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	replay := postJSON(t, srv, "/api/auth/refresh", map[string]string{"refreshToken": first.RefreshToken})
	if replay.Code != http.StatusUnauthorized {
		t.Errorf("replayed refresh status = %d, want %d", replay.Code, http.StatusUnauthorized)
	}
}

func TestRefreshRejectsADisabledAccount(t *testing.T) {
	srv := newTestServer(t)
	user, authHash := enrollTestUser(t, srv, "person@example.com")

	login := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash,
	})
	var body struct {
		RefreshToken string `json:"refreshToken"`
	}
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d, want %d; body %s", login.Code, http.StatusOK, login.Body.String())
	}
	if err := json.Unmarshal(login.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	if _, err := srv.store.DB().Exec(`UPDATE users SET status = 'disabled' WHERE id = ?`, user.ID); err != nil {
		t.Fatal(err)
	}

	// RotateSession touches only the sessions table, so before this fix a
	// disabled account's refresh token kept minting fresh access tokens with a
	// 200 for the full 30 days. Those tokens failed at requireAuth, so nothing
	// was readable — but refresh was the one path that broke the uniform-401
	// taxonomy, and it meant disabling an account did not end its sessions.
	rec := postJSON(t, srv, "/api/auth/refresh", map[string]string{"refreshToken": body.RefreshToken})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("refresh status = %d for a disabled account, want %d; body %s",
			rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestRequireAuthGuardsProtectedRoutes(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	srv.mux.HandleFunc("GET /api/test-protected", srv.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFrom(r.Context())
		if !ok {
			t.Error("requireAuth did not put the user in the context")
		}
		WriteJSON(w, http.StatusOK, map[string]string{"email": user.Email})
	}))

	t.Run("no token", func(t *testing.T) {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/test-protected", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("garbage token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/test-protected", nil)
		req.Header.Set("Authorization", "Bearer not-a-real-token")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("valid token", func(t *testing.T) {
		login := postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": "person@example.com", "authHash": authHash,
		})
		var body struct {
			AccessToken string `json:"accessToken"`
		}
		if err := json.Unmarshal(login.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/test-protected", nil)
		req.Header.Set("Authorization", "Bearer "+body.AccessToken)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
		}
	})

	t.Run("token revoked mid-session", func(t *testing.T) {
		login := postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": "person@example.com", "authHash": authHash,
		})
		var body struct {
			AccessToken string `json:"accessToken"`
		}
		if err := json.Unmarshal(login.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		sess, err := srv.store.SessionByAccessToken(context.Background(), body.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.store.RevokeSession(context.Background(), sess.ID); err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/test-protected", nil)
		req.Header.Set("Authorization", "Bearer "+body.AccessToken)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		// Revocation must bite on the very next request, not at expiry.
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d after revocation, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	// This runs before "disabled account" deliberately: that subtest disables
	// the shared test user for the rest of the function, which would break
	// this one's login if it ran after.
	t.Run("expired session", func(t *testing.T) {
		login := postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": "person@example.com", "authHash": authHash,
		})
		var body struct {
			AccessToken string `json:"accessToken"`
		}
		if login.Code != http.StatusOK {
			t.Fatalf("login status = %d, want %d; body %s", login.Code, http.StatusOK, login.Body.String())
		}
		if err := json.Unmarshal(login.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		sess, err := srv.store.SessionByAccessToken(context.Background(), body.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		past := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
		if _, err := srv.store.DB().Exec(`UPDATE sessions SET expires_at = ? WHERE id = ?`, past, sess.ID); err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/test-protected", nil)
		req.Header.Set("Authorization", "Bearer "+body.AccessToken)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d for an expired session, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("disabled account", func(t *testing.T) {
		login := postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": "person@example.com", "authHash": authHash,
		})
		var body struct {
			AccessToken string `json:"accessToken"`
		}
		if login.Code != http.StatusOK {
			t.Fatalf("login status = %d, want %d; body %s", login.Code, http.StatusOK, login.Body.String())
		}
		if err := json.Unmarshal(login.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		user, err := srv.store.UserByEmail(context.Background(), "person@example.com")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := srv.store.DB().Exec(`UPDATE users SET status = 'disabled' WHERE id = ?`, user.ID); err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/test-protected", nil)
		req.Header.Set("Authorization", "Bearer "+body.AccessToken)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		// A still-valid token must not work once the account is disabled.
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d for a disabled account, want %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

func TestLogoutRevokesTheSession(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	login := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash,
	})
	var body struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+body.AccessToken)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if _, err := srv.store.SessionByAccessToken(context.Background(), body.AccessToken); err == nil {
		t.Error("the session still works after logout")
	}
}

func TestSessionExpiryIsSlidByUse(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	login := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash,
	})
	var body struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	sess, err := srv.store.SessionByAccessToken(context.Background(), body.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	near := time.Now().UTC().Add(2 * time.Minute).Format(time.RFC3339)
	if _, err := srv.store.DB().Exec(`UPDATE sessions SET expires_at = ? WHERE id = ?`, near, sess.ID); err != nil {
		t.Fatal(err)
	}

	srv.mux.HandleFunc("GET /api/test-slide", srv.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/test-slide", nil)
	req.Header.Set("Authorization", "Bearer "+body.AccessToken)
	srv.Handler().ServeHTTP(httptest.NewRecorder(), req)

	after, err := srv.store.SessionByAccessToken(context.Background(), body.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ExpiresAt.After(time.Now().UTC().Add(20 * time.Minute)) {
		t.Errorf("expiry = %s, want it slid forward by use", after.ExpiresAt)
	}
}
