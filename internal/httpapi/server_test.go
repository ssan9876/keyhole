package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ssan9876/keyhole/internal/config"
	"github.com/ssan9876/keyhole/internal/store"
)

// newTestServer builds a server over a fresh migrated database.
func newTestServer(t *testing.T) *Server {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	cfg := config.Default()
	cfg.BaseURL = "http://test.local"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	return New(cfg, st, make([]byte, 32), logger)
}

func TestHealthzReportsOK(t *testing.T) {
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Status        string `json:"status"`
		SchemaVersion int    `json:"schemaVersion"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want %q", body.Status, "ok")
	}
	// The update command polls this after swapping the binary; a version of 0
	// would mean migrations had not run.
	if body.SchemaVersion < 1 {
		t.Errorf("schemaVersion = %d, want at least 1", body.SchemaVersion)
	}
}

func TestHealthzCarriesSecurityHeaders(t *testing.T) {
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("security headers are not applied to routed responses")
	}
}

func TestUnknownRouteReturnsTheErrorEnvelope(t *testing.T) {
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/nope", nil))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("a 404 must still be the JSON error envelope, got %q", rec.Body.String())
	}
	if body.Error.Code != "not_found" {
		t.Errorf("code = %q, want %q", body.Error.Code, "not_found")
	}
}

func TestThereIsNoRegistrationRoute(t *testing.T) {
	srv := newTestServer(t)

	// Spec section 5: accounts exist only because an admin created them.
	// This is not a disabled flag — the route must not exist at all.
	for _, path := range []string{"/api/auth/register", "/api/register", "/api/signup", "/api/users"} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("POST %s returned %d; no registration route may exist", path, rec.Code)
		}
	}
}

func TestPanicInAHandlerBecomesA500(t *testing.T) {
	srv := newTestServer(t)
	srv.mux.HandleFunc("GET /api/test-panic", func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/test-panic", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}
