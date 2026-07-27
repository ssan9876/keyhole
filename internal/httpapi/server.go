package httpapi

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/ssan9876/keyhole/internal/auth"
	"github.com/ssan9876/keyhole/internal/config"
	"github.com/ssan9876/keyhole/internal/store"
)

// Server owns the routing table and the dependencies handlers need.
type Server struct {
	cfg     config.Config
	store   *store.Store
	secret  []byte
	logger  *slog.Logger
	mux     *http.ServeMux
	limiter *auth.Limiter
	// preloginLimiter is separate and more generous. Prelogin is not an
	// enumeration oracle — the decoy salt is what defeats that, by answering
	// identically for an address with an account and one without. What this
	// bounds is abuse: an unauthenticated endpoint that does a database lookup
	// and an HMAC on every call. Keeping it off the login budget means a user
	// mistyping their password does not spend two allowances per attempt.
	preloginLimiter *auth.Limiter
	// stop ends the background sweeper. Without it every server leaks a
	// goroutine holding a ten-minute ticker — invisible in production, where
	// there is one server for the life of the process, but newTestServer is the
	// fixture every handler test uses and will keep using.
	stop     chan struct{}
	stopOnce sync.Once
}

// New builds the server and registers every route.
//
// Routing is stdlib ServeMux. Go 1.22's method-and-wildcard patterns
// ("POST /api/items/{id}") cover every route in spec section 4.3, so a router
// dependency would buy nothing.
func New(cfg config.Config, st *store.Store, secret []byte, logger *slog.Logger) *Server {
	s := &Server{
		cfg:    cfg,
		store:  st,
		secret: secret,
		logger: logger,
		mux:    http.NewServeMux(),
		// Five free attempts, then 2s, 4s, 8s… capped at five minutes. Generous
		// enough that a user mistyping their password never notices, harsh
		// enough that online guessing against a 64 MiB Argon2id is hopeless.
		limiter: auth.NewLimiter(5, 2*time.Second, 5*time.Minute),
		// Twenty free calls before any delay: a real client makes one prelogin
		// per sign-in attempt, so this never touches a human, while a script
		// walking an address list hits it immediately.
		preloginLimiter: auth.NewLimiter(20, time.Second, time.Minute),
		stop:            make(chan struct{}),
	}
	// WriteError and WriteJSON are free functions with no server to reach, so
	// this is how their one log line ends up in the configured destination and
	// format rather than the global slog's.
	setWriteLogger(logger)
	s.routes()
	go s.sweepLimiter()
	return s
}

// Close releases the server's background resources. It does not touch the
// store or the http.Server; those belong to whoever created them.
//
// Safe to call more than once, and safe to call on a server that is still
// serving — all it stops is the sweeper.
func (s *Server) Close() error {
	s.stopOnce.Do(func() { close(s.stop) })
	return nil
}

// sweepLimiter discards stale rate-limit entries. Without it, an attacker
// cycling source addresses grows the entries map without bound. It runs for
// the life of the server and exits on Close.
func (s *Server) sweepLimiter() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.limiter.Sweep(time.Hour)
			s.preloginLimiter.Sweep(time.Hour)
		case <-s.stop:
			return
		}
	}
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("POST /api/enroll/{token}", s.handleEnroll)

	s.mux.HandleFunc("POST /api/auth/prelogin", s.handlePrelogin)
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/auth/refresh", s.handleRefresh)
	s.mux.HandleFunc("POST /api/auth/logout", s.requireAuth(s.handleLogout))

	s.mux.HandleFunc("POST /api/items", s.requireAuth(s.handleCreateItem))
	s.mux.HandleFunc("POST /api/items/bulk", s.requireAuth(s.handleBulkItems))
	s.mux.HandleFunc("PUT /api/items/{id}", s.requireAuth(s.handleUpdateItem))
	s.mux.HandleFunc("DELETE /api/items/{id}", s.requireAuth(s.handleDeleteItem))

	s.mux.HandleFunc("POST /api/folders", s.requireAuth(s.handleCreateFolder))
	s.mux.HandleFunc("PUT /api/folders/{id}", s.requireAuth(s.handleUpdateFolder))
	s.mux.HandleFunc("DELETE /api/folders/{id}", s.requireAuth(s.handleDeleteFolder))

	s.mux.HandleFunc("GET /api/sync", s.requireAuth(s.handleSync))

	// The membership routes are requireAuth, not requireAdmin: a manager who is
	// not an admin must be able to run their own collection. requireManager
	// inside each handler enforces the rest.
	s.mux.HandleFunc("GET /api/collections", s.requireAuth(s.handleListCollections))
	s.mux.HandleFunc("POST /api/collections", s.requireAdmin(s.handleCreateCollection))
	s.mux.HandleFunc("GET /api/collections/pending-grants", s.requireAuth(s.handleListPendingGrants))
	s.mux.HandleFunc("DELETE /api/collections/{id}", s.requireAdmin(s.handleDeleteCollection))
	s.mux.HandleFunc("GET /api/collections/{id}/members", s.requireAuth(s.handleListMembers))
	s.mux.HandleFunc("POST /api/collections/{id}/members", s.requireAuth(s.handleAddMember))
	s.mux.HandleFunc("DELETE /api/collections/{id}/members/{userId}", s.requireAuth(s.handleRemoveMember))
	s.mux.HandleFunc("POST /api/collections/{id}/grants", s.requireAuth(s.handleFulfilGrant))

	s.mux.HandleFunc("GET /api/directory", s.requireAuth(s.handleDirectory))

	// Anything unmatched is a 404 in the standard envelope rather than Go's
	// plain-text default, so a client only ever parses one error shape.
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, http.StatusNotFound, CodeNotFound, "no such endpoint")
	})

	// Deliberately absent: any registration or signup route. Accounts are
	// created by an admin (spec section 5). Adding one here is a design change,
	// not a feature.
}

// Handler returns the fully wrapped handler. Order matters: requestID must be
// outermost so the log and panic middlewares can reference the ID.
func (s *Server) Handler() http.Handler {
	var h http.Handler = s.mux
	h = securityHeaders(h)
	h = recoverPanic(s.logger)(h)
	h = accessLog(s.logger)(h)
	h = requestID(h)
	return h
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	version, err := s.store.SchemaVersion(r.Context())
	if err != nil {
		s.logger.Error("healthz schema version", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "database is not reachable")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"schemaVersion": version,
	})
}
