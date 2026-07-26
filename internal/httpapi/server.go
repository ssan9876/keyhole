package httpapi

import (
	"log/slog"
	"net/http"
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
	}
	s.routes()
	go s.sweepLimiter()
	return s
}

// sweepLimiter discards stale rate-limit entries. Without it, an attacker
// cycling source addresses grows the entries map without bound. Runs for the
// life of the process; the server is a long-lived singleton, so there is
// nothing to stop.
func (s *Server) sweepLimiter() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.limiter.Sweep(time.Hour)
	}
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("POST /api/enroll/{token}", s.handleEnroll)

	s.mux.HandleFunc("POST /api/auth/prelogin", s.handlePrelogin)
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/auth/refresh", s.handleRefresh)
	s.mux.HandleFunc("POST /api/auth/logout", s.requireAuth(s.handleLogout))

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
