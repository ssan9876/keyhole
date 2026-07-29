package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"time"
)

type contextKey string

const requestIDKey contextKey = "request-id"

// RequestIDFrom returns the per-request identifier, or "" outside a request.
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

func newRequestID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(buf)
}

// requestID assigns every request a fresh identifier and echoes it. The
// client's own X-Request-Id is deliberately ignored: adopting it would let a
// caller forge or collide entries in our logs.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// No inline script, no external anything. The web app is served from
		// this same origin and is built without inline handlers.
		//
		// 'wasm-unsafe-eval' is required, and is the narrowest thing that works:
		// the whole of Keyhole's cryptography runs Argon2id in the browser via
		// hash-wasm, which compiles a WebAssembly module — and WebAssembly.compile
		// is blocked under a bare script-src 'self'. 'wasm-unsafe-eval' permits
		// exactly WASM compilation and nothing else; unlike 'unsafe-eval' it does
		// NOT re-enable eval() of JavaScript strings, so the anti-XSS posture on
		// the one page that handles a master password is unchanged. Without this
		// every enrol, unlock and recovery fails against the real binary, and only
		// an end-to-end run against the production CSP catches it — the dev server
		// sets no CSP at all.
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; "+
				"connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// ClientIP is the address to attribute a request to.
//
// Cloudflare terminates TLS and forwards the real address in CF-Connecting-IP,
// but that header is trusted ONLY when the immediate peer is loopback — which,
// with the tunnel running beside the server, is the only path it can legitimately
// arrive by. Trusting it unconditionally would let anyone who can reach the
// server set their own apparent address and bypass rate limiting entirely.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	peer := net.ParseIP(host)
	if peer == nil || !peer.IsLoopback() {
		return host
	}

	forwarded := r.Header.Get("CF-Connecting-IP")
	if forwarded == "" {
		return host
	}
	if net.ParseIP(forwarded) == nil {
		return host
	}
	return forwarded
}

// statusRecorder captures the status code for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// accessLog records one line per request. It deliberately logs the path but
// never the query string, body, or headers: those carry tokens and email
// addresses, which must not reach an info-level log.
func accessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rec, r)

			logger.Info("request",
				"id", RequestIDFrom(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

// recoverPanic turns a handler panic into a 500 rather than a dropped
// connection, and logs it with the request ID so it can be traced.
func recoverPanic(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					logger.Error("panic",
						"id", RequestIDFrom(r.Context()),
						"path", r.URL.Path,
						"value", recovered,
					)
					WriteError(w, http.StatusInternalServerError, CodeInternal, "internal server error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
