package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ssan9876/keyhole/internal/auth"
	"github.com/ssan9876/keyhole/internal/store"
)

// tooManyAttempts reports the throttle. Retry-After is advisory: an honest
// client can back off politely, and an attacker learns only what the timing
// already tells them.
func tooManyAttempts(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(retryAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	WriteError(w, http.StatusTooManyRequests, CodeRateLimited,
		"too many attempts; please wait before trying again")
}

const userContextKey contextKey = "user"

// UserFrom returns the authenticated user placed by requireAuth.
func UserFrom(ctx context.Context) (store.User, bool) {
	user, ok := ctx.Value(userContextKey).(store.User)
	return user, ok
}

type preloginRequest struct {
	Email string `json:"email"`
}

// handlePrelogin gives a client the salt and params it needs to derive.
//
// An unknown address gets a deterministic decoy of exactly the same shape.
// Anything else — a 404, a different field set, a different salt length —
// turns this endpoint into a way to enumerate who has an account here.
func (s *Server) handlePrelogin(w http.ResponseWriter, r *http.Request) {
	var req preloginRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	// Prelogin is not an enumeration oracle: the decoy salt below answers
	// identically for an address with an account and one without, which is what
	// actually defeats enumeration. The limit here bounds abuse of an
	// unauthenticated endpoint that does a database lookup and an HMAC per call.
	//
	// It records against its own budget on every call, not just on failure —
	// prelogin has no notion of failure, since every address gets an answer, so
	// a read-only check would bound nothing at all.
	preloginKey := "prelogin:" + ClientIP(r)
	if allowed, retryAfter := s.preloginLimiter.Allow(preloginKey); !allowed {
		tooManyAttempts(w, retryAfter)
		return
	}
	s.preloginLimiter.RecordFailure(preloginKey)

	normalized := store.NormalizeEmail(req.Email)
	response := map[string]string{
		"kdfSalt": auth.DecoySalt(s.secret, normalized),
		"params":  auth.DefaultKDFParamsJSON,
	}

	user, err := s.store.UserByEmail(r.Context(), normalized)
	if err == nil && user.Status == "active" && user.KDFSalt.Valid && user.KDFParams.Valid {
		response["kdfSalt"] = user.KDFSalt.String
		response["params"] = user.KDFParams.String
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logger.Error("prelogin lookup", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not process the request")
		return
	}

	WriteJSON(w, http.StatusOK, response)
}

type loginRequest struct {
	Email       string `json:"email"`
	AuthHash    string `json:"authHash"`
	DeviceLabel string `json:"deviceLabel"`
}

// invalidCredentials is the single response for every failed login. One
// message, one code, one status, whatever actually went wrong.
func invalidCredentials(w http.ResponseWriter) {
	WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "email or master password is incorrect")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	// Two independent keys, consulted at deliberately different points.
	//
	// The IP key gates before the hash. It is the CPU defence, so it has to stop
	// the work from starting, and it does block everyone behind that address —
	// intended: one host grinding through many accounts is what it exists to
	// stop.
	//
	// The account key gates only failures, and is therefore consulted after
	// verification. Checked up front it was a lockout weapon: household email
	// addresses are personal addresses, a low bar to learn, and anyone who knew
	// one could fail a login every few minutes and hold the real owner out
	// indefinitely, because a *correct* auth hash got the same 429. Letting a
	// correct credential through costs nothing against a guesser, who by
	// definition does not have one.
	//
	// Both keys use the normalized address so case variations cannot buy extra
	// attempts.
	ipKey := "ip:" + ClientIP(r)
	accountKey := "account:" + store.NormalizeEmail(req.Email)

	if allowed, retryAfter := s.limiter.Allow(ipKey); !allowed {
		tooManyAttempts(w, retryAfter)
		return
	}

	user, err := s.store.UserByEmail(r.Context(), req.Email)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logger.Error("login lookup", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not process the request")
		return
	}

	// Verify unconditionally, against a dummy value when the account does not
	// exist, so that the Argon2id cost is paid either way. Returning early
	// would make an unknown address measurably faster to probe.
	stored := "argon2id$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if err == nil && user.AuthHash.Valid {
		stored = user.AuthHash.String
	}
	ok := auth.VerifyAuthHash(req.AuthHash, stored)

	if err != nil || !ok || user.Status != "active" {
		// Read the account key's verdict before recording, so the sequence of
		// statuses a failing caller sees is unchanged from when it gated up
		// front. Every failing path reaches here — unknown address, wrong hash,
		// disabled account — so throttling still cannot be used to tell them
		// apart.
		allowed, retryAfter := s.limiter.Allow(accountKey)
		s.limiter.RecordFailure(ipKey)
		s.limiter.RecordFailure(accountKey)
		if !allowed {
			tooManyAttempts(w, retryAfter)
			return
		}
		invalidCredentials(w)
		return
	}

	session, accessToken, refreshToken, err := s.store.CreateSession(r.Context(), user.ID, req.DeviceLabel)
	if err != nil {
		s.logger.Error("create session", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not start a session")
		return
	}

	// A success clears both counters, so a user who mistypes a few times and
	// then gets it right is not still throttled on their next sign-in.
	s.limiter.Reset(ipKey)
	s.limiter.Reset(accountKey)
	// A successful sign-in is proof the traffic from this address is real, so
	// it clears the prelogin budget too. Without this a household behind one
	// NAT address is throttled after twenty sign-ins in an hour and told
	// nothing about why.
	s.preloginLimiter.Reset("prelogin:" + ClientIP(r))

	// The wrapped keys ride along with the tokens: the client derived its auth
	// hash before it had them, and needs them now to finish unlocking.
	WriteJSON(w, http.StatusOK, map[string]any{
		"accessToken":         accessToken,
		"refreshToken":        refreshToken,
		"expiresAt":           session.ExpiresAt.Format(time.RFC3339),
		"protectedUserKey":    user.ProtectedUserKey.String,
		"encryptedPrivateKey": user.EncryptedPrivateKey.String,
		"user": map[string]string{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
			"role":  user.Role,
		},
	})
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	session, accessToken, refreshToken, err := s.store.RotateSession(r.Context(), req.RefreshToken)
	if errors.Is(err, store.ErrNotFound) {
		WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "this session is no longer valid")
		return
	}
	if err != nil {
		s.logger.Error("rotate session", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not refresh the session")
		return
	}

	// RotateSession touches only the sessions table, so the account behind it
	// has to be checked separately. Without this a disabled account keeps
	// minting fresh access tokens with a 200 for the full refresh lifetime:
	// they fail at requireAuth, so nothing is readable, but "disable this
	// account" would not end that account's sessions and refresh would be the
	// one path that answers differently from every other. Same 401 as an
	// invalid session, for the same reason.
	//
	// Rotating first and rejecting after is deliberate: the old refresh token
	// is spent and the new pair is never handed out, so the session dies here
	// instead of lingering until its absolute expiry.
	user, err := s.store.UserByID(r.Context(), session.UserID)
	if err != nil || user.Status != "active" {
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.logger.Error("refresh user lookup", "id", RequestIDFrom(r.Context()), "error", err)
		}
		WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "this session is no longer valid")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
		"expiresAt":    session.ExpiresAt.Format(time.RFC3339),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// requireAuth cannot call this handler without a session in context, so
	// the absent case is unreachable rather than merely unlikely.
	session, _ := sessionFrom(r.Context())
	if err := s.store.RevokeSession(r.Context(), session.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logger.Error("revoke session", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not sign out")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

const sessionContextKey contextKey = "session"

func sessionFrom(ctx context.Context) (store.Session, bool) {
	session, ok := ctx.Value(sessionContextKey).(store.Session)
	return session, ok
}

// requireAuth resolves the bearer token to a live session and an active user.
//
// Every rejection is the same 401 with the same body: distinguishing "no
// token" from "revoked" from "disabled account" would tell an attacker which
// tokens were once real.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		token, found := strings.CutPrefix(header, "Bearer ")
		if !found || token == "" {
			WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required")
			return
		}

		session, err := s.store.SessionByAccessToken(r.Context(), token)
		if err != nil {
			WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required")
			return
		}

		user, err := s.store.UserByID(r.Context(), session.UserID)
		if err != nil || user.Status != "active" {
			WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required")
			return
		}

		// Sliding expiry: an actively used session stays alive. A failure here
		// must not block the request — the session is valid, we simply did not
		// manage to extend it.
		if err := s.store.TouchSession(r.Context(), session.ID); err != nil {
			s.logger.Warn("touch session", "id", RequestIDFrom(r.Context()), "error", err)
		}

		ctx := context.WithValue(r.Context(), userContextKey, user)
		ctx = context.WithValue(ctx, sessionContextKey, session)
		next(w, r.WithContext(ctx))
	}
}

// requireAdmin wraps requireAuth and additionally demands the admin role.
//
// 403, not 404: unlike a vault row, the existence of the admin surface is not
// a secret — every client knows the endpoints exist — so hiding it buys
// nothing, and a 403 tells an honest client the truth about why it failed.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFrom(r.Context())
		if !ok || user.Role != "admin" {
			WriteError(w, http.StatusForbidden, CodeForbidden, "this action requires an administrator")
			return
		}
		next(w, r)
	})
}
