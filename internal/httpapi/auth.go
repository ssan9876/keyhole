package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/ssan9876/keyhole/internal/auth"
	"github.com/ssan9876/keyhole/internal/store"
)

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
		invalidCredentials(w)
		return
	}

	session, accessToken, refreshToken, err := s.store.CreateSession(r.Context(), user.ID, req.DeviceLabel)
	if err != nil {
		s.logger.Error("create session", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not start a session")
		return
	}

	// The wrapped keys ride along with the tokens: the client derived its auth
	// hash before it had them, and needs them now to finish unlocking.
	WriteJSON(w, http.StatusOK, map[string]any{
		"accessToken":         accessToken,
		"refreshToken":        refreshToken,
		"expiresAt":           session.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
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

	WriteJSON(w, http.StatusOK, map[string]any{
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
		"expiresAt":    session.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, ok := sessionFrom(r.Context())
	if !ok {
		WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "not signed in")
		return
	}
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
