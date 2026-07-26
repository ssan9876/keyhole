package httpapi

import (
	"errors"
	"net/http"

	"github.com/ssan9876/keyhole/internal/auth"
	"github.com/ssan9876/keyhole/internal/store"
)

// enrollRequest is what a client uploads after generating its key material.
// Field names match the crypto package's return values so a reader can follow
// one name from enrollUser() through to the database column.
type enrollRequest struct {
	KDFSalt                  string `json:"kdfSalt"`
	Params                   string `json:"params"`
	AuthHash                 string `json:"authHash"`
	ProtectedUserKey         string `json:"protectedUserKey"`
	PublicKey                string `json:"publicKey"`
	EncryptedPrivateKey      string `json:"encryptedPrivateKey"`
	RecoverySalt             string `json:"recoverySalt"`
	RecoveryProtectedUserKey string `json:"recoveryProtectedUserKey"`
	RecoveryKDFParams        string `json:"recoveryKdfParams"`
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" {
		WriteError(w, http.StatusNotFound, CodeNotFound, "invalid setup link")
		return
	}

	// This route is unauthenticated and its only input is a caller-chosen
	// token, so it is throttled per source address exactly as login is.
	// Without this it was the one open endpoint that would run Argon2id on
	// demand, for free, as often as asked.
	ipKey := "ip:" + ClientIP(r)
	if allowed, retryAfter := s.limiter.Allow(ipKey); !allowed {
		tooManyAttempts(w, retryAfter)
		return
	}

	var req enrollRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	if req.AuthHash == "" {
		// Hashing an empty string succeeds and costs exactly as much as hashing
		// a real one, so this has to be checked before the hash, not after.
		// Worded by hand to match (*store.ValidationError).Error(), which is what
		// every other missing field in this payload renders as.
		WriteError(w, http.StatusBadRequest, CodeBadRequest, "field \"authHash\" is required")
		return
	}

	// Establish that the token is live before paying for Argon2id. This is an
	// optimisation, not the security boundary: CompleteEnrollment re-checks the
	// invite inside its transaction, which is what actually makes a link
	// one-time under concurrency. Both checks stay.
	if _, err := s.store.InviteByToken(r.Context(), token); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.limiter.RecordFailure(ipKey)
			WriteError(w, http.StatusNotFound, CodeNotFound, "this setup link is no longer valid")
			return
		}
		s.logger.Error("invite lookup", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not complete setup")
		return
	}

	// Hash the client's auth hash before it goes anywhere near the database.
	// It is a login credential; stored as received, a database dump would grant
	// login to every account on the server.
	hashed, err := auth.HashAuthHash(req.AuthHash)
	if err != nil {
		s.logger.Error("hash auth hash", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not complete setup")
		return
	}

	user, err := s.store.CompleteEnrollment(r.Context(), token, store.EnrollmentInput{
		KDFSalt:                  req.KDFSalt,
		KDFParams:                req.Params,
		AuthHash:                 hashed,
		ProtectedUserKey:         req.ProtectedUserKey,
		PublicKey:                req.PublicKey,
		EncryptedPrivateKey:      req.EncryptedPrivateKey,
		RecoverySalt:             req.RecoverySalt,
		RecoveryProtectedUserKey: req.RecoveryProtectedUserKey,
		RecoveryKDFParams:        req.RecoveryKDFParams,
	})
	var validationErr *store.ValidationError
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Unknown, expired, and already-used links are indistinguishable, so a
		// caller cannot probe which tokens ever existed. Reachable despite the
		// pre-check above when two enrollments race for the same link.
		s.limiter.RecordFailure(ipKey)
		WriteError(w, http.StatusNotFound, CodeNotFound, "this setup link is no longer valid")
		return
	case errors.As(err, &validationErr):
		// The client's payload was wrong; its own error text is safe to echo.
		WriteError(w, http.StatusBadRequest, CodeBadRequest, validationErr.Error())
		return
	case err != nil:
		// Anything else is ours, not theirs. Log the detail, tell them nothing.
		s.logger.Error("enrollment failed", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not complete setup")
		return
	}

	// Deliberately minimal: never echo key material, not even the caller's own.
	WriteJSON(w, http.StatusOK, map[string]any{
		"id":    user.ID,
		"email": user.Email,
		"name":  user.Name,
		"role":  user.Role,
	})
}
