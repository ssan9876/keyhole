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

	var req enrollRequest
	if !DecodeJSON(w, r, &req) {
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
	if req.AuthHash == "" {
		// Hashing an empty string succeeds, so check explicitly rather than
		// relying on the store to notice.
		WriteError(w, http.StatusBadRequest, CodeBadRequest, "enrollment field \"authHash\" is required")
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
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Unknown, expired, and already-used links are indistinguishable, so a
		// caller cannot probe which tokens ever existed.
		WriteError(w, http.StatusNotFound, CodeNotFound, "this setup link is no longer valid")
		return
	case err != nil:
		// A validation failure from the store is the client's fault; log the
		// detail and tell them without echoing the body back.
		s.logger.Warn("enrollment rejected", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusBadRequest, CodeBadRequest, err.Error())
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
