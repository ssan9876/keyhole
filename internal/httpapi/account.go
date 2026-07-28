package httpapi

import (
	"net/http"
	"time"

	"github.com/ssan9876/keyhole/internal/auth"
	"github.com/ssan9876/keyhole/internal/store"
)

func (s *Server) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	// The wrapped keys are delivered by login, once, alongside the tokens.
	// Repeating them on a plain profile read widens the blast radius of any
	// endpoint that is ever accidentally cached, proxied, or logged. The public
	// key is here because the client renders the user's own fingerprint from
	// it (spec section 3.9).
	WriteJSON(w, http.StatusOK, map[string]any{
		"id":        user.ID,
		"email":     user.Email,
		"name":      user.Name,
		"role":      user.Role,
		"publicKey": user.PublicKey.String,
		"createdAt": user.CreatedAt.Format(time.RFC3339),
	})
}

// verifyCurrentCredential re-checks the master password before a change that
// could destroy key material.
//
// The session already proves who the caller is. What it does not prove is that
// they hold the master password — and both endpoints below overwrite key
// material, so a stolen access token would otherwise be enough to write
// garbage over a wrapped key and destroy the vault. The attacker cannot
// produce a *valid* replacement, which is exactly why they would produce an
// invalid one.
func (s *Server) verifyCurrentCredential(w http.ResponseWriter, user store.User, currentAuthHash string) bool {
	if currentAuthHash == "" || !user.AuthHash.Valid {
		WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "master password is incorrect")
		return false
	}
	if !auth.VerifyAuthHash(currentAuthHash, user.AuthHash.String) {
		WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "master password is incorrect")
		return false
	}
	return true
}

type rotatePasswordRequest struct {
	CurrentAuthHash  string `json:"currentAuthHash"`
	KDFSalt          string `json:"kdfSalt"`
	Params           string `json:"params"`
	AuthHash         string `json:"authHash"`
	ProtectedUserKey string `json:"protectedUserKey"`
}

func (s *Server) handleRotatePassword(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())
	session, _ := sessionFrom(r.Context())

	var req rotatePasswordRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.AuthHash == "" {
		// Hashing an empty string costs exactly as much as hashing a real one,
		// so this is checked before the hash rather than after.
		WriteError(w, http.StatusBadRequest, CodeBadRequest, "authHash is required")
		return
	}
	// Pinned so the prelogin decoy stays indistinguishable from a real account.
	// The moment one account's params differ from the decoy's, asking prelogin
	// for an address and comparing that field answers "does this address have
	// an account here".
	if req.Params != auth.DefaultKDFParamsJSON {
		WriteError(w, http.StatusBadRequest, CodeBadRequest,
			"params must match the server's current KDF parameters exactly")
		return
	}
	if !s.verifyCurrentCredential(w, user, req.CurrentAuthHash) {
		return
	}

	stored, err := auth.HashAuthHash(req.AuthHash)
	if err != nil {
		s.logger.Error("hash auth hash", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not change the master password")
		return
	}

	if err := s.store.RotatePassword(r.Context(), user.ID, store.PasswordRotation{
		KDFSalt:          req.KDFSalt,
		KDFParams:        req.Params,
		AuthHash:         stored,
		ProtectedUserKey: req.ProtectedUserKey,
	}, session.ID); err != nil {
		s.writeStoreError(w, r, "rotate password", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type rotateRecoveryRequest struct {
	CurrentAuthHash          string `json:"currentAuthHash"`
	RecoverySalt             string `json:"recoverySalt"`
	RecoveryKDFParams        string `json:"recoveryKdfParams"`
	RecoveryProtectedUserKey string `json:"recoveryProtectedUserKey"`
	RecoveryAuthHash         string `json:"recoveryAuthHash"`
}

func (s *Server) handleRotateRecovery(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	var req rotateRecoveryRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.RecoveryAuthHash == "" {
		// Checked here rather than left to the store, because HashAuthHash("")
		// returns a well-formed hash: an empty value that reaches the hash
		// arrives at the store looking complete and is written, leaving a
		// recovery record no code can redeem. Hashing an empty string also
		// costs exactly as much as hashing a real one.
		WriteError(w, http.StatusBadRequest, CodeBadRequest, "field \"recoveryAuthHash\" is required")
		return
	}
	// Pinned so the recovery prelogin decoy stays indistinguishable from a real
	// account, exactly as handleRotatePassword pins params.
	//
	// This comment used to say the opposite: that recoveryKdfParams leaks
	// nothing because no endpoint returns it. POST /api/auth/recover/prelogin
	// now does — it hands this value to an unauthenticated caller and answers an
	// unknown address with auth.DefaultKDFParamsJSON — so an account holding
	// anything else here is distinguishable from a decoy, which is the exact
	// oracle that endpoint's decoy exists to close.
	//
	// Spec 4.2's "record what the blob was actually wrapped under" survives in
	// fact: every blob is made under the client's DEFAULT_KDF_PARAMS, which is
	// this string. Raising the default means re-wrapping every blob, which is a
	// migration rather than a per-account drift.
	//
	// Checked here as well as in the store, and before verifyCurrentCredential,
	// so a payload that cannot land costs no Argon2id.
	if req.RecoveryKDFParams != auth.DefaultKDFParamsJSON {
		WriteError(w, http.StatusBadRequest, CodeBadRequest,
			"recoveryKdfParams must match the server's current KDF parameters exactly")
		return
	}
	if !s.verifyCurrentCredential(w, user, req.CurrentAuthHash) {
		return
	}

	// Hashed for storage exactly as the login credential is. It is what the
	// redeem endpoints check possession of, so a database leak must not hand
	// over a value that can be replayed straight back at them.
	storedRecovery, err := auth.HashAuthHash(req.RecoveryAuthHash)
	if err != nil {
		s.logger.Error("hash recovery auth hash", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not change the recovery code")
		return
	}

	// RecoveryKDFParams is passed through as received; it was pinned to
	// auth.DefaultKDFParamsJSON above, and store.RecoveryRotation.validate pins
	// it again for every non-HTTP caller.
	if err := s.store.RotateRecovery(r.Context(), user.ID, store.RecoveryRotation{
		RecoverySalt:             req.RecoverySalt,
		RecoveryKDFParams:        req.RecoveryKDFParams,
		RecoveryProtectedUserKey: req.RecoveryProtectedUserKey,
		RecoveryAuthHash:         storedRecovery,
	}); err != nil {
		s.writeStoreError(w, r, "rotate recovery", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())
	current, _ := sessionFrom(r.Context())

	sessions, err := s.store.SessionsForUser(r.Context(), user.ID)
	if err != nil {
		s.writeStoreError(w, r, "list sessions", err)
		return
	}

	type sessionJSON struct {
		ID          string `json:"id"`
		DeviceLabel string `json:"deviceLabel"`
		CreatedAt   string `json:"createdAt"`
		LastSeenAt  string `json:"lastSeenAt"`
		Current     bool   `json:"current"`
	}

	out := make([]sessionJSON, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, sessionJSON{
			ID:          session.ID,
			DeviceLabel: session.DeviceLabel,
			CreatedAt:   session.CreatedAt.Format(time.RFC3339),
			LastSeenAt:  session.LastSeenAt.Format(time.RFC3339),
			// A user asked to end a session they do not recognize has to be
			// able to tell which one they are sitting in front of.
			Current: session.ID == current.ID,
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	if err := s.store.RevokeSessionForUser(r.Context(), r.PathValue("id"), user.ID); err != nil {
		s.writeStoreError(w, r, "revoke session", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
