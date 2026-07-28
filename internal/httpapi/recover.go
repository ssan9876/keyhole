package httpapi

import (
	"errors"
	"net/http"

	"github.com/ssan9876/keyhole/internal/auth"
	"github.com/ssan9876/keyhole/internal/store"
)

type recoverPreloginRequest struct {
	Email string `json:"email"`
}

// handleRecoverPrelogin gives a client the salt and params it needs to derive a
// recovery key from a recovery code.
//
// It is handlePrelogin with a different pair of columns, and for the same
// reason: an unknown address gets a deterministic decoy of exactly the same
// shape. Anything else — a 404, a different field set, a different salt length,
// a decoy regenerated per call — turns this endpoint into a way to enumerate
// who has an account here.
//
// Two states beyond "no such address" have to answer with the decoy as well:
// an account that is not active, and an account whose recovery blob predates
// the auth-hash split (recovery_auth_hash IS NULL, migration 0004). Neither can
// be redeemed. Handing back a real salt and refusing at the redeem step would
// leak that the address is real just as loudly as a 404 here.
func (s *Server) handleRecoverPrelogin(w http.ResponseWriter, r *http.Request) {
	var req recoverPreloginRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	// The same budget as login's prelogin, deliberately, rather than a second
	// one of its own. Both endpoints answer the same question about the same
	// address list, so separate budgets would mean an attacker throttled on one
	// simply finishes the list on the other.
	//
	// It records against that budget on every call, not just on failure —
	// prelogin has no notion of failure, since every address gets an answer, so
	// a read-only check would bound nothing at all.
	preloginKey := "prelogin:" + ClientIP(r)
	if allowed, retryAfter := s.preloginLimiter.Allow(preloginKey); !allowed {
		tooManyAttempts(w, retryAfter)
		return
	}
	s.preloginLimiter.RecordFailure(preloginKey)

	normalized := store.NormalizeEmail(req.Email)
	// DefaultKDFParamsJSON is the honest decoy: it is what a blob made today
	// records, so it matches what a redeemable account answers with.
	response := map[string]string{
		"recoverySalt":      auth.DecoyRecoverySalt(s.secret, normalized),
		"recoveryKdfParams": auth.DefaultKDFParamsJSON,
	}

	user, err := s.store.UserByEmail(r.Context(), normalized)
	if err == nil && user.Status == "active" && user.RecoveryAuthHash.Valid &&
		user.RecoverySalt.Valid && user.RecoveryKDFParams.Valid {
		response["recoverySalt"] = user.RecoverySalt.String
		// The parameters the blob was actually wrapped under, not the current
		// default: deriving with any others yields a different key, and the user
		// would discover that at the moment recovery was their last resort.
		response["recoveryKdfParams"] = user.RecoveryKDFParams.String
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logger.Error("recovery prelogin lookup", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not process the request")
		return
	}

	WriteJSON(w, http.StatusOK, response)
}

type recoverRequest struct {
	Email            string `json:"email"`
	RecoveryAuthHash string `json:"recoveryAuthHash"`
}

// recoveryRefused is the single response for every failed redemption: an
// unknown address, a wrong code, a disabled account, a blob that predates the
// auth-hash split. One message, one code, one status.
func recoveryRefused(w http.ResponseWriter) {
	WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "email or recovery code is incorrect")
}

// handleRecover hands back the recovery blob to a caller who proves possession
// of the recovery code, along with a short-lived token to finish with.
//
// What it returns is safe to hand over on that proof alone: the blob is wrapped
// under the *wrap* half of the recovery key and the auth half proved here
// cannot open it, and encryptedPrivateKey is wrapped under the userKey inside
// it. What it must never return is protected_user_key — the same userKey
// wrapped under the master password. The caller has not proved they know the
// master password, cannot open that blob, and has no use for it; shipping it
// would only widen what a stolen response is worth.
func (s *Server) handleRecover(w http.ResponseWriter, r *http.Request) {
	var req recoverRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	// Two keys, consulted at deliberately different points, exactly as
	// handleLogin does — and deliberately the *same* two keys. A recovery code
	// and a master password are two guesses at one account from one host, so
	// giving this endpoint budgets of its own would hand an attacker twice the
	// allowance for alternating between them.
	//
	// The IP key gates before the hash: it is the CPU defence, so it has to stop
	// the work from starting. The account key gates only failures and is
	// therefore consulted after verification — checked up front it would be a
	// lockout weapon against the one person who has already lost their password.
	ipKey := "ip:" + ClientIP(r)
	accountKey := "account:" + store.NormalizeEmail(req.Email)

	if allowed, retryAfter := s.limiter.Allow(ipKey); !allowed {
		tooManyAttempts(w, retryAfter)
		return
	}

	user, err := s.store.UserByEmail(r.Context(), req.Email)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logger.Error("recover lookup", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not process the request")
		return
	}

	// Verified unconditionally, against a dummy when there is nothing to check,
	// so an unknown address and an old-format blob cost the same Argon2id as a
	// wrong code. A response that is identical but arrives 50 ms sooner is still
	// an enumeration oracle.
	stored := dummyAuthHash
	if err == nil && user.RecoveryAuthHash.Valid {
		stored = user.RecoveryAuthHash.String
	}
	ok := auth.VerifyAuthHash(req.RecoveryAuthHash, stored)

	if err != nil || !ok || user.Status != "active" {
		// Read the account key's verdict before recording, so the sequence of
		// statuses a failing caller sees does not itself distinguish the cases.
		allowed, retryAfter := s.limiter.Allow(accountKey)
		s.limiter.RecordFailure(ipKey)
		s.limiter.RecordFailure(accountKey)
		if !allowed {
			tooManyAttempts(w, retryAfter)
			return
		}
		recoveryRefused(w)
		return
	}

	_, token, err := s.store.CreateRecoveryToken(r.Context(), user.ID, store.RecoveryTokenTTL)
	if err != nil {
		s.logger.Error("create recovery token", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not start the recovery")
		return
	}

	// A correct code is proof the traffic is real, so it clears both counters.
	s.limiter.Reset(ipKey)
	s.limiter.Reset(accountKey)
	// And the prelogin budget, exactly as handleLogin does on a successful
	// sign-in and for the same reason: that budget is per source address and is
	// spent on every call, so a household behind one NAT address is throttled
	// after twenty and told nothing about why. Redeeming a recovery code is at
	// least as strong a proof that the traffic is real as signing in — twenty
	// free calls makes it a hard corner to reach from here, but there is no
	// reason for the two paths to differ, and an asymmetry with no reason behind
	// it reads as one with a reason nobody wrote down.
	s.preloginLimiter.Reset("prelogin:" + ClientIP(r))

	WriteJSON(w, http.StatusOK, map[string]any{
		"recoveryProtectedUserKey": user.RecoveryProtectedUserKey.String,
		"encryptedPrivateKey":      user.EncryptedPrivateKey.String,
		"recoveryToken":            token,
		"expiresIn":                int(store.RecoveryTokenTTL.Seconds()),
	})
}

type recoverCompleteRequest struct {
	RecoveryToken            string `json:"recoveryToken"`
	KDFSalt                  string `json:"kdfSalt"`
	Params                   string `json:"params"`
	AuthHash                 string `json:"authHash"`
	ProtectedUserKey         string `json:"protectedUserKey"`
	RecoverySalt             string `json:"recoverySalt"`
	RecoveryKDFParams        string `json:"recoveryKdfParams"`
	RecoveryProtectedUserKey string `json:"recoveryProtectedUserKey"`
	RecoveryAuthHash         string `json:"recoveryAuthHash"`
}

// handleRecoverComplete replaces both credentials and ends every session.
//
// Both halves are mandatory. Rotating only the master password would leave a
// recovery code that still opens the vault, in the hands of whoever the user
// suspects read it; and rotating only the recovery blob would leave them locked
// out exactly as they were.
func (s *Server) handleRecoverComplete(w http.ResponseWriter, r *http.Request) {
	var req recoverCompleteRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	// Unauthenticated, and it runs two 64 MiB Argon2id computations per call, so
	// it is throttled per source address exactly as enrollment is. There is no
	// account key here: the request names a token, not an address.
	ipKey := "ip:" + ClientIP(r)
	if allowed, retryAfter := s.limiter.Allow(ipKey); !allowed {
		tooManyAttempts(w, retryAfter)
		return
	}

	// Hashing an empty string succeeds and costs exactly as much as hashing a
	// real one, so these are checked before the hash rather than after. Worded
	// by hand to match (*store.ValidationError).Error(), which is what every
	// other missing field in this payload renders as.
	if req.AuthHash == "" {
		WriteError(w, http.StatusBadRequest, CodeBadRequest, "field \"authHash\" is required")
		return
	}
	if req.RecoveryAuthHash == "" {
		WriteError(w, http.StatusBadRequest, CodeBadRequest, "field \"recoveryAuthHash\" is required")
		return
	}
	// Pinned so the prelogin decoy stays indistinguishable from a real account,
	// exactly as the other two paths that write kdf_params pin it. Byte
	// equality, and checked here so an unpinned payload is refused before
	// anything expensive happens.
	if req.Params != auth.DefaultKDFParamsJSON {
		WriteError(w, http.StatusBadRequest, CodeBadRequest,
			"params must match the server's current KDF parameters exactly")
		return
	}
	// And the recovery blob's parameters, for the same reason applied to this
	// endpoint's own prelogin: handleRecoverPrelogin answers an unknown address
	// with auth.DefaultKDFParamsJSON, so an account whose recovery_kdf_params
	// differs is an address a caller can confirm exists by comparing that field.
	// A completed recovery writes a fresh recovery blob, which makes it one of
	// the three places a divergent value could enter.
	if req.RecoveryKDFParams != auth.DefaultKDFParamsJSON {
		WriteError(w, http.StatusBadRequest, CodeBadRequest,
			"recoveryKdfParams must match the server's current KDF parameters exactly")
		return
	}

	// Establish that the token is live before paying for two Argon2id. This is
	// an optimisation, not the security boundary: CompleteRecovery spends the
	// token inside its transaction, which is what makes it single-use under
	// concurrency. Both checks stay.
	if _, err := s.store.RecoveryTokenByToken(r.Context(), req.RecoveryToken); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.limiter.RecordFailure(ipKey)
			WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "this recovery session is no longer valid")
			return
		}
		s.logger.Error("recovery token lookup", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not complete the recovery")
		return
	}

	hashed, err := auth.HashAuthHash(req.AuthHash)
	if err != nil {
		s.logger.Error("hash auth hash", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not complete the recovery")
		return
	}
	hashedRecovery, err := auth.HashAuthHash(req.RecoveryAuthHash)
	if err != nil {
		s.logger.Error("hash recovery auth hash", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not complete the recovery")
		return
	}

	err = s.store.CompleteRecovery(r.Context(), req.RecoveryToken,
		store.PasswordRotation{
			KDFSalt:          req.KDFSalt,
			KDFParams:        req.Params,
			AuthHash:         hashed,
			ProtectedUserKey: req.ProtectedUserKey,
		},
		store.RecoveryRotation{
			RecoverySalt:             req.RecoverySalt,
			RecoveryKDFParams:        req.RecoveryKDFParams,
			RecoveryProtectedUserKey: req.RecoveryProtectedUserKey,
			RecoveryAuthHash:         hashedRecovery,
		})
	var validationErr *store.ValidationError
	switch {
	case errors.Is(err, store.ErrNotFound):
		// The token was spent by a racing request, or the account is no longer
		// active. Same answer as an unknown token, for the same reason.
		s.limiter.RecordFailure(ipKey)
		WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "this recovery session is no longer valid")
		return
	case errors.As(err, &validationErr):
		WriteError(w, http.StatusBadRequest, CodeBadRequest, validationErr.Error())
		return
	case err != nil:
		s.logger.Error("complete recovery", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not complete the recovery")
		return
	}

	s.limiter.Reset(ipKey)
	w.WriteHeader(http.StatusNoContent)
}
