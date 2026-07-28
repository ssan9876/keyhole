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
