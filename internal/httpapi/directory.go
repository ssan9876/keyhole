package httpapi

import (
	"net/http"
)

// handleDirectory lists the accounts a collection key can be sealed to.
//
// Spec section 4.3 does not name this endpoint, but sharing is impossible
// without it: sealToUser needs the recipient's X25519 public key, and the
// server is where public keys live. It returns the public key and nothing
// else that is key material — spec section 3.9's first accepted limitation is
// precisely that the server distributes these, and the mitigation is the
// fingerprint the client renders from this value, not secrecy.
//
// Only active accounts appear. A pending account has no public key at all, so
// offering it as a share target would promise something that cannot happen.
func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.DB().QueryContext(r.Context(),
		`SELECT id, name, email, public_key FROM users
		 WHERE status = 'active' AND public_key IS NOT NULL
		 ORDER BY name`)
	if err != nil {
		s.writeStoreError(w, r, "list directory", err)
		return
	}
	defer func() { _ = rows.Close() }()

	type entry struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		PublicKey string `json:"publicKey"`
	}

	users := []entry{}
	for rows.Next() {
		var user entry
		if err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.PublicKey); err != nil {
			s.writeStoreError(w, r, "scan directory entry", err)
			return
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		s.writeStoreError(w, r, "iterate directory", err)
		return
	}

	WriteJSON(w, http.StatusOK, map[string]any{"users": users})
}
