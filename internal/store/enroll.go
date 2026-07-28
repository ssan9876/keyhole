package store

import (
	"context"
	"fmt"
	"time"

	"github.com/ssan9876/keyhole/internal/auth"
)

// EnrollmentInput is everything a client uploads when it sets a master
// password. Every field is an opaque string the server stores verbatim and
// never parses; the auth hash arrives already hashed for storage.
type EnrollmentInput struct {
	KDFSalt                  string
	KDFParams                string
	AuthHash                 string
	ProtectedUserKey         string
	PublicKey                string
	EncryptedPrivateKey      string
	RecoverySalt             string
	RecoveryProtectedUserKey string
	RecoveryKDFParams        string
	// Hashed for storage before it reaches this package, like AuthHash. It is
	// what lets the server check a redeeming caller holds the recovery code.
	RecoveryAuthHash string
}

func (in EnrollmentInput) validate() error {
	required := map[string]string{
		"kdfSalt":                  in.KDFSalt,
		"params":                   in.KDFParams,
		"authHash":                 in.AuthHash,
		"protectedUserKey":         in.ProtectedUserKey,
		"publicKey":                in.PublicKey,
		"encryptedPrivateKey":      in.EncryptedPrivateKey,
		"recoverySalt":             in.RecoverySalt,
		"recoveryProtectedUserKey": in.RecoveryProtectedUserKey,
		"recoveryKdfParams":        in.RecoveryKDFParams,
		// Required from the first day the column exists. NULL there is reserved
		// for accounts enrolled before the recovery key was split, and the
		// redeem endpoints read a NULL as "no such account"; an enrollment that
		// omitted this would join that set on purpose.
		"recoveryAuthHash": in.RecoveryAuthHash,
	}
	for name, value := range required {
		if value == "" {
			return &ValidationError{Field: name}
		}
	}

	// The prelogin decoy answers an unknown address with DefaultKDFParamsJSON.
	// The moment one real account holds different parameters, comparing that
	// field against the default tells an attacker whether an address has an
	// account here — which is precisely what the decoy exists to stop. So the
	// parameters are pinned, and raising them becomes a deliberate migration
	// rather than a silent per-user drift.
	//
	// Byte equality, not semantic: the decoy emits this exact string, so
	// anything that serializes differently is distinguishable even when it
	// means the same thing.
	//
	if in.KDFParams != auth.DefaultKDFParamsJSON {
		return &ValidationError{
			Field:   "params",
			Message: "must match the server's current KDF parameters exactly",
		}
	}
	// recovery_kdf_params is pinned for exactly the same reason, and the reason
	// now applies to it: POST /api/auth/recover/prelogin returns this column to
	// an unauthenticated caller and answers an unknown address with
	// DefaultKDFParamsJSON, so one account holding anything else is one address
	// an attacker can confirm exists.
	//
	// Spec 4.2's intent — record what the blob was actually wrapped under, so a
	// correct code never derives the wrong key — is preserved in fact rather
	// than by permissiveness: every blob is made under the client's
	// DEFAULT_KDF_PARAMS, which is this string. If the default ever rises, every
	// blob has to be re-wrapped anyway, and that is a migration with a version
	// bump, not a silent per-account divergence.
	if in.RecoveryKDFParams != auth.DefaultKDFParamsJSON {
		return &ValidationError{
			Field:   "recoveryKdfParams",
			Message: "must match the server's current KDF parameters exactly",
		}
	}
	return nil
}

// ValidationError means the client's payload was incomplete or malformed. It
// is the caller's fault and is safe to report back to them — unlike a database
// failure, whose text must never reach a client.
//
// Message carries a specific explanation for the cases where "is required" is
// not the truth: a field that was supplied but is unusable needs to say so, or
// the client is told to send something it already sent. It is optional, and an
// empty Message keeps the plain required-field wording.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("field %q: %s", e.Field, e.Message)
	}
	return fmt.Sprintf("field %q is required", e.Field)
}

// CompleteEnrollment consumes the invite and activates the account in one
// transaction.
//
// Both halves must land together. An account activated without its invite
// consumed leaves a replayable link; an invite consumed without the account
// activated leaves a user permanently unable to set up.
func (s *Store) CompleteEnrollment(ctx context.Context, token string, in EnrollmentInput) (User, error) {
	if err := in.validate(); err != nil {
		return User{}, err
	}

	invite, err := s.InviteByToken(ctx, token)
	if err != nil {
		return User{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339)

	// The used_at IS NULL condition makes this the point of serialization: two
	// concurrent enrollments race here and exactly one wins.
	result, err := tx.ExecContext(ctx,
		`UPDATE invites SET used_at = ? WHERE id = ? AND used_at IS NULL`,
		now, invite.ID)
	if err != nil {
		return User{}, fmt.Errorf("consume invite: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return User{}, fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return User{}, ErrNotFound
	}

	// status = 'pending' guards against enrolling over an already-active
	// account even if an invite row somehow survived.
	result, err = tx.ExecContext(ctx,
		`UPDATE users SET
			status = 'active',
			kdf_salt = ?, kdf_params = ?, auth_hash = ?,
			protected_user_key = ?, public_key = ?, encrypted_private_key = ?,
			recovery_salt = ?, recovery_protected_user_key = ?, recovery_kdf_params = ?,
			recovery_auth_hash = ?,
			revision = revision + 1,
			updated_at = ?
		 WHERE id = ? AND status = 'pending'`,
		in.KDFSalt, in.KDFParams, in.AuthHash,
		in.ProtectedUserKey, in.PublicKey, in.EncryptedPrivateKey,
		in.RecoverySalt, in.RecoveryProtectedUserKey, in.RecoveryKDFParams,
		in.RecoveryAuthHash,
		now, invite.UserID)
	if err != nil {
		return User{}, fmt.Errorf("activate user: %w", err)
	}
	if affected, err = result.RowsAffected(); err != nil {
		return User{}, fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return User{}, ErrNotFound
	}

	// Read the activated row inside the transaction, before Commit. A reload
	// after Commit would leave a window where the account is active in the
	// database but the client is told enrollment failed, with no way to
	// retry: the invite is spent and a second attempt gets ErrNotFound.
	// Reading here means any failure rolls back cleanly instead.
	user, err := scanUser(tx.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = ?`, invite.UserID))
	if err != nil {
		return User{}, fmt.Errorf("reload enrolled user: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("commit enrollment: %w", err)
	}

	return user, nil
}
