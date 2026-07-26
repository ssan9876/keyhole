package store

import (
	"context"
	"fmt"
	"time"
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
	}
	for name, value := range required {
		if value == "" {
			return &ValidationError{Field: name}
		}
	}
	return nil
}

// ValidationError means the client's enrollment payload was incomplete or
// malformed. It is the caller's fault and is safe to report back to them —
// unlike a database failure, whose text must never reach a client.
type ValidationError struct {
	Field string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("enrollment field %q is required", e.Field)
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
			revision = revision + 1,
			updated_at = ?
		 WHERE id = ? AND status = 'pending'`,
		in.KDFSalt, in.KDFParams, in.AuthHash,
		in.ProtectedUserKey, in.PublicKey, in.EncryptedPrivateKey,
		in.RecoverySalt, in.RecoveryProtectedUserKey, in.RecoveryKDFParams,
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
