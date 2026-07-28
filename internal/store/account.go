package store

import (
	"context"
	"fmt"
	"time"

	"github.com/ssan9876/keyhole/internal/auth"
)

// PasswordRotation is a master-password change. AuthHash arrives already
// hashed for storage; the server never sees the password or the raw auth hash
// at rest.
//
// ProtectedUserKey is the same userKey re-wrapped under the new wrapping key.
// That indirection is the whole reason a password change is four columns
// rather than a re-encryption of the vault.
type PasswordRotation struct {
	KDFSalt          string
	KDFParams        string
	AuthHash         string
	ProtectedUserKey string
}

func (in PasswordRotation) validate() error {
	for field, value := range map[string]string{
		"kdfSalt":          in.KDFSalt,
		"params":           in.KDFParams,
		"authHash":         in.AuthHash,
		"protectedUserKey": in.ProtectedUserKey,
	} {
		if value == "" {
			return &ValidationError{Field: field}
		}
	}
	// Pinned in the store as well as in the handler, so the invariant holds for
	// every caller rather than only the HTTP one. Enrollment pins it in
	// EnrollmentInput.validate for the same reason: these are the only two
	// paths that ever write kdf_params, and one unguarded path is all it takes
	// to make an account enumerable through prelogin.
	if in.KDFParams != auth.DefaultKDFParamsJSON {
		return &ValidationError{
			Field:   "params",
			Message: "must match the server's current KDF parameters exactly",
		}
	}
	return nil
}

// RotatePassword writes the new credential and revokes every session except
// keepSessionID.
//
// Revoking the others is not optional politeness: changing a master password
// is what a user does when they suspect a compromise, and leaving other
// devices signed in makes the action mean far less than they believe. An empty
// keepSessionID revokes all of them.
func (s *Store) RotatePassword(ctx context.Context, userID string, in PasswordRotation, keepSessionID string) error {
	if err := in.validate(); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin password rotation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339)
	if err := writePasswordCredential(ctx, tx, userID, in, keepSessionID, now); err != nil {
		return err
	}
	if err := appendAudit(ctx, tx, userID, "account.password.rotate", "user:"+userID, ""); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit password rotation: %w", err)
	}
	return nil
}

// writePasswordCredential is RotatePassword's body without the audit entry or
// the transaction, parameterized over the executor so a caller already inside a
// transaction can rotate a password as part of a larger unit of work.
// CompleteRecovery is that caller: a recovery that rewrote the password and
// then failed to revoke the sessions, or failed to spend its token, would leave
// the user believing something that is not true.
//
// It assumes in.validate() has already run. Both callers do it up front, before
// opening a transaction, because a rejected payload should not cost one.
func writePasswordCredential(ctx context.Context, db execer, userID string, in PasswordRotation, keepSessionID, now string) error {
	// The recovery columns are deliberately untouched: that blob is wrapped by
	// the recovery code, not the master password, so clearing it here would
	// silently destroy the user's last way back in.
	result, err := db.ExecContext(ctx,
		`UPDATE users SET kdf_salt = ?, kdf_params = ?, auth_hash = ?,
			protected_user_key = ?, revision = revision + 1, updated_at = ?
		 WHERE id = ? AND status = 'active'`,
		in.KDFSalt, in.KDFParams, in.AuthHash, in.ProtectedUserKey, now, userID)
	if err != nil {
		return fmt.Errorf("rotate password: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}

	// An empty keepSessionID matches no row, so every live session goes.
	if _, err := db.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ?
		 WHERE user_id = ? AND revoked_at IS NULL AND id != ?`,
		now, userID, keepSessionID); err != nil {
		return fmt.Errorf("revoke other sessions: %w", err)
	}
	return nil
}

// RecoveryRotation replaces the recovery blob and the parameters it was made
// with. The parameters are recorded rather than assumed (spec section 4.2):
// deriving a recovery key with parameters other than the ones the blob was
// wrapped under yields a different key, and that failure would surface only at
// the moment recovery was the user's last resort.
//
// RecoveryAuthHash is the server's only way to check that a caller redeeming a
// code actually holds it, and it arrives already hashed for storage, exactly as
// AuthHash does.
type RecoveryRotation struct {
	RecoverySalt             string
	RecoveryKDFParams        string
	RecoveryProtectedUserKey string
	RecoveryAuthHash         string
}

func (in RecoveryRotation) validate() error {
	for field, value := range map[string]string{
		"recoverySalt":             in.RecoverySalt,
		"recoveryKdfParams":        in.RecoveryKDFParams,
		"recoveryProtectedUserKey": in.RecoveryProtectedUserKey,
		// Required alongside the other three, not optional. A blob stored
		// without one is a blob no endpoint can ever hand back — the redeem
		// path has nothing to check possession against — so accepting it would
		// show the user a recovery code that silently does nothing.
		"recoveryAuthHash": in.RecoveryAuthHash,
	} {
		if value == "" {
			return &ValidationError{Field: field}
		}
	}
	return nil
}

// RotateRecovery issues a new recovery blob, invalidating the old code by
// replacing what it opens. Sessions and the password path are untouched: a
// user regenerating a code has not lost their password, and logging them out
// of everything for it would be gratuitous.
func (s *Store) RotateRecovery(ctx context.Context, userID string, in RecoveryRotation) error {
	if err := in.validate(); err != nil {
		return err
	}
	if err := writeRecoveryCredential(ctx, s.db, userID,
		in, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	return s.AppendAudit(ctx, userID, "account.recovery.rotate", "user:"+userID, "")
}

// writeRecoveryCredential is writePasswordCredential's counterpart for the
// recovery blob, parameterized over the executor for the same reason: a
// completed recovery replaces both credentials, and it must do so in one
// transaction or a failure between them leaves an account whose recovery code
// and master password disagree about which vault they open.
//
// It assumes in.validate() has already run.
func writeRecoveryCredential(ctx context.Context, db execer, userID string, in RecoveryRotation, now string) error {
	result, err := db.ExecContext(ctx,
		`UPDATE users SET recovery_salt = ?, recovery_kdf_params = ?,
			recovery_protected_user_key = ?, recovery_auth_hash = ?,
			revision = revision + 1, updated_at = ?
		 WHERE id = ? AND status = 'active'`,
		in.RecoverySalt, in.RecoveryKDFParams, in.RecoveryProtectedUserKey,
		in.RecoveryAuthHash, now, userID)
	if err != nil {
		return fmt.Errorf("rotate recovery: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// SessionsForUser lists a user's live sessions, newest activity first. Revoked
// and expired sessions are omitted: the list exists so a user can end a session
// they do not recognize, and rows they cannot act on are noise.
func (s *Store) SessionsForUser(ctx context.Context, userID string) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions
		 WHERE user_id = ? AND revoked_at IS NULL
		 ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("select sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	now := time.Now().UTC()
	sessions := []Session{}
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		if now.After(session.ExpiresAt) ||
			now.After(session.CreatedAt.Add(RefreshTokenLifetime)) {
			continue
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}
	return sessions, nil
}

// RevokeSessionForUser revokes a session only if it belongs to that user.
// Session ids are opaque, but "sign out my other device" must not become "sign
// out anyone's device" for a caller who guesses or observes one.
func (s *Store) RevokeSessionForUser(ctx context.Context, sessionID, userID string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ?
		 WHERE id = ? AND user_id = ? AND revoked_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339), sessionID, userID)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}
