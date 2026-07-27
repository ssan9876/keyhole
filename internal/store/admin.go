package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlited "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// UserSummary is a user plus the one derived fact the admin list needs. An
// account that is pending with no live invite is stranded — nobody can set it
// up — and the list is where that has to be visible.
type UserSummary struct {
	User
	HasPendingInvite bool
}

func (s *Store) ListUsers(ctx context.Context) ([]UserSummary, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+userColumns+`,
		    EXISTS (
		        SELECT 1 FROM invites
		        WHERE invites.user_id = users.id
		          AND invites.used_at IS NULL
		          AND invites.expires_at > ?
		    ) AS has_pending_invite
		 FROM users
		 ORDER BY name`, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("select users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	users := []UserSummary{}
	for rows.Next() {
		var summary UserSummary
		var createdAt, updatedAt string
		if err := rows.Scan(
			&summary.ID, &summary.Email, &summary.Name, &summary.Role, &summary.Status,
			&summary.KDFSalt, &summary.KDFParams, &summary.AuthHash, &summary.ProtectedUserKey,
			&summary.RecoveryProtectedUserKey, &summary.RecoverySalt, &summary.RecoveryKDFParams,
			&summary.PublicKey, &summary.EncryptedPrivateKey,
			&summary.Revision, &createdAt, &updatedAt,
			&summary.HasPendingInvite,
		); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		if summary.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
		if summary.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt); err != nil {
			return nil, fmt.Errorf("parse updated_at: %w", err)
		}
		users = append(users, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	return users, nil
}

// SetUserStatus enables or disables an account.
func (s *Store) SetUserStatus(ctx context.Context, userID, status, actorID string) error {
	if status != "active" && status != "disabled" {
		return &ValidationError{Field: "status", Message: "must be active or disabled"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin status change: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if status == "disabled" {
		var remaining int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM users
			 WHERE role = 'admin' AND status = 'active' AND id != ?`, userID).Scan(&remaining); err != nil {
			return fmt.Errorf("count admins: %w", err)
		}
		var role string
		if err := tx.QueryRowContext(ctx,
			`SELECT role FROM users WHERE id = ?`, userID).Scan(&role); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("read role: %w", err)
		}
		// With no admin left, nobody can create one: there is no registration
		// endpoint and the CLI needs shell access to the container.
		if role == "admin" && remaining == 0 {
			return ErrLastAdmin
		}
	}

	result, err := tx.ExecContext(ctx,
		`UPDATE users SET status = ?, revision = revision + 1, updated_at = ? WHERE id = ?`,
		status, time.Now().UTC().Format(time.RFC3339), userID)
	if err != nil {
		return fmt.Errorf("set status: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}

	if status == "disabled" {
		// requireAuth re-checks status on every request, so this is belt and
		// braces — but "disable this account" that leaves live session rows
		// behind is a claim the sessions list would contradict.
		if _, err := tx.ExecContext(ctx,
			`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
			time.Now().UTC().Format(time.RFC3339), userID); err != nil {
			return fmt.Errorf("revoke sessions: %w", err)
		}
	}

	if err := appendAudit(ctx, tx, actorID, "user.status", "user:"+userID,
		fmt.Sprintf(`{"status":%q}`, status)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit status change: %w", err)
	}
	return nil
}

// ResetUser is the destructive last resort from spec section 3.7.
//
// It destroys every piece of key material, deletes the personal items nothing
// can ever decrypt again, revokes collection memberships (the new keypair will
// be different, so every sealed key becomes junk), revokes sessions, returns
// the account to pending, and mints a fresh invite. It returns the raw token
// for that invite, once.
//
// Collection ITEMS are deliberately kept: they are wrapped by the collection
// key, which every other member still holds. Deleting them because their
// creator was reset would destroy shared data belonging to people the reset
// had nothing to do with.
func (s *Store) ResetUser(ctx context.Context, userID, actorID string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin reset: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339)

	result, err := tx.ExecContext(ctx,
		`UPDATE users SET status = 'pending',
			kdf_salt = NULL, kdf_params = NULL, auth_hash = NULL,
			protected_user_key = NULL, recovery_protected_user_key = NULL,
			recovery_salt = NULL, recovery_kdf_params = NULL,
			public_key = NULL, encrypted_private_key = NULL,
			revision = revision + 1, updated_at = ?
		 WHERE id = ?`, stamp, userID)
	if err != nil {
		return "", fmt.Errorf("reset user: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return "", ErrNotFound
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM items WHERE owner_user_id = ? AND collection_id IS NULL`, userID); err != nil {
		return "", fmt.Errorf("delete personal items: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM folders WHERE user_id = ?`, userID); err != nil {
		return "", fmt.Errorf("delete folders: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM collection_memberships WHERE user_id = ?`, userID); err != nil {
		return "", fmt.Errorf("delete memberships: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM pending_grants WHERE user_id = ?`, userID); err != nil {
		return "", fmt.Errorf("delete pending grants: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		stamp, userID); err != nil {
		return "", fmt.Errorf("revoke sessions: %w", err)
	}

	token, err := createInviteTx(ctx, tx, userID, InviteTTL)
	if err != nil {
		return "", err
	}
	if err := appendAudit(ctx, tx, actorID, "user.reset", "user:"+userID, ""); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit reset: %w", err)
	}
	return token, nil
}

// DeleteUser removes an account outright.
//
// The FK violation is not a bug to be prevented — collections.created_by and
// the two granted_by/requested_by columns have no ON DELETE action on purpose,
// so that deleting an admin cannot cascade into destroying a shared
// collection's key material. What matters is that the operator is told which
// problem they have, in terms they can act on, rather than shown a 500.
//
// The extended result code is 787, observed by running the driver rather than
// read from documentation, and it fires only because store.Open turns
// foreign_keys on in the DSN — the pragma is per-connection and off by default.
func (s *Store) DeleteUser(ctx context.Context, userID, actorID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete user: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var role string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id = ?`, userID).Scan(&role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("read role: %w", err)
	}
	if role == "admin" {
		var remaining int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM users
			 WHERE role = 'admin' AND status = 'active' AND id != ?`, userID).Scan(&remaining); err != nil {
			return fmt.Errorf("count admins: %w", err)
		}
		if remaining == 0 {
			return ErrLastAdmin
		}
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID); err != nil {
		var sqliteErr *sqlited.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY {
			return ErrUserReferenced
		}
		return fmt.Errorf("delete user: %w", err)
	}
	if err := appendAudit(ctx, tx, actorID, "user.delete", "user:"+userID, ""); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete user: %w", err)
	}
	return nil
}
