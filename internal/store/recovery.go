package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// RecoveryToken authorizes one account's credentials to be replaced. It is
// minted only for a caller who has just proved possession of that account's
// recovery code, and it is the invites table's mechanism reused: hashed at
// rest, single use, expiring.
type RecoveryToken struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

const recoveryTokenBytes = 32

// RecoveryTokenTTL is how long a redeemed recovery code's token stays usable.
//
// Ten minutes: long enough to type a new master password twice, short enough
// that one left behind in a laptop that was closed mid-recovery is not a spare
// key to the account. Unlike an invite, nothing has to be handed over out of
// band — the same client that received it uses it seconds later.
const RecoveryTokenTTL = 10 * time.Minute

// CreateRecoveryToken mints a token and stores only its hash. The raw token is
// returned once and cannot be recovered afterwards, by an admin or by anyone
// holding the database.
func (s *Store) CreateRecoveryToken(ctx context.Context, userID string, ttl time.Duration) (RecoveryToken, string, error) {
	raw := make([]byte, recoveryTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return RecoveryToken{}, "", fmt.Errorf("generate recovery token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	id, err := NewID()
	if err != nil {
		return RecoveryToken{}, "", err
	}
	now := time.Now().UTC()

	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO recovery_tokens (id, user_id, token_hash, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id, userID, HashToken(token),
		now.Format(time.RFC3339), now.Add(ttl).Format(time.RFC3339)); err != nil {
		return RecoveryToken{}, "", fmt.Errorf("insert recovery token: %w", err)
	}
	return RecoveryToken{ID: id, UserID: userID, CreatedAt: now, ExpiresAt: now.Add(ttl)}, token, nil
}

// RecoveryTokenByToken returns the token only if it is unspent and unexpired.
// Spent and expired tokens report ErrNotFound rather than a distinct error, so
// a caller cannot learn from the response whether a token was ever valid.
func (s *Store) RecoveryTokenByToken(ctx context.Context, token string) (RecoveryToken, error) {
	var rt RecoveryToken
	var createdAt, expiresAt string

	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, created_at, expires_at
		 FROM recovery_tokens
		 WHERE token_hash = ? AND used_at IS NULL`,
		HashToken(token),
	).Scan(&rt.ID, &rt.UserID, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RecoveryToken{}, ErrNotFound
	}
	if err != nil {
		return RecoveryToken{}, fmt.Errorf("select recovery token: %w", err)
	}

	if rt.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return RecoveryToken{}, fmt.Errorf("parse created_at: %w", err)
	}
	if rt.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt); err != nil {
		return RecoveryToken{}, fmt.Errorf("parse expires_at: %w", err)
	}
	if time.Now().UTC().After(rt.ExpiresAt) {
		return RecoveryToken{}, ErrNotFound
	}
	return rt, nil
}

// CompleteRecovery spends the token and replaces both of the account's
// credentials in one transaction.
//
// Everything here has to land together. A master password written without the
// new recovery blob leaves an account whose recovery code opens a userKey
// wrapped under a password nobody knows; a token left unspent leaves a second
// chance to rewrite the account; sessions left alive leave the person who just
// proved they lost their password signed in on a device they may no longer
// control.
//
// The account's other live recovery tokens go with it. A redemption abandoned
// half way through mints a token that would otherwise stay usable for the rest
// of its ten minutes, against an account whose credentials have since changed.
func (s *Store) CompleteRecovery(ctx context.Context, token string, password PasswordRotation, recovery RecoveryRotation) error {
	// Both payloads are checked before a transaction is opened, and before the
	// token is spent: a client that uploads an incomplete recovery must be able
	// to fix it and try again with the token it still holds.
	if err := password.validate(); err != nil {
		return err
	}
	if err := recovery.validate(); err != nil {
		return err
	}

	rt, err := s.RecoveryTokenByToken(ctx, token)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin recovery completion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339)

	// The used_at IS NULL condition makes this the point of serialization: two
	// concurrent completions race here and exactly one wins. The check in
	// RecoveryTokenByToken above is an optimisation — it keeps a dead token from
	// costing a transaction — not the thing that makes the token single-use.
	result, err := tx.ExecContext(ctx,
		`UPDATE recovery_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL`,
		now, rt.ID)
	if err != nil {
		return fmt.Errorf("spend recovery token: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE recovery_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL`,
		now, rt.UserID); err != nil {
		return fmt.Errorf("retire other recovery tokens: %w", err)
	}

	// An empty keepSessionID: every session goes, including any the recovering
	// caller somehow still holds.
	if err := writePasswordCredential(ctx, tx, rt.UserID, password, "", now); err != nil {
		return err
	}
	if err := writeRecoveryCredential(ctx, tx, rt.UserID, recovery, now); err != nil {
		return err
	}

	// One entry, not the two the separate rotation endpoints write: an admin
	// reading this log needs to see "this account was recovered", which is a
	// different event from "this user changed their password".
	if err := appendAudit(ctx, tx, rt.UserID, "account.recovery.redeem", "user:"+rt.UserID, ""); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit recovery completion: %w", err)
	}
	return nil
}
