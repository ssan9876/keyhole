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

type Invite struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    sql.NullTime
}

const inviteTokenBytes = 32

// CreateInvite mints a one-time token and stores only its hash. The raw token
// is returned once, to be handed to the invitee out of band; it cannot be
// recovered afterwards, by an admin or by anyone with the database.
func (s *Store) CreateInvite(ctx context.Context, userID string, ttl time.Duration) (Invite, string, error) {
	raw := make([]byte, inviteTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return Invite{}, "", fmt.Errorf("generate invite token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	id, err := NewID()
	if err != nil {
		return Invite{}, "", err
	}

	now := time.Now().UTC()
	expires := now.Add(ttl)

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO invites (id, user_id, token_hash, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id, userID, HashToken(token),
		now.Format(time.RFC3339), expires.Format(time.RFC3339))
	if err != nil {
		return Invite{}, "", fmt.Errorf("insert invite: %w", err)
	}

	return Invite{ID: id, UserID: userID, CreatedAt: now, ExpiresAt: expires}, token, nil
}

// InviteByToken returns the invite only if it is unused and unexpired. Used
// and expired invites report ErrNotFound rather than a distinct error, so a
// caller cannot learn from the response whether a token was ever valid.
func (s *Store) InviteByToken(ctx context.Context, token string) (Invite, error) {
	var inv Invite
	var createdAt, expiresAt string

	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, created_at, expires_at
		 FROM invites
		 WHERE token_hash = ? AND used_at IS NULL`,
		HashToken(token),
	).Scan(&inv.ID, &inv.UserID, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Invite{}, ErrNotFound
	}
	if err != nil {
		return Invite{}, fmt.Errorf("select invite: %w", err)
	}

	if inv.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return Invite{}, fmt.Errorf("parse created_at: %w", err)
	}
	if inv.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt); err != nil {
		return Invite{}, fmt.Errorf("parse expires_at: %w", err)
	}
	if time.Now().UTC().After(inv.ExpiresAt) {
		return Invite{}, ErrNotFound
	}
	return inv, nil
}

// MarkInviteUsed consumes the invite. The WHERE clause carries the
// used_at IS NULL condition so two concurrent enrollments cannot both succeed:
// the second affects zero rows and gets ErrNotFound.
func (s *Store) MarkInviteUsed(ctx context.Context, inviteID string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE invites SET used_at = ? WHERE id = ? AND used_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339), inviteID)
	if err != nil {
		return fmt.Errorf("mark invite used: %w", err)
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
