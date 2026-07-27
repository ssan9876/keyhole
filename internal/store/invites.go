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

// InviteTTL is how long a setup or invite link stays valid. Long enough to
// hand over out of band and act on unhurriedly, short enough that a link found
// later in a chat history is dead.
//
// One definition, used by both the CLI and the admin API. Two would drift, and
// the drift would show up as links that expire sooner than the message telling
// the user how long they have.
const InviteTTL = 72 * time.Hour

// createInviteTx is CreateInvite's body, parameterized over the executor so a
// caller already inside a transaction can mint an invite that commits with the
// rest of its work. ResetUser is that caller: a reset that wiped an account and
// then failed to mint a link would leave the user with no way in and no way to
// ask for one.
func createInviteTx(ctx context.Context, db execer, userID string, ttl time.Duration) (string, error) {
	raw := make([]byte, inviteTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate invite token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	id, err := NewID()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()

	if _, err := db.ExecContext(ctx,
		`INSERT INTO invites (id, user_id, token_hash, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id, userID, HashToken(token),
		now.Format(time.RFC3339), now.Add(ttl).Format(time.RFC3339)); err != nil {
		return "", fmt.Errorf("insert invite: %w", err)
	}
	return token, nil
}

// CreateInvite mints a one-time token and stores only its hash. The raw token
// is returned once, to be handed to the invitee out of band; it cannot be
// recovered afterwards, by an admin or by anyone with the database.
func (s *Store) CreateInvite(ctx context.Context, userID string, ttl time.Duration) (Invite, string, error) {
	now := time.Now().UTC()
	token, err := createInviteTx(ctx, s.db, userID, ttl)
	if err != nil {
		return Invite{}, "", err
	}
	var id string
	if err := s.db.QueryRowContext(ctx,
		`SELECT id FROM invites WHERE token_hash = ?`, HashToken(token)).Scan(&id); err != nil {
		return Invite{}, "", fmt.Errorf("read new invite: %w", err)
	}
	return Invite{ID: id, UserID: userID, CreatedAt: now, ExpiresAt: now.Add(ttl)}, token, nil
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

// Deliberately absent: a standalone MarkInviteUsed. CompleteEnrollment
// consumes the invite inside its own transaction, and that is what makes a
// link one-time under concurrency — two racing enrollments both matching
// `used_at IS NULL` in separate statements would both succeed. A separate
// function would be the wrong thing to reach for.
