package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ssan9876/keyhole/internal/auth"
)

const (
	// AccessTokenLifetime is short and slides on use, so an intercepted token
	// stops working quickly once the legitimate client goes quiet.
	AccessTokenLifetime = 30 * time.Minute
	// RefreshTokenLifetime bounds how long a device stays signed in.
	RefreshTokenLifetime = 30 * 24 * time.Hour
)

type Session struct {
	ID          string
	UserID      string
	DeviceLabel string
	CreatedAt   time.Time
	LastSeenAt  time.Time
	ExpiresAt   time.Time
	RevokedAt   sql.NullTime
}

// CreateSession issues a session and returns both tokens exactly once. Only
// their hashes are stored, so neither can be recovered from the database.
func (s *Store) CreateSession(ctx context.Context, userID, deviceLabel string) (Session, string, string, error) {
	accessToken, err := auth.NewToken()
	if err != nil {
		return Session{}, "", "", err
	}
	refreshToken, err := auth.NewToken()
	if err != nil {
		return Session{}, "", "", err
	}
	id, err := NewID()
	if err != nil {
		return Session{}, "", "", err
	}

	now := time.Now().UTC()
	expires := now.Add(AccessTokenLifetime)
	if deviceLabel == "" {
		deviceLabel = "unknown device"
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, token_hash, refresh_hash, device_label, created_at, last_seen_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, userID, HashToken(accessToken), HashToken(refreshToken), deviceLabel,
		now.Format(time.RFC3339), now.Format(time.RFC3339), expires.Format(time.RFC3339))
	if err != nil {
		return Session{}, "", "", fmt.Errorf("insert session: %w", err)
	}

	return Session{
		ID: id, UserID: userID, DeviceLabel: deviceLabel,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: expires,
	}, accessToken, refreshToken, nil
}

func scanSession(row interface{ Scan(...any) error }) (Session, error) {
	var sess Session
	var createdAt, lastSeenAt, expiresAt string
	var revokedAt sql.NullString
	err := row.Scan(&sess.ID, &sess.UserID, &sess.DeviceLabel,
		&createdAt, &lastSeenAt, &expiresAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("scan session: %w", err)
	}
	if sess.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return Session{}, fmt.Errorf("parse created_at: %w", err)
	}
	if sess.LastSeenAt, err = time.Parse(time.RFC3339, lastSeenAt); err != nil {
		return Session{}, fmt.Errorf("parse last_seen_at: %w", err)
	}
	if sess.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt); err != nil {
		return Session{}, fmt.Errorf("parse expires_at: %w", err)
	}
	if revokedAt.Valid {
		parsed, err := time.Parse(time.RFC3339, revokedAt.String)
		if err != nil {
			return Session{}, fmt.Errorf("parse revoked_at: %w", err)
		}
		sess.RevokedAt = sql.NullTime{Time: parsed, Valid: true}
	}
	return sess, nil
}

const sessionColumns = `id, user_id, device_label, created_at, last_seen_at, expires_at, revoked_at`

// SessionByAccessToken returns the session only if it is live. Revoked and
// expired sessions report ErrNotFound, so a caller cannot tell which.
func (s *Store) SessionByAccessToken(ctx context.Context, token string) (Session, error) {
	sess, err := scanSession(s.db.QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE token_hash = ? AND revoked_at IS NULL`,
		HashToken(token)))
	if err != nil {
		return Session{}, err
	}
	if time.Now().UTC().After(sess.ExpiresAt) {
		return Session{}, ErrNotFound
	}
	return sess, nil
}

// RotateSession exchanges a refresh token for a fresh pair.
//
// The refresh token is single-use: the UPDATE matches on the old hash and
// replaces it, so a replay finds nothing. A leaked refresh token is therefore
// useful only until the real client next refreshes.
func (s *Store) RotateSession(ctx context.Context, refreshToken string) (Session, string, string, error) {
	sess, err := scanSession(s.db.QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE refresh_hash = ? AND revoked_at IS NULL`,
		HashToken(refreshToken)))
	if err != nil {
		return Session{}, "", "", err
	}
	if time.Now().UTC().After(sess.CreatedAt.Add(RefreshTokenLifetime)) {
		return Session{}, "", "", ErrNotFound
	}

	newAccess, err := auth.NewToken()
	if err != nil {
		return Session{}, "", "", err
	}
	newRefresh, err := auth.NewToken()
	if err != nil {
		return Session{}, "", "", err
	}

	now := time.Now().UTC()
	expires := now.Add(AccessTokenLifetime)

	result, err := s.db.ExecContext(ctx,
		`UPDATE sessions
		 SET token_hash = ?, refresh_hash = ?, last_seen_at = ?, expires_at = ?
		 WHERE id = ? AND refresh_hash = ? AND revoked_at IS NULL`,
		HashToken(newAccess), HashToken(newRefresh),
		now.Format(time.RFC3339), expires.Format(time.RFC3339),
		sess.ID, HashToken(refreshToken))
	if err != nil {
		return Session{}, "", "", fmt.Errorf("rotate session: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Session{}, "", "", fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return Session{}, "", "", ErrNotFound
	}

	sess.LastSeenAt = now
	sess.ExpiresAt = expires
	return sess, newAccess, newRefresh, nil
}

// TouchSession slides the access-token expiry forward on use.
func (s *Store) TouchSession(ctx context.Context, sessionID string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ? AND revoked_at IS NULL`,
		now.Format(time.RFC3339), now.Add(AccessTokenLifetime).Format(time.RFC3339), sessionID)
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

func (s *Store) RevokeSession(ctx context.Context, sessionID string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339), sessionID)
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
