package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// User mirrors the users table. Every key-material field is nullable because
// an account exists in a pending state before its owner has set a master
// password, and the server never fabricates key material.
type User struct {
	ID     string
	Email  string
	Name   string
	Role   string
	Status string

	KDFSalt                  sql.NullString
	KDFParams                sql.NullString
	AuthHash                 sql.NullString
	ProtectedUserKey         sql.NullString
	RecoveryProtectedUserKey sql.NullString
	RecoverySalt             sql.NullString
	RecoveryKDFParams        sql.NullString
	PublicKey                sql.NullString
	EncryptedPrivateKey      sql.NullString

	Revision  int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

const userColumns = `id, email, name, role, status,
	kdf_salt, kdf_params, auth_hash, protected_user_key,
	recovery_protected_user_key, recovery_salt, recovery_kdf_params,
	public_key, encrypted_private_key,
	revision, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var createdAt, updatedAt string
	err := row.Scan(
		&u.ID, &u.Email, &u.Name, &u.Role, &u.Status,
		&u.KDFSalt, &u.KDFParams, &u.AuthHash, &u.ProtectedUserKey,
		&u.RecoveryProtectedUserKey, &u.RecoverySalt, &u.RecoveryKDFParams,
		&u.PublicKey, &u.EncryptedPrivateKey,
		&u.Revision, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("scan user: %w", err)
	}
	if u.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return User{}, fmt.Errorf("parse created_at: %w", err)
	}
	if u.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt); err != nil {
		return User{}, fmt.Errorf("parse updated_at: %w", err)
	}
	return u, nil
}

// CreatePendingUser creates an account with no key material. The account
// becomes usable only when its owner completes an invite and uploads their
// own wrapped blobs — the server can never populate them.
func (s *Store) CreatePendingUser(ctx context.Context, email, name, role string) (User, error) {
	if role != "admin" && role != "user" {
		return User{}, fmt.Errorf("invalid role %q: want admin or user", role)
	}
	normalized := NormalizeEmail(email)
	if normalized == "" || !strings.Contains(normalized, "@") {
		return User{}, fmt.Errorf("invalid email %q", email)
	}
	if strings.TrimSpace(name) == "" {
		return User{}, errors.New("name must not be empty")
	}

	id, err := NewID()
	if err != nil {
		return User{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, name, role, status, revision, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 'pending', 0, ?, ?)`,
		id, normalized, strings.TrimSpace(name), role, now, now)
	if err != nil {
		// modernc's driver reports constraint violations in the message; the
		// unique index on lower(email) is the only one this insert can trip.
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("insert user: %w", err)
	}
	return s.UserByID(ctx, id)
}

func (s *Store) UserByID(ctx context.Context, id string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = ?`, id))
}

// UserByEmail normalizes before looking up, so callers cannot accidentally
// miss an account by case or surrounding whitespace.
func (s *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE email = ?`, NormalizeEmail(email)))
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}
