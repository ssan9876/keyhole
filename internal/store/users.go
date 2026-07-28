package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	sqlited "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
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
	// RecoveryAuthHash is NULL for a blob written before migration 0004: it was
	// wrapped under the undifferentiated recovery key, so there is no
	// proof-of-possession value to check a redeeming caller against. Valid but
	// empty is not a state any writer may produce — the required-field checks
	// exist to keep NULL meaning exactly "predates the split".
	RecoveryAuthHash    sql.NullString
	PublicKey           sql.NullString
	EncryptedPrivateKey sql.NullString

	Revision  int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

const userColumns = `id, email, name, role, status,
	kdf_salt, kdf_params, auth_hash, protected_user_key,
	recovery_protected_user_key, recovery_salt, recovery_kdf_params,
	recovery_auth_hash,
	public_key, encrypted_private_key,
	revision, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var createdAt, updatedAt string
	err := row.Scan(
		&u.ID, &u.Email, &u.Name, &u.Role, &u.Status,
		&u.KDFSalt, &u.KDFParams, &u.AuthHash, &u.ProtectedUserKey,
		&u.RecoveryProtectedUserKey, &u.RecoverySalt, &u.RecoveryKDFParams,
		&u.RecoveryAuthHash,
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
		return User{}, classifyUserInsertError(err)
	}
	return s.UserByID(ctx, id)
}

// classifyUserInsertError maps a failed users-table insert to ErrEmailTaken
// when, and only when, it violated the users_email_unique index. The same
// INSERT can also violate the id PRIMARY KEY (astronomically unlikely at 128
// bits of random id, but a real bug in its own right if it ever happened),
// and that must not be reported as a taken email or an operator would debug
// the wrong problem entirely.
//
// modernc's driver reports both violations as *sqlite.Error with a distinct
// extended result code — SQLITE_CONSTRAINT_UNIQUE for a UNIQUE index,
// SQLITE_CONSTRAINT_PRIMARYKEY for the primary key — so we type-assert and
// branch on the code rather than matching on the message text, which
// contains "UNIQUE constraint failed" for both cases.
func classifyUserInsertError(err error) error {
	var sqliteErr *sqlited.Error
	if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
		return ErrEmailTaken
	}
	return fmt.Errorf("insert user: %w", err)
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
