package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Collection groups shared items. The name is plaintext by design (spec
// section 2): an admin has to manage membership without being a member, and
// the leak is a folder name.
type Collection struct {
	ID        string
	Name      string
	CreatedBy string
	CreatedAt time.Time
}

// CollectionWithMembership is a collection as one member sees it, carrying
// that member's own sealed copy of the collection key.
type CollectionWithMembership struct {
	Collection
	Role                string
	SealedCollectionKey string
	GrantedAt           time.Time
}

type Membership struct {
	CollectionID        string
	UserID              string
	SealedCollectionKey string
	Role                string
	GrantedBy           string
	GrantedAt           time.Time
}

type PendingGrant struct {
	CollectionID   string
	CollectionName string
	UserID         string
	Role           string
	RequestedBy    string
	CreatedAt      time.Time
}

// validRole gates the two roles from spec section 5.1. The role column has no
// CHECK constraint — SQLite's ALTER TABLE ADD COLUMN cannot add one to
// pending_grants — so this function is the constraint.
func validRole(role string) bool {
	return role == "member" || role == "manager"
}

// CreateCollection creates the collection and its creator's membership in one
// transaction.
//
// Both rows must land together. A collection with no manager cannot be
// repaired through the API: nobody holds the key, so nobody can seal it to
// anyone, and the server cannot help because it never had the key.
func (s *Store) CreateCollection(ctx context.Context, name, createdBy, sealedKeyForCreator string) (Collection, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Collection{}, &ValidationError{Field: "name"}
	}
	if sealedKeyForCreator == "" {
		return Collection{}, &ValidationError{Field: "sealedCollectionKey"}
	}

	id, err := NewID()
	if err != nil {
		return Collection{}, err
	}
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Collection{}, fmt.Errorf("begin collection insert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO collections (id, name, created_by, created_at) VALUES (?, ?, ?, ?)`,
		id, name, createdBy, stamp); err != nil {
		return Collection{}, fmt.Errorf("insert collection: %w", err)
	}
	// The creator's membership draws a revision like any other, so a device
	// that was already caught up learns about the collection it just created.
	granted, err := nextRevision(ctx, tx)
	if err != nil {
		return Collection{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO collection_memberships
		 (collection_id, user_id, sealed_collection_key, role, granted_by, granted_at, granted_revision)
		 VALUES (?, ?, ?, 'manager', ?, ?, ?)`,
		id, createdBy, sealedKeyForCreator, createdBy, stamp, granted); err != nil {
		return Collection{}, fmt.Errorf("insert creator membership: %w", err)
	}
	if err := appendAudit(ctx, tx, createdBy, "collection.create", "collection:"+id,
		fmt.Sprintf(`{"name":%q}`, name)); err != nil {
		return Collection{}, err
	}
	if err := tx.Commit(); err != nil {
		return Collection{}, fmt.Errorf("commit collection insert: %w", err)
	}

	return Collection{ID: id, Name: name, CreatedBy: createdBy, CreatedAt: now}, nil
}

const collectionColumns = `id, name, created_by, created_at`

func scanCollection(row interface{ Scan(...any) error }) (Collection, error) {
	var collection Collection
	var createdAt string
	err := row.Scan(&collection.ID, &collection.Name, &collection.CreatedBy, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Collection{}, ErrNotFound
	}
	if err != nil {
		return Collection{}, fmt.Errorf("scan collection: %w", err)
	}
	if collection.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return Collection{}, fmt.Errorf("parse created_at: %w", err)
	}
	return collection, nil
}

func (s *Store) CollectionByID(ctx context.Context, id string) (Collection, error) {
	return scanCollection(s.db.QueryRowContext(ctx,
		`SELECT `+collectionColumns+` FROM collections WHERE id = ?`, id))
}

// AllCollections is the admin view. It carries no sealed keys, because an
// admin who is not a member holds none and the server has none to give.
func (s *Store) AllCollections(ctx context.Context) ([]Collection, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+collectionColumns+` FROM collections ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("select collections: %w", err)
	}
	defer func() { _ = rows.Close() }()

	collections := []Collection{}
	for rows.Next() {
		collection, err := scanCollection(rows)
		if err != nil {
			return nil, err
		}
		collections = append(collections, collection)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate collections: %w", err)
	}
	return collections, nil
}

// DeleteCollection removes the collection. Memberships, pending grants, and
// the collection's items go with it through ON DELETE CASCADE — the items are
// hard-deleted rather than tombstoned because their key material is gone with
// the memberships, so a tombstone would describe something already unreadable.
func (s *Store) DeleteCollection(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM collections WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete collection: %w", err)
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

// CollectionsForUser returns each collection the user belongs to, carrying
// only that user's own sealed copy of the key.
func (s *Store) CollectionsForUser(ctx context.Context, userID string) ([]CollectionWithMembership, error) {
	return collectionsForUser(ctx, s.db, userID)
}

// queryer is satisfied by *sql.DB and *sql.Tx, so SyncSince can read
// collections inside its own read transaction.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func collectionsForUser(ctx context.Context, db queryer, userID string) ([]CollectionWithMembership, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT c.id, c.name, c.created_by, c.created_at,
		        m.role, m.sealed_collection_key, m.granted_at
		 FROM collections c
		 JOIN collection_memberships m ON m.collection_id = c.id
		 WHERE m.user_id = ?
		 ORDER BY c.name`, userID)
	if err != nil {
		return nil, fmt.Errorf("select memberships: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []CollectionWithMembership{}
	for rows.Next() {
		var row CollectionWithMembership
		var createdAt, grantedAt string
		if err := rows.Scan(&row.ID, &row.Name, &row.CreatedBy, &createdAt,
			&row.Role, &row.SealedCollectionKey, &grantedAt); err != nil {
			return nil, fmt.Errorf("scan membership: %w", err)
		}
		if row.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
		if row.GrantedAt, err = time.Parse(time.RFC3339, grantedAt); err != nil {
			return nil, fmt.Errorf("parse granted_at: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate memberships: %w", err)
	}
	return out, nil
}

const membershipColumns = `collection_id, user_id, sealed_collection_key, role, granted_by, granted_at`

func scanMembership(row interface{ Scan(...any) error }) (Membership, error) {
	var m Membership
	var grantedAt string
	err := row.Scan(&m.CollectionID, &m.UserID, &m.SealedCollectionKey,
		&m.Role, &m.GrantedBy, &grantedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Membership{}, ErrNotFound
	}
	if err != nil {
		return Membership{}, fmt.Errorf("scan membership: %w", err)
	}
	if m.GrantedAt, err = time.Parse(time.RFC3339, grantedAt); err != nil {
		return Membership{}, fmt.Errorf("parse granted_at: %w", err)
	}
	return m, nil
}

func (s *Store) MembershipFor(ctx context.Context, collectionID, userID string) (Membership, error) {
	return scanMembership(s.db.QueryRowContext(ctx,
		`SELECT `+membershipColumns+` FROM collection_memberships
		 WHERE collection_id = ? AND user_id = ?`, collectionID, userID))
}

func (s *Store) MembershipsOf(ctx context.Context, collectionID string) ([]Membership, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+membershipColumns+` FROM collection_memberships
		 WHERE collection_id = ? ORDER BY granted_at`, collectionID)
	if err != nil {
		return nil, fmt.Errorf("select memberships: %w", err)
	}
	defer func() { _ = rows.Close() }()

	memberships := []Membership{}
	for rows.Next() {
		m, err := scanMembership(rows)
		if err != nil {
			return nil, err
		}
		memberships = append(memberships, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate memberships: %w", err)
	}
	return memberships, nil
}

// FulfilGrantOrAdd inserts a membership directly, bypassing the pending-grant
// record. It exists for the one caller that legitimately has no grant to
// consume: an existing manager adding a member and sealing the key in the same
// request. Everything else goes through CreatePendingGrant and FulfilGrant.
func (s *Store) FulfilGrantOrAdd(ctx context.Context, collectionID, userID, sealedKey, role, grantedBy string) error {
	if !validRole(role) {
		return &ValidationError{Field: "role"}
	}
	if sealedKey == "" {
		return &ValidationError{Field: "sealedCollectionKey"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin add member: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := addMemberTx(ctx, tx, collectionID, userID, sealedKey, role, grantedBy); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit add member: %w", err)
	}
	return nil
}

func addMemberTx(ctx context.Context, tx *sql.Tx, collectionID, userID, sealedKey, role, grantedBy string) error {
	// granted_revision is drawn from the shared sequence inside this same
	// transaction. It is what delivers the collection's existing items — all of
	// which carry revisions below this member's cursor — on their next
	// incremental sync. Without it their vault looks empty and nothing reports
	// why. See migration 0003.
	granted, err := nextRevision(ctx, tx)
	if err != nil {
		return err
	}
	// A re-seal replaces the stored blob rather than failing. A member whose
	// key material was re-issued needs a fresh seal, and refusing it would
	// leave them permanently unable to open the collection.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO collection_memberships
		 (collection_id, user_id, sealed_collection_key, role, granted_by, granted_at, granted_revision)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (collection_id, user_id) DO UPDATE SET
		   sealed_collection_key = excluded.sealed_collection_key,
		   role = excluded.role,
		   granted_by = excluded.granted_by,
		   granted_at = excluded.granted_at,
		   granted_revision = excluded.granted_revision`,
		collectionID, userID, sealedKey, role, grantedBy,
		time.Now().UTC().Format(time.RFC3339), granted); err != nil {
		return fmt.Errorf("insert membership: %w", err)
	}
	return appendAudit(ctx, tx, grantedBy, "collection.member.add",
		"collection:"+collectionID, fmt.Sprintf(`{"userId":%q,"role":%q}`, userID, role))
}

// RemoveMember deletes a member's sealed key. Per spec section 5.1 this
// revokes future access and deliberately does NOT rotate the collection key: a
// removed member who kept a copy retains what they already had, and the admin
// UI says so.
//
// removedBy is recorded in the audit entry. Removing someone's access to shared
// credentials is exactly the kind of action that gets disputed later, so the
// log has to name who did it rather than storing a NULL actor.
func (s *Store) RemoveMember(ctx context.Context, collectionID, userID, removedBy string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin remove member: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var role string
	err = tx.QueryRowContext(ctx,
		`SELECT role FROM collection_memberships WHERE collection_id = ? AND user_id = ?`,
		collectionID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read membership: %w", err)
	}

	if role == "manager" {
		var managers int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM collection_memberships
			 WHERE collection_id = ? AND role = 'manager'`, collectionID).Scan(&managers); err != nil {
			return fmt.Errorf("count managers: %w", err)
		}
		// With no manager left, nobody can fulfil a pending grant, so the
		// collection can never gain another member and only an admin deleting
		// it outright ends that state.
		if managers <= 1 {
			return &ValidationError{Field: "userId"}
		}
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM collection_memberships WHERE collection_id = ? AND user_id = ?`,
		collectionID, userID); err != nil {
		return fmt.Errorf("delete membership: %w", err)
	}
	if err := appendAudit(ctx, tx, removedBy, "collection.member.remove",
		"collection:"+collectionID, fmt.Sprintf(`{"userId":%q}`, userID)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit remove member: %w", err)
	}
	return nil
}

// CreatePendingGrant records that a user should be given access. The server
// cannot grant it: it never holds a collection key. The next unlocked client
// belonging to a member seals the key and calls FulfilGrant.
func (s *Store) CreatePendingGrant(ctx context.Context, collectionID, userID, role, requestedBy string) error {
	if !validRole(role) {
		return &ValidationError{Field: "role"}
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO pending_grants (collection_id, user_id, requested_by, role, created_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (collection_id, user_id) DO UPDATE SET
		   role = excluded.role,
		   requested_by = excluded.requested_by,
		   created_at = excluded.created_at`,
		collectionID, userID, requestedBy, role,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("insert pending grant: %w", err)
	}
	return s.AppendAudit(ctx, requestedBy, "collection.grant.request",
		"collection:"+collectionID, fmt.Sprintf(`{"userId":%q,"role":%q}`, userID, role))
}

const pendingGrantSelect = `SELECT g.collection_id, c.name, g.user_id, g.role, g.requested_by, g.created_at
	FROM pending_grants g
	JOIN collections c ON c.id = g.collection_id`

// PendingGrantsFulfillableBy lists grants the caller can actually act on:
// only a member holds the collection key, so only a member can seal it to
// someone else. Listing them more widely would leak the membership graph to
// people outside the collection.
func (s *Store) PendingGrantsFulfillableBy(ctx context.Context, userID string) ([]PendingGrant, error) {
	rows, err := s.db.QueryContext(ctx,
		pendingGrantSelect+`
		 WHERE g.collection_id IN (
		     SELECT collection_id FROM collection_memberships WHERE user_id = ?
		 )
		 ORDER BY g.created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("select pending grants: %w", err)
	}
	return collectPendingGrants(rows)
}

// AllPendingGrants is the admin view: an admin needs to see that a grant they
// requested is still waiting on a member, even though they cannot fulfil it.
func (s *Store) AllPendingGrants(ctx context.Context) ([]PendingGrant, error) {
	rows, err := s.db.QueryContext(ctx, pendingGrantSelect+` ORDER BY g.created_at`)
	if err != nil {
		return nil, fmt.Errorf("select pending grants: %w", err)
	}
	return collectPendingGrants(rows)
}

func collectPendingGrants(rows *sql.Rows) ([]PendingGrant, error) {
	defer func() { _ = rows.Close() }()

	grants := []PendingGrant{}
	for rows.Next() {
		var grant PendingGrant
		var createdAt string
		if err := rows.Scan(&grant.CollectionID, &grant.CollectionName, &grant.UserID,
			&grant.Role, &grant.RequestedBy, &createdAt); err != nil {
			return nil, fmt.Errorf("scan pending grant: %w", err)
		}
		parsed, err := time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
		grant.CreatedAt = parsed
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending grants: %w", err)
	}
	return grants, nil
}

// FulfilGrant converts a pending grant into a membership, in one transaction.
//
// The role comes from the grant row, never from the caller: the fulfilling
// client holds the key but did not decide who gets what, and letting it choose
// would let any member quietly promote whoever they were sealing to.
func (s *Store) FulfilGrant(ctx context.Context, collectionID, userID, sealedKey, grantedBy string) error {
	if sealedKey == "" {
		return &ValidationError{Field: "sealedCollectionKey"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin fulfil grant: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var role string
	err = tx.QueryRowContext(ctx,
		`SELECT role FROM pending_grants WHERE collection_id = ? AND user_id = ?`,
		collectionID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		// The pending grant IS the authorization record. Without it any member
		// could add anyone to a collection just by sealing a key at them.
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read pending grant: %w", err)
	}
	if !validRole(role) {
		return &ValidationError{Field: "role"}
	}

	if err := addMemberTx(ctx, tx, collectionID, userID, sealedKey, role, grantedBy); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM pending_grants WHERE collection_id = ? AND user_id = ?`,
		collectionID, userID); err != nil {
		return fmt.Errorf("clear pending grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit fulfil grant: %w", err)
	}
	return nil
}
