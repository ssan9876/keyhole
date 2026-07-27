package store

import (
	"context"
	"errors"
	"testing"
)

func TestCreateCollectionMakesTheCreatorItsFirstManager(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed-to-creator")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if collection.Name != "Household" {
		t.Errorf("Name = %q", collection.Name)
	}

	// Spec section 5.1: a collection's creator is its first manager, and
	// managers are members, so they hold the collection key. A collection
	// created with no member at all would be unreachable — nobody could seal
	// its key to anyone, ever.
	membership, err := st.MembershipFor(ctx, collection.ID, creator)
	if err != nil {
		t.Fatalf("MembershipFor: %v", err)
	}
	if membership.Role != "manager" {
		t.Errorf("Role = %q, want manager", membership.Role)
	}
	if membership.SealedCollectionKey != "sealed-to-creator" {
		t.Errorf("SealedCollectionKey = %q, want it stored verbatim", membership.SealedCollectionKey)
	}
}

func TestCreateCollectionRejectsABlankNameOrMissingSealedKey(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")

	cases := []struct {
		name      string
		collName  string
		sealedKey string
	}{
		{"blank name", "   ", "sealed"},
		// A collection whose creator holds no sealed key is one nobody can ever
		// open or share: the server cannot produce the key, by design.
		{"no sealed key", "Household", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := st.CreateCollection(ctx, tc.collName, creator, tc.sealedKey)
			var validation *ValidationError
			if !errors.As(err, &validation) {
				t.Fatalf("err = %v, want a *ValidationError", err)
			}
		})
	}
}

func TestCreateCollectionIsAtomic(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()

	// A user id that violates the foreign key. The collection row and the
	// membership row must land together or not at all: a collection with no
	// manager cannot be repaired through the API.
	_, err := st.CreateCollection(ctx, "Household", "no-such-user", "sealed")
	if err == nil {
		t.Fatal("CreateCollection accepted a non-existent creator")
	}

	var collections, memberships int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM collections`).Scan(&collections); err != nil {
		t.Fatalf("count collections: %v", err)
	}
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM collection_memberships`).Scan(&memberships); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if collections != 0 || memberships != 0 {
		t.Errorf("left %d collections and %d memberships behind, want 0 and 0",
			collections, memberships)
	}
}

func TestCollectionsForUserCarriesTheirOwnSealedKeyOnly(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")
	member := enrolledUserID(t, st, "member@example.com")
	outsider := enrolledUserID(t, st, "outsider@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed-to-creator")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if err := st.FulfilGrantOrAdd(ctx, collection.ID, member, "sealed-to-member", "member", creator); err != nil {
		t.Fatalf("add member: %v", err)
	}

	forMember, err := st.CollectionsForUser(ctx, member)
	if err != nil {
		t.Fatalf("CollectionsForUser: %v", err)
	}
	if len(forMember) != 1 {
		t.Fatalf("got %d collections, want 1", len(forMember))
	}
	// Each member's copy of the key is sealed to their own public key. Handing
	// a user someone else's sealed blob would be useless at best, and at worst
	// would suggest the server has a key it can redistribute — it does not.
	if forMember[0].SealedCollectionKey != "sealed-to-member" {
		t.Errorf("SealedCollectionKey = %q, want this member's own copy",
			forMember[0].SealedCollectionKey)
	}
	if forMember[0].Role != "member" {
		t.Errorf("Role = %q, want member", forMember[0].Role)
	}

	forOutsider, err := st.CollectionsForUser(ctx, outsider)
	if err != nil {
		t.Fatalf("CollectionsForUser: %v", err)
	}
	if len(forOutsider) != 0 {
		t.Errorf("a non-member sees %d collections, want 0", len(forOutsider))
	}
}

func TestRemoveMemberDeletesTheirSealedKey(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")
	member := enrolledUserID(t, st, "member@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed-to-creator")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if err := st.FulfilGrantOrAdd(ctx, collection.ID, member, "sealed-to-member", "member", creator); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if err := st.RemoveMember(ctx, collection.ID, member, creator); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}

	if _, err := st.MembershipFor(ctx, collection.ID, member); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	// Spec section 5.1: removal deletes the sealed key, revoking future access.
	// It deliberately does not rotate the collection key, so this asserts what
	// the design actually promises rather than what it might appear to.
	var count int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM collection_memberships WHERE collection_id = ? AND user_id = ?`,
		collection.ID, member).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Error("the sealed key row survives removal")
	}
}

func TestRemovingTheLastManagerIsRefused(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")
	member := enrolledUserID(t, st, "member@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed-to-creator")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if err := st.FulfilGrantOrAdd(ctx, collection.ID, member, "sealed", "member", creator); err != nil {
		t.Fatalf("add member: %v", err)
	}

	// With no manager left, nobody can fulfil a pending grant, so the
	// collection can never gain another member — and only an admin deleting it
	// outright can end that state.
	err = st.RemoveMember(ctx, collection.ID, creator, creator)
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("err = %v, want a *ValidationError refusing the removal", err)
	}
}

func TestCreatePendingGrantRecordsTheRoleItWillConfer(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")
	invitee := enrolledUserID(t, st, "invitee@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if err := st.CreatePendingGrant(ctx, collection.ID, invitee, "manager", creator); err != nil {
		t.Fatalf("CreatePendingGrant: %v", err)
	}

	// Without the role on the row, the fulfilling client has to guess, and
	// every grant silently becomes a plain member.
	grants, err := st.PendingGrantsFulfillableBy(ctx, creator)
	if err != nil {
		t.Fatalf("PendingGrantsFulfillableBy: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("got %d grants, want 1", len(grants))
	}
	if grants[0].Role != "manager" {
		t.Errorf("Role = %q, want manager", grants[0].Role)
	}
	if grants[0].CollectionName != "Household" {
		t.Errorf("CollectionName = %q, want the name so the UI can name it", grants[0].CollectionName)
	}
}

func TestPendingGrantsAreVisibleOnlyToMembersWhoCanFulfilThem(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")
	invitee := enrolledUserID(t, st, "invitee@example.com")
	outsider := enrolledUserID(t, st, "outsider@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if err := st.CreatePendingGrant(ctx, collection.ID, invitee, "member", creator); err != nil {
		t.Fatalf("CreatePendingGrant: %v", err)
	}

	// Only someone who already holds the collection key can seal it to the new
	// member, so only they need to see the grant. Showing it more widely leaks
	// the membership graph to people outside the collection.
	forOutsider, err := st.PendingGrantsFulfillableBy(ctx, outsider)
	if err != nil {
		t.Fatalf("PendingGrantsFulfillableBy: %v", err)
	}
	if len(forOutsider) != 0 {
		t.Errorf("an outsider sees %d pending grants, want 0", len(forOutsider))
	}
}

func TestFulfilGrantAddsTheMemberAndClearsTheGrant(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")
	invitee := enrolledUserID(t, st, "invitee@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if err := st.CreatePendingGrant(ctx, collection.ID, invitee, "manager", creator); err != nil {
		t.Fatalf("CreatePendingGrant: %v", err)
	}
	if err := st.FulfilGrant(ctx, collection.ID, invitee, "sealed-to-invitee", creator); err != nil {
		t.Fatalf("FulfilGrant: %v", err)
	}

	membership, err := st.MembershipFor(ctx, collection.ID, invitee)
	if err != nil {
		t.Fatalf("MembershipFor: %v", err)
	}
	// The role comes from the grant, not from the fulfilling client, which
	// otherwise could quietly promote whoever it is sealing to.
	if membership.Role != "manager" {
		t.Errorf("Role = %q, want the manager role recorded on the grant", membership.Role)
	}

	// A grant left behind would show forever in the pending list and invite a
	// second, redundant seal.
	grants, err := st.PendingGrantsFulfillableBy(ctx, creator)
	if err != nil {
		t.Fatalf("PendingGrantsFulfillableBy: %v", err)
	}
	if len(grants) != 0 {
		t.Errorf("%d grants remain after fulfilment, want 0", len(grants))
	}
}

func TestFulfilGrantWithoutAGrantIsNotFound(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")
	stranger := enrolledUserID(t, st, "stranger@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}

	// The pending grant is the authorization record. Without it, any member
	// could add anyone to a collection just by sealing a key at them.
	err = st.FulfilGrant(ctx, collection.ID, stranger, "sealed", creator)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestDeleteCollectionRemovesItsItemsMembershipsAndGrants(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")

	collection, err := st.CreateCollection(ctx, "Household", creator, "sealed")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if _, err := st.CreateItem(ctx, creator, ItemInput{
		CollectionID: &collection.ID, Ciphertext: "c", WrappedItemKey: "k",
	}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	if err := st.DeleteCollection(ctx, collection.ID); err != nil {
		t.Fatalf("DeleteCollection: %v", err)
	}

	// ON DELETE CASCADE from migration 0001 does the work; this asserts the
	// cascade is real rather than assumed, because foreign_keys is a
	// per-connection pragma that is off by default.
	for _, table := range []string{"collections", "collection_memberships", "items"} {
		var count int
		if err := st.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM `+table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Errorf("%s still has %d rows after the collection was deleted", table, count)
		}
	}
}

func TestSyncCarriesTheCallersCollections(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	creator := enrolledUserID(t, st, "admin@example.com")
	outsider := enrolledUserID(t, st, "outsider@example.com")

	if _, err := st.CreateCollection(ctx, "Household", creator, "sealed-to-creator"); err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}

	// Collections ride on every sync in full, not incrementally: at household
	// scale that is a handful of rows, and it means a revoked membership simply
	// disappears rather than needing a tombstone table of its own.
	mine, err := st.SyncSince(ctx, creator, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(mine.Collections) != 1 {
		t.Fatalf("got %d collections, want 1", len(mine.Collections))
	}
	if mine.Collections[0].SealedCollectionKey != "sealed-to-creator" {
		t.Errorf("SealedCollectionKey = %q", mine.Collections[0].SealedCollectionKey)
	}

	theirs, err := st.SyncSince(ctx, outsider, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(theirs.Collections) != 0 {
		t.Errorf("a non-member's sync carries %d collections, want 0", len(theirs.Collections))
	}
}

// TestANewMembersFirstSyncDeliversTheWholeCollection covers the correction the
// plan's sync contract records after Task 2's review.
//
// The cursor is global and monotonic, but visibility is evaluated at query
// time. A shared item created before someone was granted access carries a
// revision BELOW the cursor their device already holds, so filtering on
// item.revision alone returns nothing and the household's shared passwords stay
// invisible until that device wipes its local state. There is no error and no
// empty-state signal — which is why this needs a test rather than a comment.
func TestANewMembersFirstSyncDeliversTheWholeCollection(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	owner := enrolledUserID(t, st, "owner@example.com")
	newcomer := enrolledUserID(t, st, "newcomer@example.com")

	collection, err := st.CreateCollection(ctx, "Household", owner, "sealed-to-owner")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if _, err := st.CreateItem(ctx, owner, ItemInput{
		CollectionID: &collection.ID, Ciphertext: "shared-secret", WrappedItemKey: "k",
	}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	// The newcomer's device is already up to date on its own (empty) vault, so
	// its cursor is at the high-water mark — past the shared item's revision.
	before, err := st.SyncSince(ctx, newcomer, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(before.Items) != 0 {
		t.Fatalf("newcomer saw %d items before being granted access", len(before.Items))
	}
	cursor := before.Revision

	if err := st.FulfilGrantOrAdd(ctx, collection.ID, newcomer, "sealed-to-newcomer", "member", owner); err != nil {
		t.Fatalf("add member: %v", err)
	}

	after, err := st.SyncSince(ctx, newcomer, cursor)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(after.Items) != 1 {
		t.Fatalf("newcomer's incremental sync returned %d items, want the 1 shared item; "+
			"a membership granted after the item was written leaves it below the cursor forever",
			len(after.Items))
	}
	if after.Items[0].Ciphertext != "shared-secret" {
		t.Errorf("ciphertext = %q, want %q", after.Items[0].Ciphertext, "shared-secret")
	}
}

// TestAGrantDoesNotResendTheCollectionToExistingMembers is the other half of
// the rule: granted_revision delivers the backlog to the person just added and
// to nobody else. Without this, every grant would re-send the whole collection
// to every existing member on their next poll.
func TestAGrantDoesNotResendTheCollectionToExistingMembers(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	owner := enrolledUserID(t, st, "owner@example.com")
	newcomer := enrolledUserID(t, st, "newcomer@example.com")

	collection, err := st.CreateCollection(ctx, "Household", owner, "sealed-to-owner")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if _, err := st.CreateItem(ctx, owner, ItemInput{
		CollectionID: &collection.ID, Ciphertext: "shared-secret", WrappedItemKey: "k",
	}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	caughtUp, err := st.SyncSince(ctx, owner, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	cursor := caughtUp.Revision

	if err := st.FulfilGrantOrAdd(ctx, collection.ID, newcomer, "sealed-to-newcomer", "member", owner); err != nil {
		t.Fatalf("add member: %v", err)
	}

	after, err := st.SyncSince(ctx, owner, cursor)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(after.Items) != 0 {
		t.Errorf("an existing member was re-sent %d items because someone else was granted access",
			len(after.Items))
	}
}
