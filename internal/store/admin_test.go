package store

import (
	"context"
	"errors"
	"testing"
)

// adminUser creates an active admin account.
func adminUser(t *testing.T, st *Store, email string) string {
	t.Helper()
	ctx := context.Background()
	user, err := st.CreatePendingUser(ctx, email, "Admin Person", "admin")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE users SET status = 'active', public_key = 'pk', auth_hash = 'h' WHERE id = ?`,
		user.ID); err != nil {
		t.Fatalf("activate admin: %v", err)
	}
	return user.ID
}

func TestListUsersFlagsPendingInvites(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	adminUser(t, st, "admin@example.com")

	invited, err := st.CreatePendingUser(ctx, "invited@example.com", "Invited", "user")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	if _, _, err := st.CreateInvite(ctx, invited.ID, InviteTTL); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	stranded, err := st.CreatePendingUser(ctx, "stranded@example.com", "Stranded", "user")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}

	users, err := st.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	byID := map[string]UserSummary{}
	for _, user := range users {
		byID[user.ID] = user
	}
	if len(users) != 3 {
		t.Fatalf("got %d users, want 3", len(users))
	}
	if !byID[invited.ID].HasPendingInvite {
		t.Error("an invited account is not flagged as having a live invite")
	}
	// This is the visible symptom of the failure mode the reissue path exists
	// for: a pending account with no usable link and nothing in the UI saying so.
	if byID[stranded.ID].HasPendingInvite {
		t.Error("an account with no invite is flagged as having one")
	}
}

func TestSetUserStatusRefusesToDisableTheLastAdmin(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	admin := adminUser(t, st, "admin@example.com")

	// With no admin left, nobody can create one: there is no registration
	// endpoint and the CLI needs shell access to the container.
	if err := st.SetUserStatus(ctx, admin, "disabled", admin); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("err = %v, want ErrLastAdmin", err)
	}

	user, err := st.UserByID(ctx, admin)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if user.Status != "active" {
		t.Errorf("Status = %q, want the account left active", user.Status)
	}
}

func TestSetUserStatusDisablesWhenAnotherAdminRemains(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	first := adminUser(t, st, "first@example.com")
	second := adminUser(t, st, "second@example.com")

	if err := st.SetUserStatus(ctx, second, "disabled", first); err != nil {
		t.Fatalf("SetUserStatus: %v", err)
	}
	user, err := st.UserByID(ctx, second)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if user.Status != "disabled" {
		t.Errorf("Status = %q, want disabled", user.Status)
	}
}

func TestSetUserStatusRejectsAnUnknownStatus(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	admin := adminUser(t, st, "admin@example.com")
	target := enrolledUserID(t, st, "person@example.com")

	// The column has a CHECK, but a raw constraint failure would reach the
	// client as a 500 for what is plainly a bad request.
	err := st.SetUserStatus(ctx, target, "banished", admin)
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("err = %v, want a *ValidationError", err)
	}
}

func TestDisablingAUserRevokesTheirSessions(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	admin := adminUser(t, st, "admin@example.com")
	target := enrolledUserID(t, st, "person@example.com")

	_, token, _, err := st.CreateSession(ctx, target, "their laptop")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := st.SetUserStatus(ctx, target, "disabled", admin); err != nil {
		t.Fatalf("SetUserStatus: %v", err)
	}

	// requireAuth already re-checks status on every request, so this is belt
	// and braces — but "disable this account" that leaves live session rows
	// behind is a claim the sessions list would contradict to the user's face.
	if _, err := st.SessionByAccessToken(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Errorf("a disabled account still has a live session: %v", err)
	}
}

func TestResetUserDestroysKeyMaterialAndReturnsAFreshInvite(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	admin := adminUser(t, st, "admin@example.com")
	target := enrolledUserID(t, st, "person@example.com")

	// Give the account something to lose.
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE users SET status = 'active', auth_hash = 'h', protected_user_key = 'puk',
		 recovery_protected_user_key = 'rpuk', recovery_auth_hash = 'rah',
		 public_key = 'pk', encrypted_private_key = 'epk'
		 WHERE id = ?`, target); err != nil {
		t.Fatalf("seed key material: %v", err)
	}
	if _, err := st.CreateItem(ctx, target, ItemInput{Ciphertext: "c", WrappedItemKey: "k"}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	collection, err := st.CreateCollection(ctx, "Household", admin, "sealed")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if err := st.FulfilGrantOrAdd(ctx, collection.ID, target, "sealed-to-target", "member", admin); err != nil {
		t.Fatalf("add member: %v", err)
	}

	token, err := st.ResetUser(ctx, target, admin)
	if err != nil {
		t.Fatalf("ResetUser: %v", err)
	}
	if token == "" {
		t.Fatal("ResetUser returned no invite token; the user cannot get back in")
	}

	user, err := st.UserByID(ctx, target)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if user.Status != "pending" {
		t.Errorf("Status = %q, want pending", user.Status)
	}
	// Spec section 3.7. Any of these surviving would leave a vault the new
	// master password cannot open but the old key material still could.
	for name, value := range map[string]string{
		"auth_hash":                   user.AuthHash.String,
		"protected_user_key":          user.ProtectedUserKey.String,
		"recovery_protected_user_key": user.RecoveryProtectedUserKey.String,
		// A credential in its own right, and the one the redeem endpoints check.
		// Left behind, a reset account keeps proving possession of a code whose
		// blob has just been destroyed.
		"recovery_auth_hash":    user.RecoveryAuthHash.String,
		"public_key":            user.PublicKey.String,
		"encrypted_private_key": user.EncryptedPrivateKey.String,
	} {
		if value != "" {
			t.Errorf("%s survived the reset: %q", name, value)
		}
	}

	// The personal items are gone, not tombstoned: nothing can ever decrypt
	// them again, so a tombstone would describe an item that no longer exists
	// in any meaningful sense.
	var items int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM items WHERE owner_user_id = ?`, target).Scan(&items); err != nil {
		t.Fatalf("count items: %v", err)
	}
	if items != 0 {
		t.Errorf("%d personal items survived the reset", items)
	}

	// The new keypair will be different, so every collection has to re-grant.
	// Leaving the membership row would leave a sealed key only the destroyed
	// private key could open.
	if _, err := st.MembershipFor(ctx, collection.ID, target); !errors.Is(err, ErrNotFound) {
		t.Errorf("collection membership survived the reset: %v", err)
	}

	// And the returned token actually works.
	if _, err := st.InviteByToken(ctx, token); err != nil {
		t.Errorf("the reset invite is not usable: %v", err)
	}
}

func TestResetUserKeepsCollectionItemsOthersStillNeed(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	admin := adminUser(t, st, "admin@example.com")
	target := enrolledUserID(t, st, "person@example.com")

	collection, err := st.CreateCollection(ctx, "Household", admin, "sealed")
	if err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	if err := st.FulfilGrantOrAdd(ctx, collection.ID, target, "sealed-to-target", "member", admin); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if _, err := st.CreateItem(ctx, target, ItemInput{
		CollectionID: &collection.ID, Ciphertext: "shared", WrappedItemKey: "k",
	}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	if _, err := st.ResetUser(ctx, target, admin); err != nil {
		t.Fatalf("ResetUser: %v", err)
	}

	// A collection item is wrapped by the collection key, which every other
	// member still holds. Deleting it because its creator was reset would
	// destroy shared data belonging to people the reset had nothing to do with.
	var items int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM items WHERE collection_id = ? AND deleted_at IS NULL`,
		collection.ID).Scan(&items); err != nil {
		t.Fatalf("count items: %v", err)
	}
	if items != 1 {
		t.Errorf("%d collection items survive the reset, want 1", items)
	}
}

func TestDeleteUserReportsAReferenceRatherThanFailing(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	admin := adminUser(t, st, "admin@example.com")
	creator := adminUser(t, st, "creator@example.com")

	if _, err := st.CreateCollection(ctx, "Household", creator, "sealed"); err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}

	// collections.created_by has no ON DELETE action, deliberately: a delete
	// must not cascade into destroying a shared collection. So this has to be a
	// named error the handler can turn into an actionable 409, not a raw
	// constraint failure that reads as a server fault.
	err := st.DeleteUser(ctx, creator, admin)
	if !errors.Is(err, ErrUserReferenced) {
		t.Fatalf("err = %v, want ErrUserReferenced", err)
	}

	if _, err := st.UserByID(ctx, creator); err != nil {
		t.Errorf("the user was partly deleted anyway: %v", err)
	}
}

func TestDeleteUserRemovesAnUnreferencedAccountAndItsItems(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	admin := adminUser(t, st, "admin@example.com")
	target := enrolledUserID(t, st, "person@example.com")

	if _, err := st.CreateItem(ctx, target, ItemInput{Ciphertext: "c", WrappedItemKey: "k"}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	if _, _, _, err := st.CreateSession(ctx, target, "laptop"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if err := st.DeleteUser(ctx, target, admin); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := st.UserByID(ctx, target); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	for _, table := range []string{"items", "sessions"} {
		var count int
		if err := st.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM `+table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Errorf("%s still has %d rows; the ON DELETE CASCADE did not fire", table, count)
		}
	}
}

func TestDeleteUserRefusesTheLastAdmin(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	admin := adminUser(t, st, "admin@example.com")

	if err := st.DeleteUser(ctx, admin, admin); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("err = %v, want ErrLastAdmin", err)
	}
}
