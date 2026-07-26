package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// enrolledUserID is enrolledUser (sessions_test.go) for the callers that want
// only the id.
//
// It delegates rather than seeding its own row, so there is one definition of
// what an enrolled account looks like. That matters beyond tidiness: several
// store methods added by this plan carry `AND status = 'active'` and would
// report a misleading ErrNotFound for a pending row, and the account tests
// assert that a password rotation leaves the recovery blob alone — which
// proves nothing unless a real enrollment put one there.
func enrolledUserID(t *testing.T, st *Store, email string) string {
	t.Helper()
	return enrolledUser(t, st, email).ID
}

func TestCreateItemStoresCiphertextVerbatimAndNumbersIt(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	// A ciphertext the server must not touch: it is the crypto package's
	// envelope, and anything the server did to it would corrupt the item.
	const ct = `{"v":1,"alg":"A256GCM","n":"AAAAAAAAAAAAAAAA","ct":"3q2+7w=="}`
	item, err := st.CreateItem(ctx, userID, ItemInput{
		Ciphertext:     ct,
		WrappedItemKey: "wrapped-key-blob",
	})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	// Read the row back rather than inspecting the struct CreateItem assembled
	// from this test's own input. Asserting on the returned struct proves only
	// that the test can echo itself: an INSERT that appended "-TAMPERED" to
	// both blobs passed the earlier version of this test unchanged.
	stored, err := st.ItemByID(ctx, item.ID)
	if err != nil {
		t.Fatalf("ItemByID: %v", err)
	}

	if stored.Ciphertext != ct {
		t.Errorf("stored Ciphertext = %q, want it stored verbatim (%q)", stored.Ciphertext, ct)
	}
	if stored.WrappedItemKey != "wrapped-key-blob" {
		t.Errorf("stored WrappedItemKey = %q", stored.WrappedItemKey)
	}
	if stored.CollectionID.Valid {
		t.Error("an item created with no collection must be personal")
	}
	if stored.Revision != 1 {
		t.Errorf("stored Revision = %d, want 1 as the first write to a fresh database", stored.Revision)
	}
	if stored.DeletedAt.Valid {
		t.Error("a new item must not be a tombstone")
	}
	if stored.OwnerUserID != userID {
		t.Errorf("stored OwnerUserID = %q, want %q", stored.OwnerUserID, userID)
	}
	// The struct handed back to the caller has to agree with the row, or a POST
	// response and a later GET describe different items.
	if item.Ciphertext != stored.Ciphertext || item.WrappedItemKey != stored.WrappedItemKey ||
		item.Revision != stored.Revision || item.ID != stored.ID {
		t.Errorf("returned item disagrees with the stored row:\n returned %+v\n stored   %+v", item, stored)
	}
}

func TestCreateItemRejectsEmptyCiphertextAndKey(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	// The server cannot check that a ciphertext decrypts — that is the whole
	// point — so the one check it can make is that the client sent something.
	// An item with an empty body is unrecoverable data loss the user would
	// discover only on unlocking.
	cases := []struct {
		name string
		in   ItemInput
	}{
		{"no ciphertext", ItemInput{WrappedItemKey: "k"}},
		{"no wrapped key", ItemInput{Ciphertext: "c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := st.CreateItem(ctx, userID, tc.in)
			var validation *ValidationError
			if !errors.As(err, &validation) {
				t.Fatalf("err = %v, want a *ValidationError", err)
			}
		})
	}
}

func TestUpdateItemAdvancesTheRevisionAndReplacesTheBody(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "v1", WrappedItemKey: "k1"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	// Captured before the write so the stored stamp can be compared against a
	// known lower bound rather than against another in-memory time.Now().
	before := time.Now().UTC().Truncate(time.Second)

	updated, err := st.UpdateItem(ctx, created.ID, created.Revision,
		ItemInput{Ciphertext: "v2", WrappedItemKey: "k2"})
	if err != nil {
		t.Fatalf("UpdateItem: %v", err)
	}

	if updated.Ciphertext != "v2" || updated.WrappedItemKey != "k2" {
		t.Errorf("update did not replace the body: %+v", updated)
	}
	if updated.Revision <= created.Revision {
		t.Errorf("Revision = %d, want greater than %d — a sync at the old cursor "+
			"would never see this edit", updated.Revision, created.Revision)
	}

	// The stamp has to come from the column. Comparing two in-memory
	// time.Now() values proves only that time moves forward: writing
	// updated_at = '1999-01-01T00:00:00Z' while returning now passed the
	// earlier version of this clause.
	stored, err := st.ItemByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("ItemByID: %v", err)
	}
	if stored.UpdatedAt.Before(before) {
		t.Errorf("stored updated_at = %s, want no earlier than %s — a client "+
			"sorting or displaying by this stamp sees the edit as older than it is",
			stored.UpdatedAt.Format(time.RFC3339), before.Format(time.RFC3339))
	}
	if stored.UpdatedAt.Before(stored.CreatedAt) {
		t.Errorf("stored updated_at %s is before created_at %s",
			stored.UpdatedAt.Format(time.RFC3339), stored.CreatedAt.Format(time.RFC3339))
	}
}

func TestUpdateItemRefusesAStaleRevisionAndReturnsTheCurrentRow(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "base", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	// Someone else's edit lands first.
	winner, err := st.UpdateItem(ctx, created.ID, created.Revision,
		ItemInput{Ciphertext: "theirs", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("first UpdateItem: %v", err)
	}

	// Ours was written against the pre-edit revision.
	current, err := st.UpdateItem(ctx, created.ID, created.Revision,
		ItemInput{Ciphertext: "ours", WrappedItemKey: "k"})
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("err = %v, want ErrRevisionConflict", err)
	}
	// The current row rides along so the handler can hand it to the client,
	// which is what lets the client keep BOTH edits as a conflicted copy.
	if current.Ciphertext != "theirs" {
		t.Errorf("returned Ciphertext = %q, want the winning row %q", current.Ciphertext, "theirs")
	}
	if current.Revision != winner.Revision {
		t.Errorf("returned Revision = %d, want the current %d", current.Revision, winner.Revision)
	}

	// And the losing write must not have landed.
	stored, err := st.ItemByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("ItemByID: %v", err)
	}
	if stored.Ciphertext != "theirs" {
		t.Errorf("stored Ciphertext = %q; the stale write overwrote the winner", stored.Ciphertext)
	}
}

func TestDeleteItemTombstonesAndDestroysTheCiphertext(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID,
		ItemInput{Ciphertext: "secret-ciphertext", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	deleted, err := st.DeleteItem(ctx, created.ID)
	if err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}
	if !deleted.DeletedAt.Valid {
		t.Error("DeletedAt is not set; the delete will not propagate to other devices")
	}
	if deleted.Revision <= created.Revision {
		t.Errorf("Revision = %d, want greater than %d", deleted.Revision, created.Revision)
	}

	// A delete that leaves the data readable in the database is not a delete.
	// The row survives only as a tombstone so other devices learn about it.
	stored, err := st.ItemByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("ItemByID after delete: %v", err)
	}
	if stored.Ciphertext != "" {
		t.Errorf("Ciphertext = %q after delete, want it destroyed", stored.Ciphertext)
	}
	if stored.WrappedItemKey != "" {
		t.Errorf("WrappedItemKey = %q after delete, want it destroyed", stored.WrappedItemKey)
	}
}

func TestDeletingAnAlreadyDeletedItemIsNotFound(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "c", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	if _, err := st.DeleteItem(ctx, created.ID); err != nil {
		t.Fatalf("first DeleteItem: %v", err)
	}

	// Without this, a retried delete burns a revision and re-broadcasts a
	// tombstone every client already has.
	if _, err := st.DeleteItem(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteItem err = %v, want ErrNotFound", err)
	}
}

func TestUpdatingATombstoneIsNotFound(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "c", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	deleted, err := st.DeleteItem(ctx, created.ID)
	if err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}

	// A device that was offline during the delete must not be able to
	// resurrect the item by pushing its cached copy.
	//
	// The expected revision is the TOMBSTONE's current one, not the pre-delete
	// one. A stale revision would be refused as a conflict whether or not the
	// tombstone guard exists, which is why the earlier version of this test
	// passed with `if false && current.DeletedAt.Valid`. Passing the current
	// revision leaves the guard as the only thing that can reject the write,
	// and ErrRevisionConflict is no longer an acceptable answer: a conflict
	// tells the client to resolve and retry, and there is nothing to resolve.
	_, err = st.UpdateItem(ctx, created.ID, deleted.Revision,
		ItemInput{Ciphertext: "resurrected", WrappedItemKey: "k"})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	stored, err := st.ItemByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("ItemByID: %v", err)
	}
	if stored.Ciphertext != "" || !stored.DeletedAt.Valid {
		t.Error("a tombstone was resurrected by an update")
	}
}

func TestCreateItemsBulkIsAllOrNothing(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	// An import of a thousand passwords that half-lands leaves the user with
	// no way to tell which half. One transaction, or none.
	//
	// The middle row names a collection that does not exist. That is deliberate:
	// it passes validate() and fails at the INSERT on the foreign key, INSIDE
	// the loop and AFTER row one has already been written — which is the only
	// arrangement that exercises the rollback at all. A row rejected by
	// validate() short-circuits before BeginTx, so no transaction ever exists;
	// with such a row, replacing `defer tx.Rollback()` with `defer tx.Commit()`
	// passed the earlier version of this test.
	const missingCollection = "ffffffffffffffffffffffffffffffff"
	_, err := st.CreateItemsBulk(ctx, userID, []ItemInput{
		{Ciphertext: "ok-1", WrappedItemKey: "k"},
		{CollectionID: missingCollection, Ciphertext: "orphan", WrappedItemKey: "k"},
		{Ciphertext: "ok-2", WrappedItemKey: "k"},
	})
	if err == nil {
		t.Fatal("CreateItemsBulk accepted a batch whose middle row names a collection that does not exist")
	}

	// Row one was inserted before the failure. If the transaction did not roll
	// back, it is still there.
	var count int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM items`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("%d items survived a failed batch, want 0 — the earlier rows in "+
			"the same batch must not land", count)
	}

	rev, err := st.CurrentRevision(ctx)
	if err != nil {
		t.Fatalf("CurrentRevision: %v", err)
	}
	if rev != 0 {
		t.Errorf("CurrentRevision = %d after a failed batch, want 0", rev)
	}
}

func TestCreateItemsBulkRejectsAnInvalidRowBeforeWritingAnything(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	// The cheap path: validation runs over every row before BeginTx, so a batch
	// with an empty body never opens a transaction at all.
	_, err := st.CreateItemsBulk(ctx, userID, []ItemInput{
		{Ciphertext: "ok-1", WrappedItemKey: "k"},
		{Ciphertext: "", WrappedItemKey: "k"}, // invalid
		{Ciphertext: "ok-2", WrappedItemKey: "k"},
	})
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("err = %v, want a *ValidationError", err)
	}

	var count int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM items`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("%d items survived a rejected batch, want 0", count)
	}
}

func TestCreateItemsBulkNumbersEveryRowDistinctly(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	ins := make([]ItemInput, 50)
	for i := range ins {
		ins[i] = ItemInput{Ciphertext: strings.Repeat("c", i+1), WrappedItemKey: "k"}
	}
	items, err := st.CreateItemsBulk(ctx, userID, ins)
	if err != nil {
		t.Fatalf("CreateItemsBulk: %v", err)
	}
	if len(items) != len(ins) {
		t.Fatalf("returned %d items, want %d", len(items), len(ins))
	}

	// Sharing a revision across a batch would mean a client syncing mid-import
	// records a cursor that skips the rest of the batch forever.
	//
	// The revisions have to come from the column, not from the returned structs:
	// CreateItemsBulk assembles those in memory from its own loop variable, so
	// storing a literal 1 for every row while returning the real distinct values
	// passed the earlier version of this test.
	rows, err := st.DB().QueryContext(ctx, `SELECT revision FROM items`)
	if err != nil {
		t.Fatalf("select revisions: %v", err)
	}
	defer rows.Close()

	seen := make(map[int64]bool, len(items))
	for rows.Next() {
		var revision int64
		if err := rows.Scan(&revision); err != nil {
			t.Fatalf("scan revision: %v", err)
		}
		if seen[revision] {
			t.Fatalf("stored revision %d appears twice in one batch", revision)
		}
		seen[revision] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(seen) != len(ins) {
		t.Fatalf("%d distinct revisions in the items table, want %d", len(seen), len(ins))
	}

	// And the numbers reported to the client must be the numbers on disk, or a
	// client's sync cursor points at revisions no row carries.
	for _, item := range items {
		if !seen[item.Revision] {
			t.Errorf("returned revision %d for item %s matches no stored row",
				item.Revision, item.ID)
		}
	}
}

// TestConcurrentUpdatesAndDeletesDoNotReturnBusy is a regression test for the
// deferred-transaction ordering bug.
//
// A deferred transaction that runs its SELECT first takes a WAL read snapshot
// before it ever asks for the write lock. If another connection commits in the
// gap, SQLite fails the first write with SQLITE_BUSY_SNAPSHOT — and the busy
// handler is deliberately NOT invoked for that code, so the DSN's
// busy_timeout(5000) never applies and no amount of waiting helps. Open sets
// SetMaxOpenConns(4), so this is production-reachable: two phones in one
// household editing different items at the same moment.
//
// Every operation below targets a distinct item at its own current revision, so
// every one of them is valid. Any error at all is the bug.
func TestConcurrentUpdatesAndDeletesDoNotReturnBusy(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	const n = 180
	ins := make([]ItemInput, n)
	for i := range ins {
		ins[i] = ItemInput{Ciphertext: "body", WrappedItemKey: "k"}
	}
	created, err := st.CreateItemsBulk(ctx, userID, ins)
	if err != nil {
		t.Fatalf("CreateItemsBulk: %v", err)
	}

	var mu sync.Mutex
	var failures []string

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range created {
		wg.Add(1)
		go func(i int, item Item) {
			defer wg.Done()
			<-start
			var err error
			var op string
			if i%2 == 0 {
				op = "UpdateItem"
				_, err = st.UpdateItem(ctx, item.ID, item.Revision,
					ItemInput{Ciphertext: "edited", WrappedItemKey: "k"})
			} else {
				op = "DeleteItem"
				_, err = st.DeleteItem(ctx, item.ID)
			}
			if err != nil {
				mu.Lock()
				failures = append(failures, fmt.Sprintf("%s(%s): %v", op, item.ID, err))
				mu.Unlock()
			}
		}(i, created[i])
	}
	close(start)
	wg.Wait()

	if len(failures) > 0 {
		shown := failures
		if len(shown) > 5 {
			shown = shown[:5]
		}
		t.Fatalf("%d of %d concurrent writes failed; a valid edit must not become "+
			"an unclassified 500. First failures:\n%s",
			len(failures), n, strings.Join(shown, "\n"))
	}
}

func TestItemByIDReportsAMissingItemAsNotFound(t *testing.T) {
	st := openTemp(t)

	if _, err := st.ItemByID(context.Background(), "0123456789abcdef0123456789abcdef"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
