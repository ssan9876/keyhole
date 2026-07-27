package store

import (
	"context"
	"sync"
	"testing"
	"time"
)

// seedCollectionWithMembers inserts a collection and its memberships
// directly. Task 4 replaces this with CreateCollection.
//
// Named distinctly from items_test.go's seedCollection (Task 1), which takes
// an explicit name and inserts no membership rows — that helper only needs a
// foreign-key-valid collection id, while the sync visibility tests need real
// membership rows to exercise the access rule. Both existing under the same
// name would not compile.
func seedCollectionWithMembers(t *testing.T, st *Store, createdBy string, memberIDs ...string) string {
	t.Helper()
	ctx := context.Background()
	id, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO collections (id, name, created_by, created_at) VALUES (?, ?, ?, ?)`,
		id, "Household", createdBy, now); err != nil {
		t.Fatalf("insert collection: %v", err)
	}
	for _, member := range memberIDs {
		if _, err := st.DB().ExecContext(ctx,
			`INSERT INTO collection_memberships
			 (collection_id, user_id, sealed_collection_key, role, granted_by, granted_at)
			 VALUES (?, ?, ?, 'member', ?, ?)`,
			id, member, "sealed-blob", createdBy, now); err != nil {
			t.Fatalf("insert membership: %v", err)
		}
	}
	return id
}

func TestSyncReturnsOnlyTheCallersPersonalItems(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	mine := enrolledUserID(t, st, "mine@example.com")
	theirs := enrolledUserID(t, st, "theirs@example.com")

	own, err := st.CreateItem(ctx, mine, ItemInput{Ciphertext: "mine", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	if _, err := st.CreateItem(ctx, theirs, ItemInput{Ciphertext: "theirs", WrappedItemKey: "k"}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	result, err := st.SyncSince(ctx, mine, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("got %d items, want exactly 1 — another user's vault is visible", len(result.Items))
	}
	if result.Items[0].ID != own.ID {
		t.Errorf("returned item %q, want %q", result.Items[0].ID, own.ID)
	}
}

func TestSyncReturnsItemsInCollectionsTheCallerBelongsTo(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	owner := enrolledUserID(t, st, "owner@example.com")
	member := enrolledUserID(t, st, "member@example.com")
	outsider := enrolledUserID(t, st, "outsider@example.com")

	collectionID := seedCollectionWithMembers(t, st, owner, owner, member)
	shared, err := st.CreateItem(ctx, owner, ItemInput{
		CollectionID: &collectionID, Ciphertext: "shared", WrappedItemKey: "k",
	})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	// A member sees it even though they did not create it: spec section 5.1,
	// owner_user_id records who made the item and confers no exclusive rights.
	memberView, err := st.SyncSince(ctx, member, 0)
	if err != nil {
		t.Fatalf("SyncSince(member): %v", err)
	}
	if len(memberView.Items) != 1 || memberView.Items[0].ID != shared.ID {
		t.Fatalf("member got %d items, want the shared one", len(memberView.Items))
	}

	// Membership is the whole access rule. Someone outside the collection must
	// see nothing, not even that the row exists.
	outsiderView, err := st.SyncSince(ctx, outsider, 0)
	if err != nil {
		t.Fatalf("SyncSince(outsider): %v", err)
	}
	if len(outsiderView.Items) != 0 {
		t.Errorf("a non-member received %d shared items, want 0", len(outsiderView.Items))
	}
}

func TestSyncIsIncrementalFromTheReturnedCursor(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	if _, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "first", WrappedItemKey: "k"}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	first, err := st.SyncSince(ctx, userID, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(first.Items) != 1 {
		t.Fatalf("first sync returned %d items, want 1", len(first.Items))
	}

	// Nothing changed, so the same cursor must return nothing. A sync that
	// re-sends the whole vault on every poll is the failure this cursor exists
	// to prevent.
	second, err := st.SyncSince(ctx, userID, first.Revision)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(second.Items) != 0 {
		t.Errorf("an unchanged vault returned %d items, want 0", len(second.Items))
	}
	if second.Revision != first.Revision {
		t.Errorf("cursor moved on an unchanged vault: %d -> %d", first.Revision, second.Revision)
	}

	if _, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "second", WrappedItemKey: "k"}); err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	third, err := st.SyncSince(ctx, userID, first.Revision)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(third.Items) != 1 || third.Items[0].Ciphertext != "second" {
		t.Errorf("incremental sync returned %d items, want just the new one", len(third.Items))
	}
}

func TestSyncCarriesTombstonesSoDeletesPropagate(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateItem(ctx, userID, ItemInput{Ciphertext: "c", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	afterCreate, err := st.SyncSince(ctx, userID, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if _, err := st.DeleteItem(ctx, created.ID); err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}

	// Omitting tombstones leaves the item on every other device forever, with
	// no event that ever removes it.
	result, err := st.SyncSince(ctx, userID, afterCreate.Revision)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("got %d items after a delete, want the tombstone", len(result.Items))
	}
	if !result.Items[0].DeletedAt.Valid {
		t.Error("the returned row is not marked deleted")
	}
	if result.Items[0].Ciphertext != "" {
		t.Error("a tombstone still carries ciphertext")
	}
}

func TestSyncReturnsFoldersOnTheSameCursor(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	mine := enrolledUserID(t, st, "mine@example.com")
	theirs := enrolledUserID(t, st, "theirs@example.com")

	if _, err := st.CreateFolder(ctx, mine, "mine"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	if _, err := st.CreateFolder(ctx, theirs, "theirs"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	result, err := st.SyncSince(ctx, mine, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(result.Folders) != 1 {
		t.Fatalf("got %d folders, want 1 — folders are personal and another "+
			"user's are visible", len(result.Folders))
	}
	if result.Folders[0].EncryptedName != "mine" {
		t.Errorf("returned the wrong user's folder: %q", result.Folders[0].EncryptedName)
	}

	// Folders must ride the same cursor items do, not just the same result
	// struct. Nothing changed, so this poll must return no folders; a folder
	// query that ignores the cursor re-downloads every folder the user ever
	// created on every poll, forever.
	unchanged, err := st.SyncSince(ctx, mine, result.Revision)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(unchanged.Folders) != 0 {
		t.Errorf("an unchanged vault re-sent %d folders, want 0", len(unchanged.Folders))
	}

	// One new folder, and only that one comes back.
	fresh, err := st.CreateFolder(ctx, mine, "fresh")
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	incremental, err := st.SyncSince(ctx, mine, result.Revision)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(incremental.Folders) != 1 {
		t.Fatalf("incremental sync returned %d folders, want just the new one", len(incremental.Folders))
	}
	if incremental.Folders[0].ID != fresh.ID {
		t.Errorf("incremental sync returned folder %q, want the new one %q",
			incremental.Folders[0].ID, fresh.ID)
	}
	// The folder's revision comes from the shared item/folder sequence, so it
	// must sit strictly beyond the cursor that did not include it.
	if incremental.Folders[0].Revision <= result.Revision {
		t.Errorf("new folder revision %d is not past the previous cursor %d",
			incremental.Folders[0].Revision, result.Revision)
	}
}

func TestSyncCarriesFolderTombstonesSoFolderDeletesPropagate(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	created, err := st.CreateFolder(ctx, userID, "encrypted-name")
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	afterCreate, err := st.SyncSince(ctx, userID, 0)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(afterCreate.Folders) != 1 {
		t.Fatalf("got %d folders before the delete, want 1", len(afterCreate.Folders))
	}
	if _, err := st.DeleteFolder(ctx, created.ID); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}

	// Filtering tombstoned folders out of the sync query leaves the folder on
	// every other device permanently: there is no later event that removes it.
	result, err := st.SyncSince(ctx, userID, afterCreate.Revision)
	if err != nil {
		t.Fatalf("SyncSince: %v", err)
	}
	if len(result.Folders) != 1 {
		t.Fatalf("got %d folders after a delete, want the tombstone", len(result.Folders))
	}
	if result.Folders[0].ID != created.ID {
		t.Fatalf("returned folder %q, want the deleted one %q", result.Folders[0].ID, created.ID)
	}
	if !result.Folders[0].DeletedAt.Valid {
		t.Error("the returned folder row is not marked deleted")
	}
	if result.Folders[0].EncryptedName != "" {
		t.Error("a folder tombstone still carries an encrypted name")
	}
}

// TestSyncNeverReportsACursorAheadOfItsRows asserts the invariant SyncSince's
// single transaction exists to hold: every stored row whose revision is at or
// below the reported cursor was in the returned set.
//
// Checking only that no RETURNED row exceeds the cursor is the inverse of the
// danger and cannot fail — the rows that matter are precisely the ones NOT
// returned. And with no concurrent writer there is no window to catch: reading
// the sequence after tx.Commit() (exactly the bug the doc comment on SyncSince
// warns about) is indistinguishable from reading it inside the transaction on a
// quiet database. So this runs a writer alongside the reads and audits the gap.
//
// The loop polls incrementally from the previous cursor, the way a real client
// does. That is not only more faithful, it keeps each poll constant-cost: an
// earlier version re-synced from 0 every time, so the result set grew with the
// writer and the test went quadratic — harmless in a plain build where the
// writer is starved, but it blew the 10-minute test timeout under -race.
//
// Sizing: detection is per WRITE, not per poll — a poll can only lose a row if
// a commit lands in its gap. Measured against a build with the sequence read
// moved after tx.Commit(), about half of all writes were lost. So the writer
// commits a fixed number of rows and the reader polls until it finishes, rather
// than the reader running a fixed count and the writer getting however many
// commits the machine's disk allows: an earlier version of this test left the
// write count to chance and landed on only ~12 per run, which makes a run's
// verdict depend on throughput. At 100 writes, a mutation surviving is 0.5^100
// on the measured rate and still under 1% even if a slower machine dropped the
// per-write rate to 5%. Costs ~0.55s plain (around 9000 polls overlap those 100
// writes), a few seconds under -race.
func TestSyncNeverReportsACursorAheadOfItsRows(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "owner@example.com")

	const writes = 100

	type observation struct {
		since    int64
		cursor   int64
		returned int
	}
	var observed []observation
	// Every item id the polling client ever received. A row missing from here at
	// the end is a row that client will never be told about again.
	delivered := make(map[string]bool)

	// A writer racing the reads. Its only job is to commit rows in whatever gap
	// exists between the row read and the cursor read.
	done := make(chan struct{})
	var writerErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		for i := 0; i < writes; i++ {
			if _, err := st.CreateItem(ctx, userID,
				ItemInput{Ciphertext: "c", WrappedItemKey: "k"}); err != nil {
				writerErr = err
				return
			}
		}
	}()

	since := int64(0)
	polling := true
	for polling {
		select {
		case <-done:
			// One last poll after the writer has stopped, so the client's final
			// cursor accounts for every row that was committed.
			polling = false
		default:
		}
		result, err := st.SyncSince(ctx, userID, since)
		if err != nil {
			wg.Wait()
			t.Fatalf("SyncSince: %v", err)
		}
		for _, item := range result.Items {
			delivered[item.ID] = true
		}
		observed = append(observed, observation{
			since: since, cursor: result.Revision, returned: len(result.Items)})
		since = result.Revision
	}
	wg.Wait()
	if writerErr != nil {
		t.Fatalf("concurrent writer: %v", writerErr)
	}
	finalCursor := since

	// If the reader never got a turn there was no race to observe and a pass
	// here would mean nothing.
	if len(observed) < 20 {
		t.Fatalf("only %d polls overlapped %d writes; too little interleaving for this "+
			"test to have exercised the cursor/rows window", len(observed), writes)
	}
	t.Logf("%d polls against %d concurrent writes", len(observed), writes)

	// Audited after the writer has stopped, but every count is bounded by its own
	// sample's cursor, so later commits cannot perturb an earlier answer.
	bad := 0
	for i, o := range observed {
		var stored int
		if err := st.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM items WHERE revision > ? AND revision <= ? AND owner_user_id = ?`,
			o.since, o.cursor, userID).Scan(&stored); err != nil {
			t.Fatalf("count stored rows: %v", err)
		}
		if stored == o.returned {
			continue
		}
		bad++
		if bad <= 3 {
			t.Errorf("sample %d: cursor advanced %d -> %d, a range holding %d stored rows, "+
				"but SyncSince returned %d; %d row(s) fall past the stored cursor and are "+
				"never sent again", i, o.since, o.cursor, stored, o.returned, stored-o.returned)
		}
	}
	if bad > 0 {
		t.Errorf("%d of %d polls reported a cursor ahead of the rows returned; the cursor "+
			"and the rows are not coming from one snapshot", bad, len(observed))
	}

	// The same failure stated as the client sees it, and the reason it matters:
	// after all that polling, is anything at or below the held cursor missing?
	rows, err := st.DB().QueryContext(ctx,
		`SELECT id FROM items WHERE revision <= ? AND owner_user_id = ? ORDER BY revision`,
		finalCursor, userID)
	if err != nil {
		t.Fatalf("list stored rows: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var missing []string
	total := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan id: %v", err)
		}
		total++
		if !delivered[id] {
			missing = append(missing, id)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate stored rows: %v", err)
	}
	if total == 0 {
		t.Fatal("the concurrent writer committed nothing; this test proved nothing")
	}
	if len(missing) > 0 {
		shown := missing
		if len(shown) > 3 {
			shown = shown[:3]
		}
		t.Errorf("%d of %d rows at or below the client's final cursor %d were never "+
			"delivered by any poll and never will be: %v",
			len(missing), total, finalCursor, shown)
	}
}

func TestCanAccessItemFollowsOwnershipAndMembership(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	owner := enrolledUserID(t, st, "owner@example.com")
	member := enrolledUserID(t, st, "member@example.com")
	outsider := enrolledUserID(t, st, "outsider@example.com")

	personal, err := st.CreateItem(ctx, owner, ItemInput{Ciphertext: "c", WrappedItemKey: "k"})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	collectionID := seedCollectionWithMembers(t, st, owner, owner, member)
	shared, err := st.CreateItem(ctx, owner, ItemInput{
		CollectionID: &collectionID, Ciphertext: "c", WrappedItemKey: "k",
	})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	cases := []struct {
		name   string
		userID string
		item   Item
		want   bool
	}{
		{"owner reads their personal item", owner, personal, true},
		{"outsider cannot read a personal item", outsider, personal, false},
		{"member reads a shared item they did not create", member, shared, true},
		{"outsider cannot read a shared item", outsider, shared, false},
		{"owner reads a shared item they created", owner, shared, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := st.CanAccessItem(ctx, tc.userID, tc.item)
			if err != nil {
				t.Fatalf("CanAccessItem: %v", err)
			}
			if got != tc.want {
				t.Errorf("CanAccessItem = %v, want %v", got, tc.want)
			}
		})
	}
}
