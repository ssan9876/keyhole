package store

import (
	"context"
	"sync"
	"testing"
)

func TestCurrentRevisionStartsAtZero(t *testing.T) {
	st := openTemp(t)

	rev, err := st.CurrentRevision(context.Background())
	if err != nil {
		t.Fatalf("CurrentRevision: %v", err)
	}
	if rev != 0 {
		t.Errorf("CurrentRevision = %d, want 0 on a fresh database", rev)
	}
}

func TestNextRevisionNeverRepeatsUnderConcurrency(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()

	// The sequence is the sync cursor. A repeated value means two rows share a
	// revision, and a client that syncs at exactly that number silently never
	// sees one of them again — a lost item that no error ever reports.
	const writers = 8
	const perWriter = 25

	var mu sync.Mutex
	seen := make(map[int64]bool)

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				tx, err := st.db.BeginTx(ctx, nil)
				if err != nil {
					t.Errorf("BeginTx: %v", err)
					return
				}
				rev, err := nextRevision(ctx, tx)
				if err != nil {
					_ = tx.Rollback()
					t.Errorf("nextRevision: %v", err)
					return
				}
				if err := tx.Commit(); err != nil {
					t.Errorf("Commit: %v", err)
					return
				}
				mu.Lock()
				if seen[rev] {
					t.Errorf("revision %d was handed out twice", rev)
				}
				seen[rev] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(seen) != writers*perWriter {
		t.Errorf("got %d distinct revisions, want %d", len(seen), writers*perWriter)
	}
	final, err := st.CurrentRevision(ctx)
	if err != nil {
		t.Fatalf("CurrentRevision: %v", err)
	}
	if final != int64(writers*perWriter) {
		t.Errorf("CurrentRevision = %d, want %d", final, writers*perWriter)
	}
}

func TestARolledBackTransactionDoesNotConsumeARevision(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()

	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if _, err := nextRevision(ctx, tx); err != nil {
		t.Fatalf("nextRevision: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	// A failed write must not leave a gap the client interprets as a change it
	// missed, and must not burn a number nothing will ever be stored under.
	rev, err := st.CurrentRevision(ctx)
	if err != nil {
		t.Fatalf("CurrentRevision: %v", err)
	}
	if rev != 0 {
		t.Errorf("CurrentRevision = %d after rollback, want 0", rev)
	}
}
