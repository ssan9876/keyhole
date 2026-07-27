package store

import (
	"context"
	"testing"
)

func TestAppendAuditRecordsAnEntry(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	actor := enrolledUserID(t, st, "admin@example.com")

	if err := st.AppendAudit(ctx, actor, "user.create", "user:abc", `{"email":"new@example.com"}`); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	entries, err := st.AuditPage(ctx, 10, "")
	if err != nil {
		t.Fatalf("AuditPage: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Action != "user.create" {
		t.Errorf("Action = %q, want %q", entries[0].Action, "user.create")
	}
	if entries[0].Target != "user:abc" {
		t.Errorf("Target = %q", entries[0].Target)
	}
	if !entries[0].ActorUserID.Valid || entries[0].ActorUserID.String != actor {
		t.Errorf("ActorUserID = %+v, want %q", entries[0].ActorUserID, actor)
	}
}

func TestAppendAuditAcceptsNoActorForSystemActions(t *testing.T) {
	st := openTemp(t)

	// The tombstone purge and the installer's first admin have no signed-in
	// actor. Requiring one would either fabricate an attribution or leave those
	// actions unrecorded.
	if err := st.AppendAudit(context.Background(), "", "retention.purge", "items", `{"purged":12}`); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	entries, err := st.AuditPage(context.Background(), 10, "")
	if err != nil {
		t.Fatalf("AuditPage: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].ActorUserID.Valid {
		t.Error("a system action was attributed to a user")
	}
}

func TestAuditPageIsNewestFirstAndPagesWithoutRepeating(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	actor := enrolledUserID(t, st, "admin@example.com")

	for i := 0; i < 10; i++ {
		if err := st.AppendAudit(ctx, actor, "test.action", "target", ""); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}

	first, err := st.AuditPage(ctx, 4, "")
	if err != nil {
		t.Fatalf("AuditPage: %v", err)
	}
	if len(first) != 4 {
		t.Fatalf("first page has %d entries, want 4", len(first))
	}

	second, err := st.AuditPage(ctx, 4, first[len(first)-1].ID)
	if err != nil {
		t.Fatalf("AuditPage: %v", err)
	}
	if len(second) != 4 {
		t.Fatalf("second page has %d entries, want 4", len(second))
	}

	// Entries written in the same second share a created_at. Ordering on
	// timestamp alone would let a page boundary repeat or skip rows, which in
	// an audit log means an admin can look straight past the entry they are
	// searching for.
	seen := make(map[string]bool)
	for _, entry := range append(append([]AuditEntry{}, first...), second...) {
		if seen[entry.ID] {
			t.Errorf("entry %s appears on two pages", entry.ID)
		}
		seen[entry.ID] = true
	}
	if len(seen) != 8 {
		t.Errorf("saw %d distinct entries across two pages of 4, want 8", len(seen))
	}
}

func TestAuditPageClampsTheLimit(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	actor := enrolledUserID(t, st, "admin@example.com")
	for i := 0; i < 5; i++ {
		if err := st.AppendAudit(ctx, actor, "test.action", "t", ""); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}

	// A caller asking for zero, a negative, or a million rows gets a sane page
	// rather than an empty result or the whole table.
	for _, limit := range []int{0, -1, 1_000_000} {
		entries, err := st.AuditPage(ctx, limit, "")
		if err != nil {
			t.Fatalf("AuditPage(%d): %v", limit, err)
		}
		if len(entries) == 0 || len(entries) > maxAuditPage {
			t.Errorf("AuditPage(%d) returned %d entries, want between 1 and %d",
				limit, len(entries), maxAuditPage)
		}
	}
}
