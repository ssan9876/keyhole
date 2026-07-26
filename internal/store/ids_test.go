package store

import (
	"regexp"
	"testing"
)

var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)

func TestNewIDShape(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	if !hex32.MatchString(id) {
		t.Errorf("NewID() = %q, want 32 lowercase hex characters", id)
	}
}

func TestNewIDDoesNotRepeat(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		id, err := NewID()
		if err != nil {
			t.Fatalf("NewID: %v", err)
		}
		if seen[id] {
			t.Fatalf("NewID returned a duplicate: %q", id)
		}
		seen[id] = true
	}
}

func TestNormalizeEmail(t *testing.T) {
	cases := map[string]string{
		"  Person@Example.COM ": "person@example.com",
		"person@example.com":    "person@example.com",
		"\tA@B.c\n":             "a@b.c",
	}
	for input, want := range cases {
		if got := NormalizeEmail(input); got != want {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestHashTokenIsStableAndHex(t *testing.T) {
	first := HashToken("some-token")
	second := HashToken("some-token")
	if first != second {
		t.Error("HashToken is not deterministic")
	}
	if len(first) != 64 {
		t.Errorf("HashToken length = %d, want 64", len(first))
	}
	if first == HashToken("some-other-token") {
		t.Error("HashToken collided on different inputs")
	}
	// The stored form must never be the token itself.
	if first == "some-token" {
		t.Error("HashToken returned its input")
	}
}
