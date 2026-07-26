package auth

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestLimiterAllowsUpToTheThreshold(t *testing.T) {
	l := NewLimiter(5, time.Second, time.Minute)

	for i := 0; i < 5; i++ {
		if allowed, _ := l.Allow("ip:203.0.113.1"); !allowed {
			t.Fatalf("attempt %d was blocked; the first 5 must be allowed", i+1)
		}
		l.RecordFailure("ip:203.0.113.1")
	}
	if allowed, retryAfter := l.Allow("ip:203.0.113.1"); allowed {
		t.Error("the 6th attempt was allowed")
	} else if retryAfter <= 0 {
		t.Errorf("retryAfter = %v, want a positive duration", retryAfter)
	}
}

func TestLimiterBacksOffExponentially(t *testing.T) {
	l := NewLimiter(1, time.Second, time.Hour)

	var delays []time.Duration
	for i := 0; i < 4; i++ {
		l.RecordFailure("account:person@example.com")
		_, retryAfter := l.Allow("account:person@example.com")
		delays = append(delays, retryAfter)
	}

	// Assert the ratio, not merely that each delay is larger than the last.
	// Monotonic growth alone would be satisfied by a linear backoff, which
	// against a 64 MiB Argon2id is not nearly steep enough — the whole point is
	// that a sustained guessing attempt becomes hopeless within a few attempts,
	// not gradually inconvenient. The bound is 1.5x rather than exactly 2x so
	// the assertion survives the sub-millisecond jitter between the
	// RecordFailure and Allow calls.
	for i := 1; i < len(delays); i++ {
		ratio := float64(delays[i]) / float64(delays[i-1])
		if ratio < 1.5 {
			t.Errorf("delay %d (%v) is only %.2fx delay %d (%v); backoff is not exponential",
				i, delays[i], ratio, i-1, delays[i-1])
		}
	}
}

func TestLimiterRespectsTheCeiling(t *testing.T) {
	ceiling := 5 * time.Second
	l := NewLimiter(1, time.Second, ceiling)

	for i := 0; i < 30; i++ {
		l.RecordFailure("account:person@example.com")
	}
	_, retryAfter := l.Allow("account:person@example.com")
	if retryAfter > ceiling {
		t.Errorf("retryAfter = %v, want no more than the ceiling %v", retryAfter, ceiling)
	}
}

func TestLimiterKeysAreIndependent(t *testing.T) {
	l := NewLimiter(1, time.Minute, time.Hour)

	for i := 0; i < 10; i++ {
		l.RecordFailure("ip:203.0.113.1")
	}
	// One client hammering the endpoint must not lock everyone else out.
	if allowed, _ := l.Allow("ip:198.51.100.7"); !allowed {
		t.Error("a different key was blocked by an unrelated key's failures")
	}
}

func TestResetClearsAKey(t *testing.T) {
	l := NewLimiter(2, time.Minute, time.Hour)

	for i := 0; i < 5; i++ {
		l.RecordFailure("account:person@example.com")
	}
	if allowed, _ := l.Allow("account:person@example.com"); allowed {
		t.Fatal("expected the key to be blocked before reset")
	}

	// A successful login clears the record, so a user who mistypes twice and
	// then succeeds is not still throttled on their next sign-in.
	l.Reset("account:person@example.com")
	if allowed, _ := l.Allow("account:person@example.com"); !allowed {
		t.Error("the key is still blocked after Reset")
	}
}

func TestSweepDropsStaleEntries(t *testing.T) {
	l := NewLimiter(1, time.Millisecond, time.Second)

	for i := 0; i < 100; i++ {
		l.RecordFailure(fmt.Sprintf("ip:198.51.100.%d", i))
	}
	time.Sleep(10 * time.Millisecond)
	l.Sweep(5 * time.Millisecond)

	// Without a sweep, an attacker cycling source addresses grows the map
	// without bound until the process runs out of memory.
	if n := l.size(); n != 0 {
		t.Errorf("%d entries survived the sweep, want 0", n)
	}
}

func TestLimiterIsSafeUnderConcurrentUse(t *testing.T) {
	l := NewLimiter(1000, time.Millisecond, time.Second)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := fmt.Sprintf("ip:203.0.113.%d", n%5)
			for j := 0; j < 50; j++ {
				l.Allow(key)
				l.RecordFailure(key)
			}
		}(i)
	}
	wg.Wait()
	// The assertion is that -race reports nothing; reaching here is the pass.
}
