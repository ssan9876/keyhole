package auth

import (
	"math"
	"sync"
	"time"
)

// Limiter throttles repeated failures per key with exponential backoff.
//
// In memory, because Keyhole runs as a single process against a single SQLite
// file. State is lost on restart, which is an acceptable trade for zero
// dependencies: an attacker who could restart the server has already won.
type Limiter struct {
	mu       sync.Mutex
	entries  map[string]*entry
	maxFree  int
	baseWait time.Duration
	maxWait  time.Duration
}

type entry struct {
	failures  int
	lastSeen  time.Time
	blockedTo time.Time
}

// NewLimiter allows maxFree failures per key before any delay, then backs off
// from base, doubling each failure, capped at max.
func NewLimiter(maxFree int, base, max time.Duration) *Limiter {
	return &Limiter{
		entries:  make(map[string]*entry),
		maxFree:  maxFree,
		baseWait: base,
		maxWait:  max,
	}
}

// Allow reports whether an attempt may proceed, and how long to wait if not.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.entries[key]
	if !ok {
		return true, 0
	}
	now := time.Now()
	if now.Before(e.blockedTo) {
		return false, e.blockedTo.Sub(now)
	}
	return true, 0
}

// RecordFailure counts a failed attempt and extends the block.
func (l *Limiter) RecordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.entries[key]
	if !ok {
		e = &entry{}
		l.entries[key] = e
	}
	e.failures++
	e.lastSeen = time.Now()

	if e.failures < l.maxFree {
		return
	}

	// Exponent grows with each failure past the free allowance, so the
	// maxFree-th failure gets the base wait and every failure after that
	// doubles it. Using math.Pow on a float and clamping avoids the overflow
	// a plain 1<<n would hit, which would wrap around to a *shorter* wait the
	// longer an attacker keeps failing.
	exponent := float64(e.failures - l.maxFree)
	wait := time.Duration(float64(l.baseWait) * math.Pow(2, exponent))
	if wait > l.maxWait || wait <= 0 {
		wait = l.maxWait
	}
	e.blockedTo = e.lastSeen.Add(wait)
}

// Reset clears a key after a success, so an honest user who mistyped is not
// throttled on their next attempt.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// Sweep drops entries untouched for longer than olderThan. Without it, an
// attacker cycling source addresses grows the map without bound.
func (l *Limiter) Sweep(olderThan time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)
	for key, e := range l.entries {
		if e.lastSeen.Before(cutoff) {
			delete(l.entries, key)
		}
	}
}

// size is for tests only.
func (l *Limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}
