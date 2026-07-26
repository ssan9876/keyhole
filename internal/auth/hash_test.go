package auth

import (
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const sampleAuthHash = "eXQ1Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg=="

func TestHashAuthHashShape(t *testing.T) {
	encoded, err := HashAuthHash(sampleAuthHash)
	if err != nil {
		t.Fatalf("HashAuthHash: %v", err)
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 {
		t.Fatalf("encoded = %q, want three $-separated parts", encoded)
	}
	if parts[0] != "argon2id" {
		t.Errorf("algorithm = %q, want %q", parts[0], "argon2id")
	}
	// The client's auth hash must not be recoverable from what we store.
	if strings.Contains(encoded, sampleAuthHash) {
		t.Error("the encoded form contains the auth hash verbatim")
	}
}

func TestHashAuthHashUsesAFreshSaltEveryTime(t *testing.T) {
	first, err := HashAuthHash(sampleAuthHash)
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashAuthHash(sampleAuthHash)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Error("two hashes of the same input are identical; the salt is not random")
	}
}

func TestVerifyAuthHashAcceptsTheOriginal(t *testing.T) {
	encoded, err := HashAuthHash(sampleAuthHash)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyAuthHash(sampleAuthHash, encoded) {
		t.Error("VerifyAuthHash rejected the value it just hashed")
	}
}

func TestVerifyAuthHashRejectsAnythingElse(t *testing.T) {
	encoded, err := HashAuthHash(sampleAuthHash)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string]string{
		"different value": "not-the-auth-hash",
		"empty":           "",
		"prefix":          sampleAuthHash[:len(sampleAuthHash)-1],
	} {
		t.Run(name, func(t *testing.T) {
			if VerifyAuthHash(candidate, encoded) {
				t.Error("VerifyAuthHash accepted a value it should not have")
			}
		})
	}
}

// runConcurrently fires `workers` copies of call at once and returns the
// highest number of Argon2id computations it ever observed running together.
//
// Occupancy is read from the semaphore itself: a slot is held for exactly the
// duration of one argon2.IDKey call, so len(argon2Semaphore) *is* the in-flight
// count. Sampling can only ever under-report a peak, never invent one, so a
// bound derived from it is safe in the direction the assertions rely on.
func runConcurrently(workers int, call func()) int {
	var peak atomic.Int64

	stop := make(chan struct{})
	var sampler sync.WaitGroup
	sampler.Add(1)
	go func() {
		defer sampler.Done()
		for {
			if n := int64(len(argon2Semaphore)); n > peak.Load() {
				peak.Store(n)
			}
			select {
			case <-stop:
				return
			default:
			}
			time.Sleep(50 * time.Microsecond)
		}
	}()

	start := make(chan struct{})
	var running sync.WaitGroup
	for i := 0; i < workers; i++ {
		running.Add(1)
		go func() {
			defer running.Done()
			<-start
			call()
		}()
	}
	close(start)
	running.Wait()

	close(stop)
	sampler.Wait()
	return int(peak.Load())
}

// TestArgon2idConcurrencyIsBoundedByNumCPU proves the semaphore actually gates
// both Argon2id entry points and that no more than runtime.NumCPU() of them run
// at once, however many callers pile in. Each computation holds 64 MiB, so
// without the bound a few hundred simultaneous unauthenticated requests are
// enough to exhaust memory on the machine the vault lives on.
func TestArgon2idConcurrencyIsBoundedByNumCPU(t *testing.T) {
	limit := runtime.NumCPU()
	if got := cap(argon2Semaphore); got != limit {
		t.Fatalf("cap(argon2Semaphore) = %d, want runtime.NumCPU() = %d", got, limit)
	}

	encoded, err := HashAuthHash(sampleAuthHash)
	if err != nil {
		t.Fatal(err)
	}

	// Four times as many callers as there are slots, so if the semaphore were
	// absent from the function under test the observed peak would run well past
	// the limit rather than plateauing at it.
	workers := limit * 4

	for _, tc := range []struct {
		name string
		call func()
	}{
		{"VerifyAuthHash", func() { VerifyAuthHash(sampleAuthHash, encoded) }},
		{"HashAuthHash", func() { _, _ = HashAuthHash(sampleAuthHash) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peak := runConcurrently(workers, tc.call)
			t.Logf("observed peak of simultaneous Argon2id computations: %d (runtime.NumCPU() = %d, %d concurrent callers)",
				peak, limit, workers)

			if peak > limit {
				t.Errorf("peak concurrency = %d, want at most runtime.NumCPU() = %d", peak, limit)
			}
			// A peak of zero means this function never took a semaphore slot at
			// all — it is hashing outside the bound, which is the whole defect.
			if peak == 0 {
				t.Errorf("peak concurrency = 0 with %d concurrent callers; %s is not going through the semaphore",
					workers, tc.name)
			}
			// And the harness must genuinely have caught overlapping work, or a
			// peak of 1 would "pass" for entirely the wrong reason.
			if limit > 1 && peak < 2 {
				t.Errorf("peak concurrency = %d on a %d-CPU machine; no overlap was observed, so this proves nothing",
					peak, limit)
			}
			if held := len(argon2Semaphore); held != 0 {
				t.Errorf("%d semaphore slots still held after every call returned; a slot is leaking", held)
			}
		})
	}
}

func TestVerifyAuthHashRejectsMalformedStoredValues(t *testing.T) {
	// A corrupted or empty column must fail closed, never panic and never
	// accidentally accept.
	for name, encoded := range map[string]string{
		"empty":             "",
		"no separators":     "argon2id",
		"wrong algorithm":   "bcrypt$c2FsdA==$aGFzaA==",
		"bad base64 salt":   "argon2id$!!!$aGFzaA==",
		"bad base64 digest": "argon2id$c2FsdA==$!!!",
		"too many parts":    "argon2id$a$b$c",
	} {
		t.Run(name, func(t *testing.T) {
			if VerifyAuthHash(sampleAuthHash, encoded) {
				t.Errorf("VerifyAuthHash accepted a malformed stored value %q", encoded)
			}
		})
	}
}
