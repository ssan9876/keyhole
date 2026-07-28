package release

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"
	_ "modernc.org/sqlite" // pure-Go driver, registered as "sqlite"

	"github.com/ssan9876/keyhole/internal/store"
)

const testAsset = "keyhole-test-amd64"

// fakeSource is a Source with no network: Latest and Download both read from
// data set up by the test, and Download records every URL it was asked for
// so a test can assert what was, or was not, fetched.
type fakeSource struct {
	release   Release
	latestErr error

	assets      map[string][]byte
	downloadErr map[string]error
	downloaded  []string
}

func (f *fakeSource) Latest(ctx context.Context) (Release, error) {
	return f.release, f.latestErr
}

func (f *fakeSource) Download(ctx context.Context, url string) ([]byte, error) {
	f.downloaded = append(f.downloaded, url)
	if err, ok := f.downloadErr[url]; ok {
		return nil, err
	}
	data, ok := f.assets[url]
	if !ok {
		return nil, fmt.Errorf("fakeSource: no asset registered for %s", url)
	}
	return data, nil
}

// fakeService is a Service with no systemd: it counts calls and can be told
// to fail either call.
type fakeService struct {
	stopCalls, startCalls int
	stopErr, startErr     error
}

func (f *fakeService) Stop(ctx context.Context) error {
	f.stopCalls++
	return f.stopErr
}

func (f *fakeService) Start(ctx context.Context) error {
	f.startCalls++
	return f.startErr
}

// fakeHealth is a Health with no HTTP polling: the Nth call to Wait reports
// errs[N-1], and any call past the end of the sequence reports healthy.
//
// The sequence, rather than one fixed error, is the point. A single Update
// polls health twice on the rollback path -- once for the new binary, once
// for the restored one -- and those two answers are entirely different
// questions: "did the upgrade work" and "is the vault back." A fake that
// answered both the same way could not tell a rollback that restored a
// working service from one that left the vault down.
//
// before, if set, runs once at the first poll, so a test can inject a side
// effect (e.g. removing the previous binary) at the exact moment the real
// code would be polling.
type fakeHealth struct {
	errs    []error
	before  func()
	waitedN int
}

func (f *fakeHealth) Wait(ctx context.Context, timeout time.Duration) error {
	f.waitedN++
	if f.waitedN == 1 && f.before != nil {
		f.before()
	}
	if f.waitedN <= len(f.errs) {
		return f.errs[f.waitedN-1]
	}
	return nil
}

// signedRelease builds a Release plus a fakeSource whose SHA256SUMS is
// genuinely minisign-signed over the given binary, so Verify inside Update
// passes for any test that does not deliberately break something.
func signedRelease(t *testing.T, version string, binary []byte) (Release, *fakeSource, string) {
	t.Helper()
	priv, pubText := genMinisignKeypair(t)

	checksums := sumLine(testAsset, binary)
	signature := minisign.Sign(priv, []byte(checksums))

	binURL := "https://example.test/download/" + version + "/" + testAsset
	sumsURL := "https://example.test/download/" + version + "/SHA256SUMS"
	sigURL := "https://example.test/download/" + version + "/SHA256SUMS.minisig"

	rel := Release{
		Version: version,
		Assets: map[string]string{
			testAsset:      binURL,
			checksumsAsset: sumsURL,
			signatureAsset: sigURL,
		},
	}
	src := &fakeSource{
		release: rel,
		assets: map[string][]byte{
			binURL:  binary,
			sumsURL: []byte(checksums),
			sigURL:  signature,
		},
	}
	return rel, src, pubText
}

// testDB creates a migrated database at path with one pending user, mirroring
// what a real install has before an update: something with a value that a
// migration could plausibly change, and that a restored snapshot should show
// unchanged.
func testDB(t *testing.T, path string) (userEmail string) {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := st.CreatePendingUser(context.Background(), "before@example.com", "Before Update", "user"); err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	return "before@example.com"
}

// userStatus opens its own short-lived connection to path and reads status
// for email, so it never holds a handle open across the Update call under
// test (a lingering handle changes rename semantics on Windows, exactly the
// same concern internal/backup's own tests call out).
func userStatus(t *testing.T, path, email string) string {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	u, err := st.UserByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("UserByEmail(%s): %v", email, err)
	}
	return u.Status
}

// migrateMutatesExistingRow returns a Deps.Migrate that changes the status
// of an existing row rather than merely adding a new one. That distinction
// is the point: adding a row would leave the original row looking identical
// whether or not a rollback restored the snapshot, which would let a test
// that only checks "the original row is still there" pass even with the
// database half of rollback deleted entirely.
func migrateMutatesExistingRow(dbPath, email string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			return fmt.Errorf("open %s for migration: %w", dbPath, err)
		}
		defer db.Close()
		res, err := db.ExecContext(ctx, `UPDATE users SET status = 'active' WHERE email = ?`, email)
		if err != nil {
			return fmt.Errorf("update user status: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("expected to update 1 row, updated %d", n)
		}
		return nil
	}
}

// testHarness bundles the on-disk state one Update call needs: an old
// binary at BinaryPath, a migrated database with one user, and a backup
// directory. Each field is a real file under t.TempDir(), never a fake --
// only Source, Service, and Health are faked.
type testHarness struct {
	dir        string
	binaryPath string
	prevPath   string
	dbPath     string
	backupDir  string
	oldBinary  []byte
	userEmail  string
}

func newTestHarness(t *testing.T) testHarness {
	t.Helper()
	dir := t.TempDir()
	h := testHarness{
		dir:        dir,
		binaryPath: filepath.Join(dir, "keyhole"),
		prevPath:   filepath.Join(dir, "keyhole.prev"),
		dbPath:     filepath.Join(dir, "keyhole.db"),
		backupDir:  filepath.Join(dir, "backups"),
		oldBinary:  []byte("old keyhole binary contents, pre-update"),
	}
	if err := os.WriteFile(h.binaryPath, h.oldBinary, 0o755); err != nil {
		t.Fatalf("write old binary: %v", err)
	}
	h.userEmail = testDB(t, h.dbPath)
	return h
}

func (h testHarness) deps(src Source, svc Service, health Health) Deps {
	return Deps{
		Source:       src,
		Service:      svc,
		Health:       health,
		BinaryPath:   h.binaryPath,
		PreviousPath: h.prevPath,
		DBPath:       h.dbPath,
		BackupDir:    h.backupDir,
		Migrate:      migrateMutatesExistingRow(h.dbPath, h.userEmail),
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func TestUpdateInstallsTheNewBinaryAndStartsTheService(t *testing.T) {
	h := newTestHarness(t)
	newBinary := []byte("new keyhole binary contents, post-update")
	_, src, pubKey := signedRelease(t, "v2.0.0", newBinary)

	svc := &fakeService{}
	health := &fakeHealth{}
	deps := h.deps(src, svc, health)

	outcome, err := Update(context.Background(), deps, Options{
		CurrentVersion: "v1.0.0",
		PublicKey:      pubKey,
		AssetName:      testAsset,
	})
	if err != nil {
		t.Fatalf("Update() error = %v, want nil", err)
	}
	if !outcome.Installed {
		t.Errorf("Outcome.Installed = false, want true: %+v", outcome)
	}
	if outcome.RolledBack {
		t.Errorf("Outcome.RolledBack = true, want false: %+v", outcome)
	}
	if outcome.ToVersion != "v2.0.0" {
		t.Errorf("Outcome.ToVersion = %q, want v2.0.0", outcome.ToVersion)
	}

	if got := readFile(t, h.binaryPath); !bytes.Equal(got, newBinary) {
		t.Errorf("binary at %s = %q, want the new binary %q", h.binaryPath, got, newBinary)
	}
	if got := readFile(t, h.prevPath); !bytes.Equal(got, h.oldBinary) {
		t.Errorf("previous binary at %s = %q, want the old binary %q", h.prevPath, got, h.oldBinary)
	}
	if svc.stopCalls != 1 || svc.startCalls != 1 {
		t.Errorf("service Stop/Start calls = %d/%d, want 1/1", svc.stopCalls, svc.startCalls)
	}
	if status := userStatus(t, h.dbPath, h.userEmail); status != "active" {
		t.Errorf("user status after a successful update = %q, want active (the migration ran)", status)
	}
}

// TestUpdateRollsBackBinaryAndDatabaseWhenHealthNeverComesUp is design spec
// §10's named acceptance test: a fake Health that always fails, driving the
// updater with no network, no systemd, and no real binary.
func TestUpdateRollsBackBinaryAndDatabaseWhenHealthNeverComesUp(t *testing.T) {
	h := newTestHarness(t)
	brokenBinary := []byte("new keyhole binary contents that never answers healthz")
	_, src, pubKey := signedRelease(t, "v2.0.0", brokenBinary)

	svc := &fakeService{}
	// The new binary never answers; the restored one does. Two different
	// answers to two different questions -- "did the upgrade work" and "is
	// the vault back" -- and only the second makes this a clean rollback.
	health := &fakeHealth{errs: []error{errors.New("dial tcp: connection refused"), nil}}
	deps := h.deps(src, svc, health)

	outcome, err := Update(context.Background(), deps, Options{
		CurrentVersion: "v1.0.0",
		PublicKey:      pubKey,
		AssetName:      testAsset,
		HealthTimeout:  50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Update() error = %v, want nil (a rollback is a handled outcome, not a Go error)", err)
	}

	if !outcome.RolledBack {
		t.Fatalf("Outcome.RolledBack = false, want true: %+v", outcome)
	}
	if outcome.Reason == "" {
		t.Error("Outcome.Reason is empty, want an explanation of why the rollback happened")
	}
	if outcome.Installed {
		t.Errorf("Outcome.Installed = true, want false: %+v", outcome)
	}

	// The binary on disk must be byte-identical to the original: not just
	// "some file exists at the path," but proof the exact pre-update
	// bytes came back.
	if got := readFile(t, h.binaryPath); !bytes.Equal(got, h.oldBinary) {
		t.Errorf("binary at %s after rollback = %q, want the original %q", h.binaryPath, got, h.oldBinary)
	}

	// The database must show the row's pre-update value, not the value
	// the (irreversible) migration set it to. Reading only "the row still
	// exists" would pass even if the database half of rollback were never
	// implemented, since the migration mutates the row rather than adding
	// a new one -- this is what actually proves the snapshot was restored.
	if status := userStatus(t, h.dbPath, h.userEmail); status != "pending" {
		t.Errorf("user status after a rolled-back update = %q, want pending (the pre-update value); "+
			"got %q would mean the migration's change survived the rollback", status, status)
	}

	if svc.startCalls != 2 {
		t.Errorf("service Start calls = %d, want 2 (once to try the new binary, once after rollback)", svc.startCalls)
	}

	// Two health polls, not one. The second is what turns "systemctl start
	// returned 0" into "the vault is answering again": with a Type=simple
	// unit, start returns as soon as exec succeeds and says nothing about
	// whether the process bound its port, so a rollback that stops at Start
	// can report success over a dead vault. Reporting a rollback that did
	// not actually restore service is the failure this whole path exists to
	// prevent.
	if health.waitedN != 2 {
		t.Errorf("Health.Wait calls = %d, want 2 (once for the new binary, once to confirm the restored one is serving)", health.waitedN)
	}
}

// TestRollbackThatStartsTheServiceButNeverGetsItHealthyIsNotReportedAsClean
// is the other half of that assertion: when the *restored* binary starts but
// never answers, the operator must not be told the vault is back. The old
// binary can fail for reasons that have nothing to do with the update -- a
// full disk under the restored database, say -- and "rolled back to v1.0.0"
// reads as "my vault is back," which is when an operator stops looking.
func TestRollbackThatStartsTheServiceButNeverGetsItHealthyIsNotReportedAsClean(t *testing.T) {
	h := newTestHarness(t)
	brokenBinary := []byte("new keyhole binary contents that never answers healthz")
	_, src, pubKey := signedRelease(t, "v2.0.0", brokenBinary)

	// Both Start calls "succeed" -- that is the whole point. Nothing in the
	// Service interface reports a problem here; only health does.
	svc := &fakeService{}
	health := &fakeHealth{errs: []error{
		errors.New("new binary: connection refused"),
		errors.New("restored binary: no such file or directory"),
	}}
	deps := h.deps(src, svc, health)

	outcome, err := Update(context.Background(), deps, Options{
		CurrentVersion: "v1.0.0",
		PublicKey:      pubKey,
		AssetName:      testAsset,
		HealthTimeout:  50 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("Update() error = nil, want an error: the restored service never answered healthz, so the vault is still down")
	}
	if outcome.RolledBack {
		t.Errorf("Outcome.RolledBack = true, want false: a rollback that leaves the vault down is not a completed rollback: %+v", outcome)
	}
	if svc.startCalls != 2 {
		t.Errorf("service Start calls = %d, want 2", svc.startCalls)
	}
	if !strings.Contains(err.Error(), "restored binary") {
		t.Errorf("error %q does not name why the restored service is still not serving", err.Error())
	}
}

// TestUpdateTriesToRestartTheServiceWhenStoppingItFails covers the one early
// return that can leave the vault offline. `systemctl stop` can exit
// non-zero while the unit has in fact stopped -- a stop job that timed out
// and ended in SIGKILL, or a unit that ended in `failed` state -- so bailing
// out on a stop error without trying to start the service again leaves the
// vault down until a human notices. Whichever way the restart goes, the
// message has to say so: "the service may be down" and "it is back up" are
// different instructions to the person reading it.
func TestUpdateTriesToRestartTheServiceWhenStoppingItFails(t *testing.T) {
	stopErr := errors.New("job for keyhole.service failed: timed out, killed")

	run := func(t *testing.T, startErr error) (*fakeService, testHarness, error) {
		t.Helper()
		h := newTestHarness(t)
		_, src, pubKey := signedRelease(t, "v2.0.0", []byte("new keyhole binary contents"))

		svc := &fakeService{stopErr: stopErr, startErr: startErr}
		deps := h.deps(src, svc, &fakeHealth{})

		_, err := Update(context.Background(), deps, Options{
			CurrentVersion: "v1.0.0",
			PublicKey:      pubKey,
			AssetName:      testAsset,
			HealthTimeout:  50 * time.Millisecond,
		})
		if err == nil {
			t.Fatal("Update() error = nil, want an error: the service could not be stopped")
		}
		// The stop failed before anything was swapped, so there must be
		// nothing on disk to undo -- which is also why this path must not
		// call rollback.
		if got := readFile(t, h.binaryPath); !bytes.Equal(got, h.oldBinary) {
			t.Errorf("binary at %s = %q, want it untouched at %q", h.binaryPath, got, h.oldBinary)
		}
		if _, statErr := os.Stat(h.prevPath); !os.IsNotExist(statErr) {
			t.Errorf("prev path %s exists, want it never created", h.prevPath)
		}
		return svc, h, err
	}

	t.Run("the restart works", func(t *testing.T) {
		svc, _, err := run(t, nil)
		if svc.startCalls != 1 {
			t.Fatalf("service Start calls = %d, want 1: a stop that failed may have left the vault down, so Update must try to bring it back", svc.startCalls)
		}
		msg := err.Error()
		if !strings.Contains(msg, "timed out, killed") {
			t.Errorf("error %q does not name why stopping the service failed", msg)
		}
		if !strings.Contains(msg, "restarting it succeeded") {
			t.Errorf("error %q does not tell the operator the service is back up", msg)
		}
	})

	t.Run("the restart also fails", func(t *testing.T) {
		svc, _, err := run(t, errors.New("unit keyhole.service is masked"))
		if svc.startCalls != 1 {
			t.Fatalf("service Start calls = %d, want 1", svc.startCalls)
		}
		msg := err.Error()
		if !strings.Contains(msg, "also failed") || !strings.Contains(msg, "masked") {
			t.Errorf("error %q does not say the restart attempt failed, or why -- which is the operator's cue that the vault is still down", msg)
		}
	})
}

func TestUpdateDoesNotStopTheServiceWhenVerificationFails(t *testing.T) {
	h := newTestHarness(t)
	newBinary := []byte("new keyhole binary contents")
	_, src, pubKey := signedRelease(t, "v2.0.0", newBinary)

	// Corrupt the downloaded binary in flight, without touching the
	// signed checksum list: the checksum step must catch this, and the
	// service must never go down for a download that was never going to
	// be installed.
	binURL := src.release.Assets[testAsset]
	src.assets[binURL] = []byte("corrupted in transit")

	svc := &fakeService{}
	health := &fakeHealth{}
	deps := h.deps(src, svc, health)

	_, err := Update(context.Background(), deps, Options{
		CurrentVersion: "v1.0.0",
		PublicKey:      pubKey,
		AssetName:      testAsset,
	})
	if err == nil {
		t.Fatal("Update() error = nil, want an error: the binary fails its checksum")
	}
	if svc.stopCalls != 0 {
		t.Errorf("service Stop calls = %d, want 0: verification failed before the service should ever be touched", svc.stopCalls)
	}
	if svc.startCalls != 0 {
		t.Errorf("service Start calls = %d, want 0", svc.startCalls)
	}
	if got := readFile(t, h.binaryPath); !bytes.Equal(got, h.oldBinary) {
		t.Errorf("binary at %s = %q, want it untouched at %q", h.binaryPath, got, h.oldBinary)
	}
	if _, err := os.Stat(h.prevPath); !os.IsNotExist(err) {
		t.Errorf("prev path %s exists, want it never created", h.prevPath)
	}
}

func TestUpdateWithCheckOnlyDownloadsNothingAndChangesNothing(t *testing.T) {
	h := newTestHarness(t)
	newBinary := []byte("new keyhole binary contents")
	_, src, pubKey := signedRelease(t, "v2.0.0", newBinary)

	svc := &fakeService{}
	health := &fakeHealth{}
	deps := h.deps(src, svc, health)

	outcome, err := Update(context.Background(), deps, Options{
		CurrentVersion: "v1.0.0",
		PublicKey:      pubKey,
		AssetName:      testAsset,
		CheckOnly:      true,
	})
	if err != nil {
		t.Fatalf("Update() error = %v, want nil", err)
	}
	if !outcome.Checked {
		t.Errorf("Outcome.Checked = false, want true: %+v", outcome)
	}
	if outcome.Installed || outcome.RolledBack || outcome.AlreadyCurrent {
		t.Errorf("Outcome has more than Checked set: %+v", outcome)
	}
	if len(src.downloaded) != 0 {
		t.Errorf("Source.Download called for %v, want no downloads at all in --check mode", src.downloaded)
	}
	if svc.stopCalls != 0 || svc.startCalls != 0 {
		t.Errorf("service touched during --check: stop=%d start=%d, want 0/0", svc.stopCalls, svc.startCalls)
	}
	if got := readFile(t, h.binaryPath); !bytes.Equal(got, h.oldBinary) {
		t.Errorf("binary at %s = %q, want it untouched", h.binaryPath, got)
	}
}

func TestUpdateReportsAlreadyCurrentWithoutTouchingTheService(t *testing.T) {
	h := newTestHarness(t)
	// The "latest" release is the same version already running.
	_, src, pubKey := signedRelease(t, "v1.0.0", []byte("does not matter, never downloaded"))

	svc := &fakeService{}
	health := &fakeHealth{}
	deps := h.deps(src, svc, health)

	outcome, err := Update(context.Background(), deps, Options{
		CurrentVersion: "v1.0.0",
		PublicKey:      pubKey,
		AssetName:      testAsset,
	})
	if err != nil {
		t.Fatalf("Update() error = %v, want nil", err)
	}
	if !outcome.AlreadyCurrent {
		t.Errorf("Outcome.AlreadyCurrent = false, want true: %+v", outcome)
	}
	if len(src.downloaded) != 0 {
		t.Errorf("Source.Download called for %v, want no downloads when already current", src.downloaded)
	}
	if svc.stopCalls != 0 || svc.startCalls != 0 {
		t.Errorf("service touched when already current: stop=%d start=%d, want 0/0", svc.stopCalls, svc.startCalls)
	}
}

// TestRollbackItselfFailingIsReportedRatherThanSwallowed covers the worst
// case: the new binary is bad (health never comes up) AND the previous
// binary is unreadable when rollback goes to restore it. The returned error
// must name both problems, not collapse them into one generic message --
// an operator in this state needs to know to restore from a snapshot by
// hand, and needs both failures spelled out to know why.
func TestRollbackItselfFailingIsReportedRatherThanSwallowed(t *testing.T) {
	h := newTestHarness(t)
	brokenBinary := []byte("new keyhole binary contents that never answers healthz")
	_, src, pubKey := signedRelease(t, "v2.0.0", brokenBinary)

	svc := &fakeService{}
	health := &fakeHealth{
		// The new binary never answers; the restored service does. That
		// isolates this test's failure to the one thing it is about -- the
		// previous binary being gone when rollback goes to move it back --
		// rather than letting a second health failure pad the message.
		errs: []error{errors.New("connection refused on :8477/healthz"), nil},
		// Simulate the previous binary becoming unavailable for rollback
		// -- e.g. the disk that held it went away -- at the moment the
		// real code would be polling health, just before Update decides
		// to roll back.
		before: func() {
			if err := os.Remove(h.prevPath); err != nil {
				t.Fatalf("remove %s to simulate an unreadable previous binary: %v", h.prevPath, err)
			}
		},
	}
	deps := h.deps(src, svc, health)

	_, err := Update(context.Background(), deps, Options{
		CurrentVersion: "v1.0.0",
		PublicKey:      pubKey,
		AssetName:      testAsset,
		HealthTimeout:  50 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("Update() error = nil, want a non-nil error: both the update and the rollback failed")
	}

	msg := err.Error()
	if !strings.Contains(msg, "healthz") && !strings.Contains(msg, "connection refused") {
		t.Errorf("error %q does not name why the update itself failed", msg)
	}
	if !strings.Contains(msg, h.prevPath) && !strings.Contains(msg, "previous binary") {
		t.Errorf("error %q does not name why the rollback failed", msg)
	}
}
