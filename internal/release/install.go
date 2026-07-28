package release

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ssan9876/keyhole/internal/backup"
	"github.com/ssan9876/keyhole/internal/store"
)

// Service starts and stops the process manager entry that runs the Keyhole
// server -- systemctl in production, a fake in tests.
type Service interface {
	Stop(ctx context.Context) error
	Start(ctx context.Context) error
}

// Health reports whether the running service is answering requests, waiting
// up to timeout before giving up.
type Health interface {
	Wait(ctx context.Context, timeout time.Duration) error
}

// Deps is everything Update touches outside this package. Every field is an
// interface, a func, or a plain path, so a test can supply fakes for all of
// it: no network, no systemd, no real binary.
type Deps struct {
	Source  Source
	Service Service
	Health  Health

	// BinaryPath is the running binary `keyhole update` replaces in place.
	// PreviousPath is where the binary being replaced is parked during the
	// swap (spec: "keyhole.prev"), so a rollback can move it straight back.
	// DBPath is the live database; BackupDir is where the pre-update
	// snapshot is written.
	BinaryPath, PreviousPath, DBPath, BackupDir string

	// Migrate runs pending database migrations using the *new* binary
	// (spec step 6). In production this execs BinaryPath with `migrate`;
	// in tests it is a closure with no process at all.
	Migrate func(ctx context.Context) error

	// Logf, if set, receives a line for each notable step -- in particular
	// the moment a rollback starts, since a silent rollback leaves an
	// operator believing they upgraded.
	Logf func(format string, args ...any)
}

func (d Deps) logf(format string, args ...any) {
	if d.Logf != nil {
		d.Logf(format, args...)
	}
}

// Options configures one call to Update.
type Options struct {
	// CurrentVersion is the compiled-in version of the binary running this
	// update (main.Version). Update compares it against the latest
	// release to decide whether there is anything to do.
	CurrentVersion string
	// PublicKey is the minisign public key release assets are signed
	// with.
	PublicKey string
	// CheckOnly stops after comparing versions: no download, no writes,
	// nothing touched. This is `keyhole update --check`.
	CheckOnly bool
	// HealthTimeout bounds how long Update waits for /healthz after
	// starting the new binary. Zero means DefaultHealthTimeout.
	HealthTimeout time.Duration
	// AssetName is the filename this platform's binary is published
	// under, e.g. "keyhole-linux-amd64". Empty means
	// keyhole-<GOOS>-<GOARCH>.
	AssetName string
}

// DefaultHealthTimeout is how long Update polls /healthz before deciding
// the new binary never came up, matching design spec §8.2 step 5.
const DefaultHealthTimeout = 30 * time.Second

const (
	checksumsAsset = "SHA256SUMS"
	signatureAsset = "SHA256SUMS.minisig"
)

func (o Options) assetName() string {
	if o.AssetName != "" {
		return o.AssetName
	}
	return fmt.Sprintf("keyhole-%s-%s", runtime.GOOS, runtime.GOARCH)
}

func (o Options) healthTimeout() time.Duration {
	if o.HealthTimeout > 0 {
		return o.HealthTimeout
	}
	return DefaultHealthTimeout
}

// Outcome reports what Update actually did, so the CLI can print something
// more useful than "it worked" or "it failed."
type Outcome struct {
	// FromVersion and ToVersion are the versions Update compared.
	FromVersion, ToVersion string
	// AlreadyCurrent is true when FromVersion == ToVersion: nothing was
	// downloaded, and the service was never touched.
	AlreadyCurrent bool
	// Checked is true for a --check run: Update stopped after comparing
	// versions.
	Checked bool
	// Installed is true when the new binary is running and answered
	// /healthz within the timeout.
	Installed bool
	// RolledBack is true when installation failed after the service was
	// stopped, and Update successfully restored the previous binary and
	// database. Reason explains what triggered it -- reporting a rollback
	// happened (and why) is the whole point; a silent one leaves an
	// operator believing they upgraded.
	RolledBack bool
	Reason     string
}

// Update runs the full check -> download -> verify -> install -> migrate ->
// health-check sequence from design spec §8.2, rolling back automatically
// if anything from the service stop onward fails.
func Update(ctx context.Context, deps Deps, opts Options) (Outcome, error) {
	release, err := deps.Source.Latest(ctx)
	if err != nil {
		return Outcome{}, fmt.Errorf("fetch latest release: %w", err)
	}

	outcome := Outcome{FromVersion: opts.CurrentVersion, ToVersion: release.Version}

	// Step 1: compare with the compiled-in version. Nothing has been
	// downloaded or touched yet either way.
	if release.Version == opts.CurrentVersion {
		outcome.AlreadyCurrent = true
		return outcome, nil
	}
	if opts.CheckOnly {
		outcome.Checked = true
		return outcome, nil
	}

	asset := opts.assetName()
	binaryURL, ok := release.Assets[asset]
	if !ok {
		return outcome, fmt.Errorf("release %s has no asset named %s for this platform", release.Version, asset)
	}
	checksumsURL, ok := release.Assets[checksumsAsset]
	if !ok {
		return outcome, fmt.Errorf("release %s has no %s asset", release.Version, checksumsAsset)
	}
	signatureURL, ok := release.Assets[signatureAsset]
	if !ok {
		return outcome, fmt.Errorf("release %s has no %s asset", release.Version, signatureAsset)
	}

	// Step 2: download binary, checksum list, and signature.
	binary, err := deps.Source.Download(ctx, binaryURL)
	if err != nil {
		return outcome, fmt.Errorf("download %s: %w", asset, err)
	}
	checksums, err := deps.Source.Download(ctx, checksumsURL)
	if err != nil {
		return outcome, fmt.Errorf("download %s: %w", checksumsAsset, err)
	}
	signature, err := deps.Source.Download(ctx, signatureURL)
	if err != nil {
		return outcome, fmt.Errorf("download %s: %w", signatureAsset, err)
	}

	// Step 3: verify both, before writing anything anywhere. The service
	// must never go down for a download that was never going to be
	// installed.
	if err := Verify(binary, string(checksums), signature, opts.PublicKey, asset); err != nil {
		return outcome, fmt.Errorf("verify %s: %w", asset, err)
	}

	// Step 4: snapshot the database. Migrations run against the new
	// binary in step 6 and are not reversible on their own -- this
	// snapshot is what a rollback restores.
	snapshotPath, err := backupSnapshot(ctx, deps)
	if err != nil {
		return outcome, fmt.Errorf("snapshot database: %w", err)
	}

	// Step 5 onward: everything past this point is inside the "must roll
	// back on failure" zone, because the service is about to go down.
	if err := deps.Service.Stop(ctx); err != nil {
		// This is the one early return that can leave the vault offline.
		// `systemctl stop` can exit non-zero while the unit has in fact
		// stopped -- a stop job that timed out and ended in SIGKILL, or a
		// unit that ended in `failed` state -- so returning without trying
		// to bring it back leaves the vault down until a human notices.
		// Step 8 says roll back on any failure from step 5 onward, and this
		// is step 5.
		//
		// Deliberately Start rather than rollback(): nothing has been moved
		// yet, so PreviousPath does not exist, and rollback's restoreBinary
		// would report "the previous binary is not available" -- telling an
		// operator the rollback failed and they must hand-restore a binary
		// nothing ever touched.
		restart := "restarting it succeeded"
		if startErr := deps.Service.Start(ctx); startErr != nil {
			restart = fmt.Sprintf("restarting it also failed (%v)", startErr)
		}
		return outcome, fmt.Errorf("stop service failed and the service may be down (%w); %s", err, restart)
	}

	installErr := installAndStart(ctx, deps, binary)
	if installErr == nil {
		if healthErr := deps.Health.Wait(ctx, opts.healthTimeout()); healthErr != nil {
			installErr = fmt.Errorf("service did not become healthy within %s: %w", opts.healthTimeout(), healthErr)
		}
	}

	if installErr == nil {
		outcome.Installed = true
		return outcome, nil
	}

	deps.logf("update to %s failed (%v); rolling back to %s", release.Version, installErr, opts.CurrentVersion)
	if rbErr := rollback(ctx, deps, snapshotPath, opts.healthTimeout()); rbErr != nil {
		// The worst case: the new binary is bad AND the rollback itself
		// could not complete. An operator in that state needs to know to
		// restore from a snapshot by hand rather than be told "it
		// failed" with no further detail -- so both causes are named.
		return outcome, fmt.Errorf(
			"update to %s failed (%w), AND rolling back also failed (%w); restore %s onto %s and the database snapshot at %s by hand",
			release.Version, installErr, rbErr, deps.PreviousPath, deps.BinaryPath, snapshotPath,
		)
	}

	outcome.RolledBack = true
	outcome.Reason = installErr.Error()
	return outcome, nil
}

// installAndStart performs step 5's binary swap and step 6's migrate-then-
// start, in the order the design spec lays out: the currently running
// binary is parked at PreviousPath before the new one is written, so a
// failure at any point after this still has an original to roll back to.
func installAndStart(ctx context.Context, deps Deps, binary []byte) error {
	if err := os.Rename(deps.BinaryPath, deps.PreviousPath); err != nil {
		return fmt.Errorf("move running binary to %s: %w", deps.PreviousPath, err)
	}
	if err := writeBinaryAtomically(deps.BinaryPath, binary); err != nil {
		return fmt.Errorf("write new binary: %w", err)
	}
	if deps.Migrate != nil {
		if err := deps.Migrate(ctx); err != nil {
			return fmt.Errorf("run migrations: %w", err)
		}
	}
	if err := deps.Service.Start(ctx); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	return nil
}

// writeBinaryAtomically writes data to a temp file in the same directory as
// path, chmods it 0755, fsyncs it, then renames it into place.
//
// The temp file must live in path's own directory, not a system temp
// directory: a rename is only atomic when source and destination are on the
// same filesystem, and same-directory is what guarantees that without
// having to know anything about how the target directory is mounted. That
// atomicity is what makes the swap safe to observe mid-update -- a reader
// of path sees either the whole old binary or the whole new one, never a
// partial write.
func writeBinaryAtomically(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".new-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// A successful rename below moves tmpPath away, so this Remove is a
	// no-op on the success path and cleanup on every early return.
	defer func() {
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, werr := tmp.Write(data); werr != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", tmpPath, werr)
	}
	if cerr := tmp.Chmod(0o755); cerr != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmpPath, cerr)
	}
	if serr := tmp.Sync(); serr != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync %s: %w", tmpPath, serr)
	}
	if cerr := tmp.Close(); cerr != nil {
		return fmt.Errorf("close %s: %w", tmpPath, cerr)
	}
	if rerr := os.Rename(tmpPath, path); rerr != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpPath, path, rerr)
	}
	return nil
}

// backupSnapshot writes a pre-update snapshot of deps.DBPath into
// deps.BackupDir, reusing internal/backup's already-proven VACUUM INTO
// snapshot rather than re-implementing it. The connection it opens is
// closed before returning, deliberately: nothing about this update should
// still be holding the database open once installAndStart starts moving
// files around.
func backupSnapshot(ctx context.Context, deps Deps) (string, error) {
	st, err := store.Open(deps.DBPath)
	if err != nil {
		return "", fmt.Errorf("open database %s: %w", deps.DBPath, err)
	}
	defer st.Close()

	path, err := backup.Snapshot(ctx, st.DB(), deps.BackupDir, time.Now())
	if err != nil {
		return "", err
	}
	return path, nil
}

// rollback undoes everything step 5 onward may have done: it stops the
// service (idempotent if it already isn't running), moves keyhole.prev back
// over whatever is at BinaryPath, restores the pre-update database
// snapshot, starts the service again, and waits for it to answer /healthz.
// Every step is attempted even if an earlier one fails, so a caller sees
// every problem at once rather than stopping at the first -- the worst case
// here is an operator who needs to know exactly what still needs fixing by
// hand.
func rollback(ctx context.Context, deps Deps, snapshotPath string, healthTimeout time.Duration) error {
	var errs []error

	if err := deps.Service.Stop(ctx); err != nil {
		errs = append(errs, fmt.Errorf("stop service for rollback: %w", err))
	}
	if err := restoreBinary(deps); err != nil {
		errs = append(errs, fmt.Errorf("restore previous binary: %w", err))
	}
	// Restoring the binary alone is the half-rollback nobody notices is
	// missing: the old code would be back, reading a database the new
	// code's migrations already rewrote. Migrations are not reversible, so
	// the snapshot taken in step 4 is the only way back to a database the
	// restored binary can read.
	if err := backup.Restore(snapshotPath, deps.DBPath); err != nil {
		errs = append(errs, fmt.Errorf("restore database snapshot %s onto %s: %w", snapshotPath, deps.DBPath, err))
	}
	if err := deps.Service.Start(ctx); err != nil {
		errs = append(errs, fmt.Errorf("start service after rollback: %w", err))
	}
	// Start's exit code is not the authority on whether the vault is
	// serving again. With a systemd Type=simple unit, `systemctl start`
	// returns 0 as soon as exec succeeds -- it says nothing about whether
	// the process bound its port, so a restored binary that crashes on
	// startup still looks like a clean start. Stopping at Start would let
	// Update report RolledBack, and the CLI print "rolled back to v1.0.0,"
	// while the vault is down and the operator stops looking. That is
	// exactly the silent failure reporting a rollback exists to prevent,
	// and why design spec §10's wording is "asserting the service returns
	// healthy" rather than "asserting start succeeded." The wait runs even
	// when Start reported an error, for the mirror-image reason: a non-zero
	// exit does not prove the service is down either, and health is the
	// only answer to the question the operator is actually asking.
	if err := deps.Health.Wait(ctx, healthTimeout); err != nil {
		errs = append(errs, fmt.Errorf("service did not answer healthz within %s after rollback: %w", healthTimeout, err))
	}

	return errors.Join(errs...)
}

// restoreBinary moves PreviousPath back over BinaryPath. It is named and
// returns a specific error when PreviousPath is not there to move -- the
// case where the update failed AND the rollback cannot proceed, which is
// exactly the case an operator most needs named rather than swallowed.
func restoreBinary(deps Deps) error {
	if _, err := os.Stat(deps.PreviousPath); err != nil {
		return fmt.Errorf("previous binary %s is not available: %w", deps.PreviousPath, err)
	}
	if err := os.Rename(deps.PreviousPath, deps.BinaryPath); err != nil {
		return fmt.Errorf("move %s back to %s: %w", deps.PreviousPath, deps.BinaryPath, err)
	}
	return nil
}
