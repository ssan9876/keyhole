package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ssan9876/keyhole/internal/config"
	"github.com/ssan9876/keyhole/internal/release"
)

// githubReleasesURL is pinned to this repository, per design spec §8.1's
// supply-chain reasoning: an update command that could be pointed anywhere
// is an update command that defeats the point of verifying a signature.
const githubReleasesURL = "https://api.github.com/repos/ssan9876/keyhole/releases/latest"

// systemdUnit is the name of the systemd service scripts/install.sh (task
// 6) installs Keyhole under.
const systemdUnit = "keyhole"

// migrateTimeout and systemctlTimeout bound the two subprocesses `keyhole
// update` runs while the service is stopped. Neither had a deadline before:
// exec.CommandContext only kills on its context, and that context comes from
// context.Background(). A hung `keyhole migrate` -- or a systemctl call
// blocked on a wedged D-Bus -- left the vault down indefinitely, and the
// rollback was never reached, because nothing ever returned in order to
// reach it. Any finite bound is better than that.
//
// The values are generous for real work and finite anyway, which is the
// whole point. Migrations on a household-scale SQLite file finish in well
// under a second; five minutes covers a large vault on slow storage.
// systemd's own default stop-job timeout is 90 seconds before it escalates
// to SIGKILL, so anything under that would fire on a unit that is merely
// slow to stop -- two minutes clears it with margin.
const (
	migrateTimeout   = 5 * time.Minute
	systemctlTimeout = 2 * time.Minute
)

const updateUsage = `keyhole update [--check] [--config PATH]

Fetches the latest release, verifies it against a signed checksum list, and
installs it -- stopping the service, swapping the binary, running
migrations, and restarting. If the service does not answer /healthz within
30 seconds, the binary and database are automatically rolled back and the
rollback is reported; nothing is left half-installed silently.

--check compares versions and prints what is available without downloading
or installing anything.
`

func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config.yml")
	checkOnly := fs.Bool("check", false, "check for a new release without installing it")
	// flag.ExitOnError means fs.Parse already calls os.Exit on a bad flag, so
	// there is no error here to handle.
	fs.Parse(args)

	// A "dev" build was built locally, not produced by the release
	// workflow that publishes signed binaries: there is no release entry
	// for it to compare against, and no guarantee its own version string
	// means anything to GitHub. Refusing here, before any network call,
	// is what keeps that failure mode a clear message instead of a
	// confusing "release not found."
	if Version == "" || Version == "dev" {
		return errors.New("this build was not produced by a release; update is for released binaries")
	}
	// UpdatePublicKey is set at build time by the same -ldflags step that
	// sets Version (see scripts that produce release binaries). A build
	// without one cannot verify anything it downloads, so it must refuse
	// for the same reason a "dev" build does.
	if UpdatePublicKey == "" {
		return errors.New("this build has no release public key embedded; update cannot verify a downloaded release")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate the running binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(binaryPath); err == nil {
		binaryPath = resolved
	}

	deps := release.Deps{
		Source:       githubSource{client: &http.Client{Timeout: 30 * time.Second}, apiURL: githubReleasesURL},
		Service:      systemctlService{unit: systemdUnit},
		Health:       newHTTPHealth(cfg),
		BinaryPath:   binaryPath,
		PreviousPath: binaryPath + ".prev",
		DBPath:       cfg.DBPath(),
		BackupDir:    filepath.Join(cfg.DataDir, "backups"),
		Migrate:      execMigrate(binaryPath, *configPath, migrateTimeout),
		Logf:         func(format string, args ...any) { fmt.Printf(format+"\n", args...) },
	}

	outcome, err := release.Update(context.Background(), deps, release.Options{
		CurrentVersion: Version,
		PublicKey:      UpdatePublicKey,
		CheckOnly:      *checkOnly,
	})
	if err != nil {
		return err
	}

	return reportOutcome(os.Stdout, outcome)
}

// reportOutcome turns an Outcome into what the operator sees and into the
// process's exit status. It is a separate function from runUpdate precisely
// so it can be tested without a network, a config file, or systemd: the
// rollback branch below is the one place the "a rollback happened" signal
// can be lost, and losing it is the failure mode this whole command is
// built to avoid.
func reportOutcome(out io.Writer, outcome release.Outcome) error {
	switch {
	case outcome.AlreadyCurrent:
		fmt.Fprintf(out, "Already running the latest release (%s).\n", outcome.FromVersion)
		return nil
	case outcome.Checked:
		fmt.Fprintf(out, "%s -> %s available. Run \"keyhole update\" to install it.\n", outcome.FromVersion, outcome.ToVersion)
		return nil
	case outcome.RolledBack:
		// A silent rollback leaves an operator believing they upgraded, so
		// this reports what happened AND exits non-zero: the update they
		// asked for did not happen, and the running version is still the
		// old one. Returning nil here would be the quiet failure the
		// automatic rollback exists to make survivable, not invisible.
		return fmt.Errorf("update to %s failed and was automatically rolled back to %s: %s",
			outcome.ToVersion, outcome.FromVersion, outcome.Reason)
	case outcome.Installed:
		fmt.Fprintf(out, "Updated %s -> %s.\n", outcome.FromVersion, outcome.ToVersion)
		return nil
	default:
		return nil
	}
}

// githubSource is the real release.Source: it talks to GitHub's releases
// API and downloads assets over plain HTTPS. Every test in
// internal/release drives Update with a fake instead -- this is the only
// place in the program that touches the network for an update.
type githubSource struct {
	client *http.Client
	apiURL string
}

type githubReleaseResponse struct {
	TagName string `json:"tag_name"`
	Body    string `json:"body"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func (g githubSource) Latest(ctx context.Context) (release.Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.apiURL, nil)
	if err != nil {
		return release.Release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := g.client.Do(req)
	if err != nil {
		return release.Release{}, fmt.Errorf("fetch %s: %w", g.apiURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return release.Release{}, fmt.Errorf("fetch %s: unexpected status %s", g.apiURL, resp.Status)
	}

	var body githubReleaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return release.Release{}, fmt.Errorf("decode release metadata from %s: %w", g.apiURL, err)
	}

	assets := make(map[string]string, len(body.Assets))
	for _, a := range body.Assets {
		assets[a.Name] = a.BrowserDownloadURL
	}
	return release.Release{Version: body.TagName, Notes: body.Body, Assets: assets}, nil
}

func (g githubSource) Download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: unexpected status %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// systemctlService is the real release.Service: it shells out to systemctl.
// Tests never touch this -- internal/release's fakes stand in for it.
type systemctlService struct {
	unit string
}

func (s systemctlService) Stop(ctx context.Context) error  { return runSystemctl(ctx, "stop", s.unit) }
func (s systemctlService) Start(ctx context.Context) error { return runSystemctl(ctx, "start", s.unit) }

func runSystemctl(parent context.Context, args ...string) error {
	ctx, cancel := context.WithTimeout(parent, systemctlTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if timedOut(ctx) {
			return fmt.Errorf("systemctl %s: timed out after %s: %s", strings.Join(args, " "), systemctlTimeout, strings.TrimSpace(string(out)))
		}
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// timedOut reports whether ctx's own deadline is what ended a subprocess.
// It exists so the error can say "timed out after 5m0s" rather than the
// "signal: killed" a context-killed process actually reports, which names
// the symptom and hides the cause.
func timedOut(ctx context.Context) bool {
	return errors.Is(ctx.Err(), context.DeadlineExceeded)
}

// httpHealth is the real release.Health: it polls /healthz on cfg.Addr,
// over TLS when the server terminates it itself.
type httpHealth struct {
	url    string
	client *http.Client
}

func newHTTPHealth(cfg config.Config) httpHealth {
	url := "http://" + cfg.Addr + "/healthz"
	transport := &http.Transport{}
	if cfg.TLSEnabled() {
		url = "https://" + cfg.Addr + "/healthz"
		// InsecureSkipVerify is deliberate and narrow: this dials the
		// loopback address this very process's config just configured,
		// immediately after this same process asked systemd to start it.
		// It is a liveness check against a certificate that may well be
		// the installer's self-signed one, not a decision about whether
		// to trust a remote party -- there is no separate trust store to
		// verify a loopback cert against from inside the process that
		// owns it.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- loopback liveness check, see comment above
	}
	return httpHealth{url: url, client: &http.Client{Transport: transport, Timeout: 5 * time.Second}}
}

func (h httpHealth) Wait(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		if err := h.probe(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("no healthy response from %s within %s: %w", h.url, timeout, lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (h httpHealth) probe(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
	if err != nil {
		return err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	return nil
}

// execMigrate runs `<binaryPath> migrate --config <configPath>` -- the new
// binary, not this one, per design spec step 6: migrations must run under
// the code that will actually read the migrated schema afterward.
//
// timeout is a parameter rather than a package constant read in here because
// this is the one of the two bounded subprocesses a test can actually drive:
// runSystemctl execs a binary that does not exist off Linux, while this
// execs whatever path it is handed.
func execMigrate(binaryPath, configPath string, timeout time.Duration) func(ctx context.Context) error {
	return func(parent context.Context) error {
		ctx, cancel := context.WithTimeout(parent, timeout)
		defer cancel()

		cmd := exec.CommandContext(ctx, binaryPath, "migrate", "--config", configPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			if timedOut(ctx) {
				return fmt.Errorf("%s migrate: timed out after %s: %s", binaryPath, timeout, strings.TrimSpace(string(out)))
			}
			return fmt.Errorf("%s migrate: %w: %s", binaryPath, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}
