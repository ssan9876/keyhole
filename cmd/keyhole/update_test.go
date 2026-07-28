package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ssan9876/keyhole/internal/release"
)

// TestUpdateRefusesADevBuild proves runUpdate stops before ever touching
// the network, config, or filesystem for a build whose Version is still the
// "dev" default -- the state every local `go build` produces. Without this
// guard, `keyhole update` on a developer's own build would go straight to
// "fetch the latest release" and fail with a confusing network or
// not-found error instead of the actual reason.
func TestUpdateRefusesADevBuild(t *testing.T) {
	original := Version
	Version = "dev"
	t.Cleanup(func() { Version = original })

	err := runUpdate(nil)
	if err == nil {
		t.Fatal("runUpdate() error = nil, want a refusal for a dev build")
	}
	const want = "this build was not produced by a release; update is for released binaries"
	if err.Error() != want {
		t.Errorf("runUpdate() error = %q, want %q", err.Error(), want)
	}
}

// TestUpdateRefusesABuildWithNoEmbeddedPublicKey proves the second guard:
// even a build with a real release Version but no public key embedded
// (every build except the release workflow's own) refuses rather than
// attempting to verify a signature against an empty key.
func TestUpdateRefusesABuildWithNoEmbeddedPublicKey(t *testing.T) {
	originalVersion, originalKey := Version, UpdatePublicKey
	Version = "v1.2.3"
	UpdatePublicKey = ""
	t.Cleanup(func() { Version, UpdatePublicKey = originalVersion, originalKey })

	err := runUpdate(nil)
	if err == nil {
		t.Fatal("runUpdate() error = nil, want a refusal for a build with no embedded public key")
	}
	const want = "this build has no release public key embedded; update cannot verify a downloaded release"
	if err.Error() != want {
		t.Errorf("runUpdate() error = %q, want %q", err.Error(), want)
	}
}

// TestReportOutcomeForARollbackReturnsAnErrorNamingBothVersionsAndTheReason
// pins the one branch that must never go quiet. release.Update returns a
// rollback as a nil error -- rolling back is a handled outcome, not a Go
// failure -- so it is this function alone that decides whether the operator
// hears about it. Reporting it as success would leave them believing they
// upgraded while the old binary is what is actually running.
func TestReportOutcomeForARollbackReturnsAnErrorNamingBothVersionsAndTheReason(t *testing.T) {
	var out bytes.Buffer
	err := reportOutcome(&out, release.Outcome{
		FromVersion: "v1.0.0",
		ToVersion:   "v2.0.0",
		RolledBack:  true,
		Reason:      "service did not become healthy within 30s",
	})
	if err == nil {
		t.Fatal("reportOutcome() error = nil for a rolled-back update, want a non-nil error: `keyhole update` must exit non-zero")
	}

	msg := err.Error()
	for _, want := range []string{"v2.0.0", "v1.0.0", "rolled back", "service did not become healthy within 30s"} {
		if !strings.Contains(msg, want) {
			t.Errorf("reportOutcome() error = %q, want it to mention %q", msg, want)
		}
	}
	if strings.Contains(out.String(), "Updated") {
		t.Errorf("reportOutcome() wrote %q to stdout, want no success line for a rolled-back update", out.String())
	}
}

func TestReportOutcomeForAnInstallReportsSuccessAndReturnsNoError(t *testing.T) {
	var out bytes.Buffer
	err := reportOutcome(&out, release.Outcome{FromVersion: "v1.0.0", ToVersion: "v2.0.0", Installed: true})
	if err != nil {
		t.Fatalf("reportOutcome() error = %v, want nil for a successful install", err)
	}
	if got := out.String(); !strings.Contains(got, "v1.0.0") || !strings.Contains(got, "v2.0.0") {
		t.Errorf("reportOutcome() wrote %q, want it to name both versions", got)
	}
}

// TestReportOutcomeForACheckDoesNotClaimAnythingWasInstalled guards the
// wording of `--check`, which changes nothing on disk: telling an operator
// "Updated v1.0.0 -> v2.0.0" after a check would be a lie about the running
// version.
func TestReportOutcomeForACheckDoesNotClaimAnythingWasInstalled(t *testing.T) {
	var out bytes.Buffer
	err := reportOutcome(&out, release.Outcome{FromVersion: "v1.0.0", ToVersion: "v2.0.0", Checked: true})
	if err != nil {
		t.Fatalf("reportOutcome() error = %v, want nil", err)
	}
	got := out.String()
	if !strings.Contains(got, "available") {
		t.Errorf("reportOutcome() wrote %q, want it to say an update is available", got)
	}
	if strings.Contains(got, "Updated ") {
		t.Errorf("reportOutcome() wrote %q, want it not to claim an install happened", got)
	}
}
