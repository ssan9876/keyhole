package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ssan9876/keyhole/internal/config"
	"github.com/ssan9876/keyhole/internal/store"
)

const testBaseURL = "https://vault.example.test"

// tempConfig writes a config pointing at a throwaway data directory and
// returns its path alongside the parsed result, so a test can reach the same
// database the command will create.
func tempConfig(t *testing.T) (string, config.Config) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	body := "data_dir: " + filepath.Join(dir, "data") + "\n" +
		"base_url: " + testBaseURL + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return path, cfg
}

// openStore opens the database the command wrote, for inspection.
func openStore(t *testing.T, cfg config.Config) *store.Store {
	t.Helper()

	st, err := store.Open(cfg.DBPath())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// create runs the command and returns everything it printed.
func create(t *testing.T, configPath string, args ...string) string {
	t.Helper()

	var out bytes.Buffer
	if err := runAdminCreate(&out, append(args, "--config", configPath)); err != nil {
		t.Fatalf("runAdminCreate(%v): %v", args, err)
	}
	return out.String()
}

var setupLink = regexp.MustCompile(regexp.QuoteMeta(testBaseURL) + `/enroll/([A-Za-z0-9_-]+)`)

// tokenFrom pulls the one-time token out of the printed setup link, failing if
// the link is not the shape a client's router expects.
func tokenFrom(t *testing.T, output string) string {
	t.Helper()

	match := setupLink.FindStringSubmatch(output)
	if match == nil {
		t.Fatalf("no %s/enroll/<token> link in the output:\n%s", testBaseURL, output)
	}
	return match[1]
}

func TestAdminCreateMakesOneAdminWithAWorkingSetupLink(t *testing.T) {
	configPath, cfg := tempConfig(t)

	output := create(t, configPath, "--email", "admin@example.com", "--name", "Ada")

	st := openStore(t, cfg)
	ctx := context.Background()

	// "Exactly one admin": a command that created two, or that created the user
	// and left no way to enroll, would still print a cheerful message.
	count, err := st.CountUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("user count = %d, want exactly 1", count)
	}

	user, err := st.UserByEmail(ctx, "admin@example.com")
	if err != nil {
		t.Fatalf("UserByEmail: %v", err)
	}
	if user.Role != "admin" {
		t.Errorf("role = %q, want %q", user.Role, "admin")
	}
	if user.Status != "pending" {
		t.Errorf("status = %q, want %q — the account is usable before its owner has set a master password", user.Status, "pending")
	}
	if user.Name != "Ada" {
		t.Errorf("name = %q, want %q", user.Name, "Ada")
	}
	// The server must never hold key material for an account nobody has
	// enrolled: it cannot fabricate any, and a non-NULL column here would mean
	// it had.
	if user.AuthHash.Valid || user.ProtectedUserKey.Valid {
		t.Error("a pending account already carries key material")
	}

	// "A working link": the printed token must actually resolve to this user's
	// live invite, not merely look like a token.
	token := tokenFrom(t, output)
	invite, err := st.InviteByToken(ctx, token)
	if err != nil {
		t.Fatalf("the printed token does not resolve to a live invite: %v", err)
	}
	if invite.UserID != user.ID {
		t.Errorf("the invite belongs to user %q, want %q", invite.UserID, user.ID)
	}
}

func TestAdminCreateDefaultsTheNameToTheEmailAddress(t *testing.T) {
	configPath, cfg := tempConfig(t)

	create(t, configPath, "--email", "admin@example.com")

	user, err := openStore(t, cfg).UserByEmail(context.Background(), "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if user.Name != "admin@example.com" {
		t.Errorf("name = %q, want the email address %q when --name is omitted",
			user.Name, "admin@example.com")
	}
}

func TestAdminCreateReissuesTheLinkForAPendingAccount(t *testing.T) {
	configPath, cfg := tempConfig(t)

	firstToken := tokenFrom(t, create(t, configPath, "--email", "admin@example.com"))

	// There is no rollback between CreatePendingUser and CreateInvite, so a
	// failure between them used to leave a pending user with no invite and no
	// way to recover — and rerunning reported "an account already exists",
	// which is the opposite of what the operator needs to hear. Rerunning for
	// an un-enrolled account must mint a fresh link instead, which also gives
	// reissue for a link that was lost or expired.
	secondToken := tokenFrom(t, create(t, configPath, "--email", "admin@example.com"))

	st := openStore(t, cfg)
	ctx := context.Background()

	count, err := st.CountUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("user count = %d after two invocations, want 1", count)
	}
	user, err := st.UserByEmail(ctx, "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if user.Status != "pending" {
		t.Errorf("status = %q after reissue, want %q", user.Status, "pending")
	}

	if secondToken == firstToken {
		t.Error("the second invocation reprinted the first token; invite tokens are stored hashed and cannot be recovered, so it must mint a new one")
	}
	invite, err := st.InviteByToken(ctx, secondToken)
	if err != nil {
		t.Fatalf("the reissued token does not resolve to a live invite: %v", err)
	}
	if invite.UserID != user.ID {
		t.Errorf("the reissued invite belongs to user %q, want %q", invite.UserID, user.ID)
	}
}

func TestAdminCreateRefusesAnAccountThatHasAlreadyEnrolled(t *testing.T) {
	for _, status := range []string{"active", "disabled"} {
		t.Run(status, func(t *testing.T) {
			configPath, cfg := tempConfig(t)
			create(t, configPath, "--email", "admin@example.com")

			st := openStore(t, cfg)
			ctx := context.Background()
			if _, err := st.DB().ExecContext(ctx,
				`UPDATE users SET status = ? WHERE email = ?`, status, "admin@example.com"); err != nil {
				t.Fatal(err)
			}

			// Reissue is only correct for an account nobody has enrolled. Minting
			// a fresh setup link for an account that already has a master
			// password would be a password reset by any other name, available to
			// anyone with shell access and no key material required.
			var out bytes.Buffer
			err := runAdminCreate(&out, []string{"--email", "admin@example.com", "--config", configPath})
			if err == nil {
				t.Fatalf("creating over a %s account succeeded; output:\n%s", status, out.String())
			}
			if !strings.Contains(err.Error(), "admin@example.com") {
				t.Errorf("error %q does not name the address the operator typed", err)
			}
			if setupLink.MatchString(out.String()) {
				t.Errorf("a setup link was printed for a %s account:\n%s", status, out.String())
			}

			count, err := st.CountUsers(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Errorf("user count = %d, want 1", count)
			}
		})
	}
}

func TestAdminCreateRequiresAnEmail(t *testing.T) {
	configPath, _ := tempConfig(t)

	var out bytes.Buffer
	if err := runAdminCreate(&out, []string{"--config", configPath}); err == nil {
		t.Error("runAdminCreate succeeded with no --email")
	}
}
