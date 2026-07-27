package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ssan9876/keyhole/internal/config"
	"github.com/ssan9876/keyhole/internal/store"
)

const adminUsage = `keyhole admin — administrative commands

Usage:
  keyhole admin create --email ADDRESS [--name NAME] [--config PATH]
        Create an administrator account and print a one-time setup link.
`

func runAdmin(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, adminUsage)
		os.Exit(2)
	}
	switch args[0] {
	case "create":
		return runAdminCreate(os.Stdout, args[1:])
	case "-h", "--help", "help":
		fmt.Print(adminUsage)
		return nil
	default:
		return fmt.Errorf("unknown admin subcommand %q", args[0])
	}
}

// runAdminCreate writes the setup link to out rather than straight to stdout,
// so a test can read back the token it minted and check that it resolves.
func runAdminCreate(out io.Writer, args []string) error {
	fs := flag.NewFlagSet("admin create", flag.ExitOnError)
	email := fs.String("email", "", "email address of the administrator (required)")
	name := fs.String("name", "", "display name (defaults to the email address)")
	configPath := fs.String("config", defaultConfigPath, "path to config.yml")
	// flag.ExitOnError means fs.Parse already calls os.Exit on a bad flag, so
	// there is no error here to handle.
	fs.Parse(args)
	if *email == "" {
		return errors.New("--email is required")
	}
	if *name == "" {
		*name = *email
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		return err
	}

	reissued := false
	user, err := st.CreatePendingUser(ctx, *email, *name, "admin")
	if errors.Is(err, store.ErrEmailTaken) {
		// There is no rollback between the insert above and the invite below,
		// so a failure between them leaves a pending user with no invite. The
		// old behaviour then reported "an account already exists" on the rerun,
		// which is true of the row and the opposite of what the operator needs
		// to hear: there is no usable account and no way to make one.
		//
		// A pending account has no master password and no key material, so
		// minting a fresh invite for it gives up nothing — and makes the command
		// idempotent, and reissue for a lost or expired link free. An account
		// that has enrolled is a different matter entirely: a new setup link for
		// it would be a password reset available to anyone with shell access, so
		// that case still refuses.
		user, err = st.UserByEmail(ctx, *email)
		if err != nil {
			return err
		}
		if user.Status != "pending" {
			return fmt.Errorf("an account already exists for %s", user.Email)
		}
		reissued = true
	} else if err != nil {
		return err
	}

	_, token, err := st.CreateInvite(ctx, user.ID, store.InviteTTL)
	if err != nil {
		return err
	}

	headline := "Administrator account created for %s."
	if reissued {
		// Say what actually happened. Reporting a creation that did not occur is
		// the same class of mistake as the message this replaces.
		headline = "Administrator account for %s already existed and has not been set up yet;\nissuing a new setup link. Any earlier link stays valid until it expires."
	}

	fmt.Fprintf(out, "\n"+headline+`

Open this link to set your master password:

    %s/enroll/%s

The link works once and expires in %s. Your master password is set in the
browser and never reaches the server, so nobody — including this command —
can recover it for you. Save the recovery code the setup screen gives you.

`, user.Email, cfg.BaseURL, token, store.InviteTTL)

	return nil
}
