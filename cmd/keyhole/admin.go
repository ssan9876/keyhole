package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ssan9876/keyhole/internal/config"
	"github.com/ssan9876/keyhole/internal/store"
)

const adminUsage = `keyhole admin — administrative commands

Usage:
  keyhole admin create --email ADDRESS [--name NAME] [--config PATH]
        Create an administrator account and print a one-time setup link.
`

// inviteTTL is how long a setup or invite link stays valid. Long enough to
// hand over in person or by message; short enough that a stale link in a chat
// log stops being useful.
const inviteTTL = 72 * time.Hour

func runAdmin(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, adminUsage)
		os.Exit(2)
	}
	switch args[0] {
	case "create":
		return runAdminCreate(args[1:])
	case "-h", "--help", "help":
		fmt.Print(adminUsage)
		return nil
	default:
		return fmt.Errorf("unknown admin subcommand %q", args[0])
	}
}

func runAdminCreate(args []string) error {
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

	user, err := st.CreatePendingUser(ctx, *email, *name, "admin")
	if errors.Is(err, store.ErrEmailTaken) {
		return fmt.Errorf("an account already exists for %s", *email)
	}
	if err != nil {
		return err
	}

	_, token, err := st.CreateInvite(ctx, user.ID, inviteTTL)
	if err != nil {
		return err
	}

	fmt.Printf(`
Administrator account created for %s.

Open this link to set your master password:

    %s/enroll/%s

The link works once and expires in %s. Your master password is set in the
browser and never reaches the server, so nobody — including this command —
can recover it for you. Save the recovery code the setup screen gives you.

`, user.Email, cfg.BaseURL, token, inviteTTL)

	return nil
}
