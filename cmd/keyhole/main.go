// Command keyhole is the Keyhole server and its administrative CLI.
package main

import (
	"fmt"
	"os"
)

// Version is the compiled-in release version. It is "dev" for any build not
// produced by the release workflow -- in particular, every local `go build`
// -- and is overwritten at build time via:
//
//	go build -ldflags "-X main.Version=vX.Y.Z"
//
// `keyhole update` refuses to run against a "dev" build: there is no
// release entry to compare a dev build's version against, and updating is
// a released-binary operation.
var Version = "dev"

// UpdatePublicKey is the minisign public key release assets are signed
// with, embedded the same way as Version -- via -ldflags at release-build
// time, by the release workflow that also generates the keypair and signs
// SHA256SUMS. It is empty in every build produced anywhere other than that
// workflow, and `keyhole update` refuses to run without it: no public key
// means no way to verify what gets downloaded.
var UpdatePublicKey = ""

const usage = `keyhole — self-hosted end-to-end-encrypted password manager

Usage:
  keyhole serve     [--config PATH]                       Run the HTTP server
  keyhole migrate   [--config PATH]                        Apply pending database migrations
  keyhole admin     <subcommand>                           Administrative commands
  keyhole backup    [--config PATH] [--out DIR] [--keep N] Write a snapshot and prune old ones
  keyhole restore   <file> [--config PATH]                 Replace the database with a snapshot
  keyhole update    [--check] [--config PATH]              Update to the latest release, with automatic rollback

Run "keyhole admin" for administrative subcommands.

Every backup is entirely ciphertext -- item bodies, names, and URLs are
encrypted under keys the server has never held -- so replicating a backup
somewhere less trusted than the server itself is a reasonable thing to do.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "migrate":
		err = runMigrate(os.Args[2:])
	case "admin":
		err = runAdmin(os.Args[2:])
	case "backup":
		err = runBackup(os.Args[2:])
	case "restore":
		err = runRestore(os.Args[2:])
	case "update":
		err = runUpdate(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "keyhole: %v\n", err)
		os.Exit(1)
	}
}
