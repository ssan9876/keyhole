// Command keyhole is the Keyhole server and its administrative CLI.
package main

import (
	"fmt"
	"os"
)

const usage = `keyhole — self-hosted end-to-end-encrypted password manager

Usage:
  keyhole serve     [--config PATH]   Run the HTTP server
  keyhole migrate   [--config PATH]   Apply pending database migrations
  keyhole admin     <subcommand>      Administrative commands

Run "keyhole admin" for administrative subcommands.
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
