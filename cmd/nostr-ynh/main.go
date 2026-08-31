package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		usage(errOut)
		return 2
	}
	switch args[0] {
	case "verify":
		return runVerify(args[1:], out, errOut)
	default:
		fmt.Fprintf(errOut, "unknown command %q\n", args[0])
		usage(errOut)
		return 2
	}
}

func runVerify(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(errOut)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(errOut, "usage: nostr-ynh verify <event.json>")
		return 2
	}
	data, err := os.ReadFile(flags.Arg(0))
	if err != nil {
		fmt.Fprintf(errOut, "read event: %v\n", err)
		return 1
	}
	var event protocol.Event
	if err := json.Unmarshal(data, &event); err != nil {
		fmt.Fprintf(errOut, "decode event: %v\n", err)
		return 1
	}
	if err := protocol.VerifyID(event); err != nil {
		fmt.Fprintf(errOut, "invalid event ID: %v\n", err)
		return 1
	}
	if err := protocol.VerifySignature(event); err != nil {
		fmt.Fprintf(errOut, "invalid signature: %v\n", err)
		return 1
	}
	declaration, err := protocol.ParseAppDeclaration(event)
	if err != nil {
		fmt.Fprintf(errOut, "invalid app declaration: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "valid app declaration: %s (%s)\n", declaration.AppID, declaration.Version)
	fmt.Fprintf(out, "publisher: %s\nrepository: %s\ncommit: %s\n", declaration.Publisher, declaration.Repository, declaration.Commit)
	return 0
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "usage: nostr-ynh verify <event.json>")
}
