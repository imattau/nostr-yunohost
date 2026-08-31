package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nostr-yunohost/nostr-yunohost/internal/publisher"

	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
	"github.com/nostr-yunohost/nostr-yunohost/internal/relay"
	"github.com/nostr-yunohost/nostr-yunohost/internal/repository"
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
	case "publish":
		return runPublish(args[1:], out, errOut)
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

func runPublish(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("publish", flag.ContinueOnError)
	flags.SetOutput(errOut)
	repositoryPath := flags.String("repo", ".", "YunoHost package repository")
	privateKey := flags.String("private-key", os.Getenv("NOSTR_YNH_PRIVATE_KEY"), "Nostr publishing private key")
	relayList := flags.String("relays", os.Getenv("NOSTR_YNH_RELAYS"), "comma-separated relay URLs")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *privateKey == "" || *relayList == "" {
		fmt.Fprintln(errOut, "publish requires --private-key (or NOSTR_YNH_PRIVATE_KEY) and --relays (or NOSTR_YNH_RELAYS)")
		return 2
	}
	relayURLs := splitNonEmpty(*relayList)
	metadata, err := repository.ReadMetadata(*repositoryPath)
	if err != nil {
		fmt.Fprintf(errOut, "read repository metadata: %v\n", err)
		return 1
	}
	event, err := publisher.BuildDeclaration(metadata, *privateKey)
	if err != nil {
		fmt.Fprintf(errOut, "build declaration: %v\n", err)
		return 1
	}
	client, err := relay.New(context.Background(), relayURLs)
	if err != nil {
		fmt.Fprintf(errOut, "configure relays: %v\n", err)
		return 1
	}
	results := client.Publish(context.Background(), event)
	if err := json.NewEncoder(out).Encode(event); err != nil {
		fmt.Fprintf(errOut, "write event: %v\n", err)
		return 1
	}
	succeeded := 0
	for _, result := range results {
		if result.Error != nil {
			fmt.Fprintf(errOut, "%s: %v\n", result.Relay, result.Error)
			continue
		}
		succeeded++
		fmt.Fprintf(errOut, "%s: published\n", result.Relay)
	}
	if succeeded == 0 {
		return 1
	}
	return 0
}

func splitNonEmpty(raw string) []string {
	var values []string
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "usage:")
	fmt.Fprintln(out, "  nostr-ynh verify <event.json>")
	fmt.Fprintln(out, "  nostr-ynh publish --private-key <hex> --relays <ws://...,...> [--repo <path>]")
}
