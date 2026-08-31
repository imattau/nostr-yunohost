package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nostr-yunohost/nostr-yunohost/internal/publisher"

	"github.com/nostr-yunohost/nostr-yunohost/internal/catalog"
	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
	"github.com/nostr-yunohost/nostr-yunohost/internal/relay"
	"github.com/nostr-yunohost/nostr-yunohost/internal/repository"
	"github.com/nostr-yunohost/nostr-yunohost/internal/trust"
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
	case "inspect":
		return runInspect(args[1:], out, errOut)
	case "catalog":
		return runCatalog(args[1:], out, errOut)
	case "preview":
		return runPreview(args[1:], out, errOut)
	case "keygen":
		return runKeygen(args[1:], out, errOut)
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
	remoteRepository := flags.String("repository-url", "", "remote YunoHost package repository URL")
	revision := flags.String("ref", "", "branch, tag, or commit for --repository-url")
	privateKey := flags.String("private-key", os.Getenv("NOSTR_YNH_PRIVATE_KEY"), "Nostr publishing private key")
	privateKeyFile := flags.String("private-key-file", "", "file containing the Nostr publishing private key")
	relayList := flags.String("relays", os.Getenv("NOSTR_YNH_RELAYS"), "comma-separated relay URLs")
	dryRun := flags.Bool("dry-run", false, "build and sign the event without publishing")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *privateKeyFile != "" {
		if *privateKey != "" {
			fmt.Fprintln(errOut, "use only one of --private-key, --private-key-file, or NOSTR_YNH_PRIVATE_KEY")
			return 2
		}
		data, err := os.ReadFile(*privateKeyFile)
		if err != nil {
			fmt.Fprintf(errOut, "read private key file: %v\n", err)
			return 1
		}
		*privateKey = strings.TrimSpace(string(data))
	}
	if *privateKey == "" || (!*dryRun && *relayList == "") {
		fmt.Fprintln(errOut, "publish requires --private-key (or NOSTR_YNH_PRIVATE_KEY) and --relays (or NOSTR_YNH_RELAYS), unless --dry-run is used")
		return 2
	}
	relayURLs := splitNonEmpty(*relayList)
	var metadata publisher.Metadata
	var err error
	if *remoteRepository != "" {
		metadata, err = repository.ReadRemoteMetadata(context.Background(), *remoteRepository, *revision)
	} else {
		metadata, err = repository.ReadMetadata(*repositoryPath)
	}
	if err != nil {
		fmt.Fprintf(errOut, "read repository metadata: %v\n", err)
		return 1
	}
	event, err := publisher.BuildDeclaration(metadata, *privateKey)
	if err != nil {
		fmt.Fprintf(errOut, "build declaration: %v\n", err)
		return 1
	}
	address, err := publisher.AppAddress(event, relayURLs)
	if err != nil {
		fmt.Fprintf(errOut, "encode app address: %v\n", err)
		return 1
	}
	if *dryRun {
		if err := json.NewEncoder(out).Encode(event); err != nil {
			fmt.Fprintf(errOut, "write event: %v\n", err)
			return 1
		}
		fmt.Fprintf(errOut, "naddr: %s\n", address)
		return 0
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
	fmt.Fprintf(errOut, "naddr: %s\n", address)
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

func runInspect(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	flags.SetOutput(errOut)
	relayList := flags.String("relays", os.Getenv("NOSTR_YNH_RELAYS"), "comma-separated relay URLs")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(errOut, "usage: nostr-ynh inspect [--relays <ws://...,...>] <naddr>")
		return 2
	}
	prefix, value, err := nip19.Decode(flags.Arg(0))
	if err != nil || prefix != "naddr" {
		fmt.Fprintf(errOut, "decode naddr: %v\n", err)
		return 1
	}
	pointer, ok := value.(nostr.EntityPointer)
	if !ok || pointer.Kind != protocol.AppDeclarationKind {
		fmt.Fprintln(errOut, "naddr does not point to a YunoHost app declaration")
		return 1
	}
	relayURLs := splitNonEmpty(*relayList)
	if len(relayURLs) == 0 {
		relayURLs = pointer.Relays
	}
	client, err := relay.New(context.Background(), relayURLs)
	if err != nil {
		fmt.Fprintf(errOut, "configure relays: %v\n", err)
		return 1
	}
	event, err := client.FetchReplaceable(context.Background(), pointer.PublicKey, pointer.Identifier)
	if err != nil {
		fmt.Fprintf(errOut, "fetch declaration: %v\n", err)
		return 1
	}
	if err := protocol.VerifyID(*event); err != nil {
		fmt.Fprintf(errOut, "invalid event ID: %v\n", err)
		return 1
	}
	if err := protocol.VerifySignature(*event); err != nil {
		fmt.Fprintf(errOut, "invalid signature: %v\n", err)
		return 1
	}
	declaration, err := protocol.ParseAppDeclaration(*event)
	if err != nil {
		fmt.Fprintf(errOut, "invalid app declaration: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(out).Encode(declaration); err != nil {
		fmt.Fprintf(errOut, "write declaration: %v\n", err)
		return 1
	}
	return 0
}

func runCatalog(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("catalog", flag.ContinueOnError)
	flags.SetOutput(errOut)
	relayList := flags.String("relays", os.Getenv("NOSTR_YNH_RELAYS"), "comma-separated relay URLs")
	trustedList := flags.String("trusted-publishers", os.Getenv("NOSTR_YNH_TRUSTED_PUBLISHERS"), "comma-separated publisher hex keys or npubs")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	policy, err := trust.NewExplicitPublishers(splitNonEmpty(*trustedList))
	if err != nil {
		fmt.Fprintf(errOut, "configure trust policy: %v\n", err)
		return 1
	}
	client, err := relay.New(context.Background(), splitNonEmpty(*relayList))
	if err != nil {
		fmt.Fprintf(errOut, "configure relays: %v\n", err)
		return 1
	}
	store := catalog.NewStore(policy)
	for _, event := range client.FetchAppDeclarations(context.Background()) {
		if err := store.IngestVerified(context.Background(), *event, repository.VerifyDeclaration); err != nil {
			fmt.Fprintf(errOut, "reject %s: %v\n", event.ID, err)
		}
	}
	if err := store.WriteSnapshot(out); err != nil {
		fmt.Fprintf(errOut, "write catalogue: %v\n", err)
		return 1
	}
	return 0
}

func runPreview(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("preview", flag.ContinueOnError)
	flags.SetOutput(errOut)
	revision := flags.String("ref", "", "branch, tag, or commit to inspect")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(errOut, "usage: nostr-ynh preview [--ref <branch|tag|commit>] <repository-url>")
		return 2
	}
	metadata, err := repository.ReadRemoteMetadata(context.Background(), flags.Arg(0), *revision)
	if err != nil {
		fmt.Fprintf(errOut, "preview repository: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(out).Encode(metadata); err != nil {
		fmt.Fprintf(errOut, "write metadata: %v\n", err)
		return 1
	}
	return 0
}

func runKeygen(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	flags.SetOutput(errOut)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(errOut, "usage: nostr-ynh keygen")
		return 2
	}
	privateKey := nostr.GeneratePrivateKey()
	publicKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		fmt.Fprintf(errOut, "derive public key: %v\n", err)
		return 1
	}
	nsec, err := nip19.EncodePrivateKey(privateKey)
	if err != nil {
		fmt.Fprintf(errOut, "encode private key: %v\n", err)
		return 1
	}
	npub, err := nip19.EncodePublicKey(publicKey)
	if err != nil {
		fmt.Fprintf(errOut, "encode public key: %v\n", err)
		return 1
	}
	result := struct {
		PrivateKeyHex string `json:"private_key_hex"`
		Nsec          string `json:"nsec"`
		PublicKeyHex  string `json:"public_key_hex"`
		Npub          string `json:"npub"`
	}{privateKey, nsec, publicKey, npub}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		fmt.Fprintf(errOut, "write keys: %v\n", err)
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
	fmt.Fprintln(out, "  nostr-ynh publish --private-key <hex>|--private-key-file <path> --relays <ws://...,...> [--repo <path>|--repository-url <url> --ref <ref>] [--dry-run]")
	fmt.Fprintln(out, "  nostr-ynh inspect [--relays <ws://...,...>] <naddr>")
	fmt.Fprintln(out, "  nostr-ynh catalog --relays <ws://...,...> --trusted-publishers <npub,...>")
	fmt.Fprintln(out, "  nostr-ynh preview [--ref <branch|tag|commit>] <repository-url>")
	fmt.Fprintln(out, "  nostr-ynh keygen")
}
