package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/imattau/nostr-yunohost/internal/announce"
	"github.com/imattau/nostr-yunohost/internal/catalog"
	"github.com/imattau/nostr-yunohost/internal/ciresult"
	"github.com/imattau/nostr-yunohost/internal/curation"
	"github.com/imattau/nostr-yunohost/internal/protocol"
	"github.com/imattau/nostr-yunohost/internal/publisher"
	"github.com/imattau/nostr-yunohost/internal/relay"
	"github.com/imattau/nostr-yunohost/internal/repository"
	"github.com/imattau/nostr-yunohost/internal/reverify"
	"github.com/imattau/nostr-yunohost/internal/trust"
	"github.com/imattau/nostr-yunohost/internal/verification"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		usage(errOut)
		return 2
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Fprintln(out, version)
		return 0
	}
	switch args[0] {
	case "verify":
		return runVerify(args[1:], out, errOut)
	case "publish":
		return runPublish(args[1:], out, errOut)
	case "inspect":
		return runInspect(args[1:], out, errOut)
	case "endorse":
		return runEndorse(args[1:], out, errOut)
	case "attest":
		return runAttest(args[1:], out, errOut)
	case "reverify":
		return runReverify(args[1:], out, errOut)
	case "catalog":
		return runCatalog(args[1:], out, errOut)
	case "preview":
		return runPreview(args[1:], out, errOut)
	case "keygen":
		return runKeygen(args[1:], out, errOut)
	case "profile":
		return runProfile(args[1:], out, errOut)
	default:
		fmt.Fprintf(errOut, "unknown command %q\n", args[0])
		usage(errOut)
		return 2
	}
}

func runVerify(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(errOut)
	jsonOutput := flags.Bool("json", false, "emit machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(errOut, "usage: nostr-ynh verify [--json] <event.json>")
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
	if *jsonOutput {
		if err := json.NewEncoder(out).Encode(declaration); err != nil {
			fmt.Fprintf(errOut, "write declaration: %v\n", err)
			return 1
		}
		return 0
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
	jsonOutput := flags.Bool("json", false, "emit one machine-readable JSON result")
	ciResultPath := flags.String("ci-result", "", "optional path to a ci-result.json (internal/ciresult schema) - when given, also builds and publishes a kind-30080 CI attestation for this exact revision, signed by the same key as the declaration")
	ciProvider := flags.String("ci-provider", "", "CI system that produced --ci-result, e.g. github-actions (auto-detected on GitHub Actions)")
	ciRef := flags.String("ci-ref", "", "CI run reference for --ci-result, e.g. a workflow run URL (auto-detected on GitHub Actions)")
	announceFlag := flags.Bool("announce", false, "also publish a kind-1 text note announcing this release, signed by the same key as the declaration, unless this app_id/commit was already announced")
	announcementLedgerPath := flags.String("announcement-ledger", os.Getenv("NOSTR_YNH_ANNOUNCEMENT_LEDGER"), "path to the local record of announcements already published by this key (required with --announce)")
	timeoutSeconds := relayTimeoutFlag(flags)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *timeoutSeconds <= 0 {
		fmt.Fprintln(errOut, "timeout-seconds must be positive")
		return 2
	}
	if *announceFlag && *announcementLedgerPath == "" {
		fmt.Fprintln(errOut, "--announce requires --announcement-ledger (or NOSTR_YNH_ANNOUNCEMENT_LEDGER)")
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

	// A CI result attests to a specific revision; it must be built alongside
	// the declaration it corresponds to, not published independently, or a
	// stale --ci-result could be signed against whatever repo/ref happens to
	// be checked out. Same publisher key as the declaration: the publisher
	// is the one attesting, per docs/attestations.md's "nothing requires
	// the same server to both publish and verify" - it just doesn't require
	// them to be different, either, and this is the common case.
	var attestEvent *nostr.Event
	var attestAddress string
	if *ciResultPath != "" {
		data, err := os.ReadFile(*ciResultPath)
		if err != nil {
			fmt.Fprintf(errOut, "read CI result: %v\n", err)
			return 1
		}
		result, err := ciresult.Parse(data)
		if err != nil {
			fmt.Fprintf(errOut, "invalid CI result: %v\n", err)
			return 1
		}
		if result.AppID != metadata.AppID || result.Repository != metadata.Repository ||
			result.Commit != metadata.Commit || result.Manifest != metadata.ManifestHash ||
			result.Content != metadata.ContentHash {
			fmt.Fprintln(errOut, "--ci-result does not match the revision being published (app_id/repository/commit/manifest/content); refusing to attest")
			return 1
		}
		provider, ref := *ciProvider, *ciRef
		if provider == "" || ref == "" {
			autoProvider, autoRef := githubActionsRun()
			if provider == "" {
				provider = autoProvider
			}
			if ref == "" {
				ref = autoRef
			}
		}
		if provider == "" || ref == "" {
			fmt.Fprintln(errOut, "--ci-result requires --ci-provider and --ci-ref (could not auto-detect a CI run)")
			return 2
		}
		built, err := verification.Build(result.AppID, result.Repository, result.Commit, result.Manifest, result.Content, provider, ref, result.Checks, result.Result, *privateKey)
		if err != nil {
			fmt.Fprintf(errOut, "build attestation: %v\n", err)
			return 1
		}
		addr, err := verification.Address(built, relayURLs)
		if err != nil {
			fmt.Fprintf(errOut, "encode attestation address: %v\n", err)
			return 1
		}
		attestEvent, attestAddress = &built, addr
	}

	// --announce is checked against the ledger before anything is published,
	// not after: a commit already announced by this key must produce no
	// announcement event at all (announceOutcome.Skipped), so a repeated
	// publish for an unchanged revision (a re-run CI job, a manual re-publish
	// of the same commit) can never double-post - see
	// docs/profile-and-announcements.md.
	var announceOut *announceOutcome
	var announceLedger *announce.Ledger
	if *announceFlag {
		announceLedger, err = announce.LoadLedger(*announcementLedgerPath)
		if err != nil {
			fmt.Fprintf(errOut, "load announcement ledger: %v\n", err)
			return 1
		}
		if announceLedger.HasAnnounced(metadata.AppID, metadata.Commit) {
			announceOut = &announceOutcome{Skipped: true}
		} else {
			built, err := publisher.BuildAnnouncement(event, metadata.Repository, metadata.Name, relayURLs, *privateKey)
			if err != nil {
				fmt.Fprintf(errOut, "build announcement: %v\n", err)
				return 1
			}
			nevent, err := nip19.EncodeEvent(built.ID, relayURLs, built.PubKey)
			if err != nil {
				fmt.Fprintf(errOut, "encode announcement nevent: %v\n", err)
				return 1
			}
			announceOut = &announceOutcome{Event: &built, Nevent: nevent}
		}
	}

	if *dryRun {
		if *jsonOutput {
			return writePublishJSON(out, event, address, nil, attestEvent, attestAddress, nil, announceOut)
		}
		if err := json.NewEncoder(out).Encode(event); err != nil {
			fmt.Fprintf(errOut, "write event: %v\n", err)
			return 1
		}
		fmt.Fprintf(errOut, "naddr: %s\n", address)
		if attestEvent != nil {
			if err := json.NewEncoder(out).Encode(*attestEvent); err != nil {
				fmt.Fprintf(errOut, "write attestation event: %v\n", err)
				return 1
			}
			fmt.Fprintf(errOut, "attestation naddr: %s\n", attestAddress)
		}
		if announceOut != nil {
			if announceOut.Skipped {
				fmt.Fprintln(errOut, "announcement: already announced this app_id/commit, skipping")
			} else {
				if err := json.NewEncoder(out).Encode(*announceOut.Event); err != nil {
					fmt.Fprintf(errOut, "write announcement event: %v\n", err)
					return 1
				}
				fmt.Fprintf(errOut, "announcement nevent: %s\n", announceOut.Nevent)
			}
		}
		return 0
	}
	client, err := relay.New(context.Background(), relayURLs)
	if err != nil {
		fmt.Fprintf(errOut, "configure relays: %v\n", err)
		return 1
	}
	publishCtx, cancel := context.WithTimeout(context.Background(), relayTimeout(*timeoutSeconds))
	defer cancel()
	results := client.Publish(publishCtx, event)
	var attestResults []relay.PublishResult
	if attestEvent != nil {
		attestResults = client.Publish(publishCtx, *attestEvent)
	}
	if announceOut != nil && announceOut.Event != nil {
		announceOut.Results = client.Publish(publishCtx, *announceOut.Event)
		for _, result := range announceOut.Results {
			if result.Error == nil {
				if err := announceLedger.Record(metadata.AppID, metadata.Commit, metadata.Version, announceOut.Event.ID, announceOut.Nevent); err != nil {
					fmt.Fprintf(errOut, "record announcement: %v\n", err)
					return 1
				}
				break
			}
		}
	}
	if *jsonOutput {
		return writePublishJSON(out, event, address, results, attestEvent, attestAddress, attestResults, announceOut)
	}
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
	if attestEvent != nil {
		if err := json.NewEncoder(out).Encode(*attestEvent); err != nil {
			fmt.Fprintf(errOut, "write attestation event: %v\n", err)
			return 1
		}
		fmt.Fprintf(errOut, "attestation naddr: %s\n", attestAddress)
		attestSucceeded := 0
		for _, result := range attestResults {
			if result.Error != nil {
				fmt.Fprintf(errOut, "%s: %v\n", result.Relay, result.Error)
				continue
			}
			attestSucceeded++
			fmt.Fprintf(errOut, "%s: attestation published\n", result.Relay)
		}
		if attestSucceeded == 0 {
			return 1
		}
	}
	if announceOut != nil {
		if announceOut.Skipped {
			fmt.Fprintln(errOut, "announcement: already announced this app_id/commit, skipping")
		} else {
			if err := json.NewEncoder(out).Encode(*announceOut.Event); err != nil {
				fmt.Fprintf(errOut, "write announcement event: %v\n", err)
				return 1
			}
			fmt.Fprintf(errOut, "announcement nevent: %s\n", announceOut.Nevent)
			announceSucceeded := 0
			for _, result := range announceOut.Results {
				if result.Error != nil {
					fmt.Fprintf(errOut, "%s: %v\n", result.Relay, result.Error)
					continue
				}
				announceSucceeded++
				fmt.Fprintf(errOut, "%s: announcement published\n", result.Relay)
			}
			if announceSucceeded == 0 {
				return 1
			}
		}
	}
	if succeeded == 0 {
		return 1
	}
	return 0
}

// announceOutcome carries the --announce result through the dry-run/publish
// and text/JSON output paths uniformly, whether an announcement was actually
// built (Event/Nevent/Results) or skipped as already-announced (Skipped).
type announceOutcome struct {
	Event   *nostr.Event
	Nevent  string
	Results []relay.PublishResult
	Skipped bool
}

type publishJSONResult struct {
	Event        nostr.Event          `json:"event"`
	Naddr        string               `json:"naddr"`
	Published    bool                 `json:"published"`
	Relays       []publishRelayResult `json:"relays"`
	Attestation  *attestJSONResult    `json:"attestation,omitempty"`
	Announcement *announceJSONResult  `json:"announcement,omitempty"`
}

type publishRelayResult struct {
	Relay     string `json:"relay"`
	Published bool   `json:"published"`
	Error     string `json:"error,omitempty"`
}

type announceJSONResult struct {
	Skipped   bool                 `json:"skipped"`
	Event     *nostr.Event         `json:"event,omitempty"`
	Nevent    string               `json:"nevent,omitempty"`
	Published bool                 `json:"published"`
	Relays    []publishRelayResult `json:"relays"`
}

func writePublishJSON(out io.Writer, event nostr.Event, address string, results []relay.PublishResult, attestEvent *nostr.Event, attestAddress string, attestResults []relay.PublishResult, announceOut *announceOutcome) int {
	response := publishJSONResult{Event: event, Naddr: address, Relays: []publishRelayResult{}}
	for _, result := range results {
		relayResult := publishRelayResult{Relay: result.Relay, Published: result.Error == nil}
		if result.Error != nil {
			relayResult.Error = result.Error.Error()
		}
		response.Relays = append(response.Relays, relayResult)
		response.Published = response.Published || relayResult.Published
	}
	if attestEvent != nil {
		attestation := attestJSONResult{Event: *attestEvent, Naddr: attestAddress, Relays: []publishRelayResult{}}
		for _, result := range attestResults {
			relayResult := publishRelayResult{Relay: result.Relay, Published: result.Error == nil}
			if result.Error != nil {
				relayResult.Error = result.Error.Error()
			}
			attestation.Relays = append(attestation.Relays, relayResult)
			attestation.Published = attestation.Published || relayResult.Published
		}
		response.Attestation = &attestation
	}
	if announceOut != nil {
		announcement := announceJSONResult{Skipped: announceOut.Skipped, Event: announceOut.Event, Nevent: announceOut.Nevent, Relays: []publishRelayResult{}}
		for _, result := range announceOut.Results {
			relayResult := publishRelayResult{Relay: result.Relay, Published: result.Error == nil}
			if result.Error != nil {
				relayResult.Error = result.Error.Error()
			}
			announcement.Relays = append(announcement.Relays, relayResult)
			announcement.Published = announcement.Published || relayResult.Published
		}
		response.Announcement = &announcement
	}
	if err := json.NewEncoder(out).Encode(response); err != nil {
		return 1
	}
	if len(results) > 0 && !response.Published {
		return 1
	}
	if response.Attestation != nil && len(attestResults) > 0 && !response.Attestation.Published {
		return 1
	}
	if response.Announcement != nil && !response.Announcement.Skipped && len(announceOut.Results) > 0 && !response.Announcement.Published {
		return 1
	}
	return 0
}

func runInspect(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	flags.SetOutput(errOut)
	jsonOutput := flags.Bool("json", false, "emit machine-readable JSON")
	relayList := flags.String("relays", os.Getenv("NOSTR_YNH_RELAYS"), "comma-separated relay URLs")
	timeoutSeconds := relayTimeoutFlag(flags)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *timeoutSeconds <= 0 {
		fmt.Fprintln(errOut, "timeout-seconds must be positive")
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
	fetchCtx, cancel := context.WithTimeout(context.Background(), relayTimeout(*timeoutSeconds))
	defer cancel()
	event, err := client.FetchReplaceable(fetchCtx, protocol.AppDeclarationKind, pointer.PublicKey, pointer.Identifier)
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
	if *jsonOutput {
		if err := json.NewEncoder(out).Encode(declaration); err != nil {
			fmt.Fprintf(errOut, "write declaration: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(out, "app: %s (%s)\npublisher: %s\nrepository: %s\ncommit: %s\n", declaration.AppID, declaration.Version, declaration.Publisher, declaration.Repository, declaration.Commit)
	return 0
}

func runEndorse(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("endorse", flag.ContinueOnError)
	flags.SetOutput(errOut)
	claim := flags.String("claim", "recommend", "curation claim: recommend or tested")
	comment := flags.String("comment", "", "optional curator comment")
	privateKey := flags.String("private-key", os.Getenv("NOSTR_YNH_PRIVATE_KEY"), "curator private key")
	privateKeyFile := flags.String("private-key-file", "", "file containing the curator private key")
	relayList := flags.String("relays", os.Getenv("NOSTR_YNH_RELAYS"), "comma-separated relay URLs")
	timeoutSeconds := relayTimeoutFlag(flags)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *timeoutSeconds <= 0 {
		fmt.Fprintln(errOut, "timeout-seconds must be positive")
		return 2
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(errOut, "usage: nostr-ynh endorse [--claim recommend|tested] [--comment <text>] [--private-key <hex>|--private-key-file <path>] [--relays <ws://...,...>] <naddr>")
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
	if *privateKey == "" {
		fmt.Fprintln(errOut, "endorse requires --private-key (or --private-key-file/NOSTR_YNH_PRIVATE_KEY)")
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
	if *claim != "recommend" && *claim != "tested" {
		fmt.Fprintln(errOut, "claim must be recommend or tested")
		return 2
	}
	endorsement, err := curation.Build(pointer.PublicKey, pointer.Identifier, *claim, *comment, *privateKey)
	if err != nil {
		fmt.Fprintf(errOut, "build endorsement: %v\n", err)
		return 1
	}
	relayURLs := splitNonEmpty(*relayList)
	if len(relayURLs) == 0 {
		relayURLs = pointer.Relays
	}
	if len(relayURLs) == 0 {
		fmt.Fprintln(errOut, "endorse requires --relays (or relay hints in the naddr)")
		return 2
	}
	client, err := relay.New(context.Background(), relayURLs)
	if err != nil {
		fmt.Fprintf(errOut, "configure relays: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(out).Encode(endorsement); err != nil {
		fmt.Fprintf(errOut, "write event: %v\n", err)
		return 1
	}
	publishCtx, cancel := context.WithTimeout(context.Background(), relayTimeout(*timeoutSeconds))
	defer cancel()
	succeeded := 0
	for _, result := range client.Publish(publishCtx, endorsement) {
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

// runAttest turns an unsigned CI result (internal/ciresult, produced by e.g.
// .github/workflows/static-security.yml) into a signed kind-30080
// attestation event (internal/verification) and publishes it. It is meant
// to run both as a standalone step and directly inside the CI job that
// produced the result, per docs/attestation-trust-policy-plan.md Phase 4's
// "GitHub Action -> nostr-ynh attest -> signed Nostr attestation" flow -
// ciProvider/ciRef default to the invoking GitHub Actions run when not
// given explicitly, since the CI result schema itself deliberately doesn't
// carry them (docs/ci-result-schema.md).
func runAttest(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("attest", flag.ContinueOnError)
	flags.SetOutput(errOut)
	ciResultPath := flags.String("ci-result", "", "path to a ci-result.json (internal/ciresult schema)")
	ciProvider := flags.String("ci-provider", "", "CI system that produced the result, e.g. github-actions (auto-detected on GitHub Actions)")
	ciRef := flags.String("ci-ref", "", "CI run reference, e.g. a workflow run URL (auto-detected on GitHub Actions)")
	privateKey := flags.String("private-key", os.Getenv("NOSTR_YNH_PRIVATE_KEY"), "verifier private key")
	privateKeyFile := flags.String("private-key-file", "", "file containing the verifier private key")
	relayList := flags.String("relays", os.Getenv("NOSTR_YNH_RELAYS"), "comma-separated relay URLs")
	dryRun := flags.Bool("dry-run", false, "build and sign the event without publishing")
	jsonOutput := flags.Bool("json", false, "emit one machine-readable JSON result")
	timeoutSeconds := relayTimeoutFlag(flags)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *timeoutSeconds <= 0 {
		fmt.Fprintln(errOut, "timeout-seconds must be positive")
		return 2
	}
	if *ciResultPath == "" {
		fmt.Fprintln(errOut, "attest requires --ci-result <path>")
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
		fmt.Fprintln(errOut, "attest requires --private-key (or --private-key-file/NOSTR_YNH_PRIVATE_KEY) and --relays (or NOSTR_YNH_RELAYS), unless --dry-run is used")
		return 2
	}
	data, err := os.ReadFile(*ciResultPath)
	if err != nil {
		fmt.Fprintf(errOut, "read CI result: %v\n", err)
		return 1
	}
	result, err := ciresult.Parse(data)
	if err != nil {
		fmt.Fprintf(errOut, "invalid CI result: %v\n", err)
		return 1
	}
	provider, ref := *ciProvider, *ciRef
	if provider == "" || ref == "" {
		autoProvider, autoRef := githubActionsRun()
		if provider == "" {
			provider = autoProvider
		}
		if ref == "" {
			ref = autoRef
		}
	}
	if provider == "" || ref == "" {
		fmt.Fprintln(errOut, "attest requires --ci-provider and --ci-ref (could not auto-detect a CI run)")
		return 2
	}
	event, err := verification.Build(result.AppID, result.Repository, result.Commit, result.Manifest, result.Content, provider, ref, result.Checks, result.Result, *privateKey)
	if err != nil {
		fmt.Fprintf(errOut, "build attestation: %v\n", err)
		return 1
	}
	relayURLs := splitNonEmpty(*relayList)
	address, err := verification.Address(event, relayURLs)
	if err != nil {
		fmt.Fprintf(errOut, "encode attestation address: %v\n", err)
		return 1
	}
	if *dryRun {
		if *jsonOutput {
			return writeAttestJSON(out, event, address, nil)
		}
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
	publishCtx, cancel := context.WithTimeout(context.Background(), relayTimeout(*timeoutSeconds))
	defer cancel()
	results := client.Publish(publishCtx, event)
	if *jsonOutput {
		return writeAttestJSON(out, event, address, results)
	}
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

// githubActionsRun reports the current CI provider/reference from GitHub
// Actions' own environment, so `nostr-ynh attest` run as a workflow step
// needs no extra flags. Returns empty strings outside GitHub Actions.
func githubActionsRun() (provider, ref string) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return "", ""
	}
	server := os.Getenv("GITHUB_SERVER_URL")
	repo := os.Getenv("GITHUB_REPOSITORY")
	runID := os.Getenv("GITHUB_RUN_ID")
	if server == "" || repo == "" || runID == "" {
		return "github-actions", ""
	}
	return "github-actions", fmt.Sprintf("%s/%s/actions/runs/%s", server, repo, runID)
}

type attestJSONResult struct {
	Event     nostr.Event          `json:"event"`
	Naddr     string               `json:"naddr"`
	Published bool                 `json:"published"`
	Relays    []publishRelayResult `json:"relays"`
}

func writeAttestJSON(out io.Writer, event nostr.Event, address string, results []relay.PublishResult) int {
	response := attestJSONResult{Event: event, Naddr: address, Relays: []publishRelayResult{}}
	for _, result := range results {
		relayResult := publishRelayResult{Relay: result.Relay, Published: result.Error == nil}
		if result.Error != nil {
			relayResult.Error = result.Error.Error()
		}
		response.Relays = append(response.Relays, relayResult)
		response.Published = response.Published || relayResult.Published
	}
	if err := json.NewEncoder(out).Encode(response); err != nil {
		return 1
	}
	if len(results) > 0 && !response.Published {
		return 1
	}
	return 0
}

// runReverify independently re-checks a published attestation instead of
// trusting it: it re-fetches the attestation and the declaration it claims
// to cover from relays, cross-checks their app_id/repo/commit/manifest/
// content against each other, then clones the repository fresh at the
// attested commit and recomputes both hashes - the same repository.
// VerifyDeclaration path `publish` itself uses, just fed the attestation's
// claims instead of a local checkout. This is the "just in case the
// original has been manipulated" check: it catches a repo rewritten after
// attestation, or a declaration republished pointing at a different commit
// than what was attested, without requiring a second signing identity -
// see docs/attestations.md.
//
// The declaration is looked up under the attestation's own verifier pubkey,
// matching the self-attestation model (publish --ci-result signs both
// events with the same key): a future design with a separate verifier
// identity would need an explicit --publisher flag here instead.
func runReverify(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("reverify", flag.ContinueOnError)
	flags.SetOutput(errOut)
	relayList := flags.String("relays", os.Getenv("NOSTR_YNH_RELAYS"), "comma-separated relay URLs")
	jsonOutput := flags.Bool("json", false, "emit machine-readable JSON")
	timeoutSeconds := relayTimeoutFlag(flags)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *timeoutSeconds <= 0 {
		fmt.Fprintln(errOut, "timeout-seconds must be positive")
		return 2
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(errOut, "usage: nostr-ynh reverify [--json] [--relays <ws://...,...>] [--timeout-seconds <n>] <attestation-naddr>")
		return 2
	}
	prefix, value, err := nip19.Decode(flags.Arg(0))
	if err != nil || prefix != "naddr" {
		fmt.Fprintf(errOut, "decode naddr: %v\n", err)
		return 1
	}
	pointer, ok := value.(nostr.EntityPointer)
	if !ok || pointer.Kind != verification.AttestationKind {
		fmt.Fprintln(errOut, "naddr does not point to a CI attestation")
		return 1
	}
	relayURLs := splitNonEmpty(*relayList)
	if len(relayURLs) == 0 {
		relayURLs = pointer.Relays
	}
	if len(relayURLs) == 0 {
		fmt.Fprintln(errOut, "reverify requires --relays (or relay hints in the naddr)")
		return 2
	}
	client, err := relay.New(context.Background(), relayURLs)
	if err != nil {
		fmt.Fprintf(errOut, "configure relays: %v\n", err)
		return 1
	}

	fetchCtx, cancel := context.WithTimeout(context.Background(), relayTimeout(*timeoutSeconds))
	defer cancel()
	attestationEvent, err := client.FetchReplaceable(fetchCtx, verification.AttestationKind, pointer.PublicKey, pointer.Identifier)
	if err != nil {
		fmt.Fprintf(errOut, "fetch attestation: %v\n", err)
		return 1
	}
	if err := protocol.VerifyID(*attestationEvent); err != nil {
		fmt.Fprintf(errOut, "invalid attestation event ID: %v\n", err)
		return 1
	}
	if err := protocol.VerifySignature(*attestationEvent); err != nil {
		fmt.Fprintf(errOut, "invalid attestation signature: %v\n", err)
		return 1
	}
	attestation, err := verification.Parse(*attestationEvent)
	if err != nil {
		fmt.Fprintf(errOut, "invalid attestation: %v\n", err)
		return 1
	}

	declarationEvent, err := client.FetchReplaceable(fetchCtx, protocol.AppDeclarationKind, attestation.Verifier, attestation.AppID)
	if err != nil {
		fmt.Fprintf(errOut, "fetch declaration: %v\n", err)
		return 1
	}
	if err := protocol.VerifyID(*declarationEvent); err != nil {
		fmt.Fprintf(errOut, "invalid declaration event ID: %v\n", err)
		return 1
	}
	if err := protocol.VerifySignature(*declarationEvent); err != nil {
		fmt.Fprintf(errOut, "invalid declaration signature: %v\n", err)
		return 1
	}
	declaration, err := protocol.ParseAppDeclaration(*declarationEvent)
	if err != nil {
		fmt.Fprintf(errOut, "invalid declaration: %v\n", err)
		return 1
	}

	cloneCtx, cloneCancel := context.WithTimeout(context.Background(), relayTimeout(*timeoutSeconds))
	defer cloneCancel()
	result := reverify.Run(cloneCtx, attestation, declaration)

	if *jsonOutput {
		if err := json.NewEncoder(out).Encode(result); err != nil {
			fmt.Fprintf(errOut, "write result: %v\n", err)
			return 1
		}
		if !result.Match {
			return 1
		}
		return 0
	}

	fmt.Fprintf(out, "app: %s\nrepository: %s\ncommit: %s\npublisher/verifier: %s\nattested result: %s\n", attestation.AppID, attestation.Repository, attestation.Commit, attestation.Verifier, attestation.Result)
	if result.Match {
		fmt.Fprintln(out, "MATCH: declaration, attestation, and a fresh clone of the repository all agree")
		return 0
	}
	fmt.Fprintln(out, "MISMATCH:")
	for _, mismatch := range result.Mismatches {
		fmt.Fprintf(out, "  - %s\n", mismatch)
	}
	return 1
}

// defaultCatalogBudgetSeconds bounds the *entire* per-app verification loop
// in runCatalog, not just one app's git clone. Each declared app gets its
// own fresh --timeout-seconds deadline so one dead repo doesn't consume the
// whole budget alone, but a catalog can have many declared apps: several
// dead repos in a row, each burning its own full per-app timeout, can still
// sum to more than the external caller's own timeout (e.g. the MCP
// wrapper's 120s subprocess limit) even though every individual step is
// correctly bounded. This overall deadline caps the sum: once it expires,
// remaining declarations are skipped (reported, not silently dropped)
// rather than attempted.
const defaultCatalogBudgetSeconds = 60

func runCatalog(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("catalog", flag.ContinueOnError)
	flags.SetOutput(errOut)
	relayList := flags.String("relays", os.Getenv("NOSTR_YNH_RELAYS"), "comma-separated relay URLs")
	trustedList := flags.String("trusted-publishers", os.Getenv("NOSTR_YNH_TRUSTED_PUBLISHERS"), "comma-separated publisher hex keys or npubs")
	timeoutSeconds := relayTimeoutFlag(flags)
	budgetSeconds := flags.Int("budget-seconds", envIntOrDefault("NOSTR_YNH_CATALOG_BUDGET_SECONDS", defaultCatalogBudgetSeconds), "total deadline in seconds for verifying every declared app; declarations past it are skipped, not attempted")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *timeoutSeconds <= 0 {
		fmt.Fprintln(errOut, "timeout-seconds must be positive")
		return 2
	}
	if *budgetSeconds <= 0 {
		fmt.Fprintln(errOut, "budget-seconds must be positive")
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
	fetchCtx, cancel := context.WithTimeout(context.Background(), relayTimeout(*timeoutSeconds))
	defer cancel()
	events := client.FetchAppDeclarations(fetchCtx, policy.Publishers())

	verifyBudgetCtx, verifyBudgetCancel := context.WithTimeout(context.Background(), relayTimeout(*budgetSeconds))
	defer verifyBudgetCancel()
	store := catalog.NewStore(policy)
	for i, event := range events {
		if verifyBudgetCtx.Err() != nil {
			fmt.Fprintf(errOut, "skipping %d of %d declarations: verification budget (%ds) exhausted\n", len(events)-i, len(events), *budgetSeconds)
			break
		}
		// Each declared app gets its own fresh deadline (bounded by the
		// overall verification budget above): VerifyDeclaration clones the
		// declared repository at the declared commit, so one slow or
		// unreachable git host must not stall verification of every other
		// (perfectly fine) declaration in the catalogue.
		verifyCtx, verifyCancel := context.WithTimeout(verifyBudgetCtx, relayTimeout(*timeoutSeconds))
		err := store.IngestVerifiedPackage(verifyCtx, *event, repository.VerifyDeclaration)
		verifyCancel()
		if err != nil {
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

// runProfile publishes a kind-0 profile metadata event for the given key, so
// it resolves to a name/picture in ordinary Nostr clients instead of an
// opaque hex string - see docs/profile-and-announcements.md. It is meant to
// run once at setup and again whenever the profile changes; publishing again
// simply supersedes the previous profile per NIP-01 kind-0 semantics, no
// address or dedup ledger involved.
func runProfile(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("profile", flag.ContinueOnError)
	flags.SetOutput(errOut)
	name := flags.String("name", "", "publisher display name")
	about := flags.String("about", "", "short publisher bio")
	picture := flags.String("picture", "", "publisher avatar URL")
	nip05 := flags.String("nip05", "", "NIP-05 identifier, e.g. publisher@example.org")
	website := flags.String("website", "", "publisher homepage URL")
	privateKey := flags.String("private-key", os.Getenv("NOSTR_YNH_PRIVATE_KEY"), "Nostr publishing private key")
	privateKeyFile := flags.String("private-key-file", "", "file containing the Nostr publishing private key")
	relayList := flags.String("relays", os.Getenv("NOSTR_YNH_RELAYS"), "comma-separated relay URLs")
	dryRun := flags.Bool("dry-run", false, "build and sign the event without publishing")
	jsonOutput := flags.Bool("json", false, "emit one machine-readable JSON result")
	timeoutSeconds := relayTimeoutFlag(flags)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *timeoutSeconds <= 0 {
		fmt.Fprintln(errOut, "timeout-seconds must be positive")
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
		fmt.Fprintln(errOut, "profile requires --private-key (or NOSTR_YNH_PRIVATE_KEY) and --relays (or NOSTR_YNH_RELAYS), unless --dry-run is used")
		return 2
	}
	event, err := publisher.BuildProfile(publisher.Profile{
		Name:    *name,
		About:   *about,
		Picture: *picture,
		Nip05:   *nip05,
		Website: *website,
	}, *privateKey)
	if err != nil {
		fmt.Fprintf(errOut, "build profile: %v\n", err)
		return 1
	}
	relayURLs := splitNonEmpty(*relayList)
	nprofile, err := nip19.EncodeProfile(event.PubKey, relayURLs)
	if err != nil {
		fmt.Fprintf(errOut, "encode nprofile: %v\n", err)
		return 1
	}
	if *dryRun {
		if *jsonOutput {
			return writeProfileJSON(out, event, nprofile, nil)
		}
		if err := json.NewEncoder(out).Encode(event); err != nil {
			fmt.Fprintf(errOut, "write event: %v\n", err)
			return 1
		}
		fmt.Fprintf(errOut, "nprofile: %s\n", nprofile)
		return 0
	}
	client, err := relay.New(context.Background(), relayURLs)
	if err != nil {
		fmt.Fprintf(errOut, "configure relays: %v\n", err)
		return 1
	}
	publishCtx, cancel := context.WithTimeout(context.Background(), relayTimeout(*timeoutSeconds))
	defer cancel()
	results := client.Publish(publishCtx, event)
	if *jsonOutput {
		return writeProfileJSON(out, event, nprofile, results)
	}
	if err := json.NewEncoder(out).Encode(event); err != nil {
		fmt.Fprintf(errOut, "write event: %v\n", err)
		return 1
	}
	fmt.Fprintf(errOut, "nprofile: %s\n", nprofile)
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

type profileJSONResult struct {
	Event     nostr.Event          `json:"event"`
	Nprofile  string               `json:"nprofile"`
	Published bool                 `json:"published"`
	Relays    []publishRelayResult `json:"relays"`
}

func writeProfileJSON(out io.Writer, event nostr.Event, nprofile string, results []relay.PublishResult) int {
	response := profileJSONResult{Event: event, Nprofile: nprofile, Relays: []publishRelayResult{}}
	for _, result := range results {
		relayResult := publishRelayResult{Relay: result.Relay, Published: result.Error == nil}
		if result.Error != nil {
			relayResult.Error = result.Error.Error()
		}
		response.Relays = append(response.Relays, relayResult)
		response.Published = response.Published || relayResult.Published
	}
	if err := json.NewEncoder(out).Encode(response); err != nil {
		return 1
	}
	if len(results) > 0 && !response.Published {
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

// defaultRelayTimeoutSeconds bounds every relay-pool operation (fetch,
// publish, catalog listing). The pool fans out one goroutine per relay and
// waits for all of them (EOSE, ack, or error) before returning - a single
// relay that never completes (unreachable, hung, or simply slow) blocks the
// whole operation forever, since the pool has no internal deadline of its
// own. The caller must supply a bounded context or inherit that hang -
// previously surfaced to `catalog` callers as an external wrapper's own
// blunt subprocess timeout, with no partial results and no way to tell a
// slow relay from a broken one.
const defaultRelayTimeoutSeconds = 20

// relayTimeoutFlag registers the shared --timeout-seconds flag, defaulting
// to NOSTR_YNH_TIMEOUT_SECONDS or defaultRelayTimeoutSeconds.
func relayTimeoutFlag(flags *flag.FlagSet) *int {
	return flags.Int("timeout-seconds", envIntOrDefault("NOSTR_YNH_TIMEOUT_SECONDS", defaultRelayTimeoutSeconds), "relay operation deadline in seconds")
}

func relayTimeout(seconds int) time.Duration {
	return time.Duration(seconds) * time.Second
}

func envIntOrDefault(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "usage:")
	fmt.Fprintln(out, "  nostr-ynh verify [--json] <event.json>")
	fmt.Fprintln(out, "  nostr-ynh publish --private-key <hex>|--private-key-file <path> --relays <ws://...,...> [--repo <path>|--repository-url <url> --ref <ref>] [--ci-result <path> [--ci-provider <name>] [--ci-ref <ref>]] [--announce --announcement-ledger <path>] [--dry-run] [--json] [--timeout-seconds <n>]")
	fmt.Fprintln(out, "  nostr-ynh inspect [--json] [--relays <ws://...,...>] [--timeout-seconds <n>] <naddr>")
	fmt.Fprintln(out, "  nostr-ynh endorse [--claim recommend|tested] [--comment <text>] [--private-key <hex>|--private-key-file <path>] [--relays <ws://...,...>] [--timeout-seconds <n>] <naddr>")
	fmt.Fprintln(out, "  nostr-ynh attest --ci-result <path> [--ci-provider <name>] [--ci-ref <ref>] --private-key <hex>|--private-key-file <path> --relays <ws://...,...> [--dry-run] [--json] [--timeout-seconds <n>]")
	fmt.Fprintln(out, "  nostr-ynh reverify [--json] [--relays <ws://...,...>] [--timeout-seconds <n>] <attestation-naddr>")
	fmt.Fprintln(out, "  nostr-ynh catalog --relays <ws://...,...> --trusted-publishers <npub,...> [--timeout-seconds <n>] [--budget-seconds <n>]")
	fmt.Fprintln(out, "  nostr-ynh preview [--ref <branch|tag|commit>] <repository-url>")
	fmt.Fprintln(out, "  nostr-ynh keygen")
	fmt.Fprintln(out, "  nostr-ynh profile [--name <text>] [--about <text>] [--picture <url>] [--nip05 <name@domain>] [--website <url>] --private-key <hex>|--private-key-file <path> --relays <ws://...,...> [--dry-run] [--json] [--timeout-seconds <n>]")
	fmt.Fprintln(out, "  nostr-ynh version")
}
