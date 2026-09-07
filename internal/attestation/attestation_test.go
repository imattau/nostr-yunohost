package attestation

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nostr-yunohost/nostr-yunohost/internal/localstate"
	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
	"github.com/nostr-yunohost/nostr-yunohost/internal/relay"
)

const (
	selfKey   = "1111111111111111111111111111111111111111111111111111111111111a"
	otherKey  = "2222222222222222222222222222222222222222222222222222222222222b"
	fakeRepoA = "https://example.com/repo-a"
)

// startAcceptingRelay starts a relay that completes the WebSocket handshake
// and answers any EVENT it receives with an OK acceptance, mirroring the
// real trip a signed endorsement takes through internal/relay.Client.Publish
// - a real in-process relay rather than a mock, per this project's existing
// testing convention (see cmd/nostr-ynh/main_test.go's startBlackholeRelay).
func startAcceptingRelay(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			var message []json.RawMessage
			if err := wsjson.Read(r.Context(), conn, &message); err != nil {
				return
			}
			var kind, eventID string
			if len(message) < 2 || json.Unmarshal(message[0], &kind) != nil || kind != "EVENT" {
				return
			}
			var event nostr.Event
			if json.Unmarshal(message[1], &event) != nil {
				return
			}
			eventID = event.ID
			_ = wsjson.Write(r.Context(), conn, []any{"OK", eventID, true, ""})
		}),
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return "ws://" + listener.Addr().String()
}

func selfPublisher(t *testing.T) string {
	t.Helper()
	pub, err := nostr.GetPublicKey(selfKey)
	if err != nil {
		t.Fatalf("derive self pubkey: %v", err)
	}
	return pub
}

func otherPublisher(t *testing.T) string {
	t.Helper()
	pub, err := nostr.GetPublicKey(otherKey)
	if err != nil {
		t.Fatalf("derive other pubkey: %v", err)
	}
	return pub
}

func TestCandidatesExcludesSelfPublisher(t *testing.T) {
	self := selfPublisher(t)
	declarations := []protocol.AppDeclaration{
		{AppID: "own_app", Publisher: self, Repository: fakeRepoA, Version: "1.0"},
	}
	installed := []localstate.InstalledApp{{AppID: "own_app", Repository: fakeRepoA}}
	candidates := Candidates(declarations, installed, self, nil)
	if len(candidates) != 0 {
		t.Fatalf("expected no candidates for self-published app, got %v", candidates)
	}
}

func TestCandidatesRequiresInstalledMatch(t *testing.T) {
	self := selfPublisher(t)
	other := otherPublisher(t)
	declarations := []protocol.AppDeclaration{
		{AppID: "not_installed", Publisher: other, Repository: fakeRepoA, Version: "1.0"},
	}
	candidates := Candidates(declarations, nil, self, nil)
	if len(candidates) != 0 {
		t.Fatalf("expected no candidates without a matching installed app, got %v", candidates)
	}
}

func TestCandidatesMatchesOtherPublisherInstalledApp(t *testing.T) {
	self := selfPublisher(t)
	other := otherPublisher(t)
	declarations := []protocol.AppDeclaration{
		{AppID: "hello_nostr", Publisher: other, Repository: fakeRepoA + "/", Version: "1.0"},
	}
	installed := []localstate.InstalledApp{{AppID: "hello_nostr", Repository: fakeRepoA}}
	candidates := Candidates(declarations, installed, self, nil)
	if len(candidates) != 1 {
		t.Fatalf("expected exactly one candidate, got %v", candidates)
	}
	if candidates[0].Publisher != other || candidates[0].AppID != "hello_nostr" {
		t.Fatalf("unexpected candidate: %+v", candidates[0])
	}
	if candidates[0].Attested {
		t.Fatalf("expected candidate not yet attested: %+v", candidates[0])
	}
}

func TestCandidatesRequiresMatchingAppID(t *testing.T) {
	self := selfPublisher(t)
	other := otherPublisher(t)
	declarations := []protocol.AppDeclaration{
		{AppID: "wrong_id", Publisher: other, Repository: fakeRepoA, Version: "1.0"},
	}
	installed := []localstate.InstalledApp{{AppID: "hello_nostr", Repository: fakeRepoA}}
	candidates := Candidates(declarations, installed, self, nil)
	if len(candidates) != 0 {
		t.Fatalf("expected no candidate when app IDs disagree, got %v", candidates)
	}
}

func TestCandidatesReflectsLedger(t *testing.T) {
	self := selfPublisher(t)
	other := otherPublisher(t)
	declarations := []protocol.AppDeclaration{
		{AppID: "hello_nostr", Publisher: other, Repository: fakeRepoA, Version: "1.0"},
	}
	installed := []localstate.InstalledApp{{AppID: "hello_nostr", Repository: fakeRepoA}}
	ledger, err := LoadLedger(filepath.Join(t.TempDir(), "ledger.json"))
	if err != nil {
		t.Fatalf("LoadLedger: %v", err)
	}
	if err := ledger.Record(other, "hello_nostr", "tested", "1.0"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	candidates := Candidates(declarations, installed, self, ledger)
	if len(candidates) != 1 || !candidates[0].Attested {
		t.Fatalf("expected the recorded candidate to show attested, got %v", candidates)
	}
	if candidates[0].AttestedVersion != "1.0" || candidates[0].AttestedAt == 0 {
		t.Fatalf("expected attested version/timestamp to be surfaced, got %+v", candidates[0])
	}
}

func TestCandidatesReattestableAfterVersionBump(t *testing.T) {
	self := selfPublisher(t)
	other := otherPublisher(t)
	// The publisher has since declared a newer version than what this
	// server attested to.
	declarations := []protocol.AppDeclaration{
		{AppID: "hello_nostr", Publisher: other, Repository: fakeRepoA, Version: "2.0"},
	}
	installed := []localstate.InstalledApp{{AppID: "hello_nostr", Repository: fakeRepoA}}
	ledger, err := LoadLedger(filepath.Join(t.TempDir(), "ledger.json"))
	if err != nil {
		t.Fatalf("LoadLedger: %v", err)
	}
	if err := ledger.Record(other, "hello_nostr", "tested", "1.0"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	candidates := Candidates(declarations, installed, self, ledger)
	if len(candidates) != 1 {
		t.Fatalf("expected exactly one candidate, got %v", candidates)
	}
	if candidates[0].Attested {
		t.Fatalf("expected a newer declared version to re-surface as attestable, got %+v", candidates[0])
	}
	if candidates[0].AttestedVersion != "1.0" {
		t.Fatalf("expected the prior attested version to still be reported, got %+v", candidates[0])
	}
}

func TestLedgerPersistsAcrossLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.json")
	ledger, err := LoadLedger(path)
	if err != nil {
		t.Fatalf("LoadLedger: %v", err)
	}
	if err := ledger.Record("pub", "app", "recommend", "1.0"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	reloaded, err := LoadLedger(path)
	if err != nil {
		t.Fatalf("LoadLedger reload: %v", err)
	}
	if !reloaded.HasAttested("pub", "app", "1.0") {
		t.Fatal("expected reloaded ledger to retain the recorded attestation")
	}
}

func TestLedgerHistoryOrdersMostRecentFirst(t *testing.T) {
	ledger, err := LoadLedger(filepath.Join(t.TempDir(), "ledger.json"))
	if err != nil {
		t.Fatalf("LoadLedger: %v", err)
	}
	if err := ledger.Record("pub", "app", "recommend", "1.0"); err != nil {
		t.Fatalf("Record v1.0: %v", err)
	}
	time.Sleep(1100 * time.Millisecond) // AttestedAt has second resolution
	if err := ledger.Record("pub", "app", "tested", "2.0"); err != nil {
		t.Fatalf("Record v2.0: %v", err)
	}
	history := ledger.History()
	if len(history) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(history))
	}
	if history[0].Version != "2.0" || history[1].Version != "1.0" {
		t.Fatalf("expected history most-recent-first, got %+v", history)
	}
}

func TestPublisherAttestSignsPublishesAndRecords(t *testing.T) {
	other := otherPublisher(t)
	relayURL := startAcceptingRelay(t)
	ctx := context.Background()
	client, err := relay.New(ctx, []string{relayURL})
	if err != nil {
		t.Fatalf("relay.New: %v", err)
	}
	ledger, err := LoadLedger(filepath.Join(t.TempDir(), "ledger.json"))
	if err != nil {
		t.Fatalf("LoadLedger: %v", err)
	}
	publisher := &Publisher{Client: client, PrivateKey: selfKey, Ledger: ledger}

	results, err := publisher.Attest(ctx, other, "hello_nostr", "tested", "works great", "1.0")
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if len(results) != 1 || results[0].Error != nil {
		t.Fatalf("expected one successful publish result, got %v", results)
	}
	if !ledger.HasAttested(other, "hello_nostr", "1.0") {
		t.Fatal("expected ledger to reflect the recorded attestation")
	}

	// Attesting again for the same claim/version must not duplicate the
	// ledger entry.
	if _, err := publisher.Attest(ctx, other, "hello_nostr", "tested", "still works", "1.0"); err != nil {
		t.Fatalf("second Attest: %v", err)
	}
	if len(ledger.History()) != 1 {
		t.Fatalf("expected the duplicate attestation not to add a second history entry, got %v", ledger.History())
	}
}

func TestPublisherAttestDoesNotRecordOnTotalPublishFailure(t *testing.T) {
	other := otherPublisher(t)
	ctx := context.Background()
	// A relay URL nothing listens on: relay.New accepts it (it only
	// validates scheme/host), but publishing will fail once dialed.
	client, err := relay.New(ctx, []string{"ws://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("relay.New: %v", err)
	}
	ledger, err := LoadLedger(filepath.Join(t.TempDir(), "ledger.json"))
	if err != nil {
		t.Fatalf("LoadLedger: %v", err)
	}
	publisher := &Publisher{Client: client, PrivateKey: selfKey, Ledger: ledger}

	if _, err := publisher.Attest(ctx, other, "hello_nostr", "tested", "", "1.0"); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if ledger.HasAttested(other, "hello_nostr", "1.0") {
		t.Fatal("a total publish failure must not be recorded, so the admin page can offer a retry")
	}
}

func TestPublisherAttestRejectsInvalidPublisher(t *testing.T) {
	ledger, err := LoadLedger(filepath.Join(t.TempDir(), "ledger.json"))
	if err != nil {
		t.Fatalf("LoadLedger: %v", err)
	}
	publisher := &Publisher{Client: nil, PrivateKey: selfKey, Ledger: ledger}
	if _, err := publisher.Attest(context.Background(), "not-a-pubkey", "hello_nostr", "tested", "", "1.0"); err == nil {
		t.Fatal("expected an error for an invalid publisher key")
	}
	if ledger.HasAttested("not-a-pubkey", "hello_nostr", "1.0") {
		t.Fatal("a failed build must not be recorded in the ledger")
	}
}
