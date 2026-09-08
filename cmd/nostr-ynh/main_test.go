package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/imattau/nostr-yunohost/internal/protocol"
	"github.com/imattau/nostr-yunohost/internal/verification"
)

// newTestPackageRepo creates a minimal local _ynh package repo (a real git
// repo with one committed manifest.toml and an "origin" remote), the same
// shape runPublish reads via repository.ReadMetadata.
func newTestPackageRepo(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	manifest := "id = \"testapp\"\nversion = \"1.0.0~ynh1\"\nname = \"Test App\"\ndescription.en = \"A test app\"\n\n[integration]\narchitectures = [\"amd64\"]\n"
	if err := os.WriteFile(filepath.Join(directory, "manifest.toml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "test@example.invalid"},
		{"config", "user.name", "Test"},
		{"add", "manifest.toml"},
		{"commit", "-m", "test"},
		{"remote", "add", "origin", "https://github.com/example/testapp_ynh"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = directory
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v (%s)", args, err, out)
		}
	}
	return directory
}

// startBlackholeRelay starts a relay that completes the WebSocket handshake
// (so EnsureRelay's own internal connect timeout never applies) and reads
// the subscription request, but never answers it - no events, no EOSE,
// ever. This is the shape of relay that previously hung every relay-pool
// operation forever: reachable and responsive at the connection level, just
// never finishing what it was asked to do.
func startBlackholeRelay(t *testing.T) string {
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
			// Read the subscription request, then go silent forever.
			_, _, _ = conn.Read(r.Context())
			<-r.Context().Done()
		}),
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return "ws://" + listener.Addr().String()
}

func TestRunCatalogRespectsTimeoutAgainstAHungRelay(t *testing.T) {
	relayURL := startBlackholeRelay(t)
	var stdout, stderr bytes.Buffer

	start := time.Now()
	runCatalog([]string{"--relays", relayURL, "--timeout-seconds", "1"}, &stdout, &stderr)
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Fatalf("runCatalog blocked for %s against an unresponsive relay; want it bounded by --timeout-seconds (1s)", elapsed)
	}
}

func TestRunInspectRespectsTimeoutAgainstAHungRelay(t *testing.T) {
	relayURL := startBlackholeRelay(t)
	naddr, err := nip19.EncodeEntity(strings.Repeat("ab", 32), protocol.AppDeclarationKind, "example-app", nil)
	if err != nil {
		t.Fatalf("encode naddr: %v", err)
	}
	var stdout, stderr bytes.Buffer

	start := time.Now()
	runInspect([]string{"--relays", relayURL, "--timeout-seconds", "1", naddr}, &stdout, &stderr)
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Fatalf("runInspect blocked for %s against an unresponsive relay; want it bounded by --timeout-seconds (1s)", elapsed)
	}
}

func TestRunReverifyRespectsTimeoutAgainstAHungRelay(t *testing.T) {
	relayURL := startBlackholeRelay(t)
	naddr, err := nip19.EncodeEntity(strings.Repeat("ab", 32), verification.AttestationKind, "example-app:"+strings.Repeat("f", 40), nil)
	if err != nil {
		t.Fatalf("encode naddr: %v", err)
	}
	var stdout, stderr bytes.Buffer

	start := time.Now()
	runReverify([]string{"--relays", relayURL, "--timeout-seconds", "1", naddr}, &stdout, &stderr)
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Fatalf("runReverify blocked for %s against an unresponsive relay; want it bounded by --timeout-seconds (1s)", elapsed)
	}
}

func writeTestCIResult(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ci-result.json")
	body := []byte(`{
		"schema": 1,
		"app_id": "ditto",
		"repository": "https://github.com/example/ditto_ynh",
		"commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"manifest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"content": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"checks": {"yunohost_lint": "pass", "shellcheck": "pass"},
		"result": "pass"
	}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write CI result: %v", err)
	}
	return path
}

func TestRunAttestDryRunProducesValidAttestation(t *testing.T) {
	ciResultPath := writeTestCIResult(t)
	var stdout, stderr bytes.Buffer

	code := runAttest([]string{
		"--ci-result", ciResultPath,
		"--ci-provider", "github-actions",
		"--ci-ref", "https://github.com/example/ditto_ynh/actions/runs/1",
		"--private-key", strings.Repeat("a", 64),
		"--dry-run",
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runAttest exit code = %d, stderr = %s", code, stderr.String())
	}

	var response struct {
		Event     nostr.Event `json:"event"`
		Naddr     string      `json:"naddr"`
		Published bool        `json:"published"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("decode attest output: %v (stdout=%s)", err, stdout.String())
	}
	if response.Published {
		t.Fatal("dry-run reported published=true")
	}
	attestation, err := verification.Parse(response.Event)
	if err != nil {
		t.Fatalf("Parse() rejected the event runAttest produced: %v", err)
	}
	if attestation.AppID != "ditto" || attestation.CIProvider != "github-actions" || attestation.Result != "pass" {
		t.Fatalf("unexpected attestation: %+v", attestation)
	}
	if _, _, err := nip19.Decode(response.Naddr); err != nil {
		t.Fatalf("naddr does not decode: %v", err)
	}
}

func TestRunAttestRequiresCIResult(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runAttest([]string{"--private-key", strings.Repeat("a", 64), "--dry-run"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runAttest exit code = %d, want 2 (usage error) for missing --ci-result", code)
	}
}

func TestRunAttestRequiresCIProviderOutsideGitHubActions(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	ciResultPath := writeTestCIResult(t)
	var stdout, stderr bytes.Buffer
	code := runAttest([]string{"--ci-result", ciResultPath, "--private-key", strings.Repeat("a", 64), "--dry-run"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runAttest exit code = %d, want 2 (usage error) when ci-provider/ci-ref can't be determined", code)
	}
}

func TestRunAttestAutoDetectsGitHubActionsRun(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_REPOSITORY", "example/ditto_ynh")
	t.Setenv("GITHUB_RUN_ID", "42")
	ciResultPath := writeTestCIResult(t)
	var stdout, stderr bytes.Buffer

	code := runAttest([]string{
		"--ci-result", ciResultPath,
		"--private-key", strings.Repeat("a", 64),
		"--dry-run",
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runAttest exit code = %d, stderr = %s", code, stderr.String())
	}
	var response struct {
		Event nostr.Event `json:"event"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("decode attest output: %v", err)
	}
	attestation, err := verification.Parse(response.Event)
	if err != nil {
		t.Fatalf("Parse() rejected the event: %v", err)
	}
	if attestation.CIProvider != "github-actions" || attestation.CIRef != "https://github.com/example/ditto_ynh/actions/runs/42" {
		t.Fatalf("unexpected auto-detected CI fields: provider=%q ref=%q", attestation.CIProvider, attestation.CIRef)
	}
}

type publishJSONTestResult struct {
	Event       nostr.Event `json:"event"`
	Naddr       string      `json:"naddr"`
	Published   bool        `json:"published"`
	Attestation *struct {
		Event     nostr.Event `json:"event"`
		Naddr     string      `json:"naddr"`
		Published bool        `json:"published"`
	} `json:"attestation,omitempty"`
	Announcement *struct {
		Skipped   bool         `json:"skipped"`
		Event     *nostr.Event `json:"event,omitempty"`
		Nevent    string       `json:"nevent,omitempty"`
		Published bool         `json:"published"`
	} `json:"announcement,omitempty"`
}

// TestRunPublishWithCIResultProducesMatchingAttestation is the actual
// "publisher attests" flow: one `publish --ci-result` call signs both the
// declaration and its CI attestation with the same key, for the same
// revision, in one shot.
func TestRunPublishWithCIResultProducesMatchingAttestation(t *testing.T) {
	repo := newTestPackageRepo(t)
	privateKey := strings.Repeat("b", 64)

	// First pass, no --ci-result: get this exact revision's real
	// app_id/repo/commit/manifest/content, since ci-result.json must match
	// them precisely (that's the point of the cross-check).
	var declOut, declErr bytes.Buffer
	if code := runPublish([]string{"--repo", repo, "--private-key", privateKey, "--dry-run", "--json"}, &declOut, &declErr); code != 0 {
		t.Fatalf("runPublish (no ci-result) exit code = %d, stderr = %s", code, declErr.String())
	}
	var decl publishJSONTestResult
	if err := json.Unmarshal(declOut.Bytes(), &decl); err != nil {
		t.Fatalf("decode publish output: %v", err)
	}
	tags := map[string]string{}
	for _, tag := range decl.Event.Tags {
		if len(tag) >= 2 {
			tags[tag[0]] = tag[1]
		}
	}

	ciResultPath := filepath.Join(t.TempDir(), "ci-result.json")
	ciResult := map[string]any{
		"schema":     1,
		"app_id":     tags["d"],
		"repository": tags["repo"],
		"commit":     tags["commit"],
		"manifest":   tags["manifest"],
		"content":    tags["content"],
		"checks":     map[string]string{"yunohost_lint": "pass", "shellcheck": "pass"},
		"result":     "pass",
	}
	body, err := json.Marshal(ciResult)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ciResultPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runPublish([]string{
		"--repo", repo,
		"--private-key", privateKey,
		"--dry-run", "--json",
		"--ci-result", ciResultPath,
		"--ci-provider", "github-actions",
		"--ci-ref", "https://github.com/example/testapp_ynh/actions/runs/1",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runPublish (with ci-result) exit code = %d, stderr = %s", code, stderr.String())
	}

	var response publishJSONTestResult
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("decode publish output: %v (stdout=%s)", err, stdout.String())
	}
	if response.Attestation == nil {
		t.Fatal("expected an attestation in the response, got none")
	}
	if response.Attestation.Event.PubKey != response.Event.PubKey {
		t.Fatalf("attestation signed by a different key than the declaration: declaration=%s attestation=%s",
			response.Event.PubKey, response.Attestation.Event.PubKey)
	}
	attestation, err := verification.Parse(response.Attestation.Event)
	if err != nil {
		t.Fatalf("Parse() rejected the attestation runPublish produced: %v", err)
	}
	if attestation.AppID != tags["d"] || attestation.Commit != tags["commit"] || attestation.Result != "pass" {
		t.Fatalf("unexpected attestation: %+v", attestation)
	}
	if _, _, err := nip19.Decode(response.Attestation.Naddr); err != nil {
		t.Fatalf("attestation naddr does not decode: %v", err)
	}
}

// TestRunPublishRefusesMismatchedCIResult is the safety property that makes
// the combined flow trustworthy: a --ci-result for the wrong revision must
// never get folded into a valid-looking attestation for whatever happens to
// be checked out right now.
func TestRunPublishRefusesMismatchedCIResult(t *testing.T) {
	repo := newTestPackageRepo(t)
	ciResultPath := writeTestCIResult(t) // app_id "ditto", unrelated commit/hashes
	var stdout, stderr bytes.Buffer

	code := runPublish([]string{
		"--repo", repo,
		"--private-key", strings.Repeat("c", 64),
		"--dry-run", "--json",
		"--ci-result", ciResultPath,
		"--ci-provider", "github-actions",
		"--ci-ref", "https://github.com/example/ditto_ynh/actions/runs/1",
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("runPublish accepted a --ci-result for a different app/commit; stdout=%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "does not match the revision being published") {
		t.Fatalf("unexpected error for mismatched ci-result: %s", stderr.String())
	}
}

// TestRunPublishWithoutCIResultIsUnchanged is a cheap regression guard: the
// new --ci-result plumbing must not alter existing publish-only behavior or
// output shape when the flag is simply omitted.
func TestRunPublishWithoutCIResultIsUnchanged(t *testing.T) {
	repo := newTestPackageRepo(t)
	var stdout, stderr bytes.Buffer

	code := runPublish([]string{"--repo", repo, "--private-key", strings.Repeat("d", 64), "--dry-run", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runPublish exit code = %d, stderr = %s", code, stderr.String())
	}
	var response publishJSONTestResult
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("decode publish output: %v", err)
	}
	if response.Attestation != nil {
		t.Fatal("expected no attestation when --ci-result is omitted")
	}
	if response.Announcement != nil {
		t.Fatal("expected no announcement when --announce is omitted")
	}
}

// startAcceptingRelay starts a relay that completes the WebSocket handshake
// and answers any EVENT it receives with an OK acceptance, so a non-dry-run
// publish actually succeeds - the same shape internal/attestation's own test
// helper of the same name uses, needed here because --announce's ledger is
// only written after a real, successful relay publish.
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
			for {
				_, data, err := conn.Read(r.Context())
				if err != nil {
					return
				}
				var message []json.RawMessage
				if json.Unmarshal(data, &message) != nil || len(message) < 2 {
					continue
				}
				var kind string
				if json.Unmarshal(message[0], &kind) != nil || kind != "EVENT" {
					continue
				}
				var event nostr.Event
				if json.Unmarshal(message[1], &event) != nil {
					continue
				}
				reply, err := json.Marshal([]any{"OK", event.ID, true, ""})
				if err != nil {
					return
				}
				if conn.Write(r.Context(), websocket.MessageText, reply) != nil {
					return
				}
			}
		}),
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return "ws://" + listener.Addr().String()
}

func TestRunPublishAnnounceRequiresLedger(t *testing.T) {
	repo := newTestPackageRepo(t)
	var stdout, stderr bytes.Buffer
	code := runPublish([]string{"--repo", repo, "--private-key", strings.Repeat("e", 64), "--dry-run", "--announce"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runPublish exit code = %d, want 2 (usage error) for --announce without --announcement-ledger", code)
	}
}

func TestRunPublishDryRunAnnouncesNewRevision(t *testing.T) {
	repo := newTestPackageRepo(t)
	ledgerPath := filepath.Join(t.TempDir(), "announcements.json")
	var stdout, stderr bytes.Buffer
	code := runPublish([]string{
		"--repo", repo,
		"--private-key", strings.Repeat("e", 64),
		"--dry-run", "--json",
		"--announce", "--announcement-ledger", ledgerPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runPublish exit code = %d, stderr = %s", code, stderr.String())
	}
	var response publishJSONTestResult
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("decode publish output: %v (stdout=%s)", err, stdout.String())
	}
	if response.Announcement == nil {
		t.Fatal("expected an announcement in the response, got none")
	}
	if response.Announcement.Skipped {
		t.Fatal("a never-announced revision must not be reported as skipped")
	}
	if response.Announcement.Event == nil {
		t.Fatal("expected a signed announcement event")
	}
	if response.Announcement.Event.Kind != protocol.NoteKind {
		t.Fatalf("announcement Kind = %d, want %d", response.Announcement.Event.Kind, protocol.NoteKind)
	}
	if response.Announcement.Event.PubKey != response.Event.PubKey {
		t.Fatalf("announcement signed by a different key than the declaration: declaration=%s announcement=%s",
			response.Event.PubKey, response.Announcement.Event.PubKey)
	}
	if err := protocol.VerifySignature(*response.Announcement.Event); err != nil {
		t.Fatalf("VerifySignature() on announcement error = %v", err)
	}
	// A dry run never actually publishes anything, so it must not touch the
	// ledger either - only a real, successful publish should record one.
	if _, err := os.Stat(ledgerPath); err == nil {
		t.Fatal("--dry-run --announce must not write the announcement ledger")
	}
}

func TestRunPublishDryRunSkipsAlreadyAnnouncedRevision(t *testing.T) {
	repo := newTestPackageRepo(t)
	privateKey := strings.Repeat("e", 64)

	var declOut, declErr bytes.Buffer
	if code := runPublish([]string{"--repo", repo, "--private-key", privateKey, "--dry-run", "--json"}, &declOut, &declErr); code != 0 {
		t.Fatalf("runPublish (no announce) exit code = %d, stderr = %s", code, declErr.String())
	}
	var decl publishJSONTestResult
	if err := json.Unmarshal(declOut.Bytes(), &decl); err != nil {
		t.Fatalf("decode publish output: %v", err)
	}
	appID, commit := decl.Event.Tags.GetD(), decl.Event.Tags.GetFirst([]string{"commit"}).Value()

	ledgerPath := filepath.Join(t.TempDir(), "announcements.json")
	body, err := json.Marshal([]map[string]any{{
		"app_id":       appID,
		"commit":       commit,
		"version":      "1.0.0~ynh1",
		"announced_at": 1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ledgerPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runPublish([]string{
		"--repo", repo,
		"--private-key", privateKey,
		"--dry-run", "--json",
		"--announce", "--announcement-ledger", ledgerPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runPublish exit code = %d, stderr = %s", code, stderr.String())
	}
	var response publishJSONTestResult
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("decode publish output: %v (stdout=%s)", err, stdout.String())
	}
	if response.Announcement == nil || !response.Announcement.Skipped {
		t.Fatalf("expected a skipped announcement for an already-announced app_id/commit, got %+v", response.Announcement)
	}
	if response.Announcement.Event != nil {
		t.Fatal("a skipped announcement must not carry an event")
	}
}

// TestRunPublishAnnounceOnlyRecordsAfterARealPublish is the end-to-end
// dedup property: a second, non-dry-run publish --announce for the exact
// same commit must not post a second note, because the first call's
// successful relay publish already recorded it in the ledger.
func TestRunPublishAnnounceOnlyRecordsAfterARealPublish(t *testing.T) {
	repo := newTestPackageRepo(t)
	privateKey := strings.Repeat("f", 64)
	relayURL := startAcceptingRelay(t)
	ledgerPath := filepath.Join(t.TempDir(), "announcements.json")

	var firstOut, firstErr bytes.Buffer
	code := runPublish([]string{
		"--repo", repo,
		"--private-key", privateKey,
		"--relays", relayURL,
		"--json",
		"--announce", "--announcement-ledger", ledgerPath,
	}, &firstOut, &firstErr)
	if code != 0 {
		t.Fatalf("first runPublish exit code = %d, stderr = %s", code, firstErr.String())
	}
	var first publishJSONTestResult
	if err := json.Unmarshal(firstOut.Bytes(), &first); err != nil {
		t.Fatalf("decode first publish output: %v", err)
	}
	if first.Announcement == nil || first.Announcement.Skipped || !first.Announcement.Published {
		t.Fatalf("expected the first publish to announce and succeed, got %+v", first.Announcement)
	}

	var secondOut, secondErr bytes.Buffer
	code = runPublish([]string{
		"--repo", repo,
		"--private-key", privateKey,
		"--relays", relayURL,
		"--json",
		"--announce", "--announcement-ledger", ledgerPath,
	}, &secondOut, &secondErr)
	if code != 0 {
		t.Fatalf("second runPublish exit code = %d, stderr = %s", code, secondErr.String())
	}
	var second publishJSONTestResult
	if err := json.Unmarshal(secondOut.Bytes(), &second); err != nil {
		t.Fatalf("decode second publish output: %v", err)
	}
	if second.Announcement == nil || !second.Announcement.Skipped {
		t.Fatalf("expected the second publish for the same commit to skip announcing, got %+v", second.Announcement)
	}
}

func TestRunProfileDryRun(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runProfile([]string{
		"--name", "Example Publisher",
		"--about", "Publishes YunoHost packages",
		"--nip05", "publisher@example.org",
		"--private-key", strings.Repeat("a", 64),
		"--dry-run", "--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runProfile exit code = %d, stderr = %s", code, stderr.String())
	}
	var response struct {
		Event    nostr.Event `json:"event"`
		Nprofile string      `json:"nprofile"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("decode profile output: %v (stdout=%s)", err, stdout.String())
	}
	if response.Event.Kind != protocol.ProfileKind {
		t.Fatalf("Kind = %d, want %d", response.Event.Kind, protocol.ProfileKind)
	}
	if err := protocol.VerifySignature(response.Event); err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}
	if !strings.Contains(response.Event.Content, "Example Publisher") {
		t.Fatalf("profile content missing name: %q", response.Event.Content)
	}
	if _, _, err := nip19.Decode(response.Nprofile); err != nil {
		t.Fatalf("nprofile does not decode: %v", err)
	}
}

func TestRunProfileRequiresPrivateKey(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runProfile([]string{"--name", "Example", "--dry-run"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runProfile exit code = %d, want 2 (usage error) for missing private key", code)
	}
}
