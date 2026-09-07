package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
	"github.com/nostr-yunohost/nostr-yunohost/internal/verification"
)

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
