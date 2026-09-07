package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nbd-wtf/go-nostr"

	"github.com/nostr-yunohost/nostr-yunohost/internal/attestation"
	"github.com/nostr-yunohost/nostr-yunohost/internal/catalog"
	"github.com/nostr-yunohost/nostr-yunohost/internal/relay"
	"github.com/nostr-yunohost/nostr-yunohost/internal/trust"
)

const (
	adminTestSelfKey  = "1111111111111111111111111111111111111111111111111111111111111a"
	adminTestOtherKey = "2222222222222222222222222222222222222222222222222222222222222b"
)

// newTestAdminServer builds an adminServer with a real Store containing one
// declaration from a different publisher, an installed-app snapshot that
// matches it, and a relay client pointed at nothing (publish is only
// exercised by internal/attestation's own tests) - enough to exercise the
// HTTP handlers' candidate computation and CSRF/validation logic without a
// live relay.
func newTestAdminServer(t *testing.T) *adminServer {
	t.Helper()
	other, err := nostr.GetPublicKey(adminTestOtherKey)
	if err != nil {
		t.Fatalf("derive other pubkey: %v", err)
	}
	self, err := nostr.GetPublicKey(adminTestSelfKey)
	if err != nil {
		t.Fatalf("derive self pubkey: %v", err)
	}

	policy, err := trust.NewExplicitPublishers([]string{other})
	if err != nil {
		t.Fatalf("trust.NewExplicitPublishers: %v", err)
	}
	store := catalog.NewStore(policy)
	event := nostr.Event{
		PubKey: other, CreatedAt: 1, Kind: 30078,
		Tags: nostr.Tags{
			{"d", "hello_nostr"}, {"platform", "yunohost"},
			{"repo", "https://example.com/hello_nostr"}, {"version", "1.0.0~ynh1"},
			{"commit", "cccccccccccccccccccccccccccccccccccccccc"},
			{"manifest", "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
			{"content", "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
		},
		Content: "{}",
	}
	if err := event.Sign(adminTestOtherKey); err != nil {
		t.Fatalf("sign fixture event: %v", err)
	}
	if err := store.Ingest(event); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	dir := t.TempDir()
	installedAppsFile := filepath.Join(dir, "installed-apps.json")
	installedData, err := json.Marshal(map[string]any{
		"apps": []map[string]string{{"app_id": "hello_nostr", "repository": "https://example.com/hello_nostr"}},
	})
	if err != nil {
		t.Fatalf("marshal installed apps: %v", err)
	}
	if err := os.WriteFile(installedAppsFile, installedData, 0o640); err != nil {
		t.Fatalf("write installed apps: %v", err)
	}

	ledger, err := attestation.LoadLedger(filepath.Join(dir, "ledger.json"))
	if err != nil {
		t.Fatalf("LoadLedger: %v", err)
	}
	client, err := relay.New(t.Context(), []string{"ws://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("relay.New: %v", err)
	}

	return &adminServer{
		store:         store,
		publisher:     &attestation.Publisher{Client: client, PrivateKey: adminTestSelfKey, Ledger: ledger},
		ledger:        ledger,
		selfPublisher: self,
		installedPath: installedAppsFile,
	}
}

func TestHandleAttestableReturnsCandidateAndCSRFToken(t *testing.T) {
	server := httptest.NewServer(newTestAdminServer(t).mux())
	defer server.Close()

	response, err := http.Get(server.URL + "/admin/attestable")
	if err != nil {
		t.Fatalf("GET /admin/attestable: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}
	var body attestableResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.CSRFToken == "" {
		t.Fatal("expected a CSRF token")
	}
	if len(body.Candidates) != 1 || body.Candidates[0].AppID != "hello_nostr" {
		t.Fatalf("unexpected candidates: %+v", body.Candidates)
	}
	var cookieFound bool
	for _, cookie := range response.Cookies() {
		if cookie.Name == csrfCookieName {
			cookieFound = true
		}
	}
	if !cookieFound {
		t.Fatal("expected a CSRF cookie to be set")
	}
}

func TestHandleAttestRejectsMissingCSRF(t *testing.T) {
	server := httptest.NewServer(newTestAdminServer(t).mux())
	defer server.Close()

	body, _ := json.Marshal(attestRequest{AppID: "hello_nostr", Claim: "tested"})
	response, err := http.Post(server.URL+"/admin/attest", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /admin/attest: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 without a CSRF token, got %d", response.StatusCode)
	}
}

func TestHandleAttestRejectsNonCandidateTarget(t *testing.T) {
	server := httptest.NewServer(newTestAdminServer(t).mux())
	defer server.Close()

	client := &http.Client{}
	attestable, err := client.Get(server.URL + "/admin/attestable")
	if err != nil {
		t.Fatalf("GET /admin/attestable: %v", err)
	}
	var listing attestableResponse
	if err := json.NewDecoder(attestable.Body).Decode(&listing); err != nil {
		t.Fatalf("decode listing: %v", err)
	}
	attestable.Body.Close()
	var csrfCookie *http.Cookie
	for _, cookie := range attestable.Cookies() {
		if cookie.Name == csrfCookieName {
			csrfCookie = cookie
		}
	}
	if csrfCookie == nil {
		t.Fatal("expected a CSRF cookie")
	}

	// A publisher/app pair this server never computed as a candidate must be
	// rejected even with a valid CSRF token, so the request body can never
	// name an arbitrary attestation target.
	requestBody, _ := json.Marshal(attestRequest{AppID: "not_a_candidate", Publisher: "deadbeef", Claim: "tested"})
	request, err := http.NewRequest(http.MethodPost, server.URL+"/admin/attest", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrfCookie.Value)
	request.AddCookie(csrfCookie)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST /admin/attest: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for a non-candidate target, got %d", response.StatusCode)
	}
}

func TestHandleAttestRejectsInvalidClaim(t *testing.T) {
	server := httptest.NewServer(newTestAdminServer(t).mux())
	defer server.Close()

	client := &http.Client{}
	attestable, err := client.Get(server.URL + "/admin/attestable")
	if err != nil {
		t.Fatalf("GET /admin/attestable: %v", err)
	}
	var csrfCookie *http.Cookie
	for _, cookie := range attestable.Cookies() {
		if cookie.Name == csrfCookieName {
			csrfCookie = cookie
		}
	}
	attestable.Body.Close()
	if csrfCookie == nil {
		t.Fatal("expected a CSRF cookie")
	}

	requestBody, _ := json.Marshal(attestRequest{AppID: "hello_nostr", Publisher: "irrelevant", Claim: "spam"})
	request, err := http.NewRequest(http.MethodPost, server.URL+"/admin/attest", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrfCookie.Value)
	request.AddCookie(csrfCookie)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST /admin/attest: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for an invalid claim, got %d", response.StatusCode)
	}
}

func TestHandleIndexServesEmbeddedPage(t *testing.T) {
	server := httptest.NewServer(newTestAdminServer(t).mux())
	defer server.Close()

	response, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}
	if len(adminPageHTML) == 0 {
		t.Fatal("expected the embedded admin page to be non-empty")
	}
}
