package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nbd-wtf/go-nostr"

	"github.com/imattau/nostr-yunohost/internal/announce"
	"github.com/imattau/nostr-yunohost/internal/attestation"
	"github.com/imattau/nostr-yunohost/internal/catalog"
	"github.com/imattau/nostr-yunohost/internal/publisher"
	"github.com/imattau/nostr-yunohost/internal/relay"
	"github.com/imattau/nostr-yunohost/internal/reverify"
	"github.com/imattau/nostr-yunohost/internal/trust"
	"github.com/imattau/nostr-yunohost/internal/verification"
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

	policy, err := trust.NewExplicitPublishers([]string{other, self})
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

	// A second declaration published by the admin's own key, so
	// /admin/announce (which only ever announces this server's own
	// declarations) has something valid to target.
	selfEvent := nostr.Event{
		PubKey: self, CreatedAt: 1, Kind: 30078,
		Tags: nostr.Tags{
			{"d", "self_app"}, {"platform", "yunohost"},
			{"repo", "https://example.com/self_app"}, {"version", "2.0.0~ynh1"},
			{"commit", "ffffffffffffffffffffffffffffffffffffffff"},
			{"manifest", "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
			{"content", "sha256:2222222222222222222222222222222222222222222222222222222222222222"},
		},
		Content: "{}",
	}
	if err := selfEvent.Sign(adminTestSelfKey); err != nil {
		t.Fatalf("sign self fixture event: %v", err)
	}
	if err := store.Ingest(selfEvent); err != nil {
		t.Fatalf("Ingest self event: %v", err)
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
	announceLedger, err := announce.LoadLedger(filepath.Join(dir, "announcements.json"))
	if err != nil {
		t.Fatalf("announce.LoadLedger: %v", err)
	}

	return &adminServer{
		store:          store,
		publisher:      &attestation.Publisher{Client: client, PrivateKey: adminTestSelfKey, Ledger: ledger},
		ledger:         ledger,
		selfPublisher:  self,
		installedPath:  installedAppsFile,
		announceLedger: announceLedger,
		profilePath:    filepath.Join(dir, "profile.json"),
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

func TestHandleAttestableReusesExistingCSRFCookieRatherThanRotatingIt(t *testing.T) {
	server := httptest.NewServer(newTestAdminServer(t).mux())
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("new cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}

	first, err := client.Get(server.URL + "/admin/attestable")
	if err != nil {
		t.Fatalf("first GET /admin/attestable: %v", err)
	}
	var firstBody attestableResponse
	if err := json.NewDecoder(first.Body).Decode(&firstBody); err != nil {
		t.Fatalf("decode first response: %v", err)
	}
	first.Body.Close()

	// A second GET from the same browser (a reload, a second tab, or
	// anything else hitting this same admin page) must not invalidate the
	// token a page already holds - the earlier version rotated the cookie
	// on every GET, so a token captured by an already-open tab would stop
	// matching the cookie as soon as anything else re-fetched the page,
	// turning the next attest click into a false "invalid CSRF token".
	second, err := client.Get(server.URL + "/admin/attestable")
	if err != nil {
		t.Fatalf("second GET /admin/attestable: %v", err)
	}
	var secondBody attestableResponse
	if err := json.NewDecoder(second.Body).Decode(&secondBody); err != nil {
		t.Fatalf("decode second response: %v", err)
	}
	second.Body.Close()

	if firstBody.CSRFToken != secondBody.CSRFToken {
		t.Fatalf("expected the CSRF token to stay stable across GETs, got %q then %q", firstBody.CSRFToken, secondBody.CSRFToken)
	}

	// The token from the *first* response must still work against the
	// current cookie jar state.
	requestBody, _ := json.Marshal(attestRequest{AppID: "hello_nostr", Publisher: adminTestOtherKey, Claim: "tested"})
	request, err := http.NewRequest(http.MethodPost, server.URL+"/admin/attest", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", firstBody.CSRFToken)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST /admin/attest: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden {
		t.Fatal("first tab's token was rejected after a second GET rotated the cookie")
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

func TestHandleHistoryReturnsPublishedAttestationsMostRecentFirst(t *testing.T) {
	testServer := newTestAdminServer(t)
	if err := testServer.ledger.Record(adminTestOtherKey, "hello_nostr", "tested", "1.0.0~ynh1"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	server := httptest.NewServer(testServer.mux())
	defer server.Close()

	response, err := http.Get(server.URL + "/admin/history")
	if err != nil {
		t.Fatalf("GET /admin/history: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}
	var history []struct {
		Publisher  string `json:"publisher"`
		AppID      string `json:"app_id"`
		Claim      string `json:"claim"`
		Version    string `json:"version"`
		AttestedAt int64  `json:"attested_at"`
	}
	if err := json.NewDecoder(response.Body).Decode(&history); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("expected exactly one history entry, got %v", history)
	}
	entry := history[0]
	if entry.AppID != "hello_nostr" || entry.Publisher != adminTestOtherKey || entry.Claim != "tested" || entry.Version != "1.0.0~ynh1" {
		t.Fatalf("unexpected history entry: %+v", entry)
	}
	if entry.AttestedAt == 0 {
		t.Fatal("expected a non-zero attested_at timestamp")
	}
}

func TestHandleReverifyRejectsMissingCSRF(t *testing.T) {
	server := httptest.NewServer(newTestAdminServer(t).mux())
	defer server.Close()

	body, _ := json.Marshal(reverifyRequest{AppID: "hello_nostr", Publisher: adminTestOtherKey, Commit: "cccccccccccccccccccccccccccccccccccccccc"})
	response, err := http.Post(server.URL+"/admin/reverify", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /admin/reverify: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 without a CSRF token, got %d", response.StatusCode)
	}
}

func adminTestOtherPubkey(t *testing.T) string {
	t.Helper()
	pubkey, err := nostr.GetPublicKey(adminTestOtherKey)
	if err != nil {
		t.Fatalf("derive other pubkey: %v", err)
	}
	return pubkey
}

func postReverify(t *testing.T, server *httptest.Server, req reverifyRequest) *http.Response {
	t.Helper()
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
	body, _ := json.Marshal(req)
	request, err := http.NewRequest(http.MethodPost, server.URL+"/admin/reverify", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrfCookie.Value)
	request.AddCookie(csrfCookie)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST /admin/reverify: %v", err)
	}
	return response
}

func TestHandleReverifyRejectsUnknownRevision(t *testing.T) {
	server := httptest.NewServer(newTestAdminServer(t).mux())
	defer server.Close()

	// This is the case where a declaration was republished (or never
	// existed) at this commit - the request body can only select among
	// revisions this server already accepted into its own store, it can
	// never name an arbitrary one.
	response := postReverify(t, server, reverifyRequest{AppID: "hello_nostr", Publisher: adminTestOtherKey, Commit: "0000000000000000000000000000000000000000"})
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for an unknown revision, got %d", response.StatusCode)
	}
}

func TestHandleReverifyReturnsEmptyResultsWhenNoAttestationExists(t *testing.T) {
	server := httptest.NewServer(newTestAdminServer(t).mux())
	defer server.Close()

	// The fixture declaration exists but no attestation was ever ingested
	// for it - reverify has nothing to re-check, so this must return an
	// empty (not missing/error) result list without attempting a clone.
	response := postReverify(t, server, reverifyRequest{AppID: "hello_nostr", Publisher: adminTestOtherPubkey(t), Commit: "cccccccccccccccccccccccccccccccccccccccc"})
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}
	var results []reverify.Result
	if err := json.NewDecoder(response.Body).Decode(&results); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no results without any stored attestation, got %+v", results)
	}
}

func TestHandleReverifyDetectsAnAttestationThatDoesNotMatchTheRealRepository(t *testing.T) {
	testServer := newTestAdminServer(t)
	// A second declaration, distinct from the shared fixture, pointing at a
	// repository that refuses the connection immediately (127.0.0.1:1) -
	// this must fail reverify's clone step fast and deterministically,
	// without depending on real network access or an actual clonable repo,
	// while still exercising the "attestation claims something the
	// independent re-clone cannot confirm" path this endpoint exists for.
	otherPubkey, err := nostr.GetPublicKey(adminTestOtherKey)
	if err != nil {
		t.Fatalf("derive other pubkey: %v", err)
	}
	declEvent := nostr.Event{
		PubKey: otherPubkey, CreatedAt: 1, Kind: 30078,
		Tags: nostr.Tags{
			{"d", "unreachable_app"}, {"platform", "yunohost"},
			{"repo", "https://127.0.0.1:1/unreachable_app"}, {"version", "1.0.0~ynh1"},
			{"commit", "cccccccccccccccccccccccccccccccccccccccc"},
			{"manifest", "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
			{"content", "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
		},
		Content: "{}",
	}
	if err := declEvent.Sign(adminTestOtherKey); err != nil {
		t.Fatalf("sign declaration: %v", err)
	}
	if err := testServer.store.Ingest(declEvent); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	event, err := verification.Build("unreachable_app", "https://127.0.0.1:1/unreachable_app", "cccccccccccccccccccccccccccccccccccccccc",
		"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		"github-actions", "https://example.com/actions/runs/1",
		map[string]string{"yunohost_lint": "pass"}, "pass", adminTestOtherKey)
	if err != nil {
		t.Fatalf("build attestation: %v", err)
	}
	if err := testServer.store.IngestAttestation(event); err != nil {
		t.Fatalf("IngestAttestation: %v", err)
	}

	server := httptest.NewServer(testServer.mux())
	defer server.Close()

	response := postReverify(t, server, reverifyRequest{AppID: "unreachable_app", Publisher: otherPubkey, Commit: "cccccccccccccccccccccccccccccccccccccccc"})
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}
	var results []reverify.Result
	if err := json.NewDecoder(response.Body).Decode(&results); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected exactly one reverify result, got %+v", results)
	}
	if results[0].Match {
		t.Fatalf("expected a mismatch against a repository that was never actually cloneable: %+v", results[0])
	}
}

func TestHandleTrustReturnsEntries(t *testing.T) {
	server := httptest.NewServer(newTestAdminServer(t).mux())
	defer server.Close()

	response, err := http.Get(server.URL + "/admin/trust")
	if err != nil {
		t.Fatalf("GET /admin/trust: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}
	var entries []catalog.TrustEntry
	if err := json.NewDecoder(response.Body).Decode(&entries); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// newTestAdminServer ingests two fixtures: hello_nostr (a different
	// publisher, used by the attest/candidate tests) and self_app (this
	// server's own key, used by the /admin/announce tests).
	if len(entries) != 2 {
		t.Fatalf("unexpected trust entries: %+v", entries)
	}
	var helloEntry *catalog.TrustEntry
	for i := range entries {
		if entries[i].AppID == "hello_nostr" {
			helloEntry = &entries[i]
		}
	}
	if helloEntry == nil {
		t.Fatalf("expected a hello_nostr trust entry: %+v", entries)
	}
	// newTestAdminServer ingests its fixture via plain Ingest, not
	// IngestVerified, so the repository was never actually fetched/hashed.
	if helloEntry.RepositoryVerified {
		t.Fatalf("expected RepositoryVerified=false for the Ingest-only fixture: %+v", helloEntry)
	}
	if helloEntry.Policy.Mode != "" {
		t.Fatalf("expected the fixture's unconfigured attestation policy to report empty mode: %+v", helloEntry.Policy)
	}
	if !helloEntry.Policy.Accepted {
		t.Fatalf("expected off/unconfigured policy to accept the declaration: %+v", helloEntry.Policy)
	}
}

func TestHandleTrustRejectsNonGET(t *testing.T) {
	server := httptest.NewServer(newTestAdminServer(t).mux())
	defer server.Close()

	response, err := http.Post(server.URL+"/admin/trust", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /admin/trust: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected status: %d", response.StatusCode)
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

// postJSONWithCSRF fetches a fresh CSRF cookie from /admin/attestable (any
// GET route issues the same cookie) and POSTs body to path with it attached,
// mirroring postReverify's pattern generically for the profile/announce
// routes below.
func postJSONWithCSRF(t *testing.T, server *httptest.Server, path string, body []byte) *http.Response {
	t.Helper()
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
	request, err := http.NewRequest(http.MethodPost, server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrfCookie.Value)
	request.AddCookie(csrfCookie)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return response
}

func TestHandleProfileGetReturnsEmptyProfileAndCSRFToken(t *testing.T) {
	server := httptest.NewServer(newTestAdminServer(t).mux())
	defer server.Close()

	response, err := http.Get(server.URL + "/admin/profile")
	if err != nil {
		t.Fatalf("GET /admin/profile: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}
	var body profileResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.CSRFToken == "" {
		t.Fatal("expected a CSRF token")
	}
	if body.Profile != (publisher.Profile{}) {
		t.Fatalf("expected an empty profile before any /admin/profile POST, got %+v", body.Profile)
	}
}

func TestHandleProfileRejectsMissingCSRF(t *testing.T) {
	server := httptest.NewServer(newTestAdminServer(t).mux())
	defer server.Close()

	body, _ := json.Marshal(publisher.Profile{Name: "Example"})
	response, err := http.Post(server.URL+"/admin/profile", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /admin/profile: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 without a CSRF token, got %d", response.StatusCode)
	}
}

// TestHandleProfilePostWithUnreachableRelayDoesNotPersist exercises the
// build-and-attempt-publish path against the fixture's unreachable relay
// (ws://127.0.0.1:1, refused immediately - see newTestAdminServer): the
// event is built and signed successfully, every relay publish fails, and
// the local profile cache must therefore stay untouched rather than record
// a profile nothing on the network actually received.
func TestHandleProfilePostWithUnreachableRelayDoesNotPersist(t *testing.T) {
	server := httptest.NewServer(newTestAdminServer(t).mux())
	defer server.Close()

	body, _ := json.Marshal(publisher.Profile{Name: "Example Publisher"})
	response := postJSONWithCSRF(t, server, "/admin/profile", body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}
	var outcomes []publishOutcome
	if err := json.NewDecoder(response.Body).Decode(&outcomes); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(outcomes) == 0 || outcomes[0].Error == "" {
		t.Fatalf("expected a relay error against an unreachable relay, got %+v", outcomes)
	}

	getResponse, err := http.Get(server.URL + "/admin/profile")
	if err != nil {
		t.Fatalf("GET /admin/profile: %v", err)
	}
	defer getResponse.Body.Close()
	var getBody profileResponse
	if err := json.NewDecoder(getResponse.Body).Decode(&getBody); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if getBody.Profile != (publisher.Profile{}) {
		t.Fatalf("expected the profile cache to remain empty after a total publish failure, got %+v", getBody.Profile)
	}
}

func TestHandleAnnouncementsReturnsRecordedHistory(t *testing.T) {
	testServer := newTestAdminServer(t)
	if err := testServer.announceLedger.Record("self_app", "ffffffffffffffffffffffffffffffffffffffff", "2.0.0~ynh1", "eventid", "nevent1..."); err != nil {
		t.Fatalf("Record: %v", err)
	}
	server := httptest.NewServer(testServer.mux())
	defer server.Close()

	response, err := http.Get(server.URL + "/admin/announcements")
	if err != nil {
		t.Fatalf("GET /admin/announcements: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}
	var history []announce.Record
	if err := json.NewDecoder(response.Body).Decode(&history); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(history) != 1 || history[0].AppID != "self_app" {
		t.Fatalf("unexpected announcement history: %+v", history)
	}
}

func TestHandleAnnounceRejectsMissingCSRF(t *testing.T) {
	server := httptest.NewServer(newTestAdminServer(t).mux())
	defer server.Close()

	body, _ := json.Marshal(announceRequest{AppID: "self_app", Publisher: adminTestSelfKey})
	response, err := http.Post(server.URL+"/admin/announce", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /admin/announce: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 without a CSRF token, got %d", response.StatusCode)
	}
}

// TestHandleAnnounceRejectsAnotherPublishersDeclaration is the structural
// guard equivalent to attestation.Candidates excluding self-declarations:
// here it is the opposite direction - this key must never sign an
// announcement claiming a *different* publisher's release.
func TestHandleAnnounceRejectsAnotherPublishersDeclaration(t *testing.T) {
	server := httptest.NewServer(newTestAdminServer(t).mux())
	defer server.Close()

	body, _ := json.Marshal(announceRequest{AppID: "hello_nostr", Publisher: adminTestOtherPubkey(t), Commit: "cccccccccccccccccccccccccccccccccccccccc"})
	response := postJSONWithCSRF(t, server, "/admin/announce", body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for another publisher's declaration, got %d", response.StatusCode)
	}
}

func TestHandleAnnounceRejectsUnknownRevision(t *testing.T) {
	self, err := nostr.GetPublicKey(adminTestSelfKey)
	if err != nil {
		t.Fatalf("derive self pubkey: %v", err)
	}
	server := httptest.NewServer(newTestAdminServer(t).mux())
	defer server.Close()

	body, _ := json.Marshal(announceRequest{AppID: "self_app", Publisher: self, Commit: "0000000000000000000000000000000000000000"})
	response := postJSONWithCSRF(t, server, "/admin/announce", body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for an unknown revision, got %d", response.StatusCode)
	}
}

func TestHandleAnnounceRejectsAlreadyAnnounced(t *testing.T) {
	self, err := nostr.GetPublicKey(adminTestSelfKey)
	if err != nil {
		t.Fatalf("derive self pubkey: %v", err)
	}
	testServer := newTestAdminServer(t)
	if err := testServer.announceLedger.Record("self_app", "ffffffffffffffffffffffffffffffffffffffff", "2.0.0~ynh1", "eventid", "nevent1..."); err != nil {
		t.Fatalf("Record: %v", err)
	}
	server := httptest.NewServer(testServer.mux())
	defer server.Close()

	body, _ := json.Marshal(announceRequest{AppID: "self_app", Publisher: self, Commit: "ffffffffffffffffffffffffffffffffffffffff"})
	response := postJSONWithCSRF(t, server, "/admin/announce", body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 for an already-announced revision, got %d", response.StatusCode)
	}
}

// TestHandleAnnounceWithUnreachableRelayDoesNotRecord mirrors
// TestHandleProfilePostWithUnreachableRelayDoesNotPersist: a total publish
// failure against the fixture's unreachable relay must leave the
// announcement ledger untouched, so the revision remains available for a
// retry instead of silently reading as already-announced.
func TestHandleAnnounceWithUnreachableRelayDoesNotRecord(t *testing.T) {
	self, err := nostr.GetPublicKey(adminTestSelfKey)
	if err != nil {
		t.Fatalf("derive self pubkey: %v", err)
	}
	testServer := newTestAdminServer(t)
	server := httptest.NewServer(testServer.mux())
	defer server.Close()

	body, _ := json.Marshal(announceRequest{AppID: "self_app", Publisher: self, Commit: "ffffffffffffffffffffffffffffffffffffffff"})
	response := postJSONWithCSRF(t, server, "/admin/announce", body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}
	var outcomes []publishOutcome
	if err := json.NewDecoder(response.Body).Decode(&outcomes); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(outcomes) == 0 || outcomes[0].Error == "" {
		t.Fatalf("expected a relay error against an unreachable relay, got %+v", outcomes)
	}
	if testServer.announceLedger.HasAnnounced("self_app", "ffffffffffffffffffffffffffffffffffffffff") {
		t.Fatal("expected the announcement ledger to remain untouched after a total publish failure")
	}
}
