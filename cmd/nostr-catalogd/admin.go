package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/imattau/nostr-yunohost/internal/announce"
	"github.com/imattau/nostr-yunohost/internal/attestation"
	"github.com/imattau/nostr-yunohost/internal/catalog"
	"github.com/imattau/nostr-yunohost/internal/localstate"
	"github.com/imattau/nostr-yunohost/internal/publisher"
	"github.com/imattau/nostr-yunohost/internal/reverify"
)

// reverifyTimeout bounds the git clone reverify's /admin/reverify handler
// runs on demand - an admin clicking the button waits synchronously for the
// HTTP response, so this needs to be short enough not to look hung against
// a slow or unreachable repository host, matching nostr-ynh reverify's own
// default relay/clone timeout.
const reverifyTimeout = 20 * time.Second

//go:embed admin_static/index.html
var adminPageHTML []byte

const csrfCookieName = "nostr_catalog_csrf"

// adminServer serves the attestation admin page's API. Every route here is
// expected to sit behind YunoHost's SSOwat admins-only permission at the
// packaging layer (nostr_catalog_ynh's resources.permissions.main) - the
// CSRF check below is defense in depth against a same-origin browser
// session riding an admin's cookies, not the primary access control.
type adminServer struct {
	store          *catalog.Store
	publisher      *attestation.Publisher
	ledger         *attestation.Ledger
	selfPublisher  string
	installedPath  string
	announceLedger *announce.Ledger
	profilePath    string
}

func (s *adminServer) candidates() ([]attestation.Candidate, error) {
	installed, err := localstate.Load(s.installedPath)
	if err != nil {
		return nil, err
	}
	return attestation.Candidates(s.store.Declarations(), installed, s.selfPublisher, s.ledger), nil
}

// mux builds the admin HTTP handler. Kept separate from registration onto
// any particular *http.Server so tests can exercise it with
// httptest.NewServer/NewRequest directly.
func (s *adminServer) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/admin/attestable", s.handleAttestable)
	mux.HandleFunc("/admin/attest", s.handleAttest)
	mux.HandleFunc("/admin/history", s.handleHistory)
	mux.HandleFunc("/admin/trust", s.handleTrust)
	mux.HandleFunc("/admin/reverify", s.handleReverify)
	mux.HandleFunc("/admin/profile", s.handleProfile)
	mux.HandleFunc("/admin/announcements", s.handleAnnouncements)
	mux.HandleFunc("/admin/announce", s.handleAnnounce)
	return mux
}

func (s *adminServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(adminPageHTML)
}

// issueCSRFToken returns the token for this browser's CSRF cookie, reusing
// an existing valid one rather than always minting a fresh one. Rotating on
// every GET (as an earlier version did) broke any tab that had already
// loaded the page: a second tab, a reload, or any other request to this
// same admin page from the same browser would silently invalidate the
// first tab's in-memory token, turning every subsequent attest click into
// a false "invalid CSRF token" - independent of whether that other request
// belonged to the same person at all, since the cookie is domain-wide.
func issueCSRFToken(w http.ResponseWriter, r *http.Request) (string, error) {
	if cookie, err := r.Cookie(csrfCookieName); err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		// The page never reads this cookie itself - the token reaches the
		// client via the JSON response body (attestableResponse.CSRFToken)
		// instead - so HttpOnly closes off cookie theft as a second way for
		// an injected script to obtain a valid token.
		HttpOnly: true,
	})
	return token, nil
}

func checkCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	header := r.Header.Get("X-CSRF-Token")
	return header != "" && header == cookie.Value
}

type attestableResponse struct {
	CSRFToken  string                  `json:"csrf_token"`
	Candidates []attestation.Candidate `json:"candidates"`
}

func (s *adminServer) handleAttestable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	candidates, err := s.candidates()
	if err != nil {
		http.Error(w, "failed to load candidates", http.StatusInternalServerError)
		return
	}
	token, err := issueCSRFToken(w, r)
	if err != nil {
		http.Error(w, "failed to issue CSRF token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if candidates == nil {
		candidates = []attestation.Candidate{}
	}
	_ = json.NewEncoder(w).Encode(attestableResponse{CSRFToken: token, Candidates: candidates})
}

type attestRequest struct {
	AppID     string `json:"app_id"`
	Publisher string `json:"publisher"`
	Claim     string `json:"claim"`
	Comment   string `json:"comment"`
}

type publishOutcome struct {
	Relay string `json:"relay"`
	Error string `json:"error,omitempty"`
}

func (s *adminServer) handleAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	var req attestRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Claim != "recommend" && req.Claim != "tested" {
		http.Error(w, "claim must be recommend or tested", http.StatusBadRequest)
		return
	}
	candidates, err := s.candidates()
	if err != nil {
		http.Error(w, "failed to load candidates", http.StatusInternalServerError)
		return
	}
	var matched *attestation.Candidate
	for i := range candidates {
		if candidates[i].AppID == req.AppID && candidates[i].Publisher == req.Publisher {
			matched = &candidates[i]
			break
		}
	}
	if matched == nil {
		// Never sign an attestation for a target we did not independently
		// derive ourselves - the request body names the target, but only a
		// candidate this server computed (installed + declared by someone
		// else) is a legitimate attestation. This also means the signed
		// version always comes from what this server observed, never from
		// the request body.
		http.Error(w, "not an attestable candidate", http.StatusBadRequest)
		return
	}
	results, err := s.publisher.Attest(r.Context(), req.Publisher, req.AppID, req.Claim, req.Comment, matched.Version)
	if err != nil {
		http.Error(w, fmt.Sprintf("attest: %v", err), http.StatusInternalServerError)
		return
	}
	outcomes := make([]publishOutcome, 0, len(results))
	for _, result := range results {
		outcome := publishOutcome{Relay: result.Relay}
		if result.Error != nil {
			outcome.Error = result.Error.Error()
		}
		outcomes = append(outcomes, outcome)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(outcomes)
}

// handleTrust returns every accepted declaration's trust picture (Phase 9's
// trust dashboard): what this server has verified, what CI-backed
// attestations exist for its exact revision, and what the local policy
// decided as a result - so an app filtered by --attestation-policy=require
// is explained here, not silently hidden. This is a read-only view over
// catalog.Store.TrustEntries and is separate from the candidate/attest flow
// above, which is specifically about this server's own kind-30079
// endorsements, not third-party kind-30080 CI attestations.
func (s *adminServer) handleTrust(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.store.TrustEntries())
}

type reverifyRequest struct {
	AppID     string `json:"app_id"`
	Publisher string `json:"publisher"`
	Commit    string `json:"commit"`
}

// handleReverify independently re-checks every CI attestation this server
// already holds for one accepted revision, on demand: it re-clones the
// repository fresh at the attested commit and recomputes both hashes,
// rather than trusting the signed claim or the (possibly stale, ingestion-
// time) RepositoryVerified/Status fields the trust dashboard otherwise
// shows. See internal/reverify and docs/attestations.md's "Independently
// re-checking a published attestation".
//
// This performs real outbound network I/O (a git clone) but only ever
// against a repository this server already accepted into its own store -
// the request body selects which already-trusted revision to re-check, it
// cannot name an arbitrary repository - so the CSRF check here is the same
// defense-in-depth as handleAttest's, not the only thing standing between
// this and SSRF.
func (s *adminServer) handleReverify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	var req reverifyRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	declaration, attestations, ok := s.store.RevisionAttestations(req.AppID, req.Publisher, req.Commit)
	if !ok {
		http.Error(w, "not an accepted revision", http.StatusNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), reverifyTimeout)
	defer cancel()
	results := make([]reverify.Result, 0, len(attestations))
	for _, a := range attestations {
		results = append(results, reverify.Run(ctx, a, declaration))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(results)
}

// handleHistory returns every attestation this server has published,
// regardless of whether the underlying app is still installed or its
// declaration still exists - the page's expand-on-click history view for a
// row, and a simple audit trail independent of the current candidate list.
func (s *adminServer) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.ledger.History())
}

// loadProfileState reads this server's last-published kind-0 profile
// fields from its local cache file. A missing file means nothing has been
// published yet through this admin page and is not an error - the page
// simply shows an empty form. This is deliberately a local cache rather
// than a relay fetch on every page load: the admin page is the only writer
// of this key's profile in the self-publishing setup this route is for
// (see docs/profile-and-announcements.md), so what this server last sent
// is authoritative for its own display purposes.
func loadProfileState(path string) (publisher.Profile, error) {
	var profile publisher.Profile
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return profile, nil
		}
		return profile, fmt.Errorf("read profile state: %w", err)
	}
	if err := json.Unmarshal(data, &profile); err != nil {
		return profile, fmt.Errorf("decode profile state: %w", err)
	}
	return profile, nil
}

// saveProfileState persists the profile fields atomically, mirroring
// attestation.Ledger.Record's write pattern.
func saveProfileState(path string, profile publisher.Profile) error {
	data, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("encode profile state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create profile state directory: %w", err)
	}
	temporaryPath := path + ".tmp"
	if err := os.WriteFile(temporaryPath, append(data, '\n'), 0o640); err != nil {
		return fmt.Errorf("write profile state: %w", err)
	}
	return os.Rename(temporaryPath, path)
}

type profileResponse struct {
	CSRFToken     string            `json:"csrf_token"`
	Profile       publisher.Profile `json:"profile"`
	SelfPublisher string            `json:"self_publisher"`
}

// handleProfile serves this server's own last-published kind-0 profile
// (GET) and republishes it with edited fields (POST) - see
// docs/profile-and-announcements.md. This is the same publisher key
// already used for self-endorsements/self-attestations, so no separate key
// material or flag is needed beyond what --publisher-key-file already
// provides.
func (s *adminServer) handleProfile(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		profile, err := loadProfileState(s.profilePath)
		if err != nil {
			http.Error(w, "failed to load profile", http.StatusInternalServerError)
			return
		}
		token, err := issueCSRFToken(w, r)
		if err != nil {
			http.Error(w, "failed to issue CSRF token", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(profileResponse{CSRFToken: token, Profile: profile, SelfPublisher: s.selfPublisher})
	case http.MethodPost:
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		var profile publisher.Profile
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&profile); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		event, err := publisher.BuildProfile(profile, s.publisher.PrivateKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("build profile: %v", err), http.StatusBadRequest)
			return
		}
		results := s.publisher.Client.Publish(r.Context(), event)
		outcomes := make([]publishOutcome, 0, len(results))
		published := false
		for _, result := range results {
			outcome := publishOutcome{Relay: result.Relay}
			if result.Error != nil {
				outcome.Error = result.Error.Error()
			} else {
				published = true
			}
			outcomes = append(outcomes, outcome)
		}
		// Only cache the edited fields locally once at least one relay
		// actually accepted the event - a total publish failure should leave
		// the admin page showing what is still genuinely live, not a profile
		// nobody has seen, so a retry starts from the right form contents.
		if published {
			if err := saveProfileState(s.profilePath, profile); err != nil {
				http.Error(w, fmt.Sprintf("save profile: %v", err), http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(outcomes)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAnnouncements returns every announcement note this server has
// published, most recent first - the admin page's read-only history table.
func (s *adminServer) handleAnnouncements(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.announceLedger.History())
}

type announceRequest struct {
	AppID     string `json:"app_id"`
	Publisher string `json:"publisher"`
	Commit    string `json:"commit"`
}

// handleAnnounce lets an admin manually post a kind-1 announcement note for
// a declaration this server itself published and this store has already
// accepted - never for another publisher's declaration, since this key
// signing an announcement is a claim about its own release, not someone
// else's (see the manual re-announce case in
// docs/profile-and-announcements.md). Deduped against the same
// announceLedger publish --announce uses, so a revision already announced
// (by this page or by publish --announce sharing the same ledger file)
// cannot be posted again from here either.
func (s *adminServer) handleAnnounce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	var req announceRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Publisher != s.selfPublisher {
		http.Error(w, "can only announce this server's own declarations", http.StatusBadRequest)
		return
	}
	declaration, _, ok := s.store.RevisionAttestations(req.AppID, req.Publisher, req.Commit)
	if !ok {
		http.Error(w, "not an accepted revision", http.StatusNotFound)
		return
	}
	if s.announceLedger.HasAnnounced(declaration.AppID, declaration.Commit) {
		http.Error(w, "already announced", http.StatusConflict)
		return
	}
	event, err := publisher.BuildAnnouncementForDeclaration(declaration, nil, s.publisher.PrivateKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("build announcement: %v", err), http.StatusInternalServerError)
		return
	}
	results := s.publisher.Client.Publish(r.Context(), event)
	outcomes := make([]publishOutcome, 0, len(results))
	published := false
	for _, result := range results {
		outcome := publishOutcome{Relay: result.Relay}
		if result.Error != nil {
			outcome.Error = result.Error.Error()
		} else {
			published = true
		}
		outcomes = append(outcomes, outcome)
	}
	if published {
		if err := s.announceLedger.Record(declaration.AppID, declaration.Commit, declaration.Version, event.ID, ""); err != nil {
			http.Error(w, fmt.Sprintf("record announcement: %v", err), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(outcomes)
}
