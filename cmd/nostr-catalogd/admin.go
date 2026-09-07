package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/imattau/nostr-yunohost/internal/attestation"
	"github.com/imattau/nostr-yunohost/internal/catalog"
	"github.com/imattau/nostr-yunohost/internal/localstate"
)

//go:embed admin_static/index.html
var adminPageHTML []byte

const csrfCookieName = "nostr_catalog_csrf"

// adminServer serves the attestation admin page's API. Every route here is
// expected to sit behind YunoHost's SSOwat admins-only permission at the
// packaging layer (nostr_catalog_ynh's resources.permissions.main) - the
// CSRF check below is defense in depth against a same-origin browser
// session riding an admin's cookies, not the primary access control.
type adminServer struct {
	store         *catalog.Store
	publisher     *attestation.Publisher
	ledger        *attestation.Ledger
	selfPublisher string
	installedPath string
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
