package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/nostr-yunohost/nostr-yunohost/internal/attestation"
	"github.com/nostr-yunohost/nostr-yunohost/internal/catalog"
	"github.com/nostr-yunohost/nostr-yunohost/internal/localstate"
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

func issueCSRFToken(w http.ResponseWriter) (string, error) {
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
	token, err := issueCSRFToken(w)
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
	matched := false
	for _, candidate := range candidates {
		if candidate.AppID == req.AppID && candidate.Publisher == req.Publisher {
			matched = true
			break
		}
	}
	if !matched {
		// Never sign an attestation for a target we did not independently
		// derive ourselves - the request body names the target, but only a
		// candidate this server computed (installed + declared by someone
		// else) is a legitimate attestation.
		http.Error(w, "not an attestable candidate", http.StatusBadRequest)
		return
	}
	results, err := s.publisher.Attest(r.Context(), req.Publisher, req.AppID, req.Claim, req.Comment)
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
