// Package attestation lets a nostr_catalog server endorse apps it has
// actually installed from other publishers' declarations, signing with the
// same identity it already uses to publish its own declarations. See
// nostr_ynh_catalog/docs/endorsements.md for the underlying event shape.
package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/imattau/nostr-yunohost/internal/catalog"
	"github.com/imattau/nostr-yunohost/internal/curation"
	"github.com/imattau/nostr-yunohost/internal/localstate"
	"github.com/imattau/nostr-yunohost/internal/protocol"
	"github.com/imattau/nostr-yunohost/internal/relay"
)

// Candidate is an installed app this server could attest to: it was
// declared by a different publisher and is actually running here.
type Candidate struct {
	AppID      string `json:"app_id"`
	Publisher  string `json:"publisher"`
	Repository string `json:"repository"`
	Version    string `json:"version"`
	// Attested is true only if the ledger already holds an attestation for
	// this exact Version - a newer declared version re-surfaces the
	// candidate with its buttons active again, since this server hasn't
	// actually verified that version yet.
	Attested bool `json:"attested"`
	// AttestedVersion/AttestedAt describe the most recent attestation this
	// server made for this publisher/app pair, regardless of whether it
	// matches the currently declared Version - so the page can still show
	// "last attested v0.1, now at v0.2" even once Attested goes back to
	// false for the new version.
	AttestedVersion string `json:"attested_version,omitempty"`
	AttestedAt      int64  `json:"attested_at,omitempty"`
}

// Candidates cross-references locally installed apps against accepted
// catalogue declarations. A declaration only becomes a candidate when its
// repository matches an installed app's install source and its publisher is
// not selfPublisher - attesting to one's own declaration is excluded
// structurally rather than left to curation.Policy, which has no opinion on
// who may hold curator status.
func Candidates(declarations []protocol.AppDeclaration, installed []localstate.InstalledApp, selfPublisher string, ledger *Ledger) []Candidate {
	byRepo := make(map[string]localstate.InstalledApp, len(installed))
	for _, app := range installed {
		byRepo[catalog.NormalizeRepositoryURL(app.Repository)] = app
	}
	var candidates []Candidate
	for _, declaration := range declarations {
		if declaration.Publisher == selfPublisher {
			continue
		}
		installedApp, ok := byRepo[catalog.NormalizeRepositoryURL(declaration.Repository)]
		if !ok || installedApp.AppID != declaration.AppID {
			continue
		}
		candidate := Candidate{
			AppID:      declaration.AppID,
			Publisher:  declaration.Publisher,
			Repository: declaration.Repository,
			Version:    declaration.Version,
		}
		if ledger != nil {
			candidate.Attested = ledger.HasAttested(declaration.Publisher, declaration.AppID, declaration.Version)
			if last, ok := ledger.LatestRecord(declaration.Publisher, declaration.AppID); ok {
				candidate.AttestedVersion = last.Version
				candidate.AttestedAt = last.AttestedAt
			}
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

// attestationRecord is one attestation this server has published, kept for
// both the HasAttested check and the admin page's history view.
type attestationRecord struct {
	Publisher  string `json:"publisher"`
	AppID      string `json:"app_id"`
	Claim      string `json:"claim"`
	Version    string `json:"version"`
	AttestedAt int64  `json:"attested_at"`
}

// Ledger records which attestations this server has already published, so
// the candidate list can reflect them without depending on relay round-trip
// (curation.Policy's own dedup in Store.IngestEndorsement only fires if this
// server's key happens to appear in someone else's trusted-curators list,
// which is unrelated to whether *this* server already signed the event).
type Ledger struct {
	mu      sync.Mutex
	path    string
	entries []attestationRecord
}

// LoadLedger reads a ledger from path. A missing file starts an empty ledger.
func LoadLedger(path string) (*Ledger, error) {
	ledger := &Ledger{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ledger, nil
		}
		return nil, fmt.Errorf("read attestation ledger: %w", err)
	}
	if err := json.Unmarshal(data, &ledger.entries); err != nil {
		return nil, fmt.Errorf("decode attestation ledger: %w", err)
	}
	return ledger, nil
}

// HasAttested reports whether this server has already published an
// attestation for the given publisher/app/version, regardless of claim.
func (l *Ledger) HasAttested(publisher, appID, version string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, entry := range l.entries {
		if entry.Publisher == publisher && entry.AppID == appID && entry.Version == version {
			return true
		}
	}
	return false
}

// LatestRecord returns the most recently published attestation for a
// publisher/app pair across all versions and claims, if any.
func (l *Ledger) LatestRecord(publisher, appID string) (attestationRecord, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var latest attestationRecord
	found := false
	for _, entry := range l.entries {
		if entry.Publisher != publisher || entry.AppID != appID {
			continue
		}
		if !found || entry.AttestedAt > latest.AttestedAt {
			latest = entry
			found = true
		}
	}
	return latest, found
}

// History returns every attestation this server has published, most recent
// first, for the admin page's expand-on-click history view.
func (l *Ledger) History() []attestationRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	history := make([]attestationRecord, len(l.entries))
	copy(history, l.entries)
	sort.Slice(history, func(i, j int) bool { return history[i].AttestedAt > history[j].AttestedAt })
	return history
}

// Record marks a publisher/app/claim/version attestation as done and
// persists the ledger atomically, mirroring catalog.Store.Save's write
// pattern.
func (l *Ledger) Record(publisher, appID, claim, version string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, entry := range l.entries {
		if entry.Publisher == publisher && entry.AppID == appID && entry.Claim == claim && entry.Version == version {
			return nil
		}
	}
	l.entries = append(l.entries, attestationRecord{
		Publisher:  publisher,
		AppID:      appID,
		Claim:      claim,
		Version:    version,
		AttestedAt: time.Now().Unix(),
	})
	data, err := json.Marshal(l.entries)
	if err != nil {
		return fmt.Errorf("encode attestation ledger: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o750); err != nil {
		return fmt.Errorf("create attestation ledger directory: %w", err)
	}
	temporaryPath := l.path + ".tmp"
	if err := os.WriteFile(temporaryPath, append(data, '\n'), 0o640); err != nil {
		return fmt.Errorf("write attestation ledger: %w", err)
	}
	return os.Rename(temporaryPath, l.path)
}

// Publisher signs and publishes endorsements using this server's own
// identity - the same key used to sign the declarations it publishes.
type Publisher struct {
	Client     *relay.Client
	PrivateKey string
	Ledger     *Ledger
}

// Attest signs a kind-30079 endorsement for publisher/appID with claim and
// comment and publishes it to every configured relay. It is recorded in the
// ledger against version - and so stops showing as attestable for that
// version in future Candidates listings, while remaining visible again once
// a newer version is declared - only once at least one relay accepted it; a
// total publish failure leaves the candidate visible so the admin page can
// offer a retry instead of silently hiding a signature that never actually
// reached the network.
func (p *Publisher) Attest(ctx context.Context, publisher, appID, claim, comment, version string) ([]relay.PublishResult, error) {
	event, err := curation.Build(publisher, appID, claim, comment, p.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("build endorsement: %w", err)
	}
	results := p.Client.Publish(ctx, event)
	for _, result := range results {
		if result.Error == nil {
			if err := p.Ledger.Record(publisher, appID, claim, version); err != nil {
				return results, fmt.Errorf("record attestation: %w", err)
			}
			break
		}
	}
	return results, nil
}
