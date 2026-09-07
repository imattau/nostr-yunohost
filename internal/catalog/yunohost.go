package catalog

import (
	"fmt"

	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
	"github.com/nostr-yunohost/nostr-yunohost/internal/verification"
)

// YunoHostCatalog is the top-level shape used by the v3 application catalog.
type YunoHostCatalog struct {
	Antifeatures []any                  `json:"antifeatures"`
	Apps         map[string]YunoHostApp `json:"apps"`
	Categories   []any                  `json:"categories"`
	Security     SecurityIndex          `json:"security"`
}

// SecurityIndex is the versioned security index accepted by YunoHost.
// System is left empty - nothing in this catalogue currently attests to
// system-level (as opposed to per-app) properties. Apps is populated from
// CI-backed attestations (docs/attestation-trust-policy-plan.md Phase 8);
// YunoHost itself is free to ignore this extra metadata, but the daemon's
// own admin UI (Phase 9, not implemented) will read it directly.
type SecurityIndex struct {
	Version int                           `json:"version"`
	Apps    map[string][]SecurityAppEntry `json:"apps"`
	System  map[string][]any              `json:"system"`
}

// SecurityAppEntry is one CI attestation record for a specific app revision,
// derived from a single kind-30080 attestation event
// (internal/verification.Attestation). An app can have several - one per
// verifier - for the same Revision, which is exactly the plan's Phase 12
// "multiple independent verifiers" design: this index doesn't collapse them
// into one summary judgment, it lists the evidence.
type SecurityAppEntry struct {
	Revision string            `json:"revision"`
	Status   string            `json:"status"`
	Verifier string            `json:"verifier"`
	TestedAt int64             `json:"tested_at"`
	Checks   map[string]string `json:"checks"`
}

type YunoHostApp struct {
	AddedInCatalog         int64          `json:"added_in_catalog"`
	AlternativeBranches    map[string]any `json:"alternative_branches"`
	Antifeatures           []string       `json:"antifeatures"`
	Category               string         `json:"category,omitempty"`
	Featured               bool           `json:"featured"`
	Git                    GitSource      `json:"git"`
	HighQuality            bool           `json:"high_quality"`
	ID                     string         `json:"id"`
	LastUpdate             int64          `json:"lastUpdate"`
	Level                  int            `json:"level"`
	LogoHash               string         `json:"logo_hash,omitempty"`
	Manifest               map[string]any `json:"manifest"`
	Maintained             bool           `json:"maintained"`
	PotentialAlternativeTo []string       `json:"potential_alternative_to"`
	State                  string         `json:"state"`
	Subtags                []string       `json:"subtags"`
}

// NewSecurityAppEntry converts one CI attestation into its security-index
// record. Verifier is encoded as npub for the same reason the config panel
// shows publisher identity as npub - it's the form administrators actually
// compare against a trusted-verifiers list, not the raw hex key. Encoding
// only fails for a malformed key, which verification.Parse already
// rejects before an Attestation can exist, so this falls back to the raw
// hex rather than dropping the entry entirely.
func NewSecurityAppEntry(a verification.Attestation) SecurityAppEntry {
	verifier := a.Verifier
	if npub, err := nip19.EncodePublicKey(a.Verifier); err == nil {
		verifier = npub
	}
	return SecurityAppEntry{
		Revision: a.Commit,
		Status:   securityStatus(a.Result),
		Verifier: verifier,
		TestedAt: a.TestedAt,
		Checks:   a.Checks,
	}
}

// securityStatus maps an attestation's overall result to the security
// index's status vocabulary. Phase 10's richer status vocabulary
// (unverified/integrity_verified/ci_verified/multi_verified/failed) is a
// later phase, not implemented here; "verified" for a passing attestation
// matches the plan's own Phase 8 example, and fail/error pass through
// unchanged since no better word for them exists yet.
func securityStatus(result string) string {
	if result == "pass" {
		return "verified"
	}
	return result
}

type GitSource struct {
	Branch   string `json:"branch"`
	Revision string `json:"revision"`
	URL      string `json:"url"`
}

// Translate converts a validated declaration and the authoritative manifest
// fetched from its pinned repository into the YunoHost v3 app entry.
func Translate(declaration protocol.AppDeclaration, manifest map[string]any, publishedAt int64) (YunoHostApp, error) {
	return TranslateWithBranch(declaration, manifest, "", "main", publishedAt)
}

// TranslateWithLogo converts a verified package and optional local logo into
// the YunoHost v3 app representation.
func TranslateWithLogo(declaration protocol.AppDeclaration, manifest map[string]any, logoHash string, publishedAt int64) (YunoHostApp, error) {
	return TranslateWithBranch(declaration, manifest, logoHash, "main", publishedAt)
}

// TranslateWithBranch converts a verified package into the YunoHost v3 app
// representation, preserving the repository's actual default branch.
func TranslateWithBranch(declaration protocol.AppDeclaration, manifest map[string]any, logoHash, branch string, publishedAt int64) (YunoHostApp, error) {
	if manifest == nil {
		return YunoHostApp{}, fmt.Errorf("manifest is required")
	}
	if manifestID, ok := manifest["id"].(string); !ok || manifestID != declaration.AppID {
		return YunoHostApp{}, fmt.Errorf("manifest id does not match declaration app ID")
	}
	if manifestVersion, ok := manifest["version"].(string); !ok || manifestVersion != declaration.Version {
		return YunoHostApp{}, fmt.Errorf("manifest version does not match declaration version")
	}
	if branch == "" {
		branch = "main"
	}
	return YunoHostApp{
		AddedInCatalog:      publishedAt,
		AlternativeBranches: map[string]any{},
		Antifeatures:        []string{},
		Category:            declaration.Category,
		Git:                 GitSource{Branch: branch, Revision: declaration.Commit, URL: declaration.Repository},
		ID:                  declaration.AppID,
		LastUpdate:          publishedAt,
		// YunoHost treats levels <= 4 as bad quality and blocks upgrades. This
		// catalogue has independently verified the repository, commit, manifest,
		// and content hashes, but has not run YunoHost CI. Level 5 is therefore a
		// compatibility floor that keeps custom-catalogue installs upgradeable;
		// HighQuality remains false so this is not presented as fully vetted.
		Level:                  5,
		LogoHash:               logoHash,
		Manifest:               manifest,
		Maintained:             true,
		PotentialAlternativeTo: []string{},
		State:                  "working",
		Subtags:                []string{},
	}, nil
}
