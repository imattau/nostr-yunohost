// Package reverify independently re-checks a CI attestation instead of
// trusting the publisher's signature on it: given an already-fetched
// attestation and the declaration it claims to cover, it cross-checks their
// claims against each other and against a fresh clone of the repository at
// the attested commit. Shared by `nostr-ynh reverify` (cmd/nostr-ynh) and
// nostr-catalogd's admin page reverify button, so both surfaces run exactly
// the same check. See docs/attestations.md, "Independently re-checking a
// published attestation".
package reverify

import (
	"context"
	"fmt"

	"github.com/imattau/nostr-yunohost/internal/protocol"
	"github.com/imattau/nostr-yunohost/internal/repository"
	"github.com/imattau/nostr-yunohost/internal/verification"
)

// Result is the outcome of independently re-checking one attestation.
type Result struct {
	AppID      string            `json:"app_id"`
	Repository string            `json:"repository"`
	Commit     string            `json:"commit"`
	Publisher  string            `json:"publisher"`
	Verifier   string            `json:"verifier"`
	Result     string            `json:"result"`
	Checks     map[string]string `json:"checks"`
	Match      bool              `json:"match"`
	Mismatches []string          `json:"mismatches,omitempty"`
}

// Run cross-checks attestation against declaration, then re-clones the
// repository fresh at the attested commit and recomputes both hashes,
// independent of anything either event merely asserts.
func Run(ctx context.Context, attestation verification.Attestation, declaration protocol.AppDeclaration) Result {
	var mismatches []string
	if declaration.AppID != attestation.AppID {
		mismatches = append(mismatches, fmt.Sprintf("app_id: declaration=%q attestation=%q", declaration.AppID, attestation.AppID))
	}
	if declaration.Repository != attestation.Repository {
		mismatches = append(mismatches, fmt.Sprintf("repository: declaration=%q attestation=%q", declaration.Repository, attestation.Repository))
	}
	if declaration.Commit != attestation.Commit {
		mismatches = append(mismatches, fmt.Sprintf("commit: declaration=%q attestation=%q", declaration.Commit, attestation.Commit))
	}
	if declaration.ManifestHash != attestation.ManifestHash {
		mismatches = append(mismatches, fmt.Sprintf("manifest: declaration=%q attestation=%q", declaration.ManifestHash, attestation.ManifestHash))
	}
	if declaration.ContentHash != attestation.ContentHash {
		mismatches = append(mismatches, fmt.Sprintf("content: declaration=%q attestation=%q", declaration.ContentHash, attestation.ContentHash))
	}

	// Re-clone the repository fresh at the attested commit and recompute
	// both hashes, independent of whatever the declaration/attestation
	// events merely claim - this is what actually catches a repo rewritten
	// after attestation. repository.VerifyDeclaration only reads
	// Repository/Commit/ManifestHash/ContentHash off the struct, so the
	// attestation's own claims are fed in directly rather than the
	// declaration's, in case those two already disagree above.
	claimed := protocol.AppDeclaration{
		Repository:   attestation.Repository,
		Commit:       attestation.Commit,
		ManifestHash: attestation.ManifestHash,
		ContentHash:  attestation.ContentHash,
	}
	if _, verifyErr := repository.VerifyDeclaration(ctx, claimed); verifyErr != nil {
		mismatches = append(mismatches, fmt.Sprintf("repository content: %v", verifyErr))
	}

	return Result{
		AppID:      attestation.AppID,
		Repository: attestation.Repository,
		Commit:     attestation.Commit,
		Publisher:  declaration.Publisher,
		Verifier:   attestation.Verifier,
		Result:     attestation.Result,
		Checks:     attestation.Checks,
		Match:      len(mismatches) == 0,
		Mismatches: mismatches,
	}
}
