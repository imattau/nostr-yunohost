package trust

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nostr-yunohost/nostr-yunohost/internal/verification"
)

// AttestationMode is the local administrator's policy for how CI-backed
// attestations (internal/verification) affect the generated catalogue. See
// docs/attestation-trust-policy-plan.md Phase 6.
type AttestationMode string

const (
	// AttestationOff treats attestations as informational only: every
	// validly declared package remains installable regardless of whether
	// it has been attested.
	AttestationOff AttestationMode = "off"
	// AttestationPrefer keeps every validly declared package installable,
	// but marks a declaration verified when an acceptable attestation
	// exists.
	AttestationPrefer AttestationMode = "prefer"
	// AttestationRequire excludes a declaration from the generated
	// catalogue unless it has an acceptable attestation.
	AttestationRequire AttestationMode = "require"
)

// ParseAttestationMode parses a mode string (as configured on the daemon or
// the YunoHost config panel), defaulting to AttestationOff for an empty
// string so an unconfigured daemon behaves exactly as it did before this
// policy existed.
func ParseAttestationMode(raw string) (AttestationMode, error) {
	switch AttestationMode(raw) {
	case "", AttestationOff:
		return AttestationOff, nil
	case AttestationPrefer:
		return AttestationPrefer, nil
	case AttestationRequire:
		return AttestationRequire, nil
	default:
		return "", fmt.Errorf("invalid attestation policy %q: must be off, prefer, or require", raw)
	}
}

// AttestationPolicy decides, for one declaration, how its attestations
// affect the generated catalogue under Mode. The zero value behaves as
// AttestationOff with every extension below at its most permissive
// setting, so existing callers that only ever set Mode keep working
// unchanged - these fields are the plan's Phase 12 "advanced trust
// policies" extension, deliberately deferred until Phase 6 shipped the
// simple off/prefer/require MVP first.
type AttestationPolicy struct {
	Mode AttestationMode
	// MinimumAttestations is how many independent, acceptable attestations
	// a revision needs before it counts as Verified. Zero or negative is
	// treated as 1 (the pre-Phase-12 behavior: any single acceptable
	// attestation was enough).
	MinimumAttestations int
	// RequiredChecks, when non-empty, replaces "acceptable = overall result
	// is pass" with "acceptable = every named check in this attestation's
	// own Checks map is pass" - regardless of that attestation's overall
	// Result. This is what lets an administrator require e.g.
	// "package_check" while treating an unrelated failing check (e.g.
	// vulnerability_scan) as advisory, per the plan's own example: a
	// specific required check passing is what's being trusted, not
	// whichever verdict the CI run happened to summarize itself as.
	RequiredChecks []string
	// TrustedVerifiers, when non-empty, restricts which attestations count
	// at all to those signed by one of these verifier public keys (lowercase
	// hex - use NewAttestationPolicy to build this from npub/hex input).
	// Empty means every verifier is trusted, the pre-Phase-12 behavior.
	TrustedVerifiers map[string]struct{}
}

// NewAttestationPolicy builds a validated AttestationPolicy from
// configuration-shaped input (npub or hex verifier keys, as the daemon flag
// and YunoHost config panel accept elsewhere - see trust.ExplicitPublishers
// and curation.NewPolicy for the same pattern). Passing zero
// minimumAttestations or empty requiredChecks/trustedVerifiers keeps the
// corresponding field at its permissive default; direct struct
// construction (AttestationPolicy{Mode: ...}) remains valid for callers
// that only need Mode.
func NewAttestationPolicy(mode AttestationMode, minimumAttestations int, requiredChecks, trustedVerifiers []string) (AttestationPolicy, error) {
	if minimumAttestations < 0 {
		return AttestationPolicy{}, fmt.Errorf("minimum attestations must not be negative")
	}
	checks := make([]string, 0, len(requiredChecks))
	for _, name := range requiredChecks {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		checks = append(checks, name)
	}
	var verifiers map[string]struct{}
	if len(trustedVerifiers) > 0 {
		verifiers = make(map[string]struct{}, len(trustedVerifiers))
		for _, raw := range trustedVerifiers {
			key, err := normalizePublicKey(raw)
			if err != nil {
				return AttestationPolicy{}, fmt.Errorf("trusted verifier: %w", err)
			}
			verifiers[key] = struct{}{}
		}
	}
	return AttestationPolicy{
		Mode:                mode,
		MinimumAttestations: minimumAttestations,
		RequiredChecks:      checks,
		TrustedVerifiers:    verifiers,
	}, nil
}

// TrustedVerifierKeys returns the configured trusted-verifier hex keys in
// stable sorted order, for display (e.g. the admin trust dashboard) or
// re-serializing configuration.
func (p AttestationPolicy) TrustedVerifierKeys() []string {
	keys := make([]string, 0, len(p.TrustedVerifiers))
	for key := range p.TrustedVerifiers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// AttestationDecision is the result of evaluating a declaration's
// attestations against the local policy.
type AttestationDecision struct {
	// Accepted reports whether the declaration may appear in the generated
	// catalogue at all. Always true under Off and Prefer; under Require,
	// true only when Verified is true.
	Accepted bool
	// Verified reports whether at least one acceptable attestation exists
	// for this declaration's exact revision, regardless of Mode.
	Verified bool
}

// acceptable reports whether a single attestation counts toward Verified,
// independent of which verifier signed it - trustedVerifier below filters
// on that separately, so a rejected-by-verifier attestation is never even
// passed to acceptable in the first place. With RequiredChecks empty, this
// is the pre-Phase-12 MVP criterion: an overall "pass" result. With
// RequiredChecks set, the overall Result is ignored entirely - only the
// named checks matter, which is what lets a required check pass while an
// unrelated advisory check fails without disqualifying the attestation.
func (p AttestationPolicy) acceptable(a verification.Attestation) bool {
	if len(p.RequiredChecks) == 0 {
		return a.Result == "pass"
	}
	for _, name := range p.RequiredChecks {
		if a.Checks[name] != "pass" {
			return false
		}
	}
	return true
}

// trustedVerifier reports whether verifier (hex pubkey) may contribute to
// Verified at all. An empty TrustedVerifiers trusts every verifier, the
// pre-Phase-12 behavior.
func (p AttestationPolicy) trustedVerifier(verifier string) bool {
	if len(p.TrustedVerifiers) == 0 {
		return true
	}
	_, ok := p.TrustedVerifiers[verifier]
	return ok
}

// EffectiveMinimumAttestations returns MinimumAttestations, treating zero
// or negative as 1 - the pre-Phase-12 behavior where any single acceptable
// attestation was enough. Use this rather than reading MinimumAttestations
// directly when displaying the policy's actual effect (e.g. the admin
// trust dashboard).
func (p AttestationPolicy) EffectiveMinimumAttestations() int {
	if p.MinimumAttestations <= 0 {
		return 1
	}
	return p.MinimumAttestations
}

// Evaluate applies Mode to every attestation available for one declaration
// (typically catalog.Store.AttestationsFor's result, which has already
// confirmed each attestation matches this exact revision's hashes).
// Verified requires at least minimumAttestations distinct, trusted,
// acceptable attestations - distinct because AttestationsFor already
// dedupes to one attestation per verifier for this revision, so counting
// entries here is already counting independent verifiers, not just events.
func (p AttestationPolicy) Evaluate(attestations []verification.Attestation) AttestationDecision {
	accepted := 0
	for _, a := range attestations {
		if p.trustedVerifier(a.Verifier) && p.acceptable(a) {
			accepted++
		}
	}
	verified := accepted >= p.EffectiveMinimumAttestations()
	if p.Mode == AttestationRequire {
		return AttestationDecision{Accepted: verified, Verified: verified}
	}
	return AttestationDecision{Accepted: true, Verified: verified}
}
