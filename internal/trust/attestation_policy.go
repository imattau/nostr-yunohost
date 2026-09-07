package trust

import (
	"fmt"

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
// AttestationOff.
type AttestationPolicy struct {
	Mode AttestationMode
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

// acceptable reports whether a single attestation counts toward Verified.
// The MVP criterion is deliberately simple - an overall "pass" result -
// leaving minimum_attestations/required_checks/trusted_verifiers as the
// later, explicitly deferred extension the plan describes (Phase 12).
func acceptable(a verification.Attestation) bool {
	return a.Result == "pass"
}

// Evaluate applies Mode to every attestation available for one declaration
// (typically catalog.Store.AttestationsFor's result, which has already
// confirmed each attestation matches this exact revision's hashes).
func (p AttestationPolicy) Evaluate(attestations []verification.Attestation) AttestationDecision {
	verified := false
	for _, a := range attestations {
		if acceptable(a) {
			verified = true
			break
		}
	}
	if p.Mode == AttestationRequire {
		return AttestationDecision{Accepted: verified, Verified: verified}
	}
	return AttestationDecision{Accepted: true, Verified: verified}
}
