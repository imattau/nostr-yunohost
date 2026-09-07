package trust

import (
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nostr-yunohost/nostr-yunohost/internal/verification"
)

func TestParseAttestationMode(t *testing.T) {
	cases := map[string]AttestationMode{
		"":        AttestationOff,
		"off":     AttestationOff,
		"prefer":  AttestationPrefer,
		"require": AttestationRequire,
	}
	for raw, want := range cases {
		got, err := ParseAttestationMode(raw)
		if err != nil {
			t.Fatalf("ParseAttestationMode(%q): %v", raw, err)
		}
		if got != want {
			t.Fatalf("ParseAttestationMode(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestParseAttestationModeRejectsUnknown(t *testing.T) {
	if _, err := ParseAttestationMode("strict"); err == nil {
		t.Fatal("ParseAttestationMode accepted an unknown mode")
	}
}

func TestAttestationPolicyOffAlwaysAccepts(t *testing.T) {
	policy := AttestationPolicy{Mode: AttestationOff}

	unattested := policy.Evaluate(nil)
	if !unattested.Accepted || unattested.Verified {
		t.Fatalf("off/unattested: %+v", unattested)
	}

	attested := policy.Evaluate([]verification.Attestation{{Result: "pass"}})
	if !attested.Accepted || !attested.Verified {
		t.Fatalf("off/attested: %+v", attested)
	}

	failed := policy.Evaluate([]verification.Attestation{{Result: "fail"}})
	if !failed.Accepted || failed.Verified {
		t.Fatalf("off/failed-only: %+v", failed)
	}
}

func TestAttestationPolicyPreferAlwaysAcceptsButMarksVerified(t *testing.T) {
	policy := AttestationPolicy{Mode: AttestationPrefer}

	unattested := policy.Evaluate(nil)
	if !unattested.Accepted || unattested.Verified {
		t.Fatalf("prefer/unattested: %+v", unattested)
	}

	attested := policy.Evaluate([]verification.Attestation{{Result: "pass"}})
	if !attested.Accepted || !attested.Verified {
		t.Fatalf("prefer/attested: %+v", attested)
	}

	failedOnly := policy.Evaluate([]verification.Attestation{{Result: "fail"}})
	if !failedOnly.Accepted || failedOnly.Verified {
		t.Fatalf("prefer/failed-only: %+v", failedOnly)
	}
}

func TestAttestationPolicyRequireExcludesUnattested(t *testing.T) {
	policy := AttestationPolicy{Mode: AttestationRequire}

	unattested := policy.Evaluate(nil)
	if unattested.Accepted || unattested.Verified {
		t.Fatalf("require/unattested: %+v", unattested)
	}

	failedOnly := policy.Evaluate([]verification.Attestation{{Result: "fail"}})
	if failedOnly.Accepted || failedOnly.Verified {
		t.Fatalf("require/failed-only attestation must not satisfy require: %+v", failedOnly)
	}

	attested := policy.Evaluate([]verification.Attestation{{Result: "pass"}})
	if !attested.Accepted || !attested.Verified {
		t.Fatalf("require/attested: %+v", attested)
	}
}

func TestAttestationPolicyRequireAcceptsWhenAnyAttestationPasses(t *testing.T) {
	policy := AttestationPolicy{Mode: AttestationRequire}
	mixed := policy.Evaluate([]verification.Attestation{{Result: "fail"}, {Result: "pass"}})
	if !mixed.Accepted || !mixed.Verified {
		t.Fatalf("require/mixed (one passing verifier among several) should be accepted: %+v", mixed)
	}
}

func TestAttestationPolicyZeroValueBehavesAsOff(t *testing.T) {
	var policy AttestationPolicy
	decision := policy.Evaluate([]verification.Attestation{{Result: "fail"}})
	if !decision.Accepted {
		t.Fatalf("zero-value AttestationPolicy must behave as off (always accept): %+v", decision)
	}
}

func TestAttestationPolicyMinimumAttestations(t *testing.T) {
	policy := AttestationPolicy{Mode: AttestationRequire, MinimumAttestations: 2}

	one := policy.Evaluate([]verification.Attestation{{Verifier: "a", Result: "pass"}})
	if one.Accepted || one.Verified {
		t.Fatalf("one passing attestation should not satisfy minimum_attestations=2: %+v", one)
	}

	two := policy.Evaluate([]verification.Attestation{{Verifier: "a", Result: "pass"}, {Verifier: "b", Result: "pass"}})
	if !two.Accepted || !two.Verified {
		t.Fatalf("two passing attestations should satisfy minimum_attestations=2: %+v", two)
	}

	mixed := policy.Evaluate([]verification.Attestation{{Verifier: "a", Result: "pass"}, {Verifier: "b", Result: "fail"}})
	if mixed.Accepted || mixed.Verified {
		t.Fatalf("one passing plus one failing should not satisfy minimum_attestations=2: %+v", mixed)
	}
}

func TestAttestationPolicyMinimumAttestationsZeroOrNegativeDefaultsToOne(t *testing.T) {
	for _, minimum := range []int{0, -1} {
		policy := AttestationPolicy{Mode: AttestationRequire, MinimumAttestations: minimum}
		decision := policy.Evaluate([]verification.Attestation{{Verifier: "a", Result: "pass"}})
		if !decision.Accepted || !decision.Verified {
			t.Fatalf("MinimumAttestations=%d should behave as 1, got: %+v", minimum, decision)
		}
	}
}

func TestAttestationPolicyRequiredChecks(t *testing.T) {
	policy := AttestationPolicy{Mode: AttestationRequire, RequiredChecks: []string{"package_check"}}

	// Overall result is "fail" (an advisory check failed), but the
	// specifically required check passed - this is the plan's own example:
	// requiring package_check while treating other checks as advisory.
	advisoryFailureOnly := policy.Evaluate([]verification.Attestation{{
		Result: "fail",
		Checks: map[string]string{"package_check": "pass", "vulnerability_scan": "fail"},
	}})
	if !advisoryFailureOnly.Accepted || !advisoryFailureOnly.Verified {
		t.Fatalf("a failing advisory check must not disqualify a passing required check: %+v", advisoryFailureOnly)
	}

	// Overall result is "pass", but the specifically required check is
	// missing/failed - required_checks must not be satisfied by a merely
	// good-looking overall result.
	missingRequiredCheck := policy.Evaluate([]verification.Attestation{{
		Result: "pass",
		Checks: map[string]string{"shellcheck": "pass"},
	}})
	if missingRequiredCheck.Accepted || missingRequiredCheck.Verified {
		t.Fatalf("a passing overall result without the required check must not satisfy required_checks: %+v", missingRequiredCheck)
	}
}

func TestAttestationPolicyTrustedVerifiers(t *testing.T) {
	policy, err := NewAttestationPolicy(AttestationRequire, 0, nil, []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if err != nil {
		t.Fatal(err)
	}

	untrusted := policy.Evaluate([]verification.Attestation{{Verifier: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Result: "pass"}})
	if untrusted.Accepted || untrusted.Verified {
		t.Fatalf("an attestation from an untrusted verifier must not satisfy require: %+v", untrusted)
	}

	trusted := policy.Evaluate([]verification.Attestation{{Verifier: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Result: "pass"}})
	if !trusted.Accepted || !trusted.Verified {
		t.Fatalf("an attestation from a trusted verifier should satisfy require: %+v", trusted)
	}
}

func TestNewAttestationPolicyAcceptsNpubTrustedVerifiers(t *testing.T) {
	hexKey, err := nostr.GetPublicKey(strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	npub, err := nip19.EncodePublicKey(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewAttestationPolicy(AttestationRequire, 0, nil, []string{npub})
	if err != nil {
		t.Fatal(err)
	}
	keys := policy.TrustedVerifierKeys()
	if len(keys) != 1 || keys[0] != hexKey {
		t.Fatalf("expected the npub to normalize to its hex key, got: %+v", keys)
	}
}

func TestNewAttestationPolicyRejectsInvalidVerifierKey(t *testing.T) {
	if _, err := NewAttestationPolicy(AttestationRequire, 0, nil, []string{"not-a-key"}); err == nil {
		t.Fatal("NewAttestationPolicy accepted an invalid trusted verifier key")
	}
}

func TestNewAttestationPolicyRejectsNegativeMinimum(t *testing.T) {
	if _, err := NewAttestationPolicy(AttestationRequire, -1, nil, nil); err == nil {
		t.Fatal("NewAttestationPolicy accepted a negative minimum attestation count")
	}
}
