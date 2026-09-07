package trust

import (
	"testing"

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
