package verification

import (
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

const testPrivateKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var (
	testManifestHash = "sha256:" + strings.Repeat("0", 64)
	testContentHash  = "sha256:" + strings.Repeat("1", 64)
)

func validChecks() map[string]string {
	return map[string]string{
		"yunohost_lint": "pass",
		"shellcheck":    "pass",
		"secret_scan":   "pass",
	}
}

func TestBuildAndParseAttestation(t *testing.T) {
	event, err := Build("ditto", "https://github.com/example/ditto_ynh", strings.Repeat("a", 40), testManifestHash, testContentHash, "github-actions", "run-42", validChecks(), "pass", testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := Parse(event)
	if err != nil {
		t.Fatal(err)
	}
	if attestation.AppID != "ditto" || attestation.Commit != strings.Repeat("a", 40) || attestation.Result != "pass" {
		t.Fatalf("unexpected attestation: %+v", attestation)
	}
	if attestation.Checks["yunohost_lint"] != "pass" {
		t.Fatalf("unexpected checks: %+v", attestation.Checks)
	}
}

func TestAttestationAddressIncludesCommit(t *testing.T) {
	eventABC, err := Build("ditto", "https://github.com/example/ditto_ynh", strings.Repeat("a", 40), testManifestHash, testContentHash, "github-actions", "run-1", validChecks(), "pass", testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	eventDEF, err := Build("ditto", "https://github.com/example/ditto_ynh", strings.Repeat("b", 40), testManifestHash, testContentHash, "github-actions", "run-2", validChecks(), "pass", testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dABC, dDEF := tagValue(eventABC.Tags, "d"), tagValue(eventDEF.Tags, "d")
	if dABC == dDEF {
		t.Fatalf("attestations for different commits must have different addresses, got %q for both", dABC)
	}
}

func TestBuildRejectsMissingChecks(t *testing.T) {
	if _, err := Build("ditto", "https://github.com/example/ditto_ynh", strings.Repeat("a", 40), testManifestHash, testContentHash, "github-actions", "run-1", nil, "pass", testPrivateKey); err == nil {
		t.Fatal("Build() accepted an attestation with no checks")
	}
}

func TestBuildRejectsInvalidCommit(t *testing.T) {
	if _, err := Build("ditto", "https://github.com/example/ditto_ynh", "not-a-commit", testManifestHash, testContentHash, "github-actions", "run-1", validChecks(), "pass", testPrivateKey); err == nil {
		t.Fatal("Build() accepted an invalid commit")
	}
}

func TestBuildRejectsInvalidResult(t *testing.T) {
	if _, err := Build("ditto", "https://github.com/example/ditto_ynh", strings.Repeat("a", 40), testManifestHash, testContentHash, "github-actions", "run-1", validChecks(), "maybe", testPrivateKey); err == nil {
		t.Fatal("Build() accepted an invalid result")
	}
}

func TestParseRejectsWrongKind(t *testing.T) {
	event, err := Build("ditto", "https://github.com/example/ditto_ynh", strings.Repeat("a", 40), testManifestHash, testContentHash, "github-actions", "run-1", validChecks(), "pass", testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	event.Kind = 1
	if err := event.Sign(testPrivateKey); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(event); err == nil {
		t.Fatal("Parse() accepted the wrong event kind")
	}
}

func TestParseRejectsTamperedAddress(t *testing.T) {
	event, err := Build("ditto", "https://github.com/example/ditto_ynh", strings.Repeat("a", 40), testManifestHash, testContentHash, "github-actions", "run-1", validChecks(), "pass", testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for i, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "commit" {
			event.Tags[i][1] = strings.Repeat("c", 40)
		}
	}
	if err := event.Sign(testPrivateKey); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(event); err == nil {
		t.Fatal("Parse() accepted a commit tag that disagrees with the d-tag address")
	}
}

func tagValue(tags nostr.Tags, name string) string {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == name {
			return tag[1]
		}
	}
	return ""
}
