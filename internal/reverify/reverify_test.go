package reverify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/imattau/nostr-yunohost/internal/protocol"
	"github.com/imattau/nostr-yunohost/internal/publisher"
	"github.com/imattau/nostr-yunohost/internal/verification"
)

// newReverifyTestRepo creates a real local git repo, committed with a
// manifest.toml, and returns its directory (usable directly as a `git
// clone` source - unlike newTestPackageRepo's fake GitHub origin, reverify
// actually clones the repository) plus its HEAD commit and the sha256
// manifest/content hashes repository.VerifyDeclaration will recompute.
func newReverifyTestRepo(t *testing.T) (directory, commit, manifestHash, contentHash string) {
	t.Helper()
	directory = t.TempDir()
	manifest := []byte("id = \"reverifyapp\"\nversion = \"1.0.0~ynh1\"\nname = \"Reverify App\"\n")
	if err := os.WriteFile(filepath.Join(directory, "manifest.toml"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "test@example.invalid"},
		{"config", "user.name", "Test"},
		{"add", "manifest.toml"},
		{"commit", "-m", "test"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = directory
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v (%s)", args, err, out)
		}
	}
	head := exec.Command("git", "rev-parse", "HEAD")
	head.Dir = directory
	out, err := head.Output()
	if err != nil {
		t.Fatalf("rev-parse HEAD: %v", err)
	}
	commit = strings.TrimSpace(string(out))
	archive := exec.Command("git", "archive", "--format=tar", "HEAD")
	archive.Dir = directory
	archiveBytes, err := archive.Output()
	if err != nil {
		t.Fatalf("git archive: %v", err)
	}
	return directory, commit, publisher.HashBytes(manifest), publisher.HashBytes(archiveBytes)
}

func newReverifyDeclaration(repo, commit, manifestHash, contentHash, publisherPubkey string) protocol.AppDeclaration {
	return protocol.AppDeclaration{
		AppID:        "reverifyapp",
		Publisher:    publisherPubkey,
		Repository:   repo,
		Version:      "1.0.0~ynh1",
		Commit:       commit,
		ManifestHash: manifestHash,
		ContentHash:  contentHash,
	}
}

func newReverifyAttestation(repo, commit, manifestHash, contentHash, verifierPubkey string) verification.Attestation {
	return verification.Attestation{
		Verifier:     verifierPubkey,
		AppID:        "reverifyapp",
		Repository:   repo,
		Commit:       commit,
		ManifestHash: manifestHash,
		ContentHash:  contentHash,
		CIProvider:   "github-actions",
		CIRef:        "https://github.com/example/reverifyapp_ynh/actions/runs/1",
		Checks:       map[string]string{"yunohost_lint": "pass"},
		Result:       "pass",
	}
}

func TestReverifyMatchesWhenDeclarationAttestationAndRepositoryAllAgree(t *testing.T) {
	repo, commit, manifestHash, contentHash := newReverifyTestRepo(t)
	pubkey := strings.Repeat("ab", 32)
	declaration := newReverifyDeclaration(repo, commit, manifestHash, contentHash, pubkey)
	attestation := newReverifyAttestation(repo, commit, manifestHash, contentHash, pubkey)

	result := Run(context.Background(), attestation, declaration)

	if !result.Match {
		t.Fatalf("expected match, got mismatches: %v", result.Mismatches)
	}
	if result.Result != "pass" || result.Checks["yunohost_lint"] != "pass" {
		t.Fatalf("attested checks/result not carried through: %+v", result)
	}
}

func TestReverifyDetectsDeclarationAttestationCommitMismatch(t *testing.T) {
	repo, commit, manifestHash, contentHash := newReverifyTestRepo(t)
	pubkey := strings.Repeat("ab", 32)
	declaration := newReverifyDeclaration(repo, commit, manifestHash, contentHash, pubkey)
	// A declaration republished after the attestation, now pointing at a
	// different (unattested) commit - the case this check exists for.
	attestation := newReverifyAttestation(repo, strings.Repeat("f", 40), manifestHash, contentHash, pubkey)

	result := Run(context.Background(), attestation, declaration)

	if result.Match {
		t.Fatal("expected a mismatch when declaration and attestation disagree on commit")
	}
	found := false
	for _, mismatch := range result.Mismatches {
		if strings.HasPrefix(mismatch, "commit:") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a commit mismatch entry, got: %v", result.Mismatches)
	}
}

func TestReverifyDetectsRepositoryContentDriftFromWhatWasAttested(t *testing.T) {
	repo, commit, _, contentHash := newReverifyTestRepo(t)
	pubkey := strings.Repeat("ab", 32)
	declaration := newReverifyDeclaration(repo, commit, "sha256:"+strings.Repeat("0", 64), contentHash, pubkey)
	// The attestation claims a manifest hash that does not match what is
	// actually in the repository at this commit - simulates a false claim
	// (compromised CI, or a publisher key signing a lie) that only an
	// independent clone-and-recompute, not the signature, can catch.
	attestation := newReverifyAttestation(repo, commit, "sha256:"+strings.Repeat("0", 64), contentHash, pubkey)

	result := Run(context.Background(), attestation, declaration)

	if result.Match {
		t.Fatal("expected a mismatch when the attested manifest hash does not match the real repository content")
	}
	found := false
	for _, mismatch := range result.Mismatches {
		if strings.HasPrefix(mismatch, "repository content:") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a repository content mismatch entry, got: %v", result.Mismatches)
	}
}
