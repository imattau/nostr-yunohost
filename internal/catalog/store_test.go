package catalog

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nostr-yunohost/nostr-yunohost/internal/curation"
	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
	"github.com/nostr-yunohost/nostr-yunohost/internal/trust"
	"github.com/nostr-yunohost/nostr-yunohost/internal/verification"
)

func TestStoreIngestsAndOrdersDeclarations(t *testing.T) {
	first := signedEvent(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "first_app")
	second := signedEvent(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "second_app")
	firstPublisher, _ := nostr.GetPublicKey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	secondPublisher, _ := nostr.GetPublicKey("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	policy, err := trust.NewExplicitPublishers([]string{firstPublisher, secondPublisher})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	if err := store.Ingest(second); err != nil {
		t.Fatal(err)
	}
	if err := store.Ingest(first); err != nil {
		t.Fatal(err)
	}
	declarations := store.Snapshot()
	if len(declarations) != 2 || declarations[0].AppID != "second_app" {
		t.Fatalf("unexpected snapshot: %+v", declarations)
	}
	var output bytes.Buffer
	if err := store.WriteSnapshot(&output); err != nil {
		t.Fatal(err)
	}
	if output.Len() == 0 {
		t.Fatal("snapshot was empty")
	}
}
func TestWriteSnapshotIncludesVerifiedApps(t *testing.T) {
	event := signedEvent(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "hello_nostr")
	publicKey, _ := nostr.GetPublicKey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	policy, err := trust.NewExplicitPublishers([]string{publicKey})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	verify := func(_ context.Context, declaration protocol.AppDeclaration) (map[string]any, error) {
		return map[string]any{"id": declaration.AppID, "version": declaration.Version}, nil
	}
	if err := store.IngestVerified(context.Background(), event, verify); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := store.WriteSnapshot(&output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"apps":{"hello_nostr"`)) {
		t.Fatalf("snapshot did not contain keyed app: %s", output.String())
	}
}

func TestStoreCacheRoundTrip(t *testing.T) {
	event := signedEvent(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "hello_nostr")
	publicKey, _ := nostr.GetPublicKey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	policy, err := trust.NewExplicitPublishers([]string{publicKey})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	verify := func(_ context.Context, declaration protocol.AppDeclaration) (map[string]any, error) {
		return map[string]any{"id": declaration.AppID, "version": declaration.Version}, nil
	}
	if err := store.IngestVerified(context.Background(), event, verify); err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(t.TempDir(), "catalogue.json")
	if err := store.Save(cachePath); err != nil {
		t.Fatal(err)
	}
	restored := NewStore(policy)
	if err := restored.Load(cachePath); err != nil {
		t.Fatal(err)
	}
	if got := restored.Snapshot(); len(got) != 1 || got[0].AppID != "hello_nostr" {
		t.Fatalf("unexpected restored snapshot: %+v", got)
	}
}

func TestWriteSnapshotOmitsPublisherCollision(t *testing.T) {
	first := signedEvent(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "same_app")
	second := signedEventWith(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "same_app", "https://github.com/example/other_app_ynh", "1.0.0~ynh1", 1)
	firstPublisher, _ := nostr.GetPublicKey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	secondPublisher, _ := nostr.GetPublicKey("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	policy, err := trust.NewExplicitPublishers([]string{firstPublisher, secondPublisher})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	verify := func(_ context.Context, declaration protocol.AppDeclaration) (map[string]any, error) {
		return map[string]any{"id": declaration.AppID, "version": declaration.Version}, nil
	}
	if err := store.IngestVerified(context.Background(), first, verify); err != nil {
		t.Fatal(err)
	}
	if err := store.IngestVerified(context.Background(), second, verify); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := store.WriteSnapshot(&output); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output.Bytes(), []byte(`"same_app"`)) {
		t.Fatalf("snapshot included an ambiguous app: %s", output.String())
	}
}

func TestWriteSnapshotSelectsLatestVerifiedSameSource(t *testing.T) {
	first := signedEventWith(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "same_app", "https://github.com/example/app_ynh.git/", "1.0.0~ynh1", 10)
	second := signedEventWith(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "same_app", "https://github.com/example/app_ynh", "1.1.0~ynh1", 1)
	firstPublisher, _ := nostr.GetPublicKey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	secondPublisher, _ := nostr.GetPublicKey("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	policy, err := trust.NewExplicitPublishers([]string{firstPublisher, secondPublisher})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	verify := func(_ context.Context, declaration protocol.AppDeclaration) (map[string]any, error) {
		return map[string]any{"id": declaration.AppID, "version": declaration.Version}, nil
	}
	if err := store.IngestVerified(context.Background(), first, verify); err != nil {
		t.Fatal(err)
	}
	if err := store.IngestVerified(context.Background(), second, verify); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := store.WriteSnapshot(&output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"version":"1.1.0~ynh1"`)) {
		t.Fatalf("snapshot did not select highest same-source version: %s", output.String())
	}
}

func TestWriteSnapshotSetsHighQualityOnceThresholdMet(t *testing.T) {
	event := signedEvent(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "hello_nostr")
	publisher, _ := nostr.GetPublicKey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	policy, err := trust.NewExplicitPublishers([]string{publisher})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	verify := func(_ context.Context, declaration protocol.AppDeclaration) (map[string]any, error) {
		return map[string]any{"id": declaration.AppID, "version": declaration.Version}, nil
	}
	if err := store.IngestVerified(context.Background(), event, verify); err != nil {
		t.Fatal(err)
	}

	// No curation policy configured: HighQuality must stay false.
	var withoutPolicy bytes.Buffer
	if err := store.WriteSnapshot(&withoutPolicy); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(withoutPolicy.Bytes(), []byte(`"high_quality":true`)) {
		t.Fatalf("expected high_quality false with no curation policy: %s", withoutPolicy.String())
	}

	curatorKey := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	curator, _ := nostr.GetPublicKey(curatorKey)
	curationPolicy, err := curation.NewPolicy([]string{curator}, 1)
	if err != nil {
		t.Fatal(err)
	}
	store.SetCurationPolicy(curationPolicy)

	// Below threshold (no endorsements yet): still false.
	var belowThreshold bytes.Buffer
	if err := store.WriteSnapshot(&belowThreshold); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(belowThreshold.Bytes(), []byte(`"high_quality":true`)) {
		t.Fatalf("expected high_quality false below threshold: %s", belowThreshold.String())
	}

	endorsementEvent, err := curation.Build(publisher, "hello_nostr", "tested", "works great", curatorKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.IngestEndorsement(endorsementEvent); err != nil {
		t.Fatal(err)
	}

	var atThreshold bytes.Buffer
	if err := store.WriteSnapshot(&atThreshold); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(atThreshold.Bytes(), []byte(`"high_quality":true`)) {
		t.Fatalf("expected high_quality true once the endorsement threshold is met: %s", atThreshold.String())
	}
}

const (
	testDeclarationCommit   = "cccccccccccccccccccccccccccccccccccccccc"
	testDeclarationManifest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	testDeclarationContent  = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

func TestIngestAttestationMatchesDeclaration(t *testing.T) {
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	verifierKey := strings.Repeat("1", 64)
	event := signedEvent(t, publisherKey, "hello_nostr")
	publisher, _ := nostr.GetPublicKey(publisherKey)
	policy, err := trust.NewExplicitPublishers([]string{publisher})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	if err := store.Ingest(event); err != nil {
		t.Fatal(err)
	}
	declaration := store.Snapshot()[0]

	attestation := signedAttestation(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent)
	if err := store.IngestAttestation(attestation); err != nil {
		t.Fatal(err)
	}

	matched := store.AttestationsFor(declaration)
	verifier, _ := nostr.GetPublicKey(verifierKey)
	if len(matched) != 1 || matched[0].Verifier != verifier {
		t.Fatalf("unexpected matched attestations: %+v", matched)
	}
}

func TestAttestationsForRejectsHashMismatch(t *testing.T) {
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	verifierKey := strings.Repeat("2", 64)
	event := signedEvent(t, publisherKey, "hello_nostr")
	publisher, _ := nostr.GetPublicKey(publisherKey)
	policy, err := trust.NewExplicitPublishers([]string{publisher})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	if err := store.Ingest(event); err != nil {
		t.Fatal(err)
	}
	declaration := store.Snapshot()[0]

	// Same repo and commit as the declaration, but a manifest hash that
	// disagrees with what the declaration actually advertises - the shape
	// a forged or stale attestation would take.
	forged := signedAttestation(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, "sha256:"+strings.Repeat("f", 64), testDeclarationContent)
	if err := store.IngestAttestation(forged); err != nil {
		t.Fatal(err)
	}

	if matched := store.AttestationsFor(declaration); len(matched) != 0 {
		t.Fatalf("AttestationsFor returned a hash-mismatched attestation as valid: %+v", matched)
	}
}

func TestAttestationsForRejectsDifferentCommit(t *testing.T) {
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	verifierKey := strings.Repeat("3", 64)
	event := signedEvent(t, publisherKey, "hello_nostr")
	publisher, _ := nostr.GetPublicKey(publisherKey)
	policy, err := trust.NewExplicitPublishers([]string{publisher})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	if err := store.Ingest(event); err != nil {
		t.Fatal(err)
	}
	declaration := store.Snapshot()[0]

	oldCommit := strings.Repeat("9", 40)
	attestation := signedAttestation(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", oldCommit, testDeclarationManifest, testDeclarationContent)
	if err := store.IngestAttestation(attestation); err != nil {
		t.Fatal(err)
	}

	if matched := store.AttestationsFor(declaration); len(matched) != 0 {
		t.Fatalf("AttestationsFor returned an attestation for a different commit as valid: %+v", matched)
	}
}

func TestIngestAttestationDedupesBySameVerifierNewerWins(t *testing.T) {
	verifierKey := strings.Repeat("4", 64)
	older := signedAttestationAt(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent, "fail", 1)
	newer := signedAttestationAt(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent, "pass", 2)

	store := NewStore(trust.ExplicitPublishers{})
	if err := store.IngestAttestation(newer); err != nil {
		t.Fatal(err)
	}
	if err := store.IngestAttestation(older); err != nil {
		t.Fatal(err)
	}

	matched := store.AttestationsFor(protocol.AppDeclaration{
		Repository:   "https://github.com/example/app_ynh",
		Commit:       testDeclarationCommit,
		ManifestHash: testDeclarationManifest,
		ContentHash:  testDeclarationContent,
	})
	if len(matched) != 1 || matched[0].Result != "pass" {
		t.Fatalf("an older attestation from the same verifier overwrote the newer one: %+v", matched)
	}
}

func TestAttestationsForSupportsMultipleVerifiers(t *testing.T) {
	firstVerifier := strings.Repeat("5", 64)
	secondVerifier := strings.Repeat("6", 64)
	store := NewStore(trust.ExplicitPublishers{})
	if err := store.IngestAttestation(signedAttestation(t, firstVerifier, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent)); err != nil {
		t.Fatal(err)
	}
	if err := store.IngestAttestation(signedAttestation(t, secondVerifier, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent)); err != nil {
		t.Fatal(err)
	}

	matched := store.AttestationsFor(protocol.AppDeclaration{
		Repository:   "https://github.com/example/app_ynh",
		Commit:       testDeclarationCommit,
		ManifestHash: testDeclarationManifest,
		ContentHash:  testDeclarationContent,
	})
	if len(matched) != 2 {
		t.Fatalf("expected attestations from both independent verifiers, got: %+v", matched)
	}
}

func TestIngestAttestationRejectsMalformedEvent(t *testing.T) {
	store := NewStore(trust.ExplicitPublishers{})
	malformed := nostr.Event{Kind: 1}
	if err := store.IngestAttestation(malformed); err == nil {
		t.Fatal("IngestAttestation accepted an event that is not a valid attestation")
	}
}

func TestWriteSnapshotRequirePolicyExcludesUnattested(t *testing.T) {
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	event := signedEvent(t, publisherKey, "hello_nostr")
	publisher, _ := nostr.GetPublicKey(publisherKey)
	policy, err := trust.NewExplicitPublishers([]string{publisher})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	store.SetAttestationPolicy(trust.AttestationPolicy{Mode: trust.AttestationRequire})
	verify := func(_ context.Context, declaration protocol.AppDeclaration) (map[string]any, error) {
		return map[string]any{"id": declaration.AppID, "version": declaration.Version}, nil
	}
	if err := store.IngestVerified(context.Background(), event, verify); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := store.WriteSnapshot(&output); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output.Bytes(), []byte(`"hello_nostr"`)) {
		t.Fatalf("require policy should exclude an app with no attestation: %s", output.String())
	}
}

func TestWriteSnapshotRequirePolicyExcludesFailedAttestationOnly(t *testing.T) {
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	verifierKey := strings.Repeat("7", 64)
	event := signedEvent(t, publisherKey, "hello_nostr")
	publisher, _ := nostr.GetPublicKey(publisherKey)
	policy, err := trust.NewExplicitPublishers([]string{publisher})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	store.SetAttestationPolicy(trust.AttestationPolicy{Mode: trust.AttestationRequire})
	verify := func(_ context.Context, declaration protocol.AppDeclaration) (map[string]any, error) {
		return map[string]any{"id": declaration.AppID, "version": declaration.Version}, nil
	}
	if err := store.IngestVerified(context.Background(), event, verify); err != nil {
		t.Fatal(err)
	}
	failing := signedAttestationAt(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent, "fail", 1)
	if err := store.IngestAttestation(failing); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := store.WriteSnapshot(&output); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output.Bytes(), []byte(`"hello_nostr"`)) {
		t.Fatalf("require policy should exclude an app whose only attestation failed: %s", output.String())
	}
}

func TestWriteSnapshotRequirePolicyIncludesAttestedApp(t *testing.T) {
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	verifierKey := strings.Repeat("8", 64)
	event := signedEvent(t, publisherKey, "hello_nostr")
	publisher, _ := nostr.GetPublicKey(publisherKey)
	policy, err := trust.NewExplicitPublishers([]string{publisher})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	store.SetAttestationPolicy(trust.AttestationPolicy{Mode: trust.AttestationRequire})
	verify := func(_ context.Context, declaration protocol.AppDeclaration) (map[string]any, error) {
		return map[string]any{"id": declaration.AppID, "version": declaration.Version}, nil
	}
	if err := store.IngestVerified(context.Background(), event, verify); err != nil {
		t.Fatal(err)
	}
	passing := signedAttestation(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent)
	if err := store.IngestAttestation(passing); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := store.WriteSnapshot(&output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"apps":{"hello_nostr"`)) {
		t.Fatalf("require policy should include an app with a passing attestation: %s", output.String())
	}
}

func TestWriteSnapshotOffPolicyIncludesUnattestedApp(t *testing.T) {
	// The zero-value Store (no SetAttestationPolicy call) must behave
	// exactly as it did before this policy existed.
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	event := signedEvent(t, publisherKey, "hello_nostr")
	publisher, _ := nostr.GetPublicKey(publisherKey)
	policy, err := trust.NewExplicitPublishers([]string{publisher})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	verify := func(_ context.Context, declaration protocol.AppDeclaration) (map[string]any, error) {
		return map[string]any{"id": declaration.AppID, "version": declaration.Version}, nil
	}
	if err := store.IngestVerified(context.Background(), event, verify); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := store.WriteSnapshot(&output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"apps":{"hello_nostr"`)) {
		t.Fatalf("default (off) policy must not exclude an unattested app: %s", output.String())
	}
}

func signedAttestation(t *testing.T, privateKey, appID, repositoryURL, commit, manifestHash, contentHash string) nostr.Event {
	return signedAttestationAt(t, privateKey, appID, repositoryURL, commit, manifestHash, contentHash, "pass", 1)
}

func signedAttestationAt(t *testing.T, privateKey, appID, repositoryURL, commit, manifestHash, contentHash, result string, createdAt int64) nostr.Event {
	t.Helper()
	checks := map[string]string{"yunohost_lint": "pass", "shellcheck": "pass"}
	event, err := verification.Build(appID, repositoryURL, commit, manifestHash, contentHash, "github-actions", "run-1", checks, result, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	event.CreatedAt = nostr.Timestamp(createdAt)
	if err := event.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	return event
}

func signedEvent(t *testing.T, privateKey, appID string) nostr.Event {
	return signedEventWith(t, privateKey, appID, "https://github.com/example/app_ynh", "1.0.0~ynh1", 1)
}

func signedEventWith(t *testing.T, privateKey, appID, repository, version string, createdAt nostr.Timestamp) nostr.Event {
	t.Helper()
	publicKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	event := nostr.Event{
		PubKey: publicKey, CreatedAt: createdAt, Kind: 30078,
		Tags:    nostr.Tags{{"d", appID}, {"platform", "yunohost"}, {"repo", repository}, {"version", version}, {"commit", "cccccccccccccccccccccccccccccccccccccccc"}, {"manifest", "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}, {"content", "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}},
		Content: "{}",
	}
	if err := event.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	return event
}
