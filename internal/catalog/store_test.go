package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
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

func TestWriteSnapshotSetsHighQualityFromCIVerifiedStatus(t *testing.T) {
	// Off policy, no curation policy configured at all: HighQuality must
	// still turn on from a passing CI attestation alone (Phase 10) - it is
	// a second, independent route to the same field, not something that
	// requires curator endorsements to be configured first.
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	verifierKey := strings.Repeat("e1", 32)
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

	before := writeSnapshotCatalog(t, store)
	if before.Apps["hello_nostr"].HighQuality {
		t.Fatalf("expected high_quality false before any attestation: %+v", before.Apps["hello_nostr"])
	}

	passing := signedAttestation(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent)
	if err := store.IngestAttestation(passing); err != nil {
		t.Fatal(err)
	}

	after := writeSnapshotCatalog(t, store)
	if !after.Apps["hello_nostr"].HighQuality {
		t.Fatalf("expected high_quality true once a CI attestation passes: %+v", after.Apps["hello_nostr"])
	}
	// Level stays the compatibility floor regardless - it is not a proxy
	// for attestation status (Phase 10's point).
	if after.Apps["hello_nostr"].Level != 5 {
		t.Fatalf("expected Level to remain untouched by attestation status: %+v", after.Apps["hello_nostr"])
	}
}

func TestTrustEntriesIncludesComputedStatus(t *testing.T) {
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	verifierKey := strings.Repeat("f1", 32)
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

	if got := store.TrustEntries()[0].Status; got != StatusIntegrityVerified {
		t.Fatalf("Status = %q before any attestation, want %q", got, StatusIntegrityVerified)
	}

	passing := signedAttestation(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent)
	if err := store.IngestAttestation(passing); err != nil {
		t.Fatal(err)
	}
	if got := store.TrustEntries()[0].Status; got != StatusCIVerified {
		t.Fatalf("Status = %q after a passing attestation, want %q", got, StatusCIVerified)
	}
}

func TestWriteSnapshotRequirePolicyEnforcesMinimumAttestations(t *testing.T) {
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	firstVerifier := strings.Repeat("11", 32)
	secondVerifier := strings.Repeat("22", 32)
	event := signedEvent(t, publisherKey, "hello_nostr")
	publisher, _ := nostr.GetPublicKey(publisherKey)
	policy, err := trust.NewExplicitPublishers([]string{publisher})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	store.SetAttestationPolicy(trust.AttestationPolicy{Mode: trust.AttestationRequire, MinimumAttestations: 2})
	verify := func(_ context.Context, declaration protocol.AppDeclaration) (map[string]any, error) {
		return map[string]any{"id": declaration.AppID, "version": declaration.Version}, nil
	}
	if err := store.IngestVerified(context.Background(), event, verify); err != nil {
		t.Fatal(err)
	}
	if err := store.IngestAttestation(signedAttestation(t, firstVerifier, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent)); err != nil {
		t.Fatal(err)
	}

	oneVerifier := writeSnapshotCatalog(t, store)
	if _, ok := oneVerifier.Apps["hello_nostr"]; ok {
		t.Fatalf("one attestation should not satisfy minimum_attestations=2: %+v", oneVerifier.Apps)
	}

	if err := store.IngestAttestation(signedAttestation(t, secondVerifier, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent)); err != nil {
		t.Fatal(err)
	}
	twoVerifiers := writeSnapshotCatalog(t, store)
	if _, ok := twoVerifiers.Apps["hello_nostr"]; !ok {
		t.Fatalf("two independent verifiers should satisfy minimum_attestations=2: %+v", twoVerifiers.Apps)
	}
	if twoVerifiers.Apps["hello_nostr"].HighQuality != true {
		t.Fatalf("two passing attestations should also satisfy multi_verified/HighQuality: %+v", twoVerifiers.Apps["hello_nostr"])
	}
}

func TestWriteSnapshotRequirePolicyEnforcesRequiredChecks(t *testing.T) {
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	verifierKey := strings.Repeat("33", 32)
	event := signedEvent(t, publisherKey, "hello_nostr")
	publisher, _ := nostr.GetPublicKey(publisherKey)
	policy, err := trust.NewExplicitPublishers([]string{publisher})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	store.SetAttestationPolicy(trust.AttestationPolicy{Mode: trust.AttestationRequire, RequiredChecks: []string{"package_check"}})
	verify := func(_ context.Context, declaration protocol.AppDeclaration) (map[string]any, error) {
		return map[string]any{"id": declaration.AppID, "version": declaration.Version}, nil
	}
	if err := store.IngestVerified(context.Background(), event, verify); err != nil {
		t.Fatal(err)
	}
	// Overall result "pass", but the specifically required check is absent.
	missingRequiredCheck := signedAttestationAt(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent, "pass", 1)
	if err := store.IngestAttestation(missingRequiredCheck); err != nil {
		t.Fatal(err)
	}

	excluded := writeSnapshotCatalog(t, store)
	if _, ok := excluded.Apps["hello_nostr"]; ok {
		t.Fatalf("an attestation missing the required check must not satisfy require: %+v", excluded.Apps)
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

func writeSnapshotCatalog(t *testing.T, store *Store) YunoHostCatalog {
	t.Helper()
	var output bytes.Buffer
	if err := store.WriteSnapshot(&output); err != nil {
		t.Fatal(err)
	}
	var catalogue YunoHostCatalog
	if err := json.Unmarshal(output.Bytes(), &catalogue); err != nil {
		t.Fatalf("decode snapshot: %v (raw=%s)", err, output.String())
	}
	return catalogue
}

func TestWriteSnapshotPopulatesSecurityIndex(t *testing.T) {
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	verifierKey := strings.Repeat("9", 64)
	event := signedEvent(t, publisherKey, "hello_nostr")
	publisher, _ := nostr.GetPublicKey(publisherKey)
	verifier, _ := nostr.GetPublicKey(verifierKey)
	wantVerifierNpub, err := nip19.EncodePublicKey(verifier)
	if err != nil {
		t.Fatal(err)
	}
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
	passing := signedAttestation(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent)
	if err := store.IngestAttestation(passing); err != nil {
		t.Fatal(err)
	}

	catalogue := writeSnapshotCatalog(t, store)
	entries := catalogue.Security.Apps["hello_nostr"]
	if len(entries) != 1 {
		t.Fatalf("expected exactly one security entry, got: %+v", entries)
	}
	entry := entries[0]
	if entry.Revision != testDeclarationCommit || entry.Status != "verified" || entry.Verifier != wantVerifierNpub {
		t.Fatalf("unexpected security entry: %+v", entry)
	}
	if entry.Checks["yunohost_lint"] != "pass" {
		t.Fatalf("expected checks to be carried through: %+v", entry.Checks)
	}
}

func TestWriteSnapshotSecurityIndexIncludesFailingAttestation(t *testing.T) {
	// Off policy: the app stays installable despite a failing attestation,
	// but the security index must still surface the failure rather than
	// silently omitting evidence that doesn't happen to be good news.
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	verifierKey := strings.Repeat("a1", 32)
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
	failing := signedAttestationAt(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent, "fail", 1)
	if err := store.IngestAttestation(failing); err != nil {
		t.Fatal(err)
	}

	catalogue := writeSnapshotCatalog(t, store)
	if _, ok := catalogue.Apps["hello_nostr"]; !ok {
		t.Fatal("off policy must still include the app despite the failing attestation")
	}
	entries := catalogue.Security.Apps["hello_nostr"]
	if len(entries) != 1 || entries[0].Status != "fail" {
		t.Fatalf("expected the failing attestation to appear in the security index as status fail, got: %+v", entries)
	}
}

func TestWriteSnapshotSecurityIndexListsMultipleVerifiers(t *testing.T) {
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	firstVerifier := strings.Repeat("b1", 32)
	secondVerifier := strings.Repeat("c1", 32)
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
	if err := store.IngestAttestation(signedAttestation(t, firstVerifier, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent)); err != nil {
		t.Fatal(err)
	}
	if err := store.IngestAttestation(signedAttestation(t, secondVerifier, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent)); err != nil {
		t.Fatal(err)
	}

	catalogue := writeSnapshotCatalog(t, store)
	if entries := catalogue.Security.Apps["hello_nostr"]; len(entries) != 2 {
		t.Fatalf("expected one security entry per independent verifier, got: %+v", entries)
	}
}

func TestWriteSnapshotSecurityIndexOmitsUnattestedApp(t *testing.T) {
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

	catalogue := writeSnapshotCatalog(t, store)
	if _, ok := catalogue.Security.Apps["hello_nostr"]; ok {
		t.Fatalf("expected no security index entry for an app with zero attestations, got: %+v", catalogue.Security.Apps["hello_nostr"])
	}
}

// TestWriteSnapshotDoesNotAdvanceToUnattestedUpgrade is Phase 11's own
// worked example (docs/attestation-trust-policy-plan.md): v1 is attested
// and installable; v2 (a new commit, newer version, newer CreatedAt) then
// arrives without an attestation. Under require, the catalogue must keep
// offering v1 - not disappear, and not silently advance to v2 - until v2
// itself becomes attested, at which point the catalogue advances.
func TestWriteSnapshotDoesNotAdvanceToUnattestedUpgrade(t *testing.T) {
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	verifierKey := strings.Repeat("9", 64)
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

	v1 := signedEventWith(t, publisherKey, "hello_nostr", "https://github.com/example/app_ynh", "1.0.0~ynh1", 1)
	if err := store.IngestVerified(context.Background(), v1, verify); err != nil {
		t.Fatal(err)
	}
	v1Attestation := signedAttestation(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent)
	if err := store.IngestAttestation(v1Attestation); err != nil {
		t.Fatal(err)
	}
	before := writeSnapshotCatalog(t, store)
	if got := before.Apps["hello_nostr"].Git.Revision; got != testDeclarationCommit {
		t.Fatalf("expected v1's commit before v2 arrives, got %q", got)
	}

	v2Commit := strings.Repeat("d", 40)
	v2Manifest := "sha256:" + strings.Repeat("2", 64)
	v2Content := "sha256:" + strings.Repeat("3", 64)
	v2 := nostr.Event{
		PubKey: publisher, CreatedAt: 2, Kind: 30078,
		Tags: nostr.Tags{
			{"d", "hello_nostr"}, {"platform", "yunohost"},
			{"repo", "https://github.com/example/app_ynh"}, {"version", "2.0.0~ynh1"},
			{"commit", v2Commit}, {"manifest", v2Manifest}, {"content", v2Content},
		},
		Content: "{}",
	}
	if err := v2.Sign(publisherKey); err != nil {
		t.Fatal(err)
	}
	if err := store.IngestVerified(context.Background(), v2, verify); err != nil {
		t.Fatal(err)
	}

	afterUnattestedV2 := writeSnapshotCatalog(t, store)
	app, ok := afterUnattestedV2.Apps["hello_nostr"]
	if !ok {
		t.Fatal("v1 must remain in the catalogue while v2 is unattested, not disappear")
	}
	if app.Git.Revision != testDeclarationCommit || app.Manifest["version"] != "1.0.0~ynh1" {
		t.Fatalf("catalogue must stay pinned to v1, not silently advance to unattested v2: %+v", app)
	}

	v2Attestation := signedAttestation(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", v2Commit, v2Manifest, v2Content)
	if err := store.IngestAttestation(v2Attestation); err != nil {
		t.Fatal(err)
	}
	afterAttestedV2 := writeSnapshotCatalog(t, store)
	if got := afterAttestedV2.Apps["hello_nostr"].Git.Revision; got != v2Commit {
		t.Fatalf("catalogue should advance to v2 once it is attested, got revision %q", got)
	}
}

func TestSnapshotReturnsNewestRevisionRegardlessOfAttestation(t *testing.T) {
	// Snapshot/Declarations reflect what's been declared, not what the
	// local attestation policy currently offers for install - discovery
	// stays independent of installability (plan Phase 7).
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	publisher, _ := nostr.GetPublicKey(publisherKey)
	policy, err := trust.NewExplicitPublishers([]string{publisher})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	store.SetAttestationPolicy(trust.AttestationPolicy{Mode: trust.AttestationRequire})
	v1 := signedEventWith(t, publisherKey, "hello_nostr", "https://github.com/example/app_ynh", "1.0.0~ynh1", 1)
	if err := store.Ingest(v1); err != nil {
		t.Fatal(err)
	}
	v2 := nostr.Event{
		PubKey: publisher, CreatedAt: 2, Kind: 30078,
		Tags: nostr.Tags{
			{"d", "hello_nostr"}, {"platform", "yunohost"},
			{"repo", "https://github.com/example/app_ynh"}, {"version", "2.0.0~ynh1"},
			{"commit", strings.Repeat("d", 40)}, {"manifest", "sha256:" + strings.Repeat("2", 64)}, {"content", "sha256:" + strings.Repeat("3", 64)},
		},
		Content: "{}",
	}
	if err := v2.Sign(publisherKey); err != nil {
		t.Fatal(err)
	}
	if err := store.Ingest(v2); err != nil {
		t.Fatal(err)
	}

	declarations := store.Snapshot()
	if len(declarations) != 1 || declarations[0].Version != "2.0.0~ynh1" {
		t.Fatalf("Snapshot should report the newest declared revision regardless of attestation status: %+v", declarations)
	}
}

func TestUpsertRevisionDedupesSameCommitKeepingNewer(t *testing.T) {
	older := record{Declaration: protocol.AppDeclaration{Commit: "abc"}, CreatedAt: 1}
	newer := record{Declaration: protocol.AppDeclaration{Commit: "abc"}, CreatedAt: 2}

	revisions := upsertRevision(nil, older)
	revisions = upsertRevision(revisions, newer)
	if len(revisions) != 1 || revisions[0].CreatedAt != 2 {
		t.Fatalf("expected the same commit to dedupe to its newer record, got: %+v", revisions)
	}

	// A stale re-delivery of the older event must not un-update it.
	revisions = upsertRevision(revisions, older)
	if len(revisions) != 1 || revisions[0].CreatedAt != 2 {
		t.Fatalf("an older re-delivery of the same commit must not overwrite the newer record: %+v", revisions)
	}
}

func TestUpsertRevisionKeepsDistinctCommitsNewestFirst(t *testing.T) {
	v1 := record{Declaration: protocol.AppDeclaration{Commit: "v1"}, CreatedAt: 1}
	v2 := record{Declaration: protocol.AppDeclaration{Commit: "v2"}, CreatedAt: 2}
	v3 := record{Declaration: protocol.AppDeclaration{Commit: "v3"}, CreatedAt: 3}

	revisions := upsertRevision(nil, v1)
	revisions = upsertRevision(revisions, v3)
	revisions = upsertRevision(revisions, v2)

	if len(revisions) != 3 {
		t.Fatalf("expected all three distinct commits retained, got: %+v", revisions)
	}
	if revisions[0].Declaration.Commit != "v3" || revisions[1].Declaration.Commit != "v2" || revisions[2].Declaration.Commit != "v1" {
		t.Fatalf("expected revisions sorted newest-first, got: %+v", revisions)
	}
}

func TestUpsertRevisionCapsAtMaxRevisionsPerKey(t *testing.T) {
	var revisions []record
	for i := 0; i < maxRevisionsPerKey+5; i++ {
		revisions = upsertRevision(revisions, record{
			Declaration: protocol.AppDeclaration{Commit: strings.Repeat(string(rune('a'+i)), 4)},
			CreatedAt:   nostr.Timestamp(i),
		})
	}
	if len(revisions) != maxRevisionsPerKey {
		t.Fatalf("expected the revision list capped at %d, got %d", maxRevisionsPerKey, len(revisions))
	}
	// The cap must keep the newest, not the oldest.
	if revisions[0].CreatedAt != nostr.Timestamp(maxRevisionsPerKey+4) {
		t.Fatalf("expected the cap to retain the newest revisions, got newest CreatedAt=%d", revisions[0].CreatedAt)
	}
}

func TestStoreCacheRoundTripPreservesMultipleRevisions(t *testing.T) {
	// Scoped to what Save/Load themselves are responsible for: every
	// distinct revision surviving the round-trip, independent of
	// attestations (covered separately by
	// TestStoreCacheRoundTripPreservesAttestationsAcrossRestart below).
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	publisher, _ := nostr.GetPublicKey(publisherKey)
	policy, err := trust.NewExplicitPublishers([]string{publisher})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	verify := func(_ context.Context, declaration protocol.AppDeclaration) (map[string]any, error) {
		return map[string]any{"id": declaration.AppID, "version": declaration.Version}, nil
	}
	v1 := signedEventWith(t, publisherKey, "hello_nostr", "https://github.com/example/app_ynh", "1.0.0~ynh1", 1)
	if err := store.IngestVerified(context.Background(), v1, verify); err != nil {
		t.Fatal(err)
	}
	v2 := nostr.Event{
		PubKey: publisher, CreatedAt: 2, Kind: 30078,
		Tags: nostr.Tags{
			{"d", "hello_nostr"}, {"platform", "yunohost"},
			{"repo", "https://github.com/example/app_ynh"}, {"version", "2.0.0~ynh1"},
			{"commit", strings.Repeat("d", 40)}, {"manifest", "sha256:" + strings.Repeat("2", 64)}, {"content", "sha256:" + strings.Repeat("3", 64)},
		},
		Content: "{}",
	}
	if err := v2.Sign(publisherKey); err != nil {
		t.Fatal(err)
	}
	if err := store.IngestVerified(context.Background(), v2, verify); err != nil {
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

	entries := restored.TrustEntries()
	if len(entries) != 2 {
		t.Fatalf("expected both revisions to survive the cache round-trip, got: %+v", entries)
	}
	commits := map[string]bool{entries[0].Commit: true, entries[1].Commit: true}
	if !commits[testDeclarationCommit] || !commits[strings.Repeat("d", 40)] {
		t.Fatalf("expected both v1 and v2 commits present after restore, got: %+v", commits)
	}
}

// TestStoreCacheRoundTripPreservesAttestationsAcrossRestart is the fix for
// the gap TestWriteSnapshotDoesNotAdvanceToUnattestedUpgrade's own cache
// round-trip once surfaced: a daemon restart under require must not
// transiently un-attest (and so exclude) an already-attested, already
// installable app just because the process restarted.
func TestStoreCacheRoundTripPreservesAttestationsAcrossRestart(t *testing.T) {
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	verifierKey := strings.Repeat("5", 64)
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
	v1 := signedEventWith(t, publisherKey, "hello_nostr", "https://github.com/example/app_ynh", "1.0.0~ynh1", 1)
	if err := store.IngestVerified(context.Background(), v1, verify); err != nil {
		t.Fatal(err)
	}
	if err := store.IngestAttestation(signedAttestation(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent)); err != nil {
		t.Fatal(err)
	}
	before := writeSnapshotCatalog(t, store)
	if _, ok := before.Apps["hello_nostr"]; !ok {
		t.Fatal("expected the attested app installable before the simulated restart")
	}

	cachePath := filepath.Join(t.TempDir(), "catalogue.json")
	if err := store.Save(cachePath); err != nil {
		t.Fatal(err)
	}

	restarted := NewStore(policy)
	restarted.SetAttestationPolicy(trust.AttestationPolicy{Mode: trust.AttestationRequire})
	if err := restarted.Load(cachePath); err != nil {
		t.Fatal(err)
	}

	after := writeSnapshotCatalog(t, restarted)
	if _, ok := after.Apps["hello_nostr"]; !ok {
		t.Fatal("a daemon restart must not transiently exclude an already-attested app under require")
	}
	if got := after.Apps["hello_nostr"].Git.Revision; got != testDeclarationCommit {
		t.Fatalf("expected the restored catalogue to keep offering the attested revision, got %q", got)
	}
}

func TestIngestAttestationLoadDoesNotResurrectStaleCachedAttestation(t *testing.T) {
	verifierKey := strings.Repeat("7", 64)
	store := NewStore(trust.ExplicitPublishers{})
	newer := signedAttestationAt(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent, "fail", 2)
	if err := store.IngestAttestation(newer); err != nil {
		t.Fatal(err)
	}

	cachePath := filepath.Join(t.TempDir(), "catalogue.json")
	// Save an older, stale cache containing only an older passing
	// attestation from the same verifier - simulating a cache file written
	// before the newer (failing) attestation was ever seen.
	older := signedAttestationAt(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent, "pass", 1)
	staleCache := cacheFile{Attestations: []nostr.Event{older}}
	data, err := json.Marshal(staleCache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, data, 0o640); err != nil {
		t.Fatal(err)
	}

	if err := store.Load(cachePath); err != nil {
		t.Fatal(err)
	}
	matched := store.AttestationsFor(protocol.AppDeclaration{
		Repository:   "https://github.com/example/app_ynh",
		Commit:       testDeclarationCommit,
		ManifestHash: testDeclarationManifest,
		ContentHash:  testDeclarationContent,
	})
	if len(matched) != 1 || matched[0].Result != "fail" {
		t.Fatalf("loading a stale cached attestation must not overwrite a newer in-memory one: %+v", matched)
	}
}

func TestTrustEntriesReflectsVerificationAndPolicy(t *testing.T) {
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	verifierKey := strings.Repeat("d1", 32)
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

	// Before any attestation: repository-verified, but require excludes it.
	unattested := store.TrustEntries()
	if len(unattested) != 1 {
		t.Fatalf("expected one trust entry, got: %+v", unattested)
	}
	entry := unattested[0]
	if entry.AppID != "hello_nostr" || !entry.RepositoryVerified {
		t.Fatalf("unexpected trust entry: %+v", entry)
	}
	if entry.Policy.Mode != trust.AttestationRequire || entry.Policy.Accepted || entry.Policy.Verified {
		t.Fatalf("expected require policy to reject an unattested app: %+v", entry.Policy)
	}
	if len(entry.Attestations) != 0 {
		t.Fatalf("expected no attestations yet: %+v", entry.Attestations)
	}

	passing := signedAttestation(t, verifierKey, "hello_nostr", "https://github.com/example/app_ynh", testDeclarationCommit, testDeclarationManifest, testDeclarationContent)
	if err := store.IngestAttestation(passing); err != nil {
		t.Fatal(err)
	}

	attested := store.TrustEntries()[0]
	if !attested.Policy.Accepted || !attested.Policy.Verified {
		t.Fatalf("expected require policy to accept the now-attested app: %+v", attested.Policy)
	}
	if len(attested.Attestations) != 1 || attested.Attestations[0].Status != "verified" {
		t.Fatalf("expected one verified attestation entry: %+v", attested.Attestations)
	}
}

func TestTrustEntriesMarksUnverifiedRepository(t *testing.T) {
	publisherKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	event := signedEvent(t, publisherKey, "hello_nostr")
	publisher, _ := nostr.GetPublicKey(publisherKey)
	policy, err := trust.NewExplicitPublishers([]string{publisher})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(policy)
	// Plain Ingest, not IngestVerified: the signature and trust-policy check
	// pass, but the repository itself was never fetched and hashed.
	if err := store.Ingest(event); err != nil {
		t.Fatal(err)
	}

	entries := store.TrustEntries()
	if len(entries) != 1 || entries[0].RepositoryVerified {
		t.Fatalf("expected RepositoryVerified=false for a declaration accepted via Ingest alone: %+v", entries)
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
