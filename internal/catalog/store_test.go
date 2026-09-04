package catalog

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
	"github.com/nostr-yunohost/nostr-yunohost/internal/trust"
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
