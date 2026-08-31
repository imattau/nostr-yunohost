package catalog

import (
	"bytes"
	"testing"

	"github.com/nbd-wtf/go-nostr"
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

func signedEvent(t *testing.T, privateKey, appID string) nostr.Event {
	t.Helper()
	publicKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	event := nostr.Event{
		PubKey: publicKey, CreatedAt: nostr.Timestamp(1), Kind: 30078,
		Tags:    nostr.Tags{{"d", appID}, {"platform", "yunohost"}, {"repo", "https://github.com/example/app_ynh"}, {"version", "1.0.0~ynh1"}, {"commit", "cccccccccccccccccccccccccccccccccccccccc"}, {"manifest", "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}, {"content", "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}},
		Content: "{}",
	}
	if err := event.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	return event
}
