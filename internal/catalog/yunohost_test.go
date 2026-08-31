package catalog

import (
	"testing"

	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
)

func TestTranslateProducesYunoHostEntry(t *testing.T) {
	declaration := protocol.AppDeclaration{AppID: "hello_nostr", Repository: "https://github.com/example/hello_nostr_ynh", Version: "1.0.0~ynh1", Commit: "cccccccccccccccccccccccccccccccccccccccc", Category: "development"}
	entry, err := Translate(declaration, map[string]any{"id": "hello_nostr", "version": "1.0.0~ynh1", "name": "Hello Nostr"}, 123)
	if err != nil {
		t.Fatal(err)
	}
	if entry.ID != declaration.AppID || entry.Git.Revision != declaration.Commit || entry.Manifest["name"] != "Hello Nostr" {
		t.Fatalf("unexpected YunoHost entry: %+v", entry)
	}
	if entry.Level != 5 || entry.HighQuality {
		t.Fatalf("expected compatibility level 5 without high-quality flag, got level=%d high_quality=%t", entry.Level, entry.HighQuality)
	}
}

func TestTranslateRejectsManifestMismatch(t *testing.T) {
	declaration := protocol.AppDeclaration{AppID: "hello_nostr", Version: "1.0.0~ynh1"}
	if _, err := Translate(declaration, map[string]any{"id": "other", "version": "1.0.0~ynh1"}, 123); err == nil {
		t.Fatal("Translate() accepted a mismatched manifest")
	}
}
