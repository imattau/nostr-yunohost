package catalog

import (
	"encoding/json"
	"testing"

	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
)

func TestYunoHostCatalogHasVersionedSecurityIndex(t *testing.T) {
	catalogue := YunoHostCatalog{Security: SecurityIndex{Version: 1, Apps: map[string][]any{}, System: map[string][]any{}}}
	data, err := json.Marshal(catalogue)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got == "" || !containsJSONField(data, "version", "1") {
		t.Fatalf("expected versioned security index, got %s", data)
	}
}

func containsJSONField(data []byte, field, value string) bool {
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return false
	}
	security, ok := decoded["security"].(map[string]any)
	return ok && security[field] == float64(1) && value == "1"
}

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
