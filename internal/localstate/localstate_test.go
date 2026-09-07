package localstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFileReturnsEmpty(t *testing.T) {
	apps, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(apps) != 0 {
		t.Fatalf("expected no apps, got %v", apps)
	}
}

func TestLoadParsesSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installed-apps.json")
	data, err := json.Marshal(snapshotFile{Apps: []InstalledApp{
		{AppID: "hello_nostr", Repository: "https://example.com/hello_nostr"},
	}})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	apps, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(apps) != 1 || apps[0].AppID != "hello_nostr" || apps[0].Repository != "https://example.com/hello_nostr" {
		t.Fatalf("unexpected apps: %v", apps)
	}
}

func TestLoadRejectsInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installed-apps.json")
	if err := os.WriteFile(path, []byte("not json"), 0o640); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}
