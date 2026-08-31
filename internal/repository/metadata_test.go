package repository

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nostr-yunohost/nostr-yunohost/internal/publisher"
)

func TestReadMetadata(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "manifest.toml"), []byte("id = \"hello_nostr\"\nversion = \"1.0.0~ynh1\"\nname = \"Hello Nostr\"\ncategory = \"test\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := gitCommand(directory, "init"); err != nil {
		t.Fatal(err)
	}
	if _, err := gitCommand(directory, "config", "user.email", "test@example.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := gitCommand(directory, "config", "user.name", "Test"); err != nil {
		t.Fatal(err)
	}
	if _, err := gitCommand(directory, "add", "manifest.toml"); err != nil {
		t.Fatal(err)
	}
	if _, err := gitCommand(directory, "commit", "-m", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := gitCommand(directory, "remote", "add", "origin", "https://github.com/example/hello_nostr_ynh"); err != nil {
		t.Fatal(err)
	}
	metadata, err := ReadMetadata(directory)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.AppID != "hello_nostr" || metadata.Version != "1.0.0~ynh1" || metadata.Category != "test" {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
	if metadata.ManifestHash != publisher.HashBytes([]byte("id = \"hello_nostr\"\nversion = \"1.0.0~ynh1\"\nname = \"Hello Nostr\"\ncategory = \"test\"\n")) {
		t.Fatalf("manifest hash was not calculated from manifest.toml")
	}
}
