package repository

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
	"github.com/nostr-yunohost/nostr-yunohost/internal/publisher"
)

func TestVerifyCheckedOutDirectory(t *testing.T) {
	directory := t.TempDir()
	manifest := []byte("id = \"hello_nostr\"\nversion = \"1.0.0~ynh1\"\n")
	if err := os.WriteFile(filepath.Join(directory, "manifest.toml"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init"}, {"config", "user.email", "test@example.invalid"}, {"config", "user.name", "Test"}, {"add", "manifest.toml"}, {"commit", "-m", "test"}} {
		if _, err := gitCommand(directory, args...); err != nil {
			t.Fatal(err)
		}
	}
	commit, err := gitOutput(directory, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	archive, err := gitCommandContext(context.Background(), directory, "archive", "--format=tar", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	declaration := protocol.AppDeclaration{AppID: "hello_nostr", Version: "1.0.0~ynh1", Commit: commit, ManifestHash: publisher.HashBytes(manifest), ContentHash: publisher.HashBytes(archive)}
	parsed, err := verifyCheckedOutDirectory(context.Background(), directory, declaration)
	if err != nil {
		t.Fatal(err)
	}
	if parsed["id"] != "hello_nostr" {
		t.Fatalf("unexpected manifest: %+v", parsed)
	}
}
