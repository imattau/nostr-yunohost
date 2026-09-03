package repository

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nostr-yunohost/nostr-yunohost/internal/publisher"
)

func TestReadMetadata(t *testing.T) {
	directory := t.TempDir()
	manifest := "id = \"hello_nostr\"\nversion = \"1.0.0~ynh1\"\nname = \"Hello Nostr\"\ndescription.en = \"A test app\"\ncategory = \"test\"\n\n[integration]\narchitectures = [\"amd64\", \"arm64\"]\n"
	if err := os.WriteFile(filepath.Join(directory, "manifest.toml"), []byte(manifest), 0o644); err != nil {
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
	if metadata.AppID != "hello_nostr" || metadata.Version != "1.0.0~ynh1" || metadata.Category != "test" || metadata.Description != "A test app" {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
	if len(metadata.Architectures) != 2 || metadata.Architectures[0] != "amd64" || metadata.Architectures[1] != "arm64" {
		t.Fatalf("unexpected architectures: %+v", metadata.Architectures)
	}
	if metadata.ManifestHash != publisher.HashBytes([]byte(manifest)) {
		t.Fatalf("manifest hash was not calculated from manifest.toml")
	}
	preview, err := ReadRemoteMetadata(context.Background(), directory, "")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Commit != metadata.Commit || preview.AppID != metadata.AppID {
		t.Fatalf("unexpected preview metadata: %+v", preview)
	}
}

// Regression: exec.Cmd.Output() populates *exec.ExitError.Stderr on a
// nonzero exit, but ExitError.Error() itself only ever renders "exit
// status N" - callers wrapping a git failure with "clone repository: %w"
// used to lose git's own diagnostic message entirely (e.g. "Remote branch
// X not found in upstream origin"), making every git failure
// indistinguishable from any other. wrapGitError must include it.
func TestReadRemoteMetadataIncludesGitStderrOnFailure(t *testing.T) {
	directory := t.TempDir()
	manifest := "id = \"hello_nostr\"\nversion = \"1.0.0~ynh1\"\nname = \"Hello Nostr\"\ndescription.en = \"A test app\"\ncategory = \"test\"\n\n[integration]\narchitectures = [\"amd64\"]\n"
	if err := os.WriteFile(filepath.Join(directory, "manifest.toml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "test@example.invalid"},
		{"config", "user.name", "Test"},
		{"add", "manifest.toml"},
		{"commit", "-m", "test"},
	} {
		if _, err := gitCommand(directory, args...); err != nil {
			t.Fatal(err)
		}
	}

	_, err := ReadRemoteMetadata(context.Background(), directory, "nonexistent-branch-xyz")
	if err == nil {
		t.Fatal("expected an error for a nonexistent branch")
	}
	if !strings.Contains(err.Error(), "nonexistent-branch-xyz") {
		t.Fatalf("error should include git's own stderr naming the missing branch, got: %v", err)
	}
}
