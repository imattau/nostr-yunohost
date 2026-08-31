// Package repository extracts publishable metadata from a YunoHost Git
// repository.
package repository

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nostr-yunohost/nostr-yunohost/internal/publisher"
	"github.com/pelletier/go-toml/v2"
)

type manifest struct {
	ID            string   `toml:"id"`
	Version       string   `toml:"version"`
	Name          string   `toml:"name"`
	Description   string   `toml:"description"`
	Category      string   `toml:"category"`
	Architectures []string `toml:"architectures"`
}

// ReadMetadata reads manifest.toml and Git metadata from a package directory.
func ReadMetadata(directory string) (publisher.Metadata, error) {
	directory, err := filepath.Abs(directory)
	if err != nil {
		return publisher.Metadata{}, fmt.Errorf("resolve repository path: %w", err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(directory, "manifest.toml"))
	if err != nil {
		return publisher.Metadata{}, fmt.Errorf("read manifest.toml: %w", err)
	}
	var parsed manifest
	if err := toml.Unmarshal(manifestBytes, &parsed); err != nil {
		return publisher.Metadata{}, fmt.Errorf("parse manifest.toml: %w", err)
	}
	if parsed.ID == "" || parsed.Version == "" {
		return publisher.Metadata{}, fmt.Errorf("manifest.toml must define id and version")
	}
	commit, err := gitOutput(directory, "rev-parse", "HEAD")
	if err != nil {
		return publisher.Metadata{}, fmt.Errorf("read Git commit: %w", err)
	}
	repositoryURL, err := gitOutput(directory, "remote", "get-url", "origin")
	if err != nil {
		return publisher.Metadata{}, fmt.Errorf("read Git origin: %w", err)
	}
	archive, err := gitCommand(directory, "archive", "--format=tar", "HEAD")
	if err != nil {
		return publisher.Metadata{}, fmt.Errorf("archive Git tree: %w", err)
	}
	return publisher.Metadata{
		AppID:         parsed.ID,
		Repository:    repositoryURL,
		Version:       parsed.Version,
		Commit:        commit,
		ManifestHash:  publisher.HashBytes(manifestBytes),
		ContentHash:   publisher.HashBytes(archive),
		Category:      parsed.Category,
		Name:          parsed.Name,
		Description:   parsed.Description,
		Architectures: parsed.Architectures,
	}, nil
}

func gitOutput(directory string, args ...string) (string, error) {
	output, err := gitCommand(directory, args...)
	return strings.TrimSpace(string(output)), err
}

func gitCommand(directory string, args ...string) ([]byte, error) {
	command := exec.Command("git", args...)
	command.Dir = directory
	return command.Output()
}
