// Package repository extracts publishable metadata from a YunoHost Git
// repository.
package repository

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
	"github.com/nostr-yunohost/nostr-yunohost/internal/publisher"
	"github.com/pelletier/go-toml/v2"
)

type manifest struct {
	ID            string
	Version       string
	Name          string
	Description   string
	Category      string
	Architectures []string
}

// VerifiedPackage contains the authoritative package metadata and its
// optional YunoHost logo. Logo bytes are returned so the catalogue can serve
// them locally instead of making YunoHost fetch arbitrary third-party URLs.
type VerifiedPackage struct {
	Manifest map[string]any
	Logo     []byte
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
	parsed, err := parseManifest(manifestBytes)
	if err != nil {
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

func parseManifest(data []byte) (manifest, error) {
	var values map[string]any
	if err := toml.Unmarshal(data, &values); err != nil {
		return manifest{}, err
	}
	integration, _ := values["integration"].(map[string]any)
	return manifest{
		ID:            stringValue(values["id"]),
		Version:       stringValue(values["version"]),
		Name:          localizedValue(values["name"]),
		Description:   localizedValue(values["description"]),
		Category:      stringValue(values["category"]),
		Architectures: stringSlice(integration["architectures"]),
	}, nil
}

func localizedValue(value any) string {
	if text := stringValue(value); text != "" {
		return text
	}
	translations, ok := value.(map[string]any)
	if !ok {
		return ""
	}
	if english := stringValue(translations["en"]); english != "" {
		return english
	}
	for _, candidate := range translations {
		if text := stringValue(candidate); text != "" {
			return text
		}
	}
	return ""
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func stringSlice(value any) []string {
	values, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text := stringValue(value); text != "" {
			result = append(result, text)
		}
	}
	return result
}

// VerifyDeclaration fetches a declaration's repository at its exact commit,
// verifies both advertised hashes, and returns the authoritative manifest.
func VerifyDeclaration(ctx context.Context, declaration protocol.AppDeclaration) (VerifiedPackage, error) {
	temporaryDirectory, err := os.MkdirTemp("", "nostr-ynh-repository-")
	if err != nil {
		return VerifiedPackage{}, fmt.Errorf("create repository workspace: %w", err)
	}
	defer os.RemoveAll(temporaryDirectory)
	if _, err := gitCommandContext(ctx, temporaryDirectory, "clone", "--no-checkout", "--filter=blob:none", "--quiet", declaration.Repository, "."); err != nil {
		return VerifiedPackage{}, fmt.Errorf("clone repository: %w", err)
	}
	if _, err := gitCommandContext(ctx, temporaryDirectory, "checkout", "--detach", "--quiet", declaration.Commit); err != nil {
		return VerifiedPackage{}, fmt.Errorf("checkout declared commit: %w", err)
	}
	return verifyCheckedOutDirectory(ctx, temporaryDirectory, declaration)
}

// ReadRemoteMetadata previews a remote package at a branch, tag, or commit
// without signing or publishing anything.
func ReadRemoteMetadata(ctx context.Context, repositoryURL, revision string) (publisher.Metadata, error) {
	temporaryDirectory, err := os.MkdirTemp("", "nostr-ynh-preview-")
	if err != nil {
		return publisher.Metadata{}, fmt.Errorf("create preview workspace: %w", err)
	}
	defer os.RemoveAll(temporaryDirectory)
	cloneArgs := []string{"clone", "--quiet", "--filter=blob:none"}
	if revision != "" {
		cloneArgs = append(cloneArgs, "--branch", revision)
	}
	cloneArgs = append(cloneArgs, repositoryURL, temporaryDirectory)
	if _, err := gitCommandContext(ctx, "", cloneArgs...); err != nil {
		return publisher.Metadata{}, fmt.Errorf("clone repository: %w", err)
	}
	return ReadMetadata(temporaryDirectory)
}

func verifyCheckedOutDirectory(ctx context.Context, directory string, declaration protocol.AppDeclaration) (VerifiedPackage, error) {
	manifestBytes, err := os.ReadFile(filepath.Join(directory, "manifest.toml"))
	if err != nil {
		return VerifiedPackage{}, fmt.Errorf("read repository manifest: %w", err)
	}
	if publisher.HashBytes(manifestBytes) != declaration.ManifestHash {
		return VerifiedPackage{}, fmt.Errorf("manifest hash does not match declaration")
	}
	archive, err := gitCommandContext(ctx, directory, "archive", "--format=tar", "HEAD")
	if err != nil {
		return VerifiedPackage{}, fmt.Errorf("archive checked-out repository: %w", err)
	}
	if publisher.HashBytes(archive) != declaration.ContentHash {
		return VerifiedPackage{}, fmt.Errorf("repository content hash does not match declaration")
	}
	var manifest map[string]any
	if err := toml.Unmarshal(manifestBytes, &manifest); err != nil {
		return VerifiedPackage{}, fmt.Errorf("parse repository manifest: %w", err)
	}
	logo, err := readLogo(directory)
	if err != nil {
		return VerifiedPackage{}, err
	}
	return VerifiedPackage{Manifest: manifest, Logo: logo}, nil
}

func readLogo(directory string) ([]byte, error) {
	path := filepath.Join(directory, "logo.png")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read logo.png: %w", err)
	}
	if len(data) == 0 || len(data) > 2<<20 {
		return nil, nil
	}
	magic := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}
	if len(data) < len(magic) || string(data[:len(magic)]) != string(magic) {
		return nil, nil
	}
	return data, nil
}

// LogoHash returns the YunoHost catalogue hash for an optional logo.
func LogoHash(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:])
}

func gitOutput(directory string, args ...string) (string, error) {
	output, err := gitCommand(directory, args...)
	return strings.TrimSpace(string(output)), err
}

func gitCommand(directory string, args ...string) ([]byte, error) {
	command := exec.Command("git", args...)
	command.Dir = directory
	output, err := command.Output()
	if err != nil {
		return output, wrapGitError(args, err)
	}
	return output, nil
}

func gitCommandContext(ctx context.Context, directory string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "git", args...)
	command.Dir = directory
	output, err := command.Output()
	if err != nil {
		return output, wrapGitError(args, err)
	}
	return output, nil
}

// wrapGitError includes git's own stderr in the returned error. Go's
// exec.Cmd.Output() populates *exec.ExitError.Stderr on a nonzero exit,
// but ExitError.Error() itself only ever renders "exit status N" - every
// git failure (missing branch, auth failure, network error, ...) was
// previously indistinguishable from any other, all the way up through
// every caller's "clone repository: %w"-style wrapping.
func wrapGitError(args []string, err error) error {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
		return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(exitErr.Stderr)))
	}
	return fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
}
