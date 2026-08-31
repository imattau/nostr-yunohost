// Package protocol contains the wire-level types for the MVP event schema.
package protocol

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const AppDeclarationKind int = 30078

// Event is the JSON representation used by Nostr relays.
type Event struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

// AppDeclaration is the validated, platform-specific data extracted from a
// parameterised replaceable Nostr app declaration.
type AppDeclaration struct {
	AppID         string
	Publisher     string
	Repository    string
	Version       string
	Commit        string
	ManifestHash  string
	ContentHash   string
	Category      string
	Name          string
	Description   string
	Architectures []string
}

var (
	appIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	hex64Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
)

// ParseAppDeclaration validates the event envelope and extracts the app
// declaration. Signature verification is deliberately kept separate because
// it requires the selected Nostr crypto implementation.
func ParseAppDeclaration(event Event) (AppDeclaration, error) {
	if event.Kind != AppDeclarationKind {
		return AppDeclaration{}, fmt.Errorf("unexpected event kind %d", event.Kind)
	}
	if event.CreatedAt <= 0 {
		return AppDeclaration{}, fmt.Errorf("created_at must be positive")
	}
	if !hex64Pattern.MatchString(event.PubKey) {
		return AppDeclaration{}, fmt.Errorf("pubkey must be 64 lowercase hexadecimal characters")
	}
	if !hex64Pattern.MatchString(event.ID) || !hex64Pattern.MatchString(event.Sig) {
		return AppDeclaration{}, fmt.Errorf("id and sig must be 64 lowercase hexadecimal characters")
	}

	tags, err := parseTags(event.Tags)
	if err != nil {
		return AppDeclaration{}, err
	}
	appID := tags["d"][0]
	if !appIDPattern.MatchString(appID) {
		return AppDeclaration{}, fmt.Errorf("invalid app ID %q", appID)
	}
	if tags["platform"][0] != "yunohost" {
		return AppDeclaration{}, fmt.Errorf("platform must be yunohost")
	}
	if err := validateRepository(tags["repo"][0]); err != nil {
		return AppDeclaration{}, err
	}
	if !commitPattern.MatchString(tags["commit"][0]) {
		return AppDeclaration{}, fmt.Errorf("commit must be 40-64 lowercase hexadecimal characters")
	}
	for _, name := range []string{"manifest", "content"} {
		parts := strings.Split(tags[name][0], ":")
		if len(parts) != 2 || parts[0] != "sha256" || !hex64Pattern.MatchString(parts[1]) {
			return AppDeclaration{}, fmt.Errorf("%s must use sha256:<64 lowercase hexadecimal characters>", name)
		}
	}
	if err := validateContent(event.Content); err != nil {
		return AppDeclaration{}, err
	}

	declaration := AppDeclaration{
		AppID:        appID,
		Publisher:    event.PubKey,
		Repository:   tags["repo"][0],
		Version:      tags["version"][0],
		Commit:       tags["commit"][0],
		ManifestHash: tags["manifest"][0],
		ContentHash:  tags["content"][0],
		Category:     firstTag(tags, "category"),
	}
	var metadata struct {
		Name          string   `json:"name"`
		Description   string   `json:"description"`
		Architectures []string `json:"architectures"`
	}
	if err := json.Unmarshal([]byte(event.Content), &metadata); err == nil {
		declaration.Name = metadata.Name
		declaration.Description = metadata.Description
		declaration.Architectures = metadata.Architectures
	}
	return declaration, nil
}

// VerifyID checks the event ID against Nostr's canonical event serialization.
// It does not verify the Schnorr signature; callers must perform that check
// with a secp256k1 implementation before trusting the event.
func VerifyID(event Event) error {
	serialized, err := json.Marshal([]any{0, event.PubKey, event.CreatedAt, event.Kind, event.Tags, event.Content})
	if err != nil {
		return fmt.Errorf("serialize event: %w", err)
	}
	digest := sha256.Sum256(serialized)
	calculated := fmt.Sprintf("%x", digest[:])
	if event.ID != calculated {
		return fmt.Errorf("event ID mismatch: got %s, calculated %s", event.ID, calculated)
	}
	return nil
}

func parseTags(raw [][]string) (map[string][]string, error) {
	values := make(map[string][]string)
	for _, tag := range raw {
		if len(tag) < 2 || tag[0] == "" || tag[1] == "" {
			return nil, fmt.Errorf("tags must contain a name and value")
		}
		values[tag[0]] = append(values[tag[0]], tag[1])
	}
	for _, name := range []string{"d", "platform", "repo", "version", "commit", "manifest", "content"} {
		if len(values[name]) != 1 {
			return nil, fmt.Errorf("required tag %q must occur exactly once", name)
		}
	}
	return values, nil
}

func validateRepository(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path == "" {
		return fmt.Errorf("repo must be an HTTPS repository URL")
	}
	return nil
}

func validateContent(raw string) error {
	var value map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &value); err != nil || value == nil {
		return fmt.Errorf("content must be a JSON object")
	}
	return nil
}

func firstTag(tags map[string][]string, name string) string {
	if len(tags[name]) == 0 {
		return ""
	}
	return tags[name][0]
}
