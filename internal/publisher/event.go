// Package publisher builds signed Nostr declarations for YunoHost packages.
package publisher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
)

// Metadata is the publisher-side input required to create an app declaration.
// Repository and commit identify the source; hashes pin the exact content
// that the catalogue daemon must verify before serving it.
type Metadata struct {
	AppID         string
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

// BuildDeclaration creates and signs the MVP replaceable app declaration.
// The private key is consumed only by the SDK's Sign method.
func BuildDeclaration(metadata Metadata, privateKey string) (nostr.Event, error) {
	if err := validateMetadata(metadata); err != nil {
		return nostr.Event{}, err
	}
	publicKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return nostr.Event{}, fmt.Errorf("derive publisher public key: %w", err)
	}
	content := struct {
		Name          string   `json:"name,omitempty"`
		Description   string   `json:"description,omitempty"`
		Architectures []string `json:"architectures,omitempty"`
	}{metadata.Name, metadata.Description, metadata.Architectures}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return nostr.Event{}, fmt.Errorf("encode event content: %w", err)
	}

	tags := nostr.Tags{
		{"d", metadata.AppID},
		{"platform", "yunohost"},
		{"repo", metadata.Repository},
		{"version", metadata.Version},
		{"commit", metadata.Commit},
		{"manifest", metadata.ManifestHash},
		{"content", metadata.ContentHash},
	}
	if metadata.Category != "" {
		tags = append(tags, nostr.Tag{"category", metadata.Category})
	}
	event := nostr.Event{
		PubKey:    publicKey,
		CreatedAt: nostr.Now(),
		Kind:      protocol.AppDeclarationKind,
		Tags:      tags,
		Content:   string(contentBytes),
	}
	if err := event.Sign(privateKey); err != nil {
		return nostr.Event{}, fmt.Errorf("sign app declaration: %w", err)
	}
	return event, nil
}

// HashBytes returns the hash format used by declaration tags.
func HashBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// AppAddress encodes the publisher/app identity as a shareable NIP-19 naddr.
func AppAddress(event nostr.Event, relays []string) (string, error) {
	if event.Kind != protocol.AppDeclarationKind || !nostr.IsValidPublicKey(event.PubKey) {
		return "", fmt.Errorf("event is not a valid YunoHost app declaration")
	}
	appID := event.Tags.GetD()
	if appID == "" {
		return "", fmt.Errorf("event has no app identifier")
	}
	return nip19.EncodeEntity(event.PubKey, event.Kind, appID, relays)
}

func validateMetadata(metadata Metadata) error {
	if metadata.AppID == "" || metadata.Version == "" || metadata.Commit == "" {
		return fmt.Errorf("app ID, version, and commit are required")
	}
	u, err := url.Parse(metadata.Repository)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path == "" {
		return fmt.Errorf("repository must be an HTTPS URL")
	}
	for name, value := range map[string]string{
		"manifest": metadata.ManifestHash,
		"content":  metadata.ContentHash,
	} {
		parts := strings.Split(value, ":")
		if len(parts) != 2 || parts[0] != "sha256" || len(parts[1]) != 64 {
			return fmt.Errorf("%s hash must use sha256:<64 hexadecimal characters>", name)
		}
		if _, err := hex.DecodeString(parts[1]); err != nil {
			return fmt.Errorf("%s hash must use sha256:<64 hexadecimal characters>", name)
		}
	}
	return nil
}
