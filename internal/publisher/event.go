// Package publisher builds signed Nostr declarations for YunoHost packages.
package publisher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/imattau/nostr-yunohost/internal/protocol"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
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

// Profile is the publisher-side input for a kind-0 profile metadata event
// (NIP-01), published once (and re-published on change) so the publisher
// key resolves to a real, followable account in ordinary Nostr clients
// rather than an opaque hex string. All fields are optional.
type Profile struct {
	Name    string
	About   string
	Picture string
	Nip05   string
	Website string
}

// BuildProfile creates and signs a kind-0 profile metadata event for the
// publisher key. Nostr clients treat kind 0 as replaceable by (kind,
// pubkey) alone, so publishing again with updated fields simply supersedes
// the previous profile - no address or "d" tag is needed.
func BuildProfile(profile Profile, privateKey string) (nostr.Event, error) {
	publicKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return nostr.Event{}, fmt.Errorf("derive publisher public key: %w", err)
	}
	content := struct {
		Name    string `json:"name,omitempty"`
		About   string `json:"about,omitempty"`
		Picture string `json:"picture,omitempty"`
		Nip05   string `json:"nip05,omitempty"`
		Website string `json:"website,omitempty"`
	}{profile.Name, profile.About, profile.Picture, profile.Nip05, profile.Website}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return nostr.Event{}, fmt.Errorf("encode profile content: %w", err)
	}
	event := nostr.Event{
		PubKey:    publicKey,
		CreatedAt: nostr.Now(),
		Kind:      protocol.ProfileKind,
		Tags:      nostr.Tags{},
		Content:   string(contentBytes),
	}
	if err := event.Sign(privateKey); err != nil {
		return nostr.Event{}, fmt.Errorf("sign profile: %w", err)
	}
	return event, nil
}

// BuildAnnouncement creates and signs a kind-1 text note announcing an app
// declaration, so the update shows up in an ordinary Nostr feed instead of
// only as a replaceable event most clients never render. It derives
// version/commit/app ID from the already-built, already-signed declaration
// event rather than taking them as separate parameters, so the note can
// never drift from what was actually declared. declaration must be a signed
// kind-30078 event built by BuildDeclaration for the same private key.
func BuildAnnouncement(declaration nostr.Event, repository, displayName string, relays []string, privateKey string) (nostr.Event, error) {
	if declaration.Kind != protocol.AppDeclarationKind {
		return nostr.Event{}, fmt.Errorf("declaration is not a YunoHost app declaration")
	}
	publicKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return nostr.Event{}, fmt.Errorf("derive publisher public key: %w", err)
	}
	if declaration.PubKey != publicKey {
		return nostr.Event{}, fmt.Errorf("declaration was not signed by this private key")
	}
	appID := declaration.Tags.GetD()
	version := declaration.Tags.GetFirst([]string{"version"})
	commit := declaration.Tags.GetFirst([]string{"commit"})
	if appID == "" || version == nil || commit == nil {
		return nostr.Event{}, fmt.Errorf("declaration is missing required tags")
	}
	address, err := AppAddress(declaration, relays)
	if err != nil {
		return nostr.Event{}, fmt.Errorf("encode app address: %w", err)
	}
	name := displayName
	if name == "" {
		name = appID
	}
	shortCommit := commit.Value()
	if len(shortCommit) > 7 {
		shortCommit = shortCommit[:7]
	}
	content := fmt.Sprintf("📦 %s %s published\n%s@%s\nnostr:%s", name, version.Value(), repository, shortCommit, address)
	event := nostr.Event{
		PubKey:    publicKey,
		CreatedAt: nostr.Now(),
		Kind:      protocol.NoteKind,
		Tags: nostr.Tags{
			{"a", fmt.Sprintf("%d:%s:%s", protocol.AppDeclarationKind, publicKey, appID)},
			{"r", repository},
		},
		Content: content,
	}
	if err := event.Sign(privateKey); err != nil {
		return nostr.Event{}, fmt.Errorf("sign announcement: %w", err)
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
