package publisher

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/imattau/nostr-yunohost/internal/protocol"
	"github.com/nbd-wtf/go-nostr"
)

func TestBuildDeclarationUsesSDKSigning(t *testing.T) {
	event, err := BuildDeclaration(Metadata{
		AppID:         "hello_nostr",
		Repository:    "https://github.com/example/hello_nostr_ynh",
		Version:       "1.0.0~ynh1",
		Commit:        "cccccccccccccccccccccccccccccccccccccccc",
		ManifestHash:  HashBytes([]byte("manifest")),
		ContentHash:   HashBytes([]byte("tree")),
		Name:          "Hello Nostr",
		Architectures: []string{"amd64"},
	}, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifyID(event); err != nil {
		t.Fatalf("VerifyID() error = %v", err)
	}
	if err := protocol.VerifySignature(event); err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}
	if _, err := protocol.ParseAppDeclaration(event); err != nil {
		t.Fatalf("ParseAppDeclaration() error = %v", err)
	}
}

func TestBuildDeclarationRejectsInvalidHash(t *testing.T) {
	_, err := BuildDeclaration(Metadata{
		AppID:        "hello_nostr",
		Repository:   "https://github.com/example/hello_nostr_ynh",
		Version:      "1.0.0~ynh1",
		Commit:       "cccccccccccccccccccccccccccccccccccccccc",
		ManifestHash: "sha256:not-a-hash",
		ContentHash:  HashBytes([]byte("tree")),
	}, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err == nil {
		t.Fatal("BuildDeclaration() accepted an invalid manifest hash")
	}
}

const testPrivateKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestBuildProfile(t *testing.T) {
	event, err := BuildProfile(Profile{
		Name:    "Example Publisher",
		About:   "Publishes YunoHost packages",
		Picture: "https://example.org/icon.png",
		Nip05:   "publisher@example.org",
		Website: "https://example.org",
	}, testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if event.Kind != protocol.ProfileKind {
		t.Fatalf("Kind = %d, want %d", event.Kind, protocol.ProfileKind)
	}
	if err := protocol.VerifyID(event); err != nil {
		t.Fatalf("VerifyID() error = %v", err)
	}
	if err := protocol.VerifySignature(event); err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}
	var content struct {
		Name  string `json:"name"`
		Nip05 string `json:"nip05"`
	}
	if err := json.Unmarshal([]byte(event.Content), &content); err != nil {
		t.Fatal(err)
	}
	if content.Name != "Example Publisher" || content.Nip05 != "publisher@example.org" {
		t.Fatalf("unexpected profile content: %+v", content)
	}
}

func TestBuildProfileOmitsEmptyFields(t *testing.T) {
	event, err := BuildProfile(Profile{Name: "Example Publisher"}, testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(event.Content, "about") {
		t.Fatalf("expected empty fields to be omitted, got %q", event.Content)
	}
}

func buildTestDeclaration(t *testing.T) nostr.Event {
	t.Helper()
	event, err := BuildDeclaration(Metadata{
		AppID:        "hello_nostr",
		Repository:   "https://github.com/example/hello_nostr_ynh",
		Version:      "1.0.0~ynh1",
		Commit:       "cccccccccccccccccccccccccccccccccccccccc",
		ManifestHash: HashBytes([]byte("manifest")),
		ContentHash:  HashBytes([]byte("tree")),
		Name:         "Hello Nostr",
	}, testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func TestBuildAnnouncement(t *testing.T) {
	declaration := buildTestDeclaration(t)
	event, err := BuildAnnouncement(declaration, "https://github.com/example/hello_nostr_ynh", "Hello Nostr", []string{"wss://relay.example"}, testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if event.Kind != protocol.NoteKind {
		t.Fatalf("Kind = %d, want %d", event.Kind, protocol.NoteKind)
	}
	if err := protocol.VerifyID(event); err != nil {
		t.Fatalf("VerifyID() error = %v", err)
	}
	if err := protocol.VerifySignature(event); err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}
	wantAddress := "30078:" + declaration.PubKey + ":hello_nostr"
	addressTag := event.Tags.GetFirst([]string{"a", wantAddress})
	if addressTag == nil {
		t.Fatalf("announcement missing %q a-tag, got tags %v", wantAddress, event.Tags)
	}
	if repoTag := event.Tags.GetFirst([]string{"r"}); repoTag == nil || repoTag.Value() != "https://github.com/example/hello_nostr_ynh" {
		t.Fatalf("unexpected r tag: %v", repoTag)
	}
	if !strings.Contains(event.Content, "Hello Nostr") || !strings.Contains(event.Content, "1.0.0~ynh1") {
		t.Fatalf("announcement content missing name/version: %q", event.Content)
	}
}

func TestBuildAnnouncementRejectsWrongKey(t *testing.T) {
	declaration := buildTestDeclaration(t)
	otherKey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := BuildAnnouncement(declaration, "https://github.com/example/hello_nostr_ynh", "Hello Nostr", nil, otherKey); err == nil {
		t.Fatal("BuildAnnouncement() accepted a declaration signed by a different key")
	}
}

func TestBuildAnnouncementForDeclaration(t *testing.T) {
	declaration := protocol.AppDeclaration{
		AppID:      "hello_nostr",
		Publisher:  mustPublicKey(t, testPrivateKey),
		Repository: "https://github.com/example/hello_nostr_ynh",
		Version:    "1.0.0~ynh1",
		Commit:     "cccccccccccccccccccccccccccccccccccccccc",
		Name:       "Hello Nostr",
	}
	event, err := BuildAnnouncementForDeclaration(declaration, []string{"wss://relay.example"}, testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if event.Kind != protocol.NoteKind {
		t.Fatalf("Kind = %d, want %d", event.Kind, protocol.NoteKind)
	}
	if err := protocol.VerifySignature(event); err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}
	wantAddress := "30078:" + declaration.Publisher + ":hello_nostr"
	if tag := event.Tags.GetFirst([]string{"a", wantAddress}); tag == nil {
		t.Fatalf("announcement missing %q a-tag, got tags %v", wantAddress, event.Tags)
	}
	if !strings.Contains(event.Content, "Hello Nostr") || !strings.Contains(event.Content, "1.0.0~ynh1") {
		t.Fatalf("announcement content missing name/version: %q", event.Content)
	}
}

func TestBuildAnnouncementForDeclarationRejectsWrongKey(t *testing.T) {
	declaration := protocol.AppDeclaration{
		AppID:      "hello_nostr",
		Publisher:  mustPublicKey(t, testPrivateKey),
		Repository: "https://github.com/example/hello_nostr_ynh",
		Version:    "1.0.0~ynh1",
		Commit:     "cccccccccccccccccccccccccccccccccccccccc",
	}
	otherKey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := BuildAnnouncementForDeclaration(declaration, nil, otherKey); err == nil {
		t.Fatal("BuildAnnouncementForDeclaration() accepted a declaration published by a different key")
	}
}

func mustPublicKey(t *testing.T, privateKey string) string {
	t.Helper()
	publicKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}

func TestBuildAnnouncementRejectsWrongKind(t *testing.T) {
	profile, err := BuildProfile(Profile{Name: "x"}, testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildAnnouncement(profile, "https://github.com/example/hello_nostr_ynh", "Hello Nostr", nil, testPrivateKey); err == nil {
		t.Fatal("BuildAnnouncement() accepted a non-declaration event")
	}
}
