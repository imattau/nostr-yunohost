package publisher

import (
	"testing"

	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
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
