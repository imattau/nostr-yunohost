package protocol

import (
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

func validEvent() Event {
	return Event{
		ID:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PubKey:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CreatedAt: 1,
		Kind:      AppDeclarationKind,
		Tags: nostr.Tags{
			{"d", "hello_nostr"},
			{"platform", "yunohost"},
			{"repo", "https://github.com/example/hello_nostr_ynh"},
			{"version", "1.0.0~ynh1"},
			{"commit", "cccccccccccccccccccccccccccccccccccccccc"},
			{"manifest", "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
			{"content", "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
		},
		Content: `{"name":"Hello Nostr","architectures":["amd64"]}`,
		Sig:     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
}

func TestParseAppDeclaration(t *testing.T) {
	declaration, err := ParseAppDeclaration(validEvent())
	if err != nil {
		t.Fatalf("ParseAppDeclaration() error = %v", err)
	}
	if declaration.AppID != "hello_nostr" || declaration.Name != "Hello Nostr" {
		t.Fatalf("unexpected declaration: %+v", declaration)
	}
}

func TestParseAppDeclarationRejectsDuplicateRequiredTag(t *testing.T) {
	event := validEvent()
	event.Tags = append(event.Tags, []string{"version", "2.0.0~ynh1"})
	if _, err := ParseAppDeclaration(event); err == nil {
		t.Fatal("ParseAppDeclaration() accepted duplicate version tag")
	}
}

func TestParseAppDeclarationRejectsNonHTTPSRepository(t *testing.T) {
	event := validEvent()
	event.Tags[2][1] = "git@github.com:example/hello_nostr_ynh.git"
	if _, err := ParseAppDeclaration(event); err == nil {
		t.Fatal("ParseAppDeclaration() accepted non-HTTPS repository")
	}
}
