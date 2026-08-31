package publisher

import (
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

func TestAppAddress(t *testing.T) {
	event, err := BuildDeclaration(Metadata{
		AppID:        "hello_nostr",
		Repository:   "https://github.com/example/hello_nostr_ynh",
		Version:      "1.0.0~ynh1",
		Commit:       "cccccccccccccccccccccccccccccccccccccccc",
		ManifestHash: HashBytes([]byte("manifest")),
		ContentHash:  HashBytes([]byte("tree")),
	}, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	address, err := AppAddress(event, []string{"wss://relay.example"})
	if err != nil {
		t.Fatal(err)
	}
	prefix, value, err := nip19.Decode(address)
	if err != nil || prefix != "naddr" {
		t.Fatalf("invalid address %q: %v", address, err)
	}
	pointer := value.(nostr.EntityPointer)
	if pointer.Identifier != "hello_nostr" || pointer.Kind != 30078 {
		t.Fatalf("unexpected address pointer: %+v", pointer)
	}
}
