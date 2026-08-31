package relay

import (
	"context"
	"testing"
)

func TestNewRejectsInvalidRelay(t *testing.T) {
	if _, err := New(context.Background(), []string{"https://relay.example"}); err == nil {
		t.Fatal("New() accepted an HTTPS URL as a relay")
	}
}

func TestNewDeduplicatesRelays(t *testing.T) {
	client, err := New(context.Background(), []string{
		"wss://relay.example",
		"wss://relay.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(client.urls) != 1 {
		t.Fatalf("got %d relay URLs, want 1", len(client.urls))
	}
}

func TestNewRequiresRelay(t *testing.T) {
	if _, err := New(context.Background(), nil); err == nil {
		t.Fatal("New() accepted an empty relay list")
	}
}
