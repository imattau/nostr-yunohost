package protocol

import (
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

func TestVerifyID(t *testing.T) {
	event := validEvent()
	event.ID = event.GetID()
	if err := VerifyID(event); err != nil {
		t.Fatalf("VerifyID() error = %v", err)
	}
}

func TestVerifyIDRejectsMutation(t *testing.T) {
	event := validEvent()
	event.ID = event.GetID()
	event.Content = `{"name":"changed"}`
	if err := VerifyID(event); err == nil {
		t.Fatal("VerifyID() accepted a mutated event")
	}
}

func TestVerifySignature(t *testing.T) {
	event := validEvent()
	privateKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	publicKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	event.PubKey = publicKey
	if err := event.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	if err := VerifyID(event); err != nil {
		t.Fatalf("VerifyID() error = %v", err)
	}
	if err := VerifySignature(event); err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}
}
