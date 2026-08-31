package protocol

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
)

func TestVerifyID(t *testing.T) {
	event := validEvent()
	serialized, err := json.Marshal([]any{0, event.PubKey, event.CreatedAt, event.Kind, event.Tags, event.Content})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(serialized)
	event.ID = fmt.Sprintf("%x", digest[:])
	if err := VerifyID(event); err != nil {
		t.Fatalf("VerifyID() error = %v", err)
	}
}

func TestVerifyIDRejectsMutation(t *testing.T) {
	event := validEvent()
	serialized, err := json.Marshal([]any{0, event.PubKey, event.CreatedAt, event.Kind, event.Tags, event.Content})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(serialized)
	event.ID = fmt.Sprintf("%x", digest[:])
	event.Content = `{"name":"changed"}`
	if err := VerifyID(event); err == nil {
		t.Fatal("VerifyID() accepted a mutated event")
	}
}
