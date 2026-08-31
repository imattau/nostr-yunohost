// Package curation contains curator endorsement events.
package curation

import (
	"fmt"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
)

// EndorsementKind is provisional until the event is registered/documented.
const EndorsementKind = 30079

type Endorsement struct {
	Curator   string
	Publisher string
	AppID     string
	Claim     string
	Comment   string
}

// Build creates a signed curator endorsement for a publisher/app identity.
func Build(publisher, appID, claim, comment, privateKey string) (nostr.Event, error) {
	if !nostr.IsValidPublicKey(publisher) || appID == "" || claim == "" {
		return nostr.Event{}, fmt.Errorf("publisher, app ID, and claim are required")
	}
	curator, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return nostr.Event{}, fmt.Errorf("derive curator public key: %w", err)
	}
	event := nostr.Event{
		PubKey:    curator,
		CreatedAt: nostr.Now(),
		Kind:      EndorsementKind,
		Tags: nostr.Tags{
			{"a", fmt.Sprintf("%d:%s:%s", protocol.AppDeclarationKind, publisher, appID)},
			{"claim", claim},
		},
		Content: comment,
	}
	if err := event.Sign(privateKey); err != nil {
		return nostr.Event{}, fmt.Errorf("sign endorsement: %w", err)
	}
	return event, nil
}

// Parse validates and extracts a signed endorsement event.
func Parse(event nostr.Event) (Endorsement, error) {
	if event.Kind != EndorsementKind {
		return Endorsement{}, fmt.Errorf("unexpected endorsement kind %d", event.Kind)
	}
	if err := protocol.VerifyID(event); err != nil {
		return Endorsement{}, err
	}
	if err := protocol.VerifySignature(event); err != nil {
		return Endorsement{}, err
	}
	if len(event.Tags) < 2 || len(event.Tags[0]) < 2 || event.Tags[0][0] != "a" || len(event.Tags[1]) < 2 || event.Tags[1][0] != "claim" {
		return Endorsement{}, fmt.Errorf("endorsement requires a target and claim tag")
	}
	parts := strings.SplitN(event.Tags[0][1], ":", 3)
	if len(parts) != 3 || parts[0] != fmt.Sprint(protocol.AppDeclarationKind) || !nostr.IsValidPublicKey(parts[1]) || parts[2] == "" {
		return Endorsement{}, fmt.Errorf("invalid app target")
	}
	return Endorsement{Curator: event.PubKey, Publisher: parts[1], AppID: parts[2], Claim: event.Tags[1][1], Comment: event.Content}, nil
}
