// Package trust contains local administrator trust policies.
package trust

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
)

// ExplicitPublishers accepts declarations only from configured publisher
// public keys. Keys may be supplied as lowercase hex keys or npub values.
type ExplicitPublishers struct {
	trusted map[string]struct{}
}

// NewExplicitPublishers builds the MVP allow-list policy.
func NewExplicitPublishers(keys []string) (ExplicitPublishers, error) {
	trusted := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		publicKey, err := normalizePublicKey(key)
		if err != nil {
			return ExplicitPublishers{}, err
		}
		trusted[publicKey] = struct{}{}
	}
	return ExplicitPublishers{trusted: trusted}, nil
}

// Publishers returns the normalized hexadecimal publisher keys in stable order.
func (p ExplicitPublishers) Publishers() []string {
	keys := make([]string, 0, len(p.trusted))
	for key := range p.trusted {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Validate verifies the event cryptographically, validates its declaration,
// and applies the local publisher allow-list.
func (p ExplicitPublishers) Validate(event nostr.Event) (protocol.AppDeclaration, error) {
	if _, ok := p.trusted[event.PubKey]; !ok {
		return protocol.AppDeclaration{}, fmt.Errorf("publisher %s is not trusted", event.PubKey)
	}
	if err := protocol.VerifyID(event); err != nil {
		return protocol.AppDeclaration{}, err
	}
	if err := protocol.VerifySignature(event); err != nil {
		return protocol.AppDeclaration{}, err
	}
	return protocol.ParseAppDeclaration(event)
}

func normalizePublicKey(raw string) (string, error) {
	key := strings.TrimSpace(raw)
	if nostr.IsValidPublicKey(key) {
		return key, nil
	}
	prefix, value, err := nip19.Decode(key)
	if err != nil || prefix != "npub" {
		return "", fmt.Errorf("invalid publisher public key %q", raw)
	}
	publicKey, ok := value.(string)
	if !ok || !nostr.IsValidPublicKey(publicKey) {
		return "", fmt.Errorf("invalid npub publisher key %q", raw)
	}
	return publicKey, nil
}
