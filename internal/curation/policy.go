package curation

import (
	"fmt"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
)

// Policy defines the trusted curator set and endorsement threshold.
type Policy struct {
	trustedCurators     map[string]struct{}
	minimumEndorsements int
}

func NewPolicy(curators []string, minimumEndorsements int) (Policy, error) {
	if minimumEndorsements < 1 {
		return Policy{}, fmt.Errorf("minimum endorsements must be positive")
	}
	trusted := make(map[string]struct{}, len(curators))
	for _, curator := range curators {
		key, err := normalizeKey(curator)
		if err != nil {
			return Policy{}, err
		}
		trusted[key] = struct{}{}
	}
	return Policy{trustedCurators: trusted, minimumEndorsements: minimumEndorsements}, nil
}

func (p Policy) Accept(event nostr.Event) (Endorsement, error) {
	endorsement, err := Parse(event)
	if err != nil {
		return Endorsement{}, err
	}
	if _, ok := p.trustedCurators[endorsement.Curator]; !ok {
		return Endorsement{}, fmt.Errorf("curator %s is not trusted", endorsement.Curator)
	}
	return endorsement, nil
}

// SelectCanonical returns a declaration only when exactly one candidate has
// the highest trusted endorsement count and meets the configured threshold.
// A nil result means no canonical selection is safe.
func (p Policy) SelectCanonical(candidates []protocol.AppDeclaration, endorsements []Endorsement) *protocol.AppDeclaration {
	counts := make(map[string]map[string]struct{})
	for _, endorsement := range endorsements {
		if endorsement.Claim != "recommend" && endorsement.Claim != "tested" {
			continue
		}
		key := endorsement.Publisher + "\x00" + endorsement.AppID
		if counts[key] == nil {
			counts[key] = make(map[string]struct{})
		}
		counts[key][endorsement.Curator] = struct{}{}
	}
	var selected *protocol.AppDeclaration
	best := 0
	tied := false
	for i := range candidates {
		key := candidates[i].Publisher + "\x00" + candidates[i].AppID
		count := len(counts[key])
		if count < p.minimumEndorsements || count < best {
			continue
		}
		if count == best {
			tied = true
			continue
		}
		best = count
		selected = &candidates[i]
		tied = false
	}
	if selected == nil || tied {
		return nil
	}
	return selected
}

func normalizeKey(raw string) (string, error) {
	key := strings.TrimSpace(raw)
	if nostr.IsValidPublicKey(key) {
		return key, nil
	}
	prefix, value, err := nip19.Decode(key)
	if err != nil || prefix != "npub" {
		return "", fmt.Errorf("invalid curator public key %q", raw)
	}
	publicKey, ok := value.(string)
	if !ok || !nostr.IsValidPublicKey(publicKey) {
		return "", fmt.Errorf("invalid curator npub %q", raw)
	}
	return publicKey, nil
}
