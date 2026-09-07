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

// trustedEndorsementCounts tallies distinct trusted curators per
// publisher/app pair, counting only claims that carry curation weight
// ("recommend" or "tested"). The set of trusted curators has already been
// enforced upstream by Accept, but endorsements passed in directly (as when
// replaying a stored list) are not re-checked against trustedCurators here -
// callers that need that guarantee should only pass endorsements that came
// through Accept.
func (p Policy) trustedEndorsementCounts(endorsements []Endorsement) map[string]map[string]struct{} {
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
	return counts
}

// TrustedEndorsementCount returns the number of distinct curators who have
// endorsed the given publisher/app pair with a "recommend" or "tested"
// claim. Callers checking many publisher/app pairs against the same
// endorsement list (such as Store.WriteSnapshot, once per app in the
// catalogue) should call EndorsementCounts once instead, to avoid
// rebuilding the same tally from scratch for every pair.
func (p Policy) TrustedEndorsementCount(publisher, appID string, endorsements []Endorsement) int {
	return p.EndorsementCounts(endorsements)[publisher+"\x00"+appID]
}

// EndorsementCounts tallies distinct trusted-curator counts for every
// publisher/app pair present in endorsements at once, keyed by
// "publisher\x00appID" - the same key convention Store already uses
// internally. Meant to be computed once per snapshot/selection pass rather
// than once per pair.
func (p Policy) EndorsementCounts(endorsements []Endorsement) map[string]int {
	sets := p.trustedEndorsementCounts(endorsements)
	counts := make(map[string]int, len(sets))
	for key, curators := range sets {
		counts[key] = len(curators)
	}
	return counts
}

// MinimumEndorsements returns the configured endorsement threshold.
func (p Policy) MinimumEndorsements() int {
	return p.minimumEndorsements
}

// SelectCanonical returns a declaration only when exactly one candidate has
// the highest trusted endorsement count and meets the configured threshold.
// A nil result means no canonical selection is safe.
func (p Policy) SelectCanonical(candidates []protocol.AppDeclaration, endorsements []Endorsement) *protocol.AppDeclaration {
	counts := p.trustedEndorsementCounts(endorsements)
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
