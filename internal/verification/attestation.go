// Package verification contains CI-backed package attestation events. An
// attestation is independent from a curator endorsement (kind 30079,
// internal/curation): an endorsement is a human/server recommendation, while
// an attestation is a machine-checkable claim that a specific repository
// commit passed a specific set of automated checks. See
// docs/attestation-trust-policy-plan.md Phase 1.
package verification

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/imattau/nostr-yunohost/internal/protocol"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// AttestationKind is provisional until registered/documented, mirroring
// AppDeclarationKind (30078) and curation.EndorsementKind (30079).
//
// It is a parameterised replaceable event addressed by (kind, verifier
// pubkey, d=app_id:commit). Addressing by commit, not just app_id, is the
// load-bearing choice: it is what makes attestation(repo, commit ABC) a
// distinct event from attestation(repo, commit DEF), so a package update
// invalidates the previous verification for installation purposes without
// deleting it - the old attestation remains a separate, still-valid event
// for the old commit.
const AttestationKind int = 30080

var (
	hex64Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
	resultPattern = regexp.MustCompile(`^(pass|fail|error)$`)
	checkPattern  = regexp.MustCompile(`^(pass|fail|skip|error)$`)
)

// Attestation is the validated, platform-specific data extracted from a
// parameterised replaceable Nostr attestation event.
type Attestation struct {
	Verifier     string
	AppID        string
	Repository   string
	Commit       string
	ManifestHash string
	ContentHash  string
	CIProvider   string
	CIRef        string
	TestedAt     int64
	Checks       map[string]string
	Result       string
}

// content is the machine-readable CI result payload (Phase 2 schema),
// carried as the event's JSON content. Tags duplicate the identity fields so
// relays and the daemon can filter/validate without parsing content.
type content struct {
	Schema int               `json:"schema"`
	Checks map[string]string `json:"checks"`
}

// Build creates a signed attestation for appID at commit, using privateKey
// as the verifier identity. checks must be non-empty and every value must be
// one of pass/fail/skip/error; result is the overall pass/fail/error verdict.
func Build(appID, repo, commit, manifestHash, contentHash, ciProvider, ciRef string, checks map[string]string, result, privateKey string) (nostr.Event, error) {
	if appID == "" || repo == "" {
		return nostr.Event{}, fmt.Errorf("app ID and repository are required")
	}
	if !commitPattern.MatchString(commit) {
		return nostr.Event{}, fmt.Errorf("commit must be 40-64 lowercase hexadecimal characters")
	}
	if err := validateHash("manifest", manifestHash); err != nil {
		return nostr.Event{}, err
	}
	if err := validateHash("content", contentHash); err != nil {
		return nostr.Event{}, err
	}
	if ciProvider == "" || ciRef == "" {
		return nostr.Event{}, fmt.Errorf("CI provider and CI reference are required")
	}
	if len(checks) == 0 {
		return nostr.Event{}, fmt.Errorf("at least one check is required")
	}
	for name, outcome := range checks {
		if name == "" || !checkPattern.MatchString(outcome) {
			return nostr.Event{}, fmt.Errorf("check %q has invalid outcome %q", name, outcome)
		}
	}
	if !resultPattern.MatchString(result) {
		return nostr.Event{}, fmt.Errorf("result must be pass, fail, or error")
	}
	verifier, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return nostr.Event{}, fmt.Errorf("derive verifier public key: %w", err)
	}
	payload, err := json.Marshal(content{Schema: 1, Checks: checks})
	if err != nil {
		return nostr.Event{}, fmt.Errorf("encode attestation content: %w", err)
	}
	event := nostr.Event{
		PubKey:    verifier,
		CreatedAt: nostr.Now(),
		Kind:      AttestationKind,
		Tags: nostr.Tags{
			{"d", appID + ":" + commit},
			{"app_id", appID},
			{"repo", repo},
			{"commit", commit},
			{"manifest", manifestHash},
			{"content", contentHash},
			{"ci_provider", ciProvider},
			{"ci_ref", ciRef},
			{"result", result},
		},
		Content: string(payload),
	}
	if err := event.Sign(privateKey); err != nil {
		return nostr.Event{}, fmt.Errorf("sign attestation: %w", err)
	}
	return event, nil
}

// Parse validates the event envelope and extracts the attestation. Matching
// the attestation's repo/commit/manifest/content against a specific app
// declaration is deliberately left to the caller (Phase 5), since parsing
// alone cannot know which declaration the attestation is meant to verify.
func Parse(event nostr.Event) (Attestation, error) {
	if event.Kind != AttestationKind {
		return Attestation{}, fmt.Errorf("unexpected attestation kind %d", event.Kind)
	}
	if event.CreatedAt <= 0 {
		return Attestation{}, fmt.Errorf("created_at must be positive")
	}
	if !hex64Pattern.MatchString(event.PubKey) {
		return Attestation{}, fmt.Errorf("verifier pubkey must be 64 lowercase hexadecimal characters")
	}
	if err := protocol.VerifyID(event); err != nil {
		return Attestation{}, err
	}
	if err := protocol.VerifySignature(event); err != nil {
		return Attestation{}, err
	}

	tags := make(map[string]string, len(event.Tags))
	for _, tag := range event.Tags {
		if len(tag) < 2 || tag[0] == "" || tag[1] == "" {
			return Attestation{}, fmt.Errorf("tags must contain a name and value")
		}
		if _, exists := tags[tag[0]]; exists {
			return Attestation{}, fmt.Errorf("tag %q must occur exactly once", tag[0])
		}
		tags[tag[0]] = tag[1]
	}
	for _, name := range []string{"d", "app_id", "repo", "commit", "manifest", "content", "ci_provider", "ci_ref", "result"} {
		if tags[name] == "" {
			return Attestation{}, fmt.Errorf("required tag %q must occur exactly once", name)
		}
	}
	if tags["d"] != tags["app_id"]+":"+tags["commit"] {
		return Attestation{}, fmt.Errorf("d tag must equal app_id:commit")
	}
	if !commitPattern.MatchString(tags["commit"]) {
		return Attestation{}, fmt.Errorf("commit must be 40-64 lowercase hexadecimal characters")
	}
	if err := validateHash("manifest", tags["manifest"]); err != nil {
		return Attestation{}, err
	}
	if err := validateHash("content", tags["content"]); err != nil {
		return Attestation{}, err
	}
	if !resultPattern.MatchString(tags["result"]) {
		return Attestation{}, fmt.Errorf("result must be pass, fail, or error")
	}

	var payload content
	if err := json.Unmarshal([]byte(event.Content), &payload); err != nil {
		return Attestation{}, fmt.Errorf("content must be a JSON object: %w", err)
	}
	if len(payload.Checks) == 0 {
		return Attestation{}, fmt.Errorf("content must include at least one check result")
	}
	for name, outcome := range payload.Checks {
		if name == "" || !checkPattern.MatchString(outcome) {
			return Attestation{}, fmt.Errorf("check %q has invalid outcome %q", name, outcome)
		}
	}

	return Attestation{
		Verifier:     event.PubKey,
		AppID:        tags["app_id"],
		Repository:   tags["repo"],
		Commit:       tags["commit"],
		ManifestHash: tags["manifest"],
		ContentHash:  tags["content"],
		CIProvider:   tags["ci_provider"],
		CIRef:        tags["ci_ref"],
		TestedAt:     int64(event.CreatedAt),
		Checks:       payload.Checks,
		Result:       tags["result"],
	}, nil
}

// Address encodes the attestation's identity as a shareable NIP-19 naddr,
// mirroring publisher.AppAddress for declarations.
func Address(event nostr.Event, relays []string) (string, error) {
	if event.Kind != AttestationKind || !nostr.IsValidPublicKey(event.PubKey) {
		return "", fmt.Errorf("event is not a valid attestation")
	}
	d := event.Tags.GetD()
	if d == "" {
		return "", fmt.Errorf("event has no address identifier")
	}
	return nip19.EncodeEntity(event.PubKey, event.Kind, d, relays)
}

func validateHash(name, raw string) error {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 || parts[0] != "sha256" || !hex64Pattern.MatchString(parts[1]) {
		return fmt.Errorf("%s must use sha256:<64 lowercase hexadecimal characters>", name)
	}
	return nil
}
