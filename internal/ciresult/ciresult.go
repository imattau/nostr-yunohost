// Package ciresult defines the small, versioned JSON file CI produces after
// testing a package revision. It is the on-disk artifact a workflow writes
// and `nostr-ynh attest` (Phase 4) reads to build a signed kind-30080
// attestation (internal/verification) - independent of Nostr so a CI job
// can produce it, and a human can inspect it, without any signing key
// present. See docs/attestation-trust-policy-plan.md Phase 2 and
// docs/ci-result-schema.md.
package ciresult

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// CurrentSchema is the schema version this package reads and writes. A
// future incompatible change bumps this rather than reinterpreting old
// files under a new meaning.
const CurrentSchema = 1

var (
	hex64Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
	resultPattern = regexp.MustCompile(`^(pass|fail|error)$`)
	checkPattern  = regexp.MustCompile(`^(pass|fail|skip|error)$`)
	appIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
)

// Result is the machine-readable CI result for one package revision.
// Individual check outcomes are kept, rather than a single boolean, so a
// local trust policy can later require specific checks (e.g.
// "package_check") while treating others as advisory.
type Result struct {
	Schema     int               `json:"schema"`
	AppID      string            `json:"app_id"`
	Repository string            `json:"repository"`
	Commit     string            `json:"commit"`
	Manifest   string            `json:"manifest"`
	Content    string            `json:"content"`
	Checks     map[string]string `json:"checks"`
	Result     string            `json:"result"`
}

// Parse decodes and validates a CI result document.
func Parse(data []byte) (Result, error) {
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		return Result{}, fmt.Errorf("decode CI result: %w", err)
	}
	if err := result.Validate(); err != nil {
		return Result{}, err
	}
	return result, nil
}

// Validate checks that every field is present and well formed. It does not
// check the result against any repository, declaration, or signing
// identity - those cross-checks belong to the caller (nostr-ynh attest,
// Phase 4, and the daemon's ingestion path, Phase 5).
func (r Result) Validate() error {
	if r.Schema != CurrentSchema {
		return fmt.Errorf("unsupported schema %d, expected %d", r.Schema, CurrentSchema)
	}
	if !appIDPattern.MatchString(r.AppID) {
		return fmt.Errorf("invalid app_id %q", r.AppID)
	}
	if err := validateRepository(r.Repository); err != nil {
		return err
	}
	if !commitPattern.MatchString(r.Commit) {
		return fmt.Errorf("commit must be 40-64 lowercase hexadecimal characters")
	}
	if err := validateHash("manifest", r.Manifest); err != nil {
		return err
	}
	if err := validateHash("content", r.Content); err != nil {
		return err
	}
	if len(r.Checks) == 0 {
		return fmt.Errorf("at least one check is required")
	}
	for name, outcome := range r.Checks {
		if name == "" || !checkPattern.MatchString(outcome) {
			return fmt.Errorf("check %q has invalid outcome %q", name, outcome)
		}
	}
	if !resultPattern.MatchString(r.Result) {
		return fmt.Errorf("result must be pass, fail, or error")
	}
	return nil
}

// Marshal encodes the result as indented JSON, matching the format CI
// workflows are expected to write.
func (r Result) Marshal() ([]byte, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode CI result: %w", err)
	}
	return data, nil
}

func validateHash(name, raw string) error {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 || parts[0] != "sha256" || !hex64Pattern.MatchString(parts[1]) {
		return fmt.Errorf("%s must use sha256:<64 lowercase hexadecimal characters>", name)
	}
	return nil
}

func validateRepository(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path == "" {
		return fmt.Errorf("repository must be an HTTPS repository URL")
	}
	return nil
}
