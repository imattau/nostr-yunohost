// Package catalog stores validated current app declarations and exposes a
// deterministic snapshot for the YunoHost translation layer.
package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nostr-yunohost/nostr-yunohost/internal/curation"
	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
	"github.com/nostr-yunohost/nostr-yunohost/internal/repository"
	"github.com/nostr-yunohost/nostr-yunohost/internal/trust"
	"github.com/nostr-yunohost/nostr-yunohost/internal/verification"
)

type record struct {
	Event       nostr.Event
	Declaration protocol.AppDeclaration
	CreatedAt   nostr.Timestamp
	Manifest    map[string]any
	Logo        []byte
	LogoHash    string
	Branch      string
}

// selectSameSourceLatest resolves a duplicate app ID when every declaration
// points at the same repository. Trust and repository verification have
// already happened before records reach this point. A different repository
// remains ambiguous and must be curated explicitly.
func selectSameSourceLatest(candidates []record) (record, bool) {
	if len(candidates) == 0 {
		return record{}, false
	}
	repository := normalizeRepository(candidates[0].Declaration.Repository)
	for _, candidate := range candidates[1:] {
		if normalizeRepository(candidate.Declaration.Repository) != repository {
			return record{}, false
		}
	}
	selected := candidates[0]
	for _, candidate := range candidates[1:] {
		versionOrder := comparePackageVersions(candidate.Declaration.Version, selected.Declaration.Version)
		if versionOrder > 0 || (versionOrder == 0 && newerRecord(candidate, selected)) {
			selected = candidate
		}
	}
	return selected, true
}

func normalizeRepository(repository string) string {
	repository = strings.TrimRight(strings.TrimSpace(repository), "/")
	return strings.TrimSuffix(repository, ".git")
}

// NormalizeRepositoryURL exposes the same repository-identity normalization
// used to resolve same-source duplicate declarations, so other packages
// (such as matching a locally installed app back to its declaration) treat
// repository URLs identically instead of re-implementing the rule.
func NormalizeRepositoryURL(repository string) string {
	return normalizeRepository(repository)
}

func newerRecord(left, right record) bool {
	if left.CreatedAt != right.CreatedAt {
		return left.CreatedAt > right.CreatedAt
	}
	if left.Declaration.Publisher != right.Declaration.Publisher {
		return left.Declaration.Publisher > right.Declaration.Publisher
	}
	return left.Event.ID > right.Event.ID
}

// comparePackageVersions provides the ordering needed by YunoHost versions,
// including the commonly used ~ynh suffix. It follows Debian's useful rule
// that '~' sorts before every other character, while comparing digit runs as
// numbers and all other runs lexically. This keeps the core dependency-free.
func comparePackageVersions(left, right string) int {
	for i, j := 0, 0; i < len(left) || j < len(right); {
		if i == len(left) {
			return -1
		}
		if j == len(right) {
			return 1
		}
		if left[i] == '~' || right[j] == '~' {
			if left[i] == right[j] {
				i++
				j++
				continue
			}
			if left[i] == '~' {
				return -1
			}
			return 1
		}
		leftDigit, rightDigit := left[i] >= '0' && left[i] <= '9', right[j] >= '0' && right[j] <= '9'
		if leftDigit && rightDigit {
			leftEnd, rightEnd := i, j
			for leftEnd < len(left) && left[leftEnd] >= '0' && left[leftEnd] <= '9' {
				leftEnd++
			}
			for rightEnd < len(right) && right[rightEnd] >= '0' && right[rightEnd] <= '9' {
				rightEnd++
			}
			leftRun, rightRun := strings.TrimLeft(left[i:leftEnd], "0"), strings.TrimLeft(right[j:rightEnd], "0")
			if len(leftRun) != len(rightRun) {
				if len(leftRun) > len(rightRun) {
					return 1
				}
				return -1
			}
			if leftRun != rightRun {
				if leftRun > rightRun {
					return 1
				}
				return -1
			}
			i, j = leftEnd, rightEnd
			continue
		}
		if left[i] != right[j] {
			if left[i] > right[j] {
				return 1
			}
			return -1
		}
		i++
		j++
	}
	return 0
}

// attestationRecord pairs a stored attestation with the full signed event it
// came from, so byVerifier dedup can compare CreatedAt the same way entries
// does for declarations.
type attestationRecord struct {
	Event       nostr.Event
	Attestation verification.Attestation
}

// attestationKey identifies the exact revision an attestation is about -
// the same (repository, commit) pair a declaration advertises, normalized
// the same way selectSameSourceLatest already normalizes repository
// identity so an attestation and a declaration for the same revision agree
// on the key regardless of a trailing slash or ".git" suffix.
func attestationKey(repositoryURL, commit string) string {
	return normalizeRepository(repositoryURL) + "\x00" + commit
}

// Store keeps the latest accepted declaration for each publisher/app pair.
type Store struct {
	mu             sync.RWMutex
	policy         trust.ExplicitPublishers
	entries        map[string]record
	curationPolicy *curation.Policy
	endorsements   []curation.Endorsement
	// attestations is keyed first by attestationKey(repo, commit), then by
	// verifier pubkey, so multiple independent verifiers can each hold their
	// own attestation for the same revision (docs/attestation-trust-policy-plan.md
	// Phase 12), while a later event from the same verifier for the same
	// revision replaces its earlier one.
	attestations map[string]map[string]attestationRecord
	// attestationPolicy is applied in WriteSnapshot. Its zero value is
	// trust.AttestationOff, so an unconfigured daemon behaves exactly as it
	// did before this policy existed.
	attestationPolicy trust.AttestationPolicy
}

// SetCurationPolicy enables trusted-curator selection for duplicate app IDs.
func (s *Store) SetCurationPolicy(policy curation.Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.curationPolicy = &policy
}

// SetAttestationPolicy configures how CI-backed attestations affect the
// generated catalogue (docs/attestation-trust-policy-plan.md Phase 6).
func (s *Store) SetAttestationPolicy(policy trust.AttestationPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attestationPolicy = policy
}

func NewStore(policy trust.ExplicitPublishers) *Store {
	return &Store{policy: policy, entries: make(map[string]record)}
}

// Ingest validates and stores an event. Invalid or untrusted events are not
// added to the snapshot and are returned for diagnostics.
func (s *Store) Ingest(event nostr.Event) error {
	declaration, err := s.policy.Validate(event)
	if err != nil {
		return err
	}
	key := declaration.Publisher + "\x00" + declaration.AppID
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.entries[key]; ok && current.CreatedAt >= event.CreatedAt {
		return nil
	}
	s.entries[key] = record{Event: event, Declaration: declaration, CreatedAt: event.CreatedAt}
	return nil
}

// IngestVerified applies trust validation and then verifies the authoritative
// repository before adding the declaration to the store.
func (s *Store) IngestVerified(ctx context.Context, event nostr.Event, verify func(context.Context, protocol.AppDeclaration) (map[string]any, error)) error {
	return s.IngestVerifiedPackage(ctx, event, func(ctx context.Context, declaration protocol.AppDeclaration) (repository.VerifiedPackage, error) {
		manifest, err := verify(ctx, declaration)
		return repository.VerifiedPackage{Manifest: manifest}, err
	})
}

// IngestVerifiedPackage is like IngestVerified but also retains an optional
// verified logo for serving through the YunoHost catalogue endpoint.
func (s *Store) IngestVerifiedPackage(ctx context.Context, event nostr.Event, verify func(context.Context, protocol.AppDeclaration) (repository.VerifiedPackage, error)) error {
	declaration, err := s.policy.Validate(event)
	if err != nil {
		return err
	}
	verified, err := verify(ctx, declaration)
	if err != nil {
		return fmt.Errorf("verify repository: %w", err)
	}
	logoHash := repository.LogoHash(verified.Logo)
	if _, err := TranslateWithBranch(declaration, verified.Manifest, logoHash, verified.Branch, int64(event.CreatedAt)); err != nil {
		return fmt.Errorf("translate catalogue entry: %w", err)
	}
	key := declaration.Publisher + "\x00" + declaration.AppID
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.entries[key]; ok && current.CreatedAt >= event.CreatedAt {
		return nil
	}
	s.entries[key] = record{Event: event, Declaration: declaration, CreatedAt: event.CreatedAt, Manifest: verified.Manifest, Logo: verified.Logo, LogoHash: logoHash, Branch: verified.Branch}
	return nil
}

// IngestEndorsement validates and records a trusted curator endorsement.
func (s *Store) IngestEndorsement(event nostr.Event) error {
	s.mu.Lock()
	policy := s.curationPolicy
	s.mu.Unlock()
	if policy == nil {
		return fmt.Errorf("curation policy is not configured")
	}
	endorsement, err := policy.Accept(event)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.endorsements {
		if existing.Curator == endorsement.Curator && existing.Publisher == endorsement.Publisher && existing.AppID == endorsement.AppID {
			return nil
		}
	}
	s.endorsements = append(s.endorsements, endorsement)
	return nil
}

// IngestAttestation validates and stores a CI-backed attestation event
// (kind 30080, internal/verification): signature, event ID, and every
// required tag/content field are checked by verification.Parse itself.
// Unlike declarations, an attestation is accepted independently of whether
// any matching declaration currently exists in this store - it is a
// well-formed, independently signed claim about a (repository, commit)
// pair by itself, per docs/attestation-trust-policy-plan.md Phase 5's
// "declaration + zero or more attestations" model. Whether it actually
// matches a specific accepted declaration - including the hash checks that
// matter most - is decided by AttestationsFor, not here.
func (s *Store) IngestAttestation(event nostr.Event) error {
	parsed, err := verification.Parse(event)
	if err != nil {
		return err
	}
	key := attestationKey(parsed.Repository, parsed.Commit)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attestations == nil {
		s.attestations = make(map[string]map[string]attestationRecord)
	}
	byVerifier := s.attestations[key]
	if byVerifier == nil {
		byVerifier = make(map[string]attestationRecord)
		s.attestations[key] = byVerifier
	}
	if existing, ok := byVerifier[parsed.Verifier]; ok && existing.Event.CreatedAt >= event.CreatedAt {
		return nil
	}
	byVerifier[parsed.Verifier] = attestationRecord{Event: event, Attestation: parsed}
	return nil
}

// AttestationsFor returns every stored attestation that actually matches
// declaration's exact revision, sorted by verifier pubkey for a stable
// result. Matching on repository and commit alone is not enough: an
// attestation whose manifest/content hash disagrees with the declaration's
// own (already repository-verified, see IngestVerifiedPackage) hashes is
// never returned, even though its repo/commit match - that is exactly what
// "never treat an attestation for another revision as valid" rules out, and
// the shape a forged or simply stale attestation would take.
func (s *Store) AttestationsFor(declaration protocol.AppDeclaration) []verification.Attestation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.attestationsForLocked(declaration)
}

// attestationsForLocked is AttestationsFor's implementation, callable by
// WriteSnapshot without recursively RLock-ing the same non-reentrant mutex
// it's already holding for the whole snapshot build.
func (s *Store) attestationsForLocked(declaration protocol.AppDeclaration) []verification.Attestation {
	key := attestationKey(declaration.Repository, declaration.Commit)
	byVerifier := s.attestations[key]
	if len(byVerifier) == 0 {
		return nil
	}
	matched := make([]verification.Attestation, 0, len(byVerifier))
	for _, record := range byVerifier {
		if record.Attestation.ManifestHash != declaration.ManifestHash || record.Attestation.ContentHash != declaration.ContentHash {
			continue
		}
		matched = append(matched, record.Attestation)
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].Verifier < matched[j].Verifier })
	return matched
}

type cacheFile struct {
	Entries []record `json:"entries"`
}

// Save persists accepted records to a local JSON cache. The write is atomic
// within the target directory.
func (s *Store) Save(path string) error {
	s.mu.RLock()
	entries := make([]record, 0, len(s.entries))
	for _, entry := range s.entries {
		entries = append(entries, entry)
	}
	s.mu.RUnlock()
	data, err := json.Marshal(cacheFile{Entries: entries})
	if err != nil {
		return fmt.Errorf("encode catalogue cache: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}
	temporaryPath := path + ".tmp"
	if err := os.WriteFile(temporaryPath, append(data, '\n'), 0o640); err != nil {
		return fmt.Errorf("write catalogue cache: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace catalogue cache: %w", err)
	}
	return nil
}

// Load restores a cache and revalidates every stored event against the
// current cryptographic and trust policy.
func (s *Store) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read catalogue cache: %w", err)
	}
	var cached cacheFile
	if err := json.Unmarshal(data, &cached); err != nil {
		return fmt.Errorf("decode catalogue cache: %w", err)
	}
	for _, entry := range cached.Entries {
		declaration, err := s.policy.Validate(entry.Event)
		if err != nil {
			continue
		}
		if entry.Manifest == nil {
			continue
		}
		if _, err := TranslateWithBranch(declaration, entry.Manifest, entry.LogoHash, entry.Branch, int64(entry.Event.CreatedAt)); err != nil {
			continue
		}
		key := declaration.Publisher + "\x00" + declaration.AppID
		branch := entry.Branch
		if branch == "" {
			branch = "main"
		}
		s.entries[key] = record{Event: entry.Event, Declaration: declaration, CreatedAt: entry.Event.CreatedAt, Manifest: entry.Manifest, Logo: entry.Logo, LogoHash: entry.LogoHash, Branch: branch}
	}
	return nil
}

// Declarations returns every currently accepted declaration, in stable
// publisher/app order. Unlike Snapshot, this includes entries that have not
// (yet) been verified against their authoritative repository (Manifest ==
// nil), so callers that only care about the declared identity (publisher,
// app ID, repository) - such as matching against locally installed apps -
// see the full accepted set.
func (s *Store) Declarations() []protocol.AppDeclaration {
	return s.Snapshot()
}

// Snapshot returns declarations in stable publisher/app order.
func (s *Store) Snapshot() []protocol.AppDeclaration {
	s.mu.RLock()
	declarations := make([]protocol.AppDeclaration, 0, len(s.entries))
	for _, entry := range s.entries {
		declarations = append(declarations, entry.Declaration)
	}
	s.mu.RUnlock()
	sort.Slice(declarations, func(i, j int) bool {
		left := declarations[i].Publisher + "\x00" + declarations[i].AppID
		right := declarations[j].Publisher + "\x00" + declarations[j].AppID
		return left < right
	})
	return declarations
}

// WriteSnapshot writes the current YunoHost v3 catalogue representation.
func (s *Store) WriteSnapshot(output interface{ Write([]byte) (int, error) }) error {
	s.mu.RLock()
	catalogue := YunoHostCatalog{
		Antifeatures: []any{},
		Apps:         make(map[string]YunoHostApp),
		Categories:   []any{},
		Security: SecurityIndex{
			Version: 1,
			Apps:    map[string][]any{},
			System:  map[string][]any{},
		},
	}
	byAppID := make(map[string][]record)
	for _, entry := range s.entries {
		if entry.Manifest == nil {
			continue
		}
		byAppID[entry.Declaration.AppID] = append(byAppID[entry.Declaration.AppID], entry)
	}
	// Computed once for the whole snapshot rather than once per app -
	// TrustedEndorsementCount would otherwise rebuild this same tally from
	// scratch for every entry in byAppID.
	var endorsementCounts map[string]int
	if s.curationPolicy != nil {
		endorsementCounts = s.curationPolicy.EndorsementCounts(s.endorsements)
	}
	for appID, candidates := range byAppID {
		var selected record
		if len(candidates) == 1 {
			selected = candidates[0]
		} else {
			var ok bool
			selected, ok = selectSameSourceLatest(candidates)
			if ok {
				// Same-source declarations are safe to resolve without curator input.
			} else if s.curationPolicy == nil {
				continue
			} else {
				declarations := make([]protocol.AppDeclaration, 0, len(candidates))
				for _, candidate := range candidates {
					declarations = append(declarations, candidate.Declaration)
				}
				declaration := s.curationPolicy.SelectCanonical(declarations, s.endorsements)
				if declaration == nil {
					continue
				}
				for _, candidate := range candidates {
					if candidate.Declaration.Publisher == declaration.Publisher {
						selected = candidate
						break
					}
				}
			}
		}
		// Phase 6: under AttestationRequire, a declaration without an
		// acceptable attestation for its exact revision is excluded from
		// the generated catalogue entirely - discoverable via other means
		// (e.g. Declarations/Snapshot), just not offered to the YunoHost
		// installer. Off and Prefer always accept, so this is a no-op
		// until an administrator opts into Require.
		if !s.attestationPolicy.Evaluate(s.attestationsForLocked(selected.Declaration)).Accepted {
			continue
		}
		app, err := TranslateWithBranch(selected.Declaration, selected.Manifest, selected.LogoHash, selected.Branch, int64(selected.CreatedAt))
		if err != nil {
			s.mu.RUnlock()
			return fmt.Errorf("translate app %s: %w", appID, err)
		}
		if s.curationPolicy != nil {
			count := endorsementCounts[selected.Declaration.Publisher+"\x00"+appID]
			app.HighQuality = count >= s.curationPolicy.MinimumEndorsements()
		}
		catalogue.Apps[appID] = app
	}
	s.mu.RUnlock()
	data, err := json.Marshal(catalogue)
	if err != nil {
		return fmt.Errorf("encode catalogue snapshot: %w", err)
	}
	_, err = output.Write(append(data, '\n'))
	return err
}

// WriteLogo writes a cached verified PNG by its YunoHost logo hash.
func (s *Store) WriteLogo(hash string, output interface{ Write([]byte) (int, error) }) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, entry := range s.entries {
		if entry.LogoHash == hash && len(entry.Logo) > 0 {
			_, _ = output.Write(entry.Logo)
			return true
		}
	}
	return false
}
