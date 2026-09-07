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
	"github.com/nbd-wtf/go-nostr/nip19"
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

// maxRevisionsPerKey bounds how many distinct-commit revisions this store
// keeps per publisher/app pair (see upsertRevision/capRevisionsLocked). Far
// more than any legitimate publisher should have pending unattested at
// once; it exists to cap memory from a publisher that republishes many
// distinct commits in a short window, not to model a real release cadence.
const maxRevisionsPerKey = 10

// upsertRevision inserts or updates incoming within revisions (all sharing
// one publisher/app key), keeping every distinct commit rather than only
// the latest - this is what lets WriteSnapshot fall back to an older,
// already-accepted revision when the newest one isn't (yet) accepted by
// the local attestation policy, instead of the newest always silently
// replacing it (docs/attestation-trust-policy-plan.md Phase 11: "do not
// let the new unverified release replace a previously trusted catalogue
// entry"). Revisions sharing a commit are still deduplicated exactly as a
// single-record store would: a same-commit re-publish only replaces the
// stored copy when strictly newer. Returned slice is sorted newest-first
// by CreatedAt. Capping to maxRevisionsPerKey is capRevisionsLocked's job,
// not this function's - trimming correctly needs attestation state this
// pure function doesn't have.
func upsertRevision(revisions []record, incoming record) []record {
	for i, existing := range revisions {
		if existing.Declaration.Commit != incoming.Declaration.Commit {
			continue
		}
		if existing.CreatedAt >= incoming.CreatedAt {
			return revisions
		}
		revisions[i] = incoming
		sort.Slice(revisions, func(a, b int) bool { return revisions[a].CreatedAt > revisions[b].CreatedAt })
		return revisions
	}
	revisions = append(revisions, incoming)
	sort.Slice(revisions, func(a, b int) bool { return revisions[a].CreatedAt > revisions[b].CreatedAt })
	return revisions
}

// capRevisionsLocked trims revisions (newest-first) to maxRevisionsPerKey,
// but never evicts a revision beyond the cutoff that the current
// attestation policy would still accept - trimming blindly by recency
// alone reopened Phase 11's exact bug through a different door: enough
// unattested republishes (more than maxRevisionsPerKey) would otherwise
// evict an already-attested older revision the store was actively relying
// on as WriteSnapshot's fallback, silently un-pinning a trusted revision
// through eviction instead of overwrite. Only the single newest such
// revision is kept (there is only ever one selectAcceptedRevisionLocked
// would currently choose), so the list can grow to at most
// maxRevisionsPerKey+1, not unbounded.
func (s *Store) capRevisionsLocked(revisions []record) []record {
	if len(revisions) <= maxRevisionsPerKey {
		return revisions
	}
	kept := revisions[:maxRevisionsPerKey]
	for _, r := range revisions[maxRevisionsPerKey:] {
		if r.Manifest == nil {
			continue
		}
		if s.attestationPolicy.Evaluate(s.attestationsForLocked(r.Declaration)).Accepted {
			kept = append(kept, r)
			break
		}
	}
	return kept
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

// Store keeps every recently accepted revision for each publisher/app pair
// (see upsertRevision) - not just the latest one, so an unattested new
// revision doesn't erase a previously accepted older one out from under
// WriteSnapshot (Phase 11).
type Store struct {
	mu sync.RWMutex
	// saveMu serializes Save's file write/rename separately from mu (which
	// only guards in-memory state and is released before the slow I/O
	// starts). Save is called from more than one goroutine in practice -
	// cmd/nostr-catalogd runs independent declaration and attestation
	// subscriptions, each saving after every accepted event - and without
	// this, two concurrent Save calls race on the same fixed temp file
	// path, risking a corrupted or silently dropped write.
	saveMu sync.Mutex
	policy trust.ExplicitPublishers
	// entries is keyed by publisher\x00appID; each value is that pair's
	// known revisions, newest-first.
	entries        map[string][]record
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
	return &Store{policy: policy, entries: make(map[string][]record)}
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
	s.entries[key] = s.capRevisionsLocked(upsertRevision(s.entries[key], record{Event: event, Declaration: declaration, CreatedAt: event.CreatedAt}))
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
	incoming := record{Event: event, Declaration: declaration, CreatedAt: event.CreatedAt, Manifest: verified.Manifest, Logo: verified.Logo, LogoHash: logoHash, Branch: verified.Branch}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = s.capRevisionsLocked(upsertRevision(s.entries[key], incoming))
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.storeAttestationLocked(event, parsed)
	return nil
}

// storeAttestationLocked applies an already-parsed attestation's dedup rule
// (a later event from the same verifier for the same revision replaces its
// earlier one) - shared by IngestAttestation and Load, which restores
// cached attestations following the same rule so a replay of an older
// cached event can never resurrect a stale attestation over one already in
// memory.
func (s *Store) storeAttestationLocked(event nostr.Event, parsed verification.Attestation) {
	key := attestationKey(parsed.Repository, parsed.Commit)
	if s.attestations == nil {
		s.attestations = make(map[string]map[string]attestationRecord)
	}
	byVerifier := s.attestations[key]
	if byVerifier == nil {
		byVerifier = make(map[string]attestationRecord)
		s.attestations[key] = byVerifier
	}
	if existing, ok := byVerifier[parsed.Verifier]; ok && existing.Event.CreatedAt >= event.CreatedAt {
		return
	}
	byVerifier[parsed.Verifier] = attestationRecord{Event: event, Attestation: parsed}
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

// TrustEntry is one accepted declaration revision's full trust picture:
// what this server has independently verified about it, what attestations
// exist for its exact revision, and what the local policy decided as a
// result. It backs the admin trust dashboard (docs/attestation-trust-policy-plan.md
// Phase 9) - one row per publisher/app/commit, not just the one revision
// WriteSnapshot ends up selecting (which may itself not be the newest
// revision - see Phase 11), so an administrator can see every retained
// revision's standing, including a newer one still waiting on attestation
// while an older one remains installable.
type TrustEntry struct {
	AppID     string `json:"app_id"`
	Publisher string `json:"publisher"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	// RepositoryVerified reports whether this server has independently
	// fetched the declared repository at Commit and confirmed the manifest
	// and content hashes match (IngestVerifiedPackage) - false for a
	// declaration accepted only via the cheaper Ingest path, which trusts
	// the signature and trust-policy check alone.
	RepositoryVerified bool `json:"repository_verified"`
	// Status is this server's own AttestationStatus classification (Phase
	// 10), independent of Policy below: Status is an objective read of the
	// evidence, Policy is what the local administrator chose to do with it.
	Status       AttestationStatus   `json:"status"`
	Attestations []SecurityAppEntry  `json:"attestations"`
	Policy       TrustPolicyDecision `json:"policy"`
}

// TrustPolicyDecision is the local policy's verdict for one TrustEntry,
// carrying enough of trust.AttestationPolicy/AttestationDecision to explain
// itself on the admin page without that page needing to re-derive it.
type TrustPolicyDecision struct {
	Mode     trust.AttestationMode `json:"mode"`
	Accepted bool                  `json:"accepted"`
	Verified bool                  `json:"verified"`
	// MinimumAttestations/RequiredChecks echo the policy's own
	// configuration (Phase 12), not anything specific to this
	// declaration, so the admin page can explain what Verified actually
	// required without a second request.
	MinimumAttestations int      `json:"minimum_attestations"`
	RequiredChecks      []string `json:"required_checks,omitempty"`
}

// TrustEntries returns every retained revision's trust picture across every
// publisher/app pair, sorted by app ID, then publisher, then newest
// revision first, for a stable admin-page render.
func (s *Store) TrustEntries() []TrustEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var entries []TrustEntry
	for _, revisions := range s.entries {
		for _, r := range revisions {
			attestations := s.attestationsForLocked(r.Declaration)
			securityEntries := make([]SecurityAppEntry, 0, len(attestations))
			for _, a := range attestations {
				securityEntries = append(securityEntries, NewSecurityAppEntry(a))
			}
			decision := s.attestationPolicy.Evaluate(attestations)
			publisher := r.Declaration.Publisher
			if npub, err := nip19.EncodePublicKey(r.Declaration.Publisher); err == nil {
				publisher = npub
			}
			entries = append(entries, TrustEntry{
				AppID:              r.Declaration.AppID,
				Publisher:          publisher,
				Version:            r.Declaration.Version,
				Commit:             r.Declaration.Commit,
				RepositoryVerified: r.Manifest != nil,
				Status:             ComputeAttestationStatus(r.Manifest != nil, attestations),
				Attestations:       securityEntries,
				Policy: TrustPolicyDecision{
					Mode:                s.attestationPolicy.Mode,
					Accepted:            decision.Accepted,
					Verified:            decision.Verified,
					MinimumAttestations: s.attestationPolicy.EffectiveMinimumAttestations(),
					RequiredChecks:      s.attestationPolicy.RequiredChecks,
				},
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].AppID != entries[j].AppID {
			return entries[i].AppID < entries[j].AppID
		}
		if entries[i].Publisher != entries[j].Publisher {
			return entries[i].Publisher < entries[j].Publisher
		}
		return entries[i].Commit < entries[j].Commit
	})
	return entries
}

type cacheFile struct {
	Entries []record `json:"entries"`
	// Attestations persists every stored kind-30080 event, flattened from
	// Store.attestations, so a restart doesn't lose them - see Load's
	// comment on why this matters under AttestationRequire.
	Attestations []nostr.Event `json:"attestations,omitempty"`
}

// Save persists every retained revision and every stored attestation to a
// local JSON cache, flattened from Store.entries's per-key revision lists
// and Store.attestations's per-revision/per-verifier maps respectively. The
// write is atomic within the target directory.
func (s *Store) Save(path string) error {
	s.mu.RLock()
	var entries []record
	for _, revisions := range s.entries {
		entries = append(entries, revisions...)
	}
	var attestationEvents []nostr.Event
	for _, byVerifier := range s.attestations {
		for _, a := range byVerifier {
			attestationEvents = append(attestationEvents, a.Event)
		}
	}
	s.mu.RUnlock()
	data, err := json.Marshal(cacheFile{Entries: entries, Attestations: attestationEvents})
	if err != nil {
		return fmt.Errorf("encode catalogue cache: %w", err)
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
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
// current cryptographic and trust policy, reconstructing each
// publisher/app pair's full revision list (not just its newest revision) -
// Phase 11's fallback depends on older revisions surviving a restart, not
// only the current cache format's ability to round-trip one. It also
// restores every cached attestation: without this, a restart under
// AttestationRequire would transiently exclude every previously attested
// package until relays resent their attestations, which is exactly the
// kind of gap Phase 11's revision fallback cannot paper over by itself -
// the fallback still needs *some* accepted revision to fall back to.
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
	// Attestations are restored before declarations, deliberately: entries'
	// loop below runs each incoming revision through capRevisionsLocked,
	// which needs s.attestations already populated to correctly identify
	// (and protect from eviction) whichever revision the attestation
	// policy currently accepts. Loading them in the other order would
	// evaluate every revision as unattested and could re-evict on load the
	// very revision capRevisionsLocked was protecting when the cache was
	// written.
	for _, event := range cached.Attestations {
		parsed, err := verification.Parse(event)
		if err != nil {
			continue
		}
		// Load, like the rest of its own writes to s.entries below, runs
		// without s.mu - callers load a store before any concurrent access
		// begins (see cmd/nostr-catalogd/main.go).
		s.storeAttestationLocked(event, parsed)
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
		incoming := record{Event: entry.Event, Declaration: declaration, CreatedAt: entry.Event.CreatedAt, Manifest: entry.Manifest, Logo: entry.Logo, LogoHash: entry.LogoHash, Branch: branch}
		s.entries[key] = s.capRevisionsLocked(upsertRevision(s.entries[key], incoming))
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

// Snapshot returns the newest known revision's declaration for every
// publisher/app pair, in stable publisher/app order - the newest, not
// necessarily the one WriteSnapshot currently offers for install (Phase
// 11), since this reflects what's been declared, independent of local
// attestation policy.
func (s *Store) Snapshot() []protocol.AppDeclaration {
	s.mu.RLock()
	declarations := make([]protocol.AppDeclaration, 0, len(s.entries))
	for _, revisions := range s.entries {
		if len(revisions) == 0 {
			continue
		}
		declarations = append(declarations, revisions[0].Declaration)
	}
	s.mu.RUnlock()
	sort.Slice(declarations, func(i, j int) bool {
		left := declarations[i].Publisher + "\x00" + declarations[i].AppID
		right := declarations[j].Publisher + "\x00" + declarations[j].AppID
		return left < right
	})
	return declarations
}

// selectAcceptedRevisionLocked picks the newest revision (revisions is
// newest-first) that is both repository-verified (Manifest != nil) and
// accepted by the local attestation policy for its own exact commit's
// attestations. ok is false when no revision qualifies - including when
// revisions is empty, or every revision is either unverified or rejected
// by policy - matching the pre-Phase-11 behavior of simply having nothing
// to offer for that publisher/app pair.
func (s *Store) selectAcceptedRevisionLocked(revisions []record) (record, bool) {
	for _, r := range revisions {
		if r.Manifest == nil {
			continue
		}
		if s.attestationPolicy.Evaluate(s.attestationsForLocked(r.Declaration)).Accepted {
			return r, true
		}
	}
	return record{}, false
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
			Apps:    map[string][]SecurityAppEntry{},
			System:  map[string][]any{},
		},
	}
	// Phase 11: for each publisher/app pair, pick the newest revision that
	// is both repository-verified and accepted by the local attestation
	// policy, falling back to an older one rather than to nothing when the
	// newest revision isn't (yet) accepted - "do not let the new
	// unverified release replace a previously trusted catalogue entry."
	// Off/Prefer always accept, so this reduces to "pick the newest
	// verified revision" under those modes, exactly the old behavior.
	byAppID := make(map[string][]record)
	for _, revisions := range s.entries {
		selected, ok := s.selectAcceptedRevisionLocked(revisions)
		if !ok {
			continue
		}
		byAppID[selected.Declaration.AppID] = append(byAppID[selected.Declaration.AppID], selected)
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
		// selected is already policy-accepted (selectAcceptedRevisionLocked
		// above); attestations is recomputed here only to populate the
		// security index and HighQuality below, not to gate inclusion
		// again.
		attestations := s.attestationsForLocked(selected.Declaration)
		app, err := TranslateWithBranch(selected.Declaration, selected.Manifest, selected.LogoHash, selected.Branch, int64(selected.CreatedAt))
		if err != nil {
			s.mu.RUnlock()
			return fmt.Errorf("translate app %s: %w", appID, err)
		}
		if s.curationPolicy != nil {
			count := endorsementCounts[selected.Declaration.Publisher+"\x00"+appID]
			app.HighQuality = count >= s.curationPolicy.MinimumEndorsements()
		}
		// Phase 10: CI-verified attestation status is a second, independent
		// route to HighQuality alongside curator endorsements above - a
		// genuine equivalent for YunoHost's "meets an elevated quality bar"
		// field, not a repurposing of Level (see TranslateWithBranch's
		// comment on why Level itself stays untouched by any of this).
		status := ComputeAttestationStatus(selected.Manifest != nil, attestations)
		if status == StatusCIVerified || status == StatusMultiVerified {
			app.HighQuality = true
		}
		catalogue.Apps[appID] = app
		// Phase 8: every attestation matching this exact revision becomes
		// its own security-index entry - deliberately not collapsed into
		// one summary judgment, since a failing check is exactly what an
		// administrator (or the future admin UI, Phase 9) needs visible,
		// not just whichever attestation happened to pass.
		if len(attestations) > 0 {
			entries := make([]SecurityAppEntry, 0, len(attestations))
			for _, a := range attestations {
				entries = append(entries, NewSecurityAppEntry(a))
			}
			catalogue.Security.Apps[appID] = entries
		}
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
	for _, revisions := range s.entries {
		for _, entry := range revisions {
			if entry.LogoHash == hash && len(entry.Logo) > 0 {
				_, _ = output.Write(entry.Logo)
				return true
			}
		}
	}
	return false
}
