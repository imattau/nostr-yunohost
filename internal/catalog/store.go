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
	"sync"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
	"github.com/nostr-yunohost/nostr-yunohost/internal/trust"
)

type record struct {
	Event       nostr.Event
	Declaration protocol.AppDeclaration
	CreatedAt   nostr.Timestamp
	Manifest    map[string]any
}

// Store keeps the latest accepted declaration for each publisher/app pair.
type Store struct {
	mu      sync.RWMutex
	policy  trust.ExplicitPublishers
	entries map[string]record
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
	declaration, err := s.policy.Validate(event)
	if err != nil {
		return err
	}
	manifest, err := verify(ctx, declaration)
	if err != nil {
		return fmt.Errorf("verify repository: %w", err)
	}
	if _, err := Translate(declaration, manifest, int64(event.CreatedAt)); err != nil {
		return fmt.Errorf("translate catalogue entry: %w", err)
	}
	key := declaration.Publisher + "\x00" + declaration.AppID
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.entries[key]; ok && current.CreatedAt >= event.CreatedAt {
		return nil
	}
	s.entries[key] = record{Event: event, Declaration: declaration, CreatedAt: event.CreatedAt, Manifest: manifest}
	return nil
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
		if _, err := Translate(declaration, entry.Manifest, int64(entry.Event.CreatedAt)); err != nil {
			continue
		}
		key := declaration.Publisher + "\x00" + declaration.AppID
		s.entries[key] = record{Event: entry.Event, Declaration: declaration, CreatedAt: entry.Event.CreatedAt, Manifest: entry.Manifest}
	}
	return nil
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
		Security:     []any{},
	}
	publishersByID := make(map[string]string)
	collisions := make(map[string]struct{})
	for _, entry := range s.entries {
		if entry.Manifest == nil {
			continue
		}
		appID := entry.Declaration.AppID
		if publisher, ok := publishersByID[appID]; ok && publisher != entry.Declaration.Publisher {
			collisions[appID] = struct{}{}
			delete(catalogue.Apps, appID)
			continue
		}
		publishersByID[appID] = entry.Declaration.Publisher
		if _, collision := collisions[appID]; collision {
			continue
		}
		app, err := Translate(entry.Declaration, entry.Manifest, int64(entry.CreatedAt))
		if err != nil {
			s.mu.RUnlock()
			return fmt.Errorf("translate app %s: %w", entry.Declaration.AppID, err)
		}
		catalogue.Apps[entry.Declaration.AppID] = app
	}
	s.mu.RUnlock()
	data, err := json.Marshal(catalogue)
	if err != nil {
		return fmt.Errorf("encode catalogue snapshot: %w", err)
	}
	_, err = output.Write(append(data, '\n'))
	return err
}
