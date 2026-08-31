// Package catalog stores validated current app declarations and exposes a
// deterministic snapshot for the YunoHost translation layer.
package catalog

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
	"github.com/nostr-yunohost/nostr-yunohost/internal/trust"
)

type record struct {
	Declaration protocol.AppDeclaration
	CreatedAt   nostr.Timestamp
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
	s.entries[key] = record{Declaration: declaration, CreatedAt: event.CreatedAt}
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

// WriteSnapshot writes the current intermediate catalogue representation.
// The final YunoHost field mapping belongs in a separate adapter once a
// target-version /v3/apps.json fixture is available.
func (s *Store) WriteSnapshot(output interface{ Write([]byte) (int, error) }) error {
	data, err := json.Marshal(s.Snapshot())
	if err != nil {
		return fmt.Errorf("encode catalogue snapshot: %w", err)
	}
	_, err = output.Write(append(data, '\n'))
	return err
}
