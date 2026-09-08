// Package announce tracks which app revisions a publisher key has already
// posted a kind-1 announcement note for, so `nostr-ynh publish --announce`
// can be left on for every CI run without re-posting a note for a commit
// that was already announced. See docs/profile-and-announcements.md.
package announce

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Record is one announcement this key has published, kept both for the
// dedup check and for the admin page's history view.
type Record struct {
	AppID        string `json:"app_id"`
	Commit       string `json:"commit"`
	Version      string `json:"version"`
	AnnouncedAt  int64  `json:"announced_at"`
	EventID      string `json:"event_id,omitempty"`
	NaddrPointer string `json:"address,omitempty"`
}

// Ledger records which (app_id, commit) pairs this key has already
// announced. The zero value is an empty, unpersisted ledger.
type Ledger struct {
	mu      sync.Mutex
	path    string
	records []Record
}

// LoadLedger reads a ledger from path. A missing file starts an empty
// ledger, matching attestation.LoadLedger's behaviour.
func LoadLedger(path string) (*Ledger, error) {
	ledger := &Ledger{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ledger, nil
		}
		return nil, fmt.Errorf("read announcement ledger: %w", err)
	}
	if err := json.Unmarshal(data, &ledger.records); err != nil {
		return nil, fmt.Errorf("decode announcement ledger: %w", err)
	}
	return ledger, nil
}

// HasAnnounced reports whether this key has already published an
// announcement for this exact app/commit pair. A new commit for the same
// app always re-surfaces as unannounced, regardless of how many older
// commits were already announced.
func (l *Ledger) HasAnnounced(appID, commit string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, record := range l.records {
		if record.AppID == appID && record.Commit == commit {
			return true
		}
	}
	return false
}

// History returns every announcement this key has published, most recent
// first.
func (l *Ledger) History() []Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	history := make([]Record, len(l.records))
	copy(history, l.records)
	sort.Slice(history, func(i, j int) bool { return history[i].AnnouncedAt > history[j].AnnouncedAt })
	return history
}

// Record marks an app/commit pair as announced and persists the ledger
// atomically, mirroring attestation.Ledger.Record's write pattern. Calling
// it again for a pair already recorded is a no-op - the ledger only ever
// grows, one entry per distinct (app_id, commit).
func (l *Ledger) Record(appID, commit, version, eventID, address string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, record := range l.records {
		if record.AppID == appID && record.Commit == commit {
			return nil
		}
	}
	l.records = append(l.records, Record{
		AppID:        appID,
		Commit:       commit,
		Version:      version,
		AnnouncedAt:  time.Now().Unix(),
		EventID:      eventID,
		NaddrPointer: address,
	})
	data, err := json.Marshal(l.records)
	if err != nil {
		return fmt.Errorf("encode announcement ledger: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o750); err != nil {
		return fmt.Errorf("create announcement ledger directory: %w", err)
	}
	temporaryPath := l.path + ".tmp"
	if err := os.WriteFile(temporaryPath, append(data, '\n'), 0o640); err != nil {
		return fmt.Errorf("write announcement ledger: %w", err)
	}
	return os.Rename(temporaryPath, l.path)
}
