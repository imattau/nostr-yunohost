package announce

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLedgerRecordAndHasAnnounced(t *testing.T) {
	ledger, err := LoadLedger(filepath.Join(t.TempDir(), "announcements.json"))
	if err != nil {
		t.Fatal(err)
	}
	if ledger.HasAnnounced("hello_nostr", "abc123") {
		t.Fatal("HasAnnounced() true before any Record")
	}
	if err := ledger.Record("hello_nostr", "abc123", "1.0.0~ynh1", "eventid", "naddr1..."); err != nil {
		t.Fatal(err)
	}
	if !ledger.HasAnnounced("hello_nostr", "abc123") {
		t.Fatal("HasAnnounced() false after Record")
	}
	if ledger.HasAnnounced("hello_nostr", "def456") {
		t.Fatal("HasAnnounced() true for a different commit of the same app")
	}
	if ledger.HasAnnounced("other_app", "abc123") {
		t.Fatal("HasAnnounced() true for a different app with the same commit")
	}
}

func TestLedgerRecordIsIdempotent(t *testing.T) {
	ledger, err := LoadLedger(filepath.Join(t.TempDir(), "announcements.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Record("hello_nostr", "abc123", "1.0.0~ynh1", "event1", "naddr1..."); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Record("hello_nostr", "abc123", "1.0.0~ynh1", "event2", "naddr2..."); err != nil {
		t.Fatal(err)
	}
	if len(ledger.History()) != 1 {
		t.Fatalf("History() = %d entries, want 1 after a duplicate Record", len(ledger.History()))
	}
}

func TestLedgerPersistsAcrossLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "announcements.json")
	first, err := LoadLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Record("hello_nostr", "abc123", "1.0.0~ynh1", "eventid", "naddr1..."); err != nil {
		t.Fatal(err)
	}
	second, err := LoadLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if !second.HasAnnounced("hello_nostr", "abc123") {
		t.Fatal("a freshly loaded ledger did not see the previously recorded announcement")
	}
}

func TestLedgerHistoryOrdersMostRecentFirst(t *testing.T) {
	ledger, err := LoadLedger(filepath.Join(t.TempDir(), "announcements.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Record("app_a", "commit-a", "1.0.0", "event-a", "naddr-a"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // AnnouncedAt has second resolution
	if err := ledger.Record("app_b", "commit-b", "2.0.0", "event-b", "naddr-b"); err != nil {
		t.Fatal(err)
	}
	history := ledger.History()
	if len(history) != 2 {
		t.Fatalf("History() = %d entries, want 2", len(history))
	}
	if history[0].AppID != "app_b" || history[1].AppID != "app_a" {
		t.Fatalf("History() not ordered most-recent-first: %+v", history)
	}
}

func TestLoadLedgerMissingFileIsEmpty(t *testing.T) {
	ledger, err := LoadLedger(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.History()) != 0 {
		t.Fatal("LoadLedger() on a missing file returned a non-empty ledger")
	}
}
