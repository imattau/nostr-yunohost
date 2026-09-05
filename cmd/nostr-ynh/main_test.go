package main

import (
	"bytes"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
)

// startBlackholeRelay starts a relay that completes the WebSocket handshake
// (so EnsureRelay's own internal connect timeout never applies) and reads
// the subscription request, but never answers it - no events, no EOSE,
// ever. This is the shape of relay that previously hung every relay-pool
// operation forever: reachable and responsive at the connection level, just
// never finishing what it was asked to do.
func startBlackholeRelay(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			// Read the subscription request, then go silent forever.
			_, _, _ = conn.Read(r.Context())
			<-r.Context().Done()
		}),
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return "ws://" + listener.Addr().String()
}

func TestRunCatalogRespectsTimeoutAgainstAHungRelay(t *testing.T) {
	relayURL := startBlackholeRelay(t)
	var stdout, stderr bytes.Buffer

	start := time.Now()
	runCatalog([]string{"--relays", relayURL, "--timeout-seconds", "1"}, &stdout, &stderr)
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Fatalf("runCatalog blocked for %s against an unresponsive relay; want it bounded by --timeout-seconds (1s)", elapsed)
	}
}

func TestRunInspectRespectsTimeoutAgainstAHungRelay(t *testing.T) {
	relayURL := startBlackholeRelay(t)
	naddr, err := nip19.EncodeEntity(strings.Repeat("ab", 32), protocol.AppDeclarationKind, "example-app", nil)
	if err != nil {
		t.Fatalf("encode naddr: %v", err)
	}
	var stdout, stderr bytes.Buffer

	start := time.Now()
	runInspect([]string{"--relays", relayURL, "--timeout-seconds", "1", naddr}, &stdout, &stderr)
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Fatalf("runInspect blocked for %s against an unresponsive relay; want it bounded by --timeout-seconds (1s)", elapsed)
	}
}
