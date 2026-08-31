// Package relay adapts the Go Nostr SDK to the catalogue's small relay
// interface.
package relay

import (
	"context"
	"fmt"
	"net/url"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
)

// Client publishes and subscribes through a configured set of relays.
type Client struct {
	pool *nostr.SimplePool
	urls []string
}

// New validates relay URLs and creates a multi-relay client. The SDK owns
// connection management, reconnects, deduplication, and relay backoff.
func New(ctx context.Context, relayURLs []string) (*Client, error) {
	if len(relayURLs) == 0 {
		return nil, fmt.Errorf("at least one relay is required")
	}
	urls := make([]string, 0, len(relayURLs))
	seen := make(map[string]struct{}, len(relayURLs))
	for _, raw := range relayURLs {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "wss" && u.Scheme != "ws") || u.Host == "" {
			return nil, fmt.Errorf("invalid relay URL %q: expected ws:// or wss://", raw)
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		urls = append(urls, raw)
	}
	return &Client{
		pool: nostr.NewSimplePool(ctx, nostr.WithPenaltyBox()),
		urls: urls,
	}, nil
}

// PublishResult records one relay's result for a published event.
type PublishResult struct {
	Relay string
	Error error
}

// FetchReplaceable retrieves the latest declaration for a publisher/app pair
// using the SDK's replaceable-event handling.
func (c *Client) FetchReplaceable(ctx context.Context, publisher, appID string) (*nostr.Event, error) {
	results := c.pool.FetchManyReplaceable(ctx, c.urls, nostr.Filter{
		Kinds:   []int{protocol.AppDeclarationKind},
		Authors: []string{publisher},
		Tags:    nostr.TagMap{"d": {appID}},
	})
	event, ok := results.Load(nostr.ReplaceableKey{PubKey: publisher, D: appID})
	if !ok {
		return nil, fmt.Errorf("app declaration not found")
	}
	return event, nil
}

// FetchAppDeclarations fetches the latest declaration per publisher/app pair.
func (c *Client) FetchAppDeclarations(ctx context.Context) []*nostr.Event {
	results := c.pool.FetchManyReplaceable(ctx, c.urls, nostr.Filter{
		Kinds: []int{protocol.AppDeclarationKind},
		Tags:  nostr.TagMap{"platform": {"yunohost"}},
	})
	events := make([]*nostr.Event, 0)
	results.Range(func(_ nostr.ReplaceableKey, event *nostr.Event) bool {
		events = append(events, event)
		return true
	})
	return events
}

// Publish sends an already signed event to every configured relay. A partial
// failure is returned as per-relay results so callers can report propagation
// without discarding successful publications.
func (c *Client) Publish(ctx context.Context, event nostr.Event) []PublishResult {
	results := make([]PublishResult, 0, len(c.urls))
	for result := range c.pool.PublishMany(ctx, c.urls, event) {
		results = append(results, PublishResult{Relay: result.RelayURL, Error: result.Error})
	}
	return results
}

// SubscribeAppDeclarations streams app declaration events from all configured
// relays until ctx is canceled. Duplicate and replaceable-event handling is
// provided by the SDK's pool.
func (c *Client) SubscribeAppDeclarations(ctx context.Context) <-chan nostr.RelayEvent {
	return c.pool.SubscribeMany(ctx, c.urls, nostr.Filter{
		Kinds: []int{protocol.AppDeclarationKind},
		Tags:  nostr.TagMap{"platform": {"yunohost"}},
	})
}

// SubscribeEndorsements streams curator endorsement events from all relays.
func (c *Client) SubscribeEndorsements(ctx context.Context) <-chan nostr.RelayEvent {
	return c.pool.SubscribeMany(ctx, c.urls, nostr.Filter{Kinds: []int{30079}})
}
