package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/nostr-yunohost/nostr-yunohost/internal/catalog"
	"github.com/nostr-yunohost/nostr-yunohost/internal/relay"
	"github.com/nostr-yunohost/nostr-yunohost/internal/repository"
	"github.com/nostr-yunohost/nostr-yunohost/internal/trust"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8090", "HTTP listen address")
	cachePath := flag.String("cache", "catalogue-cache.json", "local catalogue cache path")
	relayList := flag.String("relays", os.Getenv("NOSTR_YNH_RELAYS"), "comma-separated relay URLs")
	trustedList := flag.String("trusted-publishers", os.Getenv("NOSTR_YNH_TRUSTED_PUBLISHERS"), "comma-separated publisher hex keys or npubs")
	flag.Parse()
	relays := splitNonEmpty(*relayList)
	trustedPublishers := splitNonEmpty(*trustedList)
	policy, err := trust.NewExplicitPublishers(trustedPublishers)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client, err := relay.New(ctx, relays)
	if err != nil {
		log.Fatal(err)
	}
	store := catalog.NewStore(policy)
	if err := store.Load(*cachePath); err != nil {
		log.Printf("load catalogue cache: %v", err)
	}
	go func() {
		for received := range client.SubscribeAppDeclarations(ctx) {
			if err := store.IngestVerified(ctx, *received.Event, repository.VerifyDeclaration); err != nil {
				log.Printf("reject event %s: %v", received.ID, err)
				continue
			}
			if err := store.Save(*cachePath); err != nil {
				log.Printf("save catalogue cache: %v", err)
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/v3/apps.json", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if err := store.WriteSnapshot(response); err != nil {
			log.Printf("write catalogue: %v", err)
		}
	})
	server := &http.Server{Addr: *listen, Handler: mux}
	go func() {
		<-ctx.Done()
		_ = server.Shutdown(context.Background())
	}()
	log.Printf("nostr-catalogd listening on %s", *listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func splitNonEmpty(raw string) []string {
	var values []string
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}
