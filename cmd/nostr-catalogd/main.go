package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/nostr-yunohost/nostr-yunohost/internal/catalog"
	"github.com/nostr-yunohost/nostr-yunohost/internal/curation"
	"github.com/nostr-yunohost/nostr-yunohost/internal/relay"
	"github.com/nostr-yunohost/nostr-yunohost/internal/repository"
	"github.com/nostr-yunohost/nostr-yunohost/internal/trust"
)

var version = "dev"

func main() {
	versionFlag := flag.Bool("version", false, "print version")
	listen := flag.String("listen", "127.0.0.1:8090", "HTTP listen address")
	cachePath := flag.String("cache", "catalogue-cache.json", "local catalogue cache path")
	relayList := flag.String("relays", os.Getenv("NOSTR_YNH_RELAYS"), "comma-separated relay URLs")
	trustedList := flag.String("trusted-publishers", os.Getenv("NOSTR_YNH_TRUSTED_PUBLISHERS"), "comma-separated publisher hex keys or npubs")
	trustedCurators := flag.String("trusted-curators", os.Getenv("NOSTR_YNH_TRUSTED_CURATORS"), "comma-separated curator hex keys or npubs")
	minimumEndorsements := flag.Int("minimum-endorsements", defaultMinimumEndorsements(), "minimum trusted endorsements for canonical selection")
	flag.Parse()
	if *versionFlag {
		fmt.Println(version)
		return
	}
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
	if curatorKeys := splitNonEmpty(*trustedCurators); len(curatorKeys) > 0 {
		curationPolicy, err := curation.NewPolicy(curatorKeys, *minimumEndorsements)
		if err != nil {
			log.Fatal(err)
		}
		store.SetCurationPolicy(curationPolicy)
	}
	if err := store.Load(*cachePath); err != nil {
		log.Printf("load catalogue cache: %v", err)
	}
	for _, event := range client.FetchAppDeclarations(ctx, policy.Publishers()) {
		if err := store.IngestVerified(ctx, *event, repository.VerifyDeclaration); err != nil {
			log.Printf("reject event %s: %v", event.ID, err)
			continue
		}
		if err := store.Save(*cachePath); err != nil {
			log.Printf("save catalogue: %v", err)
		}
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
	if len(splitNonEmpty(*trustedCurators)) > 0 {
		go func() {
			for received := range client.SubscribeEndorsements(ctx) {
				if err := store.IngestEndorsement(*received.Event); err != nil {
					log.Printf("reject endorsement %s: %v", received.ID, err)
				}
			}
		}()
	}

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

func defaultMinimumEndorsements() int {
	raw := strings.TrimSpace(os.Getenv("NOSTR_YNH_MINIMUM_ENDORSEMENTS"))
	if raw == "" {
		return 1
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		log.Printf("invalid NOSTR_YNH_MINIMUM_ENDORSEMENTS=%q; using 1", raw)
		return 1
	}
	return value
}
