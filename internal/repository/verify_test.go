package repository

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/imattau/nostr-yunohost/internal/protocol"
	"github.com/imattau/nostr-yunohost/internal/publisher"
)

func TestVerifyCheckedOutDirectory(t *testing.T) {
	directory := t.TempDir()
	manifest := []byte("id = \"hello_nostr\"\nversion = \"1.0.0~ynh1\"\n")
	if err := os.WriteFile(filepath.Join(directory, "manifest.toml"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init"}, {"config", "user.email", "test@example.invalid"}, {"config", "user.name", "Test"}, {"add", "manifest.toml"}, {"commit", "-m", "test"}} {
		if _, err := gitCommand(directory, args...); err != nil {
			t.Fatal(err)
		}
	}
	commit, err := gitOutput(directory, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	archive, err := gitCommandContext(context.Background(), directory, "archive", "--format=tar", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	declaration := protocol.AppDeclaration{AppID: "hello_nostr", Version: "1.0.0~ynh1", Commit: commit, ManifestHash: publisher.HashBytes(manifest), ContentHash: publisher.HashBytes(archive)}
	parsed, err := verifyCheckedOutDirectory(context.Background(), directory, declaration)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Manifest["id"] != "hello_nostr" {
		t.Fatalf("unexpected manifest: %+v", parsed)
	}
}

// TestVerifyDeclarationRespectsContextDeadlineAgainstAHungHost is a
// regression test: VerifyDeclaration clones the declared repository over the
// network, and a catalog listing calls it once per declared app across every
// publisher - a single unreachable or hung git host must not block
// verification of every other declaration forever. gitCommandContext runs
// git via exec.CommandContext, so a canceled ctx must actually kill the
// subprocess, not just be ignored.
func TestVerifyDeclarationRespectsContextDeadlineAgainstAHungHost(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			// Accept the TCP connection but never speak the git protocol -
			// git's client blocks reading the handshake response forever.
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()

	repositoryURL := fmt.Sprintf("git://%s/unreachable.git", listener.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	start := time.Now()
	_, err = VerifyDeclaration(ctx, protocol.AppDeclaration{Repository: repositoryURL, Commit: "deadbeef"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error verifying an unreachable repository")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("VerifyDeclaration blocked for %s against a hung git host; want it bounded by the 1s context deadline", elapsed)
	}
}
