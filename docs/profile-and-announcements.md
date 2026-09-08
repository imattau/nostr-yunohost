# Publisher profile and announcement notes

App declarations (kind 30078), endorsements (kind 30079), and attestations
(kind 30080) are all parameterised replaceable events. Ordinary Nostr social
clients (Damus, Amethyst, ...) have no renderer for any of them, so a
publisher key that only ever signs these looks like an opaque hex string
with no visible activity - not something a person could follow.

This doc covers two additions that make the publisher key behave like a
normal Nostr account, both built with `internal/publisher` alongside
`BuildDeclaration`:

- a kind-0 profile, so the key resolves to a name/picture instead of hex;
- a kind-1 text note per real release, so updates show up in a feed.

Neither changes how `nostr-catalogd` ingests or trusts declarations - both
are purely for human/client-facing visibility and are optional.

## Profile (kind 0)

Standard NIP-01 profile metadata, published once and re-published whenever
the publisher wants to change it. Kind 0 is replaceable by `(kind, pubkey)`
alone, so there is no address/`d` tag to manage - publishing again simply
supersedes the previous profile for any client or relay that already has it.

Content is the standard JSON object:

```json
{
  "name": "Example Publisher",
  "about": "Publishes YunoHost packages",
  "picture": "https://example.org/icon.png",
  "nip05": "publisher@example.org",
  "website": "https://example.org"
}
```

All fields are optional; empty fields are omitted rather than sent as empty
strings. `internal/publisher.BuildProfile` builds and signs this event.

```bash
nostr-ynh profile \
  --name "Example Publisher" --about "Publishes YunoHost packages" \
  --picture https://example.org/icon.png --nip05 publisher@example.org \
  --private-key-file publisher.key \
  --relays wss://relay.example
```

This is a one-off setup step (and again whenever the profile changes), not
part of the regular release flow - unlike `publish --announce` below, it has
no place in a per-release CI workflow. `--dry-run` builds and signs the
event, printing its JSON and `nprofile`, without connecting to a relay, the
same pattern `nostr-ynh publish --dry-run` uses.

## Announcement notes (kind 1)

An ordinary text note posted alongside a real app declaration update, tagged
back to the declaration it accompanies rather than duplicating its data:

| Tag | Meaning |
| --- | --- |
| `a` | `30078:<publisher pubkey>:<app_id>`, the declaration's own address |
| `r` | Canonical Git repository URL, matching the declaration's `repo` tag |

Content is a short human-readable line, not machine-readable data - the
declaration remains the source of truth for anything a catalogue daemon
needs to parse:

```text
📦 Immich 1.2.3~ynh1 published
https://github.com/example/immich_ynh@abc1234
nostr:naddr1...
```

`internal/publisher.BuildAnnouncement` builds this from an already-signed
declaration event (deriving `app_id`/`version`/`commit`/address from its
tags, so the note can never disagree with what was actually declared) and
refuses to sign a note for a declaration signed by a different key, or for
an event that isn't a kind-30078 declaration at all.

### Publishing announcements

`nostr-ynh publish --announce` builds and publishes an announcement note
alongside the declaration (and the attestation, if `--ci-result` is also
given), signed with the same key. It is opt-in per invocation - not every
`publish` call (a CI re-run, a manual re-publish of unchanged metadata)
should necessarily post a public note.

Dedup is not left to the caller to get right: `--announce` is backed by a
local ledger (`internal/announce`, `--announcement-ledger`/
`NOSTR_YNH_ANNOUNCEMENT_LEDGER`) keyed by `(app_id, commit)`, the same
already-published-once pattern `internal/attestation.Ledger` uses for
self-attestations. Re-running `publish --announce` against a commit already
announced by this key is a silent no-op for the note (the declaration itself
is still published/replaced as normal) rather than a duplicate post - so
`--announce` can be left on for every CI publish without worrying about
double-posting on a re-run.

## Non-goals

Neither event is consumed by `nostr-catalogd`'s ingestion path. The
catalogue's trust and version-selection logic (`docs/event-schema.md`,
`docs/attestations.md`) is unaffected by whether a publisher has a profile
or posts announcements - these are purely for the account's visibility in
general-purpose Nostr clients and on the admin dashboard's own history view.
