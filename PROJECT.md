# Nostr-backed YunoHost App Catalogue

## Project goal

Build a decentralised YunoHost application catalogue in which:

- YunoHost apps remain normal YunoHost packages.
- Publishers announce apps and releases over Nostr.
- YunoHost discovers applications through its existing custom catalogue mechanism.
- Installation, upgrades, Webadmin, and app lifecycle management remain standard YunoHost operations.
- Trust is based on signed publisher identities and configurable local curation.

The project replaces only the centralised discovery and publication layer. It does not replace YunoHost packaging or installation.

```text
Developer → foo_ynh repository → signed Nostr event → relays
         → nostr-yunohost catalogue service → /v3/apps.json
         → YunoHost custom catalogue → normal Webadmin install/upgrade
```

## Design principles

1. Keep the Nostr protocol thin. Nostr describes publisher identity, app identity, source location, advertised version/revision, integrity data, and optional catalogue metadata.
2. Keep the YunoHost repository authoritative for `manifest.toml`, `scripts/`, `conf/`, `doc/`, and `tests/`.
3. Keep installation completely standard. Nostr never executes application code.
4. Separate publisher identity, curator identity, and local administrator policy.
5. Use multiple relays and a local cache so relay outages do not break Webadmin catalogue access.
6. Treat `publisher pubkey + app ID` as the logical application identity; display names are not globally unique.

## Architecture

### Publisher workflow

Developers continue maintaining an ordinary YunoHost package:

```text
foo_ynh/
├── manifest.toml
├── scripts/
├── conf/
├── doc/
└── tests/
```

The initial CLI will support:

```bash
nostr-ynh publish .
nostr-ynh inspect <naddr>
nostr-ynh verify <naddr>
nostr-ynh search <term>
nostr-ynh catalog
```

`publish` reads the manifest, determines repository and Git revision information, calculates integrity hashes, signs one event, and publishes it to configured relays.

### Nostr protocol MVP

Use one parameterised replaceable event for the current application declaration. The exact kind is to be allocated/documented during Phase 0; conceptually it contains:

```json
{
  "kind": 30xxx,
  "tags": [
    ["d", "immich"],
    ["platform", "yunohost"],
    ["repo", "https://github.com/example/immich_ynh"],
    ["version", "1.2.3~ynh2"],
    ["commit", "abc123"],
    ["manifest", "sha256:..."],
    ["category", "multimedia"]
  ],
  "content": "{...}"
}
```

The declaration may include app ID, name, current version, commit/tag, manifest hash, packaging version, supported architectures, category, description, homepage, licence, icon/screenshots, and support/source URLs.

Historical release events, endorsement events, key rotation/delegation, and CI attestations are intentionally deferred until the MVP proves useful.

### Catalogue daemon

`nostr-yunohost-catalogd` will:

```text
subscribe → validate events → apply trust policy → deduplicate
          → validate repository metadata → cache locally
          → generate YunoHost-compatible /v3/apps.json
```

It must not install software. Before accepting an entry, it should fetch the declared repository at the declared commit and verify the declared manifest/content hash. Failed verification excludes the entry from `apps.json`.

### YunoHost wrapper

`nostr_catalog_ynh` will package and configure the daemon as a normal YunoHost app. It will configure relays and trust policy, register a local custom catalogue such as `http://127.0.0.1:PORT/v3/apps.json`, and expose settings through the YunoHost app configuration panel.

## Trust model

A valid signature proves only that a key published information. It does not prove that software is safe.

```text
publisher identity → signed declaration → optional curation/endorsement → local admin policy
```

Trust policy levels should be implemented progressively:

1. Explicit trusted publishers — the MVP default.
2. Trusted curators and endorsement events.
3. Threshold policies, such as two endorsements.
4. Web of trust — future work only.

The first release should default to curated or explicitly trusted publishers rather than unrestricted discovery. Key rotation should eventually use a signed delegation or migration event.

## Configuration

The initial configuration model should cover:

- Multiple relay URLs.
- Trust mode: curated, trusted publishers, web of trust, or everything.
- Trusted publisher npubs.
- Trusted curator npubs.
- Minimum endorsement count when curation is enabled.
- Whether experimental apps are included.
- Refresh interval.

## Security boundaries and threats

Document and test at least: malicious publishers, compromised publisher or curator keys, malicious or modified repositories, relay censorship/disappearance, spam, naming collisions, replayed old versions, downgrade attacks, fake canonical apps, dependency substitution, and compromised GitHub Action signing secrets.

The primary MVP controls are signed events, pinned Git commits, manifest/content hashes, local trust policy, normal YunoHost validation, and a dedicated publication key rather than a developer's primary Nostr key.

## Repository layout

The main repository should separate protocol/library concerns from the YunoHost wrapper:

```text
nostr-yunohost/
├── cmd/
│   ├── nostr-ynh/
│   └── nostr-catalogd/
├── internal/
│   ├── nostr/
│   ├── catalog/
│   ├── trust/
│   ├── yunohost/
│   └── git/
├── docs/
├── examples/
└── tests/
```

The packaging repository remains separate:

```text
nostr_catalog_ynh/
```

Shared primitives with `npack` should be identified after the YunoHost implementation works: software declaration, release, artefact, publisher, attestation, endorsement, repository, platform, architecture, and dependency metadata.

## Development roadmap

### Phase 0 — protocol and compatibility

- Document the event schema and event kind strategy.
- Map the current YunoHost `/v3/apps.json` fields.
- Define validation, version, downgrade, and key-rotation rules.

### Phase 1 — publisher tooling

- Implement `publish`, `inspect`, and `verify`.
- Support `manifest.toml`, Git repositories, Nostr signing, and multiple relays.
- Add fixtures and protocol tests.

### Phase 2 — catalogue daemon

- Subscribe to relays.
- Verify signatures and explicit trusted publishers.
- Validate repository metadata and hashes.
- Generate a static valid `/v3/apps.json` from accepted events.
- Add SQLite or equivalent local state/cache.

### Phase 3 — YunoHost integration

- Connect the generated catalogue to a test server.
- Verify browse → install → upgrade using normal YunoHost tooling.

### Phase 4 — packaging and configuration

- Package the daemon as `nostr_catalog_ynh`.
- Register the custom catalogue automatically.
- Add the YunoHost configuration panel.

### Phase 5 — automation and curation

- Add GitHub Actions publication on release/tag.
- Use a dedicated catalogue publishing key; evaluate NIP-46 or delegation later.
- Add endorsement/curation events and policy thresholds.

### Phase 6 — attestations and extraction

- Add CI/test result attestations.
- Extract reusable Nostr software-registry primitives for possible `npack` and other platform adapters.

## MVP definition

Version 0.1 is complete when it supports:

- Publishing one replaceable signed app declaration from a normal YunoHost Git repository.
- Multiple configured relays.
- Signature verification and an explicit trusted publisher list.
- Repository/commit/manifest validation.
- Local cached generation of `/v3/apps.json`.
- YunoHost wrapper installation and custom catalogue registration.
- A demonstration with `hello_nostr_ynh` and `test_service_ynh` published by two npubs.
- A version update, for example `1.0.0~ynh1` → `1.1.0~ynh1`, detected through normal YunoHost upgrade machinery.

## Explicit non-goals for the MVP

- Custom YunoHost frontend.
- Replacement installer or package format.
- Binary distribution over Nostr.
- Web-of-trust ranking or reputation scoring.
- New relay implementation.
- Dependency resolver.
- Global naming registry.
- Nostr logic inside YunoHost core.

## Positioning

Initial description:

> A decentralised application catalogue for YunoHost using Nostr for signed publication, discovery, and curation, while retaining YunoHost's existing packaging and installation system.

Long-term direction:

> A decentralised software registry protocol built on Nostr, with adapters for existing package ecosystems.

## First milestone recording

The first end-to-end demonstration should show:

```text
edit normal YunoHost app → tag release → GitHub Action publishes event
→ event propagates → catalogue refreshes → app appears in Webadmin
→ user installs → publisher releases update → YunoHost reports upgrade
```
