# Nostr-backed YunoHost App Catalogue

Decentralised discovery and publication for normal YunoHost apps, using Nostr for signed declarations and configurable curation.

The project plan, architecture, MVP definition, roadmap, and security boundaries are documented in [PROJECT.md](PROJECT.md).

Publisher automation is documented in [docs/github-actions.md](docs/github-actions.md).

The planned YunoHost wrapper contract is documented in [docs/yunohost-wrapper.md](docs/yunohost-wrapper.md).

## Status

Phase 0 in progress: the event schema and structural parser are implemented;
relay publishing and repository verification are next.

## Scope

Nostr replaces the centralised catalogue discovery layer. YunoHost packaging, validation, installation, upgrades, Webadmin, and lifecycle management remain unchanged.
