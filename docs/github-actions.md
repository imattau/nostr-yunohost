# GitHub Actions publishing

The repository includes a reusable composite action for publishing a signed
YunoHost app declaration to Nostr relays.

## Example workflow

```yaml
name: Publish YunoHost app

on:
  release:
    types: [published]
  push:
    tags: ["*"]

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: nostr-yunohost/nostr-yunohost@main
        with:
          relays: wss://relay.example-a,wss://relay.example-b
          private-key: ${{ secrets.NOSTR_YNH_PUBLISHING_KEY }}
          nostr-yunohost-version: main
```

The action installs the CLI, reads the checked-out package's `manifest.toml`,
extracts the Git origin and full commit, hashes the manifest and repository
archive, signs the declaration, and publishes it to every configured relay.

The publishing key must be a dedicated catalogue key, not a user's primary
Nostr key. Store it as a masked repository or environment secret. GitHub Actions
publishing should be restricted to trusted branches/tags and protected release
environments where practical.

The action currently defaults to `main` because this project has not released a
versioned binary yet. Once releases exist, workflows should pin
`nostr-yunohost-version` to a release tag or immutable commit.
