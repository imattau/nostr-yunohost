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
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0

      - uses: imattau/nostr-yunohost@main
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

For a UI confirmation flow, `nostr-ynh publish --dry-run` builds and signs the
event, outputs its JSON and `naddr`, and makes no relay connection.

YunoHost integrations can use `--private-key-file` to keep the signing key out
of process arguments. The file should be readable only by the service account.

The same command accepts `--repository-url <url> --ref <branch|tag|commit>` to
preview and publish directly from a remote package repository. A YunoHost
publisher app can use this mode after displaying the detected manifest and
hashes for administrator confirmation.

The action currently defaults to `main` because this project has not released a
versioned binary yet. Once releases exist, workflows should pin
`nostr-yunohost-version` to a release tag or immutable commit.

## Announcing releases as notes

Setting `announce: true` also publishes a kind-1 text note alongside the
declaration, signed by the same key, so the release shows up in an ordinary
Nostr client feed - see `docs/profile-and-announcements.md`. This requires
`announcement-ledger`, a path to a small local file that tracks which
`(app_id, commit)` pairs this key has already announced, so re-running the
same tag/release trigger never posts a duplicate note. That file must
persist across workflow runs - typically via `actions/cache` keyed on the
repository - or every run effectively re-announces:

```yaml
      - uses: actions/cache@v4
        with:
          path: .nostr-ynh/announcements.json
          key: nostr-ynh-announcements

      - uses: imattau/nostr-yunohost@main
        with:
          relays: wss://relay.example-a,wss://relay.example-b
          private-key: ${{ secrets.NOSTR_YNH_PUBLISHING_KEY }}
          announce: 'true'
          announcement-ledger: .nostr-ynh/announcements.json
```

The publisher's kind-0 profile (name/picture/about) is separate and only
needs setting once - see `nostr-ynh profile` in
`docs/profile-and-announcements.md` - rather than on every release workflow
run.
