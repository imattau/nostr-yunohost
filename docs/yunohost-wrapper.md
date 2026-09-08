# YunoHost wrapper integration

`packaging/nostr_catalog_ynh` is the normal YunoHost app that runs the
catalogue daemon. It has not been installed against a live YunoHost server
(none is available in this environment) - treat it as a first draft to
validate on a real install, same as any other packaging that can't be
exercised by the Go test suite.

## Layout

```text
packaging/nostr_catalog_ynh/
├── manifest.toml       # install questions, resources (sources/ports/permissions)
├── config_panel.toml   # post-install editable relay/trust settings
├── conf/
│   ├── env                     # NOSTR_YNH_* env file template
│   ├── nostr-catalogd.service  # systemd unit template
│   └── nginx.conf              # reverse proxy for the admin page
└── scripts/
    ├── _common.sh
    ├── install
    ├── upgrade
    └── remove
```

## What the config panel exposes

`config_panel.toml`'s "Relays and trust policy" section renders
`NOSTR_YNH_RELAYS`, `NOSTR_YNH_TRUSTED_PUBLISHERS`,
`NOSTR_YNH_TRUSTED_CURATORS`, and `NOSTR_YNH_ATTESTATION_POLICY` - the
settings `cmd/nostr-catalogd/main.go` actually reads via `os.Getenv` at
startup, written to `/etc/nostr_catalog/env` and picked up on the next
service restart.

The publisher's kind-0 profile and kind-1 announcements
(`docs/profile-and-announcements.md`) are deliberately **not** config-panel
fields, because nothing in the daemon reads a `NOSTR_YNH_PROFILE_*` env
var - editing the profile happens live through the admin page's own
"Publisher profile" section instead, with no service restart involved.
`manifest.toml`'s `install.profile_name`/`install.profile_about` questions
only seed a one-time `nostr-ynh profile` call during `scripts/install`.

## Ports and permissions

Two ports, one systemd service (`cmd/nostr-catalogd` runs both HTTP
servers in one process):

- `port_catalog` (default 8090): the `/v3/apps.json` catalogue server.
  Loopback-only, never proxied by nginx - it is consumed directly by
  YunoHost's custom catalogue mechanism over 127.0.0.1, not by a browser.
- `port_admin` (default 8091): the trust/attestation/profile admin page
  (`--admin-listen`), reverse-proxied by nginx (`conf/nginx.conf`) at the
  install-time `domain`/`path`, behind the `main` permission
  (`resources.permissions.main`, admins-only) - see the access-control note
  at the top of `cmd/nostr-catalogd/admin.go`.

## Binaries and releases

Tagged core releases build one tarball per architecture
(`.github/workflows/release.yml`) containing both `nostr-catalogd` (the
running service) and `nostr-ynh` (used only at install time, for
`keygen`/`profile`). `manifest.toml`'s `resources.sources.main` pins one of
these tarballs per architecture by version and checksum rather than
compiling on the YunoHost server; the URLs/checksums are placeholders until
the first tagged release exists.

## Publisher key

`scripts/install` generates this server's own Nostr key
(`nostr-ynh keygen`) if none exists yet, stores it at
`install_dir/publisher.key` (mode 600, owned by the app's system user), and
uses it both as `--publisher-key-file` for the admin page (self-attestation
and profile/announcements) and, if `profile_name`/`profile_about` were
given at install time, to publish an initial kind-0 profile. Removing the
app removes this key along with the rest of `install_dir` - an
administrator who wants to keep publishing under the same identity after
uninstalling should copy it out first.

This wrapper is a deployment adapter, not a second implementation of the
publisher, relay, trust, or catalogue logic.
