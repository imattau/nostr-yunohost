# YunoHost catalogue translation boundary

`nostr-catalogd` ends at a local HTTP endpoint serving a YunoHost-compatible
`/v3/apps.json`. It does not install, upgrade, or execute applications.

## Data flow

```text
validated Nostr declaration
        ↓
repository metadata at pinned commit
        ↓
normalised internal catalogue entry
        ↓
YunoHost /v3/apps.json response
```

The current upstream shape is an object containing `antifeatures`, `apps`,
`categories`, and `security`. `apps` is keyed by app ID. Each app entry
contains, among other fields, `id`, `git.url`, `git.branch`, `git.revision`,
`manifest`, `category`, `state`, `level`, `maintained`, `added_in_catalog`, and
`lastUpdate`. The translator in `internal/catalog/yunohost.go` is fixture-ready
for this shape.

The daemon must not synthesize the authoritative `manifest` from Nostr hints.
It must fetch and validate `manifest.toml` from the declared repository and
pinned commit first, then pass the parsed manifest to the translator.

The generated response should be deterministic: stable ordering, stable JSON
encoding, and no relay-specific data. The local cache remains usable while
relays are unavailable.

## Local service contract

The daemon should expose:

- `GET /v3/apps.json` — generated catalogue consumed by YunoHost.
- `GET /healthz` — process and cache health for administration.

Future diagnostic endpoints must not expose private signing material or bypass
the configured trust policy.

## Non-responsibilities

The daemon does not:

- execute package scripts;
- resolve or install dependencies;
- download binaries through Nostr;
- replace YunoHost's package validation;
- provide a separate app-store user interface.
