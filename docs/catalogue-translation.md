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

The adapter should map the fields YunoHost currently requires, including the
application ID, manifest/package metadata, Git source, category, level, and
version information. Phase 0 must capture a fixture from the target YunoHost
version and test this mapping against it rather than guessing the complete
format.

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
