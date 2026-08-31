# MVP Nostr event schema

Status: draft for Phase 0.

## Event identity

The MVP uses a parameterised replaceable event with provisional kind `30078`.
The kind remains provisional until checked against the Nostr kind registry and
the YunoHost integration is implemented.

The replaceable identity is:

```text
(kind=30078, pubkey=publisher, d=app_id)
```

The stable application identifier is therefore the publisher public key plus
the app ID. A display name such as `immich` is not globally unique.

## Required tags

| Tag | Meaning |
| --- | --- |
| `d` | YunoHost app ID; lower-case package identifier |
| `platform` | Must be `yunohost` |
| `repo` | Canonical Git repository URL |
| `version` | Current YunoHost package version |
| `commit` | Full Git commit advertised by the publisher |
| `manifest` | Hash of the exact `manifest.toml`, formatted `sha256:<hex>` |
| `content` | Hash of the repository tree at `commit`, formatted `sha256:<hex>` |

The event's normal Nostr fields (`id`, `pubkey`, `created_at`, `kind`, `tags`,
`content`, and `sig`) are also required. `created_at` records publication
time; it does not override the package version or Git commit.

## Optional tags

`category`, `name`, `homepage`, `license`, `tag`, `architecture`, and `support`
may provide catalogue hints. Repeated `architecture` tags are allowed.

The repository remains authoritative for package metadata. Catalogue hints
must not silently replace values read from the repository during validation.

## Content object

Content is a JSON object. The MVP allows these optional fields:

```json
{
  "name": "Example app",
  "description": "Short catalogue description",
  "homepage": "https://example.org",
  "license": "AGPL-3.0-or-later",
  "icon": "https://example.org/icon.png",
  "screenshots": ["https://example.org/screenshot.png"],
  "source": "https://github.com/example/example_ynh",
  "issues": "https://github.com/example/example_ynh/issues",
  "architectures": ["amd64", "arm64"]
}
```

Unknown fields must be ignored for forward compatibility. Content is metadata,
not executable instructions.

## Acceptance rules

The catalogue daemon accepts an event only when:

1. The Nostr signature and event ID are valid.
2. `kind`, `d`, `platform`, `repo`, `version`, `commit`, `manifest`, and
   `content` are present and well formed.
3. The publisher is permitted by the local trust policy.
4. The repository can be fetched at the declared commit.
5. The fetched `manifest.toml` matches `manifest`.
6. The fetched repository tree matches `content`.
7. The package's own YunoHost metadata passes validation.

If any check fails, the event is retained for diagnostics but omitted from the
generated catalogue.

## Version and replay rules

The current replaceable event is selected by Nostr replacement semantics, then
validated independently. A catalogue must not downgrade an accepted package
because it received an older event or an older package version. Version
ordering must use YunoHost/Debian version semantics rather than lexical string
comparison.

Release history, endorsements, CI attestations, and key-rotation events are
out of scope for the first event implementation, but the schema leaves room
for them as separate event types.
