# CI result schema

A CI result is the small, versioned JSON file a workflow writes after
testing one package revision (`internal/ciresult`). It exists independently
of Nostr: a CI job can produce it, and a human can read it, without a
signing key anywhere in reach. `nostr-ynh attest` (Phase 4) reads this file
and turns it into a signed kind-30080 attestation event
(`internal/verification`, see `docs/attestations.md`) - the CI result is the
unsigned input, the attestation is the signed, published claim.

## Format

```json
{
  "schema": 1,
  "app_id": "ditto",
  "repository": "https://github.com/example/ditto_ynh",
  "commit": "abc123...",
  "manifest": "sha256:...",
  "content": "sha256:...",
  "checks": {
    "yunohost_lint": "pass",
    "shellcheck": "pass",
    "secret_scan": "pass",
    "vulnerability_scan": "pass",
    "package_check": "pass"
  },
  "result": "pass"
}
```

| Field | Meaning |
| --- | --- |
| `schema` | Format version; currently `1` |
| `app_id` | YunoHost app ID |
| `repository` | Canonical HTTPS repository URL |
| `commit` | Full Git commit that was tested |
| `manifest` | Hash of `manifest.toml` at that commit, `sha256:<hex>` |
| `content` | Hash of the repository tree at that commit, `sha256:<hex>` |
| `checks` | Map of check name to outcome |
| `result` | Overall verdict |

Each entry in `checks` is one of `pass`, `fail`, `skip`, or `error`. `result`
is one of `pass`, `fail`, or `error` and summarizes the run as a whole, but
is deliberately not the *only* thing recorded: keeping individual check
results is what lets a later local trust policy require specific checks
(e.g. `package_check`) while treating others (e.g. `vulnerability_scan`) as
advisory, instead of only ever seeing a collapsed `verified = true`.

## Validation

`ciresult.Parse` decodes and validates the document: schema version, `app_id`
format, an HTTPS `repository`, a well-formed `commit`, `sha256:<hex>` hashes,
at least one check with a recognised outcome, and a recognised overall
`result`. It does not check the result against a live repository, a
published declaration, or a signing identity - producing and cross-checking
those belong to `nostr-ynh attest` and the daemon's ingestion path
respectively.

## Relationship to the attestation event

`ciresult.Result` and the attestation event's tags/content
(`docs/attestations.md`) overlap by design: `app_id`, `commit`, `manifest`,
and `content` become event tags so the daemon can filter/validate without
parsing content, and `checks` becomes the event's content payload. `result`
becomes the event's `result` tag. The CI result adds nothing the attestation
event doesn't already carry once signed; it is simply the form CI produces
before a verifier identity signs and publishes it.
