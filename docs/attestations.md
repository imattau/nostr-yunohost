# Attestation events

Attestations are separate from both app declarations (kind 30078) and curator
endorsements (kind 30079, see `docs/endorsements.md`). A declaration is a
publisher's claim about what it is shipping; an endorsement is a
human/server recommendation; an attestation is a machine-checkable claim
that a specific repository commit passed a specific set of automated checks
(`internal/verification`).

The current provisional event kind is `30080`. Its address is:

```text
(kind=30080, pubkey=verifier, d=<app_id>:<commit>)
```

Addressing by `app_id:commit`, not `app_id` alone, is deliberate:

```text
attestation(repo, commit ABC) != attestation(repo, commit DEF)
```

A package update to a new commit therefore leaves the old attestation intact
as its own event and requires a fresh attestation for the new commit before
it can satisfy a `require` trust policy. Re-publishing an attestation for a
commit that was already attested by the same verifier replaces the previous
event, per normal NIP-33 replacement semantics - useful for correcting a
mis-recorded check without leaving a stale duplicate around.

## Tags

| Tag | Meaning |
| --- | --- |
| `d` | `<app_id>:<commit>`, the addressable identity |
| `app_id` | YunoHost app ID, matching the declaration's `d` tag |
| `repo` | Canonical Git repository URL, matching the declaration's `repo` tag |
| `commit` | Full Git commit that was tested |
| `manifest` | Hash of `manifest.toml` at that commit, `sha256:<hex>` |
| `content` | Hash of the repository tree at that commit, `sha256:<hex>` |
| `ci_provider` | CI system that ran the checks, e.g. `github-actions` |
| `ci_ref` | CI run/reference, e.g. a workflow run URL or ID |
| `result` | Overall verdict: `pass`, `fail`, or `error` |

`pubkey` is the verifier identity; `created_at` is treated as `tested_at`.

## Content object

Content is the machine-readable CI result payload (schema 1):

```json
{
  "schema": 1,
  "checks": {
    "yunohost_lint": "pass",
    "shellcheck": "pass",
    "secret_scan": "pass",
    "vulnerability_scan": "pass",
    "package_check": "pass"
  }
}
```

Each check outcome is one of `pass`, `fail`, `skip`, or `error`. Keeping
individual results, rather than a single `verified: true`, is what lets a
local trust policy later require specific checks (e.g. `package_check`)
while treating others (e.g. `vulnerability_scan`) as advisory.

## Validation

`verification.Parse` checks the event envelope (ID, signature, required
tags, hash formats) and that the `d` tag agrees with `app_id`/`commit`. It
does not check the attestation against a specific app declaration - that
requires cross-referencing `repo`/`commit`/`manifest`/`content` against the
matching kind-30078 event, which belongs to the daemon's ingestion path
(Phase 5), not to parsing a single event in isolation.

## Publishing an attestation

`nostr-ynh attest` turns a CI result (`docs/ci-result-schema.md`) into a
signed attestation and publishes it:

```bash
nostr-ynh attest \
  --ci-result ci-result.json \
  --private-key-file verifier.key \
  --relays wss://relay.example \
  [--ci-provider github-actions] [--ci-ref <run URL>]
```

`--ci-provider`/`--ci-ref` are only needed outside GitHub Actions: when
`GITHUB_ACTIONS=true` is set (i.e. the command runs as a workflow step), it
derives both from the run's own environment
(`GITHUB_SERVER_URL`/`GITHUB_REPOSITORY`/`GITHUB_RUN_ID`), matching the
plan's "GitHub Action -> nostr-ynh attest -> signed Nostr attestation" flow
for package repositories that want verification automatically on release.
`--dry-run` builds and signs the event, printing its JSON and `naddr`,
without connecting to a relay - the same pattern `nostr-ynh publish
--dry-run` uses.

The verifier key is a separate identity from the package publisher's key -
nothing requires the same server to both publish and verify.

## Consuming attestations in nostr-catalogd

`nostr-catalogd` subscribes to attestation events unconditionally (unlike
endorsements, which only accumulate once `--trusted-curators` is set) and
stores every well-formed one in `catalog.Store`, keyed by (repository,
commit) and then by verifier - `internal/catalog`'s `IngestAttestation`.
Storage does not require a matching declaration to already exist: a
declaration and its attestations are independent event streams, per the
plan's "declaration + zero or more attestations" model.

`Store.AttestationsFor(declaration)` returns the attestations that actually
apply to one accepted declaration. Matching on repository and commit is not
enough by itself - an attestation is only returned if its `manifest`/`content`
hashes also agree with the declaration's own (already repository-verified)
hashes. This is the "never treat an attestation for another revision as
valid" rule from the plan, applied concretely: repository and commit could
coincidentally (or maliciously) match while the actual code hash doesn't.

Nothing yet *uses* `AttestationsFor` to change what the generated catalogue
serves - that's local trust policy (Phase 6, not implemented) and the
security index (Phase 8, not implemented). Phase 5 only makes attestations
available; it does not yet gate anything on them.

**Known gap, shared with endorsements:** attestations are only accumulated
from the live subscription opened at daemon startup - there is no
historical fetch (no `FetchAttestations` alongside `FetchAppDeclarations`)
and no persistence across restarts, matching the endorsement subscription's
existing behavior. A freshly restarted daemon holds zero attestations until
new ones arrive on relays it's watching. This is fine while nothing depends
on attestations yet, but should be fixed - a historical fetch and/or cache
persistence, for both endorsements and attestations - before Phase 6's
`require` policy ships, or a restart would transiently un-attest every
package.

## Relationship to endorsements

Endorsements and attestations are structurally independent event kinds and
neither implies the other. A server can endorse an app it installed (kind
30079) without ever running CI; CI can attest a commit (kind 30080) without
anyone having installed it yet. Local trust policy (Phase 6) may eventually
weigh both, but the MVP trust policy considers attestations only.
