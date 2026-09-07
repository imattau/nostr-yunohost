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

## Relationship to endorsements

Endorsements and attestations are structurally independent event kinds and
neither implies the other. A server can endorse an app it installed (kind
30079) without ever running CI; CI can attest a commit (kind 30080) without
anyone having installed it yet. Local trust policy (Phase 6) may eventually
weigh both, but the MVP trust policy considers attestations only.
