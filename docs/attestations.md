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

`WriteSnapshot` is the only current consumer of `AttestationsFor`: the local
trust policy below decides inclusion/exclusion, and separately, every
matching attestation for a *retained* app becomes an entry in
`SecurityIndex.Apps[appID]` (`catalog.NewSecurityAppEntry`) - one entry per
verifier, carrying `revision`/`status`/`verifier` (as npub)/`tested_at`/
`checks`, matching the plan's Phase 8 example shape. This is populated
regardless of Mode: `off`/`prefer` apps that stay installable despite a
failing or absent attestation still get whatever evidence exists recorded
here (an app with zero attestations gets no entry at all, rather than an
empty list). An app excluded entirely by `require` gets no security-index
entry either, since it isn't in `Apps` for the index to be attached to.

**Known gap, shared with endorsements, now load-bearing:** attestations are
only accumulated from the live subscription opened at daemon startup -
there is no historical fetch (no `FetchAttestations` alongside
`FetchAppDeclarations`) and no persistence across restarts, matching the
endorsement subscription's existing behavior. Under `require` mode this is
no longer a cosmetic gap: **restarting the daemon transiently excludes every
previously attested package** from the generated catalogue until relays
resend those attestations. Anyone enabling `require` should be aware of
this before relying on it in production; fixing it (historical fetch and/or
cache persistence, for both endorsements and attestations) is unfinished
follow-up work, not part of this phase.

## Local trust policy

`nostr-catalogd --attestation-policy off|prefer|require` (or
`NOSTR_YNH_ATTESTATION_POLICY`) configures how `WriteSnapshot` uses
`AttestationsFor`'s result for each declaration it would otherwise include.
Default is `off`. The acceptance criterion is deliberately simple for the
MVP: an attestation counts if its overall `result` tag is `pass` - no
minimum count, no required-checks list, no trusted-verifier allowlist yet
(`trust.AttestationPolicy`, `internal/trust/attestation_policy.go`
documents these as an explicitly later extension, plan Phase 12).

| Mode | Unattested declaration | Declaration with a passing attestation |
| --- | --- | --- |
| `off` (default) | in catalogue | in catalogue |
| `prefer` | in catalogue | in catalogue, marked verified |
| `require` | **excluded** from catalogue | in catalogue, marked verified |

"Marked verified" is now visible on the generated `/v3/apps.json` itself,
via the security index above: a passing attestation's entry has
`"status": "verified"`; a failing or erroring one carries its raw result
(`"fail"`/`"error"`) instead. There is deliberately no single boolean
collapsing this into one verdict per app - an app can have several
attestations (Phase 12's multiple independent verifiers), and the plan
calls for listing the evidence, not summarizing it. The security index on
`/v3/apps.json` only appears for apps that made it into `Apps` in the first
place - `require` excludes the whole entry, security data included.

## Admin trust dashboard

The reason a `require`-excluded app doesn't appear in `/v3/apps.json` at all
is exactly what the admin page (behind `--admin-listen`/`--publisher-key-file`,
same as the existing attestation admin page) now shows first, before its
existing candidate-endorsement table: `GET /admin/trust`
(`catalog.Store.TrustEntries`) lists every accepted declaration - not just
the one WriteSnapshot ends up selecting when several publishers declare the
same app ID - with what this server has independently verified about the
repository (`repository_verified`), every matching attestation
(`attestations`, the same data as the security index), and the local
policy's verdict (`policy.mode`/`accepted`/`verified`). An excluded app
shows `UNVERIFIED` with the policy mode and why, rather than silently
vanishing from the page an administrator would check.

This flag is unrelated to the existing `--attestation-ledger`/
`--publisher-key-file` flags: those configure this server's own kind-30079
curator endorsements of apps it installed (`internal/attestation`), a
completely different, older feature that happens to share the word
"attestation" in its name.

## Relationship to endorsements

Endorsements and attestations are structurally independent event kinds and
neither implies the other. A server can endorse an app it installed (kind
30079) without ever running CI; CI can attest a commit (kind 30080) without
anyone having installed it yet. Local trust policy (Phase 6) may eventually
weigh both, but the MVP trust policy considers attestations only.

## Attestation status vs. YunoHost quality metadata

`catalog.AttestationStatus` (`internal/catalog/yunohost.go`) is this
daemon's own explicit classification of a declaration's standing, computed
by `ComputeAttestationStatus(repositoryVerified, attestations)`:

| Status | Meaning |
| --- | --- |
| `unverified` | This server has not independently confirmed the repository/commit/manifest/content hashes |
| `integrity_verified` | Repository confirmed; no CI attestation exists yet for this exact revision |
| `ci_verified` | Repository confirmed; exactly one independent verifier attested a passing result |
| `multi_verified` | Repository confirmed; two or more independent verifiers each attested a passing result |
| `failed` | Repository confirmed; at least one attestation exists, and none of them passed |

This is deliberately kept separate from YunoHost's own quality fields:

```text
YunoHost quality level  !=  Nostr Catalog attestation status
```

`Level` stays hardcoded at `5` regardless of status - it is a compatibility
floor for a YunoHost CI pipeline this catalogue has never run, which has
nothing to do with what this catalogue itself has verified or attested.
`HighQuality`, on the other hand, has a genuine equivalent: `WriteSnapshot`
now sets it whenever `ComputeAttestationStatus` returns `ci_verified` or
`multi_verified`, independently of (and in addition to) the existing
curator-endorsement-threshold route. Either signal alone is enough; they
are not required together.

`Status` also appears on each `TrustEntries()` row (the admin trust
dashboard, Phase 9) so an administrator sees the same classification the
daemon used, not just the policy's accept/reject verdict - `status` and
`policy` answer different questions (what the evidence shows, versus what
the local administrator chose to do about it) and can disagree, e.g.
`failed` under `off` policy still shows `Informational`/accepted.
