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
nothing requires the same server to both publish and verify, but nothing
requires them to be different either. The common case for a package
operator who already runs a trusted publishing identity - a YunoHost server
running `nostr-catalogd`, say - is to self-attest with that same key rather
than stand up a second one: `nostr-ynh publish` accepts `--ci-result`
directly, building and publishing the declaration and its attestation
together, signed by the same `--private-key`/`--private-key-file`, in one
call:

```bash
nostr-ynh publish \
  --repo . \
  --private-key-file publisher.key \
  --relays wss://relay.example \
  --ci-result ci-result.json \
  [--ci-provider github-actions] [--ci-ref <run URL>]
```

Before signing, this cross-checks `ci-result.json`'s
`app_id`/`repository`/`commit`/`manifest`/`content` against the declaration
it just built from the same repository state, and refuses to attest (and
does not publish either event) on any mismatch - a stale or unrelated CI
result can never get folded into a valid-looking attestation for whatever
happens to be checked out. `--ci-provider`/`--ci-ref` auto-detect the same
way `nostr-ynh attest` does. Standalone `nostr-ynh attest` remains the right
tool when the verifier genuinely is a separate identity - a third-party CI
service attesting someone else's package, for instance.

## Independently re-checking a published attestation

Self-attestation (above) is convenient, but it means the daemon's default
trust model is "believe whatever the publisher's key signed." `nostr-ynh
reverify` is the trust-but-verify counterpart: given a published
attestation's `naddr`, it re-derives everything from scratch instead of
reading the attestation's claims at face value.

```bash
nostr-ynh reverify \
  --relays wss://relay.example \
  [--json] \
  naddr1...
```

It: fetches the attestation event and, under the same pubkey (the
self-attestation model signs both with one key - see above), the
declaration it claims to cover; cross-checks their `app_id`/`repo`/
`commit`/`manifest`/`content` against each other; then clones the
repository fresh at the attested commit and recomputes both hashes,
independent of anything either event merely asserts. It prints `MATCH` or a
`MISMATCH` list (`--json` gives a `{"match": bool, "mismatches": [...]}`
result with a nonzero exit code on mismatch), so it scripts as a periodic
check or a manual spot-check on any app in the catalogue - not just your
own.

This catches: a repository whose branch/tag has been force-pushed to
different content since it was attested; a declaration silently republished
pointing at a different commit than what was actually tested; or an
attestation whose claimed hashes never matched the real repository content
in the first place (a compromised CI job, or a publisher key signing a
false claim) - none of which a signature check alone can see, since the
signature only proves who signed, not that what they signed was true.

What it does *not* catch: it does not re-run the underlying checks
(`package_linter`, `shellcheck`, ...) themselves, so a publisher whose CI
setup is broken or lax but whose signed claims are internally consistent
still reads as `MATCH`. Re-running the actual check suite against the
fresh clone is a natural follow-on (tracked, not yet built) rather than
something `reverify` does today - this first pass is deliberately just the
"has anything been tampered with since attestation" check, run manually.

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

Attestations persist across restarts via `Store.Save`/`Load`, the same
local JSON cache declarations already use (`cacheFile.Attestations`,
flattened from `Store.attestations` and restored through the same
same-verifier-same-revision dedup rule `IngestAttestation` applies live, so
a stale cached attestation can never overwrite a newer in-memory one). This
was added specifically because it matters under `require`: without it, a
daemon restart would transiently exclude every previously attested
package from the generated catalogue until relays resent those
attestations - which defeats Phase 11's whole point of keeping a trusted
revision installable. `endorsements` (kind 30079, a separate feature) do
not persist this way and remain live-subscription-only - that gap is real
but not load-bearing the way the attestation one was, since nothing
excludes an app from the catalogue for lacking an endorsement.

**Remaining, smaller gap:** attestations are still only *accumulated* from
the live subscription plus whatever the cache already held - there is no
historical fetch on startup (no `FetchAttestations` alongside
`FetchAppDeclarations`). A daemon that has never seen a given attestation
(fresh install, or a cache predating it) won't have it until the
publishing relay resends it live. Persistence closes the restart gap;
a historical fetch would additionally close the cold-start one.

## Local trust policy

`nostr-catalogd --attestation-policy off|prefer|require` (or
`NOSTR_YNH_ATTESTATION_POLICY`) configures how `WriteSnapshot` uses
`AttestationsFor`'s result for each declaration it would otherwise include.
Default is `off`. By default, an attestation counts if its overall `result`
tag is `pass` and any single acceptable attestation is enough - the
original MVP criterion. Three flags extend this (Phase 12,
`trust.AttestationPolicy`/`NewAttestationPolicy`,
`internal/trust/attestation_policy.go`), each defaulting to its most
permissive value:

- `--minimum-attestations`/`NOSTR_YNH_MINIMUM_ATTESTATIONS` (default 1):
  how many independent, acceptable attestations a revision needs before it
  counts as `Verified`. `AttestationsFor` already dedupes to one attestation
  per verifier for a given revision, so this really is counting independent
  verifiers, not just events.
- `--required-checks`/`NOSTR_YNH_REQUIRED_CHECKS` (default empty): a
  comma-separated list of check names. When set, "acceptable" stops meaning
  "overall result is pass" and starts meaning "every named check in this
  attestation's own `checks` map is individually `pass`" - the attestation's
  overall `result` is then ignored entirely. This is what lets an
  administrator require e.g. `package_check` while treating an unrelated
  failing check (e.g. `vulnerability_scan`) as advisory, per the plan's own
  example.
- `--trusted-verifiers`/`NOSTR_YNH_TRUSTED_VERIFIERS` (default empty,
  meaning any verifier): a comma-separated allowlist of verifier hex keys
  or npubs. An attestation from any other verifier is never counted toward
  `Verified`, though it still appears in the security index/admin dashboard
  as evidence - filtering happens in policy evaluation, not ingestion.

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

## Upgrade gating

A publisher releasing a new version doesn't retroactively un-attest the old
one, but it does mean `require` must decide what to do about a revision
that has no attestation yet. The plan's rule (Phase 11):

```text
v1, commit ABC, attested   ->  installable
v2, commit DEF, unattested ->  discovered, not offered

v1 stays the installable revision until DEF is itself attested, then the
catalogue advances to v2.
```

`Store` keeps every recently seen distinct-commit revision per
publisher/app pair (`upsertRevision`, capped at 10 by `capRevisionsLocked`),
not just the latest. `WriteSnapshot` picks the *newest revision that is
both repository-verified and accepted by the local attestation policy*
(`selectAcceptedRevisionLocked`), falling back through older revisions
rather than to nothing when the newest one isn't (yet) accepted. Under
`off`/`prefer` (which always accept), this reduces to "pick the newest
verified revision" - unchanged from before this existed. Only `require`
actually exercises the fallback.

The cap itself is attestation-aware, not just a blind recency window:
`capRevisionsLocked` never evicts a revision beyond the cutoff that the
policy currently accepts (at most one extra slot, so the list can reach 11,
never unbounded). Without this, enough unattested republishes - more than
10, from the same publisher, before any of them got attested - would have
reopened this exact bug through a different door: eviction instead of
overwrite. This can only ever protect the single most-recently-accepted
revision, not an arbitrary older one that might become relevant if attested
later; a revision evicted before ever being attested is gone regardless.

This was a real gap until it was verified end-to-end and fixed: the
original `require` implementation (Phases 6-10) filtered only at the
`/v3/apps.json`-generation step, but the underlying declaration store kept
just one record per publisher/app pair, unconditionally overwritten by
whatever arrived most recently - so an unattested v2 didn't just fail to
be offered, it *erased v1 from the store entirely*, and the app vanished
from the catalogue rather than staying pinned to v1. Fixed by keeping a
bounded revision history instead of a single latest record.

`Snapshot`/`Declarations` (and so `attestation.Candidates`'s
installed-app matching) deliberately still report each pair's *newest*
revision regardless of attestation status - discovery stays independent of
installability (Phase 7). Only `WriteSnapshot`'s per-app selection applies
the fallback.

This fallback depends on attestation evidence actually surviving a
restart - which it now does (see the persistence note above). Before that
fix, a restart under `require` would have lost every revision's
attestation evidence at once, making the fallback logically correct but
practically useless (an older, previously-attested revision would look
identical to a never-attested one and get excluded too).

## Admin trust dashboard

The reason a `require`-excluded app doesn't appear in `/v3/apps.json` at all
is exactly what the admin page (behind `--admin-listen`/`--publisher-key-file`,
same as the existing attestation admin page) now shows first, before its
existing candidate-endorsement table: `GET /admin/trust`
(`catalog.Store.TrustEntries`) lists every retained revision of every
accepted declaration - not just the one WriteSnapshot ends up selecting,
whether that's because several publishers declare the same app ID or
because a newer revision is sitting unattested behind an older installable
one (see Upgrade gating above) - with what this server has independently
verified about the repository (`repository_verified`), every matching attestation
(`attestations`, the same data as the security index), and the local
policy's verdict (`policy.mode`/`accepted`/`verified`, plus the policy's own
configuration echoed back as `policy.minimum_attestations`/
`policy.required_checks` so the page can explain *why* without a second
request). An excluded app shows `UNVERIFIED` with the policy mode and why,
rather than silently vanishing from the page an administrator would check.

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
