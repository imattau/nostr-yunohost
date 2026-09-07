# Standard security workflow

Phase 3 of `docs/attestation-trust-policy-plan.md`: a reusable GitHub Action
workflow that any `_ynh` package repository can call to run the standard set
of automated checks, producing the unsigned CI result document
(`docs/ci-result-schema.md`) that `nostr-ynh attest` (Phase 4) later signs
into a kind-30080 attestation event (`docs/attestations.md`).

## Static CI vs Execution CI

The plan splits checks into two security boundaries, and this is a hard
line, not a style preference:

**Static CI** (`.github/workflows/static-security.yml`, implemented here) is
safe to run against essentially any submitted repository: it reads files and
runs analysis tools, but never executes the package's own scripts.

**Execution CI** treats the package's lifecycle scripts (`install`,
`remove`, `upgrade`, `backup`, `restore`, `change_url`) as hostile code, and
requires disposable infrastructure with no repository secrets, a read-only
token, no Nostr private keys, and no persistent host or trusted-network
access. This is **not implemented yet**. Building it well needs real
ephemeral-runner infrastructure (an isolated VM or container torn down after
each run, with no access to this repository's secrets even transiently),
which is an infrastructure decision, not just a workflow file - it is
tracked as its own follow-up (implementation-order item 9,
`package_check`), not folded into this static workflow.

Do not run a submitted package's install scripts inside this workflow or any
runner that has access to real secrets.

## Usage

```yaml
name: Package security checks

on:
  push:
  pull_request:

jobs:
  static-security:
    uses: imattau/nostr-yunohost/.github/workflows/static-security.yml@main
```

The workflow checks out the calling repository, so it must run from a
workflow defined in the `_ynh` package repository itself.

## Checks

| Check (`ci-result.json` key) | Tool | What it catches |
| --- | --- | --- |
| `manifest_validation` | `nostr-ynh publish --dry-run` (this project's own metadata reader) | Missing/malformed `manifest.toml`, missing `id`/`version` |
| `yunohost_lint` | [YunoHost/package_linter](https://github.com/YunoHost/package_linter) | YunoHost packaging convention violations |
| `shellcheck` | ShellCheck (`scripts/`) | Shell scripting bugs in lifecycle scripts, without running them |
| `secret_scan` | Gitleaks | Committed secrets/credentials |
| `vulnerability_scan` | Trivy (filesystem scan) | Known-vulnerable dependencies |
| `workflow_scan` | actionlint | Misconfigured/dangerous GitHub Actions workflows |

`manifest_validation` is also where `app_id`, `repository`, `commit`,
`manifest`, and `content` come from: the dry-run publish step computes
exactly the same hashes a real `nostr-ynh publish` would, using the same
code path, so the CI result's hashes cannot drift from what publishing
would actually declare. It signs with a throwaway, never-persisted key
purely to satisfy the CLI's signing step - no real signing key is needed to
run these checks.

Each check's outcome is one of `pass`, `fail`, `skip`, or `error`, following
`internal/ciresult`. A tool crash and a genuine finding both currently
collapse to `fail`; only `manifest_validation` can distinguish a hard
failure (validation error) in more detail via its own log artifact
(`manifest.log`). The overall `result` is `pass` only if every check passed.

If `manifest_validation` fails, the workflow cannot compute the hashes a CI
result requires and does not attempt to write `ci-result.json` - a package
whose manifest doesn't even parse has nothing meaningful to attest.

## Output

The workflow uploads an `ci-result` artifact containing `ci-result.json`
(when manifest validation passed), the raw declaration JSON, and tool logs
for diagnostics. The job itself fails whenever the overall result is not
`pass`, so callers can gate merges on it directly, independent of whether
anyone ever runs `nostr-ynh attest` on the result.

Signing and publishing are deliberately not part of this workflow: doing so
would need a real verifier private key available to a job that also runs
several third-party tools against a submitted repository, which is the
opposite of what the Static CI boundary is for. A separate job (own
workflow, protected branch/environment, real secret - the same posture as
the existing publish action in `action.yml`) can consume the artifact:

```yaml
jobs:
  static-security:
    uses: imattau/nostr-yunohost/.github/workflows/static-security.yml@main

  attest:
    needs: static-security
    if: needs.static-security.outputs.result == 'pass'
    runs-on: ubuntu-latest
    environment: attestation
    steps:
      - uses: actions/download-artifact@v8
        with:
          name: ci-result
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'
      - run: go install github.com/imattau/nostr-yunohost/cmd/nostr-ynh@main
      - run: |
          "$(go env GOPATH)/bin/nostr-ynh" attest \
            --ci-result ci-result.json \
            --private-key "${{ secrets.NOSTR_ATTEST_PRIVATE_KEY }}" \
            --relays wss://relay.example
```

See `docs/attestations.md` for `nostr-ynh attest`'s full usage, including
how it auto-detects `--ci-provider`/`--ci-ref` from the GitHub Actions
environment it runs in.

## Verification

Every tool integration was checked against its actual current source
(fetched live, not from memory), not just assumed:

- `package_linter --json` always exits `0` - it only calls `sys.exit(1)` on
  its plain-text path, never its JSON one - so pass/fail is read directly
  from the JSON body's `error`/`critical` keys (its real top-level keys are
  `success`/`info`/`warning`/`error`/`critical`, each a list of test names;
  there is no `errors` key).
- `gitleaks/gitleaks-action@v2` stops working outright when GitHub removes
  Node 20 from hosted runners on 2026-09-16 (no opt-out). The workflow uses
  `@v3`, its documented Node-24 replacement with no input/behavior changes,
  and `actions/checkout@v7` (the migration guide recommends `@v6` or later).
- `aquasecurity/trivy-action` had a supply-chain compromise on several older
  tags; only `v0.35.0`+ (`v`-prefixed) and the specific preserved `0.35.0`
  tag are confirmed safe. The workflow pins `v0.36.0`, the current release,
  with its `scan-type`/`scan-ref`/`exit-code`/`severity` inputs confirmed
  unchanged on that tag.
- `ludeeus/action-shellcheck@2.0.0` and the `rhysd/actionlint` Docker image
  usage were confirmed current; actionlint is pinned to `1.7.12`.

What's still unverified: this hasn't been run end-to-end on a live GitHub
Actions runner against a real `_ynh` repository - only each component was
checked against its actual source/release metadata. Run it once for real
before gating a merge on it.
