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
    uses: nostr-yunohost/nostr-yunohost/.github/workflows/static-security.yml@main
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

## A caveat on the external tools

package_linter, ShellCheck, Gitleaks, Trivy, and actionlint are all
integrated by their current documented interfaces as of this writing, but
none of that integration has been exercised against a live GitHub Actions
runner in this change - there is no network access in the environment this
workflow was written in. Before relying on this in a real package pipeline,
run it once against a real `_ynh` repository and check each tool's actual
invocation still matches its current CLI/action interface.
