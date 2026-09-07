## Nostr Catalog attestation and trust-policy update plan

The goal is to add **CI-backed package attestations** to the Nostr catalogue, then allow each YunoHost server to decide whether unverified packages should be visible/installable.

The existing architecture already gives you most of the primitives: package declarations contain the exact repository, commit, manifest hash and content hash; the daemon validates these before generating `/v3/apps.json`; and the catalogue model already has a placeholder `security` index.

### Phase 1: Define the attestation protocol

Add a new Nostr event type specifically for package verification.

The attestation should reference the exact package declaration and revision:

```text
app_id
repo
commit
manifest_hash
content_hash

verifier pubkey
tested_at
CI provider
CI run/reference

checks:
    yunohost_lint
    package_check
    shellcheck
    secret_scan
    vulnerability_scan

overall_result
```

The critical rule is:

```text
attestation(repo, commit ABC)
    !=
attestation(repo, commit DEF)
```

Any package update therefore invalidates the previous verification for installation purposes.

Prefer a **separate attestation event**, rather than adding mutable verification fields to the existing app declaration.

---

## Phase 2: Add a machine-readable CI result format

Define a small versioned schema, for example:

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

Keep individual results rather than only:

```text
verified = true
```

That allows future policies such as requiring `package_check` while treating vulnerability scanning as advisory.

---

## Phase 3: Build the standard security workflow

Create a reusable GitHub Action/workflow for YunoHost packages.

Initial checks:

```text
manifest validation
YunoHost package lint
ShellCheck
Gitleaks
Trivy
GitHub Actions security scan
package_check
```

Split this into two security boundaries.

### Static CI

Safe to run against essentially any submitted repository:

```text
manifest
lint
ShellCheck
Gitleaks
Trivy
workflow scanning
```

### Execution CI

Treat package lifecycle scripts as hostile code:

```text
install
remove
upgrade
backup
restore
change_url
```

Run these only in disposable infrastructure with:

```text
no repository secrets
read-only token
no Nostr private keys
no persistent host access
no trusted network access
```

Do not run arbitrary submitted YunoHost install scripts directly inside trusted catalogue infrastructure.

---

## Phase 4: Add attestation publishing

Extend the publishing workflow/CLI.

Current conceptual flow:

```text
nostr-ynh publish repo
        ↓
inspect package
        ↓
calculate hashes
        ↓
publish declaration
```

New flow:

```text
nostr-ynh publish repo
        ↓
resolve exact commit
        ↓
calculate hashes
        ↓
run / request CI
        ↓
wait for result
        ↓
create attestation
        ↓
sign attestation
        ↓
publish declaration + attestation
```

Also support CI producing the attestation directly:

```text
GitHub Action
     ↓
tests package
     ↓
nostr-ynh attest
     ↓
signed Nostr attestation
```

This will be useful for package repositories that want verification automatically whenever they release.

---

## Phase 5: Consume attestations in `nostr-catalogd`

Add an attestation store alongside package declarations.

For every package revision:

```text
declaration
    +
zero or more attestations
```

Validation should verify:

```text
Nostr event signature
attestation schema
repo matches declaration
commit matches declaration
manifest hash matches
content hash matches
verifier identity
CI result integrity
```

Never treat an attestation for another revision as valid.

---

## Phase 6: Add local trust policy

Add configuration to the daemon and YunoHost config panel.

Initial setting can be deliberately simple:

```text
Attestation policy:

Off
Prefer verified
Require verified
```

Semantics:

### `off`

```text
valid declaration
→ catalogue
```

Attestations are informational only.

### `prefer`

```text
valid declaration
→ catalogue

attestation available
→ mark verified
```

Everything remains installable.

### `require`

```text
valid declaration
+
acceptable attestation
→ catalogue
```

Packages without an acceptable attestation are excluded from YunoHost's generated catalogue.

Later extend this with:

```toml
minimum_attestations = 1

required_checks = [
    "yunohost_lint",
    "package_check"
]

trusted_verifiers = [
    "npub1..."
]
```

---

## Phase 7: Separate discovery from installation

This distinction is important.

Do **not** necessarily remove unverified packages from Nostr discovery.

Instead:

```text
Nostr network
      │
      ├── verified package
      │       ↓
      │   catalogue UI
      │       +
      │   YunoHost apps.json
      │
      └── unverified package
              ↓
          catalogue UI
          "Unverified"
```

With `require` enabled:

```text
unverified package
→ discoverable
→ not exposed to YunoHost installer
```

That preserves permissionless publishing without making permissionless publishing equivalent to local trust.

---

## Phase 8: Populate the existing security index

The generated YunoHost catalogue structure already has:

```go
type SecurityIndex struct {
    Version int
    Apps    map[string][]any
    System  map[string][]any
}
```

Implement something along these lines:

```json
"security": {
  "version": 1,
  "apps": {
    "ditto": [
      {
        "revision": "abc123...",
        "status": "verified",
        "verifier": "npub1...",
        "tested_at": 1788760000,
        "checks": {
          "yunohost_lint": "pass",
          "package_check": "pass",
          "shellcheck": "pass"
        }
      }
    ]
  }
}
```

The daemon should use this internally even if YunoHost itself ignores the additional metadata.

---

## Phase 9: Update the admin interface

The existing admins-only catalogue page can become the trust dashboard.

Per package show:

```text
Ditto
Version: 1.2~ynh3
Revision: abc123

Publisher              ✓
Repository integrity   ✓
Manifest integrity     ✓
YunoHost lint          ✓
ShellCheck             ✓
Secrets scan           ✓
Package lifecycle      ✓

Verified by:
npub1...

Tested:
7 Sep 2026
```

For failures:

```text
UNVERIFIED

Missing:
package_check attestation

Local policy:
Require verified

Result:
Excluded from YunoHost catalogue
```

Also expose why an application was filtered instead of silently hiding it.

---

## Phase 10: Fix YunoHost quality handling

The current translation deliberately sets:

```go
Level: 5
HighQuality: false
```

because repository integrity is verified but actual YunoHost CI has not been run.

Once attestations exist, remove the idea that `Level: 5` represents the catalogue's security assessment.

Keep two concepts separate:

```text
YunoHost quality level
        !=
Nostr Catalog attestation status
```

Use something explicit internally:

```text
unverified
integrity_verified
ci_verified
multi_verified
failed
```

Only map into YunoHost quality metadata where there is a genuine equivalent.

---

## Phase 11: Handle updates and upgrades

When a newer declaration arrives:

```text
v1
commit ABC
attested ✓

        ↓ new release

v2
commit DEF
attested ✗
```

Under `require`:

```text
v1 remains current installable revision
v2 is discovered but not offered
```

Do **not** let the new unverified release replace a previously trusted catalogue entry.

Once:

```text
DEF → attested ✓
```

the catalogue advances to v2.

This also gives you protection against accidentally publishing a broken or compromised update.

---

## Phase 12: Multiple independent verifiers

Design the protocol for this now even if MVP uses only one verifier.

Example:

```text
package DEF
   │
   ├── publisher declaration
   ├── Armada CI attestation
   ├── community verifier attestation
   └── independent YunoHost tester
```

Then local policy can eventually support:

```toml
minimum_attestations = 2
```

or:

```toml
trusted_verifiers = [
    "npub1armada...",
    "npub1alice...",
    "npub1bob..."
]
```

This prevents the catalogue operator from becoming a central certificate authority.

---

## Recommended implementation order

1. **Attestation event schema**
2. **CI result JSON schema**
3. **Static GitHub security workflow**
4. **`nostr-ynh attest` command**
5. **Attestation parsing/validation in daemon**
6. **`off / prefer / require` trust policy**
7. **Filter `/v3/apps.json` according to policy**
8. **Admin UI verification status**
9. **Full isolated `package_check` CI**
10. **Upgrade gating**
11. **Multiple verifier support**
12. **Advanced trust policies**

The first useful release does not need the whole system. The MVP can simply be:

```text
GitHub CI
   ↓
signed attestation for exact commit
   ↓
nostr-catalogd verifies it
   ↓
setting:
    allow unverified
    OR
    require attestation
   ↓
filtered /v3/apps.json
```

That alone turns the Nostr catalogue from a decentralised **discovery catalogue** into the beginnings of a decentralised **verified software distribution layer**.
