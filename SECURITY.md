# Security Policy

`eunox` is a security-enforcement product. We take vulnerability reports
seriously and aim to respond quickly.

## Supported versions

| Version | Supported |
| ------- | --------- |
| `0.1.x` (latest release line) | ✅ |
| Older / pre-release tags      | ❌ |

Pre-1.0 means breaking changes can land between minor versions. Security fixes
are only backported to the most recent `0.1.x` release.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Use **[GitHub Private Vulnerability Reporting](https://github.com/eunolabs/eunox/security/advisories/new)**
as the primary channel. It is end-to-end private between you and the maintainers,
tracks the report through coordinated disclosure, and lets us request a CVE on your
behalf.

If you cannot use GitHub Security Advisories, email **security@eunolabs.ai**.
Include the word `eunox` in the subject line.

A good report includes:

- The version (`eunox --version`) or commit SHA you tested against.
- A minimal reproduction — ideally a manifest snippet plus the JSON-RPC request
  that demonstrates the bypass, unexpected allow, unexpected deny, or audit-log
  tampering.
- Your assessment of impact (what an attacker gains if exploited).
- Whether you intend to publish, and any timeline constraints.

We acknowledge receipt within **2 business days**. We aim to publish an advisory
and patched release within **30 days** for high-severity issues and **90 days**
for everything else. If we need more time we will say so explicitly.

## Scope

We are **especially** interested in reports against the following surfaces, since
they are the proxy's core security promise:

| Area | Examples of in-scope findings |
| --- | --- |
| **Policy bypass** | A `tools/call`, `resources/read`, `resources/subscribe`, `resources/unsubscribe`, `prompts/get`, or `sampling/createMessage` that the manifest should have denied but did not. Argument-condition bypasses (e.g. `allowedValues`, `allowedOperations`, `maxCalls`, `timeWindow`, `argumentSchema`) are explicitly in scope. |
| **List leakage** | `tools/list`, `resources/list`, or `prompts/list` returning entries the manifest forbids. |
| **JWT / claims** | Token-validation flaws, claim-intersection errors (JWT widening the manifest), JWKS-handling issues. |
| **Audit integrity** | Any path that produces a record the HMAC chain accepts but that misrepresents the underlying call, silent rotation that loses records, or recovery from a corrupted key file that re-keys without operator action. |
| **Fail-closed regressions** | Any case where an unmapped MCP method, missing manifest, or dependency failure causes the proxy to **forward** instead of deny. |
| **Gateway isolation** | Cross-route policy bleed, `expectVersion` mismatch silently accepted, secret interpolation leaking into logs/audit, route-level kill-switch failing open. |
| **Supply chain** | Issues in the released Docker images, signed binaries, or release workflow. |

The following are **out of scope** for this policy (but see the
[threat model](./docs/threat-model-mcp.md) for the full discussion):

- Vulnerabilities in the upstream MCP server being proxied (those belong to that
  server's vendor).
- Vulnerabilities in the MCP host (Claude Desktop, Cursor, VS Code, etc.).
- IdP / JWKS infrastructure compromise.
- Prompt injection or model behavior — the proxy enforces *what* the agent is
  permitted to call, not *why* the model decided to call it.
- Denial-of-service against the proxy from a host on the same machine.
- Findings that require the attacker to already have write access to the manifest
  file, audit key, or proxy binary.

If you are unsure whether something is in scope, report it anyway — we would
rather see it.

## Verifying a release

Every tagged release is signed with [Sigstore][sigstore] keyless signing from
GitHub Actions OIDC. There is no PGP key to import and no rotation to track —
the signature is bound to the workflow identity
`https://github.com/eunolabs/eunox/.github/workflows/release.yml@refs/tags/<tag>`
and recorded in the public Rekor transparency log.

[sigstore]: https://www.sigstore.dev/

**Verify a downloaded binary** (replace `<tag>` with the release tag, e.g. `v0.1.0`):

```bash
# 1. Download checksums.txt + its Sigstore bundle from the release.
gh release download <tag> --repo eunolabs/eunox \
  --pattern 'checksums.txt' \
  --pattern 'checksums.txt.sigstore.json'

# 2. Verify the signature against the GitHub Actions workflow identity.
#    The signature ships as a Sigstore bundle, so cosign v3+ is required.
cosign verify-blob \
  --certificate-identity-regexp "^https://github\.com/eunolabs/eunox/\.github/workflows/release\.yml@refs/tags/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json \
  checksums.txt

# 3. With the checksums file proven, verify the binary against it.
sha256sum -c checksums.txt --ignore-missing
```

**Verify a Docker image** (`ghcr.io/eunolabs/eunox:<tag>`):

```bash
cosign verify \
  --certificate-identity-regexp "^https://github\.com/eunolabs/eunox/\.github/workflows/release\.yml@refs/tags/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/eunolabs/eunox:<tag>
```

The image signature is bound to the **digest** of the manifest that was pushed,
so a future re-tag of the same name cannot redirect the signature at different
content. Pinning by digest (`...@sha256:...`) is recommended for production
deployments.

**SBOMs.** An SPDX-JSON Software Bill of Materials is attached to every
release archive and native package as `<artifact>.sbom.json`. Feed it to
your SCA tool of choice (`grype sbom:<file>`, `trivy sbom <file>`,
`scancode`, etc.) to surface vulnerable transitive dependencies. The SBOM
itself is covered by the same `checksums.txt` signature chain above.

## How we communicate fixes to users

When a vulnerability is confirmed and patched we:

1. **Publish a GitHub Security Advisory** with a CVE ID. GitHub automatically
   opens Dependabot PRs in every repository that depends on
   `github.com/eunolabs/eunox` via `go.mod` — this is the primary notification
   channel for downstream users.

2. **Record the fix in the release notes and, when the boundary itself moved, in
   [`docs/threat-model-mcp.md`](./docs/threat-model-mcp.md)'s revision history** in
   the same commit that ships the fix. The entry includes: severity (CVSS score and
   qualitative label), CVE ID, affected version range, what was bypassed or
   exposed, and the fix. Pre-1.0 the project keeps no separate curated changelog —
   per-release notes are generated from Conventional Commit prefixes on the
   [GitHub Releases](https://github.com/eunolabs/eunox/releases) page.

3. **Submit to the Go vulnerability database** within 7 days of the patched
   release. This ensures `govulncheck` surfaces the issue for any downstream
   user who runs it, regardless of whether they have Dependabot configured.

4. For **CRITICAL severity** findings we additionally post a heads-up in the
   project's GitHub Discussions so users who do not run Dependabot are not
   solely reliant on automated tooling.

The patched release carries the same Sigstore signature and SBOM as all other
releases (see [Verifying a release](#verifying-a-release) below), so users can
confirm they have fetched the genuine artifact.

## Coordinated disclosure

We follow standard coordinated-disclosure practice:

1. You report privately.
2. We confirm, investigate, and prepare a fix.
3. We agree a disclosure date with you (typically when the patched release ships).
4. We publish an advisory crediting the reporter (unless they prefer anonymity)
   and release the fix.

## Safe harbor

We will not pursue legal action or report to law enforcement against researchers
who:

- Make a good-faith effort to avoid privacy violations, data destruction, and
  service disruption.
- Report the issue through the private channels above before any public
  disclosure.
- Do not exploit the issue beyond what is necessary to demonstrate it.
- Do not exfiltrate user data, pivot to other systems, or use the finding to
  attack third parties.

If your research would otherwise violate the Apache-2.0 license or applicable
law, we authorize it for the purpose of finding and reporting security issues in
`eunox` under the conditions above.

## Hall of fame

Researchers who have responsibly disclosed issues will be credited here (with
their consent) after the corresponding advisory is published.

_No advisories published yet._
