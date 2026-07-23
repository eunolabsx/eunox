# Contributing to eunox

Thanks for considering a contribution. `eunox` is an Apache-2.0,
deny-by-default capability firewall for MCP servers — its job is to **say no
correctly**. Most contributions are welcome; a few have special handling
because the project sits in a security-enforcement path.

This document is the practical guide. The deeper docs it points at are:

- [`README.md`](./README.md) — what the proxy is and how to use it.
- [`docs/repo-guide.md`](./docs/repo-guide.md) — prerequisites, layout, build,
  test, debug.
- [`docs/threat-model-mcp.md`](./docs/threat-model-mcp.md) — what the proxy
  enforces and what it cannot.
- [`docs/capability-manifest-guide.md`](./docs/capability-manifest-guide.md) —
  the manifest grammar and the condition catalog.
- [`SECURITY.md`](./SECURITY.md) — how to report a vulnerability.

---

## Before you open an issue or PR

### Security vulnerabilities — do not file public issues

If you've found a way to bypass policy, smuggle past list filtering, forge an
audit record, downgrade fail-closed behavior, or anything similar, please
follow the private channel in [`SECURITY.md`](./SECURITY.md). Public issues
are for everything else.

### Bug reports

Open a GitHub Issue. The most useful reports include:

- `eunox --version` (or the commit SHA / Docker tag).
- A **minimal** manifest fragment and the JSON-RPC request that reproduces it.
- What you expected vs. what happened. For audit-tape oddities, include the
  raw record (with the HMAC field redacted if you prefer).
- Whether it reproduces against the `:latest` Docker image, so we know it's
  not local environment.

### Feature requests

Open a GitHub Issue describing the *use case* — the agent behavior you want
to permit or block, the manifest grammar that would express it, and how it
relates to existing condition types. A request grounded in a real scenario
("I want to allow `read_file` only when the agent's `mcp.task_id` claim
matches `X`") is much easier to scope than a generic capability ("we should
support more conditions").

### Discussion before a large change

Open a draft PR or an issue with the design **before** writing a lot of code,
especially for:

- New condition types (they multiply across the manifest surface).
- Changes to the manifest grammar or audit-record shape (these are
  user-visible contracts).
- Anything touching JWT validation, claim intersection, or fail-closed
  behavior.

For typo fixes, dependency bumps, and small bug fixes — just open the PR.

---

## Development setup

`make` targets are the source of truth.

```bash
git clone https://github.com/eunolabs/eunox.git
cd eunox

make build           # → bin/eunox
make test            # go test -race ./...
make lint            # go vet + golangci-lint
make check-license   # Apache-2.0 header on every .go file
make check-notice    # NOTICE matches the binary's third-party modules
make coverage        # write coverage.out
```

Full prerequisites (Go 1.26.5+, golangci-lint v2.12+, Docker) and the
repository layout are in [`docs/repo-guide.md`](./docs/repo-guide.md).

The end-to-end demo lives under [`demo/`](./demo/) — `make -C demo up` is the
fastest way to exercise a real proxy with a mock upstream and verify a
behavior change end-to-end.

---

## Pull request workflow

1. **Fork** the repository and create a topic branch off `main`. Branch names
   are free-form; a short slug is fine (`fix/jwt-claim-intersection`,
   `feat/condition-allowed-headers`).
2. **Write tests first when reasonable.** Every new condition type, every new
   fail-closed branch, every audit-record field change needs a test. CI gates
   coverage at 80% average for `pkg/` and separately for `cmd/`; new code at
   lower coverage will likely block.
3. **Run the gates locally** — `make test && make lint && make check-license`
   — before pushing. CI runs the same gates, plus the `pkg/`/`cmd/` coverage
   check and the demo integration suite.
4. **Open a PR** against `main` and fill in the
   [PR template](./.github/pull_request_template.md). The "Security
   considerations" section is not boilerplate — please answer it.
5. **One change per PR.** Mixed PRs (a refactor *plus* a behavior change)
   are much harder to review and roll back. Split them.
6. **Address review** by adding new commits — do not force-push until the
   review is finished, or it makes diffs across iterations unreadable. Squash
   on merge is fine.

---

## Commit message conventions

We use [Conventional Commits](https://www.conventionalcommits.org/). The
prefix maps directly onto release-notes grouping in
[`.goreleaser.yml`](./.goreleaser.yml):

| Prefix | Used for | Appears under |
| --- | --- | --- |
| `feat:` | a new user-visible capability | 🚀 Features |
| `fix:` | a bug fix | 🐛 Bug Fixes |
| `sec:` | a security hardening | 🔒 Security |
| `docs:` | docs only | hidden from release notes |
| `test:` | tests only | hidden |
| `ci:` | CI / workflow / release tooling | hidden |
| `chore:` | maintenance, dep bumps | hidden |

Add `!` after the prefix for a breaking change (`feat!: rename
manifest.policy → manifest.capabilities`) and include a `BREAKING CHANGE:`
footer describing the migration.

Examples:

```
feat: add allowedHeaders condition for resources/read

fix: deny resources/subscribe when manifest has no resource entries

sec: tighten JWT claim intersection when manifest grants are absent

feat!: rename TimeWindow.windowSeconds → window

BREAKING CHANGE: existing manifests using `windowSeconds` must be migrated
to `window` (an ISO-8601 duration string). See docs/capability-manifest-guide.md.
```

---

## License headers and DCO sign-off

### License header

Every `.go` file (source and test) must carry the Apache-2.0 SPDX header at
the very top:

```go
// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0
```

`make check-license` enforces this in CI and locally.

### Developer Certificate of Origin

By contributing, you certify that the contribution is yours to submit and
that you agree to the [Developer Certificate of Origin
1.1](https://developercertificate.org/). We don't use a CLA — only a DCO.

**Sign every commit** with `-s`:

```bash
git commit -s -m "feat: ..."
```

This adds a `Signed-off-by: Your Name <you@example.com>` line to the commit
message. Maintainers check for it during review. To sign off a series of
existing commits you forgot to sign, `git rebase --signoff origin/main` will
fix them in place.

---

## Style and design conventions

The codebase has a strong house style — please read the surrounding code in
the area you're changing before introducing a new idiom. A few load-bearing
rules:

- **Fail closed, then say why.** On any ambiguity — missing manifest, unmapped
  method, malformed JWT, unset condition argument — the proxy denies. Denials
  surface a structured error code (`AUTHORIZATION_FAILED`,
  `CONDITION_FAILED`, …) and are logged. New code paths must preserve this.
- **Argument shapes are part of the contract.** Conditions match a specific
  argument name; do not silently match alternatives. If you need to support
  variation, do it explicitly in the condition definition and document it in
  the manifest guide.
- **Audit records are append-only and structured.** Never rewrite a record,
  never log free-form text in a structured field, never invent a new top-level
  field without updating the threat model.
- **No telemetry.** The proxy does not phone home. Adding any background
  network activity needs explicit design discussion first.
- **Pre-1.0, no backward-compat shims.** When changing manifest grammar, audit
  shape, or config keys, change them cleanly and document the migration —
  don't accumulate shims that have to be carried forward.
- **No emojis in code or comments.** README and the site can use them; source
  files should not.
- **Comments explain *why*, not *what*.** Don't restate the code; do explain a
  non-obvious constraint, a workaround for a known upstream behavior, or
  a security-relevant invariant.

### Tests

- All test files end in `_test.go`. Race detector must pass.
- For new condition types, add table-driven tests under
  `pkg/capability/`. Include at least one allow case, one deny case, and one
  malformed-input case.
- For new MCP method coverage, add an enforcement-gap-style test in
  `internal/transport/enforcement_gaps_test.go`.
- For new audit-record fields, add a sign-and-verify round-trip test.

### Documentation

- Behavior changes need a docs update in the same PR. Reviewers will ask
  for it if missing.
- Manifest grammar changes need an update to
  [`docs/capability-manifest-guide.md`](./docs/capability-manifest-guide.md)
  *and* a corresponding change in the public spec repo
  ([`eunolabs/agent-capability-manifest`](https://github.com/eunolabs/agent-capability-manifest)).
- Schema changes need [`schemas/`](./schemas/) updated and a roundtrip test.
- Dependency changes that add or drop a third-party module linked into the
  binary need a matching [`NOTICE`](./NOTICE) update. `make check-notice`
  (CI-enforced) verifies the module list against the binary's non-test build
  closure; the license and copyright lines are hand-curated, so add or remove
  a stanza when the check flags drift. A pure version bump needs no change.
- Keep an eye on the upstream maintenance status of runtime modules. Note that
  `gopkg.in/yaml.v3`'s upstream is archived; it is retained because it is
  stable and has no open advisory, but track a maintained replacement and plan a
  migration before any future advisory forces one. Run a vulnerability scan
  (`govulncheck ./...`) as part of release prep.

---

## What we generally won't merge

- **Refactors that mix in behavior changes.** Split them.
- **Helper layers added on speculation.** "We might need this later" is not
  a reason. Three similar lines beat a premature abstraction.
- **Backwards-compatibility shims** for pre-1.0 changes. Just change the
  thing.
- **New runtime dependencies** without strong justification. The proxy is one
  static binary on purpose.
- **Detection-evasion features**, exfiltration helpers, or anything whose
  primary use is offensive against a system the operator does not own. The
  proxy is a defensive product.

---

## Roles and becoming a maintainer

You don't need any role to contribute — fork, branch, and open a PR. Most
contributors stay contributors permanently, which is healthy.

Trust *over the repository* is a separate thing, and for a security-
enforcement proxy the bar for write access is deliberately high: a commit
that weakens fail-closed behavior is a supply-chain event for every operator
who deploys eunox. We grant write access only to people with a sustained
track record who have provably internalized the fail-closed invariants and
the security boundary. There's also a lighter-weight **Triager** role for
regulars who help with issue and PR hygiene.

The full ladder and the criteria for each step live in
[`GOVERNANCE.md`](./GOVERNANCE.md).

---

## Releases and versioning

Maintainers cut releases by tagging `vMAJOR.MINOR.PATCH`; the release playbook
is maintained internally. Contributors shouldn't need to think about this — but
if your PR introduces a breaking change, please flag it in the description so the
next release notes call it out.

---

## Communication

- Bug reports and feature requests — GitHub Issues.
- Vulnerability reports — see [`SECURITY.md`](./SECURITY.md).
- Design discussion — open a draft PR with a sketch and a description.
- Anything else — `security@eunolabs.ai` (also reaches the maintainers; this
  isn't only a security inbox in practice).

Thanks again for contributing.
