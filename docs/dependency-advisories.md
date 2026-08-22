# Dependency advisories

How `eunox` scans for known vulnerabilities, which findings block a merge, and the
standing record for every finding that does not.

## Two scans, two questions

`govulncheck` queries a **live** database. A pinned toolchain therefore goes red on the
calendar rather than on a commit: the next stdlib advisory turns every open pull request
red simultaneously, none of them at fault, none of them able to fix it — the fix is a
toolchain bump, and no contributor's branch should be carrying one.

The failure mode is not the red itself. It is what a red check that nobody's diff caused
does to the other checks: it becomes the normal state and stops being read.

So the scan is split on the axis of **which module the vulnerable symbol lives in**:

| Finding | Where it runs | Gates a PR |
| --- | --- | --- |
| Called, in a module we depend on | `go-ci.yml` → `govulncheck` | **Yes.** A branch that adds or keeps a dependency whose vulnerable code we call is exactly what the scan exists for. |
| Called, in stdlib or the toolchain | Reported on the PR; tracked by `vuln-scheduled.yml` | No. Fixed by moving the Go pin, which is its own change. |
| Not called (`required` / `imported`) | Reported by both | No. Recorded in the register below. |

Both are `scripts/govulncheck.sh`, which classifies the JSON stream; the mode is the only
difference (`--mode gate` on the PR, `--mode report` on the schedule). Running one scan
two ways is deliberate — a second implementation is where the two would start disagreeing
about what counts as called.

`.github/workflows/vuln-scheduled.yml` runs daily against `main` and opens — or updates —
a single issue labelled `vulnerability-scan` when anything is found, and closes it when a
scan comes back clean. An issue is work with an owner; tree-wide red is not.

Locally:

```bash
make vulncheck                    # the same gate CI runs
make check-vulncheck-classifier   # prove the split still gates on the right bucket (no network)
```

The scanner version is pinned in the `Makefile` (`GOVULNCHECK_VERSION`), which both the
script and the workflows read — one source, the same rule as `GOLANGCI_LINT_VERSION`.

### Why "called" is the gate line

A finding at `required` or `imported` level says a vulnerable module is reachable in the
graph, not that this code can execute it. That is also `govulncheck`'s own exit-code rule,
so gating on called findings keeps the gate and the tool's own verdict in agreement.

It is still not a decision. **"Not called" is a true statement about today's call graph**,
and a refactor can turn it false without any advisory changing — the same shape as an
undeclared disposition in the repo's declaration tables. So every non-called finding gets
a line in the register below: either resolved by a bump, or recorded with the reason it
does not apply.

### Which toolchain the scan describes

`scripts/govulncheck.sh` pins `GOTOOLCHAIN` to the toolchain that actually builds this
module for the duration of the scan, then asserts the stream's `config.go_version` came
back as that toolchain. `govulncheck` reports stdlib advisories against the toolchain it
loaded packages with, and `go install pkg@version` honors the *tool's* own `go` directive
— so a future `x/vuln` requiring a newer Go than we build with would otherwise switch the
whole invocation and leave the scan describing a Go that does not ship. The assertion
turns that from an assumption into a check.

Which toolchain that is comes from `go version` rather than from parsing `go.mod`. The
`go` directive is a **language** version, not a toolchain name, and the two differ in
ways that matter here:

- `go 1.27` is a legal two-component value naming no toolchain (releases are `go1.27.0`),
  so using it as a `GOTOOLCHAIN` name fails outright — and comparing it against
  `config.go_version` would fail the assertion on every pull request.
- A `toolchain` directive overrides the `go` directive entirely, so a repo that added one
  would have the scan silently pinned to the wrong Go — precisely the failure the
  assertion exists to catch.

`go version` performs the same resolution the build does, honoring both directives, so
both sides of the comparison are toolchain names.

## Register of non-called findings

Every advisory the gate does not fail on, and what was decided about it. A line leaves
this register only when the advisory no longer applies to the tree at all.

**Current state: the scan reports nothing.** As of the run that landed this file,
`govulncheck ./...` against `go1.26.6` returns 0 in all three buckets — no called
finding, no toolchain finding, nothing at `required` or `imported` level. The entries
below are therefore a record of advisories that were *reachable in the module graph* and
what was concluded about each, not a list of things the scan is currently printing.

### Recorded — reachable in the module graph, not reported by the scan

| Advisory | Module | Disposition |
| --- | --- | --- |
| [GO-2026-6179](https://pkg.go.dev/vuln/GO-2026-6179) | `golang.org/x/mod@v0.21.0` | **Not applicable — recorded.** See below. |
| [GO-2026-6180](https://pkg.go.dev/vuln/GO-2026-6180) | `golang.org/x/mod@v0.21.0` | **Not applicable — recorded.** See below. |

These two are visible when the full module graph is walked (`go list -m all` selects
`x/mod v0.21.0`), which is how they were found. `govulncheck ./...` does **not** report
them: the scan covers the modules providing packages it loads, and no package from
`x/mod` is loaded, so they do not appear even at `required` level. They are recorded here
anyway — a graph walk is a reasonable thing for someone to run, and finding two unexplained
advisories with no written disposition is exactly the gap this register closes.

**GO-2026-6179** (transparency-log tile verification bypass in `x/mod/sumdb/tlog`) and
**GO-2026-6180** (unauthenticated hashes accepted by `x/mod/sumdb`'s `Client.Lookup`) are
both fixed in `golang.org/x/mod v0.40.0`. Neither applies here, and the bump is not
available:

- **Nothing imports it.** `go mod why -m golang.org/x/mod` answers *"main module does not
  need module golang.org/x/mod"*. It reaches the module graph only as a requirement of
  `github.com/rogpeppe/go-internal`, itself a test dependency of a test dependency
  (`gopkg.in/yaml.v3` → `gopkg.in/check.v1` → `github.com/kr/pretty` →
  `go-internal/fmtsort`). No `sumdb` code is compiled into the binary, into any test
  binary, or into any released artifact.
- **There is no upstream bump to take.** `go-internal` v1.16.0, the latest release, still
  requires `x/mod v0.21.0`.
- **An explicit `require` does not survive.** `go get golang.org/x/mod@v0.40.0` records
  the bump, and the next `go mod tidy` removes it again, because no package in the module
  graph imports it. Keeping it would mean a security pin that any contributor silently
  reverts with a routine command and no gate to catch it — a worse state than this record.

The sub-question that would change this answer is whether anything in the tree starts
importing `x/mod`. If it does, these become `imported` or `called` findings, the scheduled
scan re-reports them at the new level, and the resolution then is a real bump.

### Resolved

| Advisory | Module | Level when reported | Resolution |
| --- | --- | --- | --- |
| [GO-2026-5942](https://pkg.go.dev/vuln/GO-2026-5942) | `stdlib@go1.26.5` (`net`) | imported, not called | Fixed in `go1.26.6`; closed by the toolchain pin bump. |

This is the best identification of the "1 vulnerability in an imported package" recorded
alongside the five called stdlib advisories that made the scan red. It is a
reconstruction, not a transcript — the original scan output was not kept, and it is
reached by elimination: of the stdlib advisories open against `go1.26.5`, it is the one
whose package is in the import graph while its symbols are not called. Either way the
disposition is the same, because the toolchain bump carries the fix. The vulnerable symbols are
`net.LookupCNAME` / `Resolver.LookupCNAME`; `net` is in the import graph (transitively,
via `net/http`) but nothing resolves a CNAME, so it never reached `called`. The Go pin
moved to 1.26.6, which carries the fix, and it is no longer reported.
