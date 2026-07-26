# Changelog

All notable changes to `eunox` are recorded here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning 2.0.0](https://semver.org/).

> Per-release notes are also auto-generated on the
> [GitHub Releases](https://github.com/eunolabs/eunox/releases) page from
> Conventional Commit prefixes (see
> [`CONTRIBUTING.md`](./CONTRIBUTING.md#commit-message-conventions)). The
> file you're reading is the **curated, human-edited** changelog —
> Releases is the raw feed. Both coexist; reach for whichever fits your
> use case.

Section conventions:

- **Added** — new user-visible capabilities (condition types, transports, CLI flags).
- **Changed** — behavior or output changes that are not strictly bug fixes.
- **Deprecated** — features still present but planned for removal.
- **Removed** — features deleted in this release.
- **Fixed** — bug fixes.
- **Security** — vulnerabilities fixed or mitigations added (also tracked in [`SECURITY.md`](./SECURITY.md)).

---

## [Unreleased]

### Added

- A **successful** `POST /control/kill` now writes an audit record (an allow with
  method `control/kill` and `details.scope` — the killed session id, or `all`).
  Refusals of the endpoint were already recorded and so were the `KILL_SWITCH`
  denials that follow an activation, but the activation itself left no trace, so
  an incident reconstruction had no signed evidence of when the stop was tripped
  or that it was authorized. Written only after the kill takes effect; the control
  token is never recorded. See `docs/threat-model-mcp.md` §3.7.
- `capability.FloatToInt64`, the single definition of "exactly representable as an
  int64" now shared by manifest-load bound validation and the runtime comparison.

### Changed

- **`eunox validate` usage errors now exit 2, not 1.** Exit 1 is reserved for
  "drift warnings present, operator review required" — the code CI pipelines gate
  on — so a misspelled flag or a missing manifest argument previously read as a
  policy finding. **Update any pipeline that treats a non-zero `validate` exit as
  interchangeable:** 1 now means findings only, 2 means the command could not run.
- `eunox doctor` returns an exit code instead of terminating the process from
  inside flag parsing, so its failure paths are testable. Side effect: an unknown
  flag now exits 1 (matching `suggest` / `stats` / `audit-verify`) rather than the
  flag package's 2. `-h` still prints usage and exits 0.
- A config `listen.oauthResource` / `listen.oauthAuthorizationServers` that
  overrides an explicit `--oauth-resource` / `--oauth-authz-server` now warns,
  matching the audit-path resolver. Config still wins.
- `~` expansion accepts the native `~\...` spelling on Windows (the separator test
  is `os.IsPathSeparator`, not a literal `/`), which was previously refused.

### Removed

- `circuitbreaker.Config.Validate`. The package had two policies for a degenerate
  config — `New` clamps, `Validate` rejected — and no operator-facing breaker knobs
  exist, so clamping was the only reachable one. Callers relying on the rejecting
  form should check their own fields.
- `drift.ToolsListCursorParams` is unexported; `drift.ToolsListRequest` is the seam
  probes use and builds the whole request.

### Fixed

- A gateway route configured with no audit sink wrapped `nil` in a `routeSink`, so
  every "no sink configured" fast path in the shared enforcement core was dead —
  `*/list` catalogs were decoded and counted with nowhere to record them.
- The audit queue's byte budget under-counted each record by up to ~40 KiB of
  individually-capped `target` / `method` / agent / task / user fields, so a flood
  of such records could hold far more heap than the budget is sized to bound.
- The startup audit-tail read no longer re-opens the log a second time to fetch the
  chain-resume line: the tail is read once, through the already-held append handle,
  under the exclusive audit lock. The second open was the transient-failure mode the
  first was rewritten to eliminate.

