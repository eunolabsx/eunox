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

- `--killswitch-session-ttl` (Redis backend only) sets how long a **session** kill
  tombstone survives before it is garbage-collected. The lifetime was hardwired at 30
  days with the underlying option reachable only by a library consumer, and when a
  tombstone expires the kill is **lifted** — so a long-lived stdio agent that pins and
  reuses one `--session-id` silently re-admitted a revoked session. A negative value
  restores permanent tombstones; agent kills are never expired. The effective lifetime
  is now printed at startup even at its default, since the expiry undoes a revocation.
- A **successful** `POST /control/kill` now writes an audit record (an allow with
  method `control/kill` and `details.scope` — the killed session id, or `all`).
  Refusals of the endpoint were already recorded and so were the `KILL_SWITCH`
  denials that follow an activation, but the activation itself left no trace, so
  an incident reconstruction had no signed evidence of when the stop was tripped
  or that it was authorized. Written only after the kill takes effect; the control
  token is never recorded. See `docs/threat-model-mcp.md` §3.7.
- `capability.MatchOperation`, plus `Compile`/`AllowsOperation`/`MatchExtensions`/
  `TableLookup`/`MatchDomains` on the `allowedOperations`, `allowedExtensions`,
  `allowedTables`, and `recipientDomain` conditions. `Compile` normalizes a condition's
  allowlist once at manifest load so the hot path stops rebuilding it per request; the
  accessors serve that cached form and fall back to normalizing on the spot for a
  condition built programmatically. The cached form has no invalidation, so a
  condition's allowlist fields are immutable once compiled, and the accessors' results
  are read-only — see the doc comments in `pkg/capability/condition.go`.
- `capability.FloatToInt64`, the single definition of "exactly representable as an
  int64" now shared by manifest-load bound validation and the runtime comparison.

### Changed

- **The Redis kill switch's fail-closed staleness budget is floored against a real
  refresh-cycle cost**, instead of being a bare two reconcile intervals. The budget
  gates a total, non-downgradable denial, and a refresh cycle (a `GET` plus two `SCAN`
  loops, retried when a concurrent kill races the scan) is not proportional to the
  interval — so lowering the interval for faster kill propagation, which the flag's own
  help text recommends, could make that denial **more** likely against a perfectly
  healthy Redis. At the default 30s interval the window is unchanged (60s).
- The session-cap refusal is recorded through the same route-stamped helper as the
  per-session in-flight cap, so one `RESOURCE_EXHAUSTED` code no longer produces two
  record shapes depending on which cap a flood happened to hit. It keeps the
  pre-session rate limit, which the in-flight sibling does not need.
- eunox's own control-token directory (`~/.eunox`) is chmod'ed back to 0700 when an
  older version left it looser, and a control-token path pointing at a group/world-
  **writable**, non-sticky directory is refused: any local user could substitute the
  token there and take over the loopback emergency stop. An operator-chosen directory
  is still never chmod'ed (forcing 0700 on `/tmp` would strip its sticky bit).

- **`capability.EnforceRequest.ToolName` is now `TargetName`** (JSON `toolName` →
  `targetName`). The field always carried every enforced namespace — resource URIs,
  prompt names, `system:` targets — not just tool names, so the old name misread the
  data and forced every helper reconciling it with `Target` to explain the mismatch.
  Library callers constructing an `EnforceRequest` directly must rename the field.
  The input document `BuildRegoInput` produces is unaffected — it exposes
  `input.target.*` and never carried `toolName` — but a custom `PolicyEvaluator` that
  builds its own input by marshaling the `*EnforceRequest` it is handed will now emit
  `targetName`. A Rego rule matching on `input.toolName` would become undefined rather
  than error, which is a silent fail-open, so audit any evaluator that marshals the
  request itself.
- **`killswitch.NewRedis` takes options** — `NewRedis(client, WithFailOpen(...),
  WithReconcileInterval(...), WithLogger(...), WithSessionKillTTL(...))` — replacing
  the chained `With*` setters. Every one of those fields is read by `ShouldBlock` and
  the background loops without synchronization, so their "must be called before
  `Start`" contract was enforceable only by doc comment. Matches `pkg/callcounter`,
  `pkg/flowlabelstore`, and `pkg/circuitbreaker`.
- A whitespace-only literal `upstreamAuthHeader` is rejected at config load, joining
  the guard `listen.authToken` already had. The env-ref leg already rejected a
  reference expanding to whitespace, but it only runs for values containing a
  reference, so a literal one reached neither guard.

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

- **`redactFields` skipped a field sitting directly on a top-level result key.** The
  pass descended into each non-`content`/`structuredContent` key looking for matches
  nested inside its value but never tested the key's own name, so
  `{"content":[...],"ssn":"..."}` forwarded the SSN verbatim while the equivalent
  nested shape `{"data":{"ssn":"..."}}` was masked — same obligation, same field name,
  opposite outcome depending on how deep the upstream put it.
- **A manifest-absent tool forwarded under `--audit` recorded no `sequenceBlock`
  antecedent.** Every other downgradable deny branch records one; this one did not, so
  a later enforced `sequenceBlock` naming a tool an observe run had forwarded Peeked an
  empty history and failed open — breaking "observe predicts enforce" for exactly the
  targets an observe run exists to discover.
- **A `null`, scalar, or array `tools/list` entry poisoned every pinned tool on the
  route.** Such an entry carries no top-level name, so it can impersonate no pin; it
  was nonetheless given the "names unknown" verdict reserved for an entry whose bytes
  defeated the scan, escalating to a sticky, process-lifetime poison of every pin. It
  is still untrustworthy and still pruned from the catalog, but now poisons nothing.
- The JWT list filter's caller-rejecting branches (no claims, audience mismatch)
  returned an empty listing without running the inner PDP's filter, so the
  `descriptionHash` pin was never re-armed from that listing's bytes.
- **`RedactURL` returned a single-slash-typo URL verbatim.** `https:/user:pass@host/x`
  parses with the credential in the path, which no scrub inspected, so the raw value
  was printed. That shape and the scheme-less `user@host/path` form now take the
  conservative whole-value redaction; a genuine authority-less URL (`file:///a@b/x`)
  still keeps its path.
- `trustedProxyHops` joined the gateway config's numeric-coercion guard. A leading-zero
  value (`trustedProxyHops: 010`) was silently read as YAML octal 8, so `sourceIP()`
  picked the wrong X-Forwarded-For entry as the client and misattributed the IP every
  `ipRange` condition on the route evaluates against.
- A resolved audit-retention stall kept being reported on `/healthz` until process
  restart when the sibling count dropped to the retain bound by manual cleanup rather
  than by the delete loop itself succeeding.
- The per-session notification-pool drop is recorded on the audit tape like its
  request-pool sibling. `notifications/cancelled` is the one an incident responder most
  needs, and stderr alone is not the tamper-evident trail.
- The unverified `claimed_session_id` truncates on a rune boundary. A byte-level cut
  left dangling continuation bytes that `json.Marshal` rewrote to U+FFFD, so the signed
  value no longer matched the raw header a SIEM holds for the same request.

- **`sequenceBlock` no longer expires purely by wall clock.** The per-(session,
  tool) antecedent marker was refreshed only by a fresh call to the antecedent, so a
  session that ran the antecedent once had its "deny B after A" guarantee fail OPEN
  24h later even while still live and still probing the blocked target. A blocked
  call that finds the marker now re-arms it, so the window measures inactivity of the
  antecedent/blocked pair. The residual limit — a session quiet on both legs for a
  full window — is documented in the manifest guide.
- The CLI live probe (`init`, `validate --live`, `doctor --live`) skips a stray
  non-JSON line on a stdio upstream's stdout instead of aborting with exit 2. A
  banner or debug print is common in npx-launched servers, and the running proxy
  already skips them, so onboarding failed against servers eunox itself can front.
- A host response dropped on a reaped killed session is audited as
  `http-server-response`, not `http-notification`. That branch is the one place a
  response and a notification share an arm, so the transport-leg detail — which
  exists to distinguish drop sites during an incident — named the wrong site.
- `fetchSpecLive` fails closed on an unknown upstream transport instead of probing it
  as HTTP, matching its `fetchRouteLive` sibling.

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

