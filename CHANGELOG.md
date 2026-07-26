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
- `mcp.MethodInitialize`, the single spelling of the `initialize` handshake method,
  replacing the bare string literal at every transport site (session-creating POST,
  the notification swallow-list, the re-initialize echo, the drift-refusal record,
  the upstream handshake builder, the protocol-version header gate). It sits beside
  `mcp.MethodNotificationsInitialized`, the other half of the same handshake.

### Changed

- **A refused `Content-Type` is now recorded** as the non-policy denial code
  `UNSUPPORTED_MEDIA_TYPE`, carrying only `details.header_count` — never the
  attacker-supplied header value. It was the one transport-level refusal leaving no
  trace, so a content-type sweep of the sessionless `initialize` POST or the emergency
  stop was invisible while the same actor's wrong-`Origin` attempts were fully logged.
  A *duplicated* header additionally prints an `[eunox] SECURITY:` line, since a reverse
  proxy that re-adds `Content-Type` is the one way an operator trips the gate through no
  fault of their client.
- **The integrity markers' tail fields are renamed `claimed_tail_seq` /
  `claimed_tail_hmac`** (`tail_hmac_mismatch`, `tail_key_unknown`, `tail_unsigned`).
  Both values are read from the record the writer just declared uncertifiable, so they
  are whatever a write-capable attacker put there; signing them under bare names had
  eunox attest an arbitrary value as fact. Matches the `claimed_session_id` convention.
  A SIEM rule keyed on the old names must be updated.
- **`audit-verify` caps the per-record "unsigned record" diagnostic** at 10 lines and
  summarizes the remainder once. The `Invalid` tally is unchanged and still exact; only
  the printing is bounded, so a pre-signing prefix cannot bury a genuine `CHAIN BREAK`
  under one line per record.
- **`POST /mcp` and `POST /control/kill` now require `Content-Type: application/json`**
  and answer `415 Unsupported Media Type` otherwise, failing closed on an absent,
  unparseable, or duplicated header (parameters such as `charset` are accepted; the
  media type is matched case-insensitively). Conformant MCP clients already send it,
  so no honest host is affected. It is defence in depth behind the `Origin` check: a
  POST carrying `text/plain`/`application/x-www-form-urlencoded`/`multipart/form-data`
  is a CORS *simple* request, dispatched with no preflight, and the sessionless
  `initialize` POST — the one `/mcp` entry point with no custom header, and the one
  that spawns an upstream — was the last shape that could reach a handler without one.
  See `docs/threat-model-mcp.md` §3.7.
- **`eunox proxy` returns an exit code instead of calling `os.Exit`**, like every
  other subcommand, so its fail-closed startup rejections are testable in-process and
  the deferred audit-sink flush always runs. Its flag set moved from `ExitOnError` to
  `ContinueOnError` to match its siblings; a usage error still exits 2 and `-h` still
  exits 0, so the observable behavior is unchanged. `buildCallCounterAndKillSwitch`
  and `openConfiguredAuditSink` now return errors rather than exiting internally.
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

- **The pre-HMAC ("legacy tail") audit compatibility path is gone.** An unsigned
  record is never resumed onto and never exempted from verification: the writer
  treats an unsigned tail exactly like an unparseable one (restart the chain from
  genesis, plus a signed `AUDIT_INTEGRITY_FAILURE` marker with
  `"kind":"tail_unsigned"`), and `audit-verify` counts every HMAC-less record
  `invalid` wherever it appears. This deletes the writer's `resumedLegacyTail`
  empty-`prev_hmac` branch and the verifier's lenient-decode fallback,
  `legacy_tail_resumed` marker handling, and legacy/unanchored lattice — roughly 250
  lines whose whole purpose was policing the one splice a write-capable attacker
  could make without the signing key. `VerifyResult` loses `Legacy`, `Unanchored`,
  and `LegacyUnanchored`, and `audit-verify`'s summary line no longer prints a
  `legacy` count. **Migration:** move a pre-signing log aside before upgrading
  (`mv audit.jsonl audit.jsonl.pre-hmac`) and let the proxy start a fresh chain;
  leaving it in place is safe but makes `audit-verify` exit non-zero with one
  `invalid` per pre-signing record until they rotate out. See
  `docs/threat-model-mcp.md` §3.4.
- `circuitbreaker.Config.Validate`. The package had two policies for a degenerate
  config — `New` clamps, `Validate` rejected — and no operator-facing breaker knobs
  exist, so clamping was the only reachable one. Callers relying on the rejecting
  form should check their own fields.
- `drift.ToolsListCursorParams` is unexported; `drift.ToolsListRequest` is the seam
  probes use and builds the whole request.

### Fixed

- `eunox proxy` no longer leaks its cancel function, signal registration, or a failed
  Redis client. All three were unobservable while the function ended in `os.Exit`;
  returning an exit code made them real for any in-process caller.
- The `audit-verify` summary format is a shared constant the site-drift test asserts
  against, and that test now walks `.js` as well as `.html` — the landing page renders
  its terminal demos from a script, so an HTML-only sweep left the most prominent copy
  of eunox's own output unguarded (it had already drifted).
- `drift.ParseToolsListResult` converts each `mcp.ToolEntry` field by NAME instead of
  through a positional struct conversion. The two types share three `string` and two
  `map[string]interface{}` fields, so a same-type reorder in `mcp.ToolEntry` would have
  compiled cleanly while silently transposing the values every `descriptionHash`
  comparison is computed over. A package-level convertibility assertion keeps the other
  direction covered: ADDING a field to either struct without the other now fails the
  build rather than hashing the new field as a zero value.
- The audit lock's "another instance holds the lock" diagnostic compares the errno with
  `errors.Is`, matching the Windows variant; the previous `==` worked only because
  `Flock` returns a bare `Errno`.
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

