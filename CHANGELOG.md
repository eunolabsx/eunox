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
  The proxy **publishes** that lifetime to Redis at startup
  (`killswitch:config:session-kill-ttl`) and `eunox kill --redis-addr` adopts it, so
  the value no longer has to be set identically in two places: the tombstone's expiry
  is stamped by whichever process writes it, and the CLI is the only out-of-band
  revocation channel a stdio proxy has, so its own 30-day default used to expire a kill
  the operator had configured to last longer — silently re-admitting the session. Pass
  `--killswitch-session-ttl` to `eunox kill` only to override, or for a Redis no proxy
  has started against yet; a disagreement resolves to the longer-lived of the two and
  is reported on stderr, and a proxy that replaces a differing published value warns.
- `eunox kill --revive <session-id|all> --redis-addr <addr>` lifts a revocation:
  it removes one session's kill tombstone, or (with `all`) deactivates the global
  kill switch, leaving per-session kills in place. `killswitch.ReviveSession` and
  `DeactivateGlobal` existed but had **no caller** anywhere in the CLI, so with a
  negative `--killswitch-session-ttl` — where tombstones are permanent — the only
  remediation was deleting `killswitch:session:` keys in `redis-cli`. The startup
  banner now names the command. Redis-only by design: the loopback `/control/kill`
  endpoint stays a one-way emergency stop (a same-host caller holding the control
  token must not be able to lift the revocation issued against it), and an in-memory
  kill switch is cleared by restarting the proxy.
- `killswitch.NormalizeSessionKillTTL`, `WithSessionKillTTLEffective`,
  `(*Redis).SessionKillTTL`, `(*Redis).PublishSessionKillTTL`,
  `ReadPublishedSessionKillTTL`, and `DescribeSessionKillTTL` — the shared-TTL seam
  behind the above. `WithSessionKillTTL` keeps the operator-facing sentinels (0 = the
  default, negative = never expire) and now resolves them through the one normalizer;
  `WithSessionKillTTLEffective` takes an already-resolved lifetime, where 0 means
  never expire, so a value read back from Redis cannot be funnelled through the other
  option's sentinels and quietly become a 30-day tombstone.
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

- **A kill-switch audit record's session id is now a type-level distinction**, not a
  convention. The recorders took a plain session-id string, so keeping an unverified,
  client-supplied `Mcp-Session-Id` out of the signed `session_id` field rested on the
  author of each call site reaching for the right one of two near-identical helpers — and
  the wrong choice fails silently, producing a well-formed, HMAC-chained record asserting
  a session the proxy never established. They now take a subject value constructible only
  from an id this proxy established (recorded as `session_id`) or from the request itself
  (recorded as the unverified `details.claimed_session_id`), so a call site added later
  must state which it holds and the wrong choice does not compile. No record changes
  shape. See `docs/threat-model-mcp.md` §3.7.
- **The refusal-record rate limiter's rollup now names its own scope**, and moved off a
  key it shared with an unrelated statistic. Transport-surface refusals (`AUTH_FAILED`,
  `ORIGIN_REJECTED`, `JWT_INVALID`, `LOOPBACK_REJECTED`, …) are the only audit writes an
  unauthenticated caller can trigger, so their rate is bounded by a token bucket and the
  next admitted record carries the count elided since. That bucket is **proxy-wide by
  design** — one bucket is what bounds the sustained write rate into the single shared
  audit queue, and a per-route split would multiply the rate an attacker can drive by the
  size of the route table — so its tally is folded into whichever record is admitted next,
  whatever that record's route or category. The **session cap** is both rate-limited and
  written through the route's sink, so it can pair an `upstream`/`policy_version`/
  `policy_sha256` stamp with a count spanning every route: a bearer-token spray against
  `/mcp/routeA` (refused before route resolution, attributable to no route) surfaced as a
  five-figure count on a `RESOURCE_EXHAUSTED` record reading `upstream: routeB`, which a
  SIEM rule keyed on route + code reads as saturation against routeB's policy digest. Every
  rolled-up record now carries `details.suppressed_refusal_scope: "proxy"`, so the number
  is never inferred from the stamp beside it.
  **Breaking for log consumers:** the count itself moved from `details.suppressed_count`
  to `details.suppressed_refusal_count`. The bare key names the unrelated `*/list` filter
  statistic (catalog entries the manifest hid) in the same `details` object, so a query
  written against it matched both routine policy filtering on an `allow` and an
  unauthenticated refusal flood on a `deny`. Update any rule that reads the refusal rollup;
  a rule that reads the `*/list` statistic is unaffected. See `docs/threat-model-mcp.md`
  §3.7 and `docs/conformance.md`.
- **The `/mcp` malformed-`Content-Type` (`UNSUPPORTED_MEDIA_TYPE`) and malformed-body
  (`INVALID_REQUEST`) refusals are now route-stamped when the route is already known**,
  instead of always being written through the proxy-wide sink like the codes that genuinely
  fire before route resolution (`ORIGIN_REJECTED`, `JWT_INVALID`, …). `handleMCP` 404s an
  unknown upstream before either gate ever runs, so by the time a `/mcp/<route>` body
  reaches them the route is not merely knowable but already known; leaving the record
  unstamped anyway understated what the tape could attribute. This is the same treatment
  the session cap already got, and turns out to matter for the same reason: it is now a
  second record shape the refusal rollup's `suppressed_refusal_scope` field has to qualify,
  since both codes can also carry a rollup from the proxy-wide rate limiter. `/control/kill`
  (no route concept) is unaffected — its refusals stay unstamped. See
  `docs/threat-model-mcp.md` §3.7 and `docs/conformance.md`.
- **`eunox audit-verify` is roughly 40% faster per record**, with no change to what it
  accepts or rejects. It is the tool an incident responder points at a full retained
  archive, so its per-record cost is paid exactly when the record count is largest and
  the answer is most time-sensitive. Every line was being JSON-decoded **twice** — once
  leniently, to count it and place it in the tamper-evident chain, and again strictly
  inside the HMAC recompute — which alone was ~35-39% of the per-record cost. The two
  are now one decode on the path every well-formed record takes; the lenient decode is
  reached only by a line the strict pass rejects, so the leniency difference is
  preserved on purpose (a record carrying an unknown top-level field is still counted
  and still holds its place in the chain, while still being one no verifier may accept)
  rather than as a side effect of two decoders existing. Two smaller allocations in the
  same loop went with it: each key tried used to re-derive the digest through a fresh
  hex string and convert it back to bytes to compare, where the comparison now refills
  one buffer per record (3 allocations per key per record, multiplied by the ring size
  for a record naming no `key_id`), and the canonical-on-disk-form check no longer
  rebuilds a constant-shaped `_hmac` suffix per record. A line that is not a record at
  all — a truncated or padded one — is still decoded once rather than twice, so a
  corrupted archive does not pay for the split. End to end over a signed log:
  58 -> 32 allocations per record.
- The `/control/kill` activation record is written after the kill-store write but
  **before** the SSE eviction and session teardown, which reclaim resources rather than
  effect the stop. The kill is in force the moment the store write returns, while the
  teardown is bounded only by the shutdown budget, so recording after it left a window
  in which a crash produced a tape full of `KILL_SWITCH` denials with no activation
  record to explain them.
- The audit sink's record-dropped warnings are written outside its read lock. They fire
  during a drop storm — precisely when `Close`, which needs the write lock, must make
  progress — and stderr can block indefinitely behind a dead log collector.
- **The Redis kill switch's fail-closed staleness budget is floored against a real
  refresh-cycle cost**, instead of being a bare two reconcile intervals. The budget
  gates a total, non-downgradable denial, and a refresh cycle (a `GET` plus two `SCAN`
  loops, retried when a concurrent kill races the scan) is not proportional to the
  interval — so lowering the interval for faster kill propagation, which the flag's own
  help text recommends, could make that denial **more** likely against a perfectly
  healthy Redis. At the default 30s interval the window is unchanged (60s). The floor is
  a trade: for a refresh that *hangs* rather than errors — the one case this gate is the
  sole detector — a 1s interval now serves the last-known cache for ~31s instead of ~2s
  before failing closed. Faster kill *propagation* is unaffected; only this
  hang-detection window no longer shrinks with the interval.
- The session-cap refusal is recorded through the same route-stamped helper as the
  per-session in-flight cap, so one `RESOURCE_EXHAUSTED` code no longer produces two
  record shapes depending on which cap a flood happened to hit. It keeps the
  pre-session rate limit, which the in-flight sibling does not need.
- eunox's own control-token directory (`~/.eunox`) is chmod'ed back to 0700 when an
  older version left it looser, and a control-token path pointing at a group/world-
  **writable**, non-sticky directory is refused: any local user could substitute the
  token there and take over the loopback emergency stop. An operator-chosen directory
  is still never chmod'ed (forcing 0700 on `/tmp` would strip its sticky bit), and
  neither is a symlinked one — `os.Chmod` follows links and there is no portable
  `lchmod`, so tightening a symlinked `~/.eunox` would rewrite the mode of whatever it
  points at. "eunox's own directory" is decided by resolved location, not by how the
  operator spelled the flag: a systemd unit cannot write `~`, and a shell expands it
  before eunox sees it, so keying on the raw string skipped exactly the deployments the
  upgrade repair exists for.
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

- **`redactFields` missed a declared field inside a doubly-encoded blob under an
  unmodelled result key.** The walk over such a key anchored every dot-path at that
  key's *value*, so a multi-segment path never reached the blob the key names:
  `{"structuredContent":{"data":"{\"ssn\":\"…\"}"}}` masked while
  `{"content":[],"data":"{\"ssn\":\"…\"}"}` — the same shape one key over — forwarded
  the value verbatim. Each sibling value is now walked under both anchorings
  (envelope-relative, so a dotted path reaches into the blob its key names, and
  value-relative, so a container relocated under some other key is still masked) and
  the union is redacted.
- **A failed second `eunox proxy` start broke `eunox kill` against the running one.**
  The control token is written to a shared default path and deliberately overwrites
  what is there, and that write ran *before* `net.Listen` — so an operator who
  accidentally started a second proxy got a clean "address already in use" failure
  from a process that had already replaced the live proxy's token on disk. The
  loopback emergency stop then 401'd until restart, in exactly the confused-deployment
  situation where it matters most. The token is now persisted only after the listener
  binds; a failure at that point closes the listener rather than serving without an
  authenticated control endpoint.
- **`--upstream-timeout` accepted any negative value as "defer to the config".** Only
  `-1` is a sentinel, so a sign typo meant for a 5s bound (`--upstream-timeout -5000`)
  silently produced the 30s default instead. Values below the sentinel are now
  rejected, matching the guard the other numeric proxy flags already carry.
- **An explicit `--audit-rotate-size` / `--audit-retain` overridden by the config's
  audit block was dropped silently**, while the two string flags beside them warned.
  Both now emit the same WARNING. (`--audit-retain`'s explicitness is detected from
  whether the flag was passed, since its `0` is a meaningful "keep all".)
- **A manifest declaring an unsupported `schemaVersion` was reported as a scalar that
  needs quoting.** The content-interpreting guards ran ahead of the version gate, so a
  future-grammar manifest sent the operator hunting a spelling mistake in a
  correctly-spelled file. The version is now probed first, as the gateway-config
  loader already did.
- A pre-session refusal record now always carries `details.source_ip` (it was
  hand-added per call site, and the two that omitted it were the unauthenticated
  Origin probe and the JWT rejection), and the attacker-controlled `Origin` and
  loopback `path` details are length-bounded before reaching the tape or stderr.
- `audit-verify` now reports an unparseable `time` field on `UNKNOWN_KEY_ID` and
  `UNVERIFIABLE` records too; those arms returned before the diagnostic could run, so
  a retired-key record lost its time-drift signal.
- A complete upstream write that returned a deadline error alongside `n == len(frame)`
  poisoned the framed writer and recorded a fabricated `UPSTREAM_TIMEOUT` for a call
  that was in fact delivered. The deadline arm now keys on the byte count like the
  partial-write arm beside it.
- `drift.ParseToolsListResult` refuses an ambiguous `tools` key (duplicated or
  case-variant) itself rather than relying on callers to pre-screen it.
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
  was printed. The guard is anchored on `url.Parse`'s own report that the value carried
  no authority marker, not on a substring scan: a scan for `//` (or `://`) anywhere in
  the string is defeated by one appearing later — in a path or a query
  (`.../x?next=https://portal`) — which echoed the credential. A genuine authority-less
  URL (`file:///a@b/x`) keeps its path, and a scheme-less value
  (`/var/log/eunox@prod/audit.jsonl`) is left alone: it is an ordinary path, and audit
  targets are commonly exactly that.
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
- The unverified `claimed_session_id` is sanitized to valid UTF-8 and then truncated on
  a rune boundary. A byte-level cut left dangling continuation bytes that `json.Marshal`
  rewrote to U+FFFD, so the signed value no longer matched the raw header a SIEM holds;
  and because Go admits bytes >= 0x80 in a header value, a rune walk-back applied to the
  raw bytes could retreat to zero and stamp an EMPTY id for a full-length header.
- `eunox kill --redis-addr` accepts `--killswitch-session-ttl`. The tombstone's TTL is
  applied by whichever process WRITES it, and this is the only out-of-band revocation
  channel a stdio proxy has — so a kill issued here carried the 30-day default even
  when the proxy ran with a longer or never-expiring value, and the session came back.
- A manifest-absent tool forwarded under `--audit` records its `sequenceBlock`
  antecedent only when some `sequenceBlock` actually names it in `afterTools`. That
  branch is the one antecedent site whose target name is not bounded by the manifest,
  and each record costs a call-counter key for the history window — so recording every
  made-up name let a caller mint keys until the counter capped, at which point the
  record fails and the antecedent path returns a hard deny that `--audit` cannot
  downgrade, turning an observe route into a deny-all route.
- `redactFields` no longer masks an MCP-reserved result component wholesale when a
  single-segment path names it (`isError` is a bool, `contents`/`messages` are arrays,
  so a `"[redacted]"` string made the result undecodable). A dotted path *through* one
  — `structuredContent.ssn`, the fully-qualified spelling the manifest guide recommends
  — now resolves to the leaf it names instead of being skipped.
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

