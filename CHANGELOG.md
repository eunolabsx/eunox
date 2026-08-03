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

- **Single-use declassify approvals (`once`).** A `mcp.declassify` grant marked
  `"once": true` is **burned on first use**, so a replay is refused
  `approval_consumed` instead of clearing a flow label again. The burn is keyed by the
  grant's `id` (which `once` therefore makes mandatory), commits atomically through the
  call counter's one admission primitive so two concurrent callers cannot both spend it,
  and is **not** reclaimed by session teardown — a burn a reconnect could undo would make
  "approve this once" mean "once per connection". A grant without `once` still behaves
  exactly as before. See
  [`docs/capability-manifest-guide.md`](./docs/capability-manifest-guide.md).

- **Cross-PEP task anchoring (`taskAnchoredState`).** A new gateway-config key (per-route,
  with a `defaults` fallback) that keys accumulated enforcement state — flow-label taint,
  `sequenceBlock` antecedents, `maxCalls` and cumulative `blastRadius` budgets — on the
  caller's **validated `mcp.task_id` claim** rather than on its session, so state survives
  a hop between enforcement points instead of restarting clean on the far side. Off by
  default: it changes what every budget in a policy *means*. A request with **no token**
  is anchored on its session exactly as before; an **authenticated** request whose token
  omits the claim is refused rather than accounted against a second bucket.

- **Delegation attenuation (RFC 8693 `act` + `mcp.delegation`).** A verified token may
  carry an actor chain and a per-hop grant list that narrow authority across a delegation
  hop on five axes — `targets`, `labels`, `allowLabels`, `redactFields`, `maxEffectClass`.
  A hop that widens one of the three axes asserted at the token boundary (`targets`,
  `allowLabels`, `maxEffectClass`) **rejects the token**; `labels` and `redactFields` are
  unioned across hops and cannot widen, so a hop need not restate its ancestors' values.
  The decision path independently applies every hop, so neither check depends on the other.
  `allowLabels: []` is the quarantine: a delegate sharing a tainted task reaches no labeled
  sink at all. List results are filtered by the chain, so a delegate never sees a tool its
  call leg will refuse. Claim-borne grants are decoded strictly: an unknown member, an
  explicit `null` (which would decode to the field's widest value), or a duplicate key
  rejects the token rather than silently losing the narrowing it declares — checked both
  in a grant's own fields and, separately, in the token's top-level `act`/`mcp` claims and
  the `mcp` block's own members, so an ambiguity in WHICH claim object is selected cannot
  hide from a per-grant decoder that only ever sees the one JSON decoding already picked.
  An `act` object may carry the actor's `iss` and `client_id` beside its `sub`, as a
  token-exchange IdP emits.

- **Signed registry attestations (`eunox contracts --trust-keys`, `--attest-payload`).**
  Effect-contract corpus entries may carry Ed25519 `signatures` over their content digest,
  verified **locally** against a trusted-key file the operator supplies — never fetched,
  and never on the decision path. Role and statement are inside the signed payload, so a
  reviewer's signature cannot be re-presented as a vendor's and a **dispute** cannot be
  edited into an endorsement. A signature from an unknown key is inert; one from a trusted
  key that fails to verify is an error. `--attest-payload` prints the exact bytes a
  publisher signs — eunox verifies attestations and never mints them. See
  [`registry/README.md`](./registry/README.md#vendor-attestation-and-community-review).

- **`schemaVersion "0.2"` — the flow + effect grammar is published.** The tokens that
  shipped behind the `"0.2-draft"` staging string land as **one** batched revision:
  `flowLabel`, `labelOutput`, `declassify`, `effectClass`, `blastRadius`, a constraint's
  `effect` contract, the top-level `effectCeiling`, and the `${task.*}` variables. They
  are documented in [`docs/capability-manifest-guide.md`](./docs/capability-manifest-guide.md)
  and [`docs/effect-contracts.md`](./docs/effect-contracts.md), and published as a machine
  -readable grammar at
  [`schemas/eunox-capability-manifest.schema.json`](./schemas/eunox-capability-manifest.schema.json).
  - `"0.1"` stays **closed** against every one of them: a `0.1` manifest that uses a `0.2`
    token is refused at load, naming the revision that introduced it. That is the same
    rule a misspelled key obeys, and it is what lets a fleet run both revisions without a
    `0.1` route silently acquiring a predicate its authors never reviewed.
  - The published schema is guarded against drift from the Go types by tests that derive
    their expectation from the **condition prototype registry** rather than a mirrored
    list, so a future condition type cannot land without a schema branch.

- **`declassify` — the declassification path.** A directive naming the flow labels an
  action clears, so a policy can express the review/redaction step that legitimately drops
  taint. It is the only token in the grammar that **removes** flow state, and everything
  about it follows from that:
  - The clear happens **only** under a human approval covering every named label at that
    exact target. Approvals ride the `mcp.declassify` claim of a token eunox has already
    verified — the operator's own identity plane, so no new trust root and no fetch on the
    decision path. With no covering approval the call is refused `ESCALATION_REQUIRED`
    rather than forwarded-without-clearing, and the refusal is **hard**: a route running
    `--audit` cannot turn "no human has approved this" into "performed anyway, logged".
  - Scope rules all fail closed: the grant's `target` is matched **literally** (a glob
    would widen one approval across every matching action), its `labels` must be a
    **superset** of what the directive clears (a partial grant escalates rather than
    half-clearing), `approver` is mandatory, and a malformed grant rejects the **token**
    rather than evaluating to a grant that covers nothing.
  - **Three new audit fields**, `labels_cleared`, `approver` and `approval_id`, appear
    together or not at all and are covered by the record HMAC. `labels_cleared` reports
    what actually *changed*, so an approved clear of a label the session never held
    records neither. `eunox stats` counts declassifications separately.
  - **Requires an HTTP host.** Approvals ride a validated JWT and JWT validation needs an
    HTTP listener, so a `declassify` directive on a **stdio host** could only ever
    escalate — it is refused at startup rather than failing on every call. A stdio
    *upstream* behind an HTTP gateway is unaffected.
  - **Honest limit, stated rather than mitigated:** the token is held by the agent, so an
    approval minted into it is replayable for that token's lifetime at any action the
    grant names. Mint a short-lived token per approval rather than a standing grant.

- **`${task.*}` task-context variables** — `${task.id}`, `${task.agent}`,
  `${task.principal}` bind an `allowedValues` entry to the caller's own verified identity
  instead of to a literal. A resolved value is compared by **exact equality**, never as a
  glob (a claim of `*` must not become a wildcard the token holder chose for themselves),
  a reference must be the **entire** value, and an unresolvable one **denies** rather than
  falling back to the placeholder text. A misspelled variable is a load error **under
  `"0.2"`**; under `"0.1"` a `${` remains an ordinary character in a literal value, so an
  existing manifest whose allowlist holds template-shaped text keeps loading unchanged.

- **Interface pinning Tier-2** — every session now auto-baselines the advertised surface
  of **every** tool the upstream reports and re-diffs it on **every** `tools/list`. A tool
  whose surface changes mid-session is denied on the `tools/call` leg and hidden from
  `tools/list`, so the catalog a host is shown never advertises a tool its call leg will
  reject. **On by default: no manifest key, no flag.** This closes the two gaps
  `descriptionHash` leaves — that pin covers only tools an operator wrote one for, and it
  only ran at session init, while MCP lets a server change its tool list mid-session.
  - The deny is **hard**: a route running `--audit` cannot downgrade it to a forward,
    because forwarding to the upstream whose interface was just rewritten is the outcome
    the check exists to prevent. Operators running an observe/wiretap route should know
    this is the one refusal such a route will block.
  - The break is **sticky** and **per session**: reverting the surface does not re-open
    the tool (a host may still hold the rewritten copy), so recovery from a false positive
    is a **new session**, not a proxy restart. The blast radius of a wrong verdict is one
    session, which is why it ships without an off switch.
  - **Honest limit, do not overstate:** this is pure metadata comparison. It catches
    tool-description poisoning and silent interface drift. It does **not** catch a rug pull
    where the advertised interface is unchanged and only the server's behavior differs —
    that is behavioral, and out of scope by design. See
    [`docs/interface-pinning-tier2.md`](./docs/interface-pinning-tier2.md).
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
- `eunox kill --agent <agent-id>` and `eunox kill --revive --agent <agent-id>` target
  the **agent** kill dimension: revoking a JWT `agent_id` stops every session that
  identity holds, which is the natural granularity when one compromised agent spans
  many sessions — previously the choice was killing each session id individually or
  reaching for the global switch. `killswitch.KillAgent` / `ReviveAgent` existed but
  had no caller anywhere in the binary, so an agent kill was not merely un-remediable
  from the CLI, it was unreachable. Both halves ship together deliberately: agent kills
  never expire, so a kill without an undo would be a permanent revocation with no CLI
  remediation at all. Redis-only, like `--revive`: there is no agent dimension on the
  loopback `/control/kill` endpoint, and adding one would widen what a same-host caller
  holding the control token can reach. `--killswitch-session-ttl` is rejected alongside
  `--agent` rather than silently ignored, since an agent kill carries no expiry.
- `eunox kill --session <session-id>` targets a session id **verbatim**. The positional
  `all` means the whole deployment, which left a session whose id is literally `all` —
  possible, since `--session-id` is operator-settable on a stdio proxy — impossible to
  kill or revive individually; `--session all` is that escape hatch. Exactly one target
  may be given (a positional, `--session`, or `--agent`) and supplying more is rejected
  rather than resolved by precedence: on the emergency-stop path a silently ignored
  target is the difference between a revocation an operator believes landed and one
  that did not. Both transports' success lines now carry the dimension
  (`{"ok":true,"killed":"x","dimension":"agent","via":"redis"}`), and so does the control
  endpoint's audit record, since with two id dimensions the id alone no longer says which
  store moved — without it, revoking a session named `all` and halting the whole deployment
  produce an identical response and an identical signed record.
- `eunox kill --reset` was considered and **declined**. `killswitch.Reset` clears the
  global flag, every agent kill, and every session tombstone in one call — the same
  cross-dimension fail-open that `--revive all` deliberately avoids, with a wider
  radius, and a confirmation prompt in front of it is not a design. If bulk revive
  becomes a real operational need, the shape to build is a session-scoped sweep over
  the session-kill prefix. Recorded in `docs/adr/0003-redis-killswitch-fail-open.md`.
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

- **BREAKING (pre-1.0): the four per-token shared-state predicates are one derived predicate.**
  `config.LocalManifest.HasMaxCalls` / `HasBlastRadiusVelocity` and
  `transport.AnyRouteHasMaxCalls` / `AnyRouteHasBlastRadiusVelocity` /
  `AnyRouteHasSequenceBlock` / `AnyRouteHasFlowLabel` are replaced by
  `LocalManifest.AccumulatesSharedState` and `transport.AnyRouteAccumulatesSharedState`. The
  multi-instance advisory ORed the old four together at each of its two call sites; it now asks
  one question, answered from the state class each token declares on its `pkg/capability`
  prototype-registry entry, so a policy using a newly added accumulating token is warned about
  without the advisory being edited. Its wording changed to match ("accumulates cross-call
  state" rather than "uses maxCalls or sequenceBlock"). `HasSequenceBlock` and `HasFlowLabel`
  stay: they answer which engine SUBSYSTEM a policy uses, which is a narrower question with a
  different failure direction (extra work, not a reopened race). Same trigger set as before —
  including a per-call-only `blastRadius`, which still does not warn.

- **The decision turn no longer round-trips a route-wide registry on every enforced request.**
  On a route that anchors accumulated state on the session, the turn's anchor is a per-session
  constant, so resolving it per request took a route-wide mutex, minted a gate entry and deleted
  it again on every call — with contention scaling against the route's whole request rate rather
  than against contending anchors. A session now holds one gate for its lifetime and releases it
  at teardown. Routes running `taskAnchoredState` still resolve per request, which is where two
  sessions sharing a task have to reach the same gate. The `--require-audit=strict` gate on the
  host leg likewise stopped building its declassification detail map at the call site, for a
  gate that returns without reading it whenever the audit trail is healthy — the shape its
  server-initiated twin already had. On the stdio host the turn's anchor is resolved once from
  the identity its single host connection carries and the ticket queue is pinned for the
  proxy's life, so the read loop — which is also the only goroutine routing host replies back
  to the upstream — renders no key and enters no registry per request. No behavior change on
  any path.

- **BREAKING (pre-1.0): the declassification's four response fields are one commit handle,
  and the commit takes nothing else.** `EnforceResponse.LabelsPendingClear`, `Approver`,
  `ApprovalID` and `SpentApprovalID` are replaced by a single
  `Declassification *capability.Declassification` — nil when the decision authorized no
  clear, which is every call in a deployment with no `declassify` directive.
  `Engine.CommitDeclassification` and `pdp.PolicyDecisionPoint.CommitDeclassified` take that
  handle in place of a `[]string`.

  The four fields had a populated-together-or-not-at-all rule that lived in prose, a presence
  test (`len(LabelsPendingClear) > 0`) spelled at four sites, and a `SpentApprovalID` that
  was never anything but `ApprovalID` plus one bit two sites had to keep in agreement — now
  `SpentApprovalID()`, derived. The facts hang off one handle, so they can no longer disagree
  about which decision produced them; what a record carries is still decided by the facts
  (`PendingClear()`, `SpentApprovalID()`), not by the handle's presence. The load-bearing part
  is the parameter: the second phase used
  to accept an arbitrary label set, so an embedder holding an `*Engine` could clear any label
  it named with no approval presented, no grant burned, no escalation raised, and nothing on
  the tape — every gate the declassify surface installs sits on the FIRST phase. The handle
  carries its authorized set unexported and claims single-use, so a clear cannot be widened
  past what the decision authorized and an authorization cannot be replayed into two clears.
  The burn of a `once` grant deliberately stays with the decision: two concurrent decisions
  get two handles, so no per-handle flag could make a grant single-use across them, and the
  atomic ledger admission is what does.

  **Migration:** read `dec.Declassification` (nil-safe accessors: `Labels()`, `Approver()`,
  `ApprovalID()`, `SpentApprovalID()`, `PendingClear()`) and hand the handle itself to the
  commit once the action has SUCCEEDED. Implementers of `pdp.PolicyDecisionPoint` change
  `CommitDeclassified`'s third parameter to `*capability.Declassification`; a decision point
  that holds no flow state must still return an ERROR rather than an empty set, and must not
  claim the handle (a path that cleared nothing must leave the authorization spendable).

- **The decision turn is keyed on the state anchor, not on the session.** A
  flow-/`sequenceBlock`-relevant route serializes its decision phase; that turn used to be a
  per-session lock, which under `taskAnchoredState` did not span the key the state actually
  lives on — two sessions sharing one validated `mcp.task_id` held independent turns over
  shared state, so a source read on one could interleave with the two phases of a
  declassifying call on the other. The turn is now handed out per anchor (the task where the
  route anchors on it and the caller presented one, the session otherwise), resolved through
  the same claim lookup the engine's own key builder uses. With `taskAnchoredState` off (the
  default) the anchor is the session and the behaviour is unchanged. Two sessions on one task
  now queue behind each other for the microseconds of a decision — and, for a declassifying
  call, for its upstream round trip, which is the existing reason not to run `declassify`
  with `--upstream-timeout=0`. The gate is in-process: instances sharing a Redis backend
  still hold independent turns, and the decision-time intersection is what bounds that
  residual — see `docs/threat-model-mcp.md` §3.13.

- **`eunox stats` reports the declassification faults it previously could not see.** It
  decoded six top-level fields and never read `details` at all, so an approved clear that
  failed to apply was byte-indistinguishable from an ordinary allow, and a refused
  declassification from an ordinary `UPSTREAM_ERROR` deny — the benign case had a first-class
  count and the fault cases had none. It now reads exactly three reserved detail keys (behind
  a substring pre-filter, so a tools/call allow's argument map is not parsed per record) and
  reports: failed commits as a called-out `ATTENTION` line, clears that were never applied
  because the call was refused, and single-use approvals spent.

- **BREAKING (pre-1.0): `schemaVersion: "0.2-draft"` is removed, not aliased.** A manifest
  still declaring the draft string is refused at load, with the supported list naming
  `0.2`. **Migration: change the string to `"0.2"`.** No token was renamed and nothing else
  in the document moves. Keeping the draft accepted as a synonym would leave two spellings
  of one grammar in the wild and a second version string every future gate has to remember
  — the shim this project does not carry before 1.0.

- **Every HTTP response-write deadline is armed by one helper, floored at
  `httpWriteTimeout` (30s).** Three legs still computed their own window: the handler
  entry arm, the session-creating `initialize` arm, and the response encode. The first two
  scaled their window with `--upstream-timeout`, which is unrelated to how long the
  *client* may take to read a response — so a deployment running a 50 ms upstream budget
  armed just over five seconds for any response written before the pre-encode re-arm,
  including the early 4xx/404 legs that return without one, and the `initialize` arm armed
  25s against the 30s floor every other leg gets. Both now get the floor. The SSE delivery
  loop's per-chunk arm is deliberately **not** folded in: it is a forward-progress deadline
  re-armed per write, and pooling it with the response rule would kill a slow-but-
  progressing reader mid-frame.
- **`make lint` runs the golangci-lint version CI pins, whatever is on `PATH`,** and
  `.golangci.yml` no longer caps findings (`max-same-issues`/`max-issues-per-linter` are
  0). Installing "only if missing" left any already-installed version in charge, and one
  built with an older Go toolchain than `go.mod` targets refuses to lint at all — which
  reads as "the linter is unavailable here" while CI fails on findings no local run could
  surface. The pin lives once, in the Makefile; CI's Lint job reads it via
  `make print-lint-version`.
- **The session-kill TTL the proxy publishes to Redis now expires, and is refreshed
  while the proxy runs.** The key (`killswitch:config:session-kill-ttl`) carried no
  expiry, timestamp, or writer identity, so nothing distinguished a value a running
  proxy had just published from one left behind by a decommissioned or since-
  reconfigured instance — and `eunox kill --redis-addr`, which adopts it outright in
  the common no-flag case, could therefore write a tombstone that expires (and
  re-admits the session) earlier than the running proxy's own kills. The key now
  carries an expiry of three reconcile intervals, refreshed from the reconcile loop
  the Redis backend already runs, so a value that is readable at all belongs to a
  proxy running now and a *stale* value becomes an *absent* one — which the CLI
  already handles correctly and loudly, falling back to its own lifetime and naming
  it on stderr. No new goroutine, ticker, or connection: the refresh rides the
  existing tick. It also makes the disagreement diagnostic reliable rather than
  startup-only — two differently-configured proxies overwrite each other continuously
  and each reports the other on its next tick, including the case where the second
  started long after the first, which no one-shot comparison can catch. The warning is
  deduplicated on the prior value, so a persistent disagreement is reported once and a
  changed one again — and the dedupe is deliberately not re-armed by an intervening
  agreement, since two proxies ticking at different rates would otherwise alternate and
  print it forever. A **permanent** lifetime (`--killswitch-session-ttl -1s`) is published
  with no key expiry at all: the freshness bound exists to stop a stale value *shortening*
  a revocation, a permanent value cannot shorten anything, and letting it lapse would drop
  `eunox kill` back to its 30-day default on a deployment configured for permanent
  revocations — the fail-open the mechanism exists to prevent. The re-publish is bounded
  and is skipped when the refresh that just ran could not reach Redis, so an advisory
  write can never delay the convergence the reconcile interval bounds. Nothing here is on
  the enforcement path: a proxy always applies its own configured lifetime to the
  tombstones it writes.
- **The control-token file write is now bounded and aborts before publishing.** It runs
  after the listener binds — deliberately, so a second proxy that dies on "address
  already in use" cannot clobber the running proxy's token — but between the bind and
  the accept loop the socket is already completing handshakes nothing answers, so a slow
  write turned a startup race from an immediate connection-refused into a client-side
  hang. The write is not the "small create/rename" it looks like: it stats and possibly
  chmods the directory, creates a temp file, and **fsyncs** it, and that fsync has no
  upper bound on a contended volume or a stalled mount. `AfterListen` now runs under a
  10-second deadline (matching the budget `eunox kill` already gives its own request),
  and the hook runs on its own goroutine so expiry **abandons** it. A bounded context
  alone would not have bounded anything: Go cannot interrupt a blocked fsync, so the
  deadline would only be observed after the stall had already ended — the same hang, plus
  a new startup failure. Abandoning is safe precisely because the writer re-checks the
  context immediately before its publishing rename, so an abandoned write cannot land
  later and clobber the token of whatever proxy is actually serving. On a genuine expiry
  `Serve` fails and closes the listener, so a racing client is refused rather than left
  hanging: a proxy that could not persist its control token has an unusable emergency stop
  and should not come up. A hook cut short by *shutdown* (Serve's own context cancelled by
  a signal) is not a startup failure, so stopping a proxy mid-startup still exits cleanly.
  `transport.WriteControlTokenFile` and `HTTPGatewayOptions.AfterListen` both take a
  `context.Context` (pre-1.0 signature change, no shim).
- **The `/control/kill` handle on the kill switch is now a kill-only interface.** The
  field was typed as the full `killswitch.Manager` — the same interface whose
  `ReviveSession`/`DeactivateGlobal` the CLI reaches — so the invariant that makes the
  endpoint safe (it can issue a revocation and never lift one) was enforced nowhere in
  the package that owns it: "generalize `/control/kill` for symmetry with the CLI" would
  have landed as a three-line additive diff that compiles and passes. It now holds a
  two-method interface exposing `ActivateGlobal` and `KillSession` and nothing else, so
  that change does not compile. No behavior change; the CLI side already held itself to
  the same bar. See `docs/threat-model-mcp.md` §3.3.
- **`tools/list` filtering skips the pin-arming pass when the manifest pins nothing.**
  `filterToolsListResult` called `armPinsFromToolsList` and discarded the result, on the
  strength of a comment claiming the callee self-gates for free — but that gate sits
  *after* the envelope and tools-array decodes, so an unpinned manifest (the common
  shape) paid two full `json.Unmarshal` passes for a value nobody read. With no pin the
  function has no other effect, so the call-site gate is semantics-preserving by
  construction: measured **-19% time and -159 KB/op** on a realistically-shaped 50-tool
  catalog. `RecordObservedToolHashes` keeps calling unguarded — it needs the entry count
  for its audit record — and that asymmetry is now stated at the call site. The package
  benchmark, which built bare `mcp.ToolEntry{Name: ...}` values with no description or
  `inputSchema` and so measured almost none of the per-entry work that dominates the
  path, was replaced with a realistic catalog rather than supplemented.
- **`drift.ParseToolsListResult` keeps its envelope ambiguous-key guard**, deliberately,
  even though every in-tree caller feeds it the pre-screened output of
  `FetchAllToolPages` so the check cannot fire for them today. It is an exported function
  documented as taking raw `tools/list` bytes: the precondition a caller would have to
  satisfy is invisible at the call site, and getting it wrong reopens a
  catalog-substitution bypass rather than failing loudly. A guard whose absence is silent
  belongs on the boundary. Folding the entry screen and the decode into one per-entry pass
  to offset its cost was tried and **reverted** after measurement — encoding/json validates
  before it decodes, so per-entry decodes re-scan the same bytes and add a decoder setup
  and a heap-escaping value each (~380 more allocations and ~10 KB more per call on a
  50-tool catalog, no time saving). The cost is accepted and stated instead.

- **A kill-switch audit record's session id is now a type-level distinction**, not a
  convention. The recorders took a plain session-id string, so keeping an unverified,
  client-supplied `Mcp-Session-Id` out of the signed `session_id` field rested on the
  author of each call site reaching for the right one of two near-identical helpers — and
  the wrong choice fails silently, producing a well-formed, HMAC-chained record asserting
  a session the proxy never established. They now take a subject value constructible only
  from an id this proxy established (recorded as `session_id`) or from the request itself
  (recorded as the unverified `details.claimed_session_id`), so a call site added later
  must state which it holds and the wrong choice does not compile. No record changes
  shape. See `docs/threat-model-mcp.md` §3.7. The residual that type alone cannot close
  — Go's encapsulation is package-scoped, so a composite literal inside the package can
  write the unexported fields directly — is now guarded by a test that parses the
  package's own sources and fails if a literal of that type (or of the two
  session-carrying dispatch params structs) appears outside the files allowed to
  construct one — including a literal whose type is elided inside a slice, array or map.
  Adding a construction site therefore takes a deliberate edit to a security-invariant
  test. It does not cover a zero value mutated field by field, which is not a literal at
  all; the type's doc comment says so rather than implying the residual is fully closed. The broader `forwardParams`/`serverRequestParams` surface was
  deliberately **not** converted to the same type: neither `dispatchParams` constructor
  can receive a raw header at all (one takes a resolved session, the other no arguments),
  so the wrong value is not in scope — revisit if either grows a bare session-id string
  parameter.
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
- **`RESOURCE_EXHAUSTED` records are now written once per saturation *episode*, not once
  per refused request**, at both established-session caps: the concurrent-handler pool
  (the stdio `hostSem` and the HTTP per-session in-flight cap) and the HTTP per-session
  notification pool. The first refusal after the pool last had a free slot is recorded;
  every further refusal while it stays saturated is folded into the next record's
  `details.suppressed_refusal_count`; and a successful acquire ends the episode, so a later
  saturation is recorded again. A per-pool token bucket sits underneath, so a caller
  cycling a pool between saturated and drained cannot open episodes faster than the audit
  drainer absorbs them. What an operator wants from these records is that a pool saturated
  and by how much, not one record per refused frame — and the per-refusal form was a lever
  on the proxy's own availability: the audit queue is bounded and its drop counter
  monotonic, so enough records latch a degraded trail and, under the default
  `--require-audit=strict`, deny every enforced call on **every** route for the rest of
  the process's life. The notification pool was the cheapest way to drive that, since a
  dropped notification costs its sender no upstream round trip and is answered
  `202 Accepted`, byte-identical to a successful forward, so a flooding client gets no
  signal to back off. The gates are per pool and per session, each on its **own** bucket —
  never the proxy-wide one above — so a notification flood cannot elide the request pool's
  record or either of the other bucket's records; every record one of these gates rolls up
  states `details.suppressed_refusal_scope: "session"`, never `"proxy"`. The proxy-wide
  session cap's `RESOURCE_EXHAUSTED` is unchanged: it is reachable without an established
  session, so it stays on the pre-session rate limiter it already shared. See
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
- **Perf, no behavior change.** The JWKS cache no longer copies its key set on a
  `GetKeys` cache hit or the negative-kid suppressed arm (`ForceRefreshForKID` /
  `ForceRefreshForVerify`) when reached from the in-tree token verifier: it
  immediately narrows the result through `FindKeys`, which already returns its own
  independent slice, so the whole-set copy was transient garbage on a pre-auth path —
  up to ~14.4 KB per token at the 100-key cap. The exported cache methods still copy
  for every other caller, whose contract still promises an independent set. Route
  provenance (`upstream`/`policy_version`/`policy_sha256`) is now length-bounded and
  UTF-8-normalized once, when a route (or the stdio proxy's single-route equivalent)
  is constructed, rather than on every audit record — these three are fixed for the
  route's lifetime, so the per-record re-bound was ~100-150 ns of pure waste. And the
  recursive `argumentSchema` unknown-field check folds its check into the same decode
  pass instead of a second full byte-scan at every nesting level, closing an O(depth²)
  manifest-load cost (internal/config imposes no depth or size cap): unmeasurable at a
  realistic depth-3 manifest, but ~89ms -> ~41ms on a synthetic depth-400/16.8KB one.

### Removed

- **The declassification undo, and the three `details` keys it wrote.**
  `PolicyDecisionPoint.RestoreDeclassified`, `Engine.RestoreDeclassifiedLabels` and the
  transport's compensating restore are deleted: with the clear deferred until after the call
  succeeds, a refusal below the decision never removed a label, so there is nothing to put
  back. `details.declassify_reverted`, `details.declassify_orphaned` and
  `details.declassify_approval_id` are gone with them.
  **Migration:** SIEM rules and dashboards keyed on those three keys move to
  `_eunox_declassify_not_applied` (an approved clear that never ran — benign),
  `_eunox_declassify_commit_failed` (the call succeeded and the clear did not — **this is the
  alert**, replacing `declassify_orphaned`), and `_eunox_declassify_spent_approval_id` (a
  single-use grant this call burned, replacing `declassify_approval_id` and now stamped on
  the allow as well). `eunox stats` counts all three.

- **`EnforceResponse.LabelsCleared`, replaced by `LabelsPendingClear`.** The decision no
  longer reports what it cleared, because it no longer clears: it reports what the caller is
  authorized to clear, already intersected against what the anchor was carrying.
  **Migration:** embedders of `pkg/enforcement` read `LabelsPendingClear` and call
  `Engine.CommitDeclassification` with that set verbatim once the action has SUCCEEDED; what
  it returns is what the audit record's `labels_cleared` should carry. A caller that skips
  the commit never clears a label — fail-closed, and visible as a session that keeps
  over-blocking. Implementers of `pdp.PolicyDecisionPoint` rename `RestoreDeclassified` to
  `CommitDeclassified` (`(cleared []string, err error)`); an implementation that holds no
  flow state must return an ERROR rather than an empty set, so a broken chain is not mistaken
  for a clear that legitimately moved nothing.

- **The single-key nested-collision wrapper for reserved detail keys.** A caller argument
  named `_eunox_upstream_error_code` used to produce `{"arguments": {…}, "_eunox_…": …}` — a
  shape indistinguishable from a tool genuinely called with an argument named `arguments`,
  which `eunox suggest` had to disambiguate heuristically. Every reserved-namespace argument
  is now quarantined under `_eunox_reserved_arguments` instead.
  **Migration:** consumers resolving the old nested shape read the new holder key.

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
- **`capability.CallCounter.IncrementIfBelow` and `.AddIfTotalBelow`.** Once every quota
  handler committed through `AdmitAll`, nothing on the decision path called either
  single-bucket method again — `maxCalls` and the cumulative `blastRadius` both admit
  through `AdmitAll` with a one-element batch — yet both stayed **mandatory** on the
  contract. That is the same "two implementations of one semantics that can drift" hazard
  their merger removed one layer up, with a worse failure mode: a custom backend could get
  the retired pair exactly right (they were independently tested, so they would look
  solid) while getting `AdmitAll` subtly wrong, and nothing on the decision path would
  exercise the difference. **Migration:** a custom `CallCounter` implements
  `IncrementAndGet`, `Peek`, and `AdmitAll`; delete the other two. `callcounter.MaxLimit`
  goes with them — a counted bucket's bound is now validated by the shared batch check,
  against the same `MaxWeightedTotal` (2^53) representability limit **plus** the
  whole-number-of-calls rule the retired method's `int64` limit carried in its type (a
  fractional counted bound would otherwise deny silently in memory and fault the Redis
  script's retry pivot — the backend divergence that check exists to prevent).

### Fixed

- **A stdio proxy no longer deadlocks when an upstream emits `sampling/createMessage` during a
  declassifying call.** The server-initiated leg waits for the same decision turn the host leg
  takes, and on stdio it waits *on the upstream reader goroutine* — which is the only goroutine
  that delivers upstream responses to waiting host handlers. A `declassify`-using policy holds
  its turn across the whole upstream round trip (the two phases of the clear are one critical
  section), so a `sampling/createMessage` arriving mid-clear parked the reader on a turn whose
  holder was waiting for a response only that reader could deliver. It unwound when
  `--upstream-timeout` fired and hung the proxy permanently under `--upstream-timeout=0`, and it
  did not require sampling to be *permitted*: the turn is taken before the sampling decision
  runs. That leg now bounds its wait at the same two seconds the HTTP leg uses and fails the
  request closed (`CONDITION_FAILED`, `flowLabel`, `reason: turn_unavailable`). Bounding it
  needed the FIFO ticket to be abandonable — the turn now skips a ticket whose waiter gave up,
  so the give-up costs one deny-by-default request instead of stalling every later request on
  the anchor.

- **A task-anchored session is bound to its state anchor, so its two deciding legs cannot read
  different buckets.** The host leg decides from the current request's validated claims; the
  server-initiated (sampling) leg has no host request in scope and decides from the claims
  captured at `initialize`. The session-owner pin compared only issuer and subject, so a caller
  holding two tokens that differ only in `mcp.task_id` had both accepted on one session — and
  under `taskAnchoredState` those are two anchors: a `labelOutput` source taints one, the
  sampling sink peeks the other, finds it clean, and forwards the egress the flow label existed
  to stop. The anchor-keyed decision turn could not catch it, because the sampling leg's turn and
  its state key agreed with each other and both disagreed with the host leg. On a route that
  anchors state on the task, a request resolving a different anchor than its session's is now
  refused (`AUTHORIZATION_FAILED`, `reason: session_anchor_mismatch`), through the same resolver
  the engine's key builder uses. Routes that do not anchor on the task are unaffected.

- **"Which tokens accumulate cross-call state" is declared by the token instead of listed by
  hand.** The predicate both transports gate their decision turn on was a literal disjunction of
  two per-token predicates, and the same question was asked in four other spellings elsewhere. A
  new condition with `flowLabel`'s shape — peeking shared state in one call, committing it in
  another — would have been absent from all of them: both transports would have run its
  decisions unserialized, reopening the source→sink race, while every completeness test passed,
  since nothing asserted that a token declares this. Each condition and directive
  prototype-registry entry now declares its class beside `Since` (`StateNone`, `StateAtomic` for
  a budget admitted through one atomic `AdmitAll`, `StateNonAtomic` for a non-atomic
  read-then-write), the turn gate and the shared-state advisory derive from it, an unclassified
  token is treated as the strongest class, and a completeness test mirroring the grammar gate's
  fails the build on an entry that declares none. The documented predicate is corrected too: it
  said "reads or writes accumulated state that one call commits and a later one reads back",
  which is equally true of `maxCalls` and a cumulative `blastRadius` — both of which
  deliberately need no turn, because their admission is atomic.

- **The HTTP session's cached decision gate is keyed on the resolved anchor, not on a route
  bool.** The cache decided it was *allowed* to cache by reading the route's task-anchoring
  bit — a hand-written restatement of what `enforcement.ResolveStateAnchor` decides, correct for
  the two anchor kinds that exist and asserted independently of the resolver. A third kind
  (an agent id, a conversation, a delegation chain) breaks every caller of the resolver at
  compile time, but that restatement would have compiled untouched: the session would have kept
  serving turns on the gate it cached while the per-request resolver reached a different one and
  the engine wrote state under the new key, reopening the race for that route with nothing
  failing. Each request now resolves its anchor and compares it to the cached one, which is
  correct for any number of kinds by construction — and extends the fast path to a task-anchored
  session that stays on one task, which the bool could not express. No behavior change today.

- **A future `schemaVersion` no longer refuses the tokens its predecessor published.** The
  manifest loader's grammar gate admitted a token when the base grammar introduced it or when
  the declared revision matched it exactly — correct for exactly two published revisions. A
  third would have refused every `0.2` token under it, *including* a revision published only to
  change semantics that introduces no token of its own, telling operators their `flowLabel`
  condition "requires schemaVersion 0.2" on a manifest declaring `0.3`. The four tokens gated by
  hand rather than by the prototype registry (the top-level `effectCeiling`, a capability's
  `effect` contract, the `${task.*}` variables, and the `_meta` attribution interface) each
  carried the same equality and would have inverted independently — the last of them silently,
  since "off" there means a client's declaration is ignored rather than rejected. Inheritance
  now runs forward along one ordered list of published revisions, which the set of parseable
  versions is derived from as well, so publishing a revision is a data append. No behavior
  changes for `0.1` or `0.2`.

- **A declassification refused by a fault inside the decision no longer puts one approval id on
  the tape under two meanings.** When the decision's own state commit faulted after burning a
  single-use grant, the response handle reported that grant from both the "which approval
  authorized this clear" accessor and the "which grant did this call burn" accessor — and the
  first feeds the top-level signed `approval_id`, reserved for a declassification that actually
  took effect. Such a decision now mints a handle that can only name the burn. Latent: no
  in-tree consumer read the field on a refusal.

- **A declassification committed twice is reported as the wiring fault it is.** A second commit
  of one decision was folded into the flow-store-fault arm, which stamps
  `_eunox_declassify_commit_failed` (the key `eunox stats` raises an `ATTENTION` line on) and
  prints that the session stays tainted — the opposite of what happened, since the first commit
  applied the clear, and an instruction to re-approve work that already landed. Latent: the call
  graph commits at most once per decision.

- **A single-use declassify grant spent on a no-op clear now reaches the tape on the success
  path too.** A `once` approval is burned by the decision that accepts it even when the clear
  resolves to nothing (the anchor was not carrying the approved labels) — burning only on a
  clear that moved a label would make the grant replayable by ordering. The signed
  `labels_cleared`/`approver`/`approval_id` triple rides only a clear that *changed* something,
  so for that call the `_eunox_declassify_spent_approval_id` detail is the only record that can
  ever name the grant — and the commit returned early without writing it. Every refusal path
  named it; the path where the call actually succeeded did not, which is the reconciliation gap
  backwards. An operator reconciling outstanding one-shot approvals would have believed that
  one was still live.

- **The grammar classification is derived from the prototype registry instead of two
  hand-maintained tables.** `pkg/capability`'s condition and directive registries are the
  declared single source of the vocabulary, but the classification a manifest load depends on
  lived one package over as two lookalike maps — one naming the tokens a later revision
  introduced, one naming the base grammar. That split made a wrong answer representable and
  cheap: a `0.2` condition filed in the base-grammar table passes the completeness test (it
  is classified, exactly once) and is then admitted under a `0.1` manifest, which is
  precisely the widening the gate exists to prevent. Each registry entry now declares the
  revision that introduced it (`Since`), the loader reads it through the new
  `capability.TokenSince`, and a token with no `Since` is still refused under every revision —
  the fail-closed direction, kept. Adding a token is two coordinated edits (registry, JSON
  Schema branch) rather than three, and mis-classification is no longer expressible.
  `config.ManifestSchemaVersion01`/`02` are now aliases of `capability.SchemaVersion01`/`02`,
  so one revision has one spelling.

- **The server-initiated leg derives its decision point the same way the host path does, and
  refuses what it cannot honestly commit.** `dispatchParams.withPDP` exists so a field that
  must be the *same* PDP the dispatcher decides with cannot be set independently of it;
  `serverRequestParams` — the upstream→host leg both transports share — assigned `pdp`
  directly at both of its construction sites, so neither the compiler nor a test could see a
  derived field being forgotten. It now has its own `withPDP` constructor, and a source-level
  guard fails the build if any params literal assigns `pdp` or `committer` directly.

  The leg does **not** commit a declassification. It has no honest commit point: "delivered"
  there means the request was buffered onto an SSE channel or written to stdout, and a
  server-initiated request is answered later out of band — so the host path's commit gate (a
  successful reply in hand) has no analogue, and committing on delivery would drop taint for
  work that has not happened. A decision reaching that leg with a clear pending is therefore
  **refused**, hard, with the burned grant named on the record. Unreachable today
  (`requireSourceDirectiveTarget` refuses `declassify` on a `system:` target at load), which is
  the point: that restriction lives in another package, and relaxing it now produces a loud
  refusal rather than a silent wrong clear.

- **The server-initiated leg no longer waits indefinitely for the decision turn.** It runs on
  the session's single upstream-reader goroutine — the same goroutine that delivers every
  upstream response — so blocking it behind a declassifying call's turn (held across a whole
  upstream round trip, and unbounded when `--upstream-timeout` is `0`) stalled every in-flight
  request on that session. Under task anchoring the turn holder can be a different session
  entirely, which made it a cross-session stall. The leg now takes the turn with a bound and
  fails the sampling request **closed** when it cannot get it: sampling is deny-by-default, and
  refusing one request is cheaper than stalling a session's whole response path. The stdio
  transport keeps waiting, deliberately — its gate is FIFO, so abandoning a ticket would stall
  every later one, and its turn cannot span a second session.

- **A declassifying call releases its turn as soon as the commit lands**, rather than when the
  handler returns. Holding it through the audit enqueue and the client-facing response write
  put a window bounded by *the client's* read behaviour inside a critical section that, under
  task anchoring, other sessions queue on.

- **A withheld result is no longer recorded as a call that may never have run.** Three
  gates below the decision refuse a call whose approved declassification therefore never
  commits, and all three shared one record shape. They do not share one fact:
  `--require-audit=strict` blocks before the forward and an upstream transport failure can
  follow a side effect that already happened, so for both it is genuinely unknown whether
  the upstream executed anything — while the **redaction-failure** gate is reached only
  after a reply came back — and "a reply came back" is not the same claim. A reply flagged
  `isError`, a reply carrying an error member beside a result, or bytes eunox cannot interpret
  can all reach that gate and fail redaction, and an upstream can produce any of them at will,
  so the executed fact is stamped only for a reply that passes the same success test the clear
  itself is gated on. The clear is still withheld on that
  exit (the sanitized result never reached the host, so nothing sanitized entered the
  session, which is what a flow label tracks), but the burned `once` grant is then spent for
  a proxy- or manifest-side defect. That refusal now stamps
  `details._eunox_declassify_result_withheld` beside `_eunox_declassify_not_applied`, and
  `eunox stats` counts it, so an operator reconciling the spent grant can tell "retry the
  work" from "the work is done, only the delivery failed" — a distinction the tape did not
  carry. A non-zero count is also its own signal: a `redactFields` path and the real
  response shape disagree.

- **`allowedValues` is one predicate instead of two, and every JWT condition denial now
  carries details.** The JWT capability-claim path hand-copied the engine's
  `handleAllowedValues` — argument resolution, the `MISSING_CONTEXT` arm, the match, the
  `VALUE_NOT_PERMITTED` arm — and the copy had drifted on two axes: no empty-argument guard,
  and no structured `details`. One logical refusal therefore reached the signed tape with
  **two shapes** depending only on whether a token was involved, so a SIEM rule written
  against the manifest path's `allowedValues` denial found nothing for a token-scoped caller,
  and the host-facing error could not name the offending argument (the transport builds it
  from `details.argument`). The same mechanism had already shipped a live defect once, when
  task-variable resolution was added on the manifest side only and every grant carrying a
  `${task.*}` reference denied every call under it. Both paths now call one exported,
  **non-committing** predicate (`enforcement.EvaluateAllowedValues`), so a semantic added to
  it reaches both by construction.

  The sibling `allowedOperations` arm had the same detail-less denials and keeps its own
  deliberately different scan-all-arguments semantics, so it cannot share the handler — but it
  now shares the record **shape**, emitting the same `details` keys the engine records for the
  same denial code. Every deny this layer builds routes through one funnel that applies the
  bound `pkg/enforcement` applies to its own, so a denial's echo of a caller-supplied value
  cannot reach the tape at the caller's chosen length, and a future producer inherits the bound
  instead of having to remember it. `enforcement.BoundDenialDetails` is the exported name for
  that bound (it replaces the unexported spelling; it is deliberately not idempotent, so it
  belongs at a funnel and nowhere else). A typed-nil condition handed to any handler now denies
  rather than panicking the request goroutine.

- **One audit-details merge, one aliasing semantic.** `internal/transport` had two
  implementations of "fold extra keys into a details map" roughly 200 lines apart, with
  different aliasing behavior: one returned its base map itself when there was nothing to
  add, the other always allocated. The always-allocating one was load-bearing — its base is
  the caller's live parsed argument map under `--audit`, and it writes the effect receipt in
  afterwards — so the obvious cleanup of swapping in the helper that now existed in the same
  package would have written a key the caller never sent into the request's own argument
  map, and the signed record would have misreported the request it describes. There is now
  one merge with one semantic (always allocate, except when there is nothing to own, which
  preserves nil-vs-empty), both sites call it, and annotations go through the merge's input
  rather than being written into its result.

- **The `flow` audit discriminator is one shared constant.** `details.flow = true` is the
  cross-cutting marker every information-flow event carries so that one filter finds them
  all, and it was five independently typed string literals across two packages. A rename or
  typo on either side splits an operator's flow query while **nothing fails** — the tape
  stays well-formed, signed and chain-verifiable, and the query just returns less — and the
  records that would vanish from it are the transport-side declassification annotations
  nothing else on the tape reports. It is now `capability.FlowAuditDetailKey`, in the one
  package both producers can import, with a test that fails on any respelling.

- **`resources/unsubscribe` is enforced instead of denied.** It was mapped nowhere, so it
  fell to the fail-closed default in every mode and no manifest spelling could allow it: a
  host that subscribed to a permitted resource could never cancel through the proxy, and
  the upstream kept pushing `notifications/resources/updated` for the rest of the session.
  Denying it protected nothing — cancelling only reduces data flow. It is now authorized
  against the same manifest entry as `resources/subscribe` (the `read` action that
  permitted the subscription permits its cancellation), through a new
  `PolicyDecisionPoint.DecideResourceCancel` that matches by **name and action alone**:
  conditions on the entry are not evaluated and no session state is committed. Metering a
  cancellation would have reintroduced the same dead end through the back door — with
  `maxCalls: {count: 1}` the subscribe spends the slot and the unsubscribe is then denied
  `RATE_LIMITED`, so the stream can be opened but never closed — besides recording a
  `sequenceBlock` antecedent and applying `labelOutput` taint for a request that transfers
  no data. Kill switch, principal scoping, per-route JWT audience, a token's
  `mcp.capabilities` allowlist, and the matched entry's own `enforcement: audit` posture all
  still apply — the last so an observe-mode entry downgrades the cancel exactly as it
  downgrades the read, rather than hard-blocking the one leg that closes the stream the
  other leg opened. **Third-party `PolicyDecisionPoint` implementations must add
  `DecideResourceCancel`.**
- **The audit-mode banners no longer promise more than the dispatcher delivers.** They
  claimed "ALL calls are forwarded and logged but NOT blocked", while MCP methods outside
  the mapped set (`completion/complete`, `logging/setLevel`,
  `resources/templates/list`, …) stayed hard-denied by the fail-closed default. The
  banner now names the dispatched set — derived from the routing tables, so it cannot
  overpromise — and states the caveat. Behavior is unchanged: unmapped-means-deny is
  load-bearing.
- **A transport-conditional flag no longer clobbers a running proxy's state on its way to
  dying.** `--jwks-uri`/`--oauth-*` on a stdio host and `--session-id` on a gateway were
  rejected inside the serve functions, i.e. after the Redis dial, the audit key/log
  creation, and the session-kill TTL publish had all happened. One stray flag therefore
  overwrote another instance's published TTL — the clobber-then-die bug already fixed for
  the control-token file — and minted an audit key/log for a process about to exit. The
  rejections now run with the rest of flag validation, before any side effect, and the TTL
  publish moved into the transports' own ready hooks — the two remaining places a proxy can
  still fail to come up after that validation passes:
  - **Gateway:** the publish runs in the post-bind hook, and now runs *after* the
    control-token write rather than before it. A failed token write aborts startup, so
    publishing first meant the one startup failure that survives the bind still clobbered a
    running proxy's TTL. The hook also re-checks its context, so a shutdown landing in the
    post-bind window publishes nothing.
  - **Stdio:** the publish runs through the new `StdioProxyOptions.OnReady`, fired inside
    `Start` once the session is live. It previously ran just *before* `Start`, ahead of that
    function's own fallible steps — spawning the upstream, the initialize handshake, the
    drift check — so a missing upstream binary or a refused `descriptionHash` pin still
    overwrote a running proxy's TTL on the way to exiting.
- **The effect layer's numeric bounds are covered by the YAML coercion guard.**
  `blastRadius.max`, a `byArgument` case's `value`, and `effectCeiling.maxBlastRadius`
  were outside the check that rejects a literal YAML auto-typed away from its written
  text, so `max: 0600` loaded as an enforced bound of 384.
- **`policy` and `custom` conditions are validated at load.** A blank or whitespace-only
  `backend`/`name` resolves to no evaluator and denies every matching call at request
  time; every other condition whose misconfiguration denies at runtime is rejected at
  load, and these two had no validation arm at all.
- **The contract corpus is checked for semantic validity, not just digest consistency.** A
  digest over nonsense is still a stable digest: an entry with a class outside the closed
  vocabulary (`safe`), a `compensable` contract naming no compensating action, or a blast
  radius declaring both a `value` and an `argument` validated and digested cleanly, then
  failed later at manifest load about a block the author had copied verbatim from the
  corpus. The effect-contract validators moved to `pkg/capability` (which owns the
  vocabulary and the digest) and both layers call them.
- **A `byArgument` case's `compensatingAction` is validated against the inherited class.**
  A row declaring one under a non-compensable base class loaded clean and then had the
  field silently scrubbed at resolution, so the author's declared reversal did not exist.
- **A bare-number `schemaVersion` in a gateway config is diagnosed.** The tolerant version
  pre-read was string-typed, so `schemaVersion: 0.1` (YAML auto-types it `!!float`) failed
  it, the error was swallowed, the version gate never ran, and the strict decode reported
  the whole document with an opaque `cannot unmarshal !!float into string`. The gate now
  reads the scalar's verbatim text and the error says to quote it.
- **The process-group teardown signals the direct child first, and only then the
  group.** `os.Process.Kill` consults Go's own reaped-process state, so a call racing a
  completed `cmd.Wait` sends no signal at all; a raw `kill(-pid)` has no such guard and
  the kernel resolves it against whatever holds that pid *now*. Several teardown paths
  genuinely race a `Wait` — the stdio SIGKILL timer that `stopKillTimer` deliberately
  does not join, the HTTP session's close timer against its cleanup goroutine, the
  writer-poison hook — and since every upstream is a group leader, the likeliest holder
  of a recycled pid is another session's upstream. Killing the leader first restores the
  idempotence those call sites document, and keeps the pid reserved so the group id
  stays valid for the call that follows. The group signal also refuses `pid <= 1`:
  `kill(-1, …)` is "every process the caller may signal", not "the group led by pid 1",
  and an upstream can legitimately land on pid 1 inside a PID namespace.
- **A wrapper-launched upstream (`npx`, `uvx`, a shell script) could hang shutdown
  forever.** Both bounded teardown paths — the startup watchdog and the host-EOF
  shutdown — end by waiting for the upstream's stdout to reach EOF, but the kill
  signalled only the direct child. An MCP server started through a wrapper runs as a
  *grandchild* holding the same pipe, so SIGKILL-ing the wrapper left the pipe open, the
  EOF never arrived, and the mechanisms built to *bound* a wedged upstream hung
  indefinitely — skipping the audit-sink flush graceful shutdown performs, and leaking
  the orphan besides. Upstream subprocesses are now started in their own process group
  and torn down as a group (unix; a no-op elsewhere), and both post-kill waits are
  bounded independently so a descendant that escapes the group delays nothing. The HTTP
  transport's per-session subprocess gets the same treatment, where the leak was one
  orphan per session.
- **The audit write queue's byte budget did not bound what it claimed.** The budget
  exists so a slow disk sheds audit records — counted and marked — instead of OOM-ing
  the proxy, and three things undercut it. The enqueue charged its bytes *after* handing
  the record to the channel, so the drainer could credit a record before it was charged
  and the counter went transiently negative, under-reporting in-flight heap under
  exactly the burst-plus-slow-disk conditions the budget exists for; the charge is now
  reserved before the send, which also makes the check atomic across concurrent
  enqueuers. The drain *recomputed* the record's size after `writeRecord` had stamped
  `seq`/`prev_hmac`/`_hmac` through it, balancing only by the unenforced coincidence
  that none of those three was counted — the charge is now stored on the record and
  credited back exactly. And two attacker- or operator-influenced fields were neither
  bounded nor counted (see Security).
- **A malformed audit tail was recorded as an HMAC mismatch.** Verification
  strict-decodes a record before computing any MAC, so a tail with an unknown top-level
  field, trailing bytes, or malformed JSON is refused before a key ever sees it — yet
  the chain resume wrote a `tail_hmac_mismatch` marker, asserting a comparison that
  never ran and pointing an operator at a tampering remediation for what is usually a
  malformed or forward-versioned line. It now writes `tail_strict_decode_refused`. The
  fail-closed behavior (restart the chain from genesis, mark it in band) is unchanged.
- **A strict-drift session could miss the checks it was strict about.** The covering-set
  used by the startup drift comparison kept only the maximum-specificity manifest entry,
  on the premise that a less specific one is always shadowed — but the engine filters by
  principal *before* it scores. With a principal-scoped exact `tool:read_file` beside an
  unscoped `tool:read_*` glob, every caller who is not that principal is governed by the
  glob, yet the drift pass saw only the exact entry and never ran the glob's FM-1/FM-3/
  FM-6 checks. Since FM-1/FM-2/FM-6 abort startup under strict drift, a strict
  deployment booted believing it had verified drift it had not. The cutoff is now the
  highest specificity among the *unscoped* matches, which is the point below which an
  entry is genuinely shadowed for every caller.
- **A partial write that timed out was recorded as an upstream error, not a timeout.**
  The framed writer split its two sentinels purely on byte count, so "the subprocess
  stopped draining stdin" landed as `UPSTREAM_TIMEOUT` when the frame fit the pipe
  buffer and `UPSTREAM_ERROR` when it did not — the classification turning on payload
  size rather than on what failed. A partial write accompanied by a deadline expiry now
  carries the timeout sentinel; the framing is desynced and the writer poisoned either
  way.
- **`eunox kill --killswitch-session-ttl` is no longer silently dropped without
  `--redis-addr`.** (Landed alongside the flag itself; noted here because the guard is
  what makes the flag's own documentation true.)
- **The `suggest` subcommand emitted mined manifest entries with Go quoting.** Target
  names, argument names and observed values were rendered with `%q` rather than the
  YAML-safe renderer `init` already used for the same job. Go and YAML disagree on
  `\xNN` — a raw byte to one, the code point U+00NN to the other — so a draft could load
  cleanly while naming a string that is not the one observed. Both now share one
  renderer; the drafts are also more readable, since values that need no quoting no
  longer get any.
- **The JWKS cache handed out its live key set from the forced-refresh paths.**
  `ForceRefreshForKID` and `ForceRefreshForVerify` returned the cached pointer directly
  on both their suppressed and fetched arms, re-opening the slice-aliasing hole
  `copyKeySet` was added to close — on the two paths a caller reaches during a key
  rotation. Both now copy, like `Refresh` and `GetKeys`.
- **`eunox proxy` never released its Redis connection pool** on the paths that succeed
  and later return; only the ping-failure branch closed it, on a rationale that applies
  to every exit.
- **`eunox_audit_maintenance_stalled` stayed `0` through several faults that stopped
  rotation or retention entirely.** If the audit log's directory became unlistable *after*
  startup, rotation kept working (it needs only an `Lstat` once its ordinal seed is
  certain) while every prune pass failed to enumerate the rotated siblings — that exit
  logged one line to stderr and returned without reporting anything, so retention never
  ran again, siblings accumulated until the volume filled, and `/healthz`, `/metrics` and
  `doctor` showed green through exactly the condition the signal exists to surface. A
  rotation that could not establish a free rotated name at all (an `Lstat` that fails for
  any reason other than "absent" counts the candidate as occupied, so a directory
  returning `EACCES`/`EIO` on every probe defers rotation as durably as an unseedable
  ordinal) was equally unreported, and so — found in a follow-up pass — were a failed
  rename of the active log, a failed sync of the just-renamed sidecar, and a failed reopen
  of the fresh base, both immediately after a clean rename and on every bounded
  fallback-recovery retry: any of these leaves the active log growing past
  `rotateSizeBytes` with nothing on `/healthz` to show it. Every one of these exits now
  reports through the maintenance status; `rotate()` and `pruneRotated()` are each a thin
  wrapper that computes its own outcome and records it once, at a single exit, so a future
  branch added to either can no longer skip reporting the way these did.
- **A healthy retention pass could clear a live rotation stall.** Rotation and retention
  wrote one shared stall flag, so every report of health was a cross-subsystem write and
  the leg that finished last decided what the operator saw. The status is now two
  independent fields, one per subsystem, and each leg publishes its own once, at the
  single exit above — so a recovery in one never erases the other's stall.
  `auditMaintenanceReason` on `/healthz` correspondingly reports every stalled subsystem,
  prefixed `rotation deferred:` or `retention stalled:` and joined with `; ` when both are,
  in a fixed order rather than "whichever failed most recently" — so an operator sees
  which of the two disk bounds is unenforced.
- **`redactFields` missed a declared field inside a doubly-encoded blob under an
  unmodelled result key.** The walk over such a key anchored every dot-path at that
  key's *value*, so a multi-segment path never reached the blob the key names:
  `{"structuredContent":{"data":"{\"ssn\":\"…\"}"}}` masked while
  `{"content":[],"data":"{\"ssn\":\"…\"}"}` — the same shape one key over — forwarded
  the value verbatim. Each sibling value is now walked under both anchorings
  (envelope-relative, so a dotted path reaches into the blob its key names, and
  value-relative, so a container relocated under some other key is still masked) and
  the union is redacted. `structuredContent` itself had the identical gap one call site
  over: its own value was walked value-relative only, so the manifest guide's
  recommended fully-qualified spelling — `structuredContent.ssn` — silently redacted
  nothing when `structuredContent` was *itself* delivered as a doubly-encoded JSON
  string, while the bare `ssn` spelling against the same blob already worked. It now
  shares the sibling walk's both-anchorings logic instead of a second, hand-copied one.
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
- **The per-category refusal-record budget raised the unauthenticated audit-write
  ceiling ~8x.** Splitting the pre-session bucket by refusal category (see Security,
  above) gave every category the FULL pre-split rate/burst instead of a share of it,
  so the sustained ceiling an unauthenticated caller could drive rose from 20/s
  (burst 50) to as much as ~160/s (burst ~400) with no measurement behind the new
  number — the same aggregate the bound was introduced to hold. Categories now
  divide one aggregate budget instead of each replicating it (each share floored at
  one token, so a future category count cannot divide a share down to zero and stop
  refilling it), restoring the ceiling to at or under its original bound while
  keeping the no-cross-category-suppression property the split exists for. See
  `docs/threat-model-mcp.md` §3.7.
- **An encoded NUL (`%00`) riding alongside some other malformed `%` escape in a
  path-confinement value produced one of two different denial messages depending on
  what else in the value failed to decode**, splitting one smuggling attempt's
  taxonomy in two for an operator or SIEM rule watching for the NUL-truncation
  denial specifically. The decoder that already arbitrates NUL-vs-malformed-escape
  precedence now owns both spellings of NUL (literal and encoded), so the two
  lenient-fallback call sites that used to each carry their own encoded-NUL check no
  longer need to.
- **A startup-watchdog-killed HTTP session could hang indefinitely instead of
  failing closed.** The three other bounded-wait-after-kill sites (stdio's host-EOF
  drain and startup watchdog, the HTTP session's `close`) each bound their post-kill
  wait independently, so a descendant that escaped its process group could not hang
  them past that bound — but the HTTP session's own startup watchdog (`initUpstream`)
  was never given the same bound, so the identical escaped-descendant case could hang
  session establishment forever. All four now share one helper.

### Security

- **A declassification's label clear is now two-phase, and the second phase runs after the
  call.** The clear used to commit *inside* the decision, while the transport releases its
  per-session decision lock immediately afterwards so the slow upstream forward is not held
  under it. For the whole round trip — bounded only by `--upstream-timeout`, and by nothing
  at all when that is `0` — every concurrent decision on the session therefore read an
  already-clean label set, so a sink the taint existed to stop could be **allowed and
  forwarded while the sanitizing call was still in flight**. The compensating undo that
  shipped alongside it ran *after* the round trip, i.e. after the window it was meant to
  cover, so it narrowed the fail-open and could not close it; under `taskAnchoredState` the
  window was wider still, since the decision lock is per-session and does not span a task key
  two sessions share. The decision now only **authorizes** the clear and the removal happens
  once the call has actually run and its redacted response is deliverable, so the labels are
  never absent until the action that clears them has completed — and that holds without
  depending on any lock. `labelOutput` and the `sequenceBlock` antecedent still commit inside
  the decision (extra taint over-blocks), and so does the **burn** of a single-use grant,
  which is the atomic test that makes `once` mean once.

  Deferring alone would open the mirror race, so two things bound it. **What** to clear is
  fixed at decision time (the approved labels intersected against what the anchor is carrying,
  inside the decision's critical section), so a taint a concurrent source read asserts during
  the round trip is not in the set and cannot be laundered by it. And a declassifying call
  **keeps the per-session decision turn** until its commit lands, so nothing interleaves
  between the two phases; every other call still releases before the forward. The cost is
  head-of-line blocking on that one session for the length of one declassifying call, bounded
  by `--upstream-timeout` — which a route using `declassify` should therefore not set to `0`.

  The clear now also requires the call to have **succeeded**. A sanitize whose upstream
  answers with a JSON-RPC error, or with a tool result flagged `isError`, is delivered to the
  host and is not a transport failure, so it previously reached the commit with nothing
  sanitized and dropped the taint anyway. It is now recorded exactly as a refused call.

  The residual fails in the safe direction: a commit fault leaves the label in place, so a
  later sink over-blocks until the operator retries under a new approval. A session is
  deliberately **not** marked sticky-untrusted for it — there is no longer any state in which
  the proxy knows a session's taint is missing.

- **A caller's tool argument can no longer forge an operator alert.** eunox's reserved
  `_eunox_*` detail keys ride an **allow** record whose `details` IS the caller's argument map
  under `--audit`, and `eunox stats` raises an `ATTENTION` line off one of them. A client
  sending an argument with that name landed it on the signed tape spelled as a proxy
  statement. Reserved-namespace arguments are now quarantined under
  `_eunox_reserved_arguments` before the record is built — preserved for the auditor, never in
  a position where they read as something eunox asserted. This replaces a single-key nested
  fallback that covered only the upstream-error code and produced a `{"arguments": {…}}` shape
  a miner could not distinguish from a tool genuinely called with an argument named
  `arguments`.

- **A spent single-use approval is now named on the tape.** A `once` grant is burned by the
  decision that accepts it — including on a clear that turns out to change nothing, since
  burning only on a clear that moved a label would make the grant replayable by ordering —
  while `labels_cleared`/`approver`/`approval_id` appear only when the clear *did* change
  something. A real approval could therefore be spent with nothing anywhere on the signed
  tape naming it, so an operator could not answer "which of my outstanding one-shot approvals
  are still live?" — silent in the direction of believing you still hold an approval you do
  not. Every call that burns one now stamps `details._eunox_declassify_spent_approval_id`, on
  the allow and on any refusal below the decision alike, kept distinct from `approval_id` so
  one key never carries two provenances.

- **`internal/config`'s grammar gate no longer fails open on an unclassified token.**
  `tokenGrammarVersions` — the guard whose whole job is stopping a later revision's predicate
  from silently widening an earlier one — was consulted with a comma-ok, so a condition or
  directive missing from it was **admitted under `schemaVersion "0.1"`**, and no test walked
  `pkg/capability`'s prototype registries against it. It is now paired with an explicit
  `baseGrammarTokens` table, the two are total over the vocabulary, a token in neither is
  refused under every revision, and tests walk `KnownConditionTypes()`/`KnownDirectiveTypes()`
  against both (plus assert every later-revision token is refused under `0.1`).

  The loader's per-directive validation moved to a table keyed by the same registry. Because
  that dispatches on the discriminator a directive *reports* rather than on its Go type, each
  entry honours its type assertion instead of discarding it: a value whose report disagrees
  with its type is refused with a diagnostic, where a discarded `ok` would have dereferenced
  nil and turned a fail-closed load error into a crash.

- **`redactFields` fails closed on a result whose object keys are ambiguous.** The
  redaction path was the one JSON surface in the codebase without a duplicate-key gate:
  it decodes an upstream result with `encoding/json` (last key wins) and, when no path
  matched anything, returns the **original bytes verbatim**. So an upstream answering
  `{"content":[…],"data":{"ssn":"…"},"data":{}}` under `redactFields: ["data.ssn"]`
  presented the proxy an empty `data`, redacted nothing, and was forwarded byte-for-byte
  — rendering the ssn on any first-wins host parser (`JSON.parse`, the Python SDK) while
  the audit record reported the obligation applied. The same smuggle worked one layer
  down, inside a JSON text content item, where the envelope never sees those keys at all.
  Both now run the same streaming key scan the request path and the `*/list` filters
  apply, and deny the response when it fires: a duplicate key at any depth, or a
  case-variant collision on a key the redaction depends on resolving — a segment of a
  redact path (the masking walk looks its segments up exactly) or one of the envelope's
  protocol-reserved keys (`ApplyRedactObligs` dispatches on those exactly, so `Content`
  alongside `content` would take the lenient generic walk instead of the content-array
  pass and its fail-closed resource guard). Case variants of names the obligation does not
  touch are ordinary data and are not refused; the fold is narrower here than on the
  request and `*/list` paths because those decode into Go structs, where the decoder's own
  case-insensitive field matching makes every case-variant sibling a divergence, while the
  redaction walk decodes into a generic map. The exactly-dispatched set includes a content
  ITEM's `type` and `text`, not only the envelope keys: `{"type":"text","text":"benign",
  "Text":"<secret>"}` otherwise left the redactor inspecting the benign body while a
  case-insensitive consumer rendered the sibling, with nothing matched and the original
  bytes forwarded.
- **The audit HMAC key is opened under the symlink guard, and chmod'd through the
  handle.** The key is the one audit file whose redirection is unrecoverable — the log is
  HMAC-protected, but whoever chooses the key chooses what verifies — and it was the only
  audit path read with a plain `os.ReadFile` (which follows symlinks) and re-moded by
  path (which follows one to its target, with a re-resolution race between the stat and
  the chmod). It now opens with `RefuseNonRegularPath` + `O_NOFOLLOW` and tightens
  through the open handle. **Migration:** a key delivered through a projected secret
  mount (Kubernetes materializes each key as a symlink into a timestamped `..data`
  directory) must now set `EUNOX_AUDIT_KEY_ALLOW_SYMLINK=1`; the resolved file must still
  be a regular file either way.
- **Rotation makes its directory entries durable.** `rotateAttempt` fsynced the rotated
  file's *data* but neither the rename nor the fresh base's creation, both of which only
  dirty the parent directory inode in cache. A power loss in that window replays the
  directory to its pre-rotation state, so the records the fresh base already fsynced sit
  in blocks nothing references: restart resumes cleanly from the old tail and
  `audit-verify` passes over a log that silently lost every post-rotation record. No
  attacker required.
- **An out-of-vocabulary flow label is an error, not something to drop.**
  `peekSessionLabels` filtered a stored label outside this build's vocabulary and called
  it fail-safe. The sink rule is *present and not in `allow` ⇒ deny*, so removing a
  present label can only **suppress** a denial — reachable when two proxy versions with
  different vocabularies share one Redis flow store. It now fails closed, matching every
  sibling path.
- **`--audit` no longer hides the misconfigurations it exists to find.** `maxCalls`
  honored the observe-mode quota skip *before* its nil-counter / empty-session /
  empty-target-name guards, so an audit run recorded ALLOW exactly where enforce mode
  writes `MISSING_CONTEXT` / `CONDITION_FAILED`. Only the counter increment is skipped
  now; the structural validation runs in both modes.
- **A session established across a global kill sweep can no longer register.** The reap
  generation was captured *after* the pre-spawn kill gate — a gate that itself does a
  kill-store round-trip — so a kill activating inside that window produced a generation
  equal to the post-sweep one, and the session registered anyway, pinning an upstream and
  a `maxSessions` slot with no reaper to collect it when `sessionIdleTimeoutMs` is 0.

- **Exact numeric comparison bounds the literal it parses.** The fix that made
  integer comparison exact above 2^63 (below) reaches `big.Rat.SetString`, whose
  mantissa scan is superlinear and whose exponent handling materializes 10^N — so an
  unbounded parse would have been a CPU/memory denial of service on the pre-forward
  enforcement path, reachable with a single tool-call argument (arguments decode in
  UseNumber mode and arrive as verbatim literal text). Measured un-guarded: a 1M-digit
  fractional literal cost ~1.8 s of one core and the nine-byte `1e1000000` ~25 ms and
  ~1 MiB, each multiplied by the number of `allowedValues`/`enum` entries. A literal
  length cap and an exponent-magnitude cap now gate the parse, matching the bounds
  `internal/mcp` already applies to the same parse for the same reason; anything past
  them takes the float64 path, exactly as before the exact arm existed. The exactness
  the arm exists for is unaffected — integers around 2^63 need tens of digits.
- **A single denied tool call could write an unbounded amount into the HMAC-signed
  audit tape.** Most condition handlers echo the caller-controlled value that failed
  their check into `denial.Details` — the argument that missed an `allowedValues`
  allowlist, the path whose extension was refused — because that echo is what makes a
  deny actionable to the operator reading it back. Nothing bounds a tool-call argument
  before the condition check runs, so an agent that can trigger repeated condition
  denials with large arguments inflated the signed log at whatever rate it could issue
  calls: the same kilobyte-per-byte amplifier already closed for the rejected `Origin`
  header and the loopback endpoints' `path`, reached post-authentication through an
  argument instead of pre-authentication through a header. Every denial's `details` are
  now bounded — 512 bytes per string value, an 8 KiB budget charged across the whole
  map (which bounds an argument that decoded to a large *container* whose elements are
  each individually small), and 8 levels of nesting (which bounds a chain of empty
  containers that costs nothing against the byte budget). Elided values carry fixed
  marker codes rather than prose, and keys are walked in sorted order so two identical
  denied calls write identical records rather than differing by Go's randomized map
  iteration. The bound is applied at the single point every enforcement deny passes
  through, not at each handler's own `Details` literal, so a handler added later
  inherits it by construction — the ~20 sites could not otherwise be kept in sync. This
  is a log-growth and log-poisoning-scale fix: no policy decision, HMAC, or chain
  property was affected.
- **The audit record's denial taxonomy and route provenance were stamped without a
  length bound.** `denial_code` and `condition_type` are compile-time constants for the
  built-in engine, but a deployment wiring an external policy evaluator (OPA, Cedar) or
  a custom condition handler receives them as operator-supplied strings that reached
  the record verbatim — unbounded, they could push a record past the 4 MiB scanner
  buffer every other envelope field is bounded to stay under, and they were not counted
  against the write queue's byte budget either. `upstream`, `policy_version` and
  `policy_sha256` were likewise stamped raw, skipping the UTF-8 normalization the HMAC
  round-trip depends on. All five now take the same 8 KiB bound as `target` and
  `session_id`, and the two denial fields are counted by the queue budget.
- **A cheap refusal flood could erase the evidence of an expensive one.** The
  pre-session refusal records — the only audit writes an unauthenticated caller can
  trigger — shared one proxy-wide token bucket across every refusal category, so a
  spray of `Origin` probes (one request each, no credential) absorbed the entire budget
  and suppressed a *concurrent control-token brute force* into a number folded onto
  somebody else's record. That is the record an incident responder reads first. Each
  refusal category now has its own bucket, spanning every route, so a flood in one
  cannot elide another; `details.suppressed_refusal_scope` reads `"proxy_category"` in
  place of `"proxy"`. Per-category state is a fixed handful of counters (categories are
  code-supplied literals, and the map is capped regardless), unlike the per-source
  state the global counter was chosen to avoid.
- **An encoded `%00` riding alongside a malformed percent-escape bypassed the
  fail-closed NUL rule.** The path decoder catches an encoded NUL only *after* a
  successful unescape, so any other bad escape in the value made the unescape fail
  whole — and both lenient fallbacks then matched the literal form without scanning for
  the token. `evil.exe%00x%zz.csv` therefore cleared an `allowedExtensions: [".csv"]`
  check and a slashless `"*.csv"` glob while a NUL-truncating upstream opens
  `evil.exe`. The encoded separator got this rides-alongside guard when the lenient
  fallback was introduced; the NUL token — which the confinement rules say must always
  deny — did not, and the `allowedExtensions` fallback scanned for neither. Both are
  now checked on both fallbacks.
- **Exact numeric matching lapsed to lossy `float64` above 2^63.** Numbers are
  preserved as `json.Number` end to end specifically so two distinct integers sharing a
  `float64` are never conflated, but the comparison fell back to `float64` whenever
  *neither* side was `int64`-representable. `allowedValues: [9223372036854775808]`
  then admitted the argument `9223372036854775809`, and an argument strictly above
  `maximum: 9223372036854775808` passed the bound — a fail-open on a boundary, above
  int64 instead of above 2^53. Both comparisons now use exact rationals when both
  operands are integers, at any magnitude. Genuinely fractional operands still compare
  as floats, where a decimal literal and its 64-bit approximation are consistent on
  both sides.
- **A constraint carrying a null or typed-nil condition was downgradable under audit
  mode.** The engine fails closed on a condition it cannot evaluate, but the deny did
  not set `HardDeny`, so an audit-only constraint (or a route under `--audit`) forwarded
  the call — with a restriction the policy declared but the engine never checked even
  once. Its two sibling engine-bug denials both set the flag; this one now does too.
- **`Constraint` and `ArgumentSchema` decoded JSON leniently, silently widening a
  policy.** The condition decoder rejects unknown fields because a lenient decode drops
  a *misspelled* key and leaves a policy quietly wider than written. The same applies
  one level up: `{"target":…,"principals":{…}}` — a misspelled `principal` — decoded
  with `Principal == nil`, which applies the constraint to **every** caller, and
  `{"type":"string","maxLen":8}` validated length not at all. Both decoders now apply
  the same key-membership check, which recurses through nested `properties`/`items` for
  free. The binary's manifest loader ran its own recursive check already; these are the
  exported Go seams a library consumer reaches without it.
- **The audit log's sidecar lock file now carries the same symlink guard as every other
  audit-path open.** Every truncating or appending open on an operator-configured audit
  path pairs a portable `Lstat` refusal with `O_NOFOLLOW`; `acquireAuditLock` carried
  neither. Nothing is ever written through that handle, which is presumably why it was
  missed — but the lock's *exclusivity* is the payload, not its bytes: `flock` /
  `LockFileEx` applies to whatever the open resolved to, so a symlink planted at
  `.<log>.lock` ahead of first use sends a second instance's lock to a different inode.
  Both instances then believe they hold the audit log and append to it, forking the
  tamper-evident HMAC chain — the exact outcome the lock exists to prevent — without
  ever touching the log file. The audit directory is not trusted enough to make this
  theoretical: `MkdirAll` sets `0700` only on a directory it *creates*, so a log path
  pointed at a pre-existing group- or world-writable location carries no mode guarantee,
  and that is precisely where another uid can plant the link. Windows gets the portable
  half only, as elsewhere in the package. **Behavior change:** a deployment that
  deliberately symlinks the lock file (no reason to, but it was silently permitted) now
  fails startup with an error naming the lock file.
