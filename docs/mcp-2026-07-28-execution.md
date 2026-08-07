# MCP 2026-07-28 execution plan

**Status:** planning. Companion to [mcp-2026-07-28-plan.md](mcp-2026-07-28-plan.md),
which states what changes and why. This document states the work as workstreams —
concrete deliverables, the tests each one owes, and the exit criteria that say when
it is done. Workstream sections are keyed to the plan's numbered items.
**Verified against:** eunox @ `5dba99c`.

References name a **file and a symbol, never a line number**.

---

## How to read this

- **Sizing** is relative, not calendar time. S: contained, few files. M: one
  subsystem plus its tests. L: cross-cutting, new invariants. XL: new subsystem
  plus an ADR.
- **Exit criteria are verifiable**: a named test that passes, a behavior
  demonstrable in the e2e harness, a document in a named state. "Mostly done" has
  no checkbox.
- Every workstream additionally owes the **blanket criteria** (below). They are
  stated once and implied everywhere.

### Blanket criteria (every workstream)

- `make test` green (`-race -count=1`), `make lint`, `make check-fmt`,
  `make check-license`, `make check-notice`.
- Coverage stays at or above the CI gate (80% for each of `pkg/`, `internal/`,
  `cmd/`) — `make coverage`.
- Behavior changes carry their docs update in the same PR; manifest-grammar
  changes also update `docs/capability-manifest-guide.md`, `schemas/`, and the
  spec repo, with a roundtrip test.
- New audit-record fields carry a threat-model update and a sign-and-verify
  roundtrip test. New audit code *values* carry a threat-model note.
- Conventional Commits with DCO sign-off.
- **2025-11-25 regression invariant:** no workstream may change the wire behavior
  eunox presents to a 2025-11-25 peer. The existing test suite is the regression
  net; where a refactor touches old-revision paths, the old×old e2e cell (W13) is
  the arbiter.

---

## Decision gates

Four decisions block code. Each lands as an ADR in `docs/adr/`; the gate's exit
criterion is the ADR reaching **Final** under the ADR lifecycle
([docs/adr/README.md](adr/README.md)).

| Gate | Decision | Recorded in | Blocks |
|---|---|---|---|
| D1 | Translation boundary: which methods eunox translates across a mismatched host/upstream revision pair, and which pairs it refuses. Also: `server/discover` filter reuse, `x-mcp-header` posture, `Mcp-Session-Id` retirement, and the mixed-revision-per-connection rule. | [ADR-0006](adr/0006-dual-revision-translation-boundary.md) (Draft) | W1 activation, W3, W4, W13's mismatch cells |
| D2 | MRTR metering: the signed continuation — key sourcing, anchor binding, lifetime, replay bound, what re-evaluates per retry, and the commit-once quota rule. | [ADR-0007](adr/0007-mrtr-signed-continuation.md) (Draft) | W6 |
| D3 | Session creation without `initialize`: what mints the internal HTTP session, how requests map to it, what happens unauthenticated, and where `--require-audit=strict` gates. | [ADR-0004](adr/0004-bearer-identity-session-anchor.md) (updated: session-creation addendum) | W2, and through it W6/W7 |
| D4 | Stream and deferred-effect enforcement: `subscriptions/listen` open/deny semantics, notification filtering, cancel rehoming; tasks anchor binding and the kill×tasks interaction. | [ADR-0008](adr/0008-stream-and-task-enforcement.md) (Draft) | W7, W8 |

W1's table refactor and W2's subject-struct reshape are behavior-neutral and may
land while their ADRs are still Draft; anything that changes wire behavior waits
for Final.

---

## Workstreams

### W1 — Negotiation spine (plan §1) — L

**Depends on:** nothing (seam half); D1 (activation half). **Blocks:** everything else.

Scope:

- Replace the `MCPProtocolVersion` constant in `internal/transport` with a
  supported-revision set. Host-side revision resolved per request — from `_meta`
  `io.modelcontextprotocol/protocolVersion` for 2026-07-28 peers, from the
  `initialize` params for 2025-11-25 peers. Upstream-side revision resolved at
  probe time and pinned per `UpstreamRoute` (gateway) / per proxy (stdio).
- Make the four routing tables revision-scoped — `decideMethodHandlers`,
  `locallyAnsweredHandlers`, `forwardableHostNotifications`,
  `swallowedHostNotifications` in `internal/transport/dispatch.go` — derived from
  **one declaration per method** carrying its revision membership, mirroring the
  prototype-registry pattern `pkg/capability`'s `TokenSince` already uses. Removal
  is expressed by absence: a method outside the requesting peer's table falls to
  `dispatchUnmapped` exactly as unknown methods do today. No second mechanism.
- `UNSUPPORTED_PROTOCOL_VERSION` (-32022) response builder in `internal/mcp`;
  fail closed on a missing or unknown `_meta` revision from a peer on the new
  revision.
- Config surface: per-upstream `protocolVersion: auto | "2025-11-25" |
  "2026-07-28"` on `internal/config.UpstreamConfig` plus the flag equivalent for
  single-route mode; `schemas/` gateway-config schema updated with a roundtrip
  test.
- Audit: stamp the decided revision on each record (new structured field —
  blanket criteria apply: threat model + sign/verify roundtrip).
- Mixed-revision rule per D1: dispatch honors each request's declared revision;
  session-scoped constructs exist only where the old revision created them.

Tests:

- A derivation test asserting each revision's **exact** dispatch set, built from
  the declarations (the `sortedMethods` pattern), so membership cannot drift from
  routing. A method declared without revision membership fails the build — the
  `TestTokenSince_…` pattern.
- `internal/transport/enforcement_gaps_test.go`: per-revision unmapped denials —
  `ping` from a 2026-07-28 peer denied; `server/discover` from a 2025-11-25 peer
  denied; `notifications/roots/list_changed` from a 2026-07-28 peer dropped and
  recorded.
- Missing/unknown `_meta` revision → -32022, audited.

Exit criteria:

- [ ] One declaration per method carries revision membership; absence fails the build.
- [ ] Old-revision wire behavior unchanged through the refactor (full suite + old×old e2e cell green).
- [ ] -32022 on unsupported or missing protocol version, with audit record.
- [ ] Config key + flag + schema + roundtrip test landed.
- [ ] Revision field on audit records with threat-model update and sign/verify roundtrip.
- [ ] ADR-0006 Final before any translation behavior activates.

### W2 — Bearer identity, session creation, revocation (plan §2) — XL

**Depends on:** D3. **Blocks:** W6, W7; the HTTP transport for 2026-07-28 entirely.

Scope:

- Decode `jti` (the parsed registered claim) into `JWTClaims` and the request
  context in `internal/pdp/jwt.go`. This flips a documented deliberate absence:
  update the rationale comment and the duplicate-key oracle expectations in
  `jwt_std_claims_dupkey_test.go`, which currently assert that nothing decodes it.
- Collapse `ShouldBlock`'s positional identity arguments into one value-struct
  subject (`{AgentID, SessionID, JTI, …}`), passed by value to stay off the
  hot-path allocation budget. Update both killswitch backends and both PDPs;
  the kill check stays first in decision order.
- `RevokeJTI`/`ReviveJTI` on `killswitch.Manager`. In-memory backend: one more
  map. Redis backend: a jti key namespace plus revoke/revive events on the
  existing pub/sub channel (`pkg/killswitch/redis.go`, `handlePubSubMessage`),
  with the reconcile commit notifying as kills do, so `ObserveRevocations`
  consumers reclaim on jti revocation too.
- Operator surface: `--jti` on the kill subcommand (`cmd/eunox/kill.go`) and a
  `jti` field on `POST /control/kill` (`internal/transport/http_routing.go`).
- Audit: token-id field on the record (blanket criteria apply).
- **Session creation on first request** for 2026-07-28 HTTP peers: mint the
  internal `httpSession`, spawn the upstream, and run `registerSession` (pin,
  `gateCache`, reaper) exactly as today — but triggered by the first enforced
  request rather than `initialize`, keyed per D3 (recommended: the stable
  identity via `enforcement.ResolveStateAnchor`, so stateful policy keys and the
  session map cannot disagree; revocation on the finest unit, `jti`). The
  `--require-audit=strict` gate relocates to this path. Unauthenticated
  new-revision requests follow D3's ruling. The old-revision `initialize` path is
  untouched.
- stdio: accept a handshake-less first request; the session is the process
  lifetime, nothing to mint.

Tests:

- Killswitch table tests, both backends: revoke → deny (`KILL_SWITCH`), revive →
  allow, pub/sub delivery, reconcile-path notification (miniredis).
- Reclaim-on-jti-revocation on the HTTP transport (the `ObserveRevocations` path).
- First-request session creation: serves without `initialize`; strict-audit gate
  refuses per D3's rule; teardown/reap behavior unchanged.
- Audit roundtrip for the token-id field.
- Benchmarks: `BenchmarkDecisionTurn_*` within noise; `ShouldBlock` remains
  allocation-free with the struct subject.

Exit criteria:

- [ ] ADR-0004 updated with the session-creation half and graduated to Final.
- [ ] jti revocation end-to-end in e2e: CLI flag → control endpoint → next request denied `KILL_SWITCH` → audit record carries the token id.
- [ ] Subject struct landed; adding JTI required no signature change beyond the struct field (demonstrated by the diff itself).
- [ ] A 2026-07-28 host's first HTTP request serves with no `initialize`, on both auth postures D3 admits.
- [ ] Token-id audit field: threat model + sign/verify roundtrip.
- [ ] Benchmarks within noise; no new hot-path allocations.

### W3 — Header verification and emission (plan §3) — M

**Depends on:** W1, D1.

Scope:

- Require `Mcp-Method` and `Mcp-Name` on 2026-07-28 POSTs; verify both against
  the parsed body (`internal/transport/http_routing.go` / `http_security.go`).
  Disagreement or a missing/malformed header → `HEADER_MISMATCH` (-32020),
  recorded under a new structured audit code value (threat-model note) — an
  enforcement-confusion attempt, not a parse error.
- Emit both headers on the upstream leg (`http_remote.go`,
  `stdio_http_upstream.go`).
- `x-mcp-header`: strip by default; explicit per-upstream allowlist config key if
  D1 admits one.
- Retire `Mcp-Session-Id` from the 2026-07-28 host-facing surface; scope
  `upstreamSessID` to old-revision upstreams.

Tests: a mismatch matrix (wrong method / wrong name / missing / malformed → each
-32020 + audit); a smuggling test proving unlisted `x-mcp-header` values never
reach the upstream; header emission asserted in the remote-bridge tests.

Exit criteria:

- [ ] Mismatch matrix green; every cell audited with the new code value.
- [ ] Smuggling test green; posture documented in the threat model.
- [ ] Headers emitted on both upstream bridge paths (asserted).
- [ ] No 2026-07-28 response carries or requires `Mcp-Session-Id` (test).

### W4 — `server/discover` (plan §4) — M

**Depends on:** W1, D1 (filter-reuse ruling).

Scope: a responder registered in the 2026-07-28 `locallyAnsweredHandlers` table —
routed through `dispatchRequest`, so it inherits the shared kill gate by
construction, unlike HTTP's session-creating `initialize` today. Output built
from the upstream probe (`server/discover`, or synthesized from `initialize` for
an old-revision upstream) and filtered through the **same** `ListFilterer`
methods the `*/list` path uses. Advertise `extensions` (populated by W8).
`buildInit` generalizes to a revision-selected responder.

Tests: a **parity property test** — any tool/resource/prompt the list filters
hide is absent from the discover response for the same identity; the kill gate on
discover; synthesis from an old-revision upstream.

Exit criteria:

- [ ] Parity property test green (discover can never reveal what `*/list` hides).
- [ ] Discover denied for 2025-11-25 peers (falls out of W1's tables; asserted).
- [ ] Kill-gate test green.
- [ ] Old-upstream synthesis cell green in the e2e matrix (new host × old upstream).

### W5 — Result shape and caching invariants (plan §5) — M

**Depends on:** W1.

Scope:

- Emit `resultType` on every result eunox synthesizes or rewrites for 2026-07-28
  peers: the `internal/mcp` response builders, `dispatchList` output, the
  discover response.
- Clamp `cacheScope` to `private` on any response eunox filtered — never preserve
  an upstream `public`; set it when a translated old-upstream response lacks it;
  preserve `ttlMs` as a freshness hint. Lands in `internal/pdp`'s
  `filterListResult` path. Closes threat-model finding L-6.
- Assertion test that filtering preserves upstream list ordering (deterministic
  ordering is a spec SHOULD that eunox must not break).

Exit criteria:

- [ ] Sweep test: no builder emits a 2026-07-28 result without `resultType`; old-revision output byte-stable.
- [ ] Property test across all filter paths: a filtered response never carries `cacheScope: public`.
- [ ] Ordering-preservation test green.
- [ ] L-6 marked mitigated in `docs/threat-model-mcp.md`.

### W6 — Multi round-trip requests (plan §6) — XL

**Depends on:** W1, W2, D2. The largest and riskiest workstream.

Scope:

- **Continuation:** wrap the upstream's `requestState` in an eunox-signed
  continuation binding the original decision, its anchor, and the quota already
  committed. Key sourcing mirrors the audit HMAC key loader pattern
  (`internal/audit/keys.go`) but is a **distinct key** — never the audit key;
  shared via config for multi-instance verify, ephemeral per-process default for
  single-instance (a restart invalidates in-flight exchanges; the client re-issues
  the original call — fail closed, acceptable).
- **Response-path enforcement in `enforcedForwardCore`:** on
  `resultType: "input_required"`, enforce each `inputRequests` entry. The sampling
  lever keeps its manifest surface (`system:sampling/createMessage`); what moves is
  where it is evaluated. An entry the manifest does not permit fails the **whole
  result** fail-closed, recorded — no partial stripping, which would desynchronize
  the client/upstream exchange. `redactFields` applies to inputRequest content as
  to any result.
- **Retry path:** verify the continuation (anchor binding, lifetime, per D2),
  re-run kill check and match, re-evaluate conditions against the retry's
  arguments (including effect conditions and the ceiling — `inputResponses` can
  change arguments), and commit quota **once per logical call** per D2's rule.
- Scope the old server-initiated subsystem (`forwardServerRequest`,
  `serverRequestPool`, `samplingTurnWait`, `spansAnchors`) to 2025-11-25 via W1's
  tables; no behavior change within it.

Tests:

- **Double-meter regression:** `maxCalls: 1` — one logical call with an MRTR
  round completes; a second logical call denies. Same for a cumulative
  `blastRadius` bucket via `AdmitAll`.
- Continuation negatives: expired, foreign-anchor, tampered, wrong-key → each
  denied and audited distinctly.
- Cross-instance verify: two engines sharing the configured key, mint on one,
  verify on the other.
- **Fuzz target** on continuation decode — it is attacker-supplied input — with a
  seed corpus, per the repo's fuzz culture.
- Sampling-lever move: an `input_required` result carrying a sampling
  inputRequest with no manifest entry → whole result denied, recorded; with the
  entry → passes.
- e2e: a full MRTR round trip in the new×new matrix cell.

Exit criteria:

- [ ] ADR-0007 Final.
- [ ] Metering invariants green: no double commit, no unmetered retries beyond D2's bound.
- [ ] All continuation negatives green; fuzz target landed and in CI.
- [ ] Cross-instance verify test green.
- [ ] Sampling deny lever demonstrably relocated (old request-path test retired to the 2025-11-25 scope, response-path test green).
- [ ] Threat model: continuation, replay analysis, and the interim posture below.

**Interim fail-closed posture** (if D2 slips): deny any
`resultType: "input_required"` result whose capability carries state-accumulating
conditions, allow stateless ones. Ships safety before ergonomics and keeps W6
from blocking the release wholesale — the fallback is itself a D2 line item.

### W7 — `subscriptions/listen` (plan §7) — L

**Depends on:** W1, W2, D4.

Scope:

- Dispatch entry (2026-07-28 table): the stream open is an **enforced action**
  bound to the opener's anchor. Each requested notification type is vetted; each
  `resourceSubscriptions` URI is decided by the `resources/read` match. Per D4's
  recommended rule, any unauthorized URI fails the whole open with a structured
  error — no silently narrowed grant.
- Notifications delivered on the stream are filtered against the opener's
  identity and policy exactly as list discovery is; list-changed types carry no
  payload and pass, resource-update notifications are matched against the
  authorized subscribed set.
- Kill terminates the stream on delivery (the `ObserveRevocations` path, as the
  SSE relay gates today), with an audit record.
- Rehome `DecideResourceCancel`'s match-alone semantics onto stream teardown and
  subscription narrowing, preserving its defining property: **a spent budget can
  never refuse the close/narrow that ends a stream the open admitted.**
- The standalone GET endpoint is absent for 2026-07-28 peers (route table).
  stdio delivers the same filtered notifications on the pipe.

Tests: `enforcement_gaps_test.go` coverage for the method; unauthorized-URI
whole-open denial; kill-during-stream on both transports (including Redis-backed
kill via pub/sub); the spent-budget-can-still-close invariant; notification
filtering parity with list filtering.

Exit criteria:

- [ ] ADR-0008 Final (stream half).
- [ ] Open/deny, filtering-parity, kill-during-stream, and spent-budget-close tests green.
- [ ] GET endpoint verified absent for new-revision peers (test).
- [ ] Threat-model stream section written; conformance rows updated.

### W8 — Tasks extension (plan §8) — L

**Depends on:** W1, W6, D4.

Scope:

- Dispatch entries for `tasks/get`, `tasks/update`, `tasks/cancel` (2026-07-28
  table): manifest-gated, kill-gated, audited. If this adds manifest vocabulary
  (e.g. `system:tasks/*` targets), the full grammar convention applies — schema
  branch, drift test, guide, spec repo.
- **Extension gating:** advertise `io.modelcontextprotocol/tasks` in the discover
  response only when the upstream advertises it **and** the manifest permits;
  a denied extension is stripped from discovery and its methods deny.
- Deferred effects inherit the initiating call's anchor with the antecedent
  committed at forward time (verify against existing engine behavior; D4 decides
  how deep task→anchor binding goes beyond method+name gating, and whether it
  needs the optional store).
- **Kill × tasks (D4):** recommended — kill denies `tasks/get`/`tasks/update` as
  it denies everything, and the proxy issues an upstream `tasks/cancel` for
  outstanding tasks on kill delivery, audited as a system action, so containment
  reaches work already in flight.

Tests: both-direction `enforcement_gaps_test.go` coverage; deny-by-default with
no manifest entry; extension-stripping (manifest without tasks → discover strips
+ `tasks/*` denies); the kill-cascade path if D4 adopts it.

Exit criteria:

- [ ] ADR-0008 Final (tasks half).
- [ ] All three methods enforced, tested, deny-by-default.
- [ ] Extension gate test green.
- [ ] Kill×tasks semantics decided, implemented, e2e-tested.
- [ ] Manifest-vocabulary conventions satisfied if vocabulary was added.

### W9 — Error-code alignment (plan §9) — S

**Depends on:** W1.

Scope: resource-not-found mapping to -32602 for new-revision peers
(`denialToJSONRPCCode`, `internal/transport/jsonrpc.go`); `IsInfraDenialCode`
revision-aware; a **range-pin test** asserting every eunox-minted code sits in
-32000..-32019 and never in the reserved -32020..-32099 (except the spec-defined
-32020/-32022 emissions, which are asserted individually).

Exit criteria:

- [ ] Range-pin test green and in CI (a future code addition cannot drift into reserved space).
- [ ] Mapping tests updated for both revisions.

### W10 — Tier-2 pinning under JSON Schema 2020-12 (plan §10) — M design, S code

**Depends on:** nothing.

Scope: record the hashing decision in `docs/interface-pinning-tier2.md`.
Recommended: keep hashing the schema bytes as given (`SurfaceHash` /
`capability.ComputeToolHash`), never resolve or fetch a `$ref` — remote
resolution is a network fetch on the decision path and is refused on principle.
A benign `$ref` refactor mid-session trips the sticky per-session break; the
next session re-baselines, bounding the false positive. Document that bound.

Exit criteria:

- [ ] Decision recorded in the pinning doc; no-fetch invariant stated in the threat model.
- [ ] Test: a `$ref`-bearing schema hashes stably and triggers no network activity.
- [ ] Test: mid-session schema change (including a pure `$ref` refactor) still trips the pin — the conservative behavior is intentional and asserted.

### W11 — CLI probe and drift path (plan §11) — M

**Depends on:** W1, W4.

Scope: the probe opens with `server/discover` and falls back to `initialize` on
method-not-found or unmapped denial (or honors a config pin); generalize
`BuildInitializeRequestWithID` into a revision-selected opener; `validate
--live`, `init`, `drift.MakeDriftCheck`, and `ParseToolsListResult` handle both
revisions; the drift check's fatal-or-skip semantics preserved.

Exit criteria:

- [ ] Probe fallback matrix test green against both mock upstreams.
- [ ] `init`, `validate --live`, and the session-start drift check all work against a 2026-07-28-only upstream in e2e.
- [ ] Fatal-or-skip behavior unchanged (test).

### W12 — Documentation and ADR housekeeping (plan §12) — M, continuous

Scope: `docs/conformance.md` grows a per-revision method matrix and flips its
targeted-spec line when the global criteria hold; threat model gains the header
confusion, continuation, and stream sections and closes L-6 (L-7 re-checked);
ADR-0002 graduated to Final (its code shipped long since); ADR-0004 graduated
in W2; ADR-0006/0007/0008 authored at their gates and graduated as their
workstreams land; `CHANGELOG.md` entries accrue per workstream.

Exit criteria:

- [ ] conformance.md states both targeted revisions with a complete per-method, per-revision matrix.
- [ ] No ADR this plan touches remains Draft — each is Final, or In Review awaiting consensus.
- [ ] Threat model current; CHANGELOG complete for the release.

### W13 — Test and demo infrastructure — L

**Depends on:** W1 (minimal). **Blocks:** most exit criteria above — build it early.

Scope:

- 2026-07-28 modes for `demo/mock-mcp-server`, `demo/mock-mcp-server-stdio`,
  `demo/e2e/mock-server`, and `demo/e2e/mock-host`: discover, per-request
  `_meta`, headers, an MRTR round, `subscriptions/listen`, a tasks stub, caching
  fields.
- An e2e **interop matrix**: {host 2025-11-25, 2026-07-28} × {upstream
  2025-11-25, 2026-07-28}. Matched cells assert full function; mismatched cells
  assert **exactly** the ADR-0006 boundary — the translated subset works, the
  refused set fails with the structured error, nothing in between.
- Demo targets for the stateless variant (`make -C demo …`), so
  allow/deny/audit remain demonstrable against a real 2026-07-28 upstream.

Exit criteria:

- [ ] Four-cell matrix runs in CI.
- [ ] Mismatch cells assert the D1 boundary precisely (both directions).
- [ ] Demo allow/deny/audit walkthrough works against the new-revision mock.

---

## Order of landing

Dependency order, not calendar. Parallel where independent.

1. **Seams — land before the first tagged release:** W1's declaration/table
   refactor and revision-set type (behavior-neutral), and W2's subject-struct
   reshape plus the jti claims-carry. These are the forward-compatible hedge and
   are cheap now, breaking later.
2. **D1 + D3 resolved; W13 mocks stood up.** W1 activation; W2 in full.
3. **W3, W4, W5, W9 in parallel** (all hang off W1; none touch each other).
4. **D2 → W6. D4 → W7, W8.** W6 and W7 are independent of each other; W8 follows
   W6's anchor semantics.
5. **W10, W11** (W11 needs W4's discover client side).
6. **W12 flip + the global criteria** below.

The old-revision subsystem's deletion is **not in this plan**: the deprecation
clock permits removal of roots/sampling/logging no earlier than 2027-07-28, and
2025-11-25 peers need the subsystem until then. W1's revision scoping is what
makes that eventual deletion a subtraction.

---

## Global exit criteria — the conformance release is done when

1. **Interop:** all four matrix cells green in CI; mismatched cells behave
   exactly per ADR-0006, asserted not observed.
2. **Golden path:** a 2026-07-28-only host completes, against eunox with a real
   policy: `server/discover` (filtered) → `tools/list` (filtered) → `tools/call`
   (one allow, one deny) → an MRTR round trip → `subscriptions/listen` with a
   filtered notification → a mid-session kill that terminates the stream and
   denies the next call — every step audited, and `eunox audit-verify` passes on
   the resulting log.
3. **Fail-closed sweep:** for each revision, a derived (not hand-enumerated) test
   proves every method outside that revision's tables is denied and recorded, in
   both request and notification framing.
4. **Metering invariants:** one logical call commits quota once across MRTR
   retries; replay is bounded per ADR-0007; `BenchmarkDecisionTurn_*` and the
   kill-check path show no regression beyond noise.
5. **Filtering invariants:** the discover/list parity property holds; no filtered
   response ever carries `cacheScope: public`; every synthesized 2026-07-28
   result carries `resultType`.
6. **Old-revision stability:** the pre-existing suite passes unmodified except
   where a test itself asserted a now-revision-scoped detail, and the old×old
   cell is byte-stable.
7. **Docs and ADRs:** conformance matrix flipped; threat model current with L-6
   closed; ADR-0002 and ADR-0004 Final; ADR-0006–0008 Final; CHANGELOG
   complete.
8. **Blanket criteria** hold repo-wide: race-clean tests, lint, fmt, license,
   NOTICE, and the 80% coverage gates.

## Out of scope for this release

- MRTR translation across a mismatched revision pair (refused per D1).
- Deleting the 2025-11-25 server-initiated subsystem (clock above).
- Token issuance, remote `$ref` resolution, or any network fetch on the decision
  path — standing invariants, restated because two of this spec's features
  (schema `$ref`, extension discovery) invite them.

## Risks

| Risk | Mitigation |
|---|---|
| `http_session.go` lifecycle blast radius (pin, `gateCache`, reaper, strict-audit all initialize-anchored) | New-revision session creation is additive alongside the old path, never a rewrite of it; old×old e2e cell is the regression arbiter; W2 lands behind W13's matrix. |
| MRTR replay economics resist a clean stateless answer | ADR-0007 must bound it explicitly; the W6 interim fail-closed posture ships safety first and is itself a release-admissible state. |
| Ecosystem timing — few real 2026-07-28 upstreams to test against early | W13 mocks stand in; W11's discover-then-initialize fallback keeps onboarding working either way. |
| Spec erratas post-release | The revision is stable and the deprecation policy dated; W1's single-declaration tables make a method-set correction a data change, not a redesign. |

## See also

- [mcp-2026-07-28-plan.md](mcp-2026-07-28-plan.md) — what changes and why; decisions D1–D4 in long form
- [conformance.md](conformance.md) — the current method matrix
- [ADR-0004](adr/0004-bearer-identity-session-anchor.md) — bearer-identity anchor (D3 home)
- [threat-model-mcp.md](threat-model-mcp.md) — L-6, L-7, and the invariants this plan extends
