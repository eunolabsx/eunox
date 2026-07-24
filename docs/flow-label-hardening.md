# Flow-label session state — concurrency and lifetime hardening

**Status:** design / requirements; not yet implemented. Captures the two known
limitations of the information-flow-control feature (the `flowLabel` condition and the
`labelOutput` directive) that the initial implementation documented but did not close,
and specifies how to close them. Both stem from one root cause: flow-label state is
stored in the `CallCounter` sliding-window seam, whose consistency and lifetime
semantics do not match monotonic, per-session provenance, and enforcement is not
serialized per session.

Companions: the `handleFlowLabel` / `recordLabels` doc comments in
`pkg/enforcement/flowlabel.go` (where the limitations are noted today), the flow-exfil
honest-limits in `demo/README.md`, and the `labels_out` / `carried_labels` rows in
`docs/threat-model-mcp.md`.

## Background — what ships today

Flow labels are per-`(session, label)` presence markers in the `CallCounter` backend: a
`labelOutput` directive on an allowed source call writes a marker
(`IncrementAndGet`, `maxEntries=1`, a long window), and a `flowLabel` sink reads it
(`Peek`). Propagation is a conservative session-level set-union join — once a class is
present in the session, every sink checks the accumulated set. This reuses the same seam
and shape as `sequenceBlock`'s antecedent history, and inherits two of its properties
that are acceptable for `sequenceBlock` but not for a security-grade flow control:

1. the marker lives in a time-decaying window, not for the session's lifetime; and
2. the source write and the sink read happen in two independent requests that the
   transport dispatches concurrently, with no per-session ordering.

`sequenceBlock` accepts both because a compliant MCP client is serial and its window
(24h) covers any realistic session. Flow control makes a stronger claim — the
`FlowLabelCondition` doc says *"for all flows, a class outside Allow never reaches this
sink"* — so it must hold under an adversarial client and an arbitrarily long session.

## The two defects

### D1 — Taint lifetime is a wall-clock window, not the session

`flowLabelWindowSec` is currently set to 30 days (decoupled from `sequenceHistoryWindowSec`
so a taint no longer ages out at 24h), but it is still a fixed sliding window on a marker
that is written once at the source read and never refreshed. A session that stays alive —
or is deliberately kept idle — longer than the window loses the taint: the sink `Peek`s
`0` and fails open, even though the confidential data is still in the agent's context.

**Threat bound (for prioritization):** low likelihood, real. A >30-day live/idle MCP
session is unusual, but an attacker who controls call timing can keep one idle and exfil
after the window. It is a genuine violation of the "∀ flows" claim; it is not a
common-case leak.

### D2 — Source write and sink read are unserialized

`recordLabels`' `IncrementAndGet` (source) and `handleFlowLabel`'s `Peek` (sink) run in
two independent requests. The transports dispatch a goroutine per request (stdio reads
each line and handles it; HTTP handles each POST), and MCP permits concurrent in-flight
requests on one session, so a client that pipelines the source read and an egress on the
same session can have the sink `Peek` before the source's marker commits — the sink sees
an empty set and allows the flow. This is the 17/20 nondeterminism observed while
building the demo, which the demo hides by serializing its client; the engine and
transport impose no per-session ordering.

**Threat bound (read carefully — it shapes the fix's urgency):** the *direct* exfil of
the concurrently-read datum is bounded by data availability. To exfiltrate a secret the
agent must first receive it (the source read's response), and `recordLabels` commits the
label at decision time, i.e. *before* that response is delivered. So an egress that
carries freshly-read data cannot be concurrent with the read that produced it; by the
time the agent holds the datum, the label is committed and every later sink sees it. What
the race actually breaks is:

- **Determinism.** The decision depends on request timing, so `carried_labels` /
  `labels_out` on the tape and the allow/deny outcome are nondeterministic under
  concurrency — the determinism thesis does not hold off the serialized path.
- **The conservative session-taint invariant.** The model blocks *every* egress once a
  session is touched by a sensitive read; the race lets an egress concurrent with the
  tainting read slip the net (it carries only data the agent already held, so its direct
  leak potential is limited, but the invariant is nonetheless violated).
- **Defense in depth for model extensions.** Per-argument attribution (the optional
  attribution interface) and the integrity dual make the exact ordering more
  load-bearing; closing the race now keeps those sound.

So D2 is primarily a determinism + invariant-integrity defect, not a guaranteed
data-exfil — fix it for correctness and robustness, and weight it accordingly against
other work.

### Shared root cause

Provenance is a **monotonic, per-session** fact with a **session-scoped lifetime** and a
**required happens-before** (source-write before any subsequent sink-read on the session).
The `CallCounter` sliding-window is the wrong primitive for all three: it is a decaying
counter (D1), and it offers no per-session ordering (D2). The clean fix replaces the seam
for flow state with one whose contract matches provenance, rather than continuing to bend
the counter.

## Goals / non-goals

**Goals:**
- Close D1: a taint persists for exactly the session's lifetime and is reclaimed when the
  session ends.
- Close D2: within a session, a source's label write is observed by every sink decision
  the client issues after that source's response, regardless of client concurrency —
  deterministically.
- Preserve the current invariants: fail-closed on unreadable state, no LLM/network on the
  decision path, multi-instance support via a shared backend, one static binary.

**Non-goals:**
- Cross-session flow (labels are per-session by design).
- Reworking `sequenceBlock` (it may benefit from the same serialization, but that is a
  separate decision; do not regress it).
- Per-argument attribution (tracked separately as the attribution interface).

## Requirements and acceptance criteria

- **FR-H1 — Session-lifetime taint.** A flow label set by a source read is visible to
  every later sink in the same session for as long as the session is alive, with no
  wall-clock expiry.
  **AC:** a test that advances a fake clock far beyond any fixed window (via the engine's
  injectable `Clock`) still sees the taint; a sink after the advance denies.
- **FR-H2 — Session-end reclamation.** When a session ends (transport close / idle reap),
  its flow-label state is released, so an abandoned session does not retain state
  indefinitely and a new session with a reused id (if any) starts clean.
  **AC:** after a session is torn down, its label keys are gone from the backend
  (assertable on the in-memory and miniredis backends).
- **FR-H3 — Ordered source→sink under concurrency.** For any interleaving of a source
  read and a later egress on one session, the sink observes the source's committed label.
  **AC:** a concurrency stress test that fires the tainting read and the egress on one
  session without waiting, repeated N×, denies the egress every time (today it leaks a
  fraction — see the demo's 17/20). Determinism: `carried_labels`/`labels_out` on the
  tape are identical across runs of the concurrent scenario.
- **FR-H4 — Multi-instance parity.** All of the above hold across proxy instances sharing
  the backend, or fail closed with the existing startup NOTICE when no shared backend is
  configured (`AnyRouteHasFlowLabel` already wires this).
  **AC:** the concurrency and lifetime tests pass against the Redis (miniredis) backend,
  not only in-memory.

## Design

Two independent pieces; either can land first, but the store (A) is the larger lift and
the serialization (B) is the higher-value correctness fix.

### A. A session-scoped monotonic label store (closes D1, FR-H1/H2/H4)

Introduce a small `FlowLabelStore` seam distinct from `CallCounter`, whose contract is
provenance, not counting:

- `Add(ctx, session, labels…) error` — union labels into the session's set (idempotent).
- `Get(ctx, session) (set, error)` — the accumulated set.
- `Clear(ctx, session) error` — release on session end.

Implementations mirror `pkg/callcounter`: an in-memory map keyed by session (a `set` per
session) and a Redis-backed `SET` per session. Lifetime is the session, not a window:

- **In-memory:** the set lives until `Clear`; the transport calls `Clear` from the same
  place it already tears a session down (`httpSession` idle reaper / delete, stdio
  session end). No window at all.
- **Redis:** a `SADD` per source, an `SMEMBERS` per sink, `DEL` on session end. Give the
  key a generous *idle* TTL refreshed on each `Add`/`Get` (a safety reclamation for a
  session whose `Clear` never arrives — e.g. a crashed instance), sized to the session
  idle-timeout rather than a fixed 30 days. This keeps FR-H1 (no expiry while active) and
  bounds orphan state.

The engine's `recordLabels`/`peekSessionLabels`/`handleFlowLabel` switch from
`counter.IncrementAndGet`/`Peek` on the `flow:`-prefixed key to the new store; the
`flowLabelWindowSec` constant retires. `flowLabelKey`'s namespace component (route name)
carries over so gateway routes stay disjoint.

**Alternative considered (lighter, interim):** keep the `CallCounter` but re-stamp every
carried label on each flow-relevant call (refresh-on-activity), so only a truly idle
session past the window loses the taint. Cheaper (no new seam) but adds writes to the sink
path and still expires idle sessions; acceptable as a stopgap, not the target.

### B. Per-session decision serialization (closes D2, FR-H3)

Serialize the *decision phase* of enforced requests per session so label writes and reads
are totally ordered. The codebase deliberately does not serialize per session today (see
the `handleSequenceBlock` concurrency note), so this is a scoped reversal for flow-relevant
(and, if desired, `sequenceBlock`-relevant) sessions, accepting the loss of intra-session
decision parallelism.

- **Where:** a per-session mutex (keyed by session id, e.g. a sharded map or a lock held
  on the existing `httpSession` / stdio session object) taken around the PDP decision and
  its state write — *not* around the upstream forward. The upstream network call (the slow
  part) stays concurrent; only the `Decide` + `recordLabels`/`peekSessionLabels` critical
  section serializes. This bounds the latency cost to the decision path (microseconds on
  the cache-hit path) rather than the upstream round-trip.
- **Scope it:** only take the lock when the session's policy is flow-relevant (or
  sequenceBlock-relevant), so a non-flow policy keeps full parallelism. `AnyRouteHasFlowLabel`
  / `HasFlowLabel` already identify this.
- **Ordering semantics:** serialization gives a total order in proxy-receipt order. For the
  exfil pattern (read then egress) a compliant client's receipt order is read-first, so the
  label commits before the egress decision. Combined with A, the source's `Add` is durable
  and ordered before any later `Get`.
- **Deadlock/safety:** the lock is leaf-level (no other lock taken under it) and never held
  across I/O, so it cannot deadlock with the upstream call or the audit drainer. Document
  the ordering discipline next to the lock.

### Interaction with the existing fail-closed paths

The store and the lock must preserve the current fail-closed behavior: a store error on
`Add` denies the source read (`labelRecordFailureDenial`, already a `HardDeny`), and a
store error on `Get` denies the sink (`handleFlowLabel` / the `peekSessionLabels` fail-
closed path). Audit-mode antecedent recording (`recordAuditModeAntecedent` → `RecordLabels`)
routes through the same store.

## Recommended order

1. **B (serialization) first** — it is the higher-value correctness fix (determinism +
   the conservative invariant) and is self-contained (a lock around the decision path,
   gated on flow-relevance). It does not require the new store.
2. **A (store) next** — the larger change (new seam + two backends + lifecycle wiring),
   closing the lifetime gap and retiring the window. The interim refresh-on-activity
   alternative can bridge if A is deferred.

Land each behind the existing flow-relevance gate so non-flow policies are unaffected, and
add both to the demo/CI matrix (a concurrency stress target alongside `ci-test-flow`, run
against both counter backends).

## Test plan

- **Concurrency stress (FR-H3):** a new test fires the tainting read and the egress on one
  session concurrently (no wait), repeated ≥100×; asserts the egress denies every time and
  the tape is byte-identical across runs. This test should FAIL on today's code (mirroring
  the demo's 17/20) and pass after B. Run against in-memory and miniredis.
- **Lifetime (FR-H1):** advance the engine's injectable `Clock` far past any fixed window;
  assert the taint persists and a later sink denies. (Today's windowed marker would let it
  expire.)
- **Reclamation (FR-H2):** tear down a session; assert its label keys are gone.
- **Multi-instance (FR-H4):** source on one engine/instance, sink on another, sharing a
  miniredis store; assert the sink sees the taint; and assert the no-shared-backend case
  still emits the startup NOTICE (already covered by `AnyRouteHasFlowLabel`).

## Risks and tradeoffs

- **Intra-session parallelism.** B serializes a flow-relevant session's decisions. Scope
  the lock to the decision path (not the upstream forward) and to flow-relevant sessions
  to bound the cost. A session that pipelines many concurrent requests will see their
  *decisions* serialized (their upstream calls still overlap).
- **New runtime surface.** A adds a store seam and a Redis structure (`SET`). Keep it in
  `pkg/` behind an interface mirroring `CallCounter`, with the same miniredis test
  treatment; no new third-party dependency (reuse the existing `go-redis`).
- **Orphaned Redis state.** Bound by the idle TTL refresh; a crashed instance's session
  state self-reclaims after the idle timeout rather than persisting for a fixed 30 days.
- **sequenceBlock.** It has the identical D2 race (documented, accepted). B could cover it
  too for consistency; decide explicitly rather than let flow and sequenceBlock diverge on
  whether the race is closed.

## Open questions

- Should B serialize all enforced decisions on a flow-relevant session, or only the
  flow-relevant methods? (All is simpler and also fixes `sequenceBlock`; narrower keeps
  more parallelism.)
- Does the `FlowLabelStore` share the session-lifecycle hooks the kill-switch already uses,
  or introduce its own `Clear` call site? Prefer reusing the existing session teardown
  path so there is one place a session's per-session state is released.
- Redis idle-TTL value: tie to the transport's session idle-timeout, or a separate,
  larger bound? (The former keeps orphan state minimal; the latter tolerates long idle
  gaps within a live session.)
