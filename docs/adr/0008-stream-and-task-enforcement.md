# ADR-0008: Enforce subscription streams and task methods at the opener's anchor

- **Status:** Draft
- **Date:** 2026-08-07
- **Deciders:** eunox maintainers

## Context

The 2026-07-28 revision replaces the standalone GET stream and
`resources/subscribe`/`resources/unsubscribe` with `subscriptions/listen` — a
single long-lived stream the client opens with an explicit set of notification
types (`toolsListChanged`, `promptsListChanged`, `resourcesListChanged`,
`resourceSubscriptions`) — and moves tasks to the
`io.modelcontextprotocol/tasks` extension (poll-based `tasks/get`,
client-input `tasks/update`, `tasks/cancel`). Both create effects that outlive
the request that authorized them: a stream keeps delivering, a task keeps
running. eunox's model is per-request decisions plus state keyed on the
resolved anchor (`enforcement.ResolveStateAnchor`), so both need an explicit
answer to *whose authority a long-lived effect runs under, and when that
authority is re-checked*.

What exists today: `resources/subscribe` is enforced on the same policy path
as `resources/read`; `resources/unsubscribe` is authorized by **match alone**
through `DecideResourceCancel` (`internal/pdp/pdp.go`) — deliberately exempt
from conditions and session state, because a spent `maxCalls` budget must
never refuse the cancel that closes a stream the subscribe opened; `tasks/*`
is unmapped and denied. The kill switch already gates the upstream→host relay
on both transports, and `killswitch.Manager.ObserveRevocations` exists so a
kill's delivery can reclaim what a revoked holder keeps open.

## Decision

**We will treat the stream open and every task method as enforced actions
bound to the opener's anchor, re-check authority without committing state on
delivery, and carry the cancel-is-match-alone rule onto the new wire.**
Concretely:

- **Opening `subscriptions/listen` is an enforced action, anchored at open.**
  The list-changed types pass on their own (they carry no payload; the refetch
  they prompt is filtered as always). Each URI in `resourceSubscriptions`
  receives the full read-equivalent decision `resources/subscribe` gets today.
  **Any unauthorized URI fails the whole open** with a structured denial
  naming it — no silent narrowing: a partially-granted stream leaves the
  client and proxy disagreeing about which subscriptions are live, and the
  caller supplied the URIs, so naming the failing one reveals nothing.
- **Delivery is filtered and re-checked, but never billed.** Every
  notification delivered on the stream passes the same identity/policy
  filtering list discovery gets, plus a **non-committing re-check** — kill
  switch, constraint match, stateless conditions — so a revoked credential, a
  lapsed `timeWindow`, or a removed capability stops delivery promptly. State-
  committing conditions are not evaluated and no budget is charged per event:
  delivery transfers data under an authorization already admitted at open.
  A notification outside the authorized set is dropped silently per item,
  matching the list-filter precedent of not recording per-hidden-entry.
- **Kill terminates the stream on delivery**, through `ObserveRevocations`,
  with an audit record — the SSE-relay precedent carried forward.
- **Closing or narrowing is authorized by match alone**, commits nothing, and
  is never refusable by a spent budget — `DecideResourceCancel`'s rationale,
  rehomed onto stream teardown and subscription narrowing.
- **The stream's anchor is fixed at open.** A session that later spans
  anchors does not retarget its stream: delivery decides from the claims
  captured at open, host requests decide from their own — the same reasoning
  that makes the server-initiated leg refuse for a spanning session today.
- **Task methods are manifest-gated, kill-gated, and audited**, deny-by-
  default, with `system:`-prefixed targets following the
  `system:sampling/createMessage` convention. The extension is **gated in
  discovery**: `io.modelcontextprotocol/tasks` is advertised only when the
  upstream advertises it *and* the manifest permits it; a policy-denied
  extension is stripped from `server/discover` and its methods deny. This is
  the general rule for future extensions.
- **A task binds to the anchor that created it.** A task id minted by a call
  decided under anchor A is recorded in the engine's anchored state — the
  same backend posture as quotas: in-memory by default, the shared backend
  for multi-instance. `tasks/get` and `tasks/update` on a task bound to a
  different anchor are denied; `tasks/cancel` requires the binding match but
  is otherwise match-alone (the cancel rule again). A task with **no known
  binding** — after a restart without a shared backend, or on an instance
  that never saw the mint — is denied, fail closed: an unattributable task
  handle is exactly the ambiguity the fail-closed invariant exists for.
- **Kill cascades to bound tasks.** On kill delivery, the proxy issues
  upstream `tasks/cancel` for outstanding tasks bound to the killed anchor
  whose bindings it holds, audited as a proxy-initiated containment action
  referencing the kill. Containment reaches deferred work, not only future
  requests.
- **Deferred effects inherit the initiating call's anchor**, with the
  antecedent committed at forward time of the initiating call — the existing
  engine rule, restated here because tasks are its first long-horizon
  consumer.

## Alternatives considered

- **Narrow a partially-authorized open to the permitted subset.** Rejected:
  silent narrowing creates a live disagreement about what is subscribed;
  explicit refusal is cheaper to reason about and to audit.
- **Full committing decision per delivered notification.** Rejected: per-event
  latency and budget churn with no added authority — the open is the
  admission; the non-committing re-check catches revocation and lapse, which
  is what actually changes mid-stream.
- **No re-check on delivery (filter by set membership only).** Rejected: a
  stream opened under a `timeWindow` would keep delivering after the window
  lapses, and a killed-but-connected holder would keep receiving; the re-check
  is cheap and closes both.
- **Session-scoped task access.** Rejected: the protocol session is being
  deleted; the anchor is the durable subject, and session scoping would
  re-anchor authority on the thing the revision removes.
- **Method-level gating only, no task→anchor binding.** Rejected: any anchor
  could poll or cancel any task id it guessed; binding is what makes a task
  handle an authorization rather than a name.

## Consequences

- Streams gain prompt revocation and lapse behavior, and passive delivery is
  never metered — operators should size budgets for calls, not events; this
  is documented behavior, not an accident.
- The binding ledger is a real trade: without a shared backend, a restart
  strands in-flight tasks (denied until re-created). Deployments needing task
  durability across restarts configure the shared backend — consistent with
  the existing multi-instance posture for quotas and kills.
- The kill cascade makes a kill stronger than deny-only, and introduces a
  proxy-*initiated* upstream action — a new audit shape the threat model must
  cover before it ships.
- Test obligations: kill-during-stream on both transports (including a
  Redis-delivered kill), the spent-budget-can-still-close invariant, the
  whole-open refusal, delivery-filter parity with list filtering, the
  extension-strip test, and binding allow/deny/unknown cases.
- The delivery re-check adds per-event work on the stream path; it must stay
  allocation-lean and must not take the anchor's decision turn (it commits
  nothing, so it needs no serialization).
