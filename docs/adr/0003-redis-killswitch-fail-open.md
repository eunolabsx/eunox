# ADR-0003: Redis kill-switch failure mode during a Redis outage

- **Status:** Draft (reset from Accepted when the ADR review process was
  introduced — see [README](./README.md#process-and-lifecycle)). **Amended
  2026-06-16:** the default is now **fail-closed** with an opt-in fail-open flag,
  superseding the original fail-open default recorded below. **Amended
  2026-07-24:** documented the lifecycle and degraded-mode semantics (stopped vs.
  unreachable, startup-subscription robustness, detection window, session-kill
  durability) — see the section below.
- **Date:** 2026-06-14 (original); 2026-06-16, 2026-07-24 (amendments)
- **Deciders:** eunox maintainers

## Context

eunox's load-bearing posture is **fail closed**: on any ambiguity — a missing
manifest entry, a malformed JWT, a kill-switch *backend error* on the in-memory
path — the decision is deny. The kill switch
([pkg/killswitch](../../pkg/killswitch)) is checked first on every policy
decision, and a backend error there denies (`KILL_SWITCH_ERROR`) rather than
forwarding.

The Redis kill-switch backend ([redis.go](../../pkg/killswitch/redis.go)) has a
performance-driven design. Its hot path — `ShouldBlock()` — does **not** make a
Redis round-trip. It reads a process-local cache that a background pub/sub
listener and a fixed-interval reconcile loop refresh; Redis is contacted only on
*state changes* (`KillSession`, `ActivateGlobal`). This is what keeps the
per-request overhead at ~1.3 µs ([benchmarks.md](../benchmarks.md)) instead of a
network RTT per call.

The consequence: when Redis is unreachable, `ShouldBlock()` cannot learn about
kills issued *during* the partition. The question this ADR answers is what the
hot path should do once it knows a refresh has failed and its cache may be stale.

## Decision

**By default the Redis kill switch fails CLOSED on a Redis outage.** Once the
most recent refresh from Redis has failed (`lastRefreshErr != nil`,
`HealthStatus() != nil`), `ShouldBlock()` denies any request whose kill-switch
state it cannot confirm, returning `ErrBackendUnreachable`, which the caller maps
to a `KILL_SWITCH_ERROR` denial. A kill already present in the local cache still
blocks normally; only requests that the (possibly stale) cache would *allow* are
denied, because a kill issued during the outage would be invisible to them.

Operators can opt back into the original availability-first behaviour with
`--killswitch-fail-open` (`WithFailOpen(true)`): during an outage `ShouldBlock()`
then serves the last-known local cache and allows anything not already known to
be killed.

This reverses the original default. The fail-closed posture now matches eunox's
load-bearing "fail closed on ambiguity" invariant for the *security-critical*
direction: a security product's emergency stop should not silently stop working
because its backend is unreachable. The availability trade-off the original
decision optimised for is preserved as an explicit, documented opt-in rather than
the silent default.

The detection granularity is the reconcile interval (`defaultReconcileInterval`,
30 s): a transient Redis blip is only *seen* as a failure at a reconcile tick or
a pub/sub-triggered resync, and is cleared on the next successful refresh, which
bounds how long the degraded mode persists. The in-memory and single-instance
paths are unaffected: they have no backend to partition from, and a backend error
on those paths already denies.

## Consequences

- **A Redis outage degrades availability by default, not just revocation
  latency.** While Redis is unreachable, a fail-closed instance denies every
  request it cannot confirm (`KILL_SWITCH_ERROR`) until the next successful
  refresh. This is the intended trade-off for an emergency-stop control, but it
  means **Redis is now on the data-plane critical path for `--redis-addr`
  deployments** unless `--killswitch-fail-open` is set. Run Redis with HA
  (Sentinel/cluster) and size the reconcile interval accordingly. Recovery from a
  transient blip is bounded by the reconcile interval (the denial window persists
  until the next successful refresh, not until Redis itself recovers), so
  fail-closed deployments can shorten it with `--killswitch-reconcile-interval`
  to trade Redis load for a tighter post-recovery window.
- **Operators must still observe Redis health.** The kill switch exposes its last
  refresh error via `HealthStatus()`; the HTTP transport surfaces it on the
  loopback `/healthz` (`killSwitchHealthy`, `status: degraded`) and `/metrics`
  (`eunox_kill_switch_healthy`). Alert on it: in fail-closed mode a degraded
  backend is a partial data-plane outage; in fail-open mode it is a widening
  revocation-latency window. Startup logs the active mode.
- **Backend connection details do not leak to clients.** `ShouldBlock()` returns
  the static `ErrBackendUnreachable` sentinel, not the wrapped Redis dial error,
  so a denial message returned to an MCP host cannot expose the Redis host/port.
  The real error remains available to operators via `HealthStatus()`.
- **A kill issued while Redis is down is not lost, only delayed.** `KillSession`
  / `ActivateGlobal` against a reachable Redis persists the state; instances
  converge on it when their listeners reconnect or on the next reconcile tick.
  The `eunox kill --redis-addr` path writes straight to Redis, so the kill is
  durable as soon as Redis accepts it.
- **Fail-open is now an explicit, audited choice.** Selecting
  `--killswitch-fail-open` is the single documented way to get a fail-open path,
  logged at startup. Any *other* fail-open path remains a bug. New kill-switch
  backends should default to fail-closed and match this contract.

## Lifecycle and degraded-mode semantics

The fail-closed decision above governs the steady state. The lifecycle edges below
refine what "cannot confirm" means, so a health probe and the data plane agree on
*why* a switch is not serving allows:

- **Unstarted is distinct from healthy.** A switch that is constructed but never
  `Start`ed has never seeded its cache, so it cannot tell "nothing is killed" from
  "state never loaded" and `ShouldBlock()` denies everything with `ErrNotStarted`
  (a wiring error, so it too ignores `--killswitch-fail-open`). `HealthStatus()`
  reports the same cause, checked in the same order as `ShouldBlock`'s gates:
  reporting healthy there would publish `status: "ok"` on `/healthz` through a
  *total* data-plane outage — the state in which a green probe misleads most.

- **Stopped is distinct from unreachable.** Once the kill switch's `Start` context
  is canceled (`Stop()`, or the caller's own context), the reconcile and pub/sub
  loops exit and the local cache can never converge again — the switch is
  permanently *frozen*, not transiently partitioned. `ShouldBlock()` reports
  `ErrStopped` (and `HealthStatus()` matches) for a non-match in that state, ahead
  of `ErrBackendUnreachable`, even though a final in-flight refresh may have also
  latched a `context.Canceled` refresh error. Both fail closed, so this ordering is
  purely diagnostic accuracy: a frozen switch is an operator wiring/liveness cause,
  not a self-healing outage. `ErrStopped`, like `ErrBackendUnreachable`, fails
  closed **regardless of `--killswitch-fail-open`** — a stopped emergency stop is
  never a silent all-clear.

- **A blackholed Redis cannot wedge startup.** `Start` confirms its pub/sub
  subscription before the first snapshot, but that confirmation is a deadline-less
  socket read: a half-open/blackholed connection (dial and `SUBSCRIBE` accepted,
  confirmation never sent) would otherwise block `Start` — which holds the
  lifecycle lock across the call — forever, deadlocking a concurrent `Stop`. The
  confirmation read is bounded (`subscribeConfirmTimeout`); on timeout the switch
  falls back to reconcile-only convergence exactly as for an outright subscribe
  failure, and startup proceeds degraded rather than hanging.

- **A missed confirmation is not permanent.** Because the confirmation bound is a
  hard cutoff, a *slow but healthy* Redis — a failover, a load spike, a saturated
  link — can miss it without being down. Dropping such an instance into
  reconcile-only mode for the life of the process would stretch kill propagation
  from milliseconds to a full reconcile interval until an operator restarted it, so
  the subscription is retried in the background with capped exponential backoff
  (`subscribeRetryInitialDelay`..`subscribeRetryMaxDelay`). The retry runs off the
  startup path: blocking `Start` to retry would re-open the very lifecycle-lock
  window the bound exists to close. A subscription lost *while running* (an
  unexpected channel close) rejoins the same retry path rather than ending the
  real-time path for the process's lifetime. Because pub/sub is at-most-once, every
  event published during the gap was missed, so a successful resubscribe
  immediately reconciles rather than waiting for the next tick — ordered after the
  confirmed subscribe, mirroring the initial-snapshot ordering, so an event racing
  that reconcile is delivered on the live subscription instead of falling into the
  handoff window. Only the failure edge and the recovery edge are logged, so a
  sustained outage does not log per attempt.

- **Detection is bounded by the reconcile interval, level after the fact.** A
  partition that begins *right after* a successful refresh is invisible until the
  next reconcile tick's SCAN fails (`--killswitch-reconcile-interval`,
  default 30 s), because staleness is observed when a refresh *runs and fails*, not
  predicted. This is the inherent latency of the polling hot path (per-request
  Redis checks were rejected above), and a kill already in the cache still blocks
  throughout; only *newly issued* kills are delayed for at most one interval.
  Shorten the interval to tighten the window at the cost of Redis load.

- **Degraded-mode logging is wired in the binary.** The switch's outage and
  recovery breadcrumbs (initial-refresh-failed, subscription-unconfirmed,
  background-refresh failed/recovered) are gated on a configured logger; the proxy
  now supplies one, so a partition is visible in the process log as well as on
  `/healthz` and `/metrics`. A Redis-only flag (`--killswitch-fail-open`,
  `--killswitch-reconcile-interval`, `--redis-password`, `--redis-tls`) set
  *without* `--redis-addr` is rejected at startup rather than silently ignored —
  the in-memory switch would apply none of them.

- **Session kills are durable, not TTL'd.** `KillSession` writes a permanent Redis
  key, like `KillAgent`. A TTL is deliberately not used: a kill that *silently
  expired* while its subject was still live would be a fail-**open** transition,
  contradicting the invariant above, and the proxy cannot know a session's real
  lifetime. Killed-session keys therefore accumulate until an explicit
  `ReviveSession` or `Reset` — the required cleanup path for automated kill tooling
  that would otherwise leak tombstones.

## Alternatives considered

- **Keep fail-open as the default (the original decision).** Rejected: a security
  product's emergency stop silently ceasing to apply because its backend is
  unreachable is the more surprising and more dangerous default. Operators who
  genuinely need availability-first behaviour now select it explicitly.
- **Authoritative per-request Redis check.** Rejected: a network RTT on every
  policy decision, defeating the in-memory hot-path design and the latency
  budget. The reconcile-interval detection granularity is the accepted
  approximation.
- **No opt-out (always fail-closed).** Rejected: some deployments legitimately
  prefer that a Redis blip not block the data plane, given the manifest allowlist
  still fails closed throughout. A single, clearly-named flag preserves that
  choice without making it the silent default.
