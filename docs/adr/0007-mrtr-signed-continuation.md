# ADR-0007: Meter multi round-trip requests once per logical call, via a signed continuation

- **Status:** Draft
- **Date:** 2026-08-07
- **Deciders:** eunox maintainers

## Context

Under the 2026-07-28 revision, server-initiated requests are replaced by multi
round-trip requests (MRTR): an enforced call terminates with `resultType:
"input_required"` carrying the server's `inputRequests` plus an opaque
`requestState`, and the client re-issues a *new* request — a different JSON-RPC
id — carrying `inputResponses` and the echoed `requestState`
([ADR-0004](./0004-bearer-identity-session-anchor.md) records the shape and
already commits to treating `requestState` as attacker-controlled and
integrity-protecting it wherever it influences a decision; this ADR is that
mechanism).

The enforcement problem: **a retry is a second wire request for one logical
call.** Nothing distinguishes it today, so eunox would either double-commit
every piece of stateful enforcement — `maxCalls` and cumulative `blastRadius`
budgets admitted through `pkg/callcounter`'s `AdmitAll`, the `sequenceBlock`
antecedent, flow-label taint — or, if retries were waved through free, let a
caller launder unlimited work through one admitted call. A budget of
`maxCalls: 5` must mean five logical calls, not five wire messages; it must
also not mean unlimited retries.

The constraint from the stateless posture ([ADR-0004]): no shared store may be
required, and any instance must be able to verify a retry.

## Decision

**We will wrap the upstream's `requestState` in an eunox-signed continuation
that binds the original decision, verify it on every retry, and commit
session state exactly once per logical call.** Concretely:

- **Wrap on the way out.** When an allowed call's result is `input_required`,
  the enforcement core (`internal/transport/forward.go`,
  `enforcedForwardCore`) wraps the upstream's `requestState` in a continuation
  before the result reaches the host. The host echoes it as the opaque blob
  the spec already obliges it to return; the upstream only ever sees its own
  inner `requestState` back. Neither peer can read or mint the wrapper.
- **Continuation contents** (semantic fields fixed here; encoding is an
  implementation detail): the resolved state anchor
  (`enforcement.ResolveStateAnchor`), the matched capability identity and the
  policy digest it was decided under, the method and target name, the quota
  bucket keys already committed, a round counter, a unique continuation id,
  issued-at and expiry, and the inner `requestState`. Authenticated with
  HMAC-SHA256 under a **dedicated key** — never the audit key; key loading
  mirrors the audit key loader's discipline (`internal/audit/keys.go`).
  Default is an ephemeral per-process key (a restart invalidates in-flight
  exchanges — fail closed; the client re-issues the original call); a
  configured shared key enables cross-instance verification.
- **Verify on the way back, in order:** signature; expiry; anchor equality
  with the retry's own resolved anchor; policy-digest currency (a reloaded or
  changed policy denies the retry — re-issuing enters as a fresh logical call
  under the new policy); the kill/revocation check; the constraint match; and
  re-evaluation of non-committing checks against the retry's arguments —
  **including effect resolution and the effect ceiling**, since
  `inputResponses` can change arguments. Any failure is a structured denial,
  audited. A request presenting a continuation that fails verification is
  denied outright, never silently treated as fresh — a client can always
  re-issue without one.
- **Commit once.** Admission state — quota buckets via `AdmitAll`, the
  `sequenceBlock` antecedent — commits at the first decision of the logical
  call and never on a retry. Flow-label taint accumulates union-only across
  rounds, matching the sink's union-only convention (monotone, so a later
  round can add taint but never remove it). A capability carrying a
  `declassify` directive whose call returns `input_required` is **denied**:
  the two-phase `Declassification` commit cannot span a client round trip
  without holding the anchor's decision turn across the exchange, and we
  refuse to stretch that critical section over a peer's think time.
- **Replay is bounded three ways.** Continuation ids are single-use, burned in
  the engine's anchored ledger exactly as `declassify` once-grants are
  (in-memory by default; the shared backend, when configured, makes the burn
  cross-instance). Each re-wrap increments the round counter, capped by
  proxy-level config with a modest default. Expiry is proxy-level config with
  a minutes-scale default, sized for human-in-the-loop elicitation rather
  than machine turnaround. Residual: multi-instance without a shared backend
  burns per-instance only — the same accepted posture as per-instance quotas
  today, documented in the threat model.
- **`inputRequests` are enforced before the result reaches the host.** The
  sampling lever keeps its manifest surface
  (`system:sampling/createMessage`); what moves is where it is evaluated. An
  entry the manifest does not permit fails the **whole result** with a
  structured denial, recorded — no partial stripping, which would leave the
  client and upstream disagreeing about what was asked. `redactFields`
  applies to inputRequest content as to any result content.
- **No new manifest grammar.** TTL and round cap are proxy-level
  configuration; per-capability MRTR bounds wait for demonstrated demand.

## Alternatives considered

- **Meter every retry as a fresh call.** Rejected: breaks the meaning of
  `maxCalls`; operators would inflate budgets to accommodate retries,
  weakening the control they configured.
- **Free retries after first admission, no wrapper.** Rejected: unbounded
  laundering through one admitted call, with no anchor binding and no replay
  bound on an attacker-controlled blob.
- **Store per-exchange decision state server-side.** Rejected: reintroduces
  the coordinated store and sticky-routing pressure the stateless revision
  exists to shed, and contradicts the posture ADR-0004 commits to.
- **Asymmetric signatures.** Rejected: no third party ever verifies a
  continuation — only eunox instances do — and HMAC is materially cheaper on
  the hot path.

## Consequences

- `input_required` becomes an enforced **result** variant: response-path
  enforcement joins request-path enforcement as a place denials happen, with
  the test obligations that implies — a double-meter regression test, the
  verification-failure matrix, and a fuzz target on continuation decode,
  since it is attacker-supplied input.
- A key-management obligation appears: a dedicated continuation key whose
  rotation invalidates in-flight exchanges (fail closed), documented for
  operators; multi-instance deployments must configure a shared key.
- Continuations add bytes to every `input_required` result and its retry; the
  wrapper must bound the inner `requestState` size it will carry, and refuse
  (fail closed) rather than truncate an oversized one.
- Until this lands, the interim posture is fail-closed by class: deny
  `input_required` results on capabilities carrying state-accumulating
  conditions, allow them on stateless ones — an admissible release state, so
  this design cannot hold the conformance release hostage.
- The declassify×MRTR refusal is a real functional gap (a declassifying call
  cannot participate in an MRTR exchange). Accepted: the alternative holds
  the anchor's turn across a peer's think time, which is head-of-line
  blocking with unbounded duration.
