# ADR-0010: Classification stays push-shaped; no classifier callout on the decision path

- **Status:** Draft
- **Date:** 2026-08-22
- **Deciders:** eunox maintainers

## Context

The third proposed ingestion mode for imported sensitivity is a **pluggable
classification resolver**: a configured adapter asks the incumbent classifier
(Purview/MSIP/BigID) for a resource's class, keyed by a stable resource id.
It delegates the classification entirely, which is the posture the whole
imported-sensitivity axis was designed around — eunox owns the algebra, never
the taxonomy and never the classifier.

It also runs into a stated invariant: *"No telemetry / background network
activity without explicit design discussion"*
([CONTRIBUTING.md](../../CONTRIBUTING.md)). **This ADR is that discussion.**
The invariant does not settle the question on its own: a classification callout
to an operator-configured endpoint, for an operator-authored policy, is not
telemetry. What it is, is a third party on the decision path.

Both precedents in this repo are worth reasoning from, because they sit on
opposite sides of that line:

- **JWKS fetching is on the decision path** — cached, circuit-breaker guarded
  (`pkg/circuitbreaker`), and reported through the `HealthStatus` seam. It
  answers *who is calling*, against a key the operator's own IdP publishes, and
  eunox verifies the answer cryptographically. An outage can only refuse tokens,
  and the cached set keeps serving while it lasts.
- **Effect contracts are deliberately not** — pinned by **local** digest, with
  no registry and no key ever fetched, specifically so a registry outage cannot
  change a verdict.

A classifier is the second case, not the first. It answers *what the policy
means for this resource*: its reply is the content of the verdict, it is not
verifiable by eunox, and both its availability and its correctness change what
is permitted. That is the failure mode local effect-contract pinning was chosen
to avoid.

One ceiling holds regardless of the design, and is worth restating because it
bounds the whole discussion: eunox can only key on identifiers it sees
**structurally** — an id argument, a URI, a hash. Sensitivity derivable *only
from content* is out of scope permanently; there is no path where eunox reads a
payload and infers PII. A resolver would not widen what eunox can see. It only
delegates the judgement about what it already sees.

## Decision

**We will not add a classification callout to eunox's decision path.
Classification stays push-shaped: eunox consumes a label somebody else
resolved, through a seam that already exists.**

Three such seams are shipped or decided, and each is union-only — they can add
taint, never remove it:

- **The crosswalk** ([ADR-0009](./0009-crosswalk-label-ingestion.md)) — a
  trusted upstream labels its own responses in a declared field.
- **The attribution interface** — a cooperating client declares labels per call
  in `_meta` under `io.eunolabs.context-manifest`
  (`pkg/capability/attribution.go:25`).
- **A delegation hop's forced labels** — the taint a delegator imposes on a
  delegate's calls, carried on a verified token the delegate cannot edit.

An operator who wants incumbent classification runs the resolver themselves and
feeds one of those seams. eunox gains no HTTP client for classification, no
credential to a classifier, no cache to invalidate, and no third party whose
availability changes a verdict.

The four questions the resolver design was asked to answer all converge on this
same shape, which is why this is the design those questions imply rather than a
compromise between them:

- **Cache shape.** The right shape is resource-keyed with per-record
  granularity — which is to say a **label store**, keyed on a structural id,
  that some process populates. Once that is the shape, the process filling it
  does not have to be eunox.
- **First-touch miss.** Fail-closed-conservative is the only safe default, and
  under a flat axis with no lattice there is no "most-sensitive" class to fall
  back to ([ADR-0009](./0009-crosswalk-label-ingestion.md)), so the honest miss
  behavior is a **deny**. The resolver's usefulness therefore rests entirely on
  a warm store somebody else filled ahead of the request.
- **Outage behavior.** A classifier that is down must not silently downgrade a
  label, so it must fail closed — meaning a third party's outage denies traffic
  eunox could otherwise decide on its own state.
- **Decision-path budget.** The only acceptable answer is *never block; serve
  from cache with a background refresh* — which is behaviorally
  indistinguishable from a store populated out of band, at the cost of eunox
  owning the network client, the credential, the invalidation and the health
  surface.

An **embedder** who accepts these trade-offs for their own deployment can
already do this today without eunox shipping it: `enforcement.WithPolicyEvaluator`
(`pkg/enforcement/engine.go:381`) is the sanctioned external-PDP seam, and a
resolver written behind it puts the network dependency in the consumer's code,
where its availability is their own operational concern rather than a property
of the proxy.

**What this costs, stated plainly:** an upstream that does not label its own
data, reached by a client that does not attribute, cannot get per-resource
sensitivity out of eunox. That gap is real. It is the price of a verdict that
stays local, deterministic, and reproducible from the tape.

## Alternatives considered

- **Blocking resolve on the decision path** — rejected: it puts a third party's
  round trip and availability on every verdict, which is the exact failure mode
  local effect-contract pinning exists to prevent.
- **Cache-only resolver inside eunox with background refresh** — rejected: same
  state and same fail-closed miss as an externally-filled store, but eunox owns
  the network client, the classifier credential, the invalidation policy and a
  new health surface, for no behavior the existing seams cannot deliver.
- **Treating the classifier as another JWKS** — rejected: JWKS answers an
  identity question with a cryptographically verifiable reply, and its outage
  can only refuse. A classifier's reply is unverifiable policy content, and a
  wrong one silently permits.
- **Shipping the resolver behind an off-by-default flag** — rejected: a flag
  does not resolve the invariant, it defers it to whoever turns it on, and the
  dependency, the credential and the failure mode ship either way.

## Consequences

The decision path keeps the property the rest of the design rests on: every
verdict is a function of the policy, the request, and eunox's own state, with no
external service able to change it. `HealthStatus` gains no new degradable
subsystem, and the no-background-network invariant stands with a recorded
discussion behind it rather than an unexamined one.

In exchange, integration work moves to the operator. The push seams are the
supported path, and their documentation now has to carry that weight — including
being honest that feeding them may mean running a resolver of one's own.

This is not a permanent closure, and the conditions to revisit it are specific:

- An upstream-side convention for carrying classification in MCP results would
  make the crosswalk sufficient and the resolver moot.
- A concrete deployment demonstrating that none of the three push seams can be
  fed would be evidence this decision is wrong. Reopening it means a new ADR
  that supersedes this one, with that deployment as its context — not an edit
  here.
