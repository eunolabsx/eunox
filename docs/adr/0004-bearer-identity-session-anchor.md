# ADR-0004: Anchor client correlation and revocation on bearer identity, not the protocol session

- **Status:** Final (ratified 2026-08-23)
- **Date:** 2026-06-23
- **Deciders:** eunox maintainers

## Context

The MCP Streamable HTTP transport is moving toward a **stateless** model: the
protocol-level session and the `Mcp-Session-Id` header are being removed, and
server-initiated requests are restricted to the window in which a server is
processing a client request. The intent is that any request can be served by any
server instance with no sticky routing or shared session store. Exact conformance
tracks the published revision; this ADR records how eunox adapts its correlation
and revocation model to that direction without a transport rewrite.

The facts as they stand today (eunox @ `5a6dc1f`):

- eunox's `httpSession` is **its own construct**, keyed by a UUID the proxy
  generates. The proxy mints `sess.id` and returns it via the `Mcp-Session-Id`
  header on the `initialize` response (`internal/transport/http_routing.go:188`),
  and clients echo it on subsequent POST/GET/DELETE (`:103`, `:346`, `:495`). The
  header is a client-correlation convenience, not a security anchor — enforcement
  is per-request and body-aware, and the `httpSession` exists to own one upstream
  (a subprocess, or a remote HTTP bridge) and its in-flight bookkeeping.
- The stdio transport has no protocol session at all; its `--session-id` is
  internal audit and kill-switch correlation only (`internal/transport/stdio.go`).
- The only place the *protocol* session is consumed is `upstreamSessID`, captured
  from a remote HTTP upstream's `initialize` response and replayed on forwarded
  calls (`internal/transport/http_session.go:55`, `http_remote.go:246`).
- Revocation runs through `killswitch.Manager.ShouldBlock` — by `agent_id`
  (from the verified JWT), by eunox session id, or globally — and is checked first
  on every decision (`internal/pdp/pdp.go`), fail-closed on backend error per
  [ADR-0003](./0003-redis-killswitch-fail-open.md).

The question this ADR answers: when the protocol session and its header are no
longer something a client is required to carry, what does eunox anchor client
correlation and the unit of revocation on?

## Decision

**We will anchor client correlation and the unit of revocation on the bearer
credential identity — `jti` and `agent_id` from the verified JWT — rather than
on the protocol session.** Concretely:

- The proxy stops *depending* on a client echoing a standard session header for
  correlation. It retains an internal per-connection worker abstraction (it must:
  a stdio upstream is a stateful subprocess that cannot be made per-request
  stateless), but that abstraction is a private implementation detail, keyed
  internally and not contingent on protocol session state. The proxy presents a
  session-free face to both host and upstream as the stateless direction
  stabilizes.
- Revocation gains a credential-scoped dimension: `RevokeJTI`/`ReviveJTI` on the
  `killswitch.Manager` seam, checked per-request alongside the existing agent and
  global dimensions, fail-closed on backend error consistent with ADR-0003. `jti`
  is a registered JWT claim already parsed during verification, so this adds no
  `mcp.*` claim-schema change. It does add a token-id field to the audit record,
  which carries the usual obligations (threat-model update, sign-and-verify
  roundtrip test).
- Server-initiated requests (sampling, elicitation, roots) stop being a separate
  push and fold into the originating client request. Two spec changes drive this
  and must not be conflated: the standalone GET SSE stream is **removed** and all
  traffic is POST-only; and the round trip itself
  is replaced by a payload exchange — the original `tools/call` /
  `resources/read` / `prompts/get` terminates with an `InputRequiredResult`
  carrying the server's `inputRequests` plus an opaque `requestState`, and the
  client re-issues a *new* request (with a different JSON-RPC id) carrying
  `inputResponses` and the echoed `requestState`. The request *types* survive as
  `inputRequests` payload shapes — so what the revision removes is the delivery
  mechanism, not the vocabulary. eunox must treat `requestState`
  as attacker-controlled and integrity-protect it wherever it influences a
  decision. Because the interaction now rides the originating call, the rework
  lands in the enforced client-request path (`internal/transport/dispatch.go`,
  `forward.go` `enforcedForwardCore`) and the follow-up retry it must classify and
  enforce — not only the `forwardServerRequest` origination seam
  (`internal/transport/forward.go`), which is necessary but not sufficient.
- The binary negotiates **both** the current and the stateless protocol versions
  through the existing version-negotiation seam (`MCPProtocolVersion`,
  `internal/transport/stdio.go`), so one binary serves hosts on either
  revision and the stateless path can land incrementally.
- Session-scoped policy keys on the **stable caller identity**, not the token
  instance. `sequenceBlock` and per-session `maxCalls`/`timeWindow` scope to
  `agent_id` (or `task_id` where present); revocation keys on `jti`. These are
  deliberately different units: revocation wants the finest revocable thing (one
  token), but cross-request policy must survive token rotation — under short-lived
  rotating credentials a `jti`-scoped sequence would fragment into single-call
  windows, and `sequenceBlock` could no longer correlate (e.g. `read_credentials`
  then `write_external`). Where no stable identity is present (tokenless local
  stdio), the scope falls back to the internal per-connection worker.

The decision preserves the load-bearing invariants: every request is still
decided explicitly and fails closed on ambiguity ([CONTRIBUTING.md](../../CONTRIBUTING.md)),
and the JWT can still only narrow the manifest, never expand it
([ADR-0001](./0001-jwt-claims-intersect-manifest.md)).

## Alternatives considered

- **Keep anchoring on the `Mcp-Session-Id` header.** Rejected: it disappears
  under the stateless direction, and a client is no longer required to carry it,
  so correlation and session-scoped revocation built on it would silently lose
  their anchor.
- **Go fully stateless per request, with no internal session.** Rejected: a
  subprocess upstream is inherently stateful and cannot be spun up per request
  without unacceptable latency and lost upstream context. An internal worker
  abstraction is required; what changes is that it no longer leans on protocol
  session state.
- **Carry continuation state only in client-carried signed tokens.** A good fit
  for *continuation* state and worth adopting where continuation is needed, but it
  does not by itself provide a revocation anchor — a self-contained request
  carries no "still authorized" signal. Credential-anchored, per-request liveness
  is what fills that gap, and the two compose.
- **Key stateful-policy scope on `jti` as well (one key for everything).**
  Rejected: token rotation would fragment cross-request state and silently defeat
  `sequenceBlock` and the window conditions. The revocation key and the scope key
  serve opposite needs — the finest revocable unit versus the most stable
  correlator — so they are kept separate.

## Consequences

- **Revocation becomes credential-scoped, not connection-scoped.** Revoking a
  `jti` (or an `agent_id`) denies every subsequent request bearing it, on any
  instance, at the request's next liveness check — the stateless-friendly,
  pull-based shape, never a push to idle clients. This is strictly more useful
  than connection-scoped revocation in a world where requests are not pinned to a
  connection.
- **`jti` becomes load-bearing.** It must be present and unique per token for
  credential-scoped revocation to be meaningful; deployments whose IdP omits it
  fall back to agent-scoped and global revocation. The new audit field requires a
  threat-model update and a sign-and-verify roundtrip test in the same change.
- **Stateful policy depends on a stable caller identity.** Because the scope key
  is `agent_id`/`task_id` rather than `jti`, a deployment that rotates short-lived
  tokens without a stable `agent_id` loses cross-request correlation and falls
  back to per-call evaluation. This is the explicit trade for aligning with the
  stateless direction, and the reason the scope key and the revocation key are
  kept separate.
- **The standalone GET SSE stream is removed, not narrowed.** Under the stateless
  revision all communication is POST-only, and server-initiated interaction is the
  payload-based multi-round-trip described above rather than a push on a side
  channel. This is a larger change than relocating the push: the
  `forwardServerRequest` origination seam is necessary but not sufficient — the
  enforced client-request path gains an `InputRequiredResult` result variant and a
  follow-up retry to classify, enforce, and integrity-check. The precise wire
  surface (`InputRequiredResult` shape, `requestState` encoding, retry-id rules)
  is finalized against the published revision and reconciled there.
- **Dual-version negotiation is a maintenance obligation.** One binary must serve
  both revisions until the older is retired; the version-negotiation tests must
  cover both, and the remote-upstream bridge's `upstreamSessID` handling becomes
  dead code under a stateless upstream and should be removed when that path is
  retired.
- **Conformance tracks the published spec.** This ADR commits to the *direction*
  and the seams; the precise wire details are finalized against the published
  revision, and any divergence is reconciled there rather than guessed here. See
  the addendum below for where each deferred detail was settled.

## Addendum (2026-08-07): session creation without `initialize`

The revision is now published, and two commitments this ADR deferred have their
own records: negotiation and the mismatched-pair translation boundary in
[ADR-0006](./0006-dual-revision-translation-boundary.md), and the
`requestState` integrity mechanism in
[ADR-0007](./0007-mrtr-signed-continuation.md).

Two release-candidate-era statements in the Decision above were corrected against
the published text at the same time, since implementing either as written would
have been wrong. The first described server-to-client requests as promoted from
SHOULD to MUST associate with an in-flight client request; the published revision
does not tighten that obligation, it removes server-initiated requests as a
delivery mechanism outright. The second deferred "permitted GET-stream uses" to
the published revision; there are none — the standalone GET endpoint is removed.
What survives is the request *vocabulary* as `inputRequests` payload shapes, with
`sampling/createMessage` and `roots/list` deprecated as of 2026-07-28 but
`elicitation/create` not deprecated at all.

What remained undecided here is
*creation*: everything the HTTP transport builds per client — the internal
session, the upstream subprocess, the decision-turn pin, the identity capture,
the `--require-audit=strict` gate — hangs off the session-creating
`initialize`, and the new revision has no such request. Decisions:

- **The first enforced request mints the worker.** On the 2026-07-28 path, the
  internal session is created on the first enforced request — same
  registration, pinning, and reaping as today (`registerSession`,
  `internal/transport/http_session.go`) — with the old-revision `initialize`
  path left untouched.
- **The worker is keyed by the resolved state anchor**
  (`enforcement.ResolveStateAnchor`) — the same subject stateful policy keys
  on, so the worker map and accumulated policy state cannot disagree about a
  request. `jti` stays revocation-only, consistent with the scope-key /
  revocation-key split above.
- **Unauthenticated 2026-07-28 requests are refused by default when the
  upstream is a subprocess.** With no handshake and no credential, each
  request would otherwise fork its own upstream process — a resource-
  exhaustion vector, not a session model. A dev-mode flag opts in; remote
  HTTP upstreams, which cost nothing per request, serve unauthenticated
  traffic per-request as a matter of course.
- **`--require-audit=strict` relocates to the first-request path** with
  unchanged semantics: identity is established before any enforced action, or
  the request is refused.

## Addendum (2026-08-23): what a first request negotiates

Implementing the addendum above surfaced one more thing it did not decide, and
without it the decision cannot be built. Recorded here, before ratification,
because a `Final` record is append-only and this is a gap rather than an
amendment.

W3 established the blocker concretely: a 2026-07-28 host cannot be served over
HTTP today, and **not** because of `Mcp-Session-Id`. HTTP's sessionless arm
asserts the handshake revision as its context (`sessionlessLeg()`,
`internal/transport/http_routing.go`), on the stated grounds that "these arms
exist only to answer `initialize`". That holds while it does. It stops holding
the moment a first enforced request may mint a worker — the declaration then
disagrees with an asserted context and is refused `UNSUPPORTED_PROTOCOL_VERSION`
before session creation is ever reached. So the first-request path decided above
is unreachable until this seam is decided too.

- **On the sessionless path, a first message's declaration ESTABLISHES the
  context; it is not checked against one.** This is [ADR-0006](./0006-dual-revision-translation-boundary.md)'s
  own rule — a context pins from the first resolved message whose method that
  revision defines — applied to the arm that had nowhere to pin and substituted
  a default instead. A first message cannot *flip* a context; it opens one. The
  mid-context flip refusal is unaffected and governs from the second message on,
  which is where a peer probing for the more permissive table actually lives.
- **Omission still resolves to `2025-11-25`.** ADR-0006's rule is unchanged and
  remains the reason nothing widens by leaving a declaration out: the newer table
  is reached only by an explicit declaration, never by silence.
- **The pin attaches to the worker the request mints, keyed on the same resolved
  state anchor.** A first message that mints nothing — a notification, or a
  request refused by any gate above creation — resolves a revision for itself and
  pins nothing, since nothing accumulates for a later message to contradict.
- **The session-creating `initialize` arm keeps asserting the handshake
  revision.** Answering `initialize` *is* the negotiation, so a declaration
  naming any other revision there genuinely does contradict its context. What
  changes is that the assertion becomes per-arm rather than a property of being
  sessionless.

Gate order is unchanged and load-bearing: the revision is resolved first (a
message whose revision is unresolved has no table to be looked up in), then the
unauthenticated-subprocess refusal and `--require-audit=strict` decide whether a
worker is minted at all.

## Ratification

**Final as of 2026-08-23**, by maintainer consensus. Binding and append-only
from here; a later decision supersedes it rather than editing it.

The record commits to the anchor (bearer identity, not the protocol session),
the scope-key/revocation-key split, session creation on first enforced request,
and the negotiation rule above. Implementation status is tracked in
[the execution plan](../mcp-2026-07-28-execution.md), not here — a record that
doubles as a status board goes stale while reading as binding.
