# ADR-0004: Anchor client correlation and revocation on bearer identity, not the protocol session

- **Status:** Draft
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
  push and fold into the originating client request. Three spec changes drive this
  and must not be conflated: server-to-client requests **must** associate with an
  in-flight client request (the SHOULD-to-MUST promotion); the standalone GET SSE
  stream is **removed** and all traffic is POST-only; and the in-flight round trip
  is replaced by a payload exchange — the original `tools/call` /
  `resources/read` / `prompts/get` terminates with an `InputRequiredResult`
  carrying the server's `inputRequests` plus an opaque `requestState`, and the
  client re-issues a *new* request (with a different JSON-RPC id) carrying
  `inputResponses` and the echoed `requestState`. eunox must treat `requestState`
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
  and the seams; the precise wire details (header names, negotiation tokens,
  permitted GET-stream uses) are finalized against the published revision, and any
  divergence is reconciled there rather than guessed here.
