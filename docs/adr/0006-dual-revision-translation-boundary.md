# ADR-0006: Speak both MCP revisions per peer; translate the stateless-safe subset, refuse the rest

- **Status:** In Review
- **Date:** 2026-08-07
- **Deciders:** eunox maintainers

## Context

The 2026-07-28 MCP revision is the published stable specification. It removes
the `initialize`/`notifications/initialized` handshake and the protocol-level
session, carries the protocol version and client capabilities in `_meta` on
every request (`io.modelcontextprotocol/protocolVersion`,
`io.modelcontextprotocol/clientCapabilities`), makes `server/discover`
mandatory, requires `Mcp-Method`/`Mcp-Name` headers on Streamable HTTP POSTs,
requires `resultType` on results and `cacheScope`/`ttlMs` on list-shaped
results, and replaces server-initiated requests and the standalone GET stream
(see [ADR-0004](./0004-bearer-identity-session-anchor.md) and
[ADR-0007](./0007-mrtr-signed-continuation.md)). Its deprecation policy is
dated: the features the old revision depends on are removable no earlier than
2027-07-28, so both revisions are live in the ecosystem for at least a year.

eunox is a proxy. The host and the upstream migrate on independent schedules,
and the common migration deployment — a current host in front of a lagging
upstream, or the reverse — is precisely the situation a proxy exists to serve.
Today `MCPProtocolVersion` is a single constant in `internal/transport`, the
dispatch tables in `internal/transport/dispatch.go` describe exactly one
revision, and the fail-closed default (`dispatchUnmapped`) is what a
2026-07-28-only method hits.

ADR-0004 committed to dual-revision negotiation at the seam level. This ADR
fixes its semantics: how a peer's revision is established, which method sets
exist per revision, and what a mismatched host/upstream pair may and may not do
through the proxy.

## Decision

**We will support both revisions in one binary, negotiate them independently
per peer, translate only the stateless-safe subset across a mismatched pair,
and refuse the rest fail-closed.** Concretely:

- **Host-side revision is established per context, checked per request.** A
  context opened by `initialize` is a 2025-11-25 context. A handshake-less
  request declaring `io.modelcontextprotocol/protocolVersion` in `_meta` is a
  2026-07-28 request. A request declaring a revision that disagrees with the
  context it arrives in is denied with `UNSUPPORTED_PROTOCOL_VERSION` (-32022)
  and audited — a revision flip inside one context is an enforcement-confusion
  vector of the same family as header/body disagreement, not a negotiation. A
  request carrying **neither** a context nor a declaration resolves to
  2025-11-25 rather than being denied: turning "no context, no declaration"
  into a refusal is the session-creation-on-first-request decision, which is
  [ADR-0004](./0004-bearer-identity-session-anchor.md)'s session-creation half
  and not this boundary's to make. Until that lands, the conservative direction
  is the surface eunox already shipped — omission can never reach a newer
  method set, and the newer table stays reachable only by explicit declaration.
  If handshake-less session creation later makes refusal the correct answer,
  it is ADR-0004's half that changes it, not a silent divergence here.
- **Upstream-side revision is decided once and pinned** per route (gateway) or
  per proxy (stdio), and it SELECTS the opener rather than labelling a leg opened
  some other way: a `protocolVersion: auto | "2025-11-25" | "2026-07-28"` key on
  the upstream config picks `initialize` or `server/discover`, and everything
  else about the leg follows from it (whether the open is completed with
  `notifications/initialized`, what `MCP-Protocol-Version` names, whether eunox's
  own requests carry the per-request `_meta` declaration, and which resolved
  revision a host message must agree with to be forwardable). The upstream's own
  handshake answer is CHECKED against that decision, never allowed to set it. The
  two failures get different answers, by blast radius: a version this build DOES
  speak that is not the one offered refuses the leg at session start (the leg
  would look negotiated while eunox spoke a revision over a method that revision
  removed), while a version outside the published set is REPORTED and the leg
  continues at the revision it was opened at — refusing there would take eunox
  offline against every server on an unpublished revision, which is most of them,
  and what was wrong before was the silence rather than the fallback.

  A pin naming a revision with no handshake is refused at config load on the HTTP
  host transport, where a session can only be minted by `initialize` and the pair
  could therefore never match; and a host `initialize` reaching a leg that speaks
  such a revision is refused rather than answered from that leg's discovery data,
  since synthesizing one revision's handshake from the other's capability object
  is exactly the translation this boundary governs.

  *As landed, `auto` does not PROBE.* This ADR's original text had the
  session-start probe open with `server/discover` and fall back to `initialize`
  on method-not-found. Selecting from the pin needs no probe — an operator who
  writes the pin has stated the fact the probe would go looking for — and the
  probe changes what every existing 2025-11-25 upstream sees before eunox knows
  anything about it, which the release's own regression invariant forbids without
  the interop matrix as its arbiter. `auto` therefore opens with
  `initialize`, byte for byte as before. If the probe is still wanted once that
  matrix stands, it is an addition to the `auto` branch alone and changes nothing
  a pin already decides.
- **Method routing is revision-scoped, declared once per method.** Each entry
  in the dispatch tables (`decideMethodHandlers`, `locallyAnsweredHandlers`,
  `forwardableHostNotifications`, `swallowedHostNotifications`) carries the
  revisions it exists in, following the prototype-registry pattern
  `pkg/capability`'s `TokenSince` established; a derivation test pins each
  revision's exact set. A method outside the requesting peer's table falls to
  `dispatchUnmapped` — removal is expressed by the same fail-closed default
  that already covers unknown methods, never by a second mechanism.
- **A matched pair gets full function. A mismatched pair gets the
  stateless-safe subset, and nothing else:**
  - *Translated:* `tools/call`, `resources/read`, `prompts/get`, the three
    `*/list` methods; discovery in both directions (`server/discover` answered
    from an old upstream's synthesized handshake data, `initialize` answered
    from a new upstream's discover data); and required-field addition on
    results crossing old→new (`resultType`, `cacheScope`/`ttlMs` — with the
    filtered-response `private` clamp).
  - *Refused, fail closed, audited:* everything stateful-by-construction. An
    `input_required` result crossing to a 2025-11-25 host is converted to a
    structured denial (an old host would read it as complete — silent
    desynchronization); a server-initiated request from an old upstream toward
    a stateless host is denied back to the upstream; subscriptions in either
    direction (`resources/subscribe` against a new upstream,
    `subscriptions/listen` against an old one) and `tasks/*` against an old
    upstream are refused.
  - The rule generating both lists: **translate only what is stateless and
    lossless in both directions; never fabricate statefulness on a peer's
    behalf.**
- Refusals at this boundary carry one new structured audit code value
  (threat-model note required) and map to -32022 where the problem is the
  version, -32601 where the method has no home for the pair.
- **`server/discover` output flows through the same `ListFilterer` facets the
  `*/list` methods use** — discovery can never reveal an entry list filtering
  hides, held by a parity property test.
- **Custom client headers (the spec's `x-mcp-header` mechanism) are stripped
  by default in both directions**; an explicit per-upstream allowlist config
  key forwards named headers only. No wildcard.
- **`Mcp-Session-Id` is retired from the 2026-07-28 host leg** — never
  emitted, never required. The internal `httpSession` remains as the
  upstream-owner worker per ADR-0004; `upstreamSessID`
  (`internal/transport/http_remote.go`) is scoped to old-revision upstreams
  and leaves with them.
- **Audit records stamp the decided revision** (new structured field, carrying
  the usual obligations: threat-model update, sign-and-verify roundtrip test).

## Alternatives considered

- **One revision per build, two binaries.** Rejected: the proxy's job is
  standing between peers that disagree; paired deployments double the release
  matrix and still cannot serve a mismatched pair.
- **Refuse every mismatched pair.** Rejected: it kills the primary migration
  deployment, where the translated subset is the entire value.
- **Translate everything, including MRTR and subscriptions.** Rejected for
  now: bridging those requires the proxy to hold per-exchange state on behalf
  of a peer that cannot, reintroducing exactly the statefulness the revision
  sheds. Revisit on demonstrated demand, as its own ADR.
- **Honor per-request revision flips within one context.** Rejected: a peer
  that changes its declared revision mid-context is indistinguishable from an
  attacker probing for the more permissive table; fail closed.

## Consequences

- One binary serves the whole migration window, and a method-set correction is
  a data change to a declaration, not a redesign. The eventual removal of the
  old revision's subsystem (no earlier than 2027-07-28) becomes a subtraction.
- The fail-closed default now depends on per-revision tables. The derivation
  test that keeps tables and declarations in lockstep becomes load-bearing —
  a method declared without revision membership must fail the build.
- The refused set is a hard edge operators will hit mid-migration. `validate
  --live` must report a configured pair's disposition (which methods translate,
  which refuse) so the edge is visible at deploy time, not at the first denied
  request.
- The interop test matrix — both host revisions crossed with both upstream
  revisions, mismatched cells asserting this boundary exactly — becomes a
  required CI fixture.
- Per-request `_meta` inspection joins the hot path for new-revision traffic;
  the parse must stay allocation-lean.
