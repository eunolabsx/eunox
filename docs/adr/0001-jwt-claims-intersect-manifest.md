# ADR-0001: JWT capability claims intersect the manifest, never expand it

- **Status:** Draft
- **Date:** 2026-06-10
- **Deciders:** eunox maintainers

## Context

`eunox` can authorize MCP calls from two sources at once:

1. A local YAML **capability manifest**, the operator's declared allowlist for
   an upstream.
2. **IdP-issued JWT capability claims** (`--jwks-uri`), where an identity
   provider stamps per-agent or per-task capabilities into the bearer token —
   e.g. `mcp.capabilities: ["tool:read_file?path=/reports/*"]`. See
   [jwt.go](../../internal/pdp/jwt.go) for the claim schema (v0.2).

When both are configured, the two policies can disagree about a given call. We
must define precisely what happens then. This is a security boundary: the JWT
arrives over the wire from a token issuer that the proxy operator does not
fully control, while the manifest is the operator's own on-disk artifact,
reviewed and version-controlled alongside the deployment.

The relevant invariant is **fail closed** (see
[CONTRIBUTING.md](../../CONTRIBUTING.md) and
[architecture.md](../architecture.md)): on any ambiguity, deny. The question is
how to compose two allow/deny policies without creating a path where presenting
a token *widens* what the operator's manifest permits.

## Decision

When both `--jwks-uri` and `--policy` are set, a call is allowed **only if both
the JWT claims and the manifest allow it independently** — the intersection
(logical AND). The JWT can only *narrow* what the manifest already permits; it
can never grant access the manifest withholds.

`JWTPDP.Decide` evaluates the JWT-derived constraints first and, only on a JWT
allow, delegates to the inner `ManifestPDP`, which must also allow — neither
side can waive the other's constraints
([jwt.go](../../internal/pdp/jwt.go)). Two sub-rules fall out of
this and are settled here as well:

- **Absent `mcp.capabilities` ⇒ identity-only, but only with a manifest
  backstop.** A token with no `mcp.capabilities` field imposes no capability
  restriction of its own; the decision falls through to the inner manifest PDP,
  which is then the deciding authority. This deferral is safe only when a real
  manifest backs the route. On a route with **no** manifest (an unpoliced/wiretap
  route, whose inner is `AlwaysAllowPDP`, or no inner at all) there is nothing to
  fall through to, so an identity-only token is **denied** (fail closed) rather
  than inheriting `alwaysAllow`'s allow-everything: JWT mode requires either a
  capability claim on the token or a manifest on the route. A token *with* the
  field (even an empty array) is an exhaustive allowlist — anything not listed is
  denied. The pointer-vs-nil distinction that encodes "absent" vs "present but
  empty" is deliberate ([jwt.go](../../internal/pdp/jwt.go)). This
  no-backstop rule was added in the 2026-06-13 amendment below.
- **Cross-argument constraints AND together.** When the manifest and the JWT
  constrain *different* arguments of the same tool, both condition sets must
  pass; evaluating JWT conditions before delegating to the manifest achieves
  this for free.

### Scope: server-initiated sampling is outside the intersection

The intersection applies to client-initiated requests — the ones that arrive
with a bearer token (`tools/call`, `resources/read`, `resources/subscribe`,
`prompts/get`, and `*/list` filtering). Server-initiated
`sampling/createMessage` is the deliberate carve-out: the *upstream* initiates
it, and in HTTP mode the request is broadcast to every SSE subscriber, so
there is no single bearer token in scope to intersect.
`JWTPDP.DecideSampling` therefore checks the kill switch first (a killed
session, a killed agent — attributed from the session's most recently
validated token — or a global kill denies, and a kill-store error fails
closed; when the inner manifest PDP shares the same manager the delegated
check is the one that runs) and then delegates the capability decision to the
inner manifest's explicit `system:sampling/createMessage` opt-in, denying when
there is no inner authorizer (JWT-only mode, unpoliced route).

The manifest-as-upper-bound property is preserved — no token can enable
sampling the manifest withholds. The converse, however, does not hold: a
present-but-empty or narrow `mcp.capabilities` claim does **not** block
sampling the manifest opts in to, because no token is attributable to the
upstream-initiated request. Operators who need sampling off for a deployment
must withhold the manifest opt-in, or use the kill switch for immediate
revocation. See the capability-manifest guide § 2b.

## Alternatives considered

- **Union (JWT OR manifest).** Rejected outright: it lets a caller widen access
  by presenting a token, turning the IdP into an authority that can override the
  operator's local policy. That inverts the trust relationship and breaks
  fail-closed.
- **JWT replaces the manifest when present.** Rejected for the same reason in a
  subtler form — a permissive or compromised token issuer could grant
  capabilities the operator never put in the manifest. Intersection keeps the
  manifest as a hard ceiling the token cannot exceed.
- **Manifest-only, ignore JWT capabilities.** Rejected: it throws away the
  per-agent/per-task least-privilege scoping that is the entire point of
  IdP-issued capabilities. We want the token to *tighten* policy per principal.

## Consequences

- The manifest is always an upper bound. Reasoning about "what is the most this
  proxy could ever allow?" needs only the manifest, regardless of what any token
  claims — a property operators and auditors can rely on.
- A token issuer can reduce a principal's access but never escalate it. A
  compromised or overly-permissive IdP cannot widen the blast radius beyond the
  manifest.
- Misconfiguration tends to fail safe: if the manifest is narrower than the
  operator intended, the result is over-denial (a visible, debuggable failure),
  not over-permission (a silent breach).
- The cost is that capabilities must be granted in **both** places to take
  effect — a tool absent from the manifest stays denied no matter what the token
  says. This can surprise operators ("the token allows it, why is it denied?").
  The denial path names the target so this is diagnosable from the JSON-RPC
  error, and `list` filtering composes the same way (intersection) so a host
  never sees a tool the combined policy would deny.
- This composition rule is load-bearing for the threat model and must hold for
  any future PDP that wraps another. New PDPs that delegate to an `inner` PDP
  must preserve AND-composition; they must not introduce an OR path. The
  sampling carve-out above is not an OR path — it delegates one
  server-initiated decision wholly to the inner manifest, never widening it —
  but any further exception of this kind needs the same justification: no
  token attributable to the request.

## Amendment (2026-06-13): absent capabilities requires a manifest backstop

### Context

The original "absent `mcp.capabilities` ⇒ identity-only, fall through to the
manifest" rule assumed the fall-through always reached an enforcing manifest. In
the gateway that is not always true: an **unpoliced** route (no `policy:` in the
config — the wiretap posture) is wired with `AlwaysAllowPDP` as the JWTPDP's
inner. So "fall through to the inner PDP" on such a route meant *allow
everything*. A security review found the consequence: with `--jwks-uri` set, a
validly-signed token that simply omits `mcp.capabilities` was granted every tool
on any unpoliced route — capability enforcement became an opt-in the token
issuer controls, the exact fail-open the rest of this ADR rules out. (The
deferral is correct for a **policed** route, where the inner `ManifestPDP`
enforces the operator's allowlist; only the no-manifest case was wrong.)

### Decision

When `mcp.capabilities` is absent, the JWTPDP defers to the inner PDP **only when
that inner is a real policy backstop**. A nil inner or an `AlwaysAllowPDP`
(unpoliced/wiretap route) is not a backstop: the request is **denied**
(`AUTHORIZATION_FAILED`) rather than allowed. In effect, enabling JWT mode
requires every request to be covered by *either* a capability claim on the token
*or* a manifest policy on the route. `list` filtering composes the same way: on a
no-backstop route an identity-only token sees an empty listing, matching the
call-time deny. `JWTPDP.innerEnforces()` is the single predicate
([jwt.go](../../internal/pdp/jwt.go)); it is derived from the inner PDP
at call time so every construction path is consistent.

This is consistent with the sampling carve-out, which already denied on an
unpoliced route ("denying when there is no inner authorizer"). The
manifest-as-upper-bound property is unchanged — this only *narrows* the
absent-capabilities case, never widens it.

### Consequences

- A deployment that wants "require a valid JWT for identity, enforce nothing"
  (auth-gated wiretap with no capability scoping) is no longer expressible by
  pairing `--jwks-uri` with an unpoliced route and capability-less tokens: such
  requests now deny. Add a permissive manifest to the route, or include
  capability claims in the tokens. This is the intended fail-closed direction.
- Tokens that *do* carry `mcp.capabilities` are unaffected on every route, as are
  policed routes with identity-only tokens (the manifest still governs).

## Amendment (2026-06-26): capability-claim enforcement is experimental and opt-in

### Context

The `mcp.capabilities` claim schema (JWT v0.2) — the per-token capability set this
ADR composes with the manifest — is adjacent to functionality eunox deliberately
leaves to the identity provider: it is a small authorization grammar carried in the
token, and its shape is still converging with the capability-manifest spec. eunox is
a *capability firewall*, not an authorization server, so shipping this grammar as a
stable, always-on surface overcommits to a format that may still change before 1.0.

### Decision

Capability-claim enforcement is now **experimental and off by default**, gated behind
`--jwt-experimental-capabilities` (`JWTPDPOptions.ExperimentalCapabilities`). The
composition rule in this ADR is unchanged *when the flag is on*: the JWT is
intersected with the manifest and can only restrict, never expand.

When the flag is **off** (the default), `JWTPDP.ValidateToken` rejects any token that
carries `mcp.capabilities` (HTTP 401, fail closed) rather than admitting it with the
capability restriction silently dropped — dropping it would fail open, widening access
past what the token issuer intended, the exact inversion this ADR rules out. A token
that omits the field is identity-only and unaffected, and remains subject to the
manifest-backstop rule of the 2026-06-13 amendment above. The stable, always-active
surface is unchanged: JWT signature/`exp`/`iss`/`aud` verification and the identity
claims (`sub`, `mcp.task_id`, `mcp.agent_id`).

### Consequences

- The manifest-as-upper-bound property holds *a fortiori*: with the flag off a
  capability-bearing token is rejected outright, so it can neither widen nor narrow —
  the manifest governs identity-only tokens alone.
- Operators who relied on the JWT intersection must add `--jwt-experimental-capabilities`
  to keep enforcing capability claims; otherwise capability-bearing tokens now 401.
  This is the intended fail-closed direction while the schema is experimental.
- The flag is the single gate; the comparison/composition logic is otherwise
  untouched, so re-stabilizing the schema later is a matter of flipping the default,
  not rewriting the PDP.
