# ADR-0005: Resolve upstream credentials per request via a provider seam, prefer delegation over a shared static token

- **Status:** Draft
- **Date:** 2026-06-28
- **Deciders:** eunox maintainers

## Context

eunox authenticates *to* a remote HTTP upstream with a single static header per
route. The header is configured once (`UpstreamAuthHeader`,
[gateway_config.go:209](../../internal/config/gateway_config.go)) and attached
verbatim to every forwarded request
([http_remote.go:148](../../internal/transport/http_remote.go), replayed on each
call at [:504](../../internal/transport/http_remote.go)). A stdio upstream
receives its credential the same way in spirit: a static secret handed to the
subprocess environment at spawn.

The consequence is that **every caller who clears eunox's front-door policy
reaches the upstream as the same identity.** That is the OAuth *confused-deputy*
shape: eunox lends its upstream authority to any request the manifest and JWT let
through. There is no per-caller scoping at the upstream, and the upstream's own
audit attributes every action to eunox's single credential rather than to the
human or agent behind the call.

This sits awkwardly against what eunox already knows. The transport validates the
*inbound* credential as an OAuth 2.1 resource server — a Bearer JWT verified
against JWKS, with the discovery surface from
[ADR-0002](./0002-oauth-protected-resource-metadata.md) — and
[ADR-0004](./0004-bearer-identity-session-anchor.md) anchors correlation and
revocation on that verified bearer identity. So a verified caller identity is in
hand on every request and then discarded at the upstream boundary, replaced by
the static token.

The upstream's *own* `401` is also flattened today. Any non-200 from the upstream
becomes an opaque error ([http_remote.go:336](../../internal/transport/http_remote.go))
surfaced to the host as a generic `codeUpstreamError`
([http_handlers.go](../../internal/transport/http_handlers.go)); eunox neither
relays the upstream `WWW-Authenticate` nor attempts to acquire a credential. An
operator cannot tell "upstream rejected the credential" from "upstream is down".

### Two token domains, two legs

The design hinges on keeping two relationships distinct:

- **Leg 1 (caller → eunox).** eunox is an OAuth resource server for the caller's
  authorization server. The caller presents a token whose audience is eunox;
  eunox verifies it and enforces policy. This leg is unchanged by this decision.
- **Leg 2 (eunox → upstream).** How eunox proves identity to the upstream. The
  credential here lives in the *upstream's* token domain (e.g. a GitHub-scoped
  token for a GitHub upstream). **This decision is entirely about Leg 2.**

The clarifying question for any scheme is: *whose upstream identity does the
forwarded call run as, and where did that upstream credential come from?*

### Why Leg 2 cannot be delegated to a fronting API gateway

A natural question is whether an ingress API gateway (Apigee/Kong/Envoy/cloud
API gateway) placed in front of eunox could own Leg 2 — terminate the caller's
OAuth and inject the upstream credential — leaving eunox to enforce policy only.
It cannot, and the reason is load-bearing for *where* this seam lives.

Minting an upstream credential requires knowing (a) the target audience — which
upstream this call is bound for — and (b) whether a credential is needed at all,
i.e. whether eunox will even *allow and forward* the call. Both are outputs of
eunox's policy decision over the JSON-RPC body (`method`, tool name, arguments)
and eunox's own routing. A protocol-agnostic gateway sitting *in front of* eunox
does not parse that body, so it cannot make either determination. The one signal
it can see — the URL path (`/mcp/<name>`) — encodes the upstream, but resolving
the credential from the path alone is leaky on four counts, each a version of the
same problem:

- **Config duplication.** The path→upstream→audience mapping lives in eunox's
  route config; mirroring it in the gateway is a second source of truth that
  drifts.
- **Wrong order.** Exchange would run *before* eunox's allow decision, minting
  (and logging, and rate-charging) credentials for calls eunox is about to deny.
- **Wrong granularity.** All `/mcp/<name>` calls would get one audience and
  scope, but the credential need can vary by method/tool — a distinction in the
  body the gateway cannot see.
- **Policy-shaped forwarding.** *What* eunox forwards is shaped by policy
  (redaction, list filtering, conditional allows); the upstream call is the
  output of policy evaluation, not a fixed function of the path.

So Leg-2 credential resolution belongs in eunox (or downstream of eunox's
decision), because the audience and the very need for a credential are
consequences of the MCP-policy decision. A fronting gateway legitimately owns the
body-independent concerns — TLS, coarse Leg-1 token validation, rate-limiting,
routing/load-balancing — and nothing more. The only credential work that may move
*out* of eunox is an **egress** executor that eunox *drives*: eunox decides
"forward to this upstream as this caller" and a downstream secrets-broker attaches
the token from a vault. There the decision is still eunox's; the executor is
mechanical.

### Direction of the spec

The MCP authorization direction (the July-2026 revision) is stateless and leans
into OAuth 2.1 with Resource Indicators (RFC 8707): caller identity travels on
every request and tokens explicitly name their target resource. The surrounding
ecosystem has converged on OAuth 2.0 Token Exchange (RFC 8693) — delegation via
the `act` claim, not impersonation — as the standard way a gateway carries a
caller's identity to an upstream without becoming a confused deputy. A per-request
credential model and audience-named tokens are precisely what a stateless
transport needs.

## Decision

**We will resolve the upstream credential per request behind a provider seam, make
the static header one implementation of that seam, and add token exchange
(RFC 8693) as the first delegated provider.** Concretely:

- The forward boundary stops reading `s.route.upstreamAuthHeader` directly and
  instead calls a provider resolved per request —
  `HeaderFor(ctx, route, claims) (name, value, err)`. The `static` provider
  reproduces today's behaviour byte-for-byte. Resolution failure is **fail
  closed** (`AUTHORIZATION_FAILED`), consistent with the load-bearing invariant
  in [CONTRIBUTING.md](../../CONTRIBUTING.md). The seam lives at the transport
  boundary, not in the enforcement engine: the engine decides allow/deny and must
  not hold IdP client secrets.
- `UpstreamConfig` gains a credential-source discriminator —
  `static` | `passthrough` | `tokenExchange` — with unknown values rejected like
  other unknown keys.

### The three providers

- **`static`** — one operator-provisioned upstream token (a PAT or a single OAuth
  token) for every caller. Simplest; stateless; unchanged by the spec direction.
  It is the confused-deputy posture — a shared upstream identity, no per-caller
  attribution — and is correct only where one trusted identity for all callers is
  acceptable.
- **`passthrough`** — eunox forwards the caller's own bearer to the upstream. It
  is valid **only** when the upstream trusts the same issuer and the token's
  audience already admits it — i.e. a single identity domain (the caller
  authenticates against the *upstream's* authorization server). Within that domain
  it preserves real per-caller identity cheaply, with no eunox-held secret. Across
  trust domains it sends a token to the wrong audience — the confused deputy
  *relocated*, and a token-leak risk; under RFC 8707 resource indicators that
  misuse becomes detectable, and eunox rejects it rather than forwarding.
- **`tokenExchange`** — eunox exchanges the verified caller token at the IdP token
  endpoint for a token whose audience is the route's upstream (RFC 8707 resource
  indicator), preserving the subject and recording eunox as the actor (`act` —
  delegation, not impersonation). **eunox is the RFC 8693 client.** The exchange
  is **lazy**: on a request with no valid cached token for `(subject, route)`,
  eunox calls the token endpoint synchronously, caches the result with a TTL
  bounded by `expires_in`, then forwards; a cache hit skips straight to forward; a
  failed exchange **denies**. The call is guarded by a circuit breaker mirroring
  the protection already wrapping JWKS fetches
  ([pkg/capability/jwkscache.go](../../pkg/capability/jwkscache.go),
  [pkg/circuitbreaker](../../pkg/circuitbreaker)). This is what crosses eunox from
  a pure resource server into also being an OAuth *client*.

`tokenExchange` carries a governance advantage beyond attribution: because eunox
requests the token, it can **down-scope and audience-lock** per route — mint a
least-privilege, short-lived, upstream-only credential — whereas `passthrough`
replays whatever scopes the caller already holds. Where least privilege matters,
exchange is preferable even in a single trust domain where passthrough would
function.

### Choosing a provider

The selector is **identity topology and what governance the deployment needs**,
not company size:

```
Need per-caller identity at the upstream?
├─ No  ───────────────────────────────────▶ static
└─ Yes
   ├─ Caller authenticates against the SAME
   │    identity domain as the upstream? ───▶ passthrough
   └─ Different domain (caller IdP ≠ upstream)?
        ├─ Upstream federates with the IdP ─▶ tokenExchange
        └─ No federation (foreign IdP) ─────▶ stored-token broker (out of scope; see below)

Overlay: need least-privilege / scope minimization on the upstream credential?
        ─────────────────────────────────────▶ prefer tokenExchange even in a single domain.
```

Enterprises tend to land on `tokenExchange` because they run a separate corporate
IdP (a cross-domain topology) and have hard attribution/least-privilege
requirements — and because they have already paid for the IdP, federation, secret
rotation, and observability that make its marginal cost low. Smaller or
upstream-native deployments often land on `static` (no per-caller need) or
`passthrough` (the upstream *is* the login). `passthrough` is not a budget
downgrade; it is the correct choice for a single trust domain.

### The upstream credential as a decision input and audit dimension

- The upstream subject and the delegation chain are recorded so the upstream call
  is attributable to the caller, not to eunox. New audit fields carry the standing
  obligations — a [threat-model](../threat-model-mcp.md) update and a
  sign-and-verify roundtrip test in the same change.
- An upstream `401` stops being an opaque infra error for the delegated providers:
  it invalidates the cached credential and triggers one bounded re-acquire, and a
  persistent upstream `401` is surfaced distinctly from a transport failure so an
  operator can tell a rejected credential from an unreachable upstream.

This composes with the stateless direction of
[ADR-0004](./0004-bearer-identity-session-anchor.md): `tokenExchange` holds no
per-connection state. The caller identity arrives on every request, the exchanged
token is mintable on any instance, and the cache lives in the shared backend
rather than on a session — so per-caller upstream identity does not reintroduce
the sticky-session coupling ADR-0004 is removing.

The heavier alternative — eunox holding each caller's long-lived upstream tokens
for a *foreign* IdP (one that cannot exchange eunox's caller token, e.g. an
upstream that wants its own provider's tokens, as GitHub's hosted server does) —
is explicitly **out of scope** for this decision. It turns eunox into a stateful
OAuth client with consent capture, a token vault, and refresh loops, and is a
separate ADR if pursued.

## Alternatives considered

- **Keep the single static header as the only mechanism.** Rejected as the only
  option: fine for one trusted identity, but the confused-deputy posture for
  multi-caller deployments and no per-caller attribution at the upstream. Retained
  as the `static` provider, not removed.
- **Token passthrough as the primary mechanism.** Rejected as the default: sound
  only when caller and upstream share an issuer and audience; across trust domains
  it sends a token to the wrong audience and cannot down-scope. Offered as
  `passthrough` with the constraint documented.
- **Resolve the credential in a fronting API gateway.** Rejected: the audience and
  the very need for a credential are consequences of eunox's policy decision over
  the JSON-RPC body, which a protocol-agnostic ingress gateway cannot see;
  resolving from the URL path alone duplicates eunox's routing, runs before the
  allow decision, and cannot vary by method/tool. The gateway owns Leg-1 and
  scaling; Leg 2 stays in eunox.
- **A per-caller stored-token broker now.** Deferred: the right answer for
  upstreams on a foreign IdP that cannot participate in exchange, but it makes
  eunox a stateful OAuth client — a larger commitment and a decision of its own.
- **Delegate the exchange to an egress credential-broker rather than running it
  in-process.** A viable variant — distinct from the stored-token broker above,
  which is about *what kind* of token; this is about *where the exchange runs*.
  eunox still makes the policy decision and chooses the upstream and caller, but
  forwards the authorized request *through* a separate egress component (sidecar /
  egress proxy / token broker) that holds the IdP client secret, performs the
  exchange (or serves a warm/stored token), and attaches the credential. This
  keeps the IdP secret, the token cache, and the token-endpoint round trip out of
  eunox's process and off its enforcement critical path, preserving the
  resource-server posture and the ~microsecond decision path. It works precisely
  because the broker sits *downstream* of the decision — eunox has already chosen
  the upstream and subject, so the broker is a mechanical executor, not a
  policy-maker (unlike the fronting ingress gateway rejected above, which sits
  *upstream* of the decision and cannot know the audience or whether a credential
  is needed). The cost is a separate component to run and secure and a
  now-security-load-bearing eunox→broker hop (mTLS / signed assertion /
  loopback-only) over which the caller identity is conveyed; a weak hop just
  relocates the confused deputy. This is a *different integration point* from the
  header-returning providers above: where `static`/`passthrough`/`tokenExchange`
  resolve through `HeaderFor` (a credential eunox attaches to the upstream call it
  makes itself), the egress broker changes the forward *target* — eunox forwards
  to the broker, which attaches the credential and calls the upstream. So the
  resolver design should accommodate both shapes: a header-provider seam for
  in-process resolution and a forward-target hook for egress delegation. The two
  are realizations of the same *decision*, chosen by deployment posture (the
  latter suited to environments that already run an egress/secret layer and want
  the OAuth-client surface out of the enforcement binary).
- **Acquire the credential inside the enforcement engine.** Rejected: credential
  acquisition is a transport and identity concern, not policy. The engine returns
  allow/deny and must not hold IdP client secrets; the seam belongs at the forward
  boundary.

## Consequences

- **eunox becomes an OAuth client, not only a resource server.** The
  `tokenExchange` provider holds eunox's own client credentials for the exchange
  (client_id plus secret / `private_key_jwt` / mTLS, env-ref'd, never in-file) and
  must be registered at the IdP as a client authorized for the token-exchange
  grant and the upstream's audience. The IdP-side trust (and, for a foreign
  upstream such as GitHub, the IdP↔upstream federation) is setup *outside* eunox
  and gates whether the provider is usable at all on a given route. This also
  **expands eunox's runtime trust surface and blast radius**: a pure resource
  server holds no outbound secret, but `tokenExchange` keeps IdP client
  credentials and (when cached) live upstream-capable tokens inside the
  enforcement binary, so an eunox compromise now additionally confers the ability
  to mint upstream tokens for any caller it can present — strictly more than
  verifying inbound tokens conferred.
- **New configuration keys and a JSON Schema change** in `schemas/`, carrying the
  standing roundtrip-test and `docs/` obligations.
- **A new external service on the enforcement critical path.** `tokenExchange`
  puts the IdP token endpoint in-line on the data plane for every cache miss — in
  tension with the deliberate cached-then-fail-closed JWKS posture (threat model
  §5.2), which keeps the IdP *endpoint* off the per-request path (the key set is
  cache-served, so JWKS validation runs locally) so an IdP outage could not cause
  an immediate enforcement outage. The miss rate is higher and more
  user-correlated than JWKS (one cache entry per `(subject, route)`, not one
  shared key set), so deploys, scale-ups, evictions, and TTL churn cause exchange
  bursts that can also trip the IdP token endpoint's own rate limits. Latency
  turns bimodal: a hit costs a cache lookup, a miss costs a full token-endpoint
  round trip — orders of magnitude over the ~microsecond decision path. A circuit
  breaker, request coalescing (as the JWKS fetch already uses), and fail-closed
  denial bound the blast radius, but the coupling is real. The **egress
  credential-broker** alternative keeps this dependency, its secret, and its token
  cache off eunox's process and decision path entirely (see Alternatives).
- **Caching exchanged tokens is a security trade.** A shared cache (Redis) lets
  any instance reuse a token but puts live upstream-capable credentials at rest
  for many callers — encryption at rest, access control, and blast radius become
  threat-model items. A per-instance in-memory cache avoids tokens at rest but
  multiplies exchange volume across the fleet. This is a deliberate choice, not a
  default.
- **Revocation has a TTL tension.** A cached exchanged token stays valid at the
  upstream until it expires; eunox's own kill switch still denies per request
  (ADR-0004), so eunox-side revocation bites immediately, but the minted token
  lives to its TTL. Shorter TTL tightens upstream revocation at the cost of more
  exchanges.
- **Operational surface grows for delegated routes.** Token-endpoint rate limits,
  multi-IdP fan-out (distinct exchange-client identities per IdP relationship),
  new failure modes that must read distinctly (exchange-failure vs upstream-down),
  new metrics/alerts (exchange rate, cache-hit ratio, exchange latency/errors,
  breaker state on the existing `/healthz`+`/metrics` surface), and client-secret
  rotation. This reuses the JWKS / kill-switch ([ADR-0003](./0003-redis-killswitch-fail-open.md))
  operational playbook rather than inventing a new one.
- **The cost is opt-in per route.** `static` adds none of the above; a deployment
  pays this complexity only on routes that need per-caller upstream identity, and
  mixed configurations (one upstream `static`, another `tokenExchange`) are
  expected.
- **Per-caller attribution at the upstream and in eunox's audit becomes
  possible.** Existing single-identity deployments are unchanged until they opt
  in.
- **The [threat model](../threat-model-mcp.md) gains** confused-deputy mitigation,
  audience confinement via RFC 8707, caching of exchanged tokens at rest, and the
  upstream-`401` relay path. Credential leakage on an upstream redirect is already
  mitigated (the `CheckRedirect` rationale at
  [http_remote.go:138](../../internal/transport/http_remote.go)) and that property
  must hold for resolved credentials too.
- This commits to the *direction and the seam*, not the precise wire profile of
  the exchange, which tracks the published spec revision and the IdP's
  token-exchange support; divergence is reconciled there rather than guessed here.
