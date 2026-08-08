# MCP Conformance Matrix

**Spec version targeted: MCP 2025-11-25**

This document states how eunox handles each MCP method — enforced, filtered,
forwarded verbatim, handled locally by the proxy, or denied; what it provides in
the OAuth/authorization space; and what is
intentionally delegated to your identity provider (IdP) or authorization server
(AS).

---

## Positioning

> Use your IdP or OAuth stack for identity — authentication, consent, and token
> issuance. Use eunox to enforce least-privilege MCP capabilities at discovery
> and invocation time.

eunox is an **MCP capability firewall**, not an authorization server. It
does not issue tokens, run OAuth flows, or manage client registrations. It
assumes a valid, authenticated session (optionally backed by a Bearer JWT from
your IdP) and enforces a fine-grained YAML policy on top of it.

---

## Method enforcement table

| MCP method | eunox behavior | Notes |
|---|---|---|
| `tools/call` | **Enforced** — PDP decision (allow / deny) per manifest entry | Fails closed on unmapped tool names |
| `tools/list` | **Filtered** — only tools with `action: call` (or `*`) in manifest are returned | Capability discovery is gated |
| `resources/read` | **Enforced** — PDP decision per manifest entry | URI matched against `allowedValues` or pattern |
| `resources/list` | **Filtered** — only resources with `action: read` (or `*`) in manifest are returned | |
| `resources/subscribe` | **Enforced** — same policy path as `resources/read` | |
| `resources/unsubscribe` | **Enforced** — same manifest entry as `resources/read`, matched by name + `read` action alone | Cancelling reduces data flow, so the `read` grant that permitted the subscription permits its cancellation. Conditions on the entry are not evaluated and no session state is consumed: metering a cancel would let a spent `maxCalls` budget deny the unsubscribe that closes the stream the subscribe opened. Kill switch, principal scoping, JWT capability claims, and the entry's own `enforcement: audit` posture still apply — the last so an observe-mode entry downgrades the cancel exactly as it downgrades the read |
| `prompts/get` | **Enforced** — PDP decision per manifest entry | |
| `prompts/list` | **Filtered** — only prompts with `action: get` (or `*`) in manifest are returned | |
| `sampling/createMessage` *(upstream→host)* | **Enforced** (local subprocess upstream only) — denied by default; requires explicit `system:sampling/createMessage` entry in manifest, and the kill switch applies. On the allow path the host's response is routed back to the upstream so the round-trip completes | Fail-closed: absent = deny. See the transport caveats in *Known gaps* below. On **both** hosts each server-initiated request is handled on its own goroutine rather than on the upstream reader, so a request waiting for the decision turn cannot stall response delivery: independent server-initiated requests consequently have **no ordering guarantee** among themselves, and at most 32 may be in flight at once — per proxy on stdio (one upstream), per SESSION on HTTP (one upstream subprocess each) — beyond which the upstream is answered with a retryable server-busy error (`-32000`) and the refusal is recorded `RESOURCE_EXHAUSTED` |
| Upstream-initiated non-sampling requests (e.g. `roots/list`) | **Forwarded** for local subprocess upstreams — not policy-enforced (no allow/deny decision), but kill-switch-checked, `--require-audit=strict`-gated, and audited (an allow record on delivery, an `ENFORCEMENT_ERROR` deny if no client received it); the host's response is routed back to the upstream | Remote HTTP upstreams have no background reader and do not consume server-initiated messages. These share the concurrency bound and the ordering caveat noted for `sampling/createMessage` above, on both hosts |
| `initialize` *(host→proxy)* | **Handled by proxy** — eunox sends its own `initialize` to the upstream at startup and synthesizes the host-facing response using the upstream's declared capabilities | Host never sees the upstream's raw response |
| `ping` *(host→proxy)* | **Answered locally** with the spec's empty result. It carries no arguments, names no target, and reaches no upstream, so there is nothing for a manifest to authorize; it is not forwarded, so it cannot be used to probe upstream liveness through the proxy. | Upstream is never called. Subject to the shared kill gate: a killed session gets `KILL_SWITCH`, not a pong. No audit record (a handshake-level utility, not a guarded action). |
| Host notifications (`notifications/*`) *(host→upstream)* | **Allowlisted** — only `notifications/cancelled`, `notifications/progress`, and `notifications/roots/list_changed` are forwarded verbatim (no PDP evaluation of their contents). Any other notification-framed method is denied and recorded (`AUTHORIZATION_FAILED`), never reaching the upstream: an enforced method smuggled in as a notification (no `id`) is rejected rather than bypassing its PDP decision, and any other unmapped method gets the same fail-closed default its request-framed twin gets from `dispatchUnmapped` | Exceptions: `notifications/initialized` is swallowed (the proxy has already sent its own to the upstream); `notifications/cancelled` has its `params.requestId` rewritten to the proxy nonce the upstream saw for that request (host request ids are nonce-rewritten on the wire), so the cancel actually targets the in-flight call — a cancel for a request no longer in flight is dropped. Cancellation is best-effort on HTTP: a cancel delivered on a separate connection concurrently with its target request (before the request registered) is dropped, matching the MCP spec's inherently-racy cancellation. A killed session's notifications are dropped (ack'd) rather than forwarded. |
| Upstream notifications (`notifications/*`) *(upstream→host)* | **Relayed** — stdio writes to the host, HTTP broadcasts to the session's SSE stream(s) | A killed session stops receiving the relay: both transports gate the relay on the kill switch (so a Redis-backed kill, which does not evict SSE streams, still shuts the server→client channel), and the drop is recorded to the audit tape. |
| All other **host-originated request** methods | **Denied** — `AUTHORIZATION_FAILED` returned to host; upstream never called | Fail-closed default for unmapped host requests |

> **MCP deprecation note (SEP-2577).** The MCP specification has deprecated
> server-initiated **sampling**, **roots**, and **logging** as an advisory change —
> no wire-level protocol changes, and all three stay functional through the spec's
> transition window. eunox's behavior in the table above is unchanged:
> `sampling/createMessage` stays **enforced** (deny-by-default), `roots/list` stays
> **forwarded**, and `logging/setLevel` is already **denied** as an unmapped host
> request. A deprecated-but-functional capability still needs a deny lever, so this
> enforcement is retained for the transition and reassessed only if a future spec
> version removes these methods from the schema.

### Fail-closed invariant (enforce mode)

In the default `enforcement: enforce` posture, **when a policy is configured
for the route**, every enforced method requires an explicit `allow` decision
from the manifest. A missing manifest entry or an unmapped method produces a
JSON-RPC `AUTHORIZATION_FAILED` error — the upstream is never called.

**No-policy routes:** In gateway mode (`transport: http`), a route with no
`policy` configured and not in audit mode is a misconfiguration: the gateway
**fails closed at startup** and refuses to start, rather than mounting an
allow-all route. A route that declares `enforcement: audit` with no policy is an
explicit allow-and-log (wiretap) posture — every enforced-method call is
forwarded and recorded, none blocked — and is permitted. The single-upstream
stdio host (`transport: stdio`) with no policy remains a warn-and-forward
passthrough. Once a manifest is attached, the deny-by-default allowlist applies.

A malformed or missing JWT is handled earlier, at the HTTP authentication layer
before JSON-RPC dispatch: the HTTP transport returns a plain `401 Unauthorized`
with a `WWW-Authenticate` challenge and stops processing. This happens even in
audit mode, because JWT validation is authentication, not policy.

**Audit / observe mode exception:** When a route is set to
`enforcement: audit`, or an individual manifest entry carries
`enforcement: audit`, would-be denials are logged and then forwarded to the
upstream anyway — the decision is recorded but not enforced. Per-entry audit
mode (marking a capability entry `enforcement: audit`) behaves identically to route-level audit mode for that
entry. In audit mode the "upstream is never called" guarantee does not hold.

In audit mode `*/list` responses are also returned **unfiltered**: the host
sees the full upstream catalog, not the manifest-permitted subset. This mirrors
the call path (a would-be deny is downgraded to a logged forward), so observe
mode is a faithful wiretap of what the upstream exposes rather than a dry-run
preview of the enforced view. The kill switch is the one exception that still
hard-blocks in audit mode.

When JWT mode is active, the JWT claims additionally narrow the effective
allowlist only when `mcp.capabilities` is present in the token *and the
experimental `--jwt-experimental-capabilities` flag is enabled*; see the JWT
semantics section below.

---

## OAuth / authorization: what eunox provides vs. what your IdP must provide

| Capability | eunox | Your IdP / AS |
|---|---|---|
| **Token issuance** | No | Yes — issue Bearer JWTs with `mcp.capabilities` claims |
| **User authentication** | No | Yes — login, MFA, session |
| **OAuth consent flows** | No | Yes — authorization_code, device flow, etc. |
| **Client registration** | No | Yes — dynamic or static client registration |
| **OAuth Client ID Metadata Documents** | No | Yes — if required by your clients |
| **Incremental scope / step-up auth** | No | Yes — your AS handles scope escalation |
| **JWKS endpoint** | No (consumes) | Yes — publish JWKS at `--jwks-uri` |
| **JWT signature + expiry validation** | Yes — when `--jwks-uri` is set | |
| **JWT claims intersection with manifest** | **Experimental (opt-in)** — enabled with `--jwt-experimental-capabilities`; off by default, where a token carrying `mcp.capabilities` is rejected (HTTP 401). When on, JWT claims can only restrict the route's manifest, never expand it. Every enforcing route has a manifest: a policy-less gateway route fails closed at startup unless it sets `enforcement: audit`, in which case it is a wiretap that records the JWT decision but forwards every call (see JWT semantics below) | |
| **RFC 9728 protected-resource metadata** | Yes — serves `/.well-known/oauth-protected-resource`; issues `WWW-Authenticate` challenges on 401 responses. Requires bearer-token validation (`--jwks-uri` or `listen.authToken`): publishing the document without it would advertise a protection the gateway does not enforce, so it is rejected at startup| |
| **Per-route resource metadata paths** (gateway) | Yes — `/.well-known/oauth-protected-resource/mcp/<name>` is registered for each route, but all paths serve the same global document (configured via `listen.oauthResource` + `listen.oauthAuthorizationServers`) | |
| **Fine-grained capability enforcement** | Yes — per-tool, per-resource, per-prompt, per-parameter conditions | |
| **Audit log** | Yes — append-only OCSF JSONL, HMAC-SHA256 signed | |
| **Kill switch / session revocation** | Yes — in-memory or Redis; consumed by the enforcement layer, and kill-switch denials are written to the audit log | |

### JWT intersection semantics

> **Experimental — opt-in.** The `mcp.capabilities` claim schema (JWT schema
> v0.2) is experimental and its format may change before 1.0. The intersection
> described below is enforced only when `--jwt-experimental-capabilities` is set.
> With the flag **off** (the default), a token that carries `mcp.capabilities` is
> rejected at validation (HTTP 401) rather than having its restriction silently
> dropped; a token that omits the field is accepted as identity-only. Signature,
> expiry, issuer, and audience validation and the identity claims (`sub`,
> `mcp.task_id`, `mcp.agent_id`) are stable and always active, independent of the
> flag.

When `--jwks-uri` is configured, the token is always validated (signature,
expiry, issuer, audience) before dispatch. Capability enforcement then depends on
whether `--jwt-experimental-capabilities` is set and whether the token carries the
`mcp.capabilities` field:

- **`mcp.capabilities` present, flag on:** AND semantics apply. The JWT capability
  claims are an exhaustive allowlist that narrows the effective policy; any target
  not listed in the JWT is denied even if the manifest would allow it. JWT claims
  can only restrict — they cannot grant access to anything the manifest denies.
- **`mcp.capabilities` present, flag off (default):** the token is rejected (HTTP
  401, fail closed) — the experimental capability schema is not honored, and its
  restriction is never silently dropped.
- **`mcp.capabilities` absent:** The JWT provides identity only. No capability
  restriction is applied from the JWT; the manifest governs alone. (Unaffected by
  the flag.)

A capability-claim condition value (the shorthand `?path=/reports/*` form) doubles
as an argument-value glob at enforcement time, exactly as a manifest
`allowedValues` entry does. Such values are validated as globs when the token is
verified: a malformed pattern (e.g. an unclosed character class) rejects the token
up front rather than silently matching nothing and denying every affected call
with a misleading `VALUE_NOT_PERMITTED` — mirroring the manifest load-time check.

The one exception, and it is the same exception the manifest path makes: a
**recognized `${task.*}` reference** (`?workspace_id=${task.id}`) is not a glob.
It is compared by exact equality against the value the token's own claim resolves
to, never glob-matched — a `task_id` of `*` must not become a wildcard the token
holder granted themselves — and it never matches its own placeholder text. An
*unrecognized* reference (`${STAGE}`) stays an ordinary literal and matches itself:
a claim value has not passed through the manifest loader, so there is no
load-time error to report, and treating it as a reference would void the grant
with nothing to grep for. See the capability manifest guide, §5.4.

Every enforcing route in JWT mode has a manifest. JWT mode requires the HTTP
transport, where — since SEC-05 (see the
[fail-closed invariant](#fail-closed-invariant-enforce-mode) above) — a route
declared with no `policy:` fails closed at startup unless it sets
`enforcement: audit`. There is therefore no runtime path where a JWT bounds an
otherwise allow-all route. The one policy-less route that can run is an
`enforcement: audit` wiretap: its inner PDP is allow-all, the JWT decision
(narrowed by the claims or not) is recorded in the audit log, and the call is
then forwarded regardless — observed, never enforced.

See [ADR-0001](./adr/0001-jwt-claims-intersect-manifest.md) for the rationale
behind the intersection semantics and the identity-only fallback (both cases
above are part of its Decision). The policy-less wiretap case is governed by
SEC-05, not by the ADR; it is documented here from the implemented behavior.

---

## Known gaps vs. MCP 2025-11-25

The following 2025-11-25 features are not currently enforced by eunox.
Behavior depends on the direction each method flows (host-originated requests
are denied by the fail-closed default; upstream-initiated requests are forwarded
verbatim by the server-initiated request handler for local subprocess upstreams
only — remote HTTP upstreams have no background reader and do not consume
server-initiated messages).

| Feature | MCP 2025-11-25 method(s) | eunox behavior today | Notes |
|---|---|---|---|
| **Elicitation** | `elicitation/create` *(upstream→host)* | **Forwarded** for local subprocess upstreams — not policy-enforced, but kill-switch-checked and audited via the shared server-request path; not consumed for remote HTTP upstreams | `elicitation/create` flows upstream→host; it is not a host-originated request and is not caught by the unmapped-method denial path |
| **Tasks** | `tasks/get`, `tasks/result`, `tasks/cancel`, `tasks/list` | **Host-originated:** Denied (unmapped — fail-closed); **Upstream-initiated:** Forwarded for local subprocess upstreams — not policy-enforced, but kill-switch-checked and audited; not consumed for remote HTTP upstreams | MCP 2025-11-25 tasks methods can flow in either direction; eunox has no handler for them in either direction |
| **Sampling tool calls** | `sampling/createMessage` with `tools` in model preferences | Enforced at the `sampling/createMessage` level only; per-tool sampling controls are not applied inside the sampling payload | Payload-level inspection not yet implemented |
| **Sampling under JWT mode** | `sampling/createMessage` | **Manifest opt-in governs**, with or without `--jwks-uri`: the JWT wrapper delegates the sampling decision to the route's manifest. Token claims neither grant nor restrict it — the request is upstream-initiated, so no bearer token is in scope (the § 5.2 exhaustive-allowlist rule does not apply). The kill switch is enforced (global, session, and agent via the session's initialize-time identity) | See ADR-0001 (scope section) and the capability-manifest guide § 2b |
| **Sampling — remote HTTP upstream** | `sampling/createMessage` | **Not enforced** — remote HTTP upstream mode has no background reader; server-initiated messages arrive on the SSE stream but are not consumed or forwarded | Only local subprocess upstreams support server-initiated sampling |
| **Sampling — stdio host + HTTP upstream** | `sampling/createMessage` | **Not enforced** — when the stdio transport is the host side but the upstream is HTTP, server-initiated messages are not consumed; the proxy logs a notice and sampling deny control is inactive | This transport combination does not support server-initiated sampling enforcement |

Contributions adding enforcement for elicitation or tasks should follow the
pattern in `internal/transport/stdio.go` — add a handler, register it in the
shared dispatch switch (`internal/transport/dispatch.go`), write a test in
`internal/transport/enforcement_gaps_test.go`, and update this table.

## The 2026-07-28 stateless revision: published, not yet supported

The 2026-07-28 MCP revision is the published stable specification, but it is **not
yet the spec eunox targets** — eunox still targets 2025-11-25. Two of its changes
place obligations on a filtering proxy that are worth recording ahead of the
broader conformance work, part of which is decided in
[ADR-0004](adr/0004-bearer-identity-session-anchor.md) (see below for exactly
which part). The full migration is planned in
[mcp-2026-07-28-plan.md](mcp-2026-07-28-plan.md).

| Feature | 2026-07-28 method / field | eunox disposition | Notes |
|---|---|---|---|
| **List-result caching** (SEP-2549) | `cacheScope` (`public`/`private`) + `ttlMs` on `*/list`, `resources/read`, and the discovery result | **Open obligation.** eunox filters `*/list` per identity, so every list it emits is authorization-context-specific. `filterListResult` preserves sibling fields verbatim, so an upstream `cacheScope: public` would pass through unchanged on a personalized response. The fix is to **override `cacheScope` to `private`** on any response eunox has filtered (never preserve an upstream `public`); `ttlMs` may be preserved as a freshness hint. See threat model L-6. | A shared downstream cache honoring `public` on a filtered list could serve one identity's narrowed view to another — the spec's "caches MUST NOT be shared across authorization contexts" invariant |
| **MCP Apps** (SEP-1865) | `ui://` template resources; `ui/*` host↔iframe bridge | **Covered by existing mediation; documentation watch item.** App UI templates are fetched via `resources/read` / `resources/list` (already gated and filtered) and UI-initiated execution is an ordinary `tools/call` (already enforced and audited). The `ui/*` methods run on the host↔iframe postMessage bridge, which never traverses eunox. No new server-transport method exists today. | A *future* Apps revision adding a server-transport `app/*` method would hit the fail-closed unmapped-method path and need classification |

Broader 2026-07-28 conformance splits into what
[ADR-0004](adr/0004-bearer-identity-session-anchor.md) actually decides and what
it does not — stated precisely here because the ADR is Draft and easy to
over-cite:

- **Decided in ADR-0004** (design depth, not yet implemented): the
  bearer-identity/revocation re-anchor (`jti`/`agent_id`, `RevokeJTI`/`ReviveJTI`);
  the multi-round-trip replacement for server-initiated requests — the
  `InputRequiredResult`/`inputRequests`/`requestState` exchange that replaces the
  standalone GET SSE push, including where the enforcement work lands
  (`internal/transport/dispatch.go`, `forward.go`'s `enforcedForwardCore`) —
  pending exact field names and encodings from the published revision. Its third
  decided item, dual protocol-version negotiation at the seam level, has since
  landed (see below).
- **Landed:** the negotiation spine of
  [ADR-0006](adr/0006-dual-revision-translation-boundary.md) — per-peer revision
  negotiation (host side per request, upstream side pinned per route), the
  revision-scoped dispatch tables derived from one declaration per method, the
  `UNSUPPORTED_PROTOCOL_VERSION` (-32022) refusal, the per-upstream
  `protocolVersion` config pin, and the `protocol_revision` audit field. See the
  per-revision method table below.
- **Designed in Draft ADRs, not yet implemented:** the mismatched-pair
  translation boundary, the `server/discover` responder and its list-filter
  parity, the `Mcp-Method`/`Mcp-Name` headers, and the CLI probe/drift
  dual-revision handling in
  [ADR-0006](adr/0006-dual-revision-translation-boundary.md); the
  MRTR signed continuation and its commit-once metering in
  [ADR-0007](adr/0007-mrtr-signed-continuation.md); `subscriptions/listen` and
  the tasks extension in
  [ADR-0008](adr/0008-stream-and-task-enforcement.md). The moved
  missing-resource error code is mechanical and tracked in the
  [execution plan](mcp-2026-07-28-execution.md) alone.

### Per-revision method disposition

A peer's revision is established per context and checked per request. A context
pins its revision from its FIRST resolved message — not from the `initialize`
response, since a peer on a revision that removed the handshake would never pin
one. A request declaring `io.modelcontextprotocol/protocolVersion` in its `_meta`
is a request of the revision it names; the declaration is read by decoding the
params, so an escaped spelling of the key cannot hide it. A request declaring nothing inherits its context's revision,
and a context that negotiated none resolves to 2025-11-25 — omission never
reaches a method set the peer did not negotiate. A declaration that disagrees
with its context, or names a revision this build does not speak, is refused
`UNSUPPORTED_PROTOCOL_VERSION` (-32022) and recorded.

Each method declares the revisions it exists in once
(`internal/transport/dispatch.go`, `methodRegistry`); the routing tables are
derived from those declarations, and a method outside the requesting peer's
tables falls to the same fail-closed default (`dispatchUnmapped`,
`AUTHORIZATION_FAILED`, recorded) that already covers unknown methods.

| Method | 2025-11-25 | 2026-07-28 |
|---|---|---|
| `tools/call` | enforced | enforced |
| `resources/read` | enforced | enforced |
| `prompts/get` | enforced | enforced |
| `resources/subscribe` | enforced | denied (replaced by `subscriptions/listen`) |
| `resources/unsubscribe` | enforced | denied (replaced by `subscriptions/listen`) |
| `tools/list` / `resources/list` / `prompts/list` | answered, filtered | answered, filtered |
| `initialize` | answered locally | denied (no handshake in this revision) |
| `ping` | answered locally | denied (removed) |
| `notifications/initialized` | swallowed | denied and recorded (no handshake to close) |
| `notifications/cancelled` | forwarded | forwarded |
| `notifications/progress` | forwarded | forwarded |
| `notifications/roots/list_changed` | forwarded | denied and recorded (roots deprecated) |
| `server/discover` | denied | denied — responder not yet implemented |
| `subscriptions/listen` | denied | denied — not yet implemented |
| `tasks/*` | denied | denied — not yet implemented |

The methods listed as "not yet implemented" are absent from both tables, so they
hit the fail-closed default — denials, never bypass, but not functional. For
methods that exist in **both** revisions, eunox's decision has always been made
on the request body, so it stays correct; the new `Mcp-Method` / `Mcp-Name`
headers are not yet required or checked against that body, so a disagreeing pair
is forwarded rather than rejected with `HEADER_MISMATCH` (-32020). Verifying that
pair is tracked in the plan as a hardening item, not a compatibility gap.

### Upstream-side revision

The revision eunox speaks to an upstream is tracked separately from the host
side, because the two peers migrate on independent schedules. It is probed from
the upstream's own handshake, or pinned by a per-upstream config key:

```yaml
upstreams:
  - name: filesystem
    transport: stdio
    command: npx
    protocolVersion: auto        # auto (default) | "2025-11-25" | "2026-07-28"
```

The `proxy --audit` wiretap equivalent is `--upstream-protocol-version` (remote
`--upstream-url` upstreams only — a subprocess upstream speaks the handshake it is
given). A value this build does not speak is refused at load, not at the first
request.

The pin names the revision eunox speaks to that upstream; it does not yet change the
opener. Every upstream leg is opened with `initialize`, so the `MCP-Protocol-Version`
header its post-handshake requests carry names the handshake revision regardless of
the pin.

A host request's own `_meta` declaration is forwarded **verbatim** — nothing strips or
rewrites `_meta`. Rewriting it to match the leg is translation, which the mismatched-pair
boundary governs and this release does not implement, so eunox instead **refuses** a
declaration it cannot forward honestly: a request whose declared revision differs from the
one the upstream leg speaks (or from the revision that leg is addressed as) is refused
`UNSUPPORTED_PROTOCOL_VERSION` (`-32022`) and recorded, before the upstream is contacted.
Otherwise the proxy would not be relaying a mismatched pair but manufacturing one — a body
declaring one revision beside a header naming another, which a first-wins and a last-wins
upstream resolve differently while eunox decided under a third.

Two consequences worth stating plainly:

- The refusal applies only to messages whose params actually travel upstream: the enforced
  methods, `*/list`, and the notifications forwarded verbatim (`notifications/cancelled`,
  `notifications/progress`, `notifications/roots/list_changed`). A declaration on a
  locally-answered method (`ping`, `initialize`) contradicts nothing and is admitted, so a peer
  on the newer revision still gets that revision's tables and its own removals. Note the cost
  on the notification half: JSON-RPC forbids replying to one, so a refused
  `notifications/cancelled` is recorded and acked bodyless — the cancel does not reach the
  upstream and the call it targeted runs to completion.
- What a request must not contradict is the revision eunox ADDRESSES the upstream as, which is
  the one its own `initialize` negotiated — not whatever the upstream reported back. An
  upstream answering the handshake with a newer revision does not make a host's declaration of
  the negotiated one unhonorable; that pair is consistent and is forwarded.
- The check reads the request's RESOLVED revision, not just an explicit declaration. A peer
  that declares once on a locally-answered method pins its context, and every later request
  inherits that revision whether or not it says so.
- Because every leg is opened with `initialize`, a host declaring `2026-07-28` cannot have
  a call forwarded today, on any upstream, pinned or not. It is refused with the leg's
  revision named, rather than served into a conversation held at another revision.

---

## IdP / AS integration examples

The following patterns describe how to compose eunox with common identity
providers. In each case the IdP is the authoritative AS; eunox enforces the
capability policy on top of a validated token.

> **Note.** The `mcp.capabilities` claim used in these examples is part of the
> **experimental** JWT v0.2 schema. eunox enforces it only when started with
> `--jwt-experimental-capabilities`; otherwise a token carrying the claim is
> rejected (HTTP 401). The IdP-side identity claims and standard validation below
> work without the flag.

### Auth0

1. Create an Auth0 API resource with identifier `https://mcp.example.com`.
2. Add a custom action (or rule) that injects `mcp.capabilities` into the
   access token, scoped to the calling application's allowed tools.
3. Publish the JWKS at `https://<tenant>.auth0.com/.well-known/jwks.json`.
4. Configure eunox. JWT validation is configured via CLI flags, not the
   upstream YAML block:

```yaml
# eunox.yaml
schemaVersion: "0.1"
transport: http
listen:
  bind: "127.0.0.1"
  port: 8080
  oauthResource: "https://mcp.example.com"
  oauthAuthorizationServers:
    # Published in the RFC 9728 metadata document. Each entry is validated at
    # startup as an absolute https URI; an unset ${VAR} reference (left as literal
    # text) is rejected fail-closed rather than advertised. Use your AS issuer
    # identifier exactly: Auth0's issuer includes a trailing slash, matching the
    # iss claim and --jwt-issuer below.
    - "https://<tenant>.auth0.com/"
upstreams:
  - name: myserver
    transport: stdio
    command: node
    args: ["./server.js"]
    policy: ["manifest.yaml"]
```

```bash
eunox proxy --config eunox.yaml \
  --jwks-uri  "https://<tenant>.auth0.com/.well-known/jwks.json" \
  --jwt-issuer  "https://<tenant>.auth0.com/" \
  --jwt-audience  "https://mcp.example.com" \
  --jwt-experimental-capabilities   # experimental; required to honor mcp.capabilities
```

The manifest still defines the outer capability boundary; Auth0 claims narrow
it further at runtime. `--jwt-experimental-capabilities` is required because the
`mcp.capabilities` claim is part of the experimental JWT v0.2 schema; without it a
token carrying the claim is rejected (HTTP 401). The Okta and WorkOS setups below
reuse this same command structure (including the flag).

### Okta

1. Create an Okta Authorization Server (custom AS, not the org AS).
2. Add a custom claim `mcp.capabilities` sourced from a groups or entitlements
   attribute, or from an inline expression.
3. Note the JWKS URI from the AS metadata endpoint
   (`/oauth2/<asId>/.well-known/oauth-authorization-server`).
4. Use the same YAML config structure as the Auth0 example (no JWT fields in
   the YAML), passing Okta's issuer and JWKS URI via `--jwks-uri`,
   `--jwt-issuer`, and `--jwt-audience` CLI flags, plus
   `--jwt-experimental-capabilities` to honor the `mcp.capabilities` claim.

### WorkOS

1. Use WorkOS AuthKit to issue JWTs for your users.
2. Add `mcp.capabilities` as a custom claim via the WorkOS JWT Templates feature
   (found under Authentication in the WorkOS dashboard).
3. The JWKS URI follows the pattern
   `https://<subdomain>.authkit.app/oauth2/jwks` for your environment.
4. Pass the WorkOS issuer and JWKS URI via `--jwks-uri`, `--jwt-issuer`, and
   `--jwt-audience` CLI flags alongside the YAML config (same structure as the
   Auth0 example), plus `--jwt-experimental-capabilities` to honor the
   `mcp.capabilities` claim.

### Cloudflare Access

Cloudflare Access injects the identity token as a `Cf-Access-Jwt-Assertion`
header, not an `Authorization: Bearer` header. eunox reads only
`Authorization: Bearer`, so the headers must be bridged before the request
reaches eunox. Two options:

**Option A — Cloudflare Worker rewrite (recommended):** Deploy a Cloudflare
Worker in front of the eunox listener that copies the
`Cf-Access-Jwt-Assertion` value into `Authorization: Bearer <token>` before
forwarding the request. Cloudflare Access JWTs use:

- **JWKS URI:** `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`
- **Issuer:** `https://<team>.cloudflareaccess.com`
- **Audience:** the AUD tag for your Access application (shown in the Access
  application settings as a hex string)

```bash
eunox proxy --config eunox.yaml \
  --jwks-uri "https://<team>.cloudflareaccess.com/cdn-cgi/access/certs" \
  --jwt-issuer "https://<team>.cloudflareaccess.com" \
  --jwt-audience "<your-access-application-aud-tag>" \
  --jwt-experimental-capabilities   # experimental; required to honor mcp.capabilities
```

**Option B — External IdP pass-through:** Use Cloudflare Access with an
external IdP (Auth0, Okta, etc.) as the authoritative AS. Have your clients
obtain a Bearer JWT from that IdP directly and present it in the standard
`Authorization` header. Cloudflare Access then provides network-level access
control; eunox verifies the upstream IdP's Bearer token using that IdP's
`--jwks-uri`, `--jwt-issuer`, and `--jwt-audience` values.

### Enterprise-Managed Authorization (Okta Cross App Access and compatible IdPs)

MCP's [Enterprise-Managed Authorization extension](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization)
(stable since June 2026) standardizes enterprise-IdP-brokered access to MCP
servers. It is built on the IETF Identity Assertion JWT Authorization Grant
(ID-JAG): the client signs in through enterprise SSO, exchanges its identity
assertion at the IdP for an ID-JAG (RFC 8693 token exchange — the IdP's
policy checkpoint), then redeems the ID-JAG at the MCP server's **own**
authorization server (RFC 7523 JWT-bearer grant), which issues the
audience-restricted access token. Okta ships the flow as Cross App Access;
other identity vendors have announced or begun implementations of the same
grant.

No EMA-specific support is needed in eunox, because the token that arrives is
an ordinary `Authorization: Bearer` JWT issued by that resource-side
authorization server:

1. Point `--jwks-uri`, `--jwt-issuer`, and `--jwt-audience` at the
   authorization server that issues the **final access token** (where the
   ID-JAG is redeemed) — not at the enterprise IdP that brokered the grant.
   Validation then proceeds exactly as in the examples above.
2. The grant governs whether a token is issued and with which scopes;
   per-call capability within the authenticated session remains the
   manifest's job. The extension itself scopes the IdP's visibility to token
   issuance — it does not extend to the MCP traffic inside the session, which
   is the layer the manifest enforces.
3. If that authorization server also attaches the `mcp.capabilities` claim,
   the experimental intersection applies with
   `--jwt-experimental-capabilities`, unchanged. The capability-manifest
   specification covers
   [issuer configuration](https://github.com/eunolabs/agent-capability-manifest/blob/main/SPEC.md#43-issuer-configuration-non-normative)
   and
   [composition with MCP authorization flows](https://github.com/eunolabs/agent-capability-manifest/blob/main/SPEC.md#44-composition-with-mcp-authorization-flows-non-normative)
   in detail.

---

## Audit log and compliance

When the audit sink is available, every enforcement decision on a checked method
— allow or deny — is enqueued for an append-only
[OCSF](https://schema.ocsf.io/) record, HMAC-SHA256 signed with a key you
control. The set of records is never filtered, dropped silently, or rewritten.
The one exception to verbatim capture is size: an individual oversized argument
value (audit/observe mode logs the full argument map) is replaced with a
size-marked placeholder so a single record cannot exceed the verifier's bound —
see threat model §6.2. The record itself, and the tamper-evident chain over it,
are otherwise untouched.

**Paths that do not produce audit records:**

- **Locally handled `initialize`** — registered and answered with a
  proxy-synthesized response built from capabilities gathered at startup. It
  succeeds (it is not a denial) and writes no audit record.

**Locally-answered paths that DO produce records** (record-before-act on the
tamper-evident tape):

- **Denied unmapped methods** (any method with no registered handler) — denied
  with `AUTHORIZATION_FAILED`. A deny record is written to the
  audit tape (record-before-act), then a stderr notice is logged, and the
  upstream is never called.
- **`*/list` filtering** (`tools/list`, `resources/list`, `prompts/list`) —
  these handlers call the upstream, then filter the response down to permitted
  entries. The enumeration is recorded as an allow record carrying filter
  statistics (`upstream_count`, `filtered_count`, `suppressed_count`) so an
  auditor can tell an empty client view caused by policy filtering from a
  genuinely empty upstream. Here `suppressed_count` means catalog entries the
  manifest hid; the refusal rate limiter's unrelated rollup is spelled
  `suppressed_refusal_count` (below) so a query cannot match both.
- **Upstream-initiated non-sampling requests** (e.g. `roots/list`,
  `elicitation/create`, upstream-initiated `tasks/*`; local subprocess upstreams)
  — not policy-enforced (no allow/deny decision), but kill-switch-checked,
  `--require-audit=strict`-gated, and audited: an allow record on delivery to a
  client, or an `ENFORCEMENT_ERROR` deny if no client received it. The host's
  response is routed back to the upstream so the request completes.
- **Transport-surface refusals** — requests turned away before (or independently
  of) a PDP decision: a rejected `Origin` (`ORIGIN_REJECTED`), an invalid bearer
  or control token (`AUTH_FAILED` / `CONTROL_AUTH_FAILED`), a rejected loopback
  or DNS-rebinding `Host` on `/control/kill`, `/healthz`, `/metrics`
  (`LOOPBACK_REJECTED`), a saturated handler pool or an exhausted concurrent
  **session** cap (`RESOURCE_EXHAUSTED`), and a startup drift refusal
  (`DRIFT_REFUSED`). None names a policy target, so `suggest` skips them all.
- **Emergency-stop activation** — a successful `POST /control/kill` records an
  allow with the method `control/kill` and `details.scope` (the killed session
  id, or `all`), written only after the kill takes effect. It is the
  administrative counterpart to the refusal codes above: the `KILL_SWITCH`
  denials that follow an activation are recorded, so the activation itself must
  be too. `control/kill` is not an MCP method, so it names no target and
  `suggest` skips it.

  A caller sets the rate of every refusal above, so every one of them is
  admission-controlled, through one of two families of token bucket
  depending on what it costs to trigger.

  The pre-session refusals — the only records an *unauthenticated* caller can
  cause — get one bucket per refusal **category** (`origin`, `jwt`, `auth`,
  `control`, `loopback`, `body`, `content_type`, `saturation`), each spanning
  every route: within a burst each refusal is recorded in full, and beyond it
  the next record of that category carries a `suppressed_refusal_count` of the
  refusals elided since. **Read that count as spanning every route, for this
  record's category only.** Not one bucket per route — that would multiply the
  rate an attacker can drive by the size of the route table — and no longer one
  bucket for everything, because a spray of unauthenticated Origin probes then
  absorbed the whole budget and suppressed a concurrent control-token brute
  force into a number on somebody else's record. A suppressed refusal is folded
  into whichever record of its own category is admitted next, regardless of
  route. That matters whenever the admitted record happens to be route-stamped:
  the
  **session cap** always is (it is written through the route's sink so it
  matches its in-flight-cap sibling's shape), and the
  **malformed-`Content-Type`** (`UNSUPPORTED_MEDIA_TYPE`) and
  **malformed-body** (`INVALID_REQUEST`) refusals are too whenever they are hit
  via `/mcp/<route>` rather than `/control/kill` — in each case the record can
  carry an `upstream` / `policy_version` / `policy_sha256` stamp alongside a
  tally that spans every route. A bearer-token spray against `/mcp/routeA`
  (refused before route resolution, so attributable to no route) can therefore
  surface on a `RESOURCE_EXHAUSTED` record reading `upstream: routeB` — or
  equally on an `INVALID_REQUEST` record for a malformed body routeB's own
  client happened to send. Every rolled-up record states its scope in
  `suppressed_refusal_scope` (`"proxy_category"`) so nothing has to be inferred
  from the stamp beside it: a rule keyed on route + code must not treat the
  number as route-scoped.

  The two saturation refusals that need an established session (the handler
  pool and the notification pool) are on their OWN, separate buckets instead —
  one per pool per session, never the proxy-wide one above — and are recorded
  once per saturation **episode** rather than per refusal: the first refusal
  after the pool last had a free slot is recorded, further refusals while it
  stays saturated roll into the next record's `suppressed_refusal_count`, and a
  successful acquire ends the episode, with a per-pool token bucket underneath
  so a caller cycling one pool between saturated and drained cannot outpace it.
  Sharing a pre-session bucket would let a notification flood on ONE session
  elide the `AUTH_FAILED` / `ORIGIN_REJECTED` records an incident responder
  reads first, so every record one of these buckets rolls up states
  `suppressed_refusal_scope: "session"` instead of `"proxy_category"` — the
  count never spans more than the one session_id beside it.

  Without these bounds a credential-spray or a notification flood could
  overflow the audit queue, and because the sink's drop counter is monotonic,
  that would leave `--require-audit=strict` denying every legitimate request
  for the rest of the process's life. A non-zero `suppressed_refusal_count` on
  one of these codes therefore means a flood, not a lost decision record — no
  *policy* decision is ever rate-limited.

  The key is `suppressed_refusal_count`, not a bare `suppressed_count` — that
  name belongs to the unrelated `*/list` filter statistic above (entries the
  manifest hid), which rides in the same `details` object on `allow` records. The
  two are disjoint by decision and method, but a query written against the bare
  key matches both routine policy filtering and an unauthenticated refusal flood.

The only locally-answered path with no audit record is the `initialize`
handshake, which is not a guarded action. Every other locally-answered path —
`*/list`, upstream-initiated requests, and every transport-surface refusal —
either completes and is recorded or is refused and is recorded, so absence of a
record is not evidence that a guarded action was allowed.

Beyond those by-design paths, records can also be lost unintentionally, in two
ways:

**Sink-open failure:** If the audit log cannot be opened at startup (bad path,
permissions, missing key), the default `--require-audit=strict` makes this
**fatal**: the proxy exits rather than running without an audit trail. Relax it
with `--require-audit=off` to instead print a warning and continue with auditing
disabled — the configured enforce/observe posture still applies (enforce-mode
routes keep blocking; audit-mode routes keep forwarding would-be denials), but no
records are written for the lifetime of the process. Keep the default in any
deployment where the audit log is a compliance requirement.

**Drop behavior:** Serialization happens asynchronously in a background
goroutine. The in-process queue holds up to 4096 records; if the queue fills
(typically due to disk I/O back-pressure), new records are dropped and a
warning is printed to stderr. Under the default `--require-audit=strict`, the
first observed drop fails every subsequent forward closed (see the
`AUDIT_UNAVAILABLE` gate below); relaxed to `--require-audit=off`/`=on`,
enforcement is not blocked and the allow/deny decision still applies to the
upstream call. This tradeoff is documented in the
[threat model](./threat-model-mcp.md). For high-throughput or
compliance-critical deployments, monitor disk I/O and ship the log file to an
external sink.

**`--require-audit=strict` (fail closed on degraded coverage):** Where an
unauditable privileged call is worse than a denied one, run with
`--require-audit=strict`. In addition to the startup check above, it gates the
*forward* path at runtime: once a record has been dropped or a write has failed,
every subsequent enforced call (`tools/call`, `resources/read`,
`resources/subscribe`, `resources/unsubscribe`, `prompts/get`, `sampling/createMessage`) and `*/list`
enumeration is denied with `AUDIT_UNAVAILABLE` (JSON-RPC `-32603`) and the
upstream is not contacted. The gate is **retrospective**: because the loss
counters reflect only already-completed calls, the boundary call whose own record
is the first lost is still forwarded — the guarantee is "after the first observed
loss, every subsequent forward is denied," not "no call is ever forwarded
unaudited" (closing that window would require a blocking allow path; pair strict
mode with a real-time external sink for a zero-loss guarantee). That boundary call
is not entirely silent, though: the proxy compares audit health immediately before
and after its own record call and, if that exact call's record is the one that
tripped degradation, prints an immediate SECURITY warning naming the call — rather
than leaving the operator to infer it only once a later, unrelated request is
denied. It is also coarse and sticky — one drop denies all later forwards for the
process lifetime — trading data-plane availability for audit completeness (the
inverse of the default posture). See the [threat model](./threat-model-mcp.md)
§5.4.1 for the full semantics.

Use `eunox audit-verify` to detect post-write tampering: modified records,
deleted records within the written chain, insertion, and reordering. It verifies
the whole rotated set as one chain — every sidecar oldest-first, then the current
base log — so deleting an entire interior rotated file is caught as a cross-file
chain break (the file after the gap fails to chain onto the file before it), not
just edits within one file. On a non-rotated log it also catches leading-record
removal — the first record must be `seq 1` with the `sha256:genesis` sentinel, so
rewriting the origin is reported as a chain break. Note what it cannot detect:
records dropped from the in-memory queue (before they are written) leave no chain
gap (a signed `AUDIT_RECORDS_DROPPED` marker records the loss instead); trailing
truncation (removing the last N records) is undetectable without an external
high-water mark; and removal of the leading records — the oldest records, up to
and including whole leading rotated files (as `--audit-retain` prunes) — is
likewise undetectable, because the surviving prefix is internally consistent and
begins at `seq > 1` indistinguishably from legitimate retention — see the
[threat model §3.4](./threat-model-mcp.md#34-audit-log-tampering) for details.

For compliance integrations (SIEM, SCC, Splunk) the log is newline-delimited
JSON and can be tailed or shipped with any standard log forwarder.

---

## See also

- [Architecture overview](./architecture.md)
- [Capability manifest guide](./capability-manifest-guide.md)
- [Threat model](./threat-model-mcp.md)
- [ADR-0001: JWT claims intersect manifest](./adr/0001-jwt-claims-intersect-manifest.md)
- [ADR-0002: OAuth protected-resource metadata](./adr/0002-oauth-protected-resource-metadata.md)
