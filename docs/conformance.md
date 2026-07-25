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
| `prompts/get` | **Enforced** — PDP decision per manifest entry | |
| `prompts/list` | **Filtered** — only prompts with `action: get` (or `*`) in manifest are returned | |
| `sampling/createMessage` *(upstream→host)* | **Enforced** (local subprocess upstream only) — denied by default; requires explicit `system:sampling/createMessage` entry in manifest, and the kill switch applies. On the allow path the host's response is routed back to the upstream so the round-trip completes | Fail-closed: absent = deny. See the transport caveats in *Known gaps* below |
| Upstream-initiated non-sampling requests (e.g. `roots/list`) | **Forwarded** for local subprocess upstreams — not policy-enforced (no allow/deny decision), but kill-switch-checked, `--require-audit=strict`-gated, and audited (an allow record on delivery, an `ENFORCEMENT_ERROR` deny if no client received it); the host's response is routed back to the upstream | Remote HTTP upstreams have no background reader and do not consume server-initiated messages |
| `initialize` *(host→proxy)* | **Handled by proxy** — eunox sends its own `initialize` to the upstream at startup and synthesizes the host-facing response using the upstream's declared capabilities | Host never sees the upstream's raw response |
| `ping` *(host→proxy)* | **Denied** — no handler registered; treated as unmapped request | Upstream is never called |
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
| **RFC 9728 protected-resource metadata** | Yes — serves `/.well-known/oauth-protected-resource`; issues `WWW-Authenticate` challenges on 401 responses | |
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

## Forthcoming: the 2026-07-28 stateless release candidate

The 2026-07-28 MCP revision (release candidate, locked 2026-05-21) is **not yet
the targeted spec** — eunox still targets 2025-11-25 — but two of its changes
place obligations on a filtering proxy that are worth recording ahead of the
broader conformance work tracked in
[ADR-0004](adr/0004-bearer-identity-session-anchor.md).

| Feature | 2026-07-28 method / field | eunox disposition | Notes |
|---|---|---|---|
| **List-result caching** (SEP-2549) | `cacheScope` (`public`/`private`) + `ttlMs` on `*/list`, `resources/read`, and the discovery result | **Open obligation.** eunox filters `*/list` per identity, so every list it emits is authorization-context-specific. `filterListResult` preserves sibling fields verbatim, so an upstream `cacheScope: public` would pass through unchanged on a personalized response. The fix is to **override `cacheScope` to `private`** on any response eunox has filtered (never preserve an upstream `public`); `ttlMs` may be preserved as a freshness hint. See threat model L-6. | A shared downstream cache honoring `public` on a filtered list could serve one identity's narrowed view to another — the spec's "caches MUST NOT be shared across authorization contexts" invariant |
| **MCP Apps** (SEP-1865) | `ui://` template resources; `ui/*` host↔iframe bridge | **Covered by existing mediation; documentation watch item.** App UI templates are fetched via `resources/read` / `resources/list` (already gated and filtered) and UI-initiated execution is an ordinary `tools/call` (already enforced and audited). The `ui/*` methods run on the host↔iframe postMessage bridge, which never traverses eunox. No new server-transport method exists today. | A *future* Apps revision adding a server-transport `app/*` method would hit the fail-closed unmapped-method path and need classification |

Broader 2026-07-28 conformance — stateless transport (`server/discover`, per-request
`_meta` + the `MCP-Protocol-Version` header), the multi-round-trip replacement for
server-initiated requests, and the `Mcp-Method`/`Mcp-Name` routing headers — is
tracked in [ADR-0004](adr/0004-bearer-identity-session-anchor.md).

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

- **Denied unmapped methods** (`ping` and any method with no registered
  handler) — denied with `AUTHORIZATION_FAILED`. A deny record is written to the
  audit tape (record-before-act), then a stderr notice is logged, and the
  upstream is never called.
- **`*/list` filtering** (`tools/list`, `resources/list`, `prompts/list`) —
  these handlers call the upstream, then filter the response down to permitted
  entries. The enumeration is recorded as an allow record carrying filter
  statistics (`upstream_count`, `filtered_count`, `suppressed_count`) so an
  auditor can tell an empty client view caused by policy filtering from a
  genuinely empty upstream.
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

  These are the only records an *unauthenticated* caller can cause, so their
  write rate is bounded by a token bucket: within a burst each refusal is
  recorded in full, and beyond it the next record that gets through carries a
  `suppressed_count` of the refusals elided since. Without that bound a
  credential-spray could overflow the audit queue, and because the sink's drop
  counter is monotonic, that would leave `--require-audit=strict` denying every
  legitimate request for the rest of the process's life. A non-zero
  `suppressed_count` on one of these codes therefore means a flood, not a lost
  decision record — no *policy* decision is ever rate-limited.

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
`resources/subscribe`, `prompts/get`, `sampling/createMessage`) and `*/list`
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
