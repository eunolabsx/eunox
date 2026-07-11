# How eunox compares

Controls for what an AI agent may do now exist at nearly every layer of the
stack: identity platforms govern which agent may connect to which app, API
gateways attach per-tool ACLs to routes, managed runtimes execute tools behind
delegated OAuth, authorization platforms offer policy engines as a service, and
scanners inventory what is installed. This page maps those categories against
what eunox does, so you can decide which you need — the answer is often more
than one, and eunox is designed to compose with the others rather than replace
them.

eunox enforces at exactly one point: the **MCP protocol boundary**, as a
separate process between the host and any MCP server — local subprocess or
remote HTTPS — checking every enforced call against a deny-by-default YAML
capability manifest, filtering `*/list` discovery responses, and writing every
decision to an HMAC-signed, tamper-evident audit log. One open-source static
binary, no control plane, no account, no code changes to the agent or the
server.

---

## The short version

**Identity answers *who is calling*. Capabilities answer *what a call may do*.**

Identity-keyed tool ACLs and delegated per-user OAuth both answer the first
question, and answer it well. But the dominant agent failure mode is different:
a prompt-injected or confused agent **misusing access it legitimately holds**.
An identity-scoped ACL happily lets the right principal call `send_email`; a
consent flow happily executes what the user once delegated. Neither layer can
express:

- **Argument constraints** — `query_db` allowed, but only `SELECT`, only these
  tables (`allowedOperations`, `allowedValues`, `allowedTables`).
- **Ordering constraints** — block "read secrets, then call an external
  webhook" in one session (`sequenceBlock`), even when each call is
  individually permitted.
- **A static, reviewable ceiling** — a git-diffable file that answers "what is
  this agent *ever* allowed to do, and who approved the change."

That is the layer eunox occupies. Use your identity stack for authentication
and token issuance; use eunox to enforce least-privilege MCP capabilities at
discovery and invocation time.

---

## Category map

| | Enforcement point | Unmodified third-party MCP servers | Local stdio servers | Deny-by-default ceiling artifact | Argument-level constraints | Call-ordering constraints | Filters `*/list` discovery | Tamper-evident audit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **eunox** | MCP protocol boundary (out-of-process proxy) | Yes | Yes | Yes — reviewable YAML manifest | Yes | Yes | Yes | Yes — HMAC-signed, hash-chained |
| API gateway MCP ACLs | Network gateway (route/plugin) | Remote/HTTP only, typically | Rarely (most are HTTP-only) | Varies — check the posture when no rule is configured | Typically tool-level | No | Varies | Ordinary logs |
| Managed tool-execution runtime | Inside the vendor runtime, at execution | Tools in its catalog or rebuilt on its framework | No | Consent-driven, no static ceiling file | OAuth-scope granularity | No | n/a (own catalog) | Ordinary audit trail |
| Authorization platform (PDP) | Cloud decision engine or in-app SDK | Depends on integration code | Depends | Policy-defined | Possible, via policy code | Rarely (stateless per-call) | No | Ordinary logs |
| Identity-layer agent controls | Token issuance / credential layer | n/a (governs connections, not calls) | n/a | n/a | No | No | No | IdP system logs |
| Scanners / posture tools | Scan time, not runtime | Inventory only | Inventory only | n/a | n/a | n/a | n/a | n/a |

Rows describe categories, not any single product; individual products vary.
Where a cell matters to your deployment, verify it against the vendor's current
documentation.

---

## API gateways with MCP ACLs

**Examples:** Kong AI Gateway (MCP Tool ACLs via its AI MCP Proxy plugin),
Cloudflare AI Gateway, agentgateway (Linux Foundation), Pomerium.

API gateways are extending existing traffic infrastructure with per-tool
allow/deny rules for MCP, keyed to the gateway's identity objects (consumers,
groups, JWT claims). If you already run one, per-tool ACLs on remote MCP
endpoints are close to free — and the MCP spec's newer routing headers make
tool-name-level filtering easy for any L7 proxy.

Questions to ask before relying on one as your only MCP control:

- **What happens when no rule is configured?** eunox denies anything absent
  from the manifest, on every enforced method. Verify your gateway's default
  posture rather than assuming it.
- **Where does policy live, and can you review it?** Gateway ACLs are
  control-plane configuration attached to platform-specific objects. The eunox
  manifest is a portable file — PR-reviewable, diffable, and portable to any
  proxy implementing the open
  [capability-manifest spec](https://github.com/eunolabs/mcp-capability-manifest).
- **How deep does the policy go?** Tool-name allow/deny does not express
  argument constraints, per-session rate limits, or ordering rules.
- **Can it reach local servers?** Most network gateways cannot sit in front of
  a subprocess MCP server launched by Claude Desktop, Claude Code, Cursor, or
  VS Code on a developer machine — they police HTTP endpoints. eunox wraps
  local stdio servers with a one-line command prefix.

**Composition:** run eunox behind the gateway (or as the gateway's MCP-aware
hop) — the gateway keeps doing traffic management, TLS, and coarse ACLs; eunox
adds argument/ordering enforcement, discovery filtering, and the signed audit
tape.

## Managed tool-execution runtimes

**Example:** Arcade.dev — tools execute inside the vendor's runtime, which
brokers per-user delegated OAuth so agents act as the authenticated end user
and credentials never reach the model.

Delegated per-user OAuth is a real and complementary capability: it answers
*as whom* a tool call runs, with provider-grade consent flows. Two structural
differences matter:

- **Coverage.** A runtime secures tools in its catalog or rebuilt on its
  framework. Most MCP estates are the opposite: existing, unmodified,
  third-party servers — a community package launched with `npx`, a vendor's
  remote endpoint, an internal server owned by another team. eunox governs
  those with zero migration.
- **The ceiling.** Consent trails record what a user once granted; they are not
  a static, deny-by-default policy artifact, and OAuth scopes stop at the
  granularity each provider defined. Delegated authorization also does not
  constrain what an agent does *within* a grant — a prompt-injected agent
  misusing legitimately delegated access is fully authorized at the token
  layer. The manifest is the control that survives that failure mode.

**Composition:** eunox can front a runtime-hosted MCP endpoint like any other
remote upstream, putting a customer-side ceiling and signed audit tape in front
of it.

## Authorization platforms

**Examples:** Oso, Permit.io — general-purpose policy engines (RBAC / ABAC /
ReBAC) repositioned for agent access control, delivered as cloud decision
points or SDKs embedded in the agent application.

These are policy *decision* platforms; something still has to be the
enforcement point, and embedding checks in agent code only covers the agents
you can modify. eunox is a self-hosted enforcement point at the boundary every
MCP-speaking agent shares — and the two compose directly: the manifest's
[`policy` condition](https://github.com/eunolabs/mcp-capability-manifest/blob/main/SPEC.md)
delegates a predicate to an external evaluator (OPA, Cedar, or a platform
client) while the manifest remains the fail-closed ceiling. For the specific
case of OPA/Envoy, see the
[worked comparison in the README](../README.md#why-not-opa-or-envoy) and the
runnable demos in [`demo/opa-comparison/`](../demo/opa-comparison/).

## Identity-layer agent controls

**Examples:** Okta (Cross App Access, standardized in MCP as the
Enterprise-Managed Authorization extension), Descope (Agentic Identity Hub).

Identity platforms govern which agents exist, which apps they may connect to,
and how tokens are issued and revoked — increasingly with MCP-specific support
in the official SDKs. This is the layer eunox deliberately does **not**
implement: eunox is not an authorization server and does not mint tokens.

The two layers are designed to stack. The identity platform authenticates the
agent and issues the token; eunox validates it (signature, expiry, issuer,
audience) and enforces the manifest on every call made within that
authenticated session. Optionally, a token can carry an
[`mcp.capabilities` claim](https://github.com/eunolabs/mcp-capability-manifest/blob/main/SPEC.md)
that narrows the manifest per invocation — intersection semantics, so a token
can never *expand* what the manifest allows. (Claim enforcement is
experimental and off by default; see the
[README](../README.md#advanced-jwt--idp-issued-capability-claims).) Setup
recipes for Auth0, Okta, WorkOS, and Cloudflare Access are in
[`conformance.md`](./conformance.md#idp--as-integration-examples).

## Scanners and posture tools

**Example:** Snyk agent-scan — inventories installed agent components and
scans MCP server definitions for risk patterns (tool poisoning, credential
handling, toxic tool combinations).

Scan-time visibility and runtime enforcement answer different questions:
"what is installed and is it suspicious?" versus "what is this call allowed to
do right now?" They pair well — notably, the "toxic flow" combinations a
scanner flags statically are what eunox's `sequenceBlock` condition blocks at
runtime, where the actual call order is known.

## In-process alternatives

Authorization middleware inside a server you wrote, and agent-governance SDKs
embedded in an agent application, are covered in the README:
[Why not authorization middleware inside the server?](../README.md#why-not-authorization-middleware-inside-the-server)
and
[Why not an agent-governance SDK?](../README.md#why-not-an-agent-governance-sdk)
The short form: they enforce where the agent or server runs and require
embedding; eunox enforces at the protocol boundary, outside the process it
polices, for servers and agents you cannot instrument.

---

## What eunox does not do

Honest scoping, so the comparison cuts both ways:

- **No token minting.** eunox verifies and enforces; authentication, consent,
  and issuance belong to your IdP or OAuth stack.
- **No content inspection.** eunox evaluates structured calls against policy;
  it is not a prompt-injection detector, content moderator, or DLP engine.
- **No tool catalog or execution.** eunox proxies your servers; it does not
  host or run tools.
- **Per-user delegated OAuth flows** are the runtime/identity layer's job;
  eunox consumes the resulting tokens.

If your primary need is one of those, start there — and put eunox in front of
the MCP servers those systems ultimately reach.
