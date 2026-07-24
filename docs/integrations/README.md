# Platform and gateway integrations

How to place `eunox` inline in front of the MCP servers that a **platform,
orchestrator, or AI gateway** calls — LiteLLM, Dify, n8n, Conductor, Temporal,
Flowise, and anything that shares their wiring.

This is the companion to [client-integration.md](../client-integration.md),
which covers **end-user MCP clients** (Claude Desktop, Claude Code, Cursor, VS
Code + Copilot, …). The difference is *who* opens the connection: there it is a
desktop app on one person's machine; here it is a shared, often headless
platform where many users — or fully automated workflows — reach the same
backends through one process. That shared, autonomous position between untrusted
agent logic and sensitive systems is exactly where a capability chokepoint earns
its keep.

---

## The three insertion patterns

Every integration in this directory is one of three ways to get eunox onto the
MCP path. Each platform doc states which one (or two) it uses.

### Pattern A — HTTP gateway URL substitution

The platform connects to MCP servers over HTTP (Streamable HTTP or SSE) by URL.
Run eunox in **gateway mode** (`transport: http`), give each upstream its own
`/mcp/<name>` route and manifest, and point the platform at the eunox route
instead of the real server. No code change on the platform — you edit one URL.

Used by: **LiteLLM, Dify, n8n, Conductor**, and Flowise (HTTP transport).

### Pattern B — stdio command wrap

The platform launches the MCP server as a local subprocess over stdio. Prefix
that launch command with `eunox proxy` so eunox speaks stdio to the platform and
spawns the real server itself. This is the
[client-integration.md](../client-integration.md) pattern, and it applies to any
platform that runs stdio servers.

Used by: **Flowise (stdio transport)**, and any stdio-server platform.

### Pattern C — in-code / activity MCP client

The platform has no MCP-server registry — application code (a Temporal activity,
a custom Conductor worker) constructs an MCP client directly. Point that client's
endpoint at eunox through config or an environment variable. Low friction, but
the change lives in code, not a console.

Used by: **Temporal**, custom Conductor workers.

---

## Shared setup for Pattern A — the eunox HTTP gateway

Every Pattern-A integration reuses the setup below. The platform-specific docs
only add "where you paste the URL, and how you pass identity."

**Gateway config** — one eunox process fronts one or more upstreams, each on its
own `/mcp/<name>` route with its own manifest, all writing to one signed audit
tape:

```yaml
# eunox.gateway.yaml    (schema: schemas/eunox-gateway-config.schema.json)
schemaVersion: "0.1"
listen: { bind: 0.0.0.0, port: 3000 }        # 0.0.0.0 pairs with --unsafe-bind-all
audit:  { log: /audit/audit.jsonl, keyPath: /audit/audit.key }
defaults: { upstreamTimeoutMs: 30000 }
upstreams:
  - name: db                                 # -> POST /mcp/db
    transport: http
    upstreamUrl: http://postgres-mcp:8080     # the REAL MCP server, reachable only by eunox
    policy: ["/policies/db-readonly.yaml"]
    expectVersion: "1.0.0"                    # fail closed if the manifest version drifts
```

**Manifest** — the enforcement policy for that route. This one allows only
`SELECT` on the `query_db` tool and redacts `ssn` from every result:

```yaml
# db-readonly.yaml
schemaVersion: "0.1"
name: db-readonly
version: "1.0.0"
audience: "eunox-mcp"                # gateway mode: pins the JWT 'aud' accepted on this route
capabilities:
  - target: tool:query_db           # match to the upstream's real tool name
    actions: [call]
    conditions:
      - type: allowedOperations
        argument: query
        operations: [SELECT]        # INSERT/UPDATE/DELETE/DROP -> CONDITION_FAILED
    directives:
      - type: redactFields
        fields: ["ssn", "rows.ssn"] # scalar + per-element in a rows[] array
```

Do not hand-write the tool and argument names — generate a deny-all starter from
the live server and tighten it:

```bash
eunox init --upstream-url http://postgres-mcp:8080 --output db-readonly.yaml
# deny-all starter manifest from the upstream's live tools/list; then add conditions
```

**Launch** (identity verification on; see the next section):

```bash
eunox proxy --config eunox.gateway.yaml --unsafe-bind-all \
  --jwks-uri https://idp/.well-known/jwks.json \
  --jwt-issuer https://idp --jwt-audience eunox-mcp
```

**Verify** what happened:

```bash
eunox stats                       # per-tool ALLOW/DENY histogram
eunox audit-verify                # re-check the HMAC chain end to end (see --help for the log path)
```

---

## Passing identity through (optional, recommended)

The strongest posture splits duties: the **platform** authenticates the end user
at its edge (virtual key, JWT, OAuth) and forwards the caller's bearer token to
eunox in a header; **eunox** verifies that token against the same IdP JWKS,
enforces the per-route manifest, and stamps the caller identity onto every audit
record. Each platform doc names its own header-forwarding knob.

Without identity forwarding, eunox still enforces per-route policy and redaction
and signs the audit log — you lose only per-user attribution. Start there if the
forwarding step is fiddly, and layer identity on afterward.

Per-user *capability* differences (analyst vs admin) are expressed one of two
ways: give each identity its own route/manifest and let the platform map
key -> route (stable), or put a single route behind
`--jwt-experimental-capabilities` and intersect the token's `mcp.capabilities`
claim with the manifest (experimental; JWT can only restrict, never widen).

---

## Pre-flight checklist — the risks that actually bite

1. **Transport compatibility (spike this first).** eunox's HTTP gateway speaks
   MCP Streamable HTTP and SSE with an `Mcp-Session-Id` header. Confirm the
   platform's MCP client speaks the same framing and round-trips the session
   header. This decides whether the integration is config-only or needs an
   adapter.
2. **Identity forwarding.** Confirm the platform forwards the *end user's* token,
   not its own service credential. Fallback: static per-route policy without
   per-user attribution.
3. **`aud` / `iss` alignment.** In JWKS mode eunox fails closed if `aud`/`iss`
   are unset (unless `--jwt-allow-any-audience` / `--jwt-allow-any-issuer`). Mint
   tokens with an `aud` eunox pins.
4. **Upstream transport.** Gateway upstreams connect over HTTP. Front a
   stdio-only MCP server with a stdio->HTTP adapter, or use Pattern B with a
   stdio-native host.
5. **Bypass prevention.** eunox is only a chokepoint if the platform *cannot*
   reach the real MCP server directly. Network-isolate the upstream so only eunox
   can route to it. See [deployment-hardening.md](../deployment-hardening.md).

---

## Integrations

| Platform | Category | Pattern | Doc |
| --- | --- | --- | --- |
| LiteLLM | AI / LLM gateway | A | [litellm.md](./litellm.md) |
| Dify | LLM app platform | A | [dify.md](./dify.md) |
| n8n | Workflow automation | A | [n8n.md](./n8n.md) |
| Conductor (OSS / Orkes) | Workflow orchestration | A / C | [conductor.md](./conductor.md) |
| Temporal | Durable execution | C | [temporal.md](./temporal.md) |
| Flowise | Visual LLM builder | A / B | [flowise.md](./flowise.md) |

For end-user desktop and IDE MCP clients, see
[client-integration.md](../client-integration.md).
