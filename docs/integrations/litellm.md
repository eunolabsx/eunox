# eunox + LiteLLM

**Pattern A — HTTP gateway URL substitution.** LiteLLM owns identity and
transport; eunox owns capability policy, response redaction, and a
tamper-evident audit trail.

[LiteLLM](https://docs.litellm.ai/docs/mcp) runs an MCP Gateway: it registers
upstream MCP servers, authenticates callers (virtual keys, JWT, OAuth), and
presents every tool at one endpoint. It routes the JSON-RPC — it does not inspect
tool *arguments*, redact *responses*, or sign a *decision log*. eunox slots in
behind it to do exactly those things.

> This doc reuses the gateway config, manifest, and identity-forwarding setup
> from [README.md](./README.md#shared-setup-for-pattern-a--the-eunox-http-gateway).
> Read that first; this page adds the LiteLLM-specific wiring and a runnable
> end-to-end demo.

---

## Architecture

```
client ──▶ LiteLLM ───────────▶ eunox HTTP gateway ─────▶ real MCP server
           identity:            capability manifest:       e.g. Postgres MCP,
           virtual keys,        allowedOperations,         reachable ONLY by eunox
           JWT / OAuth,         redactFields, flow labels,
           key -> route         HMAC-signed audit log
```

LiteLLM registers **eunox's route URL** as its upstream MCP server (not the real
server) and forwards the caller's bearer token down. eunox verifies that token
against the same IdP JWKS, enforces the route manifest, redacts, forwards to the
real server, and signs an audit record stamped with the caller's identity.

## How this relates to LiteLLM's built-in MCP permissions

LiteLLM has native [MCP permission management](https://docs.litellm.ai/docs/mcp_control):
it controls, by key and team, *which MCP servers and which tools* a caller may
reach. That is coarse allow/deny at the tool boundary. eunox adds the layer below
it:

| Concern | LiteLLM | eunox |
| --- | --- | --- |
| Who may reach an MCP server / tool | yes (key, team) | — |
| Argument-level constraints (SELECT-only, allowed tables/paths) | — | yes |
| Response redaction (mask `ssn`, `api_key`) | — | yes |
| Information-flow control (block sinks after untrusted input) | — | yes |
| Tamper-evident, HMAC-signed decision log | — | yes |

Position them as complementary: LiteLLM decides *whether* a tool is reachable,
eunox decides *whether this specific call is allowed* and *what comes back*.

---

## Wiring

### 1. eunox gateway

Use the [shared gateway config and manifest](./README.md#shared-setup-for-pattern-a--the-eunox-http-gateway).
For per-identity capability, define two routes and let LiteLLM map key -> route:

```yaml
# eunox.gateway.yaml
upstreams:
  - name: db-ro                              # -> POST /mcp/db-ro   (analyst key)
    transport: http
    upstreamUrl: http://postgres-mcp:8080
    policy: ["/policies/db-readonly.yaml"]
    expectVersion: "1.0.0"
  - name: db-rw                              # -> POST /mcp/db-rw    (admin key)
    transport: http
    upstreamUrl: http://postgres-mcp:8080
    policy: ["/policies/db-readwrite.yaml"]
    expectVersion: "1.0.0"
```

### 2. LiteLLM config

Register the eunox routes as MCP servers, and forward the caller's
`Authorization` header downstream so eunox can verify and attribute it.

```yaml
# litellm-config.yaml   — confirm key names against your LiteLLM version's docs
mcp_servers:
  db-analyst:
    url: http://eunox:3000/mcp/db-ro
    transport: http                 # Streamable HTTP; matches eunox's gateway
    # forward the end-user's bearer token from the incoming request to eunox:
    extra_headers: ["Authorization"]
  db-admin:
    url: http://eunox:3000/mcp/db-rw
    transport: http
    extra_headers: ["Authorization"]

general_settings:
  enable_jwt_auth: true             # LiteLLM validates the end-user JWT at its edge
```

LiteLLM's `extra_headers` forwards named headers from the incoming request to the
downstream MCP server; `static_headers` would send fixed values instead. Confirm
the current syntax — this surface is young and moving
([header-forwarding tracking issue](https://github.com/BerriAI/litellm/issues/20695)).

### 3. eunox launch

```bash
eunox proxy --config eunox.gateway.yaml --unsafe-bind-all \
  --jwks-uri https://idp/.well-known/jwks.json \
  --jwt-issuer https://idp --jwt-audience eunox-mcp
```

Both LiteLLM and eunox trust the same IdP: LiteLLM for coarse edge auth, eunox
for fine-grained capability policy and attribution.

---

## Runnable demo

A five-service `docker-compose` stack that shows all four moments below.

**Services:** `litellm`, `eunox`, `postgres-mcp` (upstream MCP server),
`postgres` (seeded with a `customers` table carrying `ssn`/`email`, and
`orders`), `idp` (a static-JWKS issuer with two pre-minted tokens, `analyst` and
`admin`, `aud=eunox-mcp`). One shared audit volume mounted into `eunox`. Only
`eunox` can reach `postgres-mcp` on the compose network — the analyst never gets a
direct route to the server.

**The four moments:**

1. **Allow** — analyst runs `SELECT email FROM orders` -> forwarded, result
   returned, audit `ALLOW`.
2. **Deny (argument policy)** — analyst runs `DROP TABLE customers` -> eunox
   returns a structured `CONDITION_FAILED` (allowedOperations = SELECT only),
   the upstream is **never called**, audit `DENY`.
3. **Redaction** — analyst runs `SELECT * FROM customers` -> rows come back with
   `ssn: "[redacted]"`.
4. **Tamper-evident audit** — `eunox audit-verify` shows the signed chain of
   allow/deny records, each stamped with the analyst identity LiteLLM forwarded.

Optional fifth moment — swap the analyst token for the admin token and repeat:
the same eunox now applies the `db-rw` manifest, because LiteLLM routed the admin
key to `/mcp/db-rw`. Same process, same audit tape, different policy by identity.

---

## Acceptance criteria

- [ ] Allow path: a permitted `SELECT` reaches the upstream and returns.
- [ ] Deny path: a non-`SELECT` returns `CONDITION_FAILED`; the upstream is never
      called (assert via the upstream's own logs).
- [ ] Redaction: `ssn` is `[redacted]` in the analyst's result.
- [ ] Attribution: each audit record carries the forwarded caller identity.
- [ ] Integrity: `eunox audit-verify` passes; flipping one byte of the log makes
      it fail.
- [ ] Per-identity: analyst and admin keys hit different manifests.

---

## Risks and spikes (in order)

1. **Transport compatibility.** Confirm LiteLLM's upstream MCP client speaks
   Streamable HTTP the way eunox's gateway expects and round-trips
   `Mcp-Session-Id`. LiteLLM supports `sse`, `http` (streamable), and `stdio`
   upstream transports; use `http`. One-hour spike; it gates everything.
2. **Identity forwarding.** Confirm `extra_headers` forwards the *end user's*
   `Authorization`, not LiteLLM's own upstream `auth_value`. If it can't,
   ship v1 with static per-route policy (no per-user attribution) and add
   identity later.
3. **`aud` / `iss` alignment.** Mint demo tokens with `aud=eunox-mcp`; eunox
   fails closed on an unpinned audience in JWKS mode.
4. **Upstream transport.** If your Postgres MCP server is stdio-only, front it
   with a stdio->HTTP adapter (the gateway upstream is HTTP).

## Effort

- Transport spike: ~1–2 hrs, decides the shape.
- v1a (static policy, no identity): S, ~half a day after the spike.
- v1b (identity forwarded, route-per-identity): M, ~1 day.
- Demo compose + docs: S.

Roughly a 2–3 day reference if the transport spike is clean; otherwise fall back
to v1a and still ship a working artifact.

## References

- [LiteLLM MCP overview](https://docs.litellm.ai/docs/mcp)
- [LiteLLM MCP permission management](https://docs.litellm.ai/docs/mcp_control)
- [LiteLLM MCP OAuth](https://docs.litellm.ai/docs/mcp_oauth)
- eunox: [deployment-hardening.md](../deployment-hardening.md) (bypass prevention),
  [capability-manifest-guide.md](../capability-manifest-guide.md) (manifest authoring)
