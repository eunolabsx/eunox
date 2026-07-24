# eunox + Dify

**Pattern A — HTTP gateway URL substitution.**

[Dify](https://docs.dify.ai/) is a multi-tenant LLM app platform. When a builder
connects an MCP server (Postgres, GitHub, …) to a workspace, its tools become
reachable by every app and user that touches that workspace — a broad, shared
grant. eunox lets a platform operator constrain *what those apps can actually do*
with the server, per route, without touching Dify.

> Reuse the gateway config, manifest, and identity setup from
> [README.md](./README.md#shared-setup-for-pattern-a--the-eunox-http-gateway).

## Wiring

Dify registers MCP servers through its **Add MCP Server (HTTP)** flow (name,
server URL, unique identifier, description) and supports `sse` or
`streamable_http` transport with custom headers for auth.

1. Run the eunox gateway with a route for the server (e.g. `/mcp/db`).
2. In Dify, add the MCP server with:
   - **Server URL:** `http://eunox:3000/mcp/db` (the eunox route, not the real
     server).
   - **Transport:** `streamable_http` (preferred; `sse` also works).
   - **Headers:** `Authorization: Bearer <token>` if you are forwarding a static
     service token, or wire the end-user token per your Dify auth setup.
3. Import the tools. Dify apps now reach the server only through eunox.

## Gotchas

- **Timeouts.** Dify exposes request timeout and `sse_read_timeout`. For
  long-running calls behind nginx, its default keepalive is 65s — raise
  `NGINX_KEEPALIVE_TIMEOUT` in Dify's `.env` if streamed results exceed it. Keep
  eunox's `defaults.upstreamTimeoutMs` consistent with the real server's latency.
- **Multi-tenant scoping.** Dify's static per-server headers make per-end-user
  identity forwarding awkward. Simplest per-tenant model: one eunox route (and
  manifest) per Dify workspace/app, and register the matching route URL in each.
- **Transport spike.** Confirm Dify's `streamable_http` client round-trips
  `Mcp-Session-Id` against eunox's gateway.

## Effort

S–M. One route per app/workspace, URL substitution in the Dify UI, no code
change. The main work is deciding the per-tenant route/manifest layout.

## References

- [Dify Tools](https://docs.dify.ai/en/cloud/use-dify/workspace/tools)
- [Turn your Dify app into an MCP server](https://dify.ai/blog/turn-your-dify-app-into-an-mcp-server)
  (the reverse direction; eunox governs the client direction)
- eunox: [deployment-hardening.md](../deployment-hardening.md)
