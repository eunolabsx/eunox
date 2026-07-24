# eunox + n8n

**Pattern A — HTTP gateway URL substitution.**

[n8n](https://docs.n8n.io/) is a workflow-automation platform. Its **MCP Client
Tool** node lets a workflow (often headless, running unattended) call an MCP
server's tools. Point that node at eunox instead of the server and every tool
call from every workflow run is policy-checked, redacted, and logged.

> Reuse the gateway config, manifest, and identity setup from
> [README.md](./README.md#shared-setup-for-pattern-a--the-eunox-http-gateway).

## Wiring

The MCP Client Tool node takes an **HTTP Streamable URL** endpoint plus optional
additional headers (Bearer, generic header, or OAuth2).

1. Run the eunox gateway with a route for the server (e.g. `/mcp/db`).
2. In the MCP Client Tool node:
   - **Endpoint / HTTP Streamable URL:** `http://eunox:3000/mcp/db`.
   - **Headers:** `Authorization: Bearer <token>` to forward identity for
     verification + attribution.
3. The workflow's tool calls now flow through eunox.

## Gotchas

- **Use HTTP Streamable, not SSE.** SSE is deprecated in n8n's MCP nodes in favor
  of HTTP Streamable, which matches eunox's gateway. Note the known transport
  bugs where a selected transport was ignored and SSE was used anyway
  ([#18938](https://github.com/n8n-io/n8n/issues/18938),
  [#24967](https://github.com/n8n-io/n8n/issues/24967)) — verify the node
  actually negotiates Streamable HTTP against eunox and round-trips
  `Mcp-Session-Id`. This is the transport spike; do it first.
- **Headless attribution.** Automated runs have no interactive user. Forward a
  per-workflow service token (distinct `sub`) so the audit log still attributes
  calls to a named principal.

## Effort

S. One node URL change per workflow (or per shared credential), no code. Budget
the transport spike given the known SSE/Streamable bugs.

## References

- [n8n MCP Client Tool node](https://docs.n8n.io/integrations/builtin/cluster-nodes/sub-nodes/n8n-nodes-langchain.toolmcp)
- [HTTP Streamable transport support PR](https://github.com/n8n-io/n8n/pull/15454)
- eunox: [deployment-hardening.md](../deployment-hardening.md)
