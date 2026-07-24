# eunox + Conductor (OSS / Orkes)

**Pattern A (workflow tool calls) and Pattern C (custom workers).**

[Conductor](https://docs.conductor-oss.org/) is a durable workflow-orchestration
engine. It is a centralized, highly automated execution plane where workflow
tasks reach enterprise systems — a natural chokepoint, and one with a large blast
radius if a task or a prompt-injected agent step misbehaves. eunox constrains
what those tasks can do at the MCP boundary without changing the orchestration
logic.

## Which Conductor MCP surface this governs

Conductor touches MCP three ways. Only the first is the enforcement wedge:

1. **Conductor as MCP client — the wedge.** Workflows call external MCP servers
   via the `CALL_MCP_TOOL` and `LIST_MCP_TOOLS` system tasks. This is outbound:
   a workflow reaching a sensitive backend through MCP. Put eunox in that path.
2. Conductor's [MCP Gateway](https://orkes.io/content/developer-guides/mcp-gateway)
   exposes *workflows as* MCP tools (inbound to Conductor). Not this doc's target.
3. The [`conductor-mcp` server](https://github.com/conductor-oss/conductor-mcp)
   exposes Conductor's *own API* to agents. Not this doc's target.

> Reuse the gateway config, manifest, and identity setup from
> [README.md](./README.md#shared-setup-for-pattern-a--the-eunox-http-gateway).

## Wiring — Pattern A (system tasks)

`CALL_MCP_TOOL` / `LIST_MCP_TOOLS` reference an MCP server endpoint in their task
input.

1. Run the eunox gateway with a route for the server (e.g. `/mcp/db`).
2. In the task's MCP-server input, set the endpoint to the eunox route
   (`http://eunox:3000/mcp/db`) instead of the real server, and pass identity in
   the request headers. Confirm the exact input field names for the endpoint and
   headers against your Conductor version's task schema.
3. Every `CALL_MCP_TOOL` in every workflow execution now routes through eunox.

## Wiring — Pattern C (custom workers)

If a task is a hand-written worker that constructs its own MCP client, point that
client's endpoint at the eunox route via config or environment variable. See
[temporal.md](./temporal.md) for the in-code shape; it is identical here.

## Gotchas

- **Attribution.** Workflow executions are headless. Forward a per-workflow (or
  per-task) service token so audit records name a principal.
- **Transport spike.** Confirm Conductor's MCP task client speaks Streamable HTTP
  and round-trips `Mcp-Session-Id` against eunox.
- **Bypass.** Isolate the real MCP server so only eunox can reach it — otherwise a
  workflow could target the server endpoint directly. See
  [deployment-hardening.md](../deployment-hardening.md).

## Effort

S–M. URL substitution in the task input for Pattern A; a one-line endpoint change
for Pattern C workers.

## References

- [Conductor MCP Gateway](https://orkes.io/content/developer-guides/mcp-gateway)
- [Why Conductor for agents](https://conductor-oss.github.io/conductor/devguide/ai/why-conductor.html)
- eunox: [deployment-hardening.md](../deployment-hardening.md)
