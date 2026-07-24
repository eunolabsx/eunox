# eunox + Flowise

**Pattern B — stdio command wrap (primary), and Pattern A — HTTP gateway URL
substitution.**

[Flowise](https://docs.flowiseai.com/) is a visual LLM/agent builder. Its
**Custom MCP** tool node connects to an MCP server over either stdio (Flowise
spawns the configured command as a child process via `StdioClientTransport`) or
Streamable HTTP (a URL plus headers).

The stdio path is the sharp edge: any user who can edit a chatflow can supply an
arbitrary stdio MCP server command that Flowise then executes on the server host
— the class of issue behind
[CVE-2026-40933](https://www.obsidiansecurity.com/blog/when-is-stdio-mcp-actually-a-vulnerability)
(1-click RCE via stdio MCP). Wrapping that command with eunox turns an
open-ended local exec into a policy-checked, audited one.

> Reuse the gateway config, manifest, and identity setup from
> [README.md](./README.md#shared-setup-for-pattern-a--the-eunox-http-gateway).

## Wiring — Pattern B (stdio server)

Flowise's Custom MCP node takes an MCP server config like:

```json
{ "command": "npx", "args": ["-y", "@some/mcp-server", "/data"] }
```

Front it with eunox so eunox is the child process Flowise spawns, and it in turn
launches the real server. **Observe first** — the wiretap form wraps the command
inline and needs no config, forwarding and recording every call:

```json
{ "command": "eunox",
  "args": ["proxy", "--audit", "--", "npx", "-y", "@some/mcp-server", "/data"] }
```

**Then enforce** — move the command into an `eunox.yaml` (a `transport: stdio`
upstream with a `policy:`) and have Flowise spawn eunox against it:

```json
{ "command": "eunox", "args": ["proxy", "--config", "/abs/eunox.yaml"] }
```

See [client-integration.md](../client-integration.md) for the stdio config and
the wiretap-first workflow. This constrains what the spawned server may do and
records every call, regardless of who authored the chatflow.

## Wiring — Pattern A (HTTP server)

For a Streamable HTTP MCP server, run the eunox gateway and set the Custom MCP
node's URL to the eunox route (`http://eunox:3000/mcp/<name>`) with an
`Authorization` header. Same URL-substitution move as the other Pattern-A
platforms.

## Gotchas

- **Binary availability (stdio).** `eunox` must be on the Flowise host's `PATH`
  (or referenced by absolute path), including inside the Flowise container image.
- **Untrusted authorship.** Because chatflow editors control the node config,
  treat eunox here as a guardrail on a semi-trusted input surface: pin the
  manifest and prevent editors from swapping the wrapped command (deploy the node
  config from a controlled source, not free-form editing). See
  [deployment-hardening.md](../deployment-hardening.md).
- **Transport spike (HTTP).** Confirm Flowise's Streamable HTTP client
  round-trips `Mcp-Session-Id` against eunox.

## Effort

S. A config-string change on the Custom MCP node (stdio wrap or URL), plus
ensuring the `eunox` binary is present for the stdio path.

## References

- [Flowise Tools & MCP](https://docs.flowiseai.com/tutorials/tools-and-mcp)
- [CVE-2026-40933 analysis](https://www.obsidiansecurity.com/blog/when-is-stdio-mcp-actually-a-vulnerability)
- eunox: [client-integration.md](../client-integration.md),
  [deployment-hardening.md](../deployment-hardening.md)
