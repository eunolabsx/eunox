# eunox + Temporal

**Pattern C — in-code / activity MCP client.**

[Temporal](https://docs.temporal.io/) is a durable-execution engine. It has no
native MCP-server registry: an agent built on Temporal calls MCP tools from
**activity** code, where the activity constructs an MCP client and connects to a
server. eunox sits at that client's endpoint.

Temporal is the audit-conscious, enterprise end of the orchestration spectrum —
a strong fit for eunox's signed decision log. The two produce complementary
records: Temporal's event history says *what the workflow did and when eunox is
in the path*; eunox's audit tape says *which MCP calls were allowed or denied,
and why*.

> Reuse the gateway config, manifest, and identity setup from
> [README.md](./README.md#shared-setup-for-pattern-a--the-eunox-http-gateway).

## Wiring

The MCP client lives in your activity, so the insertion is a configured endpoint,
not a console setting.

- **HTTP MCP server:** run the eunox gateway and set the activity's MCP endpoint
  to the eunox route:

  ```bash
  MCP_SERVER_URL=http://eunox:3000/mcp/db      # was: the real server URL
  ```

- **stdio MCP server** spawned by the activity: use eunox in stdio mode
  (Pattern B) — have the activity launch `eunox proxy --config eunox.yaml -- <original server command>`
  instead of the server directly. See
  [client-integration.md](../client-integration.md) for the stdio wrap.

Pass the end-user or per-workflow identity in the client's request headers
(`Authorization: Bearer <token>`) so eunox verifies and attributes it.

## Gotchas

- **Change lives in code.** Unlike the URL-substitution platforms, someone edits
  the activity (or its env/config). Keep it a single injected endpoint/env var so
  the swap stays a one-line, reviewable change.
- **Determinism.** Keep the eunox call inside an **activity**, never in workflow
  code — it is non-deterministic I/O. (This is standard Temporal practice; noted
  because MCP calls are easy to misplace.)
- **Retries.** Temporal will retry failed activities. A eunox *deny* is a
  policy decision, not a transient fault — treat `AUTHORIZATION_FAILED` /
  `CONDITION_FAILED` as non-retryable in the activity's retry policy so a blocked
  call does not loop.

## Effort

S. One injected endpoint/env var per activity that speaks MCP.

## References

- [Temporal activities](https://docs.temporal.io/activities)
- eunox: [deployment-hardening.md](../deployment-hardening.md),
  [client-integration.md](../client-integration.md)
