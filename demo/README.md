# eunox demo

Two Docker services. One manifest file. First enforced tool call in under 10 minutes.

> **Just want the hero demo?** [`trifecta/`](./trifecta/) shows eunox blocking
> credential exfiltration — `read_credentials` ALLOW then `write_external` DENY
> via one `sequenceBlock` condition — against the real binary, Go only, no
> Docker: `make -C demo trifecta`. The persistent-audit variant,
> `make -C demo trifecta-audit`, keeps the signed tape across runs and shows
> tampering with it — a rewritten verdict, a forged record — being caught live.

> **Information-flow control (experimental).** `make -C demo flow-exfil` shows
> within-scope exfil blocked by *source→sink flow policy*: reading a sensitive
> source labels the task `confidential`, so the identical egress write that a
> clean session is allowed to make is **denied** once that label is present —
> the agent is inside its granted capabilities, but the flow is not permitted.
> Deterministic and model-free; `make -C demo ci-test-flow` asserts 20 identical
> runs with a verified tape. Uses the experimental flow+effect grammar
> (`flowLabel` / `labelOutput`), staged behind `schemaVersion: "0.2-draft"` in
> [`manifest-flow.yaml`](./manifest-flow.yaml) — not part of the published `0.1`
> grammar. Go + python3, no Docker.
>
> Scope: the source→sink guarantee holds even against a client that fires the
> source read and the egress write concurrently on one session — the proxy
> serializes a flow-relevant session's decision phase in receipt order, so the
> source's label commits before the egress's check regardless of client
> concurrency (the race the demo used to hide by serializing its client is closed). A
> session's taint is retained for the whole session lifetime — no wall-clock
> expiry — and reclaimed when the session ends. Across multiple proxy instances it
> requires a shared Redis flow-label store (a startup NOTICE warns when one is
> missing).

> **Effect contracts (experimental).** `make -C demo effect-escalate` shows the other
> axis: an agent reads an untrusted, customer-submitted ticket carrying a prompt
> injection and then attempts `DROP TABLE customers`. The capability is **granted** —
> `query_db` is in the allowlist and `DROP` is explicitly in its `allowedOperations` —
> so per-call authorization has nothing left to say. The call is **escalated** because
> of what it would *do*: the effect contract resolves `DROP` to `irreversible` with no
> compensating action, which exceeds the policy's tool-agnostic `effectCeiling`. A
> `SELECT` through the same tool in the same tainted session is **allowed**, so it is
> the consequence — not the tool, the session, or the taint — that decided it. The
> escalated record carries `carried_labels=untrusted`, tying the refusal to the
> provenance that produced it: one tape, one enforcement point, both axes.
> Deterministic and model-free; `make -C demo ci-test-effect` asserts 20 identical runs
> with a verified tape. Uses the experimental flow+effect grammar (`effect`,
> `effectCeiling`), staged behind `schemaVersion: "0.2-draft"` in
> [`manifest-effect.yaml`](./manifest-effect.yaml) — not part of the published `0.1`
> grammar. Go + python3, no Docker.
>
> Scope: escalate is a **refusal that says why**, not a pending state. The in-path proxy
> holds no approval workflow (that is the control-plane surface), so with none wired an
> escalation resolves fail-closed to "not forwarded", carrying the consequence inputs on
> the tape as `decision=escalate` with `ceiling_exceeded`. It is a hard refusal: a route
> running `--audit` cannot downgrade it to "performed anyway, logged".

## What this demo shows

- `eunox` sitting between a client and an MCP server, enforcing a YAML policy
- **Allow**: `read_file /reports/q3.pdf` — passes the `AllowedValues` path condition
- **Deny**: `write_file` — not in the manifest, blocked by default
- **Deny**: `read_file /etc/shadow` — path doesn't match `/reports/*`
- **Deny**: `query_db DELETE` — blocked by `AllowedOperations: [SELECT]`
- Tamper-evident OCSF audit log with HMAC-SHA256 per-record signing
- **JWT mode** (step 3): IdP-issued capability claims via Keycloak, intersected with the manifest
- **Gateway mode** (step 4): one proxy fronting **many** upstreams, each on its own `/mcp/<name>` route with its own independently versioned manifest, sharing one audit tape

## Prerequisites

```
docker      >= 24.0
docker compose >= 2.20
jq          (for pretty-printed output; optional)
curl
```

---

## Step 1 — Start the stack

```
$ make -C demo up
```

Expected output:
```
[+] Building 12.4s (21/21) FINISHED
[+] Running 2/2
 ✔ Container demo-mock-mcp-server-1  Started
 ✔ Container demo-eunox-1        Started

  eunox proxy : http://localhost:3000/mcp
  mock-mcp-server : http://localhost:8080/mcp

  Next: make -C demo allow   # allowed tool call
        make -C demo deny    # policy denial
        make -C demo audit   # live audit log
```

Keycloak is intentionally excluded from this manifest-only stack — it's gated
behind the `jwt` compose profile, so `make -C demo up` never pulls its image.
See [Step 3](#step-3--jwt-mode-manifest--idp-claims) to start it with `make -C demo up-jwt`.

The proxy takes ~5 seconds to be ready. The healthcheck polls the mock server and
waits before starting eunox.

---

## Step 2a — Allowed tool call

`read_file /reports/q3.pdf` matches the `AllowedValues: ["/reports/*"]` condition in
`demo/manifest.yaml`. The proxy forwards the call to the mock server.

```
$ make -C demo allow
```

Expected output:
```
>>> read_file /reports/q3.pdf  [expect: ALLOWED]
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "[mock] Contents of /reports/q3.pdf:\n\nQ3 Financial Summary\nRevenue:  $12,400,000\nExpenses: $ 8,900,000\nEBITDA:   $ 3,500,000\n(end of mock file /reports/q3.pdf)"
      }
    ],
    "isError": false
  }
}
```

---

## Step 2b — Policy denial (tool not in manifest)

`write_file` is intentionally absent from the manifest. The proxy denies it before
the request reaches the mock server.

```
$ make -C demo deny
```

Expected output:
```
>>> write_file /etc/passwd  [expect: DENIED — not in manifest]
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"code\":\"AUTHORIZATION_FAILED\",\"error\":\"CapabilityDenied\",\"message\":\"tool \\\"write_file\\\" is not listed in the capability manifest\",\"tool\":\"write_file\"}"
      }
    ],
    "isError": true
  }
}
```

---

## Step 2c — Policy denial (wrong path)

`read_file /etc/shadow` is denied because `/etc/shadow` does not match `/reports/*`.

```
$ make -C demo deny-path
```

Expected output:
```
>>> read_file /etc/shadow  [expect: DENIED — path not in /reports/*]
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"code\":\"VALUE_NOT_PERMITTED\",\"details\":{\"allowedValues\":[\"/reports/*\"],\"argument\":\"path\",\"value\":\"[redacted]\"},\"error\":\"CapabilityDenied\",\"message\":\"argument \\\"path\\\" value is not in the allowed set\",\"tool\":\"read_file\"}"
      }
    ],
    "isError": true
  }
}
```

---

## Step 2d — Policy denial (wrong SQL operation)

`query_db DELETE` is denied by `AllowedOperations: [SELECT]`.

```
$ make -C demo deny-op
```

Expected output:
```
>>> query_db DELETE FROM reports  [expect: DENIED — only SELECT permitted]
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"code\":\"OPERATION_NOT_PERMITTED\",\"details\":{\"allowedOperations\":[\"SELECT\"],\"operation\":\"[redacted]\"},\"error\":\"CapabilityDenied\",\"message\":\"operation \\\"DELETE\\\" is not allowed\",\"tool\":\"query_db\"}"
      }
    ],
    "isError": true
  }
}
```

---

## Step 2e — Audit log

The proxy writes a tamper-evident OCSF audit record for every decision. Each record
has an HMAC-SHA256 signature.

```
$ make -C demo audit
```

Expected output (one record per tool call, streaming):
```json
{
  "class_uid": 6003,
  "time": "2026-05-29T12:00:00.123456789Z",
  "request_id": "a3f1e2b4-...",
  "session_id": "d7c8b9a0-...",
  "target_type": "tool",
  "target": "read_file",
  "method": "tools/call",
  "decision": "allow",
  "hmac": "sha256:a1b2c3d4..."
}
{
  "class_uid": 6003,
  "time": "2026-05-29T12:00:01.456789012Z",
  "request_id": "b5e6f7a8-...",
  "session_id": "e9d0c1b2-...",
  "target_type": "tool",
  "target": "write_file",
  "method": "tools/call",
  "decision": "deny",
  "hmac": "sha256:b2c3d4e5..."
}
```

Verify the HMAC chain:
```
$ docker run --rm -v "$(pwd)/demo/audit:/audit" \
    --entrypoint /usr/local/bin/mcp \
    ghcr.io/eunolabs/eunox:latest \
    audit-verify --audit-log /audit/audit.jsonl --audit-key-path /audit/audit.key
Checked 4 record(s): 4 valid, 0 invalid, 0 skipped.
```

---

## Step 3 — JWT mode (manifest + IdP claims)

In JWT mode, every request must carry an IdP-issued Bearer JWT. The proxy
intersects the JWT's `mcp.capabilities` claims with the manifest: the JWT can
only restrict, never expand.

**Experimental.** The `mcp.capabilities` claim schema (JWT v0.2) is experimental,
so this demo runs eunox with `--jwt-experimental-capabilities` (already set in
`docker-compose.jwt.yml`). Without that flag a token carrying `mcp.capabilities`
is rejected (HTTP 401); the rest of JWT mode — signature/issuer/audience
validation and identity claims — needs no flag.

The Keycloak `demo-agent` client issues tokens with:
```json
{
  "mcp.v": "0.2",
  "mcp.capabilities": ["tool:read_file?path=/reports/*", "tool:query_db?op=SELECT"],
  "mcp.task_id": "demo-task-001",
  "mcp.agent_id": "demo-agent",
  "aud": "eunox"
}
```

### 3a — Restart with JWT mode enabled

```
$ make -C demo up-jwt
```

Expected output:
```
[+] Running 3/3
 ✔ Container demo-keycloak-1         Healthy
 ✔ Container demo-mock-mcp-server-1  Healthy
 ✔ Container demo-eunox-1        Started

  eunox (JWT mode) : http://localhost:3000/mcp
  Keycloak             : http://localhost:8081 (admin / admin)
```

### 3b — Get a test JWT

```
$ make -C demo jwt
```

Expected output (raw JWT, trimmed):
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii...
```

Decode at jwt.io to inspect the claims.

### 3c — JWT-authenticated allowed call

```
$ make -C demo jwt-allow
```

Expected output:
```
>>> [JWT mode] read_file /reports/q3.pdf  [expect: ALLOWED]
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [{ "type": "text", "text": "[mock] Contents of /reports/q3.pdf:..." }],
    "isError": false
  }
}
```

### 3d — JWT-authenticated denied call

`write_file` is absent from both the manifest and the JWT claims.

```
$ make -C demo jwt-deny
```

Expected output:
```
>>> [JWT mode] write_file /tmp/x.txt  [expect: DENIED — not in JWT capabilities]
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [{ "type": "text", "text": "{\"code\":\"AUTHORIZATION_FAILED\",...}" }],
    "isError": true
  }
}
```

---

## Step 4 — Gateway mode (one proxy, many upstreams)

The base demo runs one proxy per upstream. **Gateway mode** instead runs a
single `eunox` process fronting many MCP servers — each on its own
`/mcp/<name>` route, each governed by its **own independently versioned
manifest**, all writing to **one** signed audit tape.

This stack (`docker-compose.gateway.yml`) wires two upstreams:

```
MCP host ──► eunox-gateway ──► /mcp/files ──► mock-files  (policies/files.yaml @ 0.1.0 — read_file /reports/*)
                          └─► /mcp/db    ──► mock-db     (policies/db.yaml    @ 0.2.0 — query_db SELECT)
```

### 4a — Start the gateway stack

```
$ make -C demo gateway-up
```

```
  eunox-gateway : http://localhost:3000
    /mcp/files  → mock-files  (files.yaml @ 0.1.0 — read_file /reports/*)
    /mcp/db     → mock-db     (db.yaml    @ 0.2.0 — query_db SELECT)
```

Each route's manifest declares its own `version`. A route may pin it with
`expectVersion:` (see `gateway.yaml`); the gateway **fails closed** — refusing to
start — if the loaded manifest's version differs.

### 4b — Per-route allow

```
$ make -C demo gw-files-allow   # read_file /reports/q3.pdf on /mcp/files → ALLOWED
$ make -C demo gw-db-allow      # query_db SELECT on /mcp/db             → ALLOWED
```

### 4c — Per-route manifests (the headline)

The same `read_file` call allowed on `/mcp/files` is **denied** on `/mcp/db`,
because `db-policy` doesn't grant it — each route is enforced against its own
manifest:

```
$ make -C demo gw-cross-deny    # read_file on /mcp/db → DENIED (read_file not in db-policy)
```

### 4d — Unknown route

```
$ make -C demo gw-404           # POST /mcp/bogus → HTTP 404
```

### 4e — One audit tape, stamped per upstream

Every record across both routes lands in the same `audit/audit.jsonl`, stamped
with the handling `upstream`, the in-force `policy_version`, and a
`policy_sha256` digest:

```
$ make -C demo gateway-audit
```

```json
{ "upstream": "files", "policy_version": "0.1.0", "policy_sha256": "sha256:…", "target_type": "tool", "target": "read_file", "method": "tools/call", "decision": "allow" }
{ "upstream": "db",    "policy_version": "0.2.0", "policy_sha256": "sha256:…", "target_type": "tool", "target": "read_file", "method": "tools/call", "decision": "deny", "denial_code": "AUTHORIZATION_FAILED" }
```

Run the full per-route assertion suite (starts the stack, tests, tears down):

```
$ make -C demo ci-test-gateway
```

---

## Tear down

```
$ make -C demo down            # base / JWT stack
$ make -C demo gateway-down    # gateway stack
```

---

## What's in this directory

```
demo/
├── docker-compose.yml          base stack: mock-mcp-server + keycloak + eunox (manifest mode)
├── docker-compose.jwt.yml      overlay: switches eunox to JWT + manifest intersection mode
├── docker-compose.gateway.yml  gateway stack: one proxy fronting two upstreams (/mcp/files, /mcp/db)
├── manifest.yaml               capability policy for the base/JWT demo
├── gateway.yaml                gateway config: routes + per-route policy + version pins
├── policies/
│   ├── files.yaml              per-route manifest for /mcp/files (files-policy 0.1.0)
│   └── db.yaml                 per-route manifest for /mcp/db    (db-policy 0.2.0)
├── Makefile                    all demo targets
├── audit/                      audit log written here by eunox (bind-mounted into container)
├── mock-mcp-server/
│   ├── main.go                 minimal MCP HTTP server (3 tools, fake responses)
│   ├── main_test.go            unit tests
│   └── Dockerfile              multi-stage Go build (shares root go.mod)
├── keycloak/
│   └── realm-export.json       eunox-demo realm with demo-agent client and capability mappers
└── scripts/
    ├── mcp-call.sh             initialize session + tool call (base/JWT)
    ├── mcp-call-gateway.sh     initialize session + tool call on a /mcp/<route>
    ├── ci-test-gateway.sh      gateway per-route integration test
    └── get-jwt.sh              client-credentials token request to Keycloak
```

## Troubleshooting

**`make allow` fails with "connection refused"**
The proxy is not ready yet. Wait 10 seconds and retry. Or watch: `make -C demo logs`.

**`make jwt` fails with "failed to reach Keycloak"**
Keycloak takes up to 30 seconds to start. Check: `docker compose -f demo/docker-compose.yml logs keycloak | tail -20`

**Audit log is empty**
Make a call first (`make allow`), then re-run `make audit`.

**On Linux: audit log permission error**
The `make up` target runs `chmod 777 demo/audit/`. If you see permission errors,
run `sudo chmod 777 demo/audit && sudo chown -R 0:0 demo/audit` then `make up`.
