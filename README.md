<p align="center">
  <img src="./img/eunolabs.png" alt="eunox" height="160">
</p>

<h1 align="center">eunox</h1>

<p align="center">
  <strong>The capability-enforcement layer MCP left out.</strong><br>
  Your IdP says <em>who you are</em>. eunox says <em>which tool calls, with which arguments, in which order</em> — enforced at the protocol boundary, before the call runs.
</p>

<p align="center">
  <strong>MCP capability firewall</strong><br>
  Sits between your MCP host and any MCP server — local subprocess or remote HTTPS. Every <code>tools/call</code>, <code>resources/read</code>, <code>resources/subscribe</code>, <code>prompts/get</code>, and <code>sampling/createMessage</code> is checked against a YAML capability manifest before it is forwarded; <code>tools/list</code>, <code>resources/list</code>, and <code>prompts/list</code> are filtered to permitted entries only. Every decision on a checked method is recorded to a tamper-evident OCSF audit log (asynchronous, with documented <a href="./docs/conformance.md#audit-log-and-compliance">delivery caveats</a>; <code>--require-audit</code> defaults to <code>strict</code>, so the proxy fails fast at startup if the log cannot be opened and denies forwards fail-closed once the trail degrades — pass <code>--require-audit=on</code> for startup-fatal only, or <code>--require-audit=off</code> to run unaudited).
</p>

<p align="center">
  <em>Identity answers <strong>who is calling</strong> — that's your IdP or OAuth stack. Capabilities answer <strong>what a call may do</strong> — eunox enforces them from a <a href="https://github.com/eunolabs/agent-capability-manifest">capability manifest for agent actions</a> whose grammar is protocol-neutral. <strong>MCP is binding&nbsp;#1</strong>: the first boundary eunox polices.</em>
</p>

<p align="center">
  <em>Authorization, not detection: eunox is the least-privilege layer for agent actions — a deny-by-default allowlist, so the dangerous call is impossible rather than merely recognized. MCP is the first and sharpest boundary; the open <a href="https://github.com/eunolabs/agent-capability-manifest">capability-manifest standard</a> behind it is protocol-neutral, with a draft model-API binding already published.</em>
</p>

<p align="center">
  <em>eunox is named for the ancient Greek ideal of <strong>good order under good laws</strong> (εὐνομία).</em>
</p>

<p align="center">
  <a href="https://github.com/eunolabs/eunox/actions/workflows/go-ci.yml"><img alt="build status" src="https://github.com/eunolabs/eunox/actions/workflows/go-ci.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/eunolabs/eunox/actions/workflows/go-ci.yml"><img alt="go test coverage" src="https://img.shields.io/github/check-runs/eunolabs/eunox/main?nameFilter=Test&label=go%20test%20coverage"></a>
  <a href="https://github.com/eunolabs/eunox/actions/workflows/go-ci.yml"><img alt="benchmark tests" src="https://img.shields.io/github/check-runs/eunolabs/eunox/main?nameFilter=Benchmark%20%28sanity%29&label=benchmarks"></a>
  <a href="https://github.com/eunolabs/eunox/releases"><img alt="latest release" src="https://img.shields.io/github/v/release/eunolabs/eunox?include_prereleases"></a>
</p>

<p align="center">
  <a href="https://goreportcard.com/report/github.com/eunolabs/eunox"><img alt="go report card" src="https://goreportcard.com/badge/github.com/eunolabs/eunox"></a>
  <a href="https://github.com/eunolabs/eunox/actions/workflows/go-ci.yml"><img alt="go vulncheck" src="https://img.shields.io/github/check-runs/eunolabs/eunox/main?nameFilter=govulncheck&label=govulncheck"></a>
    <a href="https://github.com/eunolabs/eunox/security/code-scanning"><img alt="codeql" src="https://github.com/eunolabs/eunox/actions/workflows/github-code-scanning/codeql/badge.svg"></a>
  <a href="https://github.com/eunolabs/eunox/actions/workflows/scorecard.yml"><img alt="openssf scorecard" src="https://github.com/eunolabs/eunox/actions/workflows/scorecard.yml/badge.svg?branch=main"></a>
  <a href="https://snyk.io/test/github/eunolabs/eunox?targetFile=go.mod"><img alt="snyk scan" src="https://snyk.io/test/github/eunolabs/eunox/badge.svg?targetFile=go.mod"></a>
  <a href="https://github.com/eunolabs/eunox/actions/workflows/go-ci.yml"><img alt="trivy scan" src="https://img.shields.io/github/check-runs/eunolabs/eunox/main?nameFilter=Trivy%20Vulnerability%20Scan&label=trivy"></a>
</p>

<p align="center">
  <a href="https://go.dev/"><img alt="go version" src="https://img.shields.io/badge/go-%E2%89%A51.26.5-00ADD8"></a>
  <a href="https://pkg.go.dev/github.com/eunolabs/eunox"><img alt="go reference" src="https://pkg.go.dev/badge/github.com/eunolabs/eunox.svg"></a>
  <a href="https://github.com/eunolabs/eunox/blob/main/cmd/eunox/LICENSE"><img alt="license" src="https://img.shields.io/badge/eunox-Apache--2.0-green.svg"></a>
  <a href="https://spec.modelcontextprotocol.io/"><img alt="mcp" src="https://img.shields.io/badge/MCP-supported-7c3aed"></a>
</p>

---

> An AI coding agent recently wiped a startup's production database — and its backups — in nine seconds. Another was nearly tricked into deleting a project's tests by an instruction hidden in a library it imported. The model is the wrong place to stop this; by the time it emits `DROP TABLE`, the argument is already structured data. **eunox checks that structured call against a policy you wrote — and refuses it — before it ever reaches your backend.**

<p align="center">
  <img src="https://github.com/eunolabs/eunox/blob/main/img/demo.gif?raw=true" alt="eunox denying a DROP TABLE and a .pem read against a YAML manifest" width="900">
</p>

<p align="center">
  <sub>Reproduce: <code>make -C demo up && vhs demo/demo.tape</code> — see <a href="./demo/demo.tape"><code>demo/demo.tape</code></a>.</sub>
</p>

<p align="center">
  <strong>⭐ If a capability firewall for your agents is useful, star the repo — it's the fastest way to help.</strong>
</p>

---

## Quick start

eunox is adopted as a loop, not a leap: **wiretap → see the evidence → draft the policy from it → enforce**. Nothing is blocked until the last step — no scary day-one deny — and every step is one command that already ships in the binary.

**Step 1 — wiretap.** Wrap any MCP server in audit-only mode in one line, no files:

```bash
eunox proxy --audit -- npx -y @modelcontextprotocol/server-filesystem /data
# …point your MCP host at this command and use the agent for a while
```

(The example wraps the npm `server-filesystem`, so it needs Node / `npx` on `PATH` — the one-liner wraps **any** MCP server, e.g. a Python one via `uvx`, or a local binary. No toolchain at all? See the Docker / no-Docker trials below.)

Every enforced-method call (`tools/call`, `resources/read`, `resources/subscribe`, `prompts/get`, `sampling/createMessage`) is forwarded and recorded to `~/.eunox/audit.jsonl` with an HMAC signature; `tools/call` records also include the full argument map. (`…/list` calls forward the full upstream catalog unfiltered and are recorded as enumeration events — without a per-entry argument map.)

> **Security note:** In audit/wiretap mode the log contains full tool call argument values for every call. Treat `audit.jsonl` as sensitive regardless of mode — even in enforce mode, denial records include condition-specific argument excerpts (e.g., the rejected value that triggered an `allowedValues` check). Apply appropriate access controls and retention policy to this file.

**Step 2 — see what the agent actually did.**

```bash
eunox stats          # per-tool allow/deny histogram from the signed tape
```

Everything your agent really called, with full arguments, signed — that visibility alone justifies the wiretap, and it is exactly the evidence the next step turns into policy.

**Step 3 — draft the manifest from the evidence.**

```bash
eunox suggest --output manifest.yaml   # draft entries grounded in observed usage
# review and tighten each entry (the draft describes what the agent did, not vetted policy)
eunox validate manifest.yaml
```

`suggest` reads the wiretap tape and proposes one entry per observed target — including `allowedValues` conditions built from the actual argument values it saw. The policy writes itself from evidence; you review and tighten it.

**Step 4 — enforce the reviewed manifest.** Wrap the **same** upstream with a config that points at it:

```yaml
# eunox.yaml
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: filesystem
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
    policy: ["manifest.yaml"]
```

```bash
eunox proxy --config eunox.yaml
```

Anything outside the manifest is now denied before it reaches the server, with a structured error to the host and a signed audit record. Keep tightening from there — a single new rule can be staged observe-only with per-entry `enforcement: audit` (see the [audit log section](#audit-log)) while the rest of the manifest keeps blocking.

**Prefer to start deny-all instead of observe-first?** `eunox init --upstream-url <url> --output manifest.yaml --config-output eunox.yaml` scaffolds a deny-all starter manifest (every live tool present but commented out) *and* a runnable config from the server's tool list — the same loop entered from the closed end: uncomment what the wiretap proved the agent needs.

**The hero demo — block credential exfiltration (Go only, no Docker).** An agent reads a secret, then a prompt injection tells it to POST the secret to an attacker. Each call is individually authorized; eunox blocks the *combination* with one `sequenceBlock` condition — the one attack no database role or API gateway can catch, because only the proxy remembers what the agent already did this session:

```bash
make -C demo trifecta   # builds the real binary, drives read_credentials ALLOW -> write_external DENY
```

It prints the ALLOW/DENY verdicts, the signed audit records, and a clean HMAC-chain verification. The persistent variant, `make -C demo trifecta-audit`, keeps the tape across runs (one HMAC chain spanning proxy restarts) and shows tampering with it — a rewritten verdict, a forged record — being caught live by `eunox audit-verify`. Walkthrough: [`demo/trifecta/`](./demo/trifecta/).

Prefer a runnable end-to-end demo with Docker? Prerequisites: Docker 24+, docker compose 2.20+, `curl`, `jq`.

```bash
git clone https://github.com/eunolabs/eunox.git
cd eunox
make -C demo up        # start mock MCP server + eunox proxy (~10 s)
make -C demo allow     # allowed: read_file /reports/q3.pdf
make -C demo deny      # denied:  write_file (not in manifest)
make -C demo audit     # live tamper-evident audit log
```

**No Docker, no Node** — with Go and the repo checked out, wrap the bundled mock
MCP server (`read_file`, `write_file`, `query_db`) instead of an npm package:

```bash
go build -o /tmp/eunox-mock ./demo/mock-mcp-server-stdio
eunox proxy --audit -- /tmp/eunox-mock   # point your MCP host here, then:
eunox stats
```

The full walkthrough — including JWT/IdP-issued capability claims — is in [`demo/README.md`](./demo/README.md).

---

## Install

**macOS / Linux (Homebrew)**

```bash
brew install eunolabs/tap/eunox
```

**Windows (winget)**

```bash
winget install eunolabs.eunox
```

**Docker**

```bash
docker pull ghcr.io/eunolabs/eunox:latest
```

**Debian / Ubuntu (`.deb`) · Fedora / RHEL (`.rpm`) · pre-built binaries**

Native packages and pre-built binaries for every supported platform are
attached to each [GitHub Release](https://github.com/eunolabs/eunox/releases/latest)
— pick the asset that matches your OS and architecture and install with
`dpkg -i`, `rpm -i`, or unpack the tarball.

Every release is signed with [Sigstore](https://www.sigstore.dev/) keyless
signing and ships with an SPDX SBOM per artifact. See
[SECURITY.md → Verifying a release](./SECURITY.md#verifying-a-release) for
the `cosign verify-blob` command (binaries) and `cosign verify` command
(Docker images).

---

## How it works

```
MCP host (Claude Desktop, LangChain, CrewAI, ...)
        │
        │  JSON-RPC  tools/call · resources/read · resources/subscribe
        │             prompts/get · sampling/createMessage
        │             tools/list · resources/list · prompts/list
        ▼
┌─────────────────────────────────────┐
│          eunox proxy                │
│                                     │
│  1. Parse method + arguments        │
│  2. Evaluate capability manifest    │
│     · AllowedValues, MaxCalls,      │
│       AllowedOperations, TimeWindow │
│     · Session-aware rate limits     │
│     · IdP JWT claims (optional)     │
│  3. Filter list responses           │
│     (tools/list, resources/list,    │
│      prompts/list)                  │
│  4. Write OCSF audit record         │
│     (HMAC-SHA256 signed)            │
└──────────┬──────────────────────────┘
           │
   ALLOW ──┼──► upstream MCP server
           │       local subprocess  or  remote HTTPS endpoint
   DENY ───┼──► structured JSON-RPC error returned to host
           │    (upstream is never called)
```

**Point eunox at your upstream(s) with a config file, then run one command:**

```yaml
# eunox.yaml — speak MCP over stdio to one local subprocess upstream
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: local
    transport: stdio              # spawn the upstream as a subprocess
    command: node
    args: ["./server.js"]
    policy: ["manifest.yaml"]
```

```bash
eunox proxy --config eunox.yaml
```

To front a **remote** server instead, give the upstream `transport: http` and an
`upstreamUrl`. To front **many** upstreams from one HTTP listener, set the
top-level `transport: http` — the gateway shape (see **Gateway mode** below).
`eunox init --upstream-url <url> --output manifest.yaml --config-output eunox.yaml`
scaffolds both files from a live server.

> **Remote HTTP upstreams do not service server-initiated requests.** eunox issues
> request/response calls and opens no inbound stream back to a remote upstream, so a
> server-initiated `roots/list`, `elicitation/create`, or `sampling/createMessage` it
> sends is never read or replied to. A manifest `system:sampling/createMessage` grant
> on such an upstream is refused at startup; otherwise the proxy prints a startup
> NOTICE naming the affected methods. Run the upstream as a `transport: stdio`
> (subprocess) upstream if it relies on server-initiated requests. See
> [`docs/conformance.md`](./docs/conformance.md) for the full transport matrix.

---

## Capability manifest

The manifest is a YAML file that declares exactly what the agent may call, read, subscribe to, and retrieve — and under what conditions. Absent entries are denied by default for every enforced MCP method.

```yaml
schemaVersion: "0.1"                # manifest grammar version (required)
name: my-agent
version: "0.1.0"

capabilities:
  - target: tool:read_file          # "tool:" prefix required
    actions: [call]
    conditions:
      - type: allowedValues
        argument: path
        values: ["/reports/*"]      # deny read_file outside /reports/

  - target: tool:query_db
    actions: [call]
    conditions:
      - type: maxCalls
        count: 5                    # at most 5 calls per session
        windowSeconds: 3600
      - type: allowedOperations
        argument: sql               # the tool parameter that carries the query
        operations: [SELECT]        # no INSERT / UPDATE / DELETE

  # write_file intentionally absent → denied by default
```

Validate without running:

```bash
eunox validate manifest.yaml
```

See the [Capability Manifest Specification](https://github.com/eunolabs/agent-capability-manifest/blob/main/SPEC.md) for the normative format definition — a protocol-neutral core with per-protocol bindings, of which the [MCP binding](https://github.com/eunolabs/agent-capability-manifest/blob/main/bindings/mcp.md) is the first — and [`docs/capability-manifest-guide.md`](./docs/capability-manifest-guide.md) for the full condition reference (11 built-in condition types — nine enforced directly by the stock binary, plus the `policy` and `custom` extension hooks that require wiring — and response directives like `redactFields`).

---

## Startup drift detection

A manifest is written against the tools an upstream exposed at the time. Servers change: a new release adds a tool, renames another, or alters an argument. When that happens, a manifest can silently **over-permit** (a new tool slips inside an existing glob) or carry a **dead reference** (an entry that no longer matches anything). Neither shows up until call time, if at all.

After the `initialize` handshake — once the live tool list is available — the proxy fetches `tools/list` from the upstream and compares it against the manifest, emitting structured warnings to stderr at session startup:

| Finding | Level | Meaning |
| ------- | ----- | ------- |
| **New tool matched by a glob** | `WARN` | A live tool that didn't exist when the manifest was written now falls inside a glob entry (`delete_*` matching a new `delete_all_records`) — a silent over-permission. Verify it's intentional before deploying. |
| **Manifest entry matches no live tool** | `WARN` | A `tool:` entry references a tool the upstream no longer exposes (removed or renamed) — a dead reference that will never fire. |
| **`serverVersion` pin not satisfied** | `WARN` | The upstream's reported version doesn't match the manifest's `serverVersion` pin (only checked when a pin is configured) — the server may have been updated under the manifest. |
| **`descriptionHash` pin not satisfied** | `WARN` | A live tool's description — **or any of its parameter descriptions** — doesn't match the `descriptionHash` pinned for it; the model-facing instruction text may have been altered to steer the model toward unintended calls (a poisoning attempt). **Always fatal**: aborts session establishment unconditionally, with or without `--strict-drift`. |
| **Pinned argument absent from live schema** | `WARN` | A manifest entry pins an argument name — the `argument` of a condition or a top-level `argumentSchema` property — that the tool's live `inputSchema` doesn't declare (a renamed parameter), so the pin may silently stop enforcing. Advisory only: not promoted by `--strict-drift`, since in enforce mode a missing argument already fails the condition closed at call time (in audit mode it is logged and forwarded). |
| **Structural schema drift (added/retyped parameter)** | `WARN` | The live `inputSchema` diverges structurally from a constraint's `argumentSchema`: a parameter appears that a closed schema (`additionalProperties: false`) didn't declare — a new, unreviewed argument — or a declared parameter changed type. (A *disappeared* parameter is the row above.) Promoted to fatal by `--strict-drift`. |
| **Live tool not covered by the manifest** | `INFO` | A live tool no manifest entry matches. Under allowlist semantics every call to it is denied in enforce mode (logged and forwarded in audit mode); informational only. |

The advisory check never blocks session establishment — warnings are informational and ingestable by log aggregators. Timing differs by transport: the stdio host runs the check inline, before forwarding any traffic, whereas the HTTP transport runs it in the background, so a client that issues a tool call immediately after `initialize` returns may do so before the warning is logged (the call is still policed by the manifest either way). If `tools/list` is unavailable the check is skipped — a single `WARN` records the skip — rather than blocking startup.

```
[eunox] WARN drift=fm1 tool="delete_all_records" resource="tool:delete_*" — new upstream tool matched by manifest glob; verify this is intentional before deploying
[eunox] WARN drift=fm2 resource="tool:query_db" — manifest entry matches no live upstream tool (tool removed or renamed?)
[eunox] WARN drift=fm3 resource="tool:read_file" tool="read_file" argument="path" — pinned argument not in live inputSchema; the pin may not enforce if the upstream renamed it
[eunox] INFO drift=uncovered tool="summarize_document" — not covered by manifest; no allowlist entry matches it (denied in enforce mode)
```

To **fail closed** on drift instead of warning, run with `--strict-drift` (or set `strictDrift: true` per upstream / under `defaults:` in the config): the over-permission, dead-reference, unsatisfied-`serverVersion`-pin, and structural-schema-drift findings become fatal errors that abort session startup — and, on the HTTP transport, the check then runs synchronously so startup is blocked until it completes. (A `descriptionHash` mismatch is the exception that always aborts startup, with or without the flag, since a poisoned description can steer the model even within the allowed tool set.) The absent-argument `WARN` and uncovered-tool `INFO` stay advisory even under `--strict-drift` — unlike a widened glob, neither is a silent over-permission: in enforce mode the uncovered tool is denied and the renamed argument fails its condition, while in audit mode both are evaluated and logged as configured. The flag is a launch-time global override that applies to every policed route; a route with no policy has nothing to check and is unaffected — if `--strict-drift` matches no policed route at all (for example under `--audit`), the proxy logs a warning that the flag had no effect.

```bash
eunox proxy --config eunox.yaml --strict-drift
```

`eunox validate <manifest.yaml> --live --upstream-url <url>` runs the same comparison out of band, so you can catch drift in CI before it reaches a running proxy.

---

## Audit log

Every decision — allow or deny — is appended to a local **OCSF-inspired JSONL audit log**. Each record is signed with **HMAC-SHA256** and linked to its predecessor in a hash chain, so not only modification but also deletion, reordering, or insertion of records is detectable after the fact.

|             | Default                                                                       | Override                                              |
| ----------- | ----------------------------------------------------------------------------- | ----------------------------------------------------- |
| Log file    | `~/.eunox/audit.jsonl`                                                         | `--audit-log <path>`                                  |
| Signing key | `~/.eunox/audit.key` (32-byte key, generated on first run, mode `0600`)       | `--audit-key-path <path>` or `EUNOX_AUDIT_KEY_PATH`   |
| Rotation    | rotates at 100 MiB → `audit.jsonl.<timestamp>`                                | `--audit-rotate-size <bytes>`                         |
| Retention   | keeps every rotated file by default                                           | `--audit-retain <n>` / `audit.retainRotated`          |

The signing key is created once and never silently overwritten: if the key file exists but is unreadable or corrupt, the proxy fails fast rather than re-keying and invalidating every prior record.

```bash
eunox stats           # per-tool allow/deny histogram from the log
eunox audit-verify  # re-verify the HMAC signature on every record
```

To capture a compliance tape **without enforcing** anything, set a route's `enforcement: audit`: policy is evaluated but enforced-method calls are forwarded rather than blocked, and each is recorded to the audit log (`tools/call` records also include the full argument map); `…/list` calls forward the full upstream catalog unfiltered and are recorded as enumeration events. No manifest is required. Set it under `defaults:` to observe every route at once.

`enforcement: audit` is also the **only** way to run a gateway route with no `policy:`. A route that has neither a `policy:` nor `enforcement: audit` is treated as a misconfiguration — not an intent to passthrough — and the gateway **fails closed at startup** with an error naming the route, rather than silently allowing every call on it unenforced. This surfaces a typo, a deleted policy file, or a half-applied rollout before any traffic flows. To run a route intentionally unpoliced, declare `enforcement: audit` to acknowledge the open (observe-only) posture.

For a middle ground between full enforcement and a whole route in `enforcement: audit`, mark an individual capability entry `enforcement: audit` to stage just that rule in observe mode — its would-be denials are logged and forwarded while the rest of the manifest keeps blocking. It never opens the allowlist, bypasses the kill switch, or downgrades a JWT-scope denial; see [`docs/capability-manifest-guide.md`](./docs/capability-manifest-guide.md).

---

## Operating in production

The HTTP transport spawns one upstream connection per client session and the
audit log grows as traffic flows, so a long-lived gateway needs a few bounds set.
All of these are off by default (so nothing changes for a quick local run) and
layer over the config file with a matching CLI flag.

| Concern | Control | Default | Set it with |
| ------- | ------- | ------- | ----------- |
| **Runaway sessions** — each session owns an upstream subprocess/connection; an unbounded client could spawn many. | Cap concurrent sessions; a new session past the cap gets `503` **before an upstream is spawned** (the slot is reserved across the whole handshake, so racing initializes cannot all spawn first). | **512** backstop (set `0` for unlimited, via either knob) | `listen.maxSessions` / `--max-sessions` |
| **Idle sessions pinning upstreams** — a session that goes silent holds its upstream open. | Reap a session after it has sent no request for N ms. A session holding an open SSE stream is spared the normal reaper, but only up to a hard ceiling (4× the idle window with no host request), after which it is reaped regardless so a silent SSE-only client cannot pin its upstream indefinitely. | no reaping | `listen.sessionIdleTimeoutMs` / `--session-idle-timeout` |
| **A hung upstream stalling a handler** | Per-call upstream deadline; on expiry the call returns `UPSTREAM_TIMEOUT`. | **30 s** (pass `0` to disable) | `defaults.upstreamTimeoutMs` / `--upstream-timeout` |
| **Audit log filling the disk** | Keep at most N rotated files; the oldest are deleted on rotation. | keep all | `audit.retainRotated` / `--audit-retain` |
| **An unprotected upstream slipping in** — a route with no `policy:` would allow every call. | The gateway (`transport: http`) refuses to start a policyless route; opt into observe-only with `enforcement: audit` to acknowledge. (A `stdio` host warns instead.) | fail closed (gateway) | built in |
| **A unique-key flood pinning heap** — the in-memory `maxCalls`/`sequenceBlock` counter holds one key per live `(session, tool)` pair. | Cap distinct counter keys; a call under a new key past the limit fails closed. Ignored with `--redis-addr` (Redis holds counter state off-heap with TTLs). | **1,000,000** (`0` disables) | `--max-call-counter-keys` |
| **Slow kill propagation after a Redis blip** | How often the Redis kill switch reconciles its local cache against Redis. Lower shortens the kill-propagation (and fail-closed denial) window; very low raises Redis load. Only affects `--redis-addr`. | **30 s** | `--killswitch-reconcile-interval` |
| **Shutdown hanging on an unresponsive upstream** | Graceful-shutdown budget before the upstream is `SIGKILL`ed. | **5 s** | `--shutdown-timeout` |

A single JSON-RPC message from either upstream is capped at **4 MiB** — a
subprocess upstream's stdout line and a remote HTTP upstream's response body
alike. A larger message (e.g. a `resources/read` returning more than 4 MiB) is
rejected rather than buffered without bound. This is a fixed safety limit, not a
tunable; chunk or paginate oversized resources at the upstream.

**Network exposure and upstream trust.** A handful of flags change who can reach
the proxy and how much it trusts the network around it. All are off by default
(the HTTP transport binds loopback-only); set them only behind a trusted
boundary.

| Flag | What it does | Default |
| ---- | ------------ | ------- |
| `--unsafe-bind-all` | **Required** to bind the HTTP transport to all interfaces instead of loopback. Off-loopback exposure lets remote clients (and `X-Forwarded-For` spoofers) reach the proxy directly; only set it behind a trusted network boundary with `listen.authToken` or JWT auth configured. | off (loopback only) |
| `--trust-forwarded-for` | Trust the `X-Forwarded-For` header for the client source IP that `ipRange` conditions match against — but only from a peer whose connecting address matches `listen.trustedProxyCIDRs` in the gateway config; a direct client outside that allowlist gets its own connection address instead, and an empty allowlist means the flag has no effect. Set `listen.trustedProxyCIDRs` to the trusted reverse proxy's real address(es), scoped as tightly as possible. With more than one proxy in front, also set `listen.trustedProxyHops` to the chain depth (default 1) so the client is read from the correct position in the chain. | off |
| `--upstream-auth-header` / `--upstream-tls-skip-verify` | In `--audit` wiretap mode, the auth header (`"Name: Value"`) sent to an `--upstream-url`, and skipping TLS verification of that upstream (development only). | unset / off |
| `--redis-password` / `--redis-tls` | AUTH password and TLS for the `--redis-addr` connection that holds shared call-counter and kill-switch state (available on both `proxy` and `kill`). Prefer the `EUNOX_REDIS_PASSWORD` env var over the flag — a password on the command line is world-readable in `/proc/<pid>/cmdline`; the flag takes precedence over the env var. | empty / off |
| `--session-id` | Pin the session ID instead of a random UUID (stdio transport; mainly for test/correlation). | random UUID |

**Health and metrics.** On the HTTP transport, two loopback-only endpoints sit
beside `/control/kill` (same on-host-only guard — never reachable off the box):

```bash
curl -s localhost:3000/healthz   # {"status":"ok"|"degraded", sessions, auditDropped, auditWriteFailed, auditMaintenanceStalled, killSwitchHealthy, ...}
curl -s localhost:3000/metrics   # Prometheus text: eunox_active_sessions, eunox_audit_dropped_records_total, eunox_audit_write_failures_total, eunox_audit_maintenance_stalled, …
```

`eunox_audit_dropped_records_total` and `eunox_audit_write_failures_total` are the
two audit-loss signals to alert on. The audit path is non-blocking, so it never
back-pressures enforcement; instead it counts loss. A non-zero **dropped** count
means the write queue could not keep up and records were discarded before the
drainer — a healthy file under load. A non-zero **write-failures** count means
records reached the drainer but could not be written to disk (full disk, EIO) —
the file itself is failing, and a persistent failure also makes the process exit
non-zero when the audit sink closes. Either way audit coverage is being lost —
page on it. `killSwitchHealthy` / `eunox_kill_switch_healthy` go to `0` when a
Redis kill-switch backend is degraded (see below).

`eunox_audit_maintenance_stalled` / `auditMaintenanceStalled` is a third,
different signal: `1` means size-triggered rotation or retention pruning has
stopped making progress — the log directory cannot be listed, or the oldest
rotated file cannot be deleted. **No records are lost**, so this deliberately
does not gate traffic the way the two counters above feed
`--require-audit=strict`. What it means is that `audit.rotateSizeBytes` and
`audit.retainRotated` are currently unenforced and the log will grow until the
underlying fault is fixed — at which point the volume fills, writes *do* start
failing, and strict mode denies everything. Alert on it as a disk-capacity
warning, not an audit-integrity one; `auditMaintenanceReason` on `/healthz`
names the file or directory to fix.

**Multiple instances need Redis.** The call-counter (`maxCalls`) and kill-switch
state are in-memory and **per-process** by default. Run more than one instance
behind a load balancer without `--redis-addr` and every `maxCalls` quota is
silently multiplied by your replica count and revocations do not propagate — the
proxy prints a startup notice when a policy uses `maxCalls` but no Redis is
configured. Point all instances at one Redis (`--redis-addr`) to share both.

> **The Redis kill switch fails closed during a Redis outage by default —
> monitor Redis health.** The kill switch is checked on the request hot path from
> a process-local cache that a background listener refreshes; it never makes a
> per-request Redis round-trip. The deliberate consequence is that while Redis is
> unreachable the proxy cannot learn about kills issued *during* the outage. By
> default it therefore **fails closed**: once a refresh fails, every request whose
> kill-switch state cannot be confirmed is denied (`KILL_SWITCH_ERROR`) until
> Redis health is reconfirmed (at the latest on the next reconcile tick), so an
> unconfirmable revocation is never bypassed. A kill already cached before the
> outage stays enforced throughout, and the manifest allowlist still fails closed
> regardless. If data-plane availability during a Redis partition matters more
> than guaranteed revocation, pass `--killswitch-fail-open` to serve the
> last-known state and allow traffic not already known to be killed instead.
> Either way, because the degraded window is exactly the window in which Redis is
> degraded, **alert on `killSwitchHealthy` / `eunox_kill_switch_healthy`
> (`0` = degraded) and run Redis with HA (Sentinel/cluster)**. Full rationale and
> alternatives: [ADR-0003](./docs/adr/0003-redis-killswitch-fail-open.md).

---

## Why not OPA or Envoy?

OPA and Envoy enforce access control at the HTTP layer — they see the HTTP request but have no concept of the session, what the agent has already done this session, or what individual tool arguments mean. Three failure modes they cannot address:

| Scenario                                                                                                                                                                   | OPA / Envoy                           | eunox                                                                    |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- | ---------------------------------------------------------------------------- |
| **Sequential credential exfiltration** — agent calls `read_credentials` then `write_to_external`. Each call is individually permitted; together they exfiltrate secrets.   | Both calls pass — no session context  | `sequenceBlock` condition: `write_to_external` is denied once `read_credentials` has run this session (the reverse order stays allowed) |
| **Parameter-dependent authorization at scale** — `read_file` allowed for `/reports/*`, blocked for `/internal/*`. Must be expressed per-parameter across every tool shape. | Complex Rego; rules multiply per tool | `allowedValues` condition: 3 lines per tool, all enforced by the same engine |
| **Task-lifecycle credential scope** — AWS STS minimum session is 15 minutes. A credential-reading tool should be callable once per task, not for the full token lifetime.  | Time-based expiry only (15 min floor) | `maxCalls: 1` blocks after the first use, regardless of token TTL            |

Runnable demos for all three scenarios: [`demo/opa-comparison/`](./demo/opa-comparison/).

### Why not Cedar as the policy grammar?

Cedar answers a different question. As an authorization language it shares the
manifest's best properties — deny-by-default (a request needs an explicit
`permit`), schema-validated so typos fail at authoring time, and built for
automated analysis. But Cedar is deliberately stateless: every decision is a
pure function of the request, the policy set, and the entity data passed in.
The manifest's decisive conditions are stateful, and several of its features
are not decisions at all.

The sequential-exfiltration rule from the table above illustrates the
boundary. In Cedar it is one honest line:

```cedar
forbid (principal, action == MCP::Action::"tools/call", resource == MCP::Tool::"write_external")
when { context.sessionToolHistory.contains("read_credentials") };
```

Perfectly expressible — but only because something outside Cedar watched every
call in the session, maintained `sessionToolHistory`, and injected it into the
request context. That something is the enforcement engine at the protocol
boundary. The predicate was never the hard part of `sequenceBlock`; the
session memory is. The same split applies to `maxCalls` (Cedar can compare a
count, not keep one), argument normalization (`allowedOperations` case
folding, `recipientDomain` extraction — Cedar has no string manipulation, by
design), and the features that are not authorization decisions at all:
`redactFields` response redaction, `*/list` discovery filtering, the kill
switch, and the signed audit tape.

So the two compose rather than compete. The manifest's `policy` condition
delegates a predicate to an external evaluator through the engine's
`PolicyEvaluator` seam — fail-closed when no evaluator is configured — while
the manifest remains the deny-by-default ceiling. If you need
identity-differentiated authorization (roles, groups, entity hierarchies) or
automated policy analysis across a large estate, that is what Cedar is
genuinely better at, and exactly what the delegation hook is for: Cedar
decides the principal-specific predicate; the manifest stays the boundary that
no delegation can expand.

### Why not authorization middleware inside the server?

If you wrote the MCP server yourself, in-process authorization middleware
(FastMCP's auth hooks and similar) is a good fit: add it to the framework,
decide who may call which tool, done. eunox solves the opposite problem — the servers you **didn't**
write and can't modify: a community package launched with `npx`, a vendor's
remote endpoint, an internal server owned by another team. A proxy needs no
code changes, no particular framework, and no particular language.

The enforcement depth differs too. Middleware checks are typically
name-level — *may this principal call `query_db`?* — but the failure modes
above turn on **arguments and session history**: `query_db` is fine until the
argument is `DROP TABLE`, `read_file` is fine until the path is
`/internal/key.pem`, and `read_credentials` is fine exactly once per task.
eunox evaluates per-parameter conditions and session-aware limits, and writes
every decision to a tamper-evident audit log — from outside the process it
polices, where a compromised or malicious server can't switch it off.

### Why not an agent-governance SDK?

A broader class of tools — Microsoft's
[Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
is the most prominent — governs agents from **inside the agent application**.
You add the library to your agent and it hooks the framework's extension points
(LangChain callbacks, CrewAI decorators, Semantic Kernel, and so on) to check
every tool call against a policy engine before it runs. The thesis is the same
as eunox's — deterministic, pre-execution enforcement instead of prompt-level
safety, with a tamper-evident audit trail — and the scope is wider: identity
(SPIFFE/DID/mTLS), sandboxing, and compliance mapping alongside policy.

The difference is the **enforcement point**. An SDK enforces where the agent
runs: it needs to be embedded in the application, it speaks that application's
language and framework, and it polices from inside the process it governs. eunox
enforces at the **MCP protocol boundary** — a separate process between host and
upstream. That makes it agnostic to how the agent is built (any language, any
framework, or none) and lets it police servers you **didn't** write and can't
instrument: a community package launched with `npx`, a vendor's remote endpoint,
an internal server owned by another team. Because it sits outside the process,
a compromised agent or server can't disable it, and it filters `*/list`
responses so a tool the policy forbids never appears to the model in the first
place.

The two are complementary as much as competing: govern your own agents with an
in-process SDK, and put eunox in front of the MCP servers those agents reach
that the SDK can't see inside. If you standardize on MCP, the protocol boundary
is the one chokepoint every agent shares regardless of how each one is built.

The policy formats differ in the same spirit. An SDK like AGT typically uses an
ordered **rule list** with a `default_action` and free-form condition
expressions (`condition: "tool_name == 'http_request'"`, `action: rate_limit`).
eunox's [capability manifest](docs/capability-manifest-guide.md) is a
**default-deny allowlist** of typed conditions bound to named arguments — what
isn't listed cannot run, and a misspelled key is a load-time error, not a
silently weaker policy:

| | Capability manifest (eunox) | Policy rules (typical agent SDK) |
| --- | --- | --- |
| Default posture | Deny by absence — no `default_action` knob | Configurable `default_action` (often allow) |
| Unit | `capability` keyed by typed MCP target (`tool:`/`resource:`/`prompt:`) | `rule` matched by a condition expression |
| Conditions | Typed, discriminated (`allowedValues`, `maxCalls`, `allowedOperations`, `sequenceBlock`) bound to a named argument | Free-form expression over `tool_name` / `action.args` |
| Grammar | Closed — unknown keys rejected fail-closed, `validate` catches typos | Expression errors surface at evaluation |
| Session state | `sequenceBlock` + per-session `maxCalls` windows | Usually per-call predicates; rate-limit action for state |
| Outcomes | allow / deny + directives (`redactFields`) + out-of-band kill | allow / deny / rate_limit / require_approval |

Same problem, opposite bias: the SDK rule list optimizes for expressiveness
across many frameworks; the manifest optimizes for auditability and fail-closed
safety at the MCP boundary, with built-in conditions for the argument and
session shapes MCP servers actually expose.

---

## Commands

| Command                                                                 | Description                                                  |
| ----------------------------------------------------------------------- | ------------------------------------------------------------ |
| `eunox proxy --config <eunox.yaml>`                                 | Start the proxy. The config's `transport` selects the host shape: `stdio` (one upstream over stdin/stdout) or `http` (gateway: many upstreams, one `/mcp/<name>` route each). Per-route `enforcement: audit` observes without blocking. |
| `eunox proxy --audit -- <command> [args...]`                        | **Zero-config wiretap.** Bridges stdin/stdout to a subprocess (or `--upstream-url <url>`) in audit mode — enforced-method calls forwarded and recorded; …/list calls forward the full upstream catalog unfiltered and are recorded as enumeration events. Use `eunox stats` to see what an allowlist would need. |
| `eunox validate <manifest.yaml>`                                    | Validate a capability manifest without running               |
| `eunox validate <manifest.yaml> --live --upstream-url <url>`        | Validate and diff the manifest against a running upstream's live tool set |
| `eunox init --upstream-url <url> [--config-output eunox.yaml]`      | Generate a deny-all starter manifest (and, with `--config-output`, a runnable config) from a live upstream's tool list |
| `eunox suggest [--output manifest.yaml]`                            | Generate a **draft** manifest from the audit log — one entry per observed target, with `allowedValues` conditions grounded in the argument values the agent actually used. Review and tighten before enforcing. |
| `eunox kill [--port N] [--host H] <session-id\|all>`                | Revoke one or all active sessions. POSTs to an HTTP proxy's loopback control endpoint by default — authenticated with the control token the proxy writes to `~/.eunox/control.token` (0600) at startup, which `kill` reads automatically (override with `--control-token` / `--control-token-path` / `EUNOX_CONTROL_TOKEN`). With `--redis-addr` it writes the kill to shared Redis state instead — the way to revoke a stdio proxy started with `--redis-addr`, and the fan-out switch across every instance on that Redis. A plain in-memory stdio proxy has no out-of-band kill: stop the process. |
| `eunox stats`                                                       | Print a denial histogram from the audit log                  |
| `eunox audit-verify`                                              | Verify HMAC-SHA256 signatures in the audit log               |
| `eunox doctor [--config <eunox.yaml>] [--live]`                    | Print a redacted support bundle (binary identity, config, manifests, audit tail) for bug reports. Nothing is uploaded. |
| `eunox version`                                                     | Print the binary version and build metadata. |

`eunox audit-verify` accepts `--request-id <id>` and `--since <RFC3339>` to
scope which records it reports. The full HMAC chain is always verified regardless —
these filters only narrow which records are counted and printed, not what is checked.

---

## MCP client integration

eunox is a **drop-in stdio wrapper**: wherever your MCP client launches a
server, prefix the launch command with `eunox proxy --audit --` (zero-config
wiretap) or `eunox proxy --config <eunox.yaml>` (enforcement). For example,
in Claude Desktop's `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem-wiretap": {
      "command": "eunox",
      "args": ["proxy", "--audit", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]
    },
    "filesystem-enforced": {
      "command": "eunox",
      "args": ["proxy", "--config", "/path/to/eunox.yaml"]
    }
  }
}
```

Start in wiretap mode to discover what the agent calls, then graduate to a
config-driven manifest. The same pattern works for **Claude Code, Cursor, VS
Code + GitHub Copilot (agent mode), Cline, Roo Code, Windsurf**, and any other
MCP host — only the JSON key differs. Step-by-step setup for each client, plus
the remote-HTTP-proxy mode, is in
[`docs/client-integration.md`](./docs/client-integration.md).

---

## Gateway mode — one proxy, many upstreams

Instead of running one proxy per MCP server, a single `eunox` process can
front **every** server a host talks to, each on its own `/mcp/<name>` route, all
writing to **one** tamper-evident audit tape. Upstreams (and their per-route
policies) are declared in a gateway config:

```yaml
# gateway.yaml
schemaVersion: "0.1"
listen: { bind: 127.0.0.1, port: 3000, authToken: ${EUNOX_GATEWAY_TOKEN} }
audit:  { log: ~/.eunox/audit.jsonl }
defaults: { enforcement: audit }
upstreams:
  - name: filesystem            # → POST /mcp/filesystem
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
    policy: ["./policies/filesystem.yaml"]
    expectVersion: "0.1.0"      # refuse to start if the manifest's version differs
  - name: stripe                # → POST /mcp/stripe
    transport: http
    upstreamUrl: https://mcp.stripe.com
    upstreamAuthHeader: "Authorization: Bearer ${STRIPE_KEY}"
    policy: ["./policies/stripe.yaml"]
```

```bash
eunox proxy --config gateway.yaml
```

Each upstream keeps its **own manifest with its own `version`** — policies stay
independently reviewable and independently versioned. `expectVersion` pins a
route to a reviewed version and the gateway **fails closed** on mismatch. Every
audit record is stamped with the `upstream`, `policy_version`, and a
`policy_sha256` digest, so the shared tape proves *which policy version* allowed
each call. Hosts that speak remote MCP connect by URL (`/mcp/<name>`); stdio-only
hosts attach through a small per-route bridge. Full setup is in
[`docs/client-integration.md`](./docs/client-integration.md#gateway-one-proxy-many-upstreams).

The config has a JSON Schema at
[`schemas/eunox-gateway-config.schema.json`](./schemas/eunox-gateway-config.schema.json)
for editor autocomplete and inline validation — point your editor at it with a
modeline (`# yaml-language-server: $schema=...`). Unknown keys are rejected at
load time, so a typo'd field fails fast instead of being silently ignored.

A gateway route with no `policy:` **fails closed at startup** — the gateway
refuses to start — unless it sets `enforcement: audit`, so an unprotected
upstream can't slip in unnoticed. Set `enforcement: audit` to run a route
intentionally unpoliced in observe-only mode (every call forwarded and logged,
none blocked). `expectVersion` pins a single manifest
file; merge a multi-file policy before pinning it. Secrets interpolate with
`${VAR}` into string values, substituted as literal data (never re-parsed as
YAML, so a `#` or `:` inside a token is used verbatim); a literal `$` — or a
reference to an unset variable — is left untouched, so a token or password
containing `$` survives expansion intact.

---

## Advanced: JWT / IdP-issued capability claims

eunox is an **MCP capability firewall**, not an authorization server. Your
IdP or OAuth AS handles authentication, consent, and token issuance; eunox
enforces fine-grained MCP capabilities on top of a validated token.

> **Experimental — opt-in.** The `mcp.capabilities` claim schema (JWT schema
> v0.2) is **experimental** and its shape may change before 1.0. Enforcement is
> **off by default**: pass `--jwt-experimental-capabilities` to enable the
> JWT-claim ∩ manifest capability intersection. With the flag unset, a token that
> carries `mcp.capabilities` is rejected (HTTP 401) rather than having its
> restriction silently dropped. The rest of JWT mode — signature, expiry, issuer,
> and audience verification, plus the identity claims (`sub`, `mcp.task_id`,
> `mcp.agent_id`) — is stable and always active, independent of this flag.

When `--jwks-uri` is set, every incoming request must carry a Bearer JWT issued
by your IdP. The proxy always validates the signature, expiry, issuer, and
audience, then (with `--jwt-experimental-capabilities`) intersects the token with
the route's manifest — a call is allowed only if **both** allow it. When that flag
is set and the token carries an `mcp.capabilities` claim, it acts as an exhaustive
allowlist that can only narrow the manifest (AND semantics); when the claim is
absent the token is identity-only and the manifest governs alone. Every enforcing
route has a manifest: JWT mode runs over the HTTP
transport, where a route with no `policy:` fails closed at startup unless it sets
`enforcement: audit` (above). That lone policy-less case is a wiretap — the JWT
decision is recorded in the audit log but every call is forwarded, not enforced.
See [`docs/conformance.md`](./docs/conformance.md#jwt-intersection-semantics)
for the exact semantics. One carve-out: server-initiated
`sampling/createMessage` originates from the upstream, so no client bearer
token is in scope — it is governed solely by the manifest's
`system:sampling/createMessage` opt-in, and token claims neither grant nor
restrict it (see the
[capability manifest guide § 2b](docs/capability-manifest-guide.md)).
JWT validation layers over an HTTP-transport config:

```bash
# gateway.yaml declares transport: http and the upstream(s) + policy.
eunox proxy \
  --config gateway.yaml \
  --jwks-uri https://idp.example.com/.well-known/jwks.json \
  --jwt-issuer https://idp.example.com \
  --jwt-audience eunox \
  --jwt-experimental-capabilities   # experimental; enables the mcp.capabilities intersection
```

Additional JWT/OAuth flags (all HTTP transport, all optional):

| Flag | Purpose | Default |
| ---- | ------- | ------- |
| `--jwt-experimental-capabilities` | Enable the **experimental** `mcp.capabilities` (JWT v0.2) claim intersection. Off by default: a token carrying `mcp.capabilities` is otherwise rejected (HTTP 401). Signature/issuer/audience/expiry validation and identity claims are unaffected. | off |
| `--jwt-leeway` | Clock-skew grace on `exp`/`nbf`/`iat` (e.g. `10s`); `0` requires `exp` strictly in the future. Smaller is safer. | **10 s** |
| `--jwt-allow-any-audience` | Accept tokens regardless of `aud` (disables audience pinning — not recommended). `--jwt-audience` is otherwise **required** with `--jwks-uri`. | off |
| `--jwt-allow-any-issuer` | Accept tokens regardless of `iss` (disables issuer pinning — not recommended). `--jwt-issuer` is otherwise **required** with `--jwks-uri`. | off |
| `--jwks-allow-insecure-http` | Permit a plaintext `http://` `--jwks-uri` to a non-loopback host (development only). | off |
| `--oauth-resource` | RFC 9728 resource-server URI published at `/.well-known/oauth-protected-resource` and in `WWW-Authenticate`. | unset |
| `--oauth-authorization-server` | Authorization-server URI in the RFC 9728 metadata (defaults to `--jwt-issuer`). | `--jwt-issuer` |

See the JWT mode walkthrough in [`demo/README.md`](./demo/README.md#step-3--jwt-mode-manifest--idp-claims).
For integration examples with Auth0, Okta, WorkOS, and Cloudflare Access, see
[`docs/conformance.md`](./docs/conformance.md#idp--as-integration-examples).

---

## Documentation

- 🚀 **Demo — first enforcement in 10 minutes** — [`demo/README.md`](./demo/README.md)
- 📚 **Reference policy library** (filesystem, GitHub, Postgres, SQLite, Slack, fetch, git, Brave Search, Puppeteer, memory, Stripe) — [`examples/policies/`](./examples/policies/)
- 🔌 **MCP client integration** (Claude Desktop, Cursor, VS Code/Copilot, Cline, Roo, Windsurf) — [`docs/client-integration.md`](./docs/client-integration.md)
- 📄 **Capability Manifest Specification** (protocol-neutral core; MCP is binding #1) — [SPEC.md](https://github.com/eunolabs/agent-capability-manifest/blob/main/SPEC.md) · [MCP binding](https://github.com/eunolabs/agent-capability-manifest/blob/main/bindings/mcp.md)
- 📋 **Capability manifest guide** — [`docs/capability-manifest-guide.md`](./docs/capability-manifest-guide.md)
- 🗺 **MCP 2025-11-25 conformance matrix** — what eunox enforces, what the IdP must provide, known gaps, Auth0/Okta/WorkOS/Cloudflare integration examples — [`docs/conformance.md`](./docs/conformance.md)
- 🛡 **Threat model** — [`docs/threat-model-mcp.md`](./docs/threat-model-mcp.md)
- 🔒 **Deployment hardening** (mandatory enforcement chokepoint: credential, network, and endpoint controls) — [`docs/deployment-hardening.md`](./docs/deployment-hardening.md)
- ⚡ **Benchmarks** — [`docs/benchmarks.md`](./docs/benchmarks.md)

---

## Contributing

PR workflow, commit conventions, DCO sign-off, and house style are in
[`CONTRIBUTING.md`](./CONTRIBUTING.md). Build, test, and lint with `make build` /
`make test` / `make lint`; `make check-license` verifies the Apache-2.0 headers.
Prerequisites (Go 1.26.5+, golangci-lint), repository layout, and the CI matrix
are in [`docs/repo-guide.md`](./docs/repo-guide.md). Vulnerability reports go
through [`SECURITY.md`](./SECURITY.md), not the public issue tracker.

---

## License

**Apache License 2.0** — free to use, embed, redistribute, and build on.
