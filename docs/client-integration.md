# Integrating eunox with MCP clients

`eunox` is a **drop-in stdio proxy**. Wherever an MCP client currently
launches an MCP server, you prefix the launch command with `eunox proxy`
— either in **wiretap mode** (`--audit -- <original command>`, no config) for
zero-config observation, or in **enforce mode** (`--config <eunox.yaml>`) for
policy enforcement. The proxy evaluates every request, then forwards or denies
it.

## Step 0: wiretap first

Before writing a policy, see what the agent actually calls. Take whatever
command the client runs today:

```jsonc
"command": "npx",
"args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
```

and front it with `eunox proxy --audit --`:

```jsonc
"command": "eunox",
"args": ["proxy", "--audit", "--",
         "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]
```

No config file, no manifest. Every enforced-method call is forwarded and recorded
to `~/.eunox/audit.jsonl`; `tools/call` records also include the full argument map. Use the agent for a session,
then inspect what it did:

```bash
eunox stats          # per-tool histogram, with BLOCKED / OBSERVED split
```

When you're ready to enforce, switch from wiretap to a config.

## The one pattern (enforce mode)

Move the original command into an eunox config (`transport: stdio` — eunox
speaks MCP to the client over stdin/stdout, and launches the upstream as a
subprocess):

```yaml
# /absolute/path/to/eunox.yaml
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: filesystem
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
    policy: ["/absolute/path/to/manifest.yaml"]
```

and point the client at eunox:

```jsonc
"command": "eunox",
"args": ["proxy", "--config", "/absolute/path/to/eunox.yaml"]
```

eunox launches and supervises the upstream declared in the config; the client
never talks to it directly. `eunox init --upstream-url <url> --output
manifest.yaml --config-output eunox.yaml` scaffolds both files from a live server.

> **Use absolute paths.** GUI clients (Claude Desktop, Cursor, Windsurf) launch
> servers with a minimal environment and an unpredictable working directory.
> Use the full path to both `eunox` (run `which eunox` /
> `where eunox`) and your `eunox.yaml`. On Windows, escape backslashes in JSON
> (`C:\\path\\eunox.yaml`). Paths inside the config (the upstream command, the
> manifest) should be absolute too.

### Two things that differ between clients

1. **Config file location** — where the JSON lives.
2. **The top-level key** — most clients use `mcpServers`; VS Code's native MCP
   support uses `servers`.

Both are tabulated per client below.

---

## Quick reference

| Client | Config file | Top-level key | Remote (HTTP/SSE) support |
| --- | --- | --- | --- |
| Claude Desktop | `claude_desktop_config.json` | `mcpServers` | config file is stdio only¹ |
| Claude Code | `.mcp.json` (project) or `claude mcp add` | `mcpServers` | yes |
| Cursor | `~/.cursor/mcp.json` or `.cursor/mcp.json` | `mcpServers` | yes (`url`) |
| VS Code + GitHub Copilot | `.vscode/mcp.json` or user `settings.json` | `servers` | yes (`type: http`) |
| Cline (VS Code) | `cline_mcp_settings.json` | `mcpServers` | yes |
| Roo Code (VS Code) | `mcp_settings.json` or `.roo/mcp.json` | `mcpServers` | yes |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` | yes (`serverUrl`) |

¹ Claude Desktop's **config file** launches stdio servers only. Two other paths
exist: install eunox as a one-click [Desktop Extension (.mcpb)](#desktop-extension-mcpb),
or, for a shared/team deployment, run an HTTP gateway and add it as a **custom
connector** by URL — see [Team / shared enforcement point](#team--shared-enforcement-point).

---

## Gateway: one proxy, many upstreams

The per-client sections above wrap **one** server per entry. If a host talks to
several MCP servers, you can instead run a **single gateway process** that fronts
all of them — each on its own `/mcp/<name>` route, all sharing one audit tape —
and point each client entry at a URL.

Declare the upstreams (and their per-route policies) in a gateway config:

```yaml
# gateway.yaml
schemaVersion: "0.1"                  # gateway-config grammar version (required)
listen:
  bind: 127.0.0.1
  port: 3000
  authToken: ${EUNOX_GATEWAY_TOKEN}   # optional bearer required on incoming requests
  allowedOrigins: []                  # extra browser origins allowed past the DNS-rebinding guard (loopback + bind host are always allowed)
audit:
  log: ~/.eunox/audit.jsonl           # one shared, signed tape for every route
defaults:
  enforcement: audit                  # capture everything, enforce nothing (per route override below)
upstreams:
  - name: filesystem                  # → POST /mcp/filesystem
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
    policy: ["./policies/filesystem.yaml"]
    expectVersion: "0.1.0"            # fail closed if the manifest's version differs
  - name: stripe                      # → POST /mcp/stripe
    transport: http
    upstreamUrl: https://mcp.stripe.com
    upstreamAuthHeader: "Authorization: Bearer ${STRIPE_KEY}"
    policy: ["./policies/stripe.yaml"]
    protocolVersion: auto             # auto (default) | "2025-11-25" | "2026-07-28"
```

```bash
eunox proxy --config gateway.yaml
```

> **Connection wiring lives in the config; policy stays in the per-route
> manifests.** Each upstream keeps its own manifest with its own `version`, so
> policies are independently reviewable and versioned. `expectVersion` pins a
> route to a reviewed version of a **single** manifest file; the gateway refuses
> to start on a version mismatch — or if `expectVersion` is set on a route that
> merges several policy files, since the pin would silently track only the first.

> **Protocol revision per upstream.** `protocolVersion` selects how eunox OPENS
> that upstream's leg — `initialize` for `auto` and `2025-11-25`,
> `server/discover` for `2026-07-28` — and with it the version header its later
> requests carry and whether eunox's own requests declare a revision in `_meta`.
> The upstream's handshake answer is then checked against the pin rather than
> allowed to override it. It is per upstream, not per gateway, because upstreams
> migrate on independent schedules — and it is only the *upstream* leg: the
> revision each host request is decided under is negotiated from that request's
> own context (see
> [conformance.md](conformance.md#per-revision-method-disposition)). A value this
> build does not speak is refused at startup, not at the first request.
>
> Pinning `2026-07-28` makes this route a **matched pair only for a host that
> declares the same revision**; a 2025-11-25 host in front of it has its
> forwarding methods refused `UNSUPPORTED_PROTOCOL_VERSION` (-32022), because
> translating a mismatched pair is not implemented. `auto` is unchanged from
> earlier releases, byte for byte.

> **Editor support.** A JSON Schema for this config lives at
> [`schemas/eunox-gateway-config.schema.json`](../schemas/eunox-gateway-config.schema.json).
> Add a modeline to the top of your `gateway.yaml` for autocomplete and inline
> validation:
> `# yaml-language-server: $schema=/abs/path/to/schemas/eunox-gateway-config.schema.json`
> (a relative path works too). Unknown keys are rejected when the gateway loads
> the config, mirroring the schema's `additionalProperties: false`.

> **Secrets and open routes.** `${VAR}` / `$VAR` references are expanded from the
> environment into the parsed string values (tokens, auth headers), so secrets need
> not be committed. Which spellings count is a property of the FIELD: `${VAR}` is a
> reference everywhere, while the bare `$VAR` form is a reference everywhere *except*
> a stdio upstream's `command` and `args` and the query/fragment of an `upstreamUrl`
> — text that is passed verbatim to another program or to an API that gives a bare
> `$` its own meaning (OData's `?$filter=`, a JSONPath `$.`, a regex `$anchor`). There
> a bare `$word` is left exactly as written, so `command: "$SERVER_BIN"` runs a file
> literally named `$SERVER_BIN`; write `${SERVER_BIN}` to substitute. The same
> per-field rule decides what the startup guard treats as an unresolved reference, so
> the two never disagree. The value is substituted as literal data — never re-interpreted
> as YAML — so a secret containing a `#`, `:`, or other YAML metacharacter is used
> verbatim instead of silently truncating or blanking the field. A reference to an
> unset variable is left untouched — never blanked. A `$` followed by anything other
> than a letter, `_`, `{`, or `$` is already literal (`$-`, `$5`, a trailing `$`), and
> **`$$` is the escape for a literal `$`**: write `pa$$word` to mean the eight
> characters `pa$word`. Escaping consumes both `$` characters, so the identifier after
> it is *not* expanded.
>
> *Migration:* `$$` previously had no special meaning, so `pa$$word` expanded its
> second `$word` whenever an unrelated variable named `word` happened to be set —
> silently substituting a value you never chose into a credential. If a config value
> of yours contains a literal `$$`, double each one (`$$` becomes `$$$$`); if it
> contained `$name` and relied on that variable being unset, escape it as `$$name`.
>
> Separately: a gateway route with **no** `policy:`
> **fails closed at startup** — the gateway refuses to start — unless it runs in
> `enforcement: audit` mode, where allow-and-forward (observe-only) is your
> declared posture.

### Wiring clients to the gateway

**Hosts with remote MCP support** (Claude Code, Cursor, VS Code/Copilot, Cline,
Roo Code, Windsurf) connect by URL — one entry per route:

```json
{
  "mcpServers": {
    "filesystem": { "url": "http://127.0.0.1:3000/mcp/filesystem" },
    "stripe":     { "url": "http://127.0.0.1:3000/mcp/stripe" }
  }
}
```

(VS Code/Copilot uses `"servers"` with `"type": "http"`; Cursor uses `"url"`;
Windsurf uses `"serverUrl"` — same per-client differences as the table above.)

**Stdio-only hosts** (Claude Desktop) can't take a URL directly — they launch a
subprocess and speak over its stdin/stdout. Attach each route through a small
stdio↔HTTP bridge, [`mcp-remote`](https://www.npmjs.com/package/mcp-remote), one
host entry per route:

1. **Start the gateway** (from the `gateway.yaml` above), bound to loopback for a
   local, single-user setup:

   ```bash
   eunox proxy --config gateway.yaml      # serves http://127.0.0.1:3000/mcp/<name>
   ```

2. **Add one bridged entry per route** to the host's MCP config — each runs
   `mcp-remote` against that route's URL:

   ```json
   {
     "mcpServers": {
       "filesystem": {
         "command": "npx",
         "args": ["-y", "mcp-remote", "http://127.0.0.1:3000/mcp/filesystem"]
       },
       "stripe": {
         "command": "npx",
         "args": ["-y", "mcp-remote", "http://127.0.0.1:3000/mcp/stripe"]
       }
     }
   }
   ```

   The gateway exposes each upstream as its own `/mcp/<name>` endpoint, so there is
   **one bridge per route** — there is no single combined entry.

3. **If the gateway sets `listen.authToken`,** pass it as an `Authorization: Bearer`
   header on each bridged route (the credential the gateway checks):

   ```json
   "args": [
     "-y", "mcp-remote", "http://127.0.0.1:3000/mcp/filesystem",
     "--header", "Authorization: Bearer ${EUNOX_GATEWAY_TOKEN}"
   ]
   ```

   Set `EUNOX_GATEWAY_TOKEN` in that entry's `env`. If your host doesn't expand
   `${VAR}` inside `args`, inline the literal token or use the host's own secret
   mechanism.

4. **Restart the host and verify** — trigger a tool call from the agent, then read
   the shared tape:

   ```bash
   eunox stats            # allow/deny counts, split by upstream
   eunox audit-verify     # HMAC chain intact
   ```

   Every record carries its `upstream` route name, so the one tape shows the
   agent's activity across all bridged servers.

A shared, always-on gateway has to be HTTP — a single stdio process serves only one
client (one stdin/stdout pair), so multi-client sharing requires HTTP.

> **Local vs. team.** The `mcp-remote` bridge above is for a gateway on the **same
> machine** as the host (loopback, no public exposure). To make a gateway a
> **team-wide** enforcement point that Claude Desktop / Claude.ai reach as a
> **custom connector** by URL — no bridge — see
> [Team / shared enforcement point](#team--shared-enforcement-point); that path
> needs a public HTTPS URL and incoming auth.

### What lands in the audit log

Every record across all routes is written to the one configured `audit.jsonl`
and carries an `upstream` (the route name), the in-force `policy_version`, and a
`policy_sha256` digest — so the shared, HMAC-signed tape proves *which policy
version of which upstream* allowed or denied each call. Inspect it the usual way:
`eunox stats`, `eunox audit-verify`, or `jq . ~/.eunox/audit.jsonl`.

`eunox stats` splits denials into two tables: **BLOCKED DENIALS** (enforced
— the request was rejected) and **OBSERVED DENIALS** (audit mode — the request
was forwarded; the verdict is recorded but was not enforced). When you stage an
allowlist by setting `enforcement: audit` and reading the OBSERVED table, you
see exactly what would be blocked once you flip the route to `enforce`.

> **Local stdio upstreams need their runtime where the gateway runs.** A
> `transport: stdio` route launches its `command` as a subprocess of the gateway
> process, so `npx`/`uvx`/`python` must be present there (this matters when the
> gateway runs in a container). Remote `transport: http` upstreams have no such
> requirement.

---

## Team / shared enforcement point

The gateway above can run as a **central, always-on policy-enforcement point**
for a whole team: every host connects to the same eunox URL, every call across
every client is checked against the same per-route policy, and every decision
lands on **one shared, HMAC-signed audit tape**. Hosts with native remote MCP
(Claude Code, Cursor, VS Code/Copilot, Cline, Roo Code, Windsurf) point at the
URL directly; **Claude Desktop and Claude.ai** reach it as a **custom connector**.

> **Where Claude connects from.** When you add a custom connector, Claude
> reaches the URL **from Anthropic's cloud infrastructure**, not from your
> laptop — so the gateway must be reachable over the **public internet** at a
> stable **HTTPS** URL. A `127.0.0.1` gateway will not work as a custom
> connector (use the [`mcp-remote` bridge](#wiring-clients-to-the-gateway) for a
> purely local gateway instead). Because the gateway becomes internet-facing, it
> is now the trust boundary: incoming auth (below) is **mandatory**, not
> optional.

### 1. Declare the routes

Use the same gateway config as above (`transport: http`, one upstream per route,
a per-route `policy:`, and a single shared `audit.log`). Each route is published
at `/mcp/<name>`.

### 2. Bind beyond loopback

By default the gateway binds `127.0.0.1`. To serve other machines, set a routable
bind address **and** pass the explicit guardrail flag — eunox refuses a
non-loopback bind without it:

```yaml
# gateway.yaml
schemaVersion: "0.1"
transport: http
listen:
  bind: 0.0.0.0                       # listen on all interfaces (requires --unsafe-bind-all)
  port: 8080
  authToken: ${EUNOX_GATEWAY_TOKEN}   # bearer required on every incoming request
  allowedOrigins: []                  # add browser origins past the DNS-rebinding guard if needed
audit:
  log: /var/lib/eunox/audit.jsonl     # one shared, signed tape for every route
upstreams:
  - name: stripe                      # → /mcp/stripe
    transport: http
    upstreamUrl: https://mcp.stripe.com
    upstreamAuthHeader: "Authorization: Bearer ${STRIPE_KEY}"
    policy: ["/etc/eunox/policies/stripe.yaml"]
```

```bash
eunox proxy --config gateway.yaml --unsafe-bind-all
```

Prefer to keep eunox on loopback and bind only the reverse proxy to the network?
That works too — terminate TLS in front (next step) and proxy to `127.0.0.1:8080`;
then you do not need `--unsafe-bind-all`.

### 3. Terminate TLS in front

eunox speaks **plain HTTP** and does not terminate TLS itself. Put a reverse
proxy or load balancer (nginx, Caddy, Cloudflare, an ALB, …) in front and serve
a public certificate, so clients reach e.g. `https://eunox.example.com/mcp/stripe`.
Never expose the gateway to the internet without TLS — the bearer token and
every request would otherwise travel in clear text.

### 4. Require auth on incoming requests

The gateway is internet-facing, so authenticate every caller — pick one:

- **Shared bearer token** — set `listen.authToken` (above). Every request must
  carry `Authorization: Bearer <token>`. Simplest; one secret for the whole team.
- **IdP-issued JWTs** — validate per-identity tokens from your IdP with
  `--jwks-uri https://idp.example.com/.well-known/jwks.json` plus the
  fail-closed pins `--jwt-issuer` and `--jwt-audience`. This anchors each session
  to a verified identity in the audit log, and (with the experimental
  `--jwt-experimental-capabilities` flag) lets a token further *restrict* — never
  expand — what the manifest already allows. See
  [Advanced: JWT / IdP-issued capability claims](../README.md#advanced-jwt--idp-issued-capability-claims)
  and the [conformance matrix](./conformance.md).

> Firewalling the edge to Anthropic's published IP ranges is a reasonable extra
> layer, but it is **not** a substitute for `authToken`/JWT — keep the token in
> force even behind an IP allowlist.

### 5. Add it to Claude as a custom connector

In **Claude Desktop** or **Claude.ai**: **Settings → Connectors → Add custom
connector**, then paste the per-route URL (`https://eunox.example.com/mcp/stripe`)
and supply the bearer token / complete the OAuth flow the connector requires. Add
one connector per route. Hosts with native remote MCP instead use their URL form
from the [table above](#quick-reference) (`url` / `serverUrl` / `type: http`).

### 6. Scale out and revoke across instances

Behind a load balancer the gateway runs as **multiple instances**, so call-count
state and the kill switch must be shared rather than per-process. Point every
instance at one Redis:

```bash
eunox proxy --config gateway.yaml --unsafe-bind-all --redis-addr redis.internal:6379
```

`maxCalls` budgets and revocations are then consistent across the fleet, and a
single command fans a kill out to **every** instance on that Redis:

```bash
eunox kill --redis-addr redis.internal:6379 all             # revoke every live session
eunox kill --redis-addr redis.internal:6379 <session-id>    # revoke one
eunox kill --redis-addr redis.internal:6379 --revive <id>   # lift a revocation
```

(A single-instance gateway can instead use the loopback `/control/kill`
endpoint — `eunox kill --port 8080 all` — without Redis; see
[Revoking a session](#revoking-a-session-kill-switch).)

### What the team gets

- **One policy surface** — each upstream's manifest is independently versioned
  and reviewable; `expectVersion` pins a route to a reviewed manifest version.
- **One audit tape** — every record carries the route name, `policy_version`,
  and `policy_sha256`, so the shared signed log proves *which policy version of
  which upstream* allowed or denied each call. Inspect with `eunox stats`;
  verify the chain with `eunox audit-verify`.
- **Central revocation** — pull one session, or all, across the fleet from a
  single command.

---

## Claude Desktop

Two local install paths: hand-edit the config file (below), or install the
signed **Desktop Extension** for a one-click setup with no JSON
([next subsection](#desktop-extension-mcpb)). For a shared team gateway reached
by URL, see [Team / shared enforcement point](#team--shared-enforcement-point).

### Config file

Config file:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

Edit it directly, or use **Settings → Developer → Edit Config**.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "eunox",
      "args": ["proxy", "--config", "/path/to/eunox.yaml"]
    }
  }
}
```

Fully quit and reopen Claude Desktop after editing. The tools surfaced to the
model are already filtered by your manifest (`tools/list` is filtered to
permitted entries).

### Desktop Extension (.mcpb)

A **Desktop Extension** is a signed `.mcpb` bundle that ships the `eunox`
binary and registers it with Claude Desktop through the UI — no
`claude_desktop_config.json` editing. eunox is a single static binary, so it
packs as a `binary`-type bundle (one per platform).

1. **Download** the bundle for your platform from the
   [latest release](https://github.com/eunolabs/eunox/releases/latest):
   `eunox_<version>_<os>_<arch>.mcpb` — macOS is `darwin_arm64`, Windows is
   `windows_amd64` / `windows_arm64`, Linux is `linux_amd64` / `linux_arm64`.

2. **(Recommended) verify** the bundle exactly like any other release artifact —
   the `.mcpb` hashes are in the release's single `checksums.txt`, covered by the
   one Sigstore signature over it:

   ```bash
   cosign verify-blob \
     --certificate-identity-regexp "https://github.com/eunolabs/eunox/.*" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     --bundle checksums.txt.sigstore.json \
     checksums.txt
   sha256sum -c checksums.txt --ignore-missing
   ```

   Each bundle also ships an SPDX SBOM (`<bundle>.mcpb.sbom.json`) and a SLSA
   build-provenance attestation:
   `gh attestation verify eunox_<version>_<os>_<arch>.mcpb --repo eunolabs/eunox`.

3. **Install:** in Claude Desktop, **Settings → Extensions → Advanced settings →
   Install Extension…** and select the `.mcpb`.

4. **Configure:** when prompted, set **eunox config (eunox.yaml)** to the
   absolute path of your config — point it at **your `eunox.yaml`, not the
   `.mcpb` bundle you just downloaded.** If you don't have a config yet,
   scaffold one from a live server first, then select the generated
   `eunox.yaml`:

   ```bash
   eunox init --upstream-url <url> --output manifest.yaml --config-output eunox.yaml
   ```

   > **Don't select the `.mcpb` here.** A `.mcpb` is a binary archive, not a
   > config. Pointing the config field at it makes eunox try to parse the bundle
   > as YAML and fail closed at startup (it reports the file "looks like a ZIP
   > archive … not a text config"), so the extension serves no tools.

   **Just want to try it without writing a policy?** Copy
   [`examples/eunox.example.yaml`](../examples/eunox.example.yaml), edit the
   upstream, and point the config field at your copy. It starts in audit
   (observe-only) mode — every call eunox can route is forwarded and logged, and
   policy blocks nothing — so no manifest is required to begin; inspect what ran
   with `eunox stats`, then add a `policy:` and switch to `enforce` when ready.
   (See [What observe mode does *not*
   downgrade](#what-observe-mode-does-not-downgrade) for the two things that
   still refuse.)

The extension launches eunox in enforce mode (`proxy --config <your eunox.yaml>`),
so the tool list Claude sees is already filtered by your manifest. As with the
config-file path, a `transport: stdio` upstream is launched as a subprocess, so
its runtime (`npx` / `uvx` / `python`) must be reachable on PATH in Claude
Desktop's launch environment — use an absolute command path in the config, or a
`transport: http` upstream, if the upstream fails to start.

> **Audit-log path.** eunox writes its audit log to `~/.eunox/audit.jsonl` by
> default. If that location is not writable in Claude Desktop's launch
> environment, eunox fails closed and the extension won't serve tools — set
> `audit.log` to an absolute, writable path in your `eunox.yaml`.

---

## Claude Code

Add the wrapped server with the CLI (recommended):

```bash
claude mcp add filesystem -- eunox proxy --config /path/to/eunox.yaml
```

Or commit a project-scoped `.mcp.json` at the repo root so the whole team picks
it up:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "eunox",
      "args": ["proxy", "--config", "./eunox.yaml"]
    }
  }
}
```

Run `claude mcp list` to confirm the server is connected.

---

## Cursor

- **Global (all projects):** `~/.cursor/mcp.json`
- **Project:** `.cursor/mcp.json` in the repo root

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "eunox",
      "args": ["proxy", "--config", "/path/to/eunox.yaml"]
    }
  }
}
```

Open **Settings → MCP** and confirm the server shows a green dot. If you run
eunox as a shared HTTP proxy instead, use the remote form:

```json
{
  "mcpServers": {
    "team-proxy": { "url": "https://eunox.internal.example.com/mcp" }
  }
}
```

---

## VS Code + GitHub Copilot (agent mode)

GitHub Copilot's **agent mode** consumes MCP servers through VS Code's native
MCP support. Note the key is `servers`, not `mcpServers`, and each entry
declares a `type`.

- **Workspace:** `.vscode/mcp.json`
- **User (all workspaces):** run the **MCP: Open User Configuration** command from the Command Palette — it opens a user-level `mcp.json` with the same `servers` schema.

`.vscode/mcp.json`:

```json
{
  "servers": {
    "filesystem": {
      "type": "stdio",
      "command": "eunox",
      "args": ["proxy", "--config", "${workspaceFolder}/eunox.yaml"]
    }
  }
}
```

`"type": "stdio"` is the default and may be omitted for command-based servers;
remote servers use `"type": "http"` with a `"url"`.

Enable MCP discovery if it is off (`"chat.mcp.discovery.enabled": true`), then
open the Copilot Chat view, switch to **Agent** mode, and click the tools icon
to confirm eunox's filtered tool list appears. For a remote eunox HTTP proxy,
use `"type": "http"` with a `"url"`.

> The **Cline** and **Roo Code** extensions are separate VS Code plugins with
> their own config — see the next two sections. They do **not** read
> `.vscode/mcp.json`.

---

## Cline (VS Code extension)

Open the Cline panel → **MCP Servers** icon → **Configure MCP Servers**. This
opens `cline_mcp_settings.json` (stored in the extension's global storage under
`saoudrizwan.claude-dev/settings/`).

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "eunox",
      "args": ["proxy", "--config", "/path/to/eunox.yaml"]
    }
  }
}
```

Cline reloads MCP servers when the file is saved.

---

## Roo Code (VS Code extension)

Roo Code (a Cline fork) supports both global and project scopes:

- **Global:** **MCP Servers → Edit Global MCP** → `mcp_settings.json`
- **Project:** `.roo/mcp.json` in the repo root

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "eunox",
      "args": ["proxy", "--config", "/path/to/eunox.yaml"]
    }
  }
}
```

---

## Windsurf (Codeium)

Open **Windsurf Settings → Cascade → MCP Servers → Manage / View raw config**,
or edit `~/.codeium/windsurf/mcp_config.json` directly.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "eunox",
      "args": ["proxy", "--config", "/path/to/eunox.yaml"]
    }
  }
}
```

Click **Refresh** in the MCP panel after saving. For a remote eunox HTTP proxy,
Windsurf uses `"serverUrl"` instead of `command`/`args`.

---

## Any other MCP client

Almost every MCP host (LangChain, CrewAI, LlamaIndex, Goose, custom SDK hosts,
…) launches stdio servers with the same `command` + `args` shape. The pattern
is identical: set the command to `eunox` and the args to
`["proxy", "--config", "/path/to/eunox.yaml"]`.

If a client only supports **remote** servers over HTTP/SSE, run eunox as an
HTTP gateway (top-level `transport: http`) and hand the client its URL:

```yaml
# gateway.yaml
schemaVersion: "0.1"
transport: http
listen: { bind: 127.0.0.1, port: 8080 }
upstreams:
  - name: example
    transport: http
    upstreamUrl: https://mcp.example.com
    upstreamAuthHeader: "Authorization: Bearer ${UPSTREAM_TOKEN}"
    policy: ["/path/to/manifest.yaml"]
```

```bash
eunox proxy --config gateway.yaml
```

The client then connects to `http://localhost:8080/mcp/example` (or your
published URL). Require a static Bearer token from incoming hosts with
`listen.authToken`, or validate IdP-issued JWTs with `--jwks-uri`. To expose it
beyond localhost, set `listen.bind` to a non-loopback address (which additionally
requires the `--unsafe-bind-all` flag) and terminate TLS in front of it.
This mode also enables IdP-issued capability claims, which are experimental and
require the `--jwt-experimental-capabilities` flag (signature and identity-claim
verification do not) — see
[Advanced: JWT / IdP-issued capability claims](../README.md#advanced-jwt--idp-issued-capability-claims)
and the [demo walkthrough](../demo/README.md#step-3--jwt-mode-manifest--idp-claims).

---

## Verifying enforcement is live

Regardless of client, confirm the proxy is actually in the path:

1. **Tool list is filtered** — only tools your manifest permits should appear in
   the client's tool picker. A tool absent from the manifest should not show up.
2. **A denied call returns a structured error** — e.g. ask the agent to call a
   tool the manifest forbids; you should get an `AUTHORIZATION_FAILED` /
   `CONDITION_FAILED` error, not a result.
3. **The audit log grows** — every decision is written to the OCSF audit log.
   Tail it or run `eunox stats` to see per-tool counts, and
   `eunox audit-verify` to verify the HMAC chain.

If tools appear but nothing is denied, the client is almost certainly launching
the upstream directly — re-check that `command` is `eunox` and that
`--config` points at your `eunox.yaml`.

---

## Revoking a session (kill switch)

`eunox kill <session-id|all>` revokes a live session. Which transport it
uses depends on how the proxy you want to stop shares its kill-switch state:

| Proxy shape | How to revoke |
| --- | --- |
| HTTP proxy / gateway (`transport: http`) | `eunox kill --port <N> all` — POSTs to the loopback `/control/kill` endpoint. |
| stdio proxy started with `--redis-addr` | `eunox kill --redis-addr <host:port> all` — writes the kill straight to the shared Redis state the proxy reads; the same command fans a revocation out to every instance on that Redis. |
| stdio proxy with the default in-memory switch | No out-of-band channel — it is a single process wrapping one upstream, so stop that process (the client's "disconnect", or kill the `eunox` PID). |

Most desktop-client setups in this doc are the third shape (one stdio proxy per
server): the lifecycle is the client's, so there is nothing to revoke remotely.
Reach for `--redis-addr` only when you run a shared, restart-surviving
deployment and need to pull one session (or all) without taking the proxy down.

**The kill switch stops every route, including wiretap.** A policyless route
running in `enforcement: audit` (a wiretap: forward-and-log, no policy) still
forwards every call by default, but a global (`kill all`) or per-session kill
hard-blocks it just like a policed route — the wiretap decision point is wired to
the shared kill switch. This makes a wiretap route consistent with
audit-mode-with-policy, which already hard-blocks kill-switch denials. There is
no partial-coverage caveat to track: the kill response carries `{"ok":true,
"killed":<target>}` with no `wiretap_routes_unaffected` field.

The same holds for a single-upstream **stdio host** running in `--audit`
(wiretap) mode: it builds its decision point through the same path, so a kill
reaching it — for stdio that means the `--redis-addr` row above — hard-blocks the
wiretap session too. A stdio proxy on the default in-memory switch has no
out-of-band kill channel (stop the process), so this only changes behavior for a
`--redis-addr` deployment.

### What observe mode does *not* downgrade

Observe mode downgrades a **policy verdict**: a call policy would deny is
forwarded, and the would-be denial is recorded as an OBSERVED denial. A message
eunox cannot **route** has no verdict to downgrade, so it is still refused — in
`enforcement: audit` and under `--audit` alike:

| Still refused in observe mode | Code | Why it is not downgraded |
| --- | --- | --- |
| The kill switch | `KILL_SWITCH` | An emergency stop that a mode flag could soften would not be one. |
| A method absent from the MCP revision the host negotiated | `UNROUTABLE_METHOD` | The revision's routing table holds no handler for it; forwarding it would be inventing a route, not observing one. |
| A method this build dispatches under no revision | `UNROUTABLE_METHOD` | Same — the fail-closed default, unchanged since before revision scoping. Covers a method nobody has heard of and one the negotiated revision mandates that eunox has not implemented yet. |
| A method sent in a framing its revision does not dispatch | `UNROUTABLE_METHOD` | A notification-only method sent as a request, or a locally-answered one sent as a notification. |
| An *enforced* method sent in notification framing | `INVALID_REQUEST` | Forwarding it verbatim would bypass both the decision and the record. Refused separately, and it carries no marker. |
| A protocol revision that cannot be established, or that disagrees with the context it arrived in | `UNSUPPORTED_PROTOCOL_VERSION` | There is no revision to route by; picking one would be a guess, and each way of guessing contradicts either the declaration or the leg eunox already opened. |

The routing refusals — the three `UNROUTABLE_METHOD` rows above, and only
those — carry a `details._eunox_unroutable` object naming `reason` and the
`revision` whose tables were consulted:

| `reason` | Meaning |
| --- | --- |
| `unknown_method` | This build dispatches the method under no revision — it is unknown, or it belongs to the negotiated revision and is not implemented yet. |
| `removed_in_revision` | The build dispatches it under some revision, but not the one the host negotiated. |
| `framing_unmapped` | The method exists in the host's revision, but not in the framing it arrived in (a notification-only method sent as a request, or the reverse). |

`UNROUTABLE_METHOD` is a code of its own rather than the `AUTHORIZATION_FAILED`
these refusals used to record — a genuine policy code for a message no policy
evaluated — so the tape distinguishes eunox's own routing from a policy block,
and the class it carries is what keeps an observing route from downgrading it.
The wire code stays `-32001`. The marker adds which of the three ways applied.
These records also name no policy target (`target` is left empty whenever the method resolves
a target type), so `eunox suggest` proposes nothing from them rather than
drafting a capability for a resource named after the method.

This mostly bites when the host speaks a **newer MCP revision** than the
upstream, and it surfaces as *two* codes, not one. eunox opens every upstream
leg with `initialize`, so it addresses that leg as `2025-11-25`; a message that
resolves `2026-07-28` **and whose params would travel** is refused
`UNSUPPORTED_PROTOCOL_VERSION` before routing is even consulted, rather than
relaying a declaration the leg contradicts. That covers every enforced method,
every `…/list`, and the forwarded notifications — so those records carry no
`_eunox_unroutable` marker, because no routing decision was reached. The marker
appears for what is left: the methods that forward nothing and simply do not
exist in the negotiated revision (`initialize`, `ping`,
`notifications/initialized`). Either code on a discovery tape means the same
thing — pin the revision the pair actually shares rather than reading the tape
as upstream behavior.

### Lifting a revocation

`eunox kill --revive <session-id|all> --redis-addr <host:port>` undoes a kill:
`<session-id>` removes that session's kill tombstone, and `all` deactivates
the global kill switch. Lifting the global switch leaves per-session **and
per-agent** kills in place — they are separate dimensions, so revive those by id.

`--revive --agent <agent-id>` lifts an agent kill. Agent kills never expire, so
this is the only way to remove one.

It is Redis-only. The loopback `/control/kill` endpoint is a one-way emergency
stop with no undo (a same-host caller holding the control token must not be able
to lift the revocation issued against it), and a proxy on the default in-memory
kill switch is cleared by restarting it.

### Targeting a specific dimension

There are three kill dimensions, and exactly one target may be given — passing
more than one is rejected rather than resolved by precedence:

```bash
eunox kill <session-id>                                   # revoke one session
eunox kill all                                            # halt the deployment
eunox kill --session <session-id> --redis-addr <addr>     # same as the positional
eunox kill --agent <agent-id>  --redis-addr <addr>        # revoke a JWT identity
```

`--agent` targets the JWT `agent_id`, which stops every session that identity
holds — the right granularity when one compromised agent spans many sessions,
instead of killing each session id or reaching for the global switch. It is
Redis-only: there is no agent dimension on the loopback control endpoint. An
agent kill is only *consulted* where the proxy validates JWTs (`--jwks-uri`, HTTP
transport); on a stdio proxy, which cannot take `--jwks-uri`, kill the session
ids instead. The command warns about this on stderr.

`--session` addresses a session id verbatim. That matters in one case: the
positional `all` means the whole deployment, so `--session all` is the only way
to reach a session whose id is literally `all` — possible, since `--session-id`
is operator-settable on a stdio proxy. The control endpoint's response and audit
record carry a `dimension` field (`global` or `session`) so the two cannot be
confused after the fact.

What removing the tombstone actually restores depends on the proxy shape:

- **stdio proxy pinning one `--session-id`** — the primary case `--revive`
  exists for. The proxy never locally reaps that session on a kill (there's
  nothing to reap; it's the one connection the process wraps), so lifting the
  tombstone immediately un-blocks it — the same id may connect again.
- **HTTP proxy/gateway** — a session killed via the loopback `/control/kill`
  endpoint is torn down locally at kill time (its registry entry and upstream
  connection are closed), and a Redis-side `--revive` has no visibility into
  that. The tombstone still clears, so a client is no longer blocked from
  establishing a *new* session, but the original connection and its
  `Mcp-Session-Id` are gone regardless of the revive.

Revive matters most with a negative `--killswitch-session-ttl`, where tombstones
never expire and would otherwise have to be deleted by hand in `redis-cli`.
Note that a kill or revive written over Redis is *not* recorded on the proxy's
audit tape — the CLI is a separate process with no sink, and the kill's effect
shows up as the `KILL_SWITCH` denials that follow it. Only the HTTP
`/control/kill` endpoint records the activation itself. Treat write access to
the shared Redis as equivalent to control of the kill switch.

### One TTL, one place

Both the proxy and `eunox kill --redis-addr` write session tombstones, and the
expiry is stamped by whichever one performs the write. The proxy publishes the
lifetime it runs with to Redis at startup and `eunox kill` adopts it, so
`--killswitch-session-ttl` belongs on `eunox proxy` and does not need to be
repeated on the kill command:

```bash
eunox proxy --config gateway.yaml --redis-addr redis.internal:6379 \
  --killswitch-session-ttl -1s                         # tombstones never expire
eunox kill --redis-addr redis.internal:6379 <id>       # adopts it; no flag needed
```

Passing the flag to `eunox kill` anyway still works — for a Redis no proxy has
started against yet, or to override deliberately. If it disagrees with the
published value, the longer-lived of the two is used (a revocation must never
expire early) and the mismatch is printed on stderr.

The published value carries its own expiry, refreshed by the running proxy, so a
value left behind by a stopped or decommissioned instance stops being readable
rather than being adopted as if it were live. When nothing is published — a fresh
Redis, or a fleet that has been down longer than the refresh window — `eunox
kill` falls back to its own default and says so on stderr; restart the proxy, or
pass `--killswitch-session-ttl`, to make the two agree again. A proxy configured
for *permanent* tombstones (`--killswitch-session-ttl -1s`) publishes a value
with no expiry at all, so that setting is never silently downgraded to the
30-day default by a fleet restart.

---

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Server fails to start in a GUI client | Relative path to `eunox` or the config — use absolute paths. |
| Extension installs but disconnects immediately; log says "looks like a ZIP archive" or "yaml: control characters" | The **eunox config (eunox.yaml)** field points at the downloaded `.mcpb` bundle (a binary), not a YAML config. Repoint it at your `eunox.yaml` (or a copy of [`examples/eunox.example.yaml`](../examples/eunox.example.yaml)). |
| `eunox: command not found` | Not on the GUI app's `PATH`. Use the absolute binary path from `which eunox`. |
| All tools missing | Manifest denies everything, or the manifest path in your config is wrong (check the proxy's stderr). |
| Nothing is ever denied | Client is launching the upstream directly, or the route is in `enforcement: audit`. |
| Windows path errors | Backslashes must be escaped in JSON (`C:\\...`), or use forward slashes. |
| VS Code Copilot sees no server | Wrong key (`servers`, not `mcpServers`), or `chat.mcp.discovery.enabled` is off, or not in Agent mode. |
