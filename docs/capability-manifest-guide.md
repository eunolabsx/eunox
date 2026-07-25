# Capability Manifest Guide

> Patterns for writing capability manifests that work the first time
> and age well. This guide is the practical companion to the normative
> [Capability Manifest Specification](https://github.com/eunolabs/agent-capability-manifest/blob/main/SPEC.md)
> and to `eunox validate` in `cmd/eunox/`. Where this guide and the
> specification differ, the specification governs.

A **capability manifest** is the YAML file a route references via its `policy:`
field in the eunox config. The proxy loads it at startup and checks
every `tools/call` against it before forwarding.
The manifest is therefore the **single source of authority** for what
an agent can do — get it right and the rest of the system enforces it
mechanically.

The proxy enforces policy on the following MCP methods:

| Method | What the proxy does |
|---|---|
| `tools/call` | PDP decision — allow or deny based on manifest + conditions |
| `tools/list` | Filter response to permitted tools only (`call` / `*` action) |
| `resources/read` | PDP decision — allow or deny based on manifest + conditions |
| `resources/list` | Filter response to permitted resources only (`read` / `*` action) |
| `resources/subscribe` | Gate initial subscription with the same read-access policy |
| `prompts/get` | PDP decision — allow or deny based on manifest + conditions |
| `prompts/list` | Filter response to permitted prompts only (`get` / `*` action) |
| `sampling/createMessage` | Denied by default; opt-in with `allow` / `*` action (see §2b for HTTP-mode limitation) |
| unmapped host-originated request methods | Denied (`AUTHORIZATION_FAILED`) — never forwarded to upstream; prevents enumeration via unknown methods (see [threat model §1](threat-model-mcp.md#1-system-overview)) |
| host notifications (e.g. `notifications/cancelled`) | Forwarded verbatim to upstream (except `notifications/initialized`, which the proxy absorbs during handshake) |
| upstream-initiated requests other than `sampling/createMessage` (e.g. `roots/list`) | Forwarded verbatim to the host — no policy check, no audit record |

## 0. Discovery: wiretap first, write second

Before writing a manifest, run the upstream behind eunox in **wiretap mode** for
a session to see what your agent actually calls. No config, no manifest:

```bash
eunox proxy --audit -- <the command that launches your MCP server>
# …use the agent for real work, then:
eunox stats
```

Every enforced-method call (`tools/call`, `resources/read`, `resources/subscribe`,
`prompts/get`, `sampling/createMessage`) is forwarded and recorded to `~/.eunox/audit.jsonl`
with `audit_only: true`; `tools/call` records also include the full tool argument map.
(`…/list` calls forward the full upstream catalog unfiltered and are recorded as enumeration events.) `eunox stats` prints a
per-tool histogram split into **BLOCKED** (none, in wiretap mode) and
**OBSERVED** (would-be denials if you had a policy) so you can see which tools
the agent uses, with what shapes of arguments. That tape is the ground truth
your first manifest should describe.

> **Security note:** In wiretap/audit mode the audit log contains full tool
> call argument values for every allowed call. Treat `~/.eunox/audit.jsonl`
> as sensitive regardless of mode — even in enforce mode, denial records
> include condition-specific argument excerpts (e.g., the rejected value that
> triggered an `allowedValues` check). Apply appropriate access controls and
> retention policy to this file.

Then turn the tape straight into a draft policy:

```bash
eunox suggest --output manifest.yaml
```

`suggest` reads the same audit log and emits one capability entry per observed
target — and, for a tool argument that was present on **every** observed allowed
call and seen only with a bounded set of **string** values, an `allowedValues`
condition grounded in those exact values (with a commented glob hint when they
share a directory prefix). An argument that was omitted from some calls, that
took non-string values, or that mixed both is deliberately left **unconstrained**
with an explanatory comment rather than turned into a condition: because a
missing argument and a non-string value both fail closed at enforcement, emitting
such a condition would reject exactly the calls the tape recorded as allowed.
Argument names are emitted as quoted scalars, so a name carrying a
YAML-significant character (a colon, a leading `*`) still produces a valid draft.
The sensitive `system:sampling/createMessage` opt-in is always emitted
**commented out**, and any target seen only as a denial is listed commented under
a "seen only as denials" heading — so regenerating the draft never silently
widens access. The output is a *draft describing observed usage, not vetted
policy*: review and tighten every entry, then `eunox validate manifest.yaml`
before you enforce it.

Prefer to start from the upstream's declared tool list instead of the tape?
`eunox init --upstream-url <url> --output manifest.yaml --config-output
eunox.yaml` scaffolds a deny-all starter (every entry commented out) plus a
runnable config. The patterns below explain how to fill in either starting point.

## 1. Required structure

The required top-level fields are `schemaVersion`, `name`, `version`, and
`capabilities`. Optional fields are `description` and `audience`.
Anything missing or shaped differently is rejected by `eunox validate`.

> **Migration note (pre-1.0).** The `defaultTtl` field was removed — it was
> informational only and never enforced. Because unknown keys are rejected
> fail-closed (see below), a manifest that still carries a `defaultTtl:` line no
> longer loads: it is refused at startup with `manifest: unknown field
> "defaultTtl"`. Delete the line — nothing consumed it, so removing it changes no
> enforcement behavior.

**Unknown keys are rejected, fail-closed.** A misspelled field anywhere in the
manifest — `arguments` for `argument`, `action` for `actions`, `value` for
`values` — is refused at load with a "did you mean …?" hint, rather than
silently dropped. A typo in a security policy must never quietly produce a
*different* policy: an `allowedValues` whose `argument` got swallowed would deny
every call at runtime, and a `maxCalls` missing its `windowSeconds` would become
a counter that never resets. `validate` catches both before they ship.
`windowSeconds` also has an upper bound (~4.6e9 seconds, ~146 years): a value
beyond it overflows the call-counter's internal duration arithmetic and would
silently reset the quota at runtime, so it is rejected at load rather than
allowed to fail open. This
extends into `argumentSchema`, which follows a closed JSON-Schema subset (SPEC
§ 3.2.2): the supported keywords are `type`, `enum`, `properties`, `required`,
`additionalProperties`, `items`, `minItems`, `maxItems`, `minLength`,
`maxLength`, `pattern`, `minimum`, `maximum`, and the `description` annotation.
Anything else — `const`, `$ref`, `allOf`, `exclusiveMinimum`, `format`, … — is
rejected at load (recursively through `properties` and `items`) rather than
silently dropped and left unenforced. A property mapped to an explicit **null**
subschema (`properties: {id: null}`) is likewise rejected: a null subschema would
accept any value for the declared property — almost never what the author meant.
Use the empty object `{}` for an explicit "any" subschema; only the `null` form is
refused. The `type` keyword itself must name a real JSON-Schema type (`string`,
`number`, `integer`, `boolean`, `object`, `array`, `null`) — an empty string, an
empty array, an unrecognized name, or a duplicate name within a `type: [...]`
list is rejected at load rather than silently disabling the type check (an empty
array in particular decodes indistinguishably from "no type declared," so leaving
it unvalidated would have quietly dropped type enforcement for that property).
`type` itself may be omitted, or set explicitly to `null`, to declare no type
constraint. JSON has a single numeric type, so a value
like `3.14` and `3` both arrive as the same kind; `type: integer` therefore
rejects any number carrying a fractional part (only `42`, `0`, `-3` pass), while
`type: number` accepts both. An operator pinning a parameter to whole numbers
gets a real `INVALID_PARAMS` denial, not a silently-accepted `LIMIT 3.14`. Keywords
are independent and all must hold: a value that matches `enum` is still checked
against `type` (and the other declared keywords), so `{type: string, enum: [1, 2]}`
rejects the number `1` rather than letting the enum match waive the type check.
A numeric `minimum` / `maximum` bound must be **exactly representable** — an
integer bound whose magnitude exceeds 2^53 (or any literal that does not round-trip
through a 64-bit float) is **rejected at load** rather than silently rounded to a
neighbouring value. A rounded-down `minimum`, for example, would admit an argument
strictly below the written bound (the exact-integer argument comparison compares
against the *rounded* bound), silently weakening the constraint; the load-time check
prevents that fail-open. Keep large integer bounds at or below 2^53
(`9007199254740992`), or enforce them with an `allowedValues` condition, which
preserves the literal exactly.

Like `directives` (§ 5a), `argumentSchema` applies to **`tool:` targets only**
(SPEC § 3.2.2): it validates the shape of a tool call's argument map, which
`resource:`, `prompt:`, and `system:` requests do not carry — `resources/read`
and `prompts/get` are matched on a single URI/name, and the sampling opt-in is
argument-less. An `argumentSchema` on a non-tool target is therefore **rejected
at load** rather than silently accepted and never enforced. To constrain a
resource URI or prompt name beyond the target glob, use an `allowedValues`
condition on `uri` / `name` (§ 5). The decision path is hardened as defense in
depth: should a `resource:`/`prompt:` constraint carrying an `argumentSchema`
ever reach enforcement (e.g. a manifest assembled in-process rather than through
the loader), the request is denied with `ENFORCEMENT_ERROR` rather than forwarded
with the schema silently skipped — the tool-only guarantee does not rest on
load-time validation alone.

`schemaVersion` is the manifest **grammar** version (currently `"0.1"`) — the
dialect of fields the document is written in, distinct from the policy-content
`version`. A manifest with an absent or unsupported `schemaVersion` is refused at
load (fail-closed) rather than parsed under a grammar the proxy may not model.

> **Version axes are independent.** Three versions appear in these docs and they
> do not move together: the **manifest grammar** version (`schemaVersion`, e.g.
> `"0.1"`), the **JWT capability-claim schema** version (`mcp.v`, e.g. `"0.2"`),
> and the **eunox binary/release** version (e.g. `0.1.0-rc1`). References
> elsewhere in this guide to a later grammar revision (for example reclassifying
> a field as a directive in a future grammar version) describe the *grammar's*
> evolution, not the binary's — do not read them as the product release number.

```yaml
schemaVersion: "0.1"       # manifest grammar version; required, fail-closed if unsupported
name: "Sales Research Bot" # human-readable, unique per logical agent
version: "0.1.0"           # policy-content semver; recorded in every audit log entry
capabilities: []           # see § 2 — each entry is a capability constraint
description: "Synthesizes account-research briefings." # optional
audience: "svc-research"   # gateway mode: the JWT aud required on this route
```

In **gateway mode** (`eunox proxy --config`), the manifest `audience` field
pins the JWT `aud` claim required on that route: a token is authorized on the
route only if its `aud` carries this value. It **overrides** the global
`--jwt-audience` for that route, and `--jwt-audience` remains the **fallback**
for routes that declare no `audience`. So a gateway whose two routes declare
`audience: svc-a` and `audience: svc-b` accepts only the matching audience on
each — a token minted for `svc-a` presented to the `svc-b` route is denied. The
shared validator first verifies signature/exp/iss and that the token's `aud`
matches *some* route's audience; each route then narrows to its own. The pin is
enforced on every enforced action (`tools/call`, `*/list`, `resources/read`,
`prompts/get`, server-initiated sampling) **and** on the session-creating
`initialize`, so a cross-audience token cannot even open a session on, or spawn
the upstream of, a route whose audience it does not carry. A token whose `aud`
is a list is accepted on a route when that route's audience is **among** the
list. `--jwt-allow-any-audience` disables audience pinning entirely. Fail-closed
is preserved: a route with no `audience` and no `--jwt-audience` (outside
`--jwt-allow-any-audience`) refuses to start.

In **single-upstream** (non-gateway) mode there is no per-route concept; the
manifest `audience` field is not consulted and audience pinning comes from
`--jwt-audience` alone.

**Version is the unit of pinning.** In gateway mode (`eunox proxy --config`)
a route may declare `expectVersion: "0.1.0"` for its manifest; the gateway
**fails closed** — it refuses to start — if the loaded manifest's `version`
differs. A pin targets a **single** manifest file: a route that merges several
policy files can't declare `expectVersion` (the gateway rejects the combination
at startup), so consolidate split policies before pinning a version. Every audit
record is stamped with the in-force `policy_version` and a
`policy_sha256` digest of the manifest, so each decision is traceable to an exact,
versioned policy. Increment `version` on every policy change.

**A gateway route must be policed or explicitly observed.** In gateway mode a
route with no `policy:` only loads when it also declares `enforcement: audit`
(observe-only). A route with neither is a misconfiguration — a typo, a deleted
manifest reference, or a half-applied rollout — and the gateway **fails closed
at startup** rather than mounting it unenforced. To run a route intentionally
unpoliced, set `enforcement: audit` to acknowledge the allow-and-log posture.

## 2. How enforcement works

Before writing a manifest, understand what the proxy actually checks.

**Namespace prefix (required)** — every `target` field must
begin with one of four typed prefixes. The proxy rejects any manifest that
contains an unprefixed `target` string (fail-closed at startup):

| Prefix | Matches against | Valid actions |
|--------|-----------------|---------------|
| `tool:` | MCP tool name (e.g. `tool:read_file`) | `call`, `*` |
| `resource:` | Resource URI (e.g. `resource:file:///data/reports/*`) | `read`, `*` |
| `prompt:` | Prompt name (e.g. `prompt:code_review`) | `get`, `*` |
| `system:` | System primitive (only `system:sampling/createMessage`) | `allow`, `*` |

The prefix makes matching **namespace-scoped**: a `tool:` constraint can
never authorize a `resources/read` request, even if the pattern strings
happen to match. This closes the cross-namespace authorization bypasses
described in the specification § 7.7 (with the MCP method mapping in the
spec's MCP binding § 2.2).

**Matching** — after stripping the prefix, the proxy matches the remaining
pattern against the target using `path.Match` glob semantics.
`target: tool:get_*` matches any tool whose name starts with `get_`;
`target: tool:read_file` matches only the tool named `read_file` exactly.

**Actions** — the action keyword controls which primitive is permitted.

| Action | Permits |
|--------|---------|
| `call` | `tools/call` for the matched tool name (also shown in `tools/list`) |
| `read` | `resources/read` for the matched URI (also shown in `resources/list`); gates `resources/subscribe` |
| `get` | `prompts/get` for the matched prompt name (also shown in `prompts/list`) |
| `allow` | `sampling/createMessage` from the upstream (opt-in) |
| `*` | every action valid for the constraint's own target type only |

Each action is valid only for its target type's prefix. A `tool:` constraint
with `actions: [read]` is rejected at manifest-load time.

`[call]` is explicit, deterministic, and what most entries in this guide use.

**tools/list filtering** — automatic based on `call` / `*` entries.

When a manifest is configured, the proxy filters the upstream
`tools/list` response before returning it to the host. Only tools
whose names match a `tool:` capability entry with `call` or `*` action are
included. The host and model therefore never see tool descriptions for
tools they cannot call. No manifest change is required; filtering is
automatic. Conditions are **not** evaluated during filtering (no arguments
exist at list time); a tool that is call-permitted only under a condition
still appears in the filtered list.

**resources/list filtering** — automatic based on `read` / `*` entries.

The proxy similarly filters the upstream `resources/list` response to
only include resources whose URIs match a `resource:` capability entry with
`read` or `*` action. Absent entries are filtered out. Conditions are not
evaluated here either.

**prompts/list filtering** — automatic based on `get` / `*` entries.

The proxy also filters the upstream `prompts/list` response to only include
prompts whose names match a `prompt:` capability entry with `get` or `*`
action. Without this, an agent correctly blocked from retrieving an
unauthorized prompt via `prompts/get` could still discover its existence
(and its argument schema) through `prompts/list`. As with the other list
filters, conditions are not evaluated here.

## 2a. Resource reads (`resources/read`)

MCP servers can expose _resources_ — files, database rows, API results —
identified by a URI. The proxy enforces `resources/read` using the same
allowlist model as `tools/call`. Use the `resource:` prefix:

- Absent entries → **deny** (default).
- Matching `resource:` entry with `read` or `*` action → **allow** (conditions apply).

```yaml
capabilities:
  # Allow reading any file under the reports directory.
  - target: "resource:file:///data/reports/*"
    actions: [read]

  # Allow reading specific database resources.
  - target: "resource:db://warehouse/orders"
    actions: [read]

  # Wildcard — allow all resources on a server (use sparingly).
  - target: "resource:db://analytics/*"
    actions: [read]
```

All condition types work on resource reads. The URI is the match
target; the arguments map passed to condition evaluation contains
`{"uri": "<uri>"}`. (`argumentSchema`, by contrast, is `tool:`-only — see
§ 1 — and is rejected at load on a `resource:` target; constrain the URI with an
`allowedValues` condition on `uri` instead.)

## 2b. Server-initiated sampling (`sampling/createMessage`)

> **Deprecation note (MCP).** Server-initiated sampling is deprecated by the MCP
> specification (SEP-2577, "Deprecate Roots, Sampling, and Logging"). The
> deprecation is advisory — the wire protocol is unchanged and sampling stays
> functional through the spec's transition window — so eunox continues to enforce
> it. A deprecated-but-live capability is exactly the kind of channel a compromised
> upstream may still try to use, so the deny-by-default control below retains its
> full value. The manifest grammar (`system:sampling/createMessage`) and the
> `SAMPLING_DENIED` code are unchanged; this stance is reassessed only if a future
> spec version removes the method from the schema.

MCP 2025-11-25 allows the _server_ to request that the host LLM generate
a message — the reverse of the normal flow. Because this gives a
potentially compromised server direct access to the model, it is
**denied by default**. To allow it, add an explicit `system:` entry:

```yaml
capabilities:
  - target: "system:sampling/createMessage"
    actions: [allow]   # or [*]
```

Without this entry, any `sampling/createMessage` request from the
upstream receives a JSON-RPC error and is never forwarded to the host.
This is enforced regardless of whether a manifest is otherwise configured.

The `system:` prefix is critical: a tool or resource entry — even one
literally named `sampling/createMessage` — cannot satisfy this opt-in.
Namespace-scoped matching ensures only a `system:` constraint with the
exact identifier `sampling/createMessage` enables the channel.

**JWT mode** (`--jwks-uri`) does not change this decision. Sampling is
initiated by the upstream server, not by an HTTP client, so no bearer
token is in scope when the request arrives — JWT capability claims can
neither grant nor restrict it, and the exhaustive-allowlist rule (§ 5.2)
does not apply. The manifest's `system:` opt-in alone governs; a route
with no manifest stays denied even in JWT mode.

**The kill switch applies** to sampling like every other enforced
method: a killed session, a killed agent (attributed from the session's
most recently validated bearer token, since the upstream-initiated
request carries no token of its own), or an active global kill denies
the request even when the manifest opts in, and a kill-store error
fails closed. This is the immediate-revocation lever when sampling must
stop before a manifest change can be rolled out. During proxy shutdown
a remote (Redis) kill store can no longer be consulted, so in-flight
sampling requests in that window are denied and recorded as
`KILL_SWITCH_ERROR` — fail-closed, not a kill-store outage.

**Route-level audit (observe) mode applies** to sampling: a route in audit
mode (`proxy --audit`, or `defaults.enforcement: audit`) observes a would-be
sampling denial and forwards the request to the host anyway, recording it
with `audit_only: true` rather than blocking. There is **no per-entry** audit
mode for sampling — `enforcement: audit` on a `system:` target is rejected at
manifest load, because the sampling opt-in is binary (you either grant the
channel or you do not). A kill-switch denial is the one exception to observe
mode — it hard-blocks even under `--audit`, since it is an operator emergency
stop, not a policy verdict.

> **Limitation:** In HTTP proxy mode, when sampling is allowed,
> the request is broadcast to SSE subscribers but the host's response
> is not forwarded back to the upstream.  Full sampling round-trip
> support in HTTP mode is a known gap.

## 2c. Resource subscriptions (`resources/subscribe`)

`resources/subscribe` opens a live update channel for a specific resource
URI. The proxy enforces the same read-access policy as `resources/read`:
a subscription is only allowed if the resource URI matches a `resource:`
manifest capability with `read` or `*` action.

```yaml
capabilities:
  # Permit reading and subscribing to live metrics.
  - target: "resource:file:///data/live/*"
    actions: [read]   # covers both resources/read and resources/subscribe
```

If the URI does not match any manifest entry, the subscription is denied
before any channel is established.  Kill-switch and audit-mode semantics
apply.

> **Note:** Ongoing `notifications/resources/updated` messages (pushed by
> the server after a subscription is established) are currently forwarded
> verbatim.  The initial subscription gate is the primary defense.

## 2d. Prompt access (`prompts/get` and `prompts/list`)

MCP servers can expose _prompts_ — named, parameterized instruction
templates injected into the conversation. Because a prompt is executable
model instruction, it can construct tool-call chains that would otherwise
be blocked individually. The proxy enforces an allowlist on both
`prompts/get` and `prompts/list` using the `prompt:` prefix:

```yaml
capabilities:
  # Permit a specific prompt by exact name.
  - target: "prompt:code_review"
    actions: [get]

  # Permit all prompts whose names start with "summarize_".
  - target: "prompt:summarize_*"
    actions: [get]

  # Permit every prompt the server exposes (use sparingly in production).
  - target: "prompt:*"
    actions: [get]
```

The prompt name from the `prompts/get` request params is matched directly
against the pattern after the `prompt:` prefix. Manifests that contain no
`prompt:` entries deny all `prompts/get` and `prompts/list` requests by
default. Prompt _content_ inspection (checking what the prompt says) is
out of scope. (`argumentSchema` is `tool:`-only — see § 1 — and is rejected at
load on a `prompt:` target; constrain the name with an `allowedValues` condition
on `name` instead.)

The same `prompt:` entry that authorizes `prompts/get` also controls
`prompts/list` filtering: only prompts matched by an authorized `prompt:`
constraint appear in the filtered list. Without this, an agent correctly
blocked from retrieving an unauthorized prompt could still discover its
argument schema through `prompts/list`.

## 2e. Token model — the IdP capability claim

eunox authenticates requests via a JWT your IdP issues, carrying an `mcp.*`
capability claim.

> **Experimental — opt-in.** The `mcp.capabilities` claim schema (JWT schema
> v0.2) is experimental and its format may change before 1.0. eunox enforces the
> JWT-claim ∩ manifest intersection only when started with
> `--jwt-experimental-capabilities`; with the flag off (the default) a token
> carrying `mcp.capabilities` is rejected (HTTP 401) rather than having its
> restriction silently dropped. JWT signature/expiry/issuer/audience
> verification and the identity claims (`sub`, `mcp.task_id`, `mcp.agent_id`)
> are stable and always active, independent of this flag.

| | **IdP capability claim** |
|---|---|
| Where it lives | `mcp.*` claim inside a JWT your IdP issues |
| Schema | published [`mcp-jwt-claim.json`](https://github.com/eunolabs/agent-capability-manifest/blob/main/schemas/0.1/mcp-jwt-claim.json), `mcp.v = "0.2"` (experimental) |
| Go type | `mcpClaimSet` in `internal/pdp/jwt.go` |
| Verified by | the IdP's JWKS (`--jwks-uri`) |
| `capabilities` shape | array of **shorthand strings** (`tool:read_file?path=/reports/*`) |
| How conditions appear | encoded in the `?key=value` suffix grammar (§ 5.2, Pattern D) |
| Extra machinery | `task_id`, `agent_id` |
| Role | per-invocation narrowing in intersection mode |

**Why conditions aren't enumerated in the published JWT schema.** In the IdP
claim, conditions are *not* JSON structure — they ride inside the capability
strings as a form-urlencoded shorthand (`?op=SELECT&table=sales`). The proxy
expands that grammar into typed conditions only at enforcement time. A JSON
Schema `pattern` on a string can't express the sub-grammar, so the condition
vocabulary is normative prose (§ 5.2 / Pattern D), not schema. Conditions are
fully expressible in the JWT — just opaque and narrowing-only.

A sender-constrained token (RFC 7800 `cnf`: a DPoP `jkt`, embedded `jwk`, `kid`
reference, or an RFC 8705 mTLS `x5t#S256` binding) is bound to a
proof-of-possession key the proxy has no verification path for, so it is
rejected fail-closed (`capability.CnfIsSenderConstrained`) rather than honored
as a plain bearer token.

## 2f. Staged rollout — `enforcement: audit`

By default a constraint **enforces**: a denial it produces (a failed action
check, `argumentSchema`, or condition) blocks the call. Set `enforcement: audit`
on a single entry to put just that entry in **observe mode** — its would-be
denial is written to the audit tape and the call is **forwarded** instead of
blocked:

```yaml
capabilities:
  - target: tool:execute_sql
    actions: [call]
    enforcement: audit          # log violations, don't block — yet
    conditions:
      - type: allowedOperations
        argument: sql             # required: name the parameter carrying the SQL string
        operations: [SELECT]
```

Use it to **stage** a new tool, or a stricter condition on an existing one,
before it blocks production traffic: turn it on in `audit`, watch
`~/.eunox/audit.jsonl` for `decision:"deny"` records carrying `audit_only: true`,
then flip to `enforce` (or drop the field) once the rule runs clean.

> **Security note:** Per-entry `enforcement: audit` affects how _denials_ are
> handled (observed and forwarded rather than blocked); it does **not** cause
> full argument values to be written on allowed calls. However, denial records
> in any mode include condition-specific argument excerpts (for example,
> `allowedValues` writes the rejected value into the `details` field). Treat
> `audit.jsonl` as potentially sensitive regardless of mode. Full argument
> capture on allowed calls only occurs in route-level observe mode (`--audit`
> flag on the `proxy` subcommand, or `enforcement: audit` under `defaults:` /
> per-route `enforcement:` in a gateway config); see the threat model §6.2.

> **Catalog disclosure in route-level audit mode.** A route in observe mode
> (`--audit`, or `enforcement: audit` with no per-entry enforcement) returns the
> **full, unfiltered** upstream `tools/list` / `resources/list` / `prompts/list`
> to the host — even when a restrictive manifest is loaded. This is intentional
> (observe everything, block nothing, so a host can call what it observes), but it
> means audit mode is not a way to *hide* the catalog: the host sees every
> upstream tool. The kill switch still hard-blocks enumeration. Per-entry
> `enforcement: audit` on an otherwise-enforcing route still filters `*/list` to
> the permitted entries.

It is deliberately fail-open **for that one entry**, so the scope is bounded:

- It only affects an entry that is **present and matched**. A tool absent from
  the manifest is still denied by default — `audit` never opens the allowlist.
- It never bypasses the **kill switch**, and never downgrades a **JWT-scope**
  denial — only the manifest entry's own verdict is observed.
- It is rejected on a `system:` target (the sampling opt-in is binary), and an
  unrecognized `enforcement` value is rejected at load (fail-closed).

The proxy logs a startup notice naming how many entries are in audit mode, so an
unenforced rule can't hide. Treat `audit` as a transient rollout state, not a
steady-state posture. See SPEC § 3.2.3 / § 7.9.

## 2g. Denial codes — what the host sees

Every deny carries a stable symbolic code in `error.data.code` (and the audit
record's `denial_code`) plus a JSON-RPC integer `error.code`. Alert on the
symbolic code: the integers are coarse (several codes share one), the symbols are
exact. This is the authoritative set.

| `denial_code` | JSON-RPC | When |
| ------------- | -------- | ---- |
| `AUTHORIZATION_FAILED` | `-32001` | No manifest entry matches the target (allowlist miss), or an unmapped method reached the enforced path. |
| `NO_JWT_CLAIMS` | `-32001` | JWT mode is active but the request carried no validated token claims (an authentication miss, surfaced as a capability denial). |
| `CAPABILITY_DENIED` | `-32002` | A matched entry's verdict is deny (e.g. the action is not granted for the target). |
| `SAMPLING_DENIED` | `-32001` | A server-initiated `sampling/createMessage` is not permitted — no `system:sampling/createMessage` entry, or a JWT claim withholds it. Surfaced to the upstream initiator as `AUTHORIZATION_FAILED` (`-32001`); the symbolic `SAMPLING_DENIED` is what the audit log records. |
| `CONDITION_FAILED` | `-32003` | A condition rejected the call for a structural reason (e.g. an `allowedOperations` entry missing its `argument`, or a malformed condition input). |
| `VALUE_NOT_PERMITTED` | `-32003` | An `allowedValues` condition: the argument value is outside the permitted set. |
| `OPERATION_NOT_PERMITTED` | `-32003` | An `allowedOperations` condition: the operation is outside the permitted set. |
| `RATE_LIMITED` | `-32003` | A `maxCalls` condition's count/window was exceeded. |
| `MISSING_CONTEXT` | `-32003` | A condition's required argument is absent or empty (fail closed — the condition is never skipped). |
| `INVALID_PARAMS` | `-32602` | `argumentSchema` structural validation failed (takes precedence over condition failures). |
| `KILL_SWITCH` | `-32603`* | The session or agent has been killed via the kill switch. |
| `KILL_SWITCH_ERROR` | `-32603`* | The kill-switch backend errored; the proxy fails closed rather than treat the error as "not blocked". |
| `AUDIT_UNAVAILABLE` | `-32603` | Under `--require-audit=strict`, the audit trail has degraded (a record was dropped or a write failed); an otherwise-authorized call is denied rather than forwarded unaudited. |
| `ENFORCEMENT_ERROR` | `-32603` | Defensive fail-closed guard for an internal enforcement-engine error (not emitted on any reachable path today). |

`*` The kill-switch codes are infrastructure failures mapped to the internal-error
class on the wire; the symbolic code in `error.data.code` disambiguates them from a
clean policy denial.

## 3. The capability list — four common patterns

### Pattern A — Single-purpose read agent

> _"This agent looks things up and reports. It never writes anywhere."_

```yaml
capabilities:
  - target: "tool:get_*"    # matches get_customer, get_invoice, get_report …
    actions: [call]
  - target: "tool:list_*"   # matches list_customers, list_orders …
    actions: [call]
  - target: "tool:search_*" # matches search_products, search_tickets …
    actions: [call]
```

- The `tool:` prefix is required. A bare `get_*` is rejected at startup.
- Use `actions: [call]` — it is unconditional for any matched tool.
- Scope each target glob to one verb prefix. Do not write
  `target: "tool:*"` (rejected by `eunox validate` as too broad).
- If the agent should only call a small fixed set of tools, list them
  individually rather than using a prefix glob — narrow is always safer.

  ```yaml
  capabilities:
    - target: tool:get_customer
      actions: [call]
    - target: tool:list_orders
      actions: [call]
  ```

### Pattern B — Workflow agent (read-many, narrow write)

> _"This agent reads broadly but writes to exactly one tool."_

```yaml
capabilities:
  - target: "tool:get_*"            # reads — broad
    actions: [call]
  - target: "tool:list_*"           # reads — broad
    actions: [call]
  - target: tool:add_customer_note  # single permitted write tool — explicit
    actions: [call]
  # create_*, update_*, delete_* are absent → denied by default
```

- There are no resource paths in MCP — you control access by
  **naming the write tools explicitly**, not by restricting to a path prefix.
- Never add a write tool "just in case it's needed later".
  Every write capability you add is blast radius.
- If the agent genuinely needs several write tools, list each one
  individually rather than widening to `"create_*"` or `"*"`.

### Pattern C — Tool-specialist agent

> _"This agent calls one specific tool many times, with argument constraints."_

```yaml
capabilities:
  - target: tool:run_forecast  # exact tool name, tool: prefix required
    actions: [call]
    conditions:
      - type: maxCalls           # at most 30 calls per minute
        count: 30
        windowSeconds: 60
      - type: allowedOperations  # narrow the operation verb further
        argument: operation       # the tool parameter that carries the verb
        operations: ["predict"]
```

- Use the exact tool name, not a glob — you want this constraint to
  apply to precisely one tool.
- Apply typed conditions to constrain arguments and rate. Each condition
  is one of the typed shapes in `pkg/capability/condition.go`.
- See § 4 for the full condition type reference.

### Pattern D — JWT-scoped agent (manifest + IdP intersection)

> _"A per-task JWT narrows what this invocation can do within the
> broader manifest."_

```yaml
# manifest.yaml — broadest policy the system ever permits
capabilities:
  - target: tool:read_file
    actions: [call]
    conditions:
      - type: allowedValues
        argument: path
        values: ["/reports/*"]
  - target: tool:query_db
    actions: [call]
```

The IdP then issues a JWT carrying a narrower `mcp.capabilities` claim
(JWT schema v0.2 — namespace prefixes required, explicit argument names):

```json
{
  "mcp": {
    "v": "0.2",
    "capabilities": ["tool:read_file?path=/reports/q3.pdf"],
    "agent_id": "summarizer-run-42",
    "task_id": "briefing-2026-05-31"
  }
}
```

The proxy takes the **intersection**: the JWT can only restrict, never
expand beyond what the manifest permits. `tool:query_db` is denied for
this invocation even though the manifest allows it.

JWT shorthand format: `<prefix>:<target>[?<key>=<value>[&<key>=<value>…]]`

| Shorthand | Meaning |
|---|---|
| `tool:read_file` | allow `read_file`, no extra condition |
| `tool:read_file?path=/reports/*` | allow `read_file` only when `path` matches `/reports/*` |
| `tool:query_db?op=SELECT` | allow `query_db` only for `SELECT` operations |
| `tool:query_db?op=SELECT&table=sales` | allow `query_db` only when the op is `SELECT` **and** the `table` arg is `sales` |
| `resource:file:///data/*` | allow reads on any file in `/data/` |
| `prompt:code_review` | allow the `code_review` prompt |

The suffix is `application/x-www-form-urlencoded`: pairs joined by `&` combine
with logical **AND**, and each `<value>` is percent-decoded (and `+` → space)
before matching — so `tool:read_file?path=/reports/Q3%20Draft.pdf` matches the
argument value `/reports/Q3 Draft.pdf`. The key `op` maps to `allowedOperations`;
any other key maps to `allowedValues` on the argument literally named by that
key. There is no default-argument fallback — every condition pair MUST name its
argument explicitly.

> **`op=` is SQL-only.** The bare `op=<verb>` shorthand names no argument, so the
> proxy inspects the first word of every string argument. This is only sound for
> SQL operations, where a disallowed statement smuggled into any argument is
> caught by the SQL-verb guard. A **non-SQL** operation (e.g. `op=publish`) in
> this bare form **fails closed** (`CONDITION_FAILED`): the proxy cannot tell
> which argument carries the operation, so a benign free-text argument starting
> with the granted verb could otherwise mask a disallowed operation field. To
> restrict a non-SQL operation, use the structured manifest form that names the
> operation argument explicitly (`allowedOperations` with an `argument`).

A `&` or `=` that is part of a *value* MUST itself be percent-encoded (`%26`,
`%3D`) so it is not read as a delimiter. The `mcp.v` value stays `"0.2"`: the
grammar extends compatibly, so single-condition v0.2 tokens are unaffected.

Tokens are rejected (HTTP 401) when `mcp.v` is absent or unrecognized, when a
shorthand entry is missing the namespace prefix, or when a suffix cannot be
parsed unambiguously into explicit `(argument, value)` pairs — a pair missing
`=`, an empty or percent-encoded key, a duplicate key, or a value with a
malformed percent-escape all fail closed. A token carrying `mcp.capabilities`
is likewise rejected (HTTP 401) unless the proxy was started with
`--jwt-experimental-capabilities` (this claim schema is experimental — see § 2e).

- Start the proxy in JWT mode: run an `transport: http` config and add `--jwks-uri <url> --jwt-issuer <iss> --jwt-audience eunox`; each route's manifest is intersected with the token's claims
- The audit log records `agent_id` and `task_id` from the JWT automatically.
- Standard-claim validation (`exp`/`nbf`/`iat`) applies a clock-skew grace controlled by `--jwt-leeway` (default `10s`). A token whose `exp` is up to this far in the past is still accepted, tolerating modest skew between the IdP and eunox; pass a smaller value to tighten the reuse window or `--jwt-leeway 0` to disable the grace entirely (`exp` must then be strictly in the future). The grace was previously a hardcoded one minute with no override.

### Per-principal scoping (`principal`)

Where the JWT intersection (Pattern D) restricts an invocation from the *token*
side, a constraint's `principal` field scopes an entry from the *manifest* side:
the entry applies only to requests whose validated JWT identity matches.

```yaml
capabilities:
  # Only the admin agent may delete.
  - target: tool:delete_*
    actions: [call]
    principal:
      agent_id: ["agent-admin"]

  # Everyone may query the database, but the batch agents get a tighter cap.
  - target: tool:query_db          # the stricter, identity-scoped rule …
    actions: [call]
    principal:
      agent_id: ["batch-*"]        # exact value or path.Match glob
    conditions:
      - type: maxCalls
        count: 10
        windowSeconds: 3600
  - target: tool:query_db          # … and the general fallback for everyone else
    actions: [call]
    conditions:
      - type: maxCalls
        count: 100
        windowSeconds: 3600
```

Semantics:

- **Supported claims:** `agent_id`, `task_id`, `sub`, `iss` — the identity
  dimensions eunox validates and stamps into the audit log. A `principal` key
  outside this set is rejected at manifest load (custom claims are not yet
  captured from the token). Each claim lists one or more allowed patterns (exact
  or `path.Match` glob).
- **Match rule:** a request matches when **every** named claim is present and
  satisfies one of its patterns — AND across claims, OR within a claim's list.
- **Glob semantics:** patterns use `path.Match`, where `*` matches within a path
  segment but **not** across `/`. `iss` and `sub` are commonly URLs, so
  `iss: ["https://idp.example.com/*"]` does **not** match
  `https://idp.example.com/tenant/a` — the `*` stops at the first `/`. Use an
  exact value for slash-bearing identities (a malformed glob is rejected at
  manifest load rather than silently never matching).
- **Fail closed:** a `principal`-scoped entry whose identity does not match is
  *skipped* during selection, exactly like a target mismatch. With no other
  matching entry the call is denied. A `principal` rule therefore needs a
  validated token: under a manifest-only deployment (no `--jwks-uri`) there are
  no claims, so principal-scoped entries never apply.
- **Refinement beats order:** at equal target specificity a matching
  `principal`-scoped entry wins over a general one regardless of where it sits in
  the file, so the identity-specific rule refines the general one without
  depending on entry ordering.
- **Specificity still dominates:** that tie-break applies *only at equal target
  specificity*. A more specific target always wins first, even an unscoped one,
  so a broad principal entry (`tool:*` scoped to `agent_id: [X]`) does **not**
  override a more specific general entry (`tool:query_db`). To deny or tighten a
  specific tool for one principal, scope the entry at the same (or a finer)
  target specificity as the rule it must beat — not a wider glob.
- **List filtering follows suit:** a principal-scoped tool/resource/prompt is
  hidden from `*/list` for an identity that does not match it, so the catalog a
  caller sees matches what it can actually invoke.
- **Equal-specificity ties between two principal entries resolve first-wins.**
  "Refinement beats order" only breaks a tie between a principal-scoped entry and
  a *general* one. When **two** `principal`-scoped entries match the same request
  at the *same* target specificity — for example two entries for `tool:query_db`
  both scoped to `sub: [alice]` but carrying different `conditions` — the engine
  applies the **first one in declaration order** and ignores the rest. The
  outcome therefore depends on YAML ordering, which is easy to get wrong. Do not
  rely on it: express per-principal differences as a single constraint, or give
  the entries distinct target specificities, rather than two equal-specificity
  duplicates whose winner is positional.
- **Across multiple policy files, that tie is rejected, not resolved by order.**
  Within one file the first-wins rule above is something you can see and control —
  both entries sit in the same document. When policy is **split across several
  files** — a gateway route's `policy: [a.yaml, b.yaml]`, or
  `eunox validate a.yaml b.yaml` — the "first" entry is just whichever file
  was listed first, and the shadowing is invisible: appending a file to *tighten*
  a target can instead leave the new entry inert, or an earlier
  `enforcement: audit` entry can downgrade a later restrictive one to
  allow-and-log. So eunox **fails closed at load**: if two files declare the same
  target with overlapping actions and `principal` scopes that a single request can
  satisfy at once, the merge is rejected with an error naming the target (two
  byte-identical entries in different files are a special case of this and are
  rejected too). To compose policy across files, give the entries non-overlapping
  reach — combine them into one file (where the documented first-wins applies and
  is visible), or scope them to principals **no single request can satisfy
  together**: disjoint *literal* values on the **same** claim, e.g.
  `agent_id: [ci-bot]` in one file and `agent_id: [release-bot]` in the other.
  Two pairings that look distinct but are **not** safe across files:
  - **Different claims.** `sub: [alice]` in one file and `iss: [acme]` in another
    for the same target *do* conflict — a token carrying both claims satisfies
    both scopes (a `principal` ANDs only within its own entry), so the engine
    still breaks the tie by file order. Use disjoint values on one shared claim
    instead.
  - **Two globs on one claim.** These are conservatively treated as conflicting
    (the check does not try to prove two globs disjoint); use literal values, or a
    literal tested against a glob, if a rejection is spurious.
  A general entry in one file and a principal-scoped entry for the same target in
  another do **not** conflict — the engine resolves that pair deterministically
  (refinement beats order).

  This load-time check compares targets **semantically**, not by their written
  form: two *different* target patterns that could tie on the same request — e.g.
  `tool:read_*` and `tool:*_file`, which both match `read_file` at equal
  specificity — are detected and rejected, exactly as if they were spelled
  identically. Only target glob pairs the engine can prove disjoint (e.g.
  `tool:read_*` and `tool:write_*`) are allowed to coexist across files.

### JWT exhaustive-allowlist rule (§ 5.2)

When the `mcp.capabilities` array is **present** in the token (even when empty), it
acts as an exhaustive allowlist for that invocation. Any target not explicitly
listed is denied with `AUTHORIZATION_FAILED`, regardless of what the manifest
permits:

| JWT `mcp.capabilities` value | Effect |
|---|---|
| `["tool:read_file"]` | only `read_file` is accessible; `query_db` is denied even if the manifest allows it |
| `[]` (present but empty) | every target is denied for this invocation |
| field absent entirely | no JWT restriction; the manifest alone governs |

The absence of a JWT token entirely (no `--jwks-uri` configured) is not an
empty allowlist — the manifest governs without any JWT narrowing.

For an **http(s) `resource:` claim**, the URI's query component (everything from
the first `?`) has its own matching rule. A claim that carries a query pins it
**exactly** — `resource:https://api/data?format=json` grants only that precise
query. A claim with **no** query component is a path-only wildcard that accepts
**any** (or no) query string on the target: `resource:https://api/search/*`
grants both `https://api/search/results` and `https://api/search/results?page=2`.
There is no glob syntax for the query component itself, so a broad REST grant is
written as the path-only wildcard. (This query rule applies only to http(s)
resource URIs; for other schemes a `?` is parsed as a condition suffix.)

Server-initiated `sampling/createMessage` is outside this rule: the upstream,
not the token-bearing client, initiates it, so no token is attributable to the
request and the manifest's `system:` opt-in alone governs (see § 2b and
ADR-0001). A present-but-empty `mcp.capabilities` claim does not block
sampling the manifest opts in to.

### Cross-argument intersection (§ 5.2.1)

When manifest and JWT both constrain the same target but on *different* arguments,
both condition sets must pass — neither side waives the other's constraint:

```
Manifest: tool:read_file with allowedValues(path=/reports/*)
JWT:      tool:read_file?mode=ro

→ The call is allowed only when path ∈ /reports/* AND mode == "ro".
  Satisfying the JWT mode condition does not relax the manifest path rule,
  and vice-versa.
```

A side that is silent about an argument imposes no constraint on it — it never
grants access that the other side would deny.

## 4. Resource pattern reference

Every `target` field has the form `<prefix>:<pattern>`. The prefix
determines the target type; the pattern is matched against the appropriate
MCP field using `path.Match` glob semantics. Matching is namespace-scoped:
a `tool:` constraint is never consulted for a `resources/read` request.

### Tool-name patterns (`tool:`)

Tool names rarely contain `/`, so `*` effectively matches any suffix.

| `target` value | Matches tool name | Does **not** match |
|---|---|---|
| `tool:get_customer` | `get_customer` only | `get_customers`, `get_customer_by_id` |
| `tool:get_*` | `get_customer`, `get_invoice`, `get_report` | `list_customers`, `create_customer` |
| `tool:*_report` | `get_report`, `create_report`, `delete_report` | `report_get`, `reports` |
| `tool:read_file` | `read_file` only | `read_files`, `read_file_metadata` |
| `tool:*` | (rejected by `eunox validate` — too broad) | — |

### Resource URI patterns (`resource:`)

Resource URIs contain `/`, so `*` matches within a single path segment.

| `target` value | Matches URI | Does **not** match |
|---|---|---|
| `resource:file:///data/reports/*` | `file:///data/reports/q3.pdf` | `file:///data/q3.pdf` |
| `resource:db://warehouse/*` | `db://warehouse/orders`, `db://warehouse/customers` | `db://analytics/orders` |
| `resource:file:///data/public/readme.txt` | exact URI only | any other URI |
| `resource:*` | (rejected — too broad) | — |
| `resource:api://*` | (rejected — too broad) | — |

### Prompt patterns (`prompt:`)

Matched against the prompt `name` from `prompts/get` / `prompts/list`.

| `target` value | Matches prompt name | Does **not** match |
|---|---|---|
| `prompt:code_review` | `code_review` only | `code_review_v2` |
| `prompt:summarize_*` | `summarize_doc`, `summarize_pr` | `code_review` |
| `prompt:*` | any prompt name | — |

### System primitive patterns (`system:`)

Only one value is defined; wildcards are not permitted.

| `target` value | Matches |
|---|---|
| `system:sampling/createMessage` | the server-initiated sampling channel |

Rules:

- **The prefix is required.** A `target` value without a recognized
  prefix is rejected at manifest load (fail-closed).
- **`*` matches any characters except `/`.** Resource URIs contain `/`
  separators, so each `*` matches within one path segment only.
- **Bare `tool:*` / `tool:**` and `resource:*` / `resource:**` are rejected**
  by `eunox validate` — too broad. (A target that is nothing but stars
  matches everything, so `**` is rejected alongside `*`.) `prompt:*` is the sole
  exception (prompt namespaces are server-enumerated and small; even so, prefer
  enumeration in production).
- **Wildcards in a `resource:` URI scheme or authority are rejected** — scope
  resources to a concrete scheme/authority and put any globs in the path.
- **Wildcards in an opaque `resource:` URI are rejected** — opaque URIs (a
  scheme with no `//` authority and no `/` path, e.g. `urn:…` or `mailto:…`)
  match by exact equality only; a glob in one is rejected at load.
- **Wildcards in `system:` are rejected** — system targets are fixed identifiers.
- **Most-specific match wins.** If two entries both match, the one with the
  higher specificity score is used. An exact match always wins; otherwise the
  score rewards literal characters and penalizes wildcards, counting **all**
  literal characters in the pattern — including any after a wildcard. So
  `tool:*_admin` (more literal content) outranks the catch-all `tool:*`, and the
  winner does not depend on the order entries appear in the manifest.

## 5. Conditions cookbook

`conditions` is an array of typed shapes from
`pkg/capability/condition.go`. Every entry has a `type` discriminator.
Unknown types are denied at the proxy, so spelling matters.

### Nested arguments — the `$.` path selector

The `argument` field of the value-matching conditions (`allowedValues`,
`allowedOperations`, `allowedExtensions`, `allowedTables`, `recipientDomain`)
names a **top-level** call argument by default. Some tools nest the value you
want to police inside an object argument — e.g. a call whose arguments are
`{"request": {"owner": "acme-corp"}}`. To reach into it, prefix the path with
`$.` and separate the keys with dots:

```yaml
- target: tool:create_issue
  actions: [call]
  conditions:
    - type: allowedValues
      argument: $.request.owner    # reads arguments["request"]["owner"]
      values: ["acme-corp"]
```

Rules:

- The `$.` prefix is **required** to opt into traversal. A plain `argument:`
  value is always an exact top-level key — so an argument literally named
  `a.b` keeps its meaning and is never silently traversed (the manifest never
  matches an alternative argument).
- It **fails closed**: a missing key anywhere along the path, a segment that
  lands on a non-object, or a malformed path (`$.a..b`, a trailing dot) all deny
  the call, exactly like a missing top-level argument.
- Drift detection checks the path's **root key** (`$.request.owner` → `request`)
  against the tool's live top-level `inputSchema`; the nested remainder is below
  the granularity the proxy can see.
- For arguments that are not flat scalars or simple nested objects (arbitrary
  array indexing, etc.), delegate to an external engine with a `policy`
  condition instead.
- A top-level argument whose name itself begins with `$.` (a legal JSON object
  key, e.g. `$.x`) cannot be referenced by writing `argument: $.x` — that is
  always read as a traversal path into `arguments["x"]`. Escape it with an
  extra leading `$`: `argument: $$.x` names the literal top-level key `$.x`.
  The escape only strips one leading `$`; it does not itself support further
  traversal (`$$.x` is always a literal key, never a path). If an argument's
  literal name itself begins with `$$.` (or more dollars), add one more
  leading `$` than it has: `argument: $$$.x` names the literal top-level key
  `$$.x`, `$$$$.x` names `$$$.x`, and so on — each extra `$` unwraps exactly
  one level, so a name with any number of leading dollars is always
  reachable and never collides with a shorter escape.

```yaml
# Rate-limit, time-window, and IP-allowlist on a reporting tool
- target: tool:get_invoice
  actions: [call]
  conditions:
    - type: maxCalls        # at most 60 calls per minute
      count: 60
      windowSeconds: 60
    - type: timeWindow      # restrict to a fiscal-year window
      notBefore: "2026-04-01T00:00:00Z"
      notAfter: "2026-12-31T23:59:59Z"
    - type: ipRange         # internal network only
      cidrs: ["10.0.0.0/8"]
      # Note: ipRange always denies in stdio transport mode because there is no
      # network connection to extract a source IP from. Only use ipRange on
      # routes that are reachable over the HTTP transport.

# Restrict file exports to safe types
- target: tool:export_data
  actions: [call]
  conditions:
    - type: allowedExtensions
      argument: path
      extensions: [".csv", ".json"]

# Database query tool: restrict tables (condition) and redact a column (directive)
- target: tool:query_sales
  actions: [call]
  conditions:
    - type: allowedTables
      argument: table
      tables: ["sales"]
      columns:
        sales: ["customer_id", "amount", "ts"]
  directives:                  # response obligation — see § 5a
    - type: redactFields       # proxy masks this field's value in the allowed result
      fields: ["sales.customer_email"]

# Email tool: allowlist recipient domains
- target: tool:send_email
  actions: [call]
  conditions:
    - type: recipientDomain
      argument: to
      domains: ["example.com"]
```

Each recipient is parsed as `local@domain`; both halves must be non-empty, free
of internal whitespace, and the domain half must not contain a second `@`.
Malformed addresses — `user@` (empty domain), `@example.com` / `@@example.com`
(empty local part), `user@@example.com` (a second, embedded `@` whose parsed
domain would be `@example.com`), or `user@ example.com` (whitespace around the
`@`) — are denied with an explicit `invalid recipient email` error, distinct
from the `recipient domain "…" is not allowed` policy denial. This keeps audit
records actionable: an operator can tell a genuine unapproved-domain attempt
apart from a tool that received a malformed recipient.

The `domains` list itself is validated at manifest load: an empty list, an
empty or whitespace-only entry (`domains: [""]`), or an entry that begins with
`@` (an accidental full-address paste such as `@example.com` instead of the bare
`example.com`) is rejected with a config error rather than shipped as a dead or
overly broad allowlist entry — so a typo surfaces at `validate` time instead of
silently denying every call or, worse, admitting a malformed double-`@`
recipient.

`maxCalls` counts only **admitted** calls. A call that is over the limit is
denied without being recorded, so the sliding window holds exactly the allowed
calls and clears `windowSeconds` after the oldest of them — a client that keeps
retrying while rate-limited does not extend its own lockout (and does not grow
the counter's backing store). Each `RATE_LIMITED` denial carries a `retryAfter`
hint in its details (whole seconds until a slot frees up) so a well-behaved
caller can back off instead of hammering the limit.

A `maxCalls` slot is consumed only when the call is allowed by **every** other
condition on the same constraint. The engine evaluates the pure predicates
(`allowedValues`, `timeWindow`, `ipRange`, `allowedExtensions`, …) first and
checks `maxCalls` last, regardless of where `maxCalls` appears in the
`conditions` list, so a call denied by another condition does not burn a
rate-limit slot. You therefore do not need to order `maxCalls` last by hand. A
corollary: when a call would fail both `maxCalls` and another condition, the
other condition's denial code is reported (the rate limit is never reached).

A capability may carry **several** `maxCalls` conditions to layer rate limits of
different lengths — e.g. 30/minute *and* 500/hour — and each is counted in its
own sliding-window bucket (keyed in part by `windowSeconds`), so the two never
interfere; both must pass. When several `maxCalls` conditions are present the
`retryAfter` hint on a denial is the tight per-bucket estimate (time until the
denying window's oldest over-limit call ages out), the same value a single
`maxCalls` reports — not the whole `windowSeconds`. What is **rejected at load** is two `maxCalls`
conditions on one capability that share the same `windowSeconds`: equal-length
windows address the same bucket, so each admitted call would be counted once per
condition and the effective limit would collapse to the lower `count` divided by
the number of conditions (`validate` reports `conditions N and M are both
maxCalls with the same windowSeconds`). Two equal windows carry no meaning a
single condition lacks — they are satisfied exactly when the lower `count` is —
so combine them into one `maxCalls` with that lower `count`.

> **Concurrency — multiple `maxCalls` on one constraint.** A *single* `maxCalls`
> condition is admitted atomically: the check and the slot consumption are one
> operation, so its limit holds exactly even under simultaneous requests. A
> constraint that carries **two or more** `maxCalls` conditions is also admitted
> atomically **across** all of its buckets: the engine records a call in every
> bucket only if every bucket has headroom, and otherwise records nothing (one
> Lua `EVAL` over all buckets on Redis, one mutex spanning all keys in memory). So
> two same-session requests arriving at the same instant can no longer both be
> admitted past a shared limit — the committed count is exact for single- and
> multi-condition constraints alike. (Earlier releases admitted multiple
> `maxCalls` in two phases — a non-committing check then a separate per-bucket
> commit — which left a narrow cross-bucket window that could over-admit under
> concurrent load; that window is now closed.)

The full list of shipped condition types: `timeWindow`, `ipRange`,
`allowedOperations`, `allowedExtensions`, `allowedTables`, `maxCalls`,
`recipientDomain`, `allowedValues`, `sequenceBlock`, the `policy` hook
(library-only — requires an evaluator registered via `WithPolicyEvaluator`;
denied fail-closed in the stock binary), and the `custom` escape hatch
(library-only — requires a handler registered at construction via
`WithConditionHandler(capability.ConditionTypeCustom, …)` that dispatches on the
condition's `name`; denied fail-closed in the stock binary).

> **`redactFields` is a directive, not a condition.** It mutates the
> response rather than allowing or denying, so it lives under `directives`
> (§ 5a), and `conditions` is strictly boolean predicates.

**`timeWindow`** — restricts calls to a not-before / not-after window. Both
bounds are optional, but at least one is required, and each must be an RFC3339
timestamp (e.g. `2026-04-01T00:00:00Z`). The window is **half-open**:
`[notBefore, notAfter)` — a call at exactly `notBefore` is allowed, and a call at
exactly `notAfter` is denied. This matches the common `[from, until)` scheduling
convention, so "allow until `2026-12-31T23:59:59Z`" closes precisely at that
instant rather than admitting one more call at it. The bounds are parsed at
`validate` time, so a typo'd timestamp (e.g. `2026-13-01T00:00:00Z`), a window
with neither bound, or an empty window (`notBefore` at or after `notAfter`) is
rejected at load rather than denying the first live request with a
`CONDITION_FAILED` code that reads like a legitimate denial:

```yaml
- target: tool:get_invoice
  actions: [call]
  conditions:
    - type: timeWindow
      notBefore: "2026-04-01T00:00:00Z"
      notAfter: "2026-12-31T23:59:59Z"
```

**`ipRange`** — restricts calls to source IPs inside the listed CIDRs. The
`cidrs` list is required and must be non-empty, and every entry is parsed at
`validate` time, so a malformed CIDR (e.g. `10.0.1/24`) is rejected at load. A
CIDR with **host bits set** is rejected too: `10.0.0.5/8` is almost always a
`/32`-vs-network mistake that would silently widen the allowlist to all of
`10.0.0.0/8`, so write the network address (`10.0.0.0/8`) or use `/32` to allow
just that one host. Note that `ipRange` always denies under the **stdio**
transport — there is no network connection to read a source IP from — so use it
only on routes reachable over the HTTP transport:

```yaml
- target: tool:get_invoice
  actions: [call]
  conditions:
    - type: ipRange
      cidrs: ["10.0.0.0/8", "2001:db8::/32"]
```

On a `system:sampling/createMessage` opt-in, `ipRange` is evaluated against the
**session's originating client IP** — the address the HTTP client connected from
when it opened the session. Server-initiated sampling carries no request of its
own, so this is the only meaningful source IP for the channel; it lets you allow
sampling only for sessions opened from a trusted network. As with any other
target, `ipRange` always denies sampling under the **stdio** transport (no client
IP exists there).

**`allowedValues`** — restricts a named tool argument to a set of allowed
literal values or glob patterns:

```yaml
- target: tool:read_file
  actions: [call]
  conditions:
    - type: allowedValues   # restrict the path argument
      argument: path
      values: ["/reports/*", "/public/*"]
```

The `argument` field names the tool parameter to check; `values` is a
list of exact strings or glob patterns (e.g. `/reports/*` matches
`/reports/q3.pdf`).

> **Unquoted dates are kept as literal strings.** A bare date such as
> `2026-01-01` in a YAML `values` list is loaded as the string `"2026-01-01"`,
> matching what a tool argument carries — it is **not** rewritten to an RFC3339
> timestamp (`2026-01-01T00:00:00Z`), which earlier silently denied calls whose
> argument was the plain date. Quoting (`"2026-01-01"`) is therefore
> optional, but still recommended for clarity.

> **Quote string-like numbers.** A `values:` (or argumentSchema `enum:`) entry
> whose unquoted text YAML auto-types into a *different* number is **rejected at
> load** rather than silently rewritten: `010` parses as octal `8`, `1.0` as the
> integer `1`, `+5` as `5`. A leading-zero account/ZIP/country code, or any value
> meant as a string, must be quoted (`"010"`); to match a number, write its
> canonical form (`8`). Numbers whose text already round-trips (`200`, `1.5`,
> `-3`) are accepted unquoted as numeric values. **JSON manifests** are held to a
> narrower check — a JSON number is unambiguous, so `1.0`/`1e3` load fine — but an
> integer beyond float64 precision (e.g. `12345678901234567890123`) is likewise
> **rejected at load**, because it would otherwise round to a different value and
> silently widen the allowlist. Quote it to mean the string, or write a value that
> round-trips exactly.
>
> Manifests load through one hardened path regardless of file extension: `.yaml`,
> `.yml`, `.json`, and an extensionless file all get **duplicate-key rejection** and
> **multi-document rejection**, so a duplicated security-critical key (e.g. two
> `enforcement:` values) can never silently last-win.

> **Glob semantics.** A **string** value is matched *only* as a glob — there is
> no exact-equality shortcut — so the metacharacters `*`, `?`, and `[...]` are
> **not** treated literally. A metacharacter-free pattern still matches itself
> (e.g. `"active"` admits `"active"`, because `path.Match("active","active")` is
> true), so plain literal values keep working; but a pattern that *does* contain
> metacharacters matches only what the glob matches, never the literal pattern
> text itself. For example `values: ["[0-9]"]` admits a single digit (`"5"`) and
> denies the literal string `"[0-9]"`. The wildcards work like this:
> - **`*` (alone)** and **`**` (alone)** match *any string* value, including one
>   that contains `/`. Write `values: ["*"]` to mean "allow any string value" —
>   that is now exactly what it does. (Before, a bare `*` matched only values
>   with no `/`, so it silently denied file paths and URIs; see the migration
>   note below.) A **non-string** argument — a number, boolean, or null — is only
>   ever matched by exact equality, so `["*"]` does not allow it. Numbers match by
>   numeric **value**, not Go type: a manifest `values: [42]` (decoded from YAML as
>   an integer) matches a request argument `42` (decoded from JSON as a float), and
>   vice versa. A boolean is never numerically equal to `1`/`0`.
> - A **`*`** inside a pattern matches a run of characters that does **not**
>   cross `/`. So `/reports/*` matches `/reports/q3.pdf` but **not**
>   `/reports/sub/q3.pdf` or `/internal/secret.txt` — it matches exactly one
>   path segment after `/reports/`.
> - A **`**` path segment** matches zero or more `/`-delimited segments, so
>   `/reports/**` matches both `/reports/q3.pdf` *and* `/reports/sub/q3.pdf`.
>   Use it when you want to allow a whole subtree. A **hard limit of 1000
>   `/`-separated segments** applies to the value being matched against a `**`
>   pattern: a value with more segments fails the match (fail-closed deny). The
>   cap is far above any legitimate file path or URI depth and bounds the
>   segment-matcher's memory so a caller cannot drive an unbounded allocation by
>   supplying a value with an enormous slash count.
> - **Subtree confinement rejects traversal.** A path-style pattern (one
>   containing `/`, e.g. `/reports/**`) is meant to confine a value to that
>   subtree, so a value carrying a `.` or `..` path segment is denied even when its
>   literal text starts with the confined prefix — `/reports/../../etc/passwd`
>   matches `/reports/**` textually but escapes the subtree once the upstream
>   resolves it. The guard first folds the separator/dot aliases an upstream would
>   resolve so the traversal cannot be smuggled past it: `\` is treated as a
>   separator and the value is percent-decoded once (`%2f` → `/`, `%2e` → `.`), so
>   `/reports/..%2f..%2fetc%2fpasswd` and `/reports/..\..\etc\passwd` are rejected
>   too. A malformed percent-escape fails closed (deny). Only an exact `.` or `..`
>   segment is rejected — dotfiles (`.env`) and names that merely contain dots
>   (`a..b`) are fine. This applies only to path-style patterns; in a non-path
>   `allowedValues` (no `/` in the pattern) a `..` is an ordinary literal.
> - **An encoded separator does not widen a single-segment scope.** A single `*`
>   (or `?`/`[…]`) confines a value to one segment, e.g. `/reports/*` permits only
>   direct children of `/reports`. A value that smuggles an *encoded* separator into
>   that segment — `/reports/sub%2fsecret` (a `%2f` an upstream resolves to `/`) —
>   is rejected (fail closed), because the proxy cannot know whether the upstream
>   decodes it and a single `*` must not span a separator the operator scoped out. A
>   value carrying a *literal* `%` that is not an encoded separator (e.g.
>   `report_50%2aoff` → `*`) still matches its own segment. This guard applies per
>   single-segment element, not per pattern: a `**` already spans separators, so an
>   encoded separator inside a `**` subtree is admitted (`/reports/**` still matches
>   `/reports/a%2fb`) — only the `.`/`..` traversal scan applies there, and it still
>   blocks an escape such as `/reports/..%2f..%2fetc`.
> - **This holds for a slashless pattern too.** A pattern with no `/` at all, such
>   as `*.csv` or `[a-z].log`, is still a single-segment grant: `path.Match`'s `*`
>   never crosses `/`, so the operator meant "any CSV here, no subpaths." A value
>   smuggling an encoded or backslash separator — `..%2f..%2fetc%2fpasswd.csv`,
>   `sub%2fsecret.csv`, or `..\..\etc\passwd.csv` — is therefore rejected (fail
>   closed) rather than matched on its literal `%`/`\` bytes, closing the same
>   traversal class the slash-bearing patterns confine. A benign leaf with a
>   non-separator encoding (`q3%20report.csv`) or a literal `%` (`50%off.csv`) still
>   matches.
>   But in a **mixed** pattern that combines a single `*` with `**` (e.g. `/a/*/**`),
>   the single-`*` segment still confines its own segment: a value with an encoded
>   separator in that segment is rejected (`/a/*/**` does **not** match
>   `/a/x%2fy/z`), while one whose encoded separator lands in the `**` portion is
>   admitted (`/a/*/**` matches `/a/b/x%2fy`). The presence of `**` elsewhere in the
>   pattern does not relax the confinement of a co-occurring single `*`.
> - **An unmatchable pattern is rejected at load.** A pattern that can never match
>   any value is a silently dead, deny-all grant, so the loader rejects it as an
>   error rather than shipping it. Three cases:
>   - a path-style pattern that itself contains a literal `.` or `..` segment
>     (e.g. `/**/../x`, `/a/./b`) — the confinement scan above denies every value
>     carrying the required `.`/`..` segment first;
>   - a pattern whose *literal* text carries an *encoded* path separator (`%2f` or
>     `%5c`, e.g. `a%2fb`) — the runtime confinement denies any value that decodes
>     to contain a separator, so the only value the pattern could match is itself
>     denied (write a literal `/` for a path separator). The same characters inside
>     a bracket class are ordinary class members, so `[a%2f]` (a class matching one
>     of `a`, `%`, `2`, `f`) stays valid;
>   - a `**` pattern with more `/`-separated segments than the runtime match cap —
>     the segment matcher refuses to match beyond the cap.
> - A value you intend literally but that contains `*`, `?`, or `[` (a filename
>   glob, a regex-looking token, a value like `a[1]`) is reinterpreted as a
>   pattern (`a[1]` matches only `1`; `report*` matches `report_secret`).
>
> **These rules apply to `allowedValues` argument *values* only.** Target
> patterns on `tool:`/`resource:` entries (and JWT target names) match through a
> single-segment `path.Match`, where `**` is just two single-`*` stars and does
> **not** cross `/`. A `resource:` target like `file:///reports/**` therefore
> gets single-segment matching, not a subtree.
>
> **Migration note (pre-1.0).** Two matching behaviours changed: a bare `"*"`
> (or `"**"`) now matches any value rather than only single-segment values, and
> a `"**"` path segment now crosses `/` (it previously behaved like a single
> `*`). Patterns built from a single `*` — like `/reports/*` — are unchanged.
> Audit your manifests for bare `"*"` entries you did not intend as allow-all,
> and for `"**"` patterns you expected to behave like `"*"`.
>
> If you need a literal value that contains a glob metacharacter, there is
> currently no escape — keep such values out of `allowedValues` and enforce them
> with a stricter `argumentSchema` `enum`/`pattern` instead. A *malformed* glob
> pattern in `allowedValues` (e.g. an unbalanced `[`) is rejected by `eunox
> validate` and on proxy startup, the same way an invalid target glob is — so a
> broken pattern surfaces as a load error rather than a silently over-restrictive
> policy. String values no longer have an exact-match path at all: a *well-formed*
> metacharacter pattern such as `[0-9]` matches only what the glob matches, never
> its own literal text, and a *malformed* glob such as `/reports/[invalid` is
> refused at load because the loader cannot tell an intended literal from a
> mistyped glob. Likewise a malformed `argumentSchema` `pattern` regex is rejected
> at load — the regex is compiled once when the manifest loads, so `validate`
> reports the bad pattern up front rather than letting it surface as a per-request
> denial.

> **`argumentSchema` `pattern` matches a *substring* — anchor it with `^…$`.**
> The `pattern` keyword follows JSON-Schema / ECMA-262 semantics: it matches when
> the regex is found **anywhere** in the value, not when it matches end-to-end. So
> `pattern: "[0-9]+"` admits `"abc123"` (it *contains* digits), and
> `pattern: "SELECT|INSERT"` admits `"DROP TABLE users; SELECT 1"` (it *contains*
> `SELECT`). For a security policy this is almost never what you want — anchor the
> pattern so the **whole** value must match: `^[0-9]+$` admits only all-digit
> strings, and `^(?:SELECT|INSERT)$` admits only those exact verbs. The proxy does
> **not** anchor for you: an unanchored "starts-with" idiom like `^[A-Z]` is a
> legitimate use, so anchoring is the author's choice. A SQL-operation
> allowlist is also better expressed with the `allowedOperations` condition than a
> bare `pattern`.

**`allowedOperations`** — restricts the SQL verb or operation keyword
extracted from a named tool argument. The `argument` field is required; an
`allowedOperations` condition without it is rejected at `validate` time and
fails closed at runtime. The `operations` list must also be **non-empty**: an
empty list matches no operation and would deny every call, so (like the empty
`values`/`cidrs`/`domains` lists of the other allowlist conditions) it is
rejected at `validate` time rather than silently shipping a deny-all policy:

```yaml
- target: tool:query_db
  actions: [call]
  conditions:
    - type: allowedOperations
      argument: sql            # the tool parameter that carries the SQL string
      operations: ["SELECT"]   # blocks INSERT, UPDATE, DELETE, DROP, …
```

The named argument must carry a string. An absent argument, or one whose value
is an empty or whitespace-only string, denies with `MISSING_CONTEXT`; an
argument that is present but holds a non-string value (a number, boolean, or
array) denies with `CONDITION_FAILED` — so the audit trail distinguishes a
field the tool omitted from one it supplied with the wrong type.

> **`allowedOperations` checks only the first whitespace-delimited token.** It is
> a coarse verb gate, not a SQL parser. A leading CTE (`WITH cte AS (…) DELETE …`),
> an `EXPLAIN`/`SET` prefix, or a leading comment makes the first token something
> other than the effective verb, so `operations: ["SELECT"]` does **not** block a
> statement whose first token is `WITH`. Use it to constrain simple, single-verb
> statements; for untrusted or CTE-bearing SQL, pair it with database-level
> controls (read-only roles, grants) rather than relying on it alone.
>
> Statement stacking is the dangerous case. `operations: ["SELECT"]` does **not**
> stop `SELECT 1; DROP TABLE users`: only the first token (`SELECT`) is inspected,
> so the call is allowed and the trailing `DROP` reaches the upstream and executes
> if the database driver permits multiple statements per call. Unlike the
> CTE/`EXPLAIN` examples above (which cause false *denials*), this is an
> under-block — a forbidden operation slips through. Disable multi-statement
> execution at the driver or connection level, and treat `allowedOperations` as
> defense-in-depth over a read-only database role, never as the sole control on
> untrusted SQL.

**`allowedExtensions`** — restricts a tool's file-path argument to an allowlist
of file extensions. The `argument` field is required (a condition without it is
rejected at `validate` time and fails closed at runtime) and names the parameter
carrying the path. The `extensions` list must be **non-empty** — an empty list
matches no extension and denies every call, so it is rejected at `validate` time. That parameter may be a single path string **or an array of
path strings** — e.g. `read_multiple_files`' `paths` — in which case every path
must clear the allowlist or the whole call is denied. If the array carries a
**non-string item** (a number, boolean, or null), the call is denied fail-closed
rather than the offending item being silently skipped — a structurally malformed
argument is never treated as a smaller, valid one. The other array-accepting
conditions apply the same rule: `recipientDomain` to its recipient list, and
`allowedTables` to both its table list and a table's `columns` list. For
`allowedTables`, the object form (`{table: "...", columns: [...]}`) is held to
the same standard: an object that carries no non-empty `table` entry — for
example `{"columns": ["id"]}`, whether on its own or as one element of an array —
is structurally malformed and denied fail-closed with `CONDITION_FAILED`, not
reported as a missing or empty argument (the value is present, it just omits the
required `table` entry). The same holds when the argument itself is present but
is neither a string, an object, nor an array — for example a number or boolean:
the call is denied with `CONDITION_FAILED` for the type mismatch rather than
`MISSING_CONTEXT`, since the field was supplied, just not as a table reference.

All of these string comparisons are **case-insensitive**. `allowedExtensions`
lowercases extensions on both sides, `recipientDomain` lowercases domains,
`allowedOperations` folds case, and `allowedTables` lowercases both table names
and column names (including the per-table keys of the `columns` map). So
`tables: ["users"]` admits an argument table `USERS`, and a column allowlist
written `columns: { users: ["name"] }` denies `Password_Hash` exactly as it
denies `password_hash`. This matters for `allowedTables` in particular: MySQL,
SQL Server, and many other databases treat table and column identifiers
case-insensitively, so a case-sensitive policy match would be a silent bypass —
a request spelling a restricted column in a different case would slip through.
If you need case-sensitive identifier matching (e.g. quoted PostgreSQL
identifiers), that is not currently supported; open an issue describing the use
case.

Allowlist entries are also **whitespace-trimmed** before matching, exactly like
the request values they are compared against, so a stray space in
`domains: ["example.com "]`, `operations: ["SELECT "]`, or `tables: [" users"]`
cannot silently turn an entry into a dead rule that denies every call. To catch
the typo at its source, `eunox validate` rejects a `recipientDomain`,
`allowedOperations`, or `allowedTables` entry whose value carries leading or
trailing whitespace.

An **empty column allowlist** for a table — `columns: { users: [] }` — is
rejected at `validate`/load time. At runtime such a key would deny every access
to that table unconditionally (a request that sends no columns fails
`MISSING_CONTEXT`, and any request that does send columns fails because none are
in the empty allowlist), even though the table is listed in `tables` — a
permanently unfulfillable condition. To allow **any** column for a table, omit
it from `columns` entirely; to deny the table outright, remove it from `tables`.

Because table names fold case, a `columns` map must not carry two keys that
differ only in case (`columns: { users: [...], Users: [...] }`): they address
the same table, and collapsing them would non-deterministically drop one
allowlist. Such a manifest is **rejected at load** (`validate` time and proxy
startup) so the contradiction surfaces as an operator error rather than an
ambiguous runtime policy — merge the columns under a single key.

The `tables` list must be **non-empty**. Because a `columns` restriction is
consulted only for a table that is already in the `tables` allowlist, an empty
`tables` list admits no table at all and denies every call — a `columns` map
cannot rescue it. An empty `tables` list is therefore rejected at `validate`
time rather than silently shipping a deny-all policy.

```yaml
- target: tool:read_multiple_files
  actions: [call]
  conditions:
    - type: allowedExtensions
      argument: paths          # a single path string, or an array of paths
      extensions: [".csv", ".json", ".txt"]
```

Matching is **suffix-based on the file name**: a path clears the allowlist when
its name ends with one of the listed entries on a dot boundary. Entries may be
written with or without the leading dot, and case is ignored (`".env"`, `"env"`,
and `".ENV"` are equivalent). A file with no dot at all (`Makefile`, `id_rsa`) has
no extension and is denied — it can never satisfy an extension allowlist.

**Compound extensions are honored in full.** An entry like `.tar.gz` matches
`backup.tar.gz` and **not** a bare `data.gz` — listing the compound suffix means
the compound suffix, never just its last segment. (Earlier builds took only the
final dot, so `.tar.gz` silently denied every file *and* a `.gz` entry secretly
admitted `*.tar.gz`; both are fixed.) Conversely, a single-component entry matches
on its dot boundary alone: `.gz` admits **any** name ending in `.gz`, including
double extensions such as `archive.tar.gz` and `payload.exe.gz`, but not `.tgz`
(the leading dot is a hard boundary). If you must admit a true single-extension
file and reject double extensions, extension matching cannot express that —
constrain the path with `allowedValues` instead.

> **Reading a denial in the audit log.** A denial record's `details.extension`
> reports the file's **full compound suffix** (e.g. `.tar.bz2` for
> `backup.tar.bz2`), which is presentational — it is *not* the exact segment the
> allowlist matched on. Do not infer the inverse from it: seeing `.tar.bz2`
> denied does **not** mean `.tar.gz` would also be denied. With
> `extensions: [".gz"]`, `backup.tar.gz` is **admitted** (it ends in `.gz`) while
> `backup.tar.bz2` is denied — even though both look like "compound archives".
> The decision is always "does the name end in a listed suffix on a dot
> boundary?"; the record's full `filePath` is the unambiguous identifier.

> **Security note — not a defense against double-extension smuggling.**
> `allowedExtensions` checks the file-name suffix, not the file's content or
> "real" type. A `.txt` entry admits `malware.exe.txt`, a `.csv` entry admits
> `payload.exe.csv` and `script.sh.csv`, and a `.gz` entry admits `payload.exe.gz`
> — each genuinely ends in the allowed suffix, so an agent can bypass an
> extension allowlist by appending an allowed extension to any file name. This is
> inherent to suffix matching (single-extension `filepath.Ext` matching has the
> same property — `filepath.Ext("malware.exe.txt")` is `.txt`), so do not reach
> for `allowedExtensions` as a content-type gate or a guard against disguised
> executables. When the risk is a mislabeled or double-extension payload, pin the
> exact paths with `allowedValues` and validate content downstream.

Dotfile names work as ordinary entries: `extensions: [".env"]` matches `/app/.env`,
and `[".gitignore"]` matches `.gitignore`. A leading dot with no further dot
(`.env`, `.bashrc`) is itself the extension, while a multi-dot name matches any
listed suffix — `.env.local` matches both `.local` and `.env.local`.

Because the leading dot is stripped on both sides of the comparison, an entry
**cannot distinguish a bare dotfile from a same-suffixed regular file**:
`extensions: [".env"]` (equivalently `["env"]`) allows *both* the dotfile
`/app/.env` *and* any `/app/config.env`. This matters when you use
`allowedExtensions` to gate secrets — allow-listing `*.env` config files silently
also permits a bare `.env` secret, and vice versa. If you need to admit one but
not the other, constrain the path itself rather than relying on the extension
alone — e.g. an `allowedValues` pattern on the same argument
(`allowedValues: ["/app/config.env"]` admits the regular file without the bare
`.env`). Note `allowedValues` globs use `path.Match`, where `*` does not cross a
`/`, so `/app/*.env` matches `/app/config.env` but not `/app/sub/config.env`; use
an exact value or a per-segment pattern when a single `*` is too narrow.

> **Security note — a simple extension also admits compound-extension files.**
> Matching is suffix-based on a dot boundary, and the simple→compound direction is
> broader than it reads. A single-extension entry like `.gz` matches **both**
> `data.gz` **and** `archive.tar.gz`, because `.gz` is itself a suffix of `.tar.gz`.
> So `extensions: [".gz"]` does **not** mean "plain gzip files only" — it also admits
> every `.tar.gz`, `.tar.br.gz`, etc. Because `allowedExtensions` is allow-only (there
> is no deny list), there is **no** configuration that allows `.gz` while blocking
> `.tar.gz`. The compound→simple direction is the opposite: a compound entry like
> `.tar.gz` matches `backup.tar.gz` but **not** a bare `data.gz`. If you must admit
> plain single-extension files only, constrain the path itself with `allowedValues`
> rather than relying on the extension suffix.

> **Path normalization before the extension check.** The extension is derived from
> the form an upstream resolves: a `\` is folded to `/` and a single percent-decode
> is applied (`%2f` → `/`, `%2e` → `.`) so a directory component cannot be smuggled
> into the matched file name (`report.pdf%2fevil` resolves to the extension-less
> `evil` and is denied). Two refinements:
>
> - An **embedded NUL** (a literal `\x00` or a `%00` that decodes to one) is denied
>   outright — a NUL-truncating upstream would open the pre-NUL file, so the suffix
>   checked here would not be the suffix it opens (`evil.exe%00.csv` is rejected,
>   not admitted as `.csv`).
> - A **literal `%`** that is not a valid escape is a legal filename character for
>   an upstream that does not percent-decode, so the extension is checked on the
>   literal (separator-folded) form instead of denying. `report_50%_off.csv` clears
>   an `[".csv"]` allowlist. (This is unlike the `allowedValues` confinement guard,
>   which fails closed on a malformed escape — extension matching is not a
>   confinement feature.)

**`sequenceBlock`** — denies the call when any tool named in `afterTools` has
already been called (and allowed) earlier in the **same session**. This is
cross-tool sequencing — "deny B after A" — which a stateless policy engine
(OPA, Envoy `ext_authz`) cannot express, because it has no memory of what ran
before in the session.

```yaml
# Block any external write once credentials have been read this session.
- target: tool:write_external
  actions: [call]
  conditions:
    - type: sequenceBlock
      afterTools: [read_credentials]   # deny write_external if read_credentials ran first
```

- `afterTools` is required and must be non-empty; an empty list **fails closed**
  (the call is denied). Each entry names an antecedent by its namespace: a bare
  entry (e.g. `read_credentials`) or an explicit `tool:` prefix selects the
  **tool** namespace, and a `prompt:`, `resource:`, or `system:` prefix selects
  that namespace. The namespace is part of the match, so a tool and a prompt that
  share a bare name do **not** alias: `afterTools: [export]` is armed only by the
  *tool* `export`, while `afterTools: [prompt:export]` is armed only by the
  *prompt* `export`. Resource antecedents are addressed by their URI with the
  explicit prefix (e.g. `resource:file:///etc/passwd`). An entry that names
  nothing once its prefix is stripped and surrounding whitespace is trimmed (an
  empty string, a bare `tool:`, or `"  "`) is rejected at manifest load and
  **fails closed** at runtime: it can never match session history, so accepting
  it would let a rule whose every entry reduces to empty pass unconditionally.
  `eunox validate` additionally rejects a **colon-bearing entry whose prefix
  is not recognized** (e.g. `mcp:read_file`, or a case mismatch like
  `Tool:read_file`) at load time — only `tool:`, `resource:`, `prompt:`, and
  `system:` are recognized. This is deliberately strict: a resource antecedent
  must use the explicit `resource:` prefix, since a bare URI is indistinguishable
  from a prefix typo at load time. Finally, because an entry is matched
  **literally** against the concrete names recorded in session history — in every
  namespace, `resource:` included — a **glob metacharacter** (`*`, `?`, `[`, `\`)
  in a `tool:`, `prompt:`, `system:`, or bare (tool) entry is rejected at load: a
  pattern like `read_*` would never match a recorded name, so the block would look
  armed yet silently fail open — name the exact tool(s) instead. For a
  `resource:` entry only the wildcard `*` is rejected, since a resource URI
  legitimately contains `[` (an IPv6 literal host, `resource:file://[::1]/x`) or
  `?` (a query string) and neither can make a block look armed while never firing.
  A `*` can, and resource *targets* legitimately glob — so
  `afterTools: ["resource:file:///secrets/*"]` is refused even though
  `target: "resource:file:///secrets/*"` is valid; name the exact resource(s) in
  the antecedent.
- The rule is **directional**: with the policy above, `read_credentials` →
  `write_external` is blocked, but `write_external` → `read_credentials` is
  allowed (nothing read credentials before the write).
- It is **session-scoped**: history is keyed by session ID, so one session's
  activity can never gate another's. Recording happens whenever the antecedent
  **actually runs**: an allowed call arms the block, and a hard-denied call (the
  upstream is never reached) does not. The one subtlety is **audit (observe)
  mode**: an antecedent that is **forwarded despite a failing condition** —
  because its own constraint is `enforcement: audit`, *or* because the whole route
  runs under `--audit` — still runs, so it **does** arm the block even though its
  decision was "deny". Without this an observed antecedent would silently fail the
  block open for a later *enforced* `sequenceBlock`.
- **Concurrency limitation** (same-session parallel requests): the antecedent
  check and the antecedent's own recording are two separate, non-atomic
  operations across two requests. A client that deliberately fires the antecedent
  and the blocked tool **concurrently on the same session** can, in a narrow
  timing window, let the blocked tool slip through before the antecedent's record
  lands. MCP's request model is serial per session, so a compliant host never
  triggers this; it is documented rather than closed because no single-request
  atomic primitive can order one request's check against another request's write.
- It requires a call-counter backend (the same one `maxCalls` uses); with no
  counter, or an `EnforceRequest` carrying no `sessionId`, the condition fails
  closed.
- **Recording** is fail-closed too. Every allowed call is written to session
  history (so any tool can later serve as an antecedent), and if the counter
  backend errors during that write, the call that triggered it is **denied**
  (`CONDITION_FAILED`) rather than allowed. A swallowed write would leave the
  marker missing, and a later `sequenceBlock` lookup on that empty key would
  conclude the antecedent never ran and fail open — so a transient backend fault
  must not silently disarm the block. Because recording is indiscriminate, a
  counter-backend outage denies **every** allowed call in a session carrying a
  `sessionId`, not only calls to tools that gate a sequence.
- Distinguish it from `maxCalls`: `maxCalls: 1` on each of two tools limits each
  *independently* — the exfiltration pair (one read, one write) still executes
  once. `sequenceBlock` is what actually stops the read-then-write sequence.

**`policy`** — hands the allow/deny decision to an **external evaluator you
register via `WithPolicyEvaluator`**. This is a **library-only** extension
point: the shipped `eunox` binary embeds no policy engine — there is no
OPA/Rego interpreter linked in — so a `policy` condition is only live when you
import `pkg/enforcement` as a Go library and wire an evaluator. With no
evaluator registered (which is always the case for the stock binary) any
`policy` condition is **denied fail-closed**. Use it for logic the typed
conditions cannot express — for example by calling out to an OPA sidecar from
inside your evaluator. The standard `input` document your evaluator receives:

```json
{
  "arguments": { "path": "/reports/q3.pdf" },
  "target": {
    "type": "tool",
    "name": "read_file"
  },
  "claims": {
    "sub":       "alice",
    "iss":       "https://idp.corp.example",
    "task_id":   "task-007",
    "agent_id":  "bot-1",
    "tenant_id": "acme",
    "roles":     ["reader", "writer"]
  },
  "context": {
    "session_id": "uuid-of-this-session",
    "source_ip":  "10.0.0.5",
    "request_id": "opaque-per-call-id",
    "timestamp":  "2026-06-01T12:00:00Z"
  }
}
```

| Field | Always present? | Description |
|-------|-----------------|-------------|
| `input.arguments` | Yes (empty map `{}` if none) | Tool call arguments |
| `input.target.type` | Yes, when set by ManifestPDP | Namespace type: `"tool"`, `"resource"`, `"prompt"`, or `"system"` |
| `input.target.name` | Yes, when set by ManifestPDP | Bare resource name (prefix stripped) |
| `input.claims` | Yes (empty map `{}` if no JWT) | **Every** raw top-level claim from the verified token — the canonical `sub`, `iss`, `task_id`, `agent_id` plus any custom IdP claim (`tenant_id`, `roles`, `region`, `org_id`, …) and the nested `mcp` object. See the precedence rules below. |
| `input.context.session_id` | Yes | Proxy session UUID |
| `input.context.source_ip` | Yes (empty string if unavailable) | Client source IP |
| `input.context.request_id` | Yes | Opaque per-call correlation ID generated by the engine (a unique string; not guaranteed to be a UUID) |
| `input.context.timestamp` | Yes (empty string if unset) | RFC3339 timestamp |
| `input.directives` | Yes (empty `[]` if none) | The matched constraint's `directives` list — a policy may reason about, but not alter, the obligations that run on allow |

`input.arguments` is always an object — the **empty object `{}`** (never `null`)
for targets that take no arguments, e.g. `system:sampling/createMessage`. Policies
that must distinguish "no arguments supplied" from "target takes no arguments"
branch on `input.target.type`.

`input.directives` is always an array — the **empty array `[]`** (never `null`)
when the matched constraint carries no directives. An evaluator (e.g. OPA/Rego)
can safely iterate it without a null guard:

```rego
some i; input.directives[i].type == "redactFields"
```

`input.claims` carries **every** top-level claim from the verified token, not
just the four eunox-canonical fields, so a policy can restrict on an arbitrary
IdP claim:

```rego
allow { input.claims.tenant_id == "acme" }
```

**Claim-name precedence.** Four keys are *reserved* and are always sourced from
the values eunox validates, never from a same-named claim in the token body:

| Reserved key | Authoritative source |
|--------------|----------------------|
| `sub` | the validated standard `sub` claim |
| `iss` | the validated standard `iss` claim |
| `task_id` | the verified `mcp.task_id` claim |
| `agent_id` | the verified `mcp.agent_id` claim |

A token cannot subvert these: a top-level claim named `task_id` (or `sub`,
`iss`, `agent_id`) never overrides the canonical value, and when the canonical
value is empty the reserved key is **absent** rather than falling back to the
raw claim — so `input.claims.task_id` is only ever the verified `mcp.task_id`.
Every other claim name passes through verbatim, including the nested `mcp`
object (e.g. `input.claims.mcp.capabilities`). Standard registered claims such
as `exp`, `iat`, and `aud` are present as the IdP emitted them (numbers stay
numbers). Because the claim set is only assembled **after** signature
verification, an unsigned or invalid token contributes nothing.

> The reserved-key guard is **top-level only**. The nested `mcp` object is
> unguarded raw token data, so prefer the top-level reserved keys
> (`input.claims.task_id`, `input.claims.agent_id`) over reaching into
> `input.claims.mcp.task_id` / `input.claims.mcp.agent_id` — today they agree
> because the canonical values are sourced from `mcp.*`, but only the top-level
> keys are guaranteed to stay authoritative.

Existing policies that reference only `input.arguments` continue to work unchanged — the additional fields are additive.

There is **no inline `rego:` field** in the manifest grammar — the proxy never
parses or executes Rego itself. A `policy` condition only names an evaluator
(`backend`) and its static `config`/`input`; the evaluation runs in code you
register via `WithPolicyEvaluator`.

**Example — external evaluator via `WithPolicyEvaluator`:**

```yaml
- target: tool:query_db
  actions: [call]
  conditions:
    - type: policy
      backend: opa          # name passed to your registered PolicyEvaluator
      config:
        query: "data.authz.allow"
      input:
        env: production     # static config merged with the dynamic input
```

The proxy calls `PolicyEvaluator.Evaluate(ctx, backend, config, input, req)`.
The helper `enforcement.BuildRegoInput(ctx, req)` assembles the standard
`input` document from the `EnforceRequest`; call it inside your
`PolicyEvaluator.Evaluate` implementation to get the full policy input map.
It returns `(map[string]interface{}, error)` — a non-nil error means a
directive on the request could not be serialized into `input.directives`.
Treat that error as a denial (fail closed); forwarding a request whose
`input.directives` understates the obligations attached to the decision would
let a policy that inspects `input.directives` decide on incomplete information.
When no evaluator is wired — the default, and the only state the prebuilt
binary can be in — any `policy` condition is denied fail-closed. Use this for
logic that cannot be expressed with the other typed conditions.

> If a condition type you need does not exist, **add a new typed shape
> to `pkg/capability/condition.go` first**, register its handler in
> `pkg/enforcement/handlers.go`, and ship a test.
> Unknown condition types are denied at the proxy — that is the correct
> behavior, but a regression for the manifest author if they forget to
> register the handler.

## 5a. Directives — response obligations

> **Note:** `redactFields` must be placed in `directives`, not in `conditions`
> — a manifest that uses `redactFields` inside `conditions` is rejected at load
> with a migration hint.

A **directive** is a proxy obligation applied to a request that has *already
been allowed* — it never participates in the allow/deny decision. `directives`
is a sibling array on the constraint, separate from `conditions` (which are
strictly boolean predicates). The proxy evaluates every condition first; only
if the request is allowed does it apply the directives.

```yaml
- target: tool:query_sales
  actions: [call]
  conditions:                    # predicates — decide allow/deny
    - type: allowedTables
      argument: table
      tables: ["sales"]
  directives:                    # obligations — applied only after allow
    - type: redactFields
      fields: ["customer_email", "ssn"]
```

**`redactFields`** — masks the named fields in a **`tools/call`** result
before it is returned to the caller: each matched field keeps its key but has its
value replaced by the placeholder string `"[redacted]"`, so the caller can see
that the field was present without ever seeing its value. Matching is recursive
(nested objects and array elements) and is applied to every JSON **text** content
item **and** to the `structuredContent` object. Binary media content the proxy
cannot address (images, audio) and metadata (`_meta`, content annotations) are
preserved unchanged.

> **`resource` / `resource_link` content fails closed under an active `redactFields`.**
> A `resource` or `resource_link` content item nests a `resource` object that can carry
> a `text` or `blob` body holding arbitrary (possibly sensitive) data the proxy does
> **not** walk. Rather than silently forward such an item — which would let an upstream
> evade a declared `redactFields` obligation by embedding the named field inside a
> resource body — the whole `tools/call` response is **denied fail-closed** whenever a
> `redactFields` obligation is active and the result contains a `resource`/`resource_link`
> item. (With no `redactFields` obligation in play, resource items are forwarded normally.)
> If a tool legitimately returns resource content that must reach the caller, redact that
> content **upstream** and drop the `redactFields` directive for that tool.

> **Scope: cleanly-parseable JSON fields only.** `redactFields` resolves
> dot-paths against decoded JSON **object keys** (recursing into nested objects
> and into the elements of object arrays). It acts **only on string content that
> parses cleanly as a single JSON object or array**, and it masks the value at each
> named key of that JSON. It does **not** reach into the *contents* of string values, and it
> does **not** parse JSON that is malformed or embedded in surrounding prose. A
> field name that appears only inside such a string — a log line like
> `"log entry: {user: alice}"`, a truncated body like `{"ssn": "…"`, or a
> status-prefixed body like `OK {"ssn": "…"}` — has no addressable JSON key, so the
> content **passes through unredacted**. (A *clean* JSON array of strings such as
> `["log entry: {user: alice}", "status: ok"]` is a separate case: it parses, so it
> **is** decoded and walked, but its string elements expose no object key for a path
> to match, so it too passes through unredacted.)
>
> **This is a silent pass, never a fail-closed.** `redactFields` redacts valid JSON
> and forwards everything else **unchanged**; it does **not** fail the response
> closed over a string it cannot parse. The trade-off is explicit and accepted: a
> named field hidden inside **malformed** JSON, or inside JSON **embedded in
> prose**, is **not** redacted. If you need to redact data carried in string values,
> scalar array elements, malformed JSON, or prose, redact it **upstream** (at the
> tool/server that produces the response) or with a custom condition —
> `redactFields` is the wrong tool for content that is not modeled as named JSON
> fields. (Redacting JSON embedded in surrounding prose is not currently supported.)
>
> **Exception — doubly-encoded JSON.** A `structuredContent` value or array element —
> **and, identically, a text content item** — that is itself a serialized JSON object or
> array (e.g. `{"data": "{\"ssn\": \"…\"}"}` or `["{\"ssn\": \"…\"}"]`) is unwrapped,
> redacted, and re-serialized, so an upstream cannot smuggle a named field past redaction
> by double-encoding it. A dotted path is **rebased** to the leaf's position, so the same
> path that redacts the honest `{"data": {"ssn": "…"}}` (`data.ssn`) also redacts the
> double-encoded `{"data": "{\"ssn\": \"…\"}"}`.
>
> **Path matching across encoding boundaries.** Each unwrapped container is matched from
> its own root, so a **bare** path (`ssn`) also redacts a doubly-encoded `ssn` wherever it
> is smuggled. A bare path still matches only the **top level** of an honest, un-encoded
> object (the same rule as everywhere — bare `ssn` does *not* reach `{"data": {"ssn": …}}`),
> so **prefer the fully-qualified dotted path** when the field is nested; it then covers
> both the honest and the double-encoded shapes consistently.
>
> Each such nested string is held to the **same rule as a top-level
> `structuredContent` string**: one that parses cleanly as a JSON container is unwrapped and
> redacted; one that does **not** parse cleanly — truncated, trailing data, a status-word
> prefix (`OK {…}`), or JSON embedded in prose — is **not** a clean container and **passes
> through unchanged** (it is not failed closed). Brace-free prose, a plain scalar, and a
> `structuredContent` of JSON `null`/number/bool likewise pass through. Unwrapping
> **recurses through multiple encoding layers** (a field hidden several clean layers deep is
> redacted too), up to a fixed nesting bound beyond which the response fails closed. This
> bound is not specific to encoding layers — it caps the total nesting walked, so a plain,
> non-encoded `structuredContent` nested past the limit fails closed the same way. That depth
> bound, together with a re-serialization failure on the redacted JSON, is the only case
> nested-string redaction denies rather than passing through.
> **Residual:** because only *clean* nested JSON is unwrapped, an upstream that
> double-encodes a **malformed** payload (one that does not parse) thereby evades redaction,
> exactly as a top-level malformed body does; such data must be redacted upstream.
>
> **Upstream error channel.** `redactFields` masks fields in a `tools/call`
> **result**. When the upstream instead answers an allowed call with a JSON-RPC
> **error**, there is no result to redact and the free-form `error.data` payload
> cannot be verified against the result-shaped redact paths. Rather than forward it
> unredacted — a channel an adversarial or misconfigured upstream could use to smuggle
> a declared-redactable value to the host — the proxy **strips `error.data`** (fails
> closed) whenever a `redactFields` obligation is attached; the error `code` and
> `message` still reach the host, and the obligation is **not** recorded as discharged.

Directives apply only to `tool:` targets. A directive on a `resource:`,
`prompt:`, or `system:` target is **rejected at load** — the proxy redacts
tools/call results, not resource/prompt responses, so accepting it would
silently forward unredacted data while recording a misleading "obligation
discharged" audit entry.

Field paths use **dot notation** (`user.ssn`, `$.result.secret`). An optional
JSONPath **root marker** may lead the path, but only in its two real spellings:
`$.` (root followed by a key, as in `$.result.secret`) or a lone `$` (the root
itself). A leading `$` is **reserved** for that marker: any *other* `$`-prefixed
path — `$ref`, `$schema`, or `$users.ssn` (a likely typo for `$.users.ssn`) — is
**rejected at load**. The runtime strips only the two real spellings, so a path
like `$users.ssn` would otherwise reach the redactor unchanged, which then looks
up a literal first key `$users`, finds nothing, and silently redacts nothing while
the audit record reports the obligation applied — exactly the fail-open this
validation prevents. As a consequence a top-level key *literally* named with a
leading `$` (`$ref`, `$schema`, `$defs`) cannot be targeted — a documented
limitation, like keys containing a literal `.`. A path
whose final segment names a field inside array elements redacts that field in
**every** element — `users.ssn` masks `ssn` in each object in the `users`
array. **Array-index notation (`users[0].ssn`,
`data[2].password`) is not supported and is rejected at load**: the
redactor treats each dot-separated segment as a literal object key, so `users[0]`
would never resolve to the array and the field would silently survive — a declared
redaction with no runtime effect. Drop the index to redact from all elements.

> **Keys containing a literal `.` are unaddressable.** Because `.` is the path
> separator, a path such as `a.b` always means nested object `a` -> key `b`. A
> **flat** JSON key literally named `"a.b"` (legal JSON) therefore cannot be
> targeted: no dot-path resolves to it, and the field passes through unredacted
> while the obligation is still recorded as applied. Load-time validation cannot
> detect this (the manifest alone does not say whether `a.b` is nested or flat), so
> it does **not** reject such paths. If an upstream emits keys containing literal
> dots that must be redacted, redact them **upstream** instead.

Failure modes per the specification § 3.4:

- A field named for redaction that is absent from the response is a **no-op**,
  not an error — there is no value to mask.
- A **genuine free-form text content item** — an error string, a `[ERROR] …` log
  line, a bare scalar — is **forwarded unchanged**. Path-based
  redaction targets JSON object keys, which such text has none of, so there is no
  named field to leak; failing the call here would only block a tool's legitimate
  plain-text output (e.g. an `"Error: file not found"` message) without protecting
  anything.
- A text or `structuredContent` item that **looks like JSON** but **does not parse
  cleanly** as a single JSON document — a trailing comma, a truncated tail, a
  status-word prefix (`OK {…}`), or JSON embedded in surrounding prose — is
  **forwarded unchanged**, *not* failed closed. `redactFields` redacts
  cleanly-parseable JSON only; a named field hidden inside malformed or
  prose-embedded JSON is **not** redacted and must be redacted upstream.
- If redaction genuinely cannot be **verified** — the response **envelope** itself
  is not parseable JSON (or carries trailing data), the `content` array or one of
  its items has a structurally unverifiable shape, re-serializing the redacted JSON
  fails, or a value nests deeper than the fixed redaction depth bound — the proxy
  returns a **sanitized error** to the caller and audits the failure. It MUST NOT
  fail open by returning the unparsed body. These structural and resource guards are
  the **only** cases `redactFields` fails closed; it never fails closed over string
  *content* it merely cannot parse as JSON.

A `redactFields` object found inside `conditions` is rejected at load —
`redactFields` is a directive, so it belongs under `directives`, not
`conditions`. An unknown directive `type` is likewise rejected at load
(fail-closed) rather than silently dropped.

## 6. TTL guidance

In JWT mode, token lifetime is controlled by the `exp` claim your IdP
stamps on the JWT — eunox validates and rejects expired tokens but
does not issue them.

| Scenario                                | Recommended JWT TTL (seconds) |
| --------------------------------------- | ----------------------------- |
| Interactive chat / tool call            | 900 (15 min)                  |
| Long-running batch (ETL, embedding job) | 1800–3600                     |
| Task-scoped sub-invocation              | 60–300                        |
| Anything that touches money or PII      | 300                           |

Configure short TTLs in your IdP client settings; request a fresh
token per task rather than re-using a long-lived one.

## 7. Anti-patterns to avoid

These all _work_ (token issued, proxy happy) but each one silently
degrades the security posture.

1. **Manifest copied between agents** with `name` not changed.
   Audit logs lose attribution clarity. Use a unique manifest `name` per logical
   agent, not per pod / replica.
2. **Over-broad target globs** "for development". Configure dev
   manifests with realistic scopes from day one — a manifest that is
   too wide in development tends to stay that way in production.
3. **Adding tools the agent doesn't currently need.** List only what
   the agent actually calls. Over-broad manifests silently widen the
   blast radius of a prompt-injection or supply-chain compromise.
4. **One manifest shared across every environment.** Use a separate
   manifest per environment (`dev`, `staging`, `prod`) with
   progressively tighter conditions — the `name`/`version` fields make
   this traceable in the audit log.
5. **Long-lived JWTs re-used across tasks.** Request a fresh token
   per task and keep TTLs short; the audit log records `task_id` from
   the JWT so attribution is preserved without needing long-lived tokens.

## 8. Tooling

| Step                                          | CLI command                                          |
| --------------------------------------------- | ---------------------------------------------------- |
| Draft a manifest from observed usage          | `eunox suggest --output manifest.yaml` (reads the audit tape; grounds entries and `allowedValues` in what the agent actually called — review before enforcing) |
| Validate a manifest file                      | `eunox validate ./manifest.yaml`                 |
| Validate multiple manifests at once           | `eunox validate ./a.yaml ./b.yaml`               |
| Diff a manifest against a live HTTP upstream   | `eunox validate ./manifest.yaml --live --upstream-url <url>` (contract-drift report; exit 0 clean, 1 warnings/stale, 2 connection error) |
| Diff a manifest against a live stdio upstream  | `eunox validate ./manifest.yaml --live --transport stdio -- <command> [args...]` (introspects a subprocess instead of an HTTP server) |
| Validate every route in a config (syntax)     | `eunox validate --config ./eunox.yaml` (walks every route's manifest(s); exit code = max across routes) |
| Validate every route against its live upstream | `eunox validate --config ./eunox.yaml --live` (per-route drift report; no need to re-specify the upstream wiring) |
| Start the proxy                               | `eunox proxy --config eunox.yaml` (declare the upstream(s) and per-route `policy:` in the config) |
| Add JWT (IdP-issued capability intersection)  | add `--jwks-uri <url> --jwt-issuer <iss> --jwt-audience eunox` (transport: http) |
| Enforce drift as fatal                        | set `strictDrift: true` per route or under `defaults:` (aborts session on FM-1/FM-2/FM-4/FM-6; FM-5 always fatal) |
| Observe without enforcing                     | set `enforcement: audit` per route or under `defaults:` |
| Verify HMAC signatures in the audit log       | `eunox audit-verify --audit-log audit.jsonl --audit-key-path audit.key` |
| Inspect denial counts (split by posture)      | `eunox stats` (BLOCKED = enforced; OBSERVED = `enforcement: audit` denials that were forwarded — read these before flipping to `enforce`) |
| Generate a support bundle for a bug report    | `eunox doctor --config eunox.yaml [--live]` — prints redacted binary identity, config, manifest digests, and the last 50 audit records. Nothing leaves your machine; paste the output manually. |

Relative `policy:` paths in a gateway config are resolved against the **config
file's directory**, not the process working directory — so
`eunox proxy --config /etc/eunox/gateway.yaml` finds
`policy: ["./policies/x.yaml"]` no matter which directory it is launched from.
Absolute paths are used unchanged.

### Observation mode

Before enabling enforcement in production, run a route in **audit (observe)
mode** — `enforcement: audit` — to understand what the proxy would do, or what an
agent is actually doing:

```yaml
upstreams:
  - name: local
    transport: stdio
    command: npx
    args: ["-y", "@mcp/server"]
    enforcement: audit         # evaluate + log, but forward every call
    policy: ["manifest.yaml"]  # optional — omit to observe raw traffic before writing any policy
```

Set it under `defaults:` to observe every route at once. In audit mode each
request is forwarded to the upstream and written to the audit trail: requests
that _would_ be denied are recorded and forwarded anyway, and allowed calls log
their complete tool argument map in the `details` field. Every record is marked
`audit_only=true`.

The audit record fields in audit mode:

| Record field | deny (would-be) | allow |
|---|---|---|
| `audit_only` | `true` | `true` |
| `details` | denial details | **full tool arguments** |

To stage a single rule in observe mode while the rest of the manifest keeps
enforcing, mark that individual capability entry `enforcement: audit` instead
(see below) — only the matched rule observes.

Wire `eunox validate` into your CI pipeline for every manifest PR
to catch schema errors and over-broad globs before they reach production.

### Startup drift detection

Every time a session is established the proxy fetches `tools/list` from
the upstream and compares the live tool set against the manifest. Each
finding is classified `FM-1` through `FM-6` (or `uncovered`):

| Finding | Meaning | Fatality |
| ------- | ------- | -------- |
| **FM-1** | A live upstream tool is matched only by a manifest **glob** (`tool:delete_*`) rather than an exact entry — a newly added tool silently inherits the glob's permissions (over-permission). | Fatal under `strictDrift`. |
| **FM-2** | A `tool:` manifest entry matches **no** live upstream tool — a dead reference (the tool was removed or renamed). | Fatal under `strictDrift`. |
| **FM-3** | A pinned argument name — the `argument` of a condition or a top-level `argumentSchema` property — is absent from the live `inputSchema`, so the pin may silently stop enforcing. | Advisory (never promoted). |
| **FM-4** | The upstream's reported version does not satisfy the manifest's `serverVersion` pin (only checked when a pin is set). | Fatal under `strictDrift`. |
| **FM-5** | A live tool's description, title, annotations, **or any `inputSchema`/`outputSchema` parameter description** — at any depth, under any subschema-valued keyword (nested `properties`/`patternProperties`, `items`/`prefixItems`, `$defs`/`definitions`, `allOf`/`anyOf`/`oneOf`, and applicators such as `additionalProperties`/`propertyNames`/`contains`/`not`/`if`/`then`/`else`) — does not match its `descriptionHash` pin — the model-facing instruction text may have been modified to steer the model toward unintended calls. `outputSchema` is covered the same way as `inputSchema`, since common hosts render its parameter descriptions to the model alongside the tool's description. | **Always fatal** (independent of `strictDrift`). |
| **FM-6** | The live `inputSchema` diverges structurally from an **exact-name** `tool:` constraint's `argumentSchema`: a parameter (or nested parameter) appears that a closed schema (`additionalProperties: false`) did not declare and no condition references, or a declared parameter changed type incompatibly. A *disappeared* parameter is FM-3; a `number`→`integer` change and glob targets are not flagged. | Fatal under `strictDrift`. |
| `schema_absent` | A covering constraint pins one or more arguments, but the live tool published **no** `inputSchema` at all, so FM-3/FM-6 could not run and those pins went *unverified* this session. Surfaces the gap that would otherwise be silent (see below). | Advisory (never promoted). |
| `uncovered` | A live tool matches no manifest entry. Under allowlist semantics every call is denied in enforce mode; informational only. | Advisory (`INFO`). |

Findings are emitted as structured log lines to stderr:

```
[eunox] WARN drift=fm1 tool="delete_all_records" resource="delete_*" — new upstream tool matched by manifest glob; verify this is intentional before deploying
[eunox] WARN drift=fm2 resource="query_db" — manifest entry matches no live upstream tool (tool removed or renamed?)
[eunox] WARN drift=fm3 resource="read_file" tool="read_file" argument="path" — pinned argument not in live inputSchema; the pin may not enforce if the upstream renamed it
[eunox] WARN drift=fm4 serverVersion="1.4.*" actual="1.5.2" — server version does not satisfy manifest pin; server may have been updated
[eunox] WARN drift=fm5 resource="read_file" tool="read_file" — description hash mismatch; tool description may have been modified (expected sha256:9f86d0…, got sha256:2c2640…)
[eunox] WARN drift=fm6 resource="send_email" tool="send_email" argument="bcc" — live parameter is not declared by the closed argumentSchema (additionalProperties:false) — a new, unreviewed tool argument; review whether the argumentSchema still constrains this tool as intended
[eunox] WARN drift=schema_absent resource="read_file" tool="read_file" argument="path" — tool published no inputSchema, so pinned arguments could not be verified this session (request-time enforcement is unaffected)
[eunox] INFO drift=uncovered tool="summarize_text" — not covered by manifest; no allowlist entry matches it (denied in enforce mode)
```

FM-3 (schema drift) fires for any argument a manifest entry pins to a specific
upstream parameter — the `argument` of a condition (e.g. `allowedValues`) **or**
a top-level property of an `argumentSchema` — that is absent from the live
`inputSchema`. A renamed or removed parameter means the pin silently stops
matching, so the condition or schema constraint no longer enforces. This
includes the strongest case: a tool that drops its entire `properties` block
(an `inputSchema` like `{"type": "object"}` with no declared parameters) is
treated as having *every* pinned argument absent and is flagged for each. A tool
that reports **no** `inputSchema` at all is different — the live parameter set is
then unknown, so FM-3 (and FM-6) are skipped: the check cannot tell a dropped
parameter from a tool that simply omits its schema block, so it emits no false
FM-3. Instead, when the covering constraint actually pins arguments, an advisory
`schema_absent` finding is emitted so the unverified pins are visible rather than
silently skipped. This skip is **not** fail-closed — the pinned arguments go
*unverified* for that session. Request-time enforcement of those arguments is
unaffected; only the startup drift signal is absent.

**`serverVersion` pin syntax.** The `serverVersion` field (checked by FM-4) is a
dot-separated version string, **not** a semver range. A **trailing** `*`
wildcards that position and everything to its right; a **non-trailing** `*`
wildcards only its own component, and the components after it are still compared:

| Pin | Matches |
| --- | ------- |
| `"1.2.3"` | exactly `1.2.3` |
| `"1.2.*"` | major 1, minor 2, any patch (`1.2.0`, `1.2.9`, …) |
| `"1.*"` | major 1, any minor and patch |
| `"*"` | any *reported* version (an upstream that reports no version at all still trips FM-4) |
| `"*.0"` | any major, minor exactly `0` (`2.0`, `7.0`; not `2.1`) |
| `"1.*.3"` | major 1, any minor, patch exactly `3` (`1.2.3`, `1.9.3`; not `1.2.4`) |

(A non-trailing wildcard previously short-circuited to match *every* version,
silently defeating the pin; it now compares the later components as written.)

An **absent** upstream version (the `initialize` response reported none) satisfies
**no** pin, not even `"*"` — FM-4 exists precisely to surface an upstream that
reports no version, so a "don't care" `"*"` pin still flags it.

Comparison/range operators (`>=`, `>`, `<=`, `~`, `^`) are **not** supported and
never match a real version string — e.g. `serverVersion: ">=2.0.0"` splits into
the literal components `[">=2", "0", "0"]`, which no upstream version begins with,
so under `strictDrift: true` it would block every session. The proxy rejects a
`serverVersion` containing such operators at manifest-load time so the mistake
surfaces up front rather than as a permanent traffic blackout.

**Splitting a `serverVersion` pin across `--policy` files.** When a route (or a
`validate` invocation) loads several policy files, their capabilities are unioned
and the `serverVersion` pin is taken from whichever file declares one — so a pin
set in any single file still drives FM-4. Declare the pin in **at most one** file
(or with the same value in each): two files that pin *different* non-empty
`serverVersion` values are rejected at load with a clear error, rather than
silently keeping the first file's pin and dropping the others. The same
single-value rule applies to `schemaVersion`. (Other top-level metadata — `name`,
`version`, `description` — is inherited from the first file; none of
it drives enforcement, so a later file's differing value is simply ignored.
`audience`, by contrast, pins the per-route JWT audience in gateway mode (see
above), so it is folded under the same single-value rule as `serverVersion`
rather than first-file-wins: a value declared in any one file survives, and two
files declaring *different* non-empty audiences are rejected at load rather than
silently collapsed — keeping one file from quietly dropping another file's
accepted audience.)

**Conflicting `descriptionHash` pins.** Two exact-tool entries that pin the
**same** tool name to **different** `descriptionHash` values are ambiguous — no
single description can be authoritative — and are rejected at manifest-load time
with a clear error, rather than being accepted and only failing closed later on
the live FM-5 drift probe or the enforcement path. This applies within one file
and across merged `--policy` files (the merged manifest is re-validated), so a
conflict that only arises after merging is caught too. Pinning the same tool to
the **same** hash in more than one entry, and pinning **different** tools to
different hashes, remain valid.

Set `strictDrift: true` (per route, or under `defaults:`) to abort session
establishment (HTTP 500) when FM-1, FM-2, FM-4, or FM-6 drift is detected. FM-5
(description-hash mismatch) aborts startup unconditionally — it does not require
`strictDrift`, because a poisoned description can steer the model even within the
allowed tool set. FM-3 and `uncovered` stay advisory either way.  Appropriate for
production deployments where any policy gap must be resolved before traffic is
admitted.

**When the `tools/list` probe itself fails.** Drift checking depends on fetching
the live tool list at session start. If that probe errors (or returns an
unparseable result), the proxy cannot evaluate FM-1 through FM-6 at all. The
outcome is fail-closed:

- Under `strictDrift: true`, a probe failure is **fatal** — an upstream we cannot
  inspect is indistinguishable from one that has drifted, so a broken or malicious
  upstream must not be able to dodge the fatal-on-drift guarantee by withholding
  `tools/list`.
- Without `strictDrift`, a probe failure is fatal **only** when the manifest pins
  any `descriptionHash` (those pins cannot be verified without the live list);
  otherwise it is a logged best-effort skip and the session proceeds.

A *successful* probe that returns an empty or `null` tool list is a distinct case:
it is trusted as a genuine zero-tool upstream, not a withheld probe. With no live
tools there is nothing for FM-1/FM-2 to flag, so the session proceeds even under
`strictDrift`. This is not a bypass — FM-4 (server version, captured at
`initialize`) is still evaluated, and per-call manifest enforcement still gates
every `tools/call` regardless of what the probe returned.

Each drift finding is a structured log line — pipe stderr to your log aggregator to alert on `drift=fm1` or `drift=fm2` in production.

The same checks back the offline `eunox validate --live` report, which
groups findings into COVERED / WARNINGS / NOT COVERED / STALE MANIFEST ENTRIES
sections and is the recommended CI gate (see §8). The "Fatality" column above
governs **startup** only (whether drift aborts session establishment); the
`validate --live` CI gate is stricter and exits non-zero on FM-1, FM-2, FM-3,
FM-4, FM-5, or FM-6 so a potential enforcement gap fails the pipeline rather than
passing silently — including FM-3 argument drift, where the pinned condition may
have stopped enforcing (`uncovered` remains informational and does not fail the
gate). A tool flagged by FM-3 or FM-5 is listed under WARNINGS, not COVERED, so
the ✓ COVERED list means "covered with no outstanding issues".

## 9. Where this guide lives in the rest of the docs

- **Security properties and threat model**: [`threat-model-mcp.md`](./threat-model-mcp.md)
- **Performance baseline**: [`benchmarks.md`](./benchmarks.md)
