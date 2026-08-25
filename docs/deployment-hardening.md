# Deployment Hardening: Making eunox a Mandatory Chokepoint

`eunox` enforces policy on every MCP call that passes *through* it. It cannot
enforce policy on a call that goes *around* it. A host configured to connect
directly to an upstream MCP server bypasses the proxy entirely — no policy
decision, no `*/list` filtering, no audit record. eunox is an enforcement
**point**; whether it is also an enforcement **boundary** is a property of the
deployment, not of the binary.

This guide describes how to turn "clients are configured to use eunox" — a
cooperative arrangement — into "there is no usable path to the upstream except
through eunox." It is the operational companion to
[threat-model-mcp.md](./threat-model-mcp.md) §4.6.

## The principle

A direct, bypassing connection needs three things:

1. a **credential** the upstream will accept,
2. a **network path** to the upstream, and
3. a **place to run** the client.

Remove any one and the bypass fails. The three control planes below each remove
one. They compose — apply as many as the environment allows — but credential
control is the one to reach for first, because it is the only one that holds on
devices and networks you do not control.

---

## 1. Credential control — the strongest, most portable lever

Make eunox the only thing that can obtain a credential the upstream will honor.
Then a direct connection is *unauthenticated* and fails at the upstream,
regardless of network position or device.

- **Do not distribute upstream secrets to clients.** In the static-credential
  model the upstream token lives only in eunox's configuration/environment, never
  on a developer machine. A client that dials the upstream directly has no token.
- **Mint short-lived, audience-locked, delegated tokens per request.** For
  per-caller identity, use the upstream-credential delegation model (token
  exchange): the only way to obtain a usable upstream-audience token is to make a
  request *through* eunox, which mints one per call. There is no long-lived secret
  on any client to extract and replay.
- **Require gateway provenance at the upstream.** Where the upstream (or an
  IdP/upstream policy) can be configured to honor only tokens that carry eunox's
  delegation marker (`act`) or audience, a client's own token — lacking eunox in
  the chain — is rejected by the upstream itself.
- **eunox strips its own secrets from the upstream subprocess environment.** An
  upstream launched as a subprocess is the least-trusted process eunox runs, yet a
  child spawned with an unset environment inherits the parent's entire
  `os.Environ()`. eunox filters its own emergency-stop credential
  (`EUNOX_CONTROL_TOKEN`) and shared-backend password (`EUNOX_REDIS_PASSWORD`) out
  of every spawn's environment, so a compromised upstream cannot read them from its
  own environment. Names are matched case-insensitively, because Windows folds
  environment-variable case: a variable set as `Eunox_Control_Token` is the one the
  proxy resolves, so a case-sensitive filter would hand the live credential to the
  child. Matching is on the whole name, so a distinct variable that merely begins
  with a secret's name (`EUNOX_CONTROL_TOKEN_PATH`) is preserved.

  This is a denylist of eunox-owned names: a secret you reference from the gateway
  config under an arbitrary `${VAR}` name is **not** auto-stripped. That includes the
  variable behind `listen.authToken` — an upstream that reads it can authenticate to
  the proxy's own listener on every route — as well as an `upstreamAuthHeader` bearer.
  Start the proxy with only the environment the upstream may legitimately see, or
  supply those secrets through a channel the child does not inherit. Note also that
  the emergency-stop token's primary home is the 0600 file, which a subprocess running
  as the same UID can still read; run the upstream under a distinct UID or sandbox it
  away from that path where that matters.

Credential control is enforced at the IdP and the upstream, so it does not depend
on owning the network path or the device. It is the lever that works for remote
and BYOD scenarios alike.

---

## 2. Network egress control — for remote (HTTP) upstreams

Make the upstream *unreachable* except through eunox. A bypassing connection is
then *unroutable*.

- **Egress firewall / forward proxy.** Route outbound traffic through a controlled
  egress (corporate SASE, forward proxy) that permits the upstream's host only
  from eunox's egress identity, and blocks it for everyone else.
- **Split-horizon DNS / transparent proxy.** Resolve the upstream's hostname to
  eunox internally, so a client "configured" to reach the upstream lands on eunox
  regardless.
- **Upstream-side source allowlist.** Have the upstream accept connections only
  from eunox's source address or workload identity.

Network controls are robust but bounded to the managed network — a developer on a
personal or home network escapes them unless always-on SASE/ZTNA is in force. Pair
with credential control to cover the off-network case.

---

## 3. Upstream-side provenance — where you can shape the upstream or its tenancy

Have the resource itself refuse non-gateway traffic.

- **mTLS / workload identity.** In a service mesh, the upstream accepts only mTLS
  connections from eunox's identity (e.g. a SPIFFE ID).
- **Tenant/organization governance** on a SaaS upstream you do not control.
  Even where you cannot change the server, you can often constrain *who and what*
  reaches it. For **GitHub**, the org-level controls compose into a chokepoint:
  - an **organization IP allowlist** restricted to eunox's egress address,
  - **enforced SAML SSO**,
  - **restricting or disabling personal access tokens** org-wide, and
  - scoping a **GitHub App** so the practical-only access path is the App
    credential eunox holds.

  Stacked, these make a developer's personal token unable to reach org resources
  directly, so the gateway-held App credential is the only working path.

---

## 4. Endpoint control — the necessary lever for local (stdio) upstreams

A local stdio MCP server has no network chokepoint: the bypass is "spawn the
subprocess yourself." Here the control is the device, and a bypass becomes
*unconfigurable*.

- **MDM-pushed, locked client configuration.** Manage the MCP host's config (the
  pointer to eunox) through device management so users cannot repoint it. See
  [client-integration.md](./client-integration.md) for the per-client config
  surfaces.
- **No local secrets.** Do not provision upstream tokens (PATs, API keys) to
  developer machines; keep them server-side with eunox. A locally spawned MCP
  server then has nothing to authenticate with.
- **Application allowlisting / EDR.** Block unapproved MCP server binaries from
  executing, so a developer cannot run an arbitrary server to bypass policy.

---

## 5. Detection — the backstop when prevention is incomplete

You cannot always *prevent* bypass (unmanaged or off-network endpoints). You can
*detect* it.

- **Audit reconciliation.** eunox writes a tamper-evident record for every call it
  mediates (threat model §3.4). Reconcile those records against the **upstream's
  own** audit log: any upstream activity with no corresponding eunox record is
  access that skipped the gateway. For GitHub, that is the org/enterprise audit
  log; for an internal upstream, its own access log.
- **Network and CASB monitoring.** Alert on direct connections to known upstream
  MCP endpoints that did not originate from eunox.

Detection is detective, not preventive — but it is the realistic floor for
endpoints outside your control, and it turns a silent bypass into a visible event.

---

## Composition: what a hardened deployment looks like

The controls compose so that a direct connection fails on every axis at once:

| A bypass attempt is… | …blocked by |
| -------------------- | ----------- |
| **unauthenticated**  | credential control (§1) — no usable token exists outside eunox |
| **unroutable**       | egress + upstream provenance (§2, §3) — the upstream is unreachable directly |
| **unconfigurable**   | endpoint control (§4) — client config locked, no local binaries or secrets |
| **visible**          | detection (§5) — audit reconciliation catches what slips through |

## Bottom line

eunox earns its place as the chokepoint by what it does once traffic reaches it —
policy enforcement, list filtering, per-caller credential delegation, tamper-evident audit —
but the surrounding controls are what make it *the* chokepoint. The single most
leverage-efficient move, because it holds even on devices and networks you do not
control, is **credential control**: stop distributing upstream secrets, mint only
short-lived eunox-delegated tokens, and require the upstream to honor only the
gateway's delegation chain. That converts "please route through eunox" into "there
is no other way to obtain a credential that works." Network and endpoint controls
close the residual paths, and audit reconciliation catches the rest.
