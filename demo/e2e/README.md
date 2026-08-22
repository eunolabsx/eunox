# eunox end-to-end test suite

A black-box integration suite that runs the **real compiled `eunox`
binary** — driven by a mock MCP **host** against a mock MCP **server**, over
real transports, writing a real on-disk audit tape — and asserts the policy
outcome of every enforced MCP method in positive, negative, and edge cases.

It targets the class of bugs that in-process unit tests cannot reach: CLI/config
wiring, transport framing, subprocess lifecycle, `*/list` filtering, response
redaction, the server-initiated sampling round-trip, kill-switch behaviour, and
audit-log integrity across process restarts.

```
make -C demo ci-test-e2e      # or: make -C demo e2e
```

No Docker required — it builds local binaries and needs only Go and `curl`.

## What it runs

`run.sh` builds three binaries (`eunox`, `e2e-mock-server`, `e2e-mock-host`)
and drives seven legs, all writing to **one shared, signed audit tape**:

| Leg | Transport | What it proves |
|-----|-----------|----------------|
| 1. full matrix | stdio | every target type, every condition, redaction directive, sampling ALLOW |
| 2. sampling deny | stdio | a manifest without the `system:` opt-in denies server-initiated sampling |
| 3. interop matrix | stdio | {host 2025-11-25, 2026-07-28} x {upstream 2025-11-25, 2026-07-28}: matched pairs serve the enforced surface, mismatched pairs are refused -32022 in both directions |
| 4. cli probes | stdio | `init` and `validate --live` open a 2026-07-28-only upstream through the revision-selected opener, and the handshake opener is refused there |
| 5. http suite | http (gateway) | sessions, session isolation, kill-switch, malformed body, 404, per-route policy isolation |
| 6. audit-verify | — | the HMAC chain stays intact across every proxy invocation |
| 7. audit assertions | — | decisions, denial codes, condition types, target types, obligations, and both protocol revisions are recorded |

## The interop matrix

Both mocks take a `--protocol-version` (`2025-11-25` or `2026-07-28`), and the host takes
`--host-protocol-version`, so one binary pair drives all four cells. The catalog, the tool
results and the transports are shared across revisions on purpose: a cell whose upstream
differed in more than its revision would be proving something else.

|  | upstream 2025-11-25 | upstream 2026-07-28 |
|---|---|---|
| **host 2025-11-25** | full enforced surface | refused `-32022` |
| **host 2026-07-28** | refused `-32022` | full enforced surface |

Two properties are worth stating because they are easy to lose:

- **The declaring upstream refuses an undeclared request.** A 2026-07-28 mock rejects any
  request whose `_meta` lacks `io.modelcontextprotocol/protocolVersion`. That is what makes
  the matched new-revision cell evidence that eunox declares the revision on every request it
  sends such a leg, rather than a cell that would pass against a lenient peer.
- **Both mismatched cells refuse.** This build translates nothing across a revision boundary,
  so the refusal *is* the boundary. When translation is activated, the cells that stop
  refusing are the diff.

The matrix runs on stdio only. A 2026-07-28 host has no `initialize`, and HTTP session
creation is still anchored on that handshake, so the two new-host cells over HTTP would be
asserting the absence of a feature rather than the revision boundary. They stay outstanding.

## Components

- **`mock-server/`** — upstream MCP server implementing the full surface
  (`tools/*`, `resources/*`, `prompts/*`, `sampling/createMessage`, `ping`,
  `completion/complete`) over **both** stdio and http (`--transport`), at
  **either protocol revision** (`--protocol-version`; see `revision.go` for what
  a revision changes and what it deliberately does not). It
  returns deterministic responses, including redactable payloads, a
  malformed-JSON payload (to exercise pass-through of unparseable content), and a
  `trigger_sampling` tool that opens the server-initiated sampling round-trip
  and reflects the proxy's verdict back as a deterministic marker.
- **`mock-host/`** — the MCP host (client) and assertion engine. In `stdio`
  mode it spawns the proxy and answers inbound sampling requests; in `http`
  mode it manages sessions and the loopback kill endpoint; in `audit` mode it
  asserts on the audit JSONL. `--host-protocol-version` picks the revision it
  speaks, and the `interop-matched` / `interop-mismatch` suites are the matrix
  cells (`revision.go`). It exits non-zero on any failed assertion.
- **`policy.yaml`** — comprehensive manifest: one capability per enforced
  method, condition, and directive, with deliberate omissions for
  deny-by-default and list-filtering assertions. The `system:sampling/createMessage`
  opt-in is deliberately *not* here, so the HTTP gateway leg can reuse it (the
  proxy rejects a sampling opt-in on an http upstream, which cannot enforce it).
- **`policy-sampling.yaml`** — the `system:sampling/createMessage` opt-in overlay,
  merged on top of `policy.yaml` for the stdio sampling-ALLOW leg (where sampling
  IS enforced).
- **`policy-no-sampling.yaml`** — minimal: `trigger_sampling` only, no opt-in
  (sampling DENY).
- **`policy-db.yaml`** — `query_db SELECT` only, for the gateway's per-route
  isolation check.

## Coverage at a glance

- **tools/call** — `allowedValues` (`*` vs `**` glob), `allowedOperations`
  (case/whitespace), `allowedExtensions`, `recipientDomain`, `timeWindow`,
  `maxCalls` rollover, `sequenceBlock`; deny-by-default; missing / wrong-type
  argument fail-closed.
- **redactFields** — sensitive fields masked (each value replaced with
  `"[redacted]"`, the key kept) in text content and `structuredContent`
  (cleanly-parseable JSON only); malformed JSON and free-form text pass through
  unchanged (the proxy redacts valid JSON and never fails closed over content it
  cannot parse).
- **list filtering** — `tools/list`, `resources/list`, `prompts/list` filtered
  to permitted entries.
- **resources** — `resources/read` and `resources/subscribe` allow/deny;
  `resources/templates/list` denied as an unmapped method.
- **prompts** — `prompts/get` exact and glob allow, deny-by-default.
- **sampling** — server-initiated `sampling/createMessage` allowed (round-trip
  reaches the host) and denied (no opt-in).
- **unmapped methods** — `ping`, `completion/complete`, and unknown methods are
  denied by default.
- **transport robustness** — JSON-RPC id-type preservation (including an id
  above 2^53, which float64 cannot represent exactly), malformed-input handling,
  a large (256 KiB) + unicode request argument, and a 2 MiB response forwarded
  intact (no proxy or audit-detail truncation).
- **http only** — session establishment, missing-session rejection, session
  isolation (independent sessions share no state), loopback kill-switch,
  unknown-route 404, per-route policy isolation.
- **audit** — HMAC chain verification across restarts plus targeted record
  assertions, including that decisions were recorded under both protocol
  revisions and that no record carries an unpublished one.
- **protocol revisions** — per-revision method sets (the methods 2026-07-28
  removes are unroutable; the ones it adds deny fail-closed until their
  responders land), the per-request `_meta` declaration reaching the upstream,
  the `cacheScope` clamp on a filtered list (the mock sends `public`, the host
  asserts `private`), and the `-32022` refusal on both mismatched pairs.

## Adding a case

Add an assertion in the relevant `runStdio*` / `runHTTP*` function in
`mock-host/main.go` using the `expectAllow` / `expectDeny` / `expectErrorCode`
helpers. If the case needs a new upstream behaviour, extend `toolCallResult`
(or the catalog) in `mock-server/main.go`, and grant or omit the matching
capability in `policy.yaml`.

A case about a **revision** goes in the `revision.go` of whichever side owns it: a method
appearing or disappearing is a `methodRemovedInDeclaring` / `methodAddedInDeclaring` entry on
the server, and a cell assertion is a `runInterop*` function on the host. Keep the exhaustive
condition matrix in `runStdioFull` — re-running it under a second revision does not make it a
different assertion, and the matrix cells stay readable because they are short.
