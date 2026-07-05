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
and drives five legs, all writing to **one shared, signed audit tape**:

| Leg | Transport | What it proves |
|-----|-----------|----------------|
| 1. full matrix | stdio | every target type, every condition, redaction directive, sampling ALLOW |
| 2. sampling deny | stdio | a manifest without the `system:` opt-in denies server-initiated sampling |
| 3. http suite | http (gateway) | sessions, session isolation, kill-switch, malformed body, 404, per-route policy isolation |
| 4. audit-verify | — | the HMAC chain stays intact across all three proxy invocations |
| 5. audit assertions | — | decisions, denial codes, condition types, target types, and obligations are recorded |

## Components

- **`mock-server/`** — upstream MCP server implementing the full surface
  (`tools/*`, `resources/*`, `prompts/*`, `sampling/createMessage`, `ping`,
  `completion/complete`) over **both** stdio and http (`--transport`). It
  returns deterministic responses, including redactable payloads, a
  malformed-JSON payload (to exercise pass-through of unparseable content), and a
  `trigger_sampling` tool that opens the server-initiated sampling round-trip
  and reflects the proxy's verdict back as a deterministic marker.
- **`mock-host/`** — the MCP host (client) and assertion engine. In `stdio`
  mode it spawns the proxy and answers inbound sampling requests; in `http`
  mode it manages sessions and the loopback kill endpoint; in `audit` mode it
  asserts on the audit JSONL. It exits non-zero on any failed assertion.
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
  assertions.

## Adding a case

Add an assertion in the relevant `runStdio*` / `runHTTP*` function in
`mock-host/main.go` using the `expectAllow` / `expectDeny` / `expectErrorCode`
helpers. If the case needs a new upstream behaviour, extend `toolCallResult`
(or the catalog) in `mock-server/main.go`, and grant or omit the matching
capability in `policy.yaml`.
