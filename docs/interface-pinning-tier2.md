# Interface pinning — Tier-2 design

**Status:** design; not yet implemented. The behavior below is specified here and
pinned by a committed, skipped test (`internal/drift/tier2_pinning_test.go`) that is
red when unskipped. Removing that skip and making it pass is the entry point for the
implementation.

## What ships today

Interface conformance has two shipped pieces:

- **Tier-1 (request side).** Argument validation, method mapping, and fail-closed
  handling of unmapped methods — a request that does not conform to the manifest is
  denied before it reaches the upstream.
- **`descriptionHash` pinning (FM-5).** An *opt-in, per-tool* pin: an operator writes
  `descriptionHash: "sha256:..."` on an exact-name `tool:` target, and
  `internal/drift` verifies the live tool's advertised surface hash against it **at
  session init** (and in `validate --live`). The hash is computed by
  `capability.ComputeToolHash` over the tool's description plus its title, annotations,
  input schema, and output schema (`capability.ToolHashParams`). A mismatch is fatal.

Two gaps remain, and Tier-2 closes them:

1. FM-5 only covers tools an operator **manually pinned**. An unpinned tool's
   advertised surface can change with no finding.
2. FM-5 only runs **at session init**. MCP lets a server change its tool list
   mid-session (`notifications/tools/list_changed`, after which the client re-lists);
   a surface that changes *after* init is not re-checked.

## What Tier-2 adds

**Automatically baseline the full advertised surface of every advertised tool at
session init, and re-diff on any subsequent `tools/list`.**

- **Baseline.** At session init, for every tool the upstream advertises, compute its
  surface hash with the *same* primitive FM-5 uses (`capability.ComputeToolHash` over
  name + description + input schema + title/annotations/output schema) and record a
  `map[toolName]surfaceHash` baseline for the session. No manual pin required — every
  advertised tool is pinned to what it first advertised.
- **Re-diff on change.** On any later `tools/list` result in the same session
  (including the re-list prompted by a `tools/list_changed` notification), recompute
  each tool's surface hash and compare to the baseline. A changed hash, an added tool,
  or a removed tool is a **pin break**.
- **Fail closed on a break.** A tool whose surface no longer matches its baseline is
  denied until re-review (the operator restarts or re-baselines deliberately), the same
  posture FM-5 takes on a mismatch. Adds/removes are surfaced as findings.
- **New audit record type.** A pin break emits a dedicated drift finding
  (a new `drift.Kind`, e.g. a surface-pin break) and a distinct audit record, so a
  SIEM rule can alert on interface drift specifically. It also feeds the registry: a
  drift-vs-registry mismatch is a **community-advisory signal, not a scanner verdict**.

Tier-2 is a strict superset of the FM-5 machinery: same hash, applied to every tool
automatically and re-checked on change, rather than to a hand-pinned subset at init
only. It reuses `capability.ComputeToolHash` / `ToolHashParams` and the existing
`internal/drift` comparison seam; it is **metadata comparison, not a new subsystem**.

## Honest limit (do not overstate)

Tier-2 is **pure metadata comparison**. It catches:

- tool-description poisoning (a description rewritten to inject instructions), and
- silent interface drift (schemas or names changing under a session).

It does **not** catch a rug pull where the **advertised interface is unchanged** but
the upstream's *behavior* changes — a server that returns the same tool metadata while
doing something different on the wire. That is behavioral, not metadata, and Tier-2
makes no claim to detect it. Detecting it would require watching server behavior, which
is out of scope by design (eunox verifies attestations; it does not monitor servers).
The documentation and any operator-facing copy must state this non-coverage explicitly
rather than imply Tier-2 is a general anti-tamper guarantee.

## Wiring sketch

- `internal/drift` gains a baseline type and a re-diff entrypoint (baseline built from
  the first `tools/list`, compared against each later one), alongside the existing
  `CheckManifestDrift`. The transport already probes `tools/list` at session start for
  FM-5; Tier-2 records the baseline there and re-runs the diff whenever a `tools/list`
  result passes through.
- A new `drift.Kind` for a surface-pin break, threaded through `Warning` and the audit
  record shape (a new record type, per the audit discipline: additive field/kind, a
  sign-and-verify round-trip test, and a threat-model update).
- No change to the manifest grammar: Tier-2 needs no new manifest keys — it pins what
  the upstream advertises, not what the operator writes. (`descriptionHash` stays as the
  explicit, stricter opt-in for a tool an operator wants pinned to a *specific* hash.)

## The staged test

`internal/drift/tier2_pinning_test.go` encodes the acceptance criterion and is committed
**skipped**, demonstrably **red when unskipped**: it asserts that a description change on
an *unpinned* tool trips a pin break, which today it does not (only the opt-in FM-5 pin
fires, and only at init). Removing the `t.Skip` and making the assertion pass is the
first implementation step.
