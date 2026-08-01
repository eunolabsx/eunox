# Interface pinning — Tier-2

**Status:** implemented and on by default. No manifest key, no flag: every session
auto-baselines the advertised surface of every tool the upstream reports and denies a
tool whose surface later changes. The acceptance suite is
`internal/pdp/surface_pin_test.go`.

## What ships today

Interface conformance has three pieces:

- **Tier-1 (request side).** Argument validation, method mapping, and fail-closed
  handling of unmapped methods — a request that does not conform to the manifest is
  denied before it reaches the upstream.
- **`descriptionHash` pinning (FM-5).** An *opt-in, per-tool* pin: an operator writes
  `descriptionHash: "sha256:..."` on an exact-name `tool:` target, and
  `internal/drift` verifies the live tool's advertised surface hash against it **at
  session init** (and in `validate --live`). The hash is computed by
  `capability.ComputeToolHash` over the tool's description plus its title, annotations,
  input schema, and output schema (`capability.ToolHashParams`). A mismatch is fatal.
- **Tier-2 (this document).** The same hash, applied **automatically to every advertised
  tool** and **re-diffed on every `tools/list`**, pinned to what the tool first advertised
  in this session rather than to a hash an operator wrote.

Tier-2 closes the two gaps `descriptionHash` leaves:

1. FM-5 only covers tools an operator **manually pinned**. An unpinned tool's advertised
   surface could change with no finding.
2. FM-5 only ran **at session init**. MCP lets a server change its tool list mid-session
   (`notifications/tools/list_changed`, after which the client re-lists); a surface that
   changed *after* init was not re-checked.

## Behavior

- **Baseline.** The first `tools/list` a session sees establishes the baseline: a
  `toolName -> surfaceHash` map, where the hash is `capability.ComputeToolHash` over
  exactly the bytes FM-5 pins (description + every parameter description at any depth +
  title + annotations + `outputSchema` descriptions). When the manifest configures a
  startup drift check, the session-start probe is that first list, so the baseline is
  taken before the host has listed anything; otherwise the host's first `tools/list`
  takes it.
- **Re-diff on change.** Every later `tools/list` result in the session is re-hashed and
  compared. This covers both the enforce-mode filter and the audit-mode (observe) path,
  where the catalog is forwarded verbatim and `RecordObservedToolHashes` is the only pass
  that can arm the pin.
- **A changed surface is a pin break.** The tool is **denied on the `tools/call` leg**
  with a hard `AUTHORIZATION_FAILED` (not downgradable — an `--audit` route cannot forward
  it) and **hidden from `tools/list`**, so the catalog a host is shown never advertises a
  tool its call leg will reject. The break is **sticky**: reverting the surface does not
  re-open the tool, because a host may still hold the rewritten copy.
- **The break outranks a wrapping PDP's own refusal.** A JWT-backed route short-circuits
  above the manifest PDP on its own denials, so the pin check inside it does not run for
  such a call. Were the composed refusal left soft, an `--audit` route would downgrade it
  to a forward and send the request to the rewritten upstream — so turning a JWT on would
  have removed a guarantee, which inverts the rule that a JWT may only *restrict*. The
  wrapper therefore re-stamps its refusal as hard when the pin is broken, keeping the
  wrapping layer's own code and message (an operator fixing the token still needs to see
  the authorization failure) and adding the pin break to it.
- **Membership findings need a complete listing.** A single *page* of a paginated
  `tools/list` says nothing about which tools exist, so additions and removals are reported
  only for an observation that covers the whole advertised surface (the session-start probe,
  which fetches every page). A partial page still baselines and re-diffs each tool it
  carries — a surface change is per-tool — so a break is never suppressed by pagination;
  only the membership notices are.
- **Adds and removes are advisory.** MCP supports a changing tool list explicitly, and a
  new tool is still gated by the manifest allowlist, so an appearance or disappearance is
  logged, not denied. An added tool is baselined on sight, so a later change to *it* is a
  break like any other; a removed tool's baseline is **retained**, so a tool that
  disappears and returns with a rewritten surface still breaks.
- **Untrustworthy bytes fail closed.** A `tools/list` entry the proxy cannot trust to
  decode to what a host renders (a duplicate or case-variant key) cannot be baselined, so
  every name it could be presenting is broken. An entry whose bytes aborted the trust scan
  — leaving the names it could impersonate unknown rather than none — and an unreadable
  envelope or `tools` array break every tool the session had baselined.
- **Findings are logged.** Each finding emits one structured stderr line
  (`[eunox] ERROR drift=tier2 tool="..." — ...`), matching the shape `internal/drift`
  emits for FM-1..FM-6 so an operator greps interface findings uniformly.

## Scope: per session, not per process

The baseline is keyed by **session**, and released on session teardown alongside the
flow-label state. Two reasons:

- A tool's advertised surface changing *within* a session is anomalous — servers evolve
  across restarts, not mid-conversation — so a session-scoped pin has a low false-positive
  rate while still catching the mid-session rewrite that is the poisoning carrier.
- In HTTP/gateway mode one per-route PDP serves N sessions, each with its own upstream
  process. A per-process baseline would let a session talking to an upgraded server poison
  every other session on the route until the proxy restarted.

**Recovery from a false positive is therefore a new session, not a proxy restart.** That
is why Tier-2 ships without an off switch: the blast radius of a wrong verdict is one
session, and an off switch is a fail-open an operator would reach for exactly once.

## Honest limit (do not overstate)

Tier-2 is **pure metadata comparison**. It catches:

- tool-description poisoning (a description, title, annotation, or parameter description
  rewritten to inject instructions), and
- silent interface drift (schemas or names changing under a session).

It covers **tools only**. Prompt and resource descriptions reach the model by the same
route a tool description does, and neither Tier-2 nor the manifest's `descriptionHash`
pins them; the two other `*/list` flavors carry only the per-entry ambiguity gate (an
entry whose bytes could decode differently for the proxy than for the host is dropped).
The baseline machinery is generic over `(name, hash)`, so extending it is a design
decision rather than a rewrite — but until that decision is made, do not describe eunox
as pinning "the advertised surface" without saying which surface.

It does **not** catch a rug pull where the **advertised interface is unchanged** but
the upstream's *behavior* changes — a server that returns the same tool metadata while
doing something different on the wire. That is behavioral, not metadata, and Tier-2
makes no claim to detect it. Detecting it would require watching server behavior, which
is out of scope by design (eunox verifies attestations; it does not monitor servers).
The break log line states this non-coverage inline, and operator-facing copy must do the
same rather than imply Tier-2 is a general anti-tamper guarantee.

## Where it lives

`internal/pdp/surface_pin.go` holds the baseline (`SurfaceBaseline`), the diff, and the
sticky break set; `internal/pdp/pdp.go` arms it from the one `tools/list` pass that also
arms the FM-5 pin, and consults it on the call leg and in the list filter.

**Deviation from the original design sketch, recorded:** that sketch put the baseline in
`internal/drift` alongside the FM-1..FM-6 comparison. It is in `internal/pdp` instead,
because Tier-2 must *deny* — and the call-leg decision and the list filter both live in
the PDP, which sits **below** `internal/drift` in the layering (`internal/drift` imports
`internal/pdp`, so the reverse is a cycle). Putting the state in `drift` would have meant
either a second copy of the break set in the PDP or a new transport-mediated hook to push
verdicts down a layer. The comparison itself is one line — hash equality against the same
`capability.ComputeToolHash` primitive FM-5 uses — so nothing about the drift *policy* is
duplicated by the move. The session-scoping decision above is the second deviation: the
sketch said "for the session" and this implements exactly that, which the per-route PDP
made a real design constraint rather than a wording detail.

No manifest grammar change: Tier-2 pins what the upstream advertises, not what the
operator writes. `descriptionHash` stays as the explicit, stricter opt-in for a tool an
operator wants pinned to a *specific* hash, verified at startup and fatal on mismatch.
