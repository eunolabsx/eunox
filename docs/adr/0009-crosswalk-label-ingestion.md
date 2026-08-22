# ADR-0009: Ingest an imported sensitivity label from a declared response field

- **Status:** Draft
- **Date:** 2026-08-22
- **Deciders:** eunox maintainers

## Context

The imported-sensitivity axis lets a policy name a class from an external
taxonomy as `namespace:value` alongside the closed native provenance set. Today
that assertion is **authored per target**: the policy author writes
`purview:highly-confidential` on the source capability, and every call to that
target carries it. Coarse, but zero integration — and wrong the moment one tool
returns items of different classes.

The sharper mode is the one where the label **travels with the data**.
Purview/MSIP labels already live in artifact metadata (Office XML parts,
`x-msip` headers, Graph `assignedLabels`), so where an upstream passes that
through, eunox can read a **declared field structurally** — the way
`redactFields` reads a named path, never the content — and map the source
taxonomy's own spelling onto the namespaced axis.

This is not a new argument on an existing directive. `labelOutput`
(`pkg/capability/flowlabel.go:367`) is a **decision-time state write on allow**:
that is exactly why it carries no response obligation
(`pkg/capability/flowlabel.go:377`) and is valid on any source target, `tool:`
or `resource:`. Deriving a label from `$.metadata.msip_label` makes it
**response-reading for the first time**, which changes when the taint is known,
what happens when it cannot be committed, and what an audit record can say about
it.

Three questions had to be answered before any code, and a fourth constraint had
to ship with it:

1. Where the crosswalk lives, and how it merges.
2. What a source value with no crosswalk entry means.
3. Whether the field reference reuses the existing path grammar.
4. Where the trust boundary is — a label is only as trustworthy as its source,
   and an agent-settable or downgradeable one defeats flow control entirely.

The invariants in play: **fail closed on any ambiguity**, **audit records are
append-only** ([CONTRIBUTING.md](../../CONTRIBUTING.md)), conditions match a
**specific** named field and never silently match alternatives, and — decisively
for question 2 — both label axes are **flat**, with no lattice and no partial
order, including between two values of one taxonomy.

The imported-sensitivity axis this builds on is in place: a label may name a
class from an external taxonomy as `namespace:value`, and the top-level
`flowLabelNamespaces` declares the taxonomies a policy speaks, merged as a union
across files (`internal/config/manifest.go:1843`). The guide records the
crosswalk itself as deliberately not wired, for the trust reason question 4
states (`docs/capability-manifest-guide.md` §5b).

## Decision

**We will ingest an imported label from a declared response field, as a
response-reading form of `labelOutput` that can only ever ADD taint, gated on
the operator declaring the upstream a trusted label source.**

```yaml
- target: tool:fetch_document
  actions: [call]
  directives:
    - type: labelOutput
      labels: [confidential]            # the floor, asserted regardless
      from: "$.metadata.msip_label"     # a DECLARED field, never the content
      map:  purview-crosswalk

crosswalks:                             # their taxonomy -> our namespace
  purview-crosswalk:
    "Confidential\\PII":   ["msip:confidential", "sensitivity:gdpr-pii"]
    "Highly Confidential": ["msip:highly-confidential"]
    "General":             []
    unmapped:              ["msip:unclassified"]
```

**The crosswalk lives in the manifest**, as a top-level `crosswalks` key
published under `schemaVersion "0.2"` — the open pre-1.0 grammar head that also
carries `flowLabelNamespaces`. A crosswalk entry *decides taint*, and the
manifest is what `policy_sha256` digests onto every audit record. A table in
deployment config could change what a label means without changing the digest an
auditor joins on.

**Merging is a union across names; a colliding entry is a load error.**
`flowLabelNamespaces` unions freely because a namespace grants nothing on its
own. A crosswalk entry does. Two files mapping one source value to different
label sets is a contradiction rather than composition, so it takes the conflict
check `audience` takes; an identical re-declaration is idempotent and allowed.

**An unmapped source value takes the table's authored `unmapped` entry, and is a
hard deny when the table declares none.** There is no "most-sensitive class" to
fall back on: both axes are deliberately flat, so *conservative* has no
structural meaning here, and the fallback has to be authored by the person who
knows the taxonomy. An empty label set as the default would be fail-open — the
one direction the union-only rule forbids everywhere else. Saying "this value
carries nothing" stays possible and stays explicit (`"General": []`). A field
that is **absent**, `null`, or not a JSON string takes the same path as an
unmapped value, so there is one rule and one code path rather than four.

**`from` reuses the `$.` dot-path grammar in its response-side `redactFields`
reading** — the same root normalization (`internal/pdp/redact.go:949`), the same
depth bound, and the same structural fail-closed guards
(`internal/pdp/redact.go:39`): an unparseable envelope, duplicate or
case-colliding object keys, or a `resource`/`resource_link` item whose embedded
body the walker cannot inspect all deny rather than resolving to "absent". A
second grammar for the same job is the drift this repo removes elsewhere.

**The response-reading form is valid on `tool:` targets only.** It needs a
response the proxy inspects, and that is `tools/call` today — the reasoning
`requireResponseDirectiveTarget` (`internal/config/manifest.go:1769`) already
applies to `redactFields`. Native `labelOutput` keeps its any-source-target
validity (`internal/config/manifest.go:1780`), because a decision-time assertion
needs no response.

**`labels` and `from`+`map` compose on one directive, and the ingested set is
UNIONED into the authored one.** `from` and `map` must appear together, and a
directive carrying neither shape is a load error, so "response-reading with
nothing to read" is unrepresentable. Encoding the union structurally — rather
than as a rule stated across two directives — is what makes "the crosswalk can
only add" a property of the shape instead of a property someone has to remember:
a downgrade attempt by the upstream can at worst fail to add.

**The mode is refused unless the operator declares the upstream a trusted label
source**, per route in deployment config. The field is upstream-controlled, so
an untrusted server asserting `"General"` would be asserting *less* sensitivity
than the data carries. Trust in a particular deployment's upstream is deployment
wiring; the crosswalk table is policy vocabulary — which is why they live in
different files, and why a manifest carrying the response-reading form is
refused at route build when its route makes no such declaration.

**The taint commits before any response byte reaches the host, and the decision
turn is not extended across the forward.** Data can only flow into a later call
after the host has the response, so a sink issued *concurrently* with the source
call was issued before the data existed and cannot carry it. The accepted cost is
stated rather than hidden: for that concurrent window the crosswalk form is
**less conservative** than the decision-time native form, which over-blocks it.
That is a property of this form only and must not be generalized to the rest of
the flow layer.

**A commit that fails withholds the response.** A flow-store fault turns an
allowed call into an `ENFORCEMENT_ERROR` and the result is not relayed. Handing
the host tainted data with the taint unrecorded is the fail-open the whole layer
exists to prevent.

**The ingestion writes its own audit record.** The allow record was already
written when the response arrived, and records are append-only, so the ingested
labels cannot be folded into it. The new record reports the ingested set
separately from policy-asserted `labels_out` — an auditor has to be able to tell
what the policy said from what the upstream said, the same separation
`declared_labels` and `delegated_labels` already carry — together with the
source value, bounded and control-sanitized (`capability.BoundString` +
`capability.SanitizeControlRunes`), since it is a string eunox did not author.

## Alternatives considered

- **Crosswalk in deployment config** — rejected: it would change what a label
  means without changing the `policy_sha256` on the tape.
- **Crosswalk in its own file** — rejected: a third merge order and a second
  digest to pin, for a table that is policy vocabulary either way.
- **Unmapped ⇒ the most-sensitive class** — rejected: the axes are flat, so no
  such class exists to name.
- **Unmapped ⇒ empty label set** — rejected: fail-open, and silently so.
- **Unmapped ⇒ load error** — rejected: impossible. The value space is the
  incumbent's and is not enumerable at load.
- **A separate discriminator for the response-reading form** — rejected: it
  would split the union of authored and ingested labels across two directives
  and lose the structural guarantee that ingestion can only add.
- **Extending the decision turn across the forward** — rejected: it serializes
  an in-flight upstream call per anchor to close a window that provably cannot
  carry the data.
- **Inferring sensitivity from response content** — rejected permanently, not
  for this iteration. eunox reads a declared field structurally and runs no
  classifier; see [ADR-0010](./0010-no-decision-path-classification.md).

## Consequences

Real sensitivity flows without the operator restating a taxonomy eunox does not
own, the table that decides taint sits inside the policy digest, and the trust
boundary is a declaration an operator makes rather than an assumption the code
carries.

The costs are real:

- **`labelOutput` is no longer uniformly decision-time.** Every reader of the
  flow layer now has to ask which form a directive is, and the two forms differ
  in commit point, target validity, and trust requirement.
- **A new denial shape reaches the host: a deny after an allow.** A call the
  policy permitted can still end in `ENFORCEMENT_ERROR` with the response
  withheld. Clients and the integration guide need to expect it.
- **A second audit record per ingesting call**, which the record-rate
  admission control has to budget for.
- **The concurrent-sink window is weaker than the native form's**, and the
  reason it is safe is an argument rather than a mechanism — it needs to be
  restated wherever someone is tempted to reuse it.
- **A wrong trust declaration is a fail-open**, which is why it is a hard
  route-build refusal and not a `validate` warning.

Tests this commits us to: table-driven crosswalk resolution (mapped, unmapped,
absent, `null`, non-string, malformed envelope); the load-time collision rule and
the multi-file union; the `0.1` refusal for the new token; the trust-gate
refusal at route build; the commit-failure-withholds-response path; and a
sign-and-verify round trip for the new record's fields.

Docs this commits us to keeping in sync: `docs/capability-manifest-guide.md`
§5b, the `$defs` branch plus the top-level `crosswalks` key in
`schemas/eunox-capability-manifest.schema.json`, `docs/threat-model-mcp.md` for
the upstream-asserted-label trust boundary, and the spec repo
(`eunolabs/agent-capability-manifest`), which `CONTRIBUTING.md` requires for any
manifest grammar change.

The axis this rests on has landed, so nothing external gates the build; what
gates it is this decision, which is `Draft` until maintainer consensus moves it.
