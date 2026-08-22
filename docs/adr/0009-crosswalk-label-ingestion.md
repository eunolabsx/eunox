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
flowLabelNamespaces: [msip, sensitivity]   # every label the table can mint

- target: tool:fetch_document
  actions: [call]
  directives:
    - type: labelOutput
      labels: [confidential]            # the floor, asserted regardless
      from: "$.metadata.msip_label"     # a DECLARED field, never the content
      map:  purview-crosswalk

crosswalks:                             # their taxonomy -> our namespace
  purview-crosswalk:
    map:
      "Confidential\\PII":   ["msip:confidential", "sensitivity:gdpr-pii"]
      "Highly Confidential": ["msip:highly-confidential"]
      "General":             []
    unmapped:                ["msip:unclassified"]
```

The fallback sits **beside** the value table rather than inside it. The
incumbent's value space is deliberately not enumerable, so a reserved key within
it would be a key eunox claims and a taxonomy could legitimately use; `map` and
`unmapped` as siblings leave the value key space wholly the incumbent's.

**Every label the table can mint goes through the same namespace closure the
authored ones do** — `validateFlowLabelSet` against the declared
`flowLabelNamespaces` (`internal/config/manifest.go:1796`), which today covers
`flowLabel`'s `allow`, `labelOutput`'s `labels`, and `declassify`'s `labels`. A
crosswalk's right-hand sides are a fourth site producing labels, and they must
take that check at load or the grammar loses its one real invariant: that a
label legal in a `labelOutput` is legal in the `flowLabel` that reads it back.

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
than as a rule stated across two directives — is what makes the authored
`labels` an actual floor rather than a default someone has to remember.

**The floor is the whole of what the trust gate does not have to carry, and the
residual above it is stated rather than glossed.** A crosswalk cannot take the
session below the authored `labels`, whatever the upstream returns. It can,
however, land a *weaker set than a correct mapping would have* whenever the
upstream drives the value to the `unmapped` arm — by omitting the field,
returning `null`, returning a non-string, or spelling the value differently (a
body the walker refuses denies outright, and so is not one of these) — and an
authored `unmapped` is by construction a set the
policy is willing to accept. So a table that declares `unmapped` hands the
upstream a channel around its own mapping, bounded below by `labels` and by
nothing else. Two things follow: the authored `labels` floor is the load-bearing
control and an `unmapped` entry is the convenience, not the reverse; and the
comparison is **exact bytes**, with no case folding, trimming, or Unicode
normalization, so a spelling variant lands on `unmapped` (visible, and floored)
rather than silently matching a neighbouring entry.

**The mode is refused unless the operator declares the upstream a trusted label
source**, on the upstream in deployment config. The field is upstream-controlled,
so an untrusted server asserting `"General"` would be asserting *less*
sensitivity than the data carries. Trust in a particular deployment's upstream is
deployment wiring; the crosswalk table is policy vocabulary — which is why they
live in different files.

The refusal belongs on `LoadUpstreamPDP` (`internal/transport/route.go`), **not**
on `BuildRoutes`. `BuildRoutes` is the gateway's path only; the stdio transport
reaches its policy through `LoadUpstreamPDP` directly (`cmd/eunox/main.go:1753`),
so a gate placed at route build would ship the fail-open ungated on stdio — the
exact hazard `LoadUpstreamPDP`'s own `requireUsable` calls already exist to close
at that seam, and for the reason its comment gives.

**The taint commits before any response byte reaches the host, and the call
HOLDS the decision turn until it has.** A sink issued concurrently with the
source call cannot carry the data — it was issued before the data existed — so
ordering against *sinks* would not by itself require the turn. Ordering against a
concurrent **declassify** does. `finishDecision` (`internal/transport/dispatch.go:104`)
already keeps the turn past the forward for exactly one case, and gives the
reason: a declassifying call splits its flow-state write across the decision
(resolving what to clear) and the post-forward commit (removing it), so releasing
early lets a concurrent source land between the two and have a fresh taint
wrongly cleared. A crosswalk commit **is** such a source, and lands in precisely
that window. Extending the same exception to a constraint carrying the
response-reading form is therefore not new machinery, and not a conservatism
preference — it is the existing exception applied to the second member of the
class it was written for.

The cost is the one `finishDecision` already documents: head-of-line blocking on
the anchor for the duration of one ingesting call, bounded by
`--upstream-timeout`, paid only by calls that actually ingest.

**A commit that fails withholds the response.** A flow-store fault turns an
allowed call into an `ENFORCEMENT_ERROR` and the result is not relayed. Handing
the host tainted data with the taint unrecorded is the fail-open the whole layer
exists to prevent.

**The ingested labels land on the call's own allow record, as a new top-level
field beside `labels_out`.** The allow record is written *after* the forward, the
redaction and the declassify commit (`internal/transport/forward.go`), so the
response-derived set is in hand before there is a record to write — nothing has
to be appended to a record already on the tape, and the append-only invariant is
untouched. `labels_cleared` is the precedent and the proof: it is likewise
derived post-forward and is carried as a signed top-level field on the same allow
record, through `RecordDeclassifiedAllow`.

It is a **separate field** rather than more entries in `labels_out`, because an
auditor has to be able to tell what the policy asserted from what the upstream
said — the separation `declared_labels` and `delegated_labels` draw, though those
are keys in a denial's `Details` map rather than top-level fields, so they are
the precedent for the *distinction*, not for the shape. The source value rides
along, bounded and control-sanitized (`capability.BoundString` +
`capability.SanitizeControlRunes`), since it is a string eunox did not author.

A new top-level field means **the threat model must be updated in the same
change** — `CONTRIBUTING.md` requires it, and the delegation work set the
precedent of recording explicitly that it added none.

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
- **Releasing the decision turn at the decision, as a non-declassifying call
  does** — rejected, and it was this record's own first answer. The argument for
  it (a concurrent sink cannot carry data it was issued before) is sound but
  answers only half the question: it says nothing about a concurrent
  *declassify*, whose held window a post-forward taint commit lands inside.
- **A second audit record for the ingestion** — rejected: also this record's own
  first answer, on the mistaken premise that the allow record was already
  written. It is not; it is written after the forward, which is why
  `labels_cleared` can already carry post-forward state on it.
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
- **A wider allow record**, not a second one. The earlier draft of this decision
  assumed the allow record was already written by then and budgeted a second
  record against the record-rate limiter; both halves were wrong — that limiter
  meters refusal categories, not allows, and the ordering makes the second record
  unnecessary. What the extra field does cost is audit queue depth under
  `--require-audit=strict`, which is where a real bound would have to be argued.
- **Head-of-line blocking on the anchor for the length of an ingesting call**,
  since it holds the decision turn past the forward. This is the second member
  of the class `finishDecision` already pays that cost for, so the cost is
  precedented — but it now applies to a directive an author may reach for far
  more often than `declassify`.
- **An upstream can route around its own mapping** wherever the table declares
  `unmapped`, bounded below by the authored `labels` floor and by nothing else.
  The floor is the control; `unmapped` is a convenience that widens what the
  upstream can choose.
- **A wrong trust declaration is a fail-open**, which is why it is a hard
  refusal at `LoadUpstreamPDP` — the seam BOTH transports reach — and not a
  `validate` warning.

Tests this commits us to: table-driven crosswalk resolution (mapped, unmapped,
absent, `null`, non-string, malformed envelope, and a spelling variant landing on
`unmapped` rather than a neighbour); the load-time collision rule and the
multi-file union; every right-hand label taking the `flowLabelNamespaces`
closure, so an undeclared namespace in a crosswalk is refused exactly as one in a
`labelOutput` is; the `0.1` refusal for the new token; the trust-gate refusal
reached on BOTH transports, not only the gateway; the turn being held past the
forward for an ingesting constraint; the commit-failure-withholds-response path;
and a sign-and-verify round trip for the new field.

Docs this commits us to keeping in sync: `docs/capability-manifest-guide.md`
§5b, the `$defs` branch plus the top-level `crosswalks` key in
`schemas/eunox-capability-manifest.schema.json`, `docs/threat-model-mcp.md` for
both the upstream-asserted-label trust boundary and the new top-level audit
field, and the spec repo
(`eunolabs/agent-capability-manifest`), which `CONTRIBUTING.md` requires for any
manifest grammar change.

The axis this rests on has landed, so nothing external gates the build; what
gates it is this decision, which is `Draft` until maintainer consensus moves it.
