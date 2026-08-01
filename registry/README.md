# eunox effect-contract registry

A shared, reviewable corpus of **effect contracts**: what a given MCP tool *does* —
reversible, compensable, or irreversible; how big its blast radius is; whether it is
idempotent; what action compensates it — as policy input a PDP can address.

Format: [`schemas/eunox-effect-contract.schema.json`](../schemas/eunox-effect-contract.schema.json).
Entries: [`contracts/`](./contracts). Loader and validator: `internal/registry`.

## Why a registry, and why a typed schema

MCP servers already self-declare hints about their tools. A hint travels with the thing
being judged, is unauthenticated, and is set by the party whose behavior is in question. A
contract is different: it is asserted by the operator's manifest or copied from a corpus
entry someone reviewed, and it is **hash-pinned**, so the thing enforced is provably the
thing reviewed.

That pinnability is why the effect vocabulary is a closed typed schema and not a policy
language. You can hash-pin a declaration and check it locally; you cannot meaningfully pin
a policy *program*, because "what does this contract mean" would require executing it. **A
general policy language and a portable effect-contract standard are mutually exclusive**,
and this corpus is the reason the choice went the way it did. (A partner's complex
escalation *predicate* can still be delegated to Cedar/OPA through the `policy` condition —
that is a different layer.)

## Trust model — package signing, NOT behavioral verification

A contract **asserts** what a tool does. Nothing in eunox observes whether the assertion is
true, and nothing here is a scanner verdict.

What the corpus gives you:

- **Reviewable** — a closed typed schema a human reads in seconds, with a `notes` field
  carrying the *reasoning* for the class, especially where the obvious reading is wrong.
- **Pinnable** — a content digest, so a manifest can prove it enforces the entry that was
  reviewed.
- **Attributable** — an attestation naming who authored the entry and what review it has
  had (`pending`, `community`, `vendor`).

What it does not give you: any claim that a server behaves as its contract says. A
divergence between a contract and observed behavior is a **community-advisory signal**, not
a detection result. The runtime counterpart to this — a server *attesting* what it actually
did, which eunox verifies for signature and consistency — is the effect-receipt surface,
and it too verifies attestations rather than watching servers.

## How it is used — authoring time, never the decision path

eunox **never fetches a contract while deciding**. The decision path takes no network I/O,
so a registry outage cannot change a verdict.

The flow is:

1. Find the entry for a tool you are writing policy for.
2. Copy its `effect` block into the capability, and set `effect.ref` to the entry's
   `"<id>@<digest>"`.
3. eunox verifies the pin **locally at manifest load** by recomputing the digest of the
   inline block. A mismatch is a load error.

```yaml
capabilities:
  - target: tool:delete_entities
    actions: [call]
    effect:
      class: irreversible
      blastRadius:
        argument: entityNames
        unit: entities
      ref: modelcontextprotocol/memory.delete_entities@sha256:3722a7d5…
```

Editing a pinned contract therefore fails at load until the author re-pins — which is
exactly the review step the registry exists to create. Without that check, `ref` would be a
comment: a manifest could carry a reviewed contract's id while enforcing something else,
the one substitution a hash-pinned registry exists to prevent.

## The fail-closed flywheel

A capability with **no** effect contract resolves to the most consequential reading:
irreversible, blast radius unknown. Under a policy's `effectCeiling` that means it
**escalates**. So:

- an unannotated tool costs you approval friction, by default, with no configuration;
- annotating it is what buys it out;
- the corpus is where the annotation comes from.

That is the flywheel, and it only works because "unannotated" fails closed rather than
being treated as harmless.

## Digest semantics

`digest` is sha256 over the canonical JSON encoding of the `effect` block, with `ref`
excluded (a contract cannot contain its own digest). Two entries whose contracts are
**identical in content share a digest** — that is correct and expected. Identity lives in
`id`; integrity lives in `digest`. `read_file` and `brave_web_search` both being
"reversible, idempotent" is the same *contract* attached to two different tools.

## Contributing an entry

- One file per contract, named after its id with `/` replaced by `_`.
- Set `attestation.source` honestly: `authored` (written by hand from the tool's documented
  behavior), `vendor` (contributed by the server's publisher), or `imported` (derived from
  an orchestrator's existing compensation definitions — a shop already running SAGA-style
  workflows has half-annotated its tools: has-compensation ⇒ `compensable`,
  read/idempotent ⇒ `reversible`, neither ⇒ `irreversible`).
- `attestation.review` starts at `pending`. It is not a correctness guarantee at any value.
- Recompute `digest` after any edit to `effect`. `go test ./internal/registry/` fails
  otherwise, and so does any manifest that pinned the old value.
- The corpus test also checks each entry's `effect` block **semantically**, not just for
  digest consistency — a digest over nonsense is still a stable digest. It runs the same
  validators the manifest loader applies (they live in `pkg/capability`, which owns both
  the vocabulary and the digest, so the two layers cannot disagree about what a valid
  contract is). An entry fails the test when it:
  - names a `class` outside the closed vocabulary (a typo, or a plausible-sounding
    invention such as `safe`);
  - is `compensable` but names no `compensatingAction`, or names one under a
    non-compensable class — including in a `byArgument` row, judged against the class and
    action the row *effectively* has after inheriting from the base block;
  - declares a `blastRadius` with both a fixed `value` and an `argument`, or with neither;
  - declares a `byArgument` table with no `argument`, with neither `cases` nor `default`,
    or with two case keys that match the same argument value (matching is case-insensitive
    after trimming, so `DROP` and `drop` are one key);
  - carries its own `effect.ref` — a corpus entry *is* the thing a ref points at.

  Previously only the digest was checked, so a mistake in an entry survived review and
  surfaced later as a confusing manifest-load error about a block the author had copied
  verbatim from here.
- **Be conservative.** `compensable` means *a declared action reverses this*, and it is the
  class most easily mislabeled — "there is an undo" is how an irreversible action gets waved
  through a consequence gate. Compensable is not safe: the compensation may be visible,
  costly, or delayed, and the action still happened. The shipped entries record that
  reasoning in `notes`; a compensable entry without notes fails the corpus test.

## Status

The shipped entries are **eunolabs-authored and review-pending**: written from public
documentation of widely-used MCP servers, not contributed or confirmed by their publishers.
They are a starting corpus and a worked demonstration of the format, not an authority.
Vendor attestation and community review are what turn them into one.
