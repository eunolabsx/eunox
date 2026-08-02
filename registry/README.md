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

- **Signed** — an optional `signatures` array carrying a vendor's or a reviewer's Ed25519
  statement over the entry's content digest, verified locally against a trusted-key file
  you supply. That is what turns the attestation block above from an unverifiable label
  into something a second party asserted with a key. See
  [Vendor attestation and community review](#vendor-attestation-and-community-review).

What it does not give you: any claim that a server behaves as its contract says. A
divergence between a contract and observed behavior is a **community-advisory signal**, not
a detection result. The runtime counterpart to this is the **effect-receipt** surface — a
server *attesting*, in a tool result's `_meta`, what it actually did, which eunox verifies
for signature (against that upstream's own key domain, configured per upstream and never
the caller's IdP) and for consistency with the contract the decision used. It too verifies
attestations rather than watching servers, and an unverifiable receipt earns nothing. The
two halves of the same trust story: reviewable, pinnable, attributable *declarations* here;
what the server says it did at runtime there. See
[`docs/effect-contracts.md`](../docs/effect-contracts.md).

## How it is used — authoring time, never the decision path

eunox **never fetches a contract while deciding**. The decision path takes no network I/O,
so a registry outage cannot change a verdict.

The flow is:

1. Find the entry for a tool you are writing policy for — `eunox contracts` lists the
   corpus, verifying every entry's digest against its own content as it goes.
2. Copy its `effect` block into the capability, and set `effect.ref` to the entry's
   `"<id>@<digest>"`. `eunox contracts --ref <id>` prints exactly that string, so the pin
   is copied rather than hand-computed.
3. eunox verifies the pin **locally at manifest load** by recomputing the digest of the
   inline block. A mismatch is a load error.

```console
$ eunox contracts --ref modelcontextprotocol/memory.delete_entities
modelcontextprotocol/memory.delete_entities@sha256:3722a7d51f956e37275c957bb15295491ccdbffe5897bebadc309028ad125b67
```

Both are **local**: the digest is over the contract's own content, so verifying a corpus
someone handed you and pinning an entry from it both work offline. `--dir` points at any
corpus directory; nothing searches, and a path that does not exist is an error rather than
a clean bill of health for an empty result.

To see how much of a policy is annotated, `eunox validate` (and `eunox doctor`) report the
ratio and name what is missing — under an `effectCeiling` those are exactly the capabilities
that will escalate.

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

## Vendor attestation and community review

A content digest establishes that an entry **is what it says it is**. It says nothing about
*who* is saying it, and nothing about whether anyone else has looked. Those are the two
things that turn a corpus of files into a corpus with a trust model.

An entry may carry a `signatures` array: Ed25519 statements over the entry's content digest,
each naming the key that made it, the **role** its signer claims, and **what** they claim.

```jsonc
"signatures": [
  {
    "keyId": "stripe-2026",
    "algorithm": "ed25519",
    "role": "vendor",        // "vendor" = publishes the server; "reviewer" = a third party
    "statement": "attests",  // "attests" = the contract is correct; "disputes" = it is not
    "signature": "<base64>"
  }
]
```

Verify a corpus against keys **you** have chosen to trust:

```console
$ eunox contracts --trust-keys ./trusted-keys.json
OK    ./trusted-keys.json  (2 trusted attestation key(s))
OK    registry/contracts  (12 contract(s), every declared digest matches its content)

ID                        TOOL           CLASS        REVIEW   ATTESTATION  REF
stripe/mcp.create_refund  create_refund  compensable  vendor   vendor       stripe/mcp.create_refund@sha256:cf8e…
```

The trust store is a local JSON file — there is no key discovery, no fetch, and no
well-known URL:

```jsonc
{
  "keys": [
    {
      "keyId": "stripe-2026",
      "algorithm": "ed25519",
      "publicKey": "<base64 raw 32-byte Ed25519 public key>",
      "owner": "Stripe",
      "roles": ["vendor"]     // optional: what this key may assert. Empty means any.
    }
  ]
}
```

`roles` exists because trusting a key is not one decision. You may well trust a security
researcher's key as a **reviewer** while not accepting it as the vendor of anything, and
without this the two would be the same grant.

### Four properties, each a deliberate limit

1. **Local, always.** Verification takes the trust store you point at and nothing else, so
   checking a corpus someone handed you works offline.
2. **Never on the decision path.** Attestations are authoring-time input. A manifest still
   pins an entry by content digest, and that pin is still what the manifest loader verifies.
   An unattested contract enforces exactly as it did before — attestation changes what a
   human knows when choosing to pin it, not what the proxy does with it.
3. **A claim of authorship, not of truth.** A vendor signature says the vendor asserts this
   is what their tool does. Nothing here observes the tool. A **dispute** is likewise a
   community-advisory signal, not a detection result — the same posture the drift layer
   takes about a manifest/upstream mismatch. A disputed entry is surfaced prominently and is
   **not** an error exit: someone who looked disagreeing is a signal to weigh.
4. **An untrusted signature is inert; a trusted one that fails is an error.** A corpus may
   carry signatures from keys you have never heard of, and refusing to load it over one
   would make every entry's usability depend on collecting every publisher's key — those are
   reported as `unverified(n)`, which is a materially different state from unsigned. But a
   signature by a key you *did* configure that does not verify means the entry was **edited
   after it was signed**, and that stops the command.

### Producing a signature

eunox **verifies** attestations and never mints them — it holds no signing key, for the same
reason it consumes IdP tokens and never issues them. What it gives a publisher is the exact
byte string to sign:

```console
$ eunox contracts --attest-payload stripe/mcp.create_refund --role vendor --statement attests
eunox-effect-contract-attestation/v1
stripe/mcp.create_refund
sha256:cf8e502e17adee78495c683e8a96da5fff5d85ca967d8dc6bc2c014e2bd08898
vendor
attests
```

Sign those bytes with your Ed25519 key, base64 the 64-byte signature, and add the entry to
`signatures`. Note what is inside the payload: the **digest**, so re-signing is required
after any edit to the `effect` block; and the **role and statement**, so a reviewer's
signature cannot be re-presented as a vendor's and a dispute cannot be edited into an
endorsement. There is deliberately no timestamp — a value beside a signature that the
signature does not cover is exactly the mistake this format should not permit, and a
timestamp inside it would promise a freshness story an offline trust store cannot deliver.

Signatures sit **outside** the digest. Each one is over the digest, so including them would
be circular — and every added countersignature would invalidate every manifest pin to the
entry.

## Status

The shipped entries are **eunolabs-authored and review-pending**: written from public
documentation of widely-used MCP servers, not contributed or confirmed by their publishers.
They are a starting corpus and a worked demonstration of the format, not an authority. None
of them is signed yet — the format and the verifier are in place, and the signatures are the
part only their publishers and reviewers can supply.
