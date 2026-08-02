# Effect contracts and the effect ceiling

**Status:** experimental, staged behind `schemaVersion: "0.2-draft"`. The tokens below are
**not part of the published `0.1` grammar** — a `0.1` manifest that uses one is refused at
load, fail closed. They are deliberately absent from
[capability-manifest-guide.md](./capability-manifest-guide.md) and from `schemas/` until
they land in a batched grammar bump. This document is where they live until then.

*(The registry corpus format is a separate artifact with its own published schema — see
[`registry/README.md`](../registry/README.md) — because a distributed corpus has its own
compatibility story and should not wait on a manifest grammar bump.)*

## The problem

Every capability control decides whether a call is **permitted**. None of them decides
whether it is **survivable**.

An agent acting on untrusted input can be steered into an action that is fully inside its
granted capabilities and catastrophic anyway:

- `DROP TABLE customers` through a `query_db` whose `allowedOperations` legitimately
  includes `DROP`,
- a $5,000 refund through a refund tool whose entire purpose is refunds,
- four hundred individually-permitted small transfers.

Identity says yes. The argument allowlist says yes. The damage is in the **consequence**.
There is no per-call fact that is wrong, which is exactly why per-call authorization
cannot reach it.

Information-flow control answers *who may know*. Effect contracts answer *what may break*.
Same enforcement point, same manifest, two axes.

## The vocabulary

Three reversibility classes, ordered least to most consequential. Flat and totally ordered
on purpose — no lattice until a partner forces a partial order.

| Class | Meaning |
| --- | --- |
| `reversible` | The caller can undo it with no external coordination (a read, an idempotent write, a soft delete with an undo). |
| `compensable` | It cannot be undone directly, but a **declared** compensating action reverses its business effect (a refund reverses a charge). |
| `irreversible` | Nothing the caller can do reverses it (an outbound email, a wire transfer, a hard delete). Also the fail-closed default for anything with no contract. |

**`compensable` is not `safe`.** The compensation may be visible, costly, or delayed, and a
compensated action still happened. The loader enforces the one invariant that keeps the
class meaningful: `compensable` requires a `compensatingAction`, and a `compensatingAction`
may not appear with any other class. Without that, "compensable" decays into a softer word
for irreversible — and "there is an undo" is precisely how an irreversible action gets
waved through a consequence gate.

## Declaring a contract

```yaml
schemaVersion: "0.2-draft"

capabilities:
  - target: tool:refund
    actions: [call]
    effect:
      class: compensable
      compensatingAction: tool:reverse_refund
      idempotent: false
      blastRadius:
        argument: amount        # the magnitude is the value of this argument
        unit: usd               # a label for reports; never compared
      ref: eunox/payments.refund@sha256:69c29150…   # optional registry pin
```

- **`blastRadius`** is either a fixed `value` or the value of a named `argument` — exactly
  one, never both. A **list** argument contributes its **length** ("how many things does
  this touch"). A non-numeric string has no magnitude and resolves to *unquantified*; it is
  not counted by characters, because inventing a magnitude is the inference this layer
  refuses to do. A **negative** argument value also resolves to unquantified: a magnitude
  is non-negative by construction, so a negative one is caller-supplied nonsense, and
  treating it as a very small number would pass every bound. A magnitude outside the
  shared numeric-literal bound (1024 characters, exponent within +/-1024) likewise resolves
  to unquantified rather than being parsed: `1e100000000` is twelve caller-supplied bytes
  that expand to gigabytes when a denial renders them, and an argument is caller-supplied.
- Every `argument` reference — here and in `byArgument` — obeys the **same `$.` nested-path
  grammar** the conditions use: `$.filters.query` traverses into a nested object, and
  `$$.x` addresses a literal top-level key named `$.x`. A malformed path resolves to
  absent, fail closed.
- **`ref`** pins the registry entry the block was authored from. eunox never fetches it —
  the decision path takes no network I/O — but the pin is **verified locally at load** by
  recomputing the digest of the inline block. Editing a pinned contract therefore fails
  until the author re-pins. `eunox contracts --ref <id>` prints the exact string to paste,
  so the digest is never hand-computed. See [`registry/README.md`](../registry/README.md).

## Operator surface

Three things about the effect layer are visible from the CLI rather than only by reading
YAML:

| Question | Command |
| --- | --- |
| How much of my policy is annotated, and what is not? | `eunox validate <manifest…>` (also in `eunox doctor`) |
| Is this contract corpus intact? | `eunox contracts --dir <path>` |
| What do I paste into `effect.ref` for this entry? | `eunox contracts --dir <path> --ref <id>` |

The coverage line is the progress meter on the flywheel below: under an `effectCeiling`
every unannotated capability escalates, so the named worklist is what turns "everything is
hitting the approval queue" into a list of files to edit. It is advisory and never changes
`validate`'s exit code — an unannotated capability is the fail-closed default working as
intended, not a defect.

`eunox contracts` loads every entry, recomputes each declared digest against its own
content, and rejects a duplicate id — the same checks the corpus test runs, reachable
without writing Go. All of it is **local**: nothing is fetched, here or on the decision
path.

### Argument-parameterized contracts

The same tool is a different effect depending on what it is asked to do. That is expressed
as a **static decision table**, resolved from the call's own arguments — no callout, no
inference:

```yaml
    effect:
      class: reversible
      byArgument:
        argument: query
        cases:
          SELECT: {class: reversible}
          DELETE: {class: compensable, compensatingAction: tool:restore_backup}
          DROP:   {class: irreversible}
        default: {class: irreversible}
```

A table, not an expression, because a table is **reviewable and pinnable** and an
expression must be executed to be understood — the property the registry depends on.

Two behaviors worth knowing:

- The first whitespace-delimited token is matched too, so `DROP` matches
  `DROP TABLE users` — and, because it splits on *any* whitespace, a multi-line or
  tab-formatted statement resolves the same verb. This is literally the rule
  `allowedOperations` uses (one shared implementation), with the same documented limit:
  **it is not a SQL parser**. Pair it with a read-only role and multi-statement execution
  disabled at the driver; never make it the sole control.
- Two case keys that fold together (`DROP` and `drop`) are **rejected at load**: one value
  cannot resolve to two effects, and leaving the tie to map order would make the verdict
  nondeterministic.
- A row that **raises** the class does not inherit the base contract's
  `compensatingAction`. Compensable is the only class that may carry one, and that
  invariant holds on the *resolved* effect, not just the authored one — otherwise an
  irreversible row would carry something claiming to reverse it, and the ceiling's
  `no_compensating_action` reason would never fire.
- An **uncovered** value falls to `default`, and an **absent** `default` means the
  fail-closed reading (irreversible, unquantified) — *not* the base contract. A table that
  does not mention a value has not said the value is safe.

## The two conditions

```yaml
    conditions:
      - type: effectClass
        allow: [reversible, compensable]   # this target may only ever do these
      - type: blastRadius
        max: 500                           # no single call over this magnitude
        maxTotal: 2000                     # no more than this SUMMED...
        windowSeconds: 3600                # ...within this sliding window
```

A call whose blast radius **cannot be quantified** fails a `blastRadius` bound — either
half of it. An action whose size cannot be established must not be treated as small, and it
must not contribute 0 to a sum; treating unknown as zero is the fail-open the condition
exists to prevent.

### Cumulative velocity

`max` bounds one call. `maxTotal` over `windowSeconds` bounds the **summed** magnitude of a
session's calls to the target — the thing per-call authorization structurally cannot see.
The per-call bound catches the $5,000 refund; it does not catch four hundred
individually-permitted $10 refunds, which is the shape a compromised or prompt-injected
agent actually produces, because every one of those calls is legal and only the aggregate
is catastrophic.

- The two cumulative keys are **set together or not at all**, and at least one of `max` or
  `maxTotal` must be present. Half a pair silently disables the other half, and an authored
  bound that bounded nothing is worse than its absence — the operator would believe a limit
  was in force. Both shapes are load errors.
- The budget is per **(session, target)**, like a `maxCalls` quota, and it is summed by
  `CallCounter.AdmitAll` over a **weight-summing** bucket — the same admission `maxCalls`
  goes through with an **entry-counting** one, on the same seam rather than in a second
  accounting system.
- An over-limit call **records nothing**. Charging a refused call's magnitude to the window
  would let a burst of rejections extend its own lockout past the window that actually
  spent the budget — the same rule an over-limit `maxCalls` follows.
- The per-call bound is checked **first**, so a call refused for being too large on its own
  never consumes cumulative budget that the permitted calls would then be denied.
- `maxTotal` must be at most 2^53, the largest total both counter backends sum exactly. The
  Redis backend evaluates its admission in Lua, whose numbers are IEEE-754 doubles; a larger
  bound would be enforced as a threshold nobody authored, so it is refused at load — compared
  in arbitrary precision, so a bound one unit above the maximum cannot round its way in. A
  **fractional** magnitude is summable and expected: currency is the motivating case, and
  both backends accumulate in double precision by contract, so `$19.99` differs from an exact
  decimal sum only in the last bits, far below any bound an operator authors.
- A call whose weight cannot move the running total — zero, or anything too small to register
  in double precision — is admitted **without being recorded**. It can never affect a future
  decision, and recording it was the one case with no bound on how much a key could grow.
- Under `--audit` the budget is **not** consumed, exactly as `maxCalls` quota is not:
  observing it accurately would spend the thing observation exists to leave alone.

## The effect ceiling

```yaml
effectCeiling:
  maxEffectClass: compensable
  maxBlastRadius: 1000
  requireCompensation: true
  onExceed: escalate        # or: deny
```

A top-level bound that **every allowed action is additionally checked against**, keyed on
the action's effect properties and never on which tool it is.

That placement is the whole point. A per-target condition guards only the targets someone
remembered to write one for, so the tool nobody thought about is the one with no gate. The
ceiling inverts that: a new or unannotated tool has no contract, therefore resolves to
irreversible, therefore exceeds the ceiling, therefore escalates. Approval is triggered by
*irreversibility + blast radius + the absence of a compensating action* — never by tool
identity.

The ceiling can only ever **narrow**: it runs after a constraint has already allowed the
call, so it never admits anything the allowlist or the conditions denied. It runs **before**
the session-state commit, so an over-ceiling call leaves neither a phantom `sequenceBlock`
antecedent nor a stranded flow label — it was never forwarded.

### Under a JWT-wrapped route

A JWT layer refuses some calls on its own terms and short-circuits above the manifest PDP,
so the ceiling would never evaluate for them. The call is still refused, but the *kind* of
refusal matters: a plain `AUTHORIZATION_FAILED` carries none of the consequence inputs a
human acts on, so the action never enters the approval queue and `eunox stats` under-counts
escalations — and, being a soft deny, an `--audit` route **forwards** it, meaning adding a
JWT would perform the very action the ceiling flagged. The wrapper therefore consults the
ceiling itself and returns its verdict, appending the token's own refusal reason to the
message so an operator fixing the token still sees it.

That consultation is **non-committing** by construction: it evaluates the ceiling alone,
never the matched constraint's conditions, because some of those commit (`maxCalls`,
`labelOutput`, `sequenceBlock`) and replaying them for a call that will never be forwarded
would leave exactly the phantom state the ordering above prevents. The ceiling's inputs are
the resolved effect and nothing else, so the composed verdict cannot disagree with a
full-path one about whether the action is over the bound. Where a *condition* would have
denied first, the composed refusal is the ceiling's rather than that condition's — harder
than the manifest's, which is the safe direction for a call that is refused either way.

`requireCompensation` applies only to an action already **above** `maxEffectClass`;
demanding a compensating action for a reversible read would be noise. It therefore requires
`maxEffectClass` to be set, and the loader rejects every shape where it is not. Two
different things enforce that for the library seam that takes a ceiling directly, since
that seam never passes through the loader: a ceiling carrying **only**
`requireCompensation` does not count as set at all, so it cannot report itself active while
being structurally incapable of refusing anything; and a ceiling carrying
`requireCompensation` **alongside `maxBlastRadius` but no `maxEffectClass`** — which *is*
set, and whose compensation leg still could never fire — exceeds outright, with the reason
`ceiling_misconfigured`. A ceiling leg that cannot be evaluated must not read as "checked
and fine".

## `escalate` is a refusal, not a pending state

The in-path proxy holds no approval workflow — approval is the control-plane surface — so
with none wired, an escalation resolves fail-closed to **not forwarded**. Every forward gate
in the proxy tests `!= allow`, so this holds structurally rather than by a check someone
could forget.

It is a **hard** refusal with the audit-mode downgrade deliberately unavailable: a route
running `--audit` cannot turn "needs human approval" into "performed anyway, logged". That
is the one downgrade that would defeat the control entirely.

What escalate buys over a plain deny is the **record**:

```
decision: escalate
denial_code: ESCALATION_REQUIRED
details:
  effect: true
  effect_class: irreversible
  ceiling_exceeded: [effect_class, no_compensating_action]
  annotated: true
  carried_labels: [untrusted]
```

`decision: escalate` is an additive **value** of the existing field, not a new top-level
field, so the signed-record schema is unchanged. It is derived inside the audit sink from
the `ESCALATION_REQUIRED` code, so no call site can record one without the other.
`carried_labels` rides in `details` here (the top-level field is reserved for allow
records) because an escalation is the one refusal a human is expected to act on, and *which
provenance produced this* is the first thing they need.

`eunox stats` tallies escalations separately: they are the operator's approval queue, not a
policy defect.

## The fail-closed flywheel

A capability with **no** `effect` block resolves to `irreversible`, unquantified. Under a
ceiling that means it escalates. So an unannotated tool costs approval friction by default,
with no configuration, and annotating it is what buys it out. That only works because
unannotated fails closed rather than reading as harmless.

Denial messages distinguish the two cases, because the remediation differs: *declared, and
it does not pass* (review the action) versus *never declared, so it defaulted to the most
consequential reading* (annotate the tool).

## Scope and limits

- **Not RBAC.** This does not re-implement DDL or database-grant controls. It covers the
  contextually-poisoned and the cumulatively-catastrophic-but-individually-permitted
  cases, **over** a resource's own grants, never instead of them.
- **Assertion, not verification.** A contract asserts what a tool does. Nothing here
  observes whether a server behaves as its contract says. The runtime counterpart is the
  effect-receipt surface below, and it too verifies attestations rather than watching
  servers.
- **Ordering.** The cumulative bound COMMITS, so it is evaluated after every pure predicate
  *and* after the effect ceiling: a call the ceiling escalates is never forwarded, so it must
  not have spent budget the calls that follow then lack. That is the same rule the
  `sequenceBlock` antecedent and the flow label already obeyed, in a third currency.
- **A count and a budget compose.** A cumulative `blastRadius` bound and a `maxCalls` are
  different questions about the same call — "how many" and "how much" — and a capability may
  carry both: *no more than 20 refunds an hour AND no more than $2,000 an hour*. They draw
  on separately-namespaced counter keys and are admitted in ONE atomic backend call, so
  neither can spend the other's budget on a call the other denies. What IS refused at load
  is two bounds of the same kind on the same `windowSeconds`: they address one physical
  bucket, so every call would be charged to it twice and the effective limit halved — a
  limit the manifest never states. Write the lower of the two instead.
- **Determinism.** Nothing on this path reads a payload, consults a model, or makes a
  network call. Effect is declared by policy and resolved from the call's own arguments.

## Effect receipts — what the server says it actually did

A contract is an assertion. Nothing above checks whether a server behaves as its contract
says, and the design deliberately refuses to find out by watching: eunox verifies
attestations, it does not monitor servers, and no payload inference or egress observation is
on the table.

A **receipt** closes that loop honestly. A server MAY publish, in a tool *result's* `_meta`,
a signed statement of what it actually did:

```json
{
  "_meta": {
    "io.eunolabs.effect-receipt": { "jws": "<compact JWS>" }
  }
}
```

whose signed payload carries the same vocabulary a contract does — `tool`, `class`,
`blastRadius`, `unit`, `compensatingAction`, and an `iat`. eunox verifies the signature
against the key domain configured for **that upstream**, checks the statement against the
contract the pre-call decision resolved, and records the verdict.

Configure it per upstream, with a **local** JWKS file:

```yaml
upstreams:
  - name: payments
    effectReceiptKeys: /etc/eunox/payments-receipt-jwks.json
```

The key domain is the **server's own**, deliberately not the JWKS that authenticates
callers. A receipt is a statement by the upstream about its own behavior — closer to
package signing than to an access token — so tying it to the caller's IdP would let any
party who can mint a caller token also mint attestations about a server's behavior. The
file is read once at startup and never fetched, for the same reason the registry is never
fetched: the check's value is that it is local and unfalsifiable.

Verdicts are a closed vocabulary, recorded under `details.effect_receipt`:

| Verdict | Meaning |
| --- | --- |
| `verified` | Signature checked against this upstream's key domain, and consistent with the declaration. |
| `inconsistent` | Signature checked; the server's own account contradicts the contract. Evidence, never a late denial. |
| `unverified` | Unknown key, bad signature, stale or future-dated. Earns nothing. |
| `malformed` | A block is present but is not a well-formed envelope. Earns nothing. |

Four properties are load-bearing:

- **Verification only, never monitoring.** The declared block is read and nothing else.
- **Fail closed on trust.** An unsigned or unverifiable receipt earns nothing, and **none
  of its claims reach the tape** — a forged "reversible, 1 row" recorded as fact would
  invert the control it is meant to strengthen.
- **Post-hoc, never retroactive.** The call already happened. An inconsistency is evidence
  and an input to future friction, never a refusal taken after the side effect.
- **Zero cost when unconfigured.** With no key domain the surface does nothing at all — no
  parse, no record. A non-supporting server simply never sets the field, so value accrues
  per server with no ecosystem coordination.

Consistency is one-directional: a server reporting a **smaller or less consequential**
action than declared is honoring the contract, since the declaration is the upper bound the
decision was made against. Only exceeding it contradicts. Silence, though, is not agreement:
a receipt that omits a dimension the contract **quantified** records as `inconsistent`
(`blast_radius_unstated`), because an attestation that never covered the bounded dimension
must not earn `verified` — the strongest signal this surface emits. A contract that could not be
resolved before the call — genuinely runtime-dynamic effect — has no bound to exceed, and
the receipt is then the only account of what happened, which is the case receipts uniquely
serve.

**Residual — replay.** `iat` plus a freshness window bounds how long a captured receipt can
be re-presented; it does not eliminate replay, which would need a nonce eunox supplies on
the request leg. That bound is adequate today because a receipt grants no friction reduction
at all: it is recorded evidence, and nothing consumes it as an authorization input. Any
future mechanism that lets a receipt lower a bar has to close this first.

## Worked example

The full scenario, running against the real binary: `make -C demo effect-escalate`
([`demo/manifest-effect.yaml`](../demo/manifest-effect.yaml)). An agent reads an untrusted
support ticket carrying an injection, then attempts `DROP TABLE customers`. The capability
is granted and `DROP` is explicitly in its `allowedOperations`; the call is escalated on its
consequence, while a `SELECT` through the same tool in the same tainted session is allowed.
`make -C demo ci-test-effect` asserts 20 identical runs with a verified tape.
