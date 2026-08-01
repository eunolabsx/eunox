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
  until the author re-pins. See [`registry/README.md`](../registry/README.md).

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
```

A call whose blast radius **cannot be quantified** fails a `blastRadius` bound. An action
whose size cannot be established must not be treated as small; treating unknown as zero is
the fail-open the condition exists to prevent.

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
  observes whether a server behaves as its contract says. The runtime counterpart —
  a server attesting what it actually did, which eunox verifies for signature and
  consistency — is the effect-receipt surface, and it too verifies attestations rather
  than watching servers.
- **No cumulative velocity yet.** "No more than $2,000 of refunds an hour" — the four
  hundred individually-permitted $10 refunds — is **not expressible**. It needs a weighted
  sliding-window sum the `CallCounter` contract does not provide, and the grammar
  deliberately carries no half-working key for it: an authored `maxTotal` that silently
  bounded nothing would be worse than its absence.
- **Determinism.** Nothing on this path reads a payload, consults a model, or makes a
  network call. Effect is declared by policy and resolved from the call's own arguments.

## Worked example

The full scenario, running against the real binary: `make -C demo effect-escalate`
([`demo/manifest-effect.yaml`](../demo/manifest-effect.yaml)). An agent reads an untrusted
support ticket carrying an injection, then attempts `DROP TABLE customers`. The capability
is granted and `DROP` is explicitly in its `allowedOperations`; the call is escalated on its
consequence, while a `SELECT` through the same tool in the same tainted session is allowed.
`make -C demo ci-test-effect` asserts 20 identical runs with a verified tape.
