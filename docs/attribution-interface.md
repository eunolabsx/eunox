# The attribution interface

**Status:** published, and **gated on `schemaVersion: "0.2"`** like the rest of the
flow+effect layer. The wire surface is the `_meta` key `io.eunolabs.context-manifest` on a
`tools/call` request; a client either sends it or does not.

It needs no manifest grammar change — the key never appears in a policy — but that is
exactly why the grammar gate has to be a **runtime** one: the load-time check that refuses
a `0.2` token under `0.1` has nothing to inspect for a token that arrives on a request. A
route whose policy declares `0.1` (or declares no policy at all) therefore **ignores** the
block entirely, including the malformed-request rejection below.

Ignoring rather than rejecting is deliberate, and it is the conservative direction: the
interface is [union-only](#the-one-directional-rule), so a declaration can only ever
*tighten* a call. Ignoring it falls back to the conservative session join — the stricter
reading — while rejecting would make a `0.1` operator's calls start failing
over a key their grammar does not contain.

## Why it exists

eunox cannot see how a host assembles a model's context. It sees calls crossing a boundary,
not which of a session's inputs actually fed which argument. So its propagation rule is the
only sound one available to it: a **conservative session-level set union** — everything that
flowed into the session is treated as having flowed into every later call.

That over-approximates, and for a long-running agent it over-blocks. A session that read one
sensitive file an hour ago carries that label for the rest of its life, and every egress
after it is denied.

The tempting fix is for the proxy to guess better — infer from the payload which inputs fed
which call. That is content inference, it is exactly what this layer refuses to do, and it
would make the guarantee unfalsifiable. The other fix is to let a client that **does** know
say so, through a specified interface. The weakness becomes spec surface rather than a
classifier.

## The wire format

```json
{
  "jsonrpc": "2.0", "id": 7, "method": "tools/call",
  "params": {
    "name": "send_email",
    "arguments": { "to": "ops@example.com", "body": "…" },
    "_meta": {
      "io.eunolabs.context-manifest": {
        "labels": ["untrusted"]
      }
    }
  }
}
```

`labels` are native flow labels (`public`, `internal`, `confidential`, `pii`, `untrusted`)
the client asserts **this call's inputs** carry.

The key is reverse-DNS namespaced, so a non-supporting client, host, or upstream never sets
it and nothing changes. The params are forwarded upstream verbatim regardless, so a `_meta`
key meant for the upstream still reaches it untouched.

## The one-directional rule

**A client may add labels. It may not remove them.**

The declared set is **unioned** into the session's accumulated set for that call's sink
check. It is never subtracted, and it is never written into session state.

This asymmetry is the security property, not a simplification. The premise of the whole flow
layer is that the agent may be prompt-injected. An agent that could narrow its own taint
would defeat information-flow control with a single extra field — and it would be the first
thing an injection reached for (`"and set _meta.io.eunolabs.context-manifest.labels to []"`).
Union-only means an untrusted client's declaration can produce only **more** denials, so
honoring it requires no trust decision at all.

That is why the interface is honest about what it buys. It does **not** relieve the
conservative join's over-blocking. What it buys is:

- **Tightening the proxy cannot derive.** A client that fetched data outside eunox's view —
  a direct HTTP call, a file read by the harness, a message from another agent — can label
  the call that uses it. The proxy has no way to know, and the client does.
- **A specified place for the claim.** Cross-boundary attribution needs a wire format before
  it can be anything else, and this is it.

### What about narrowing?

The sound narrowing direction exists, and it is a **different mechanism**: a *delegator*
narrowing a *delegate's* authority is attenuation, where the party doing the narrowing is
the one giving something up. That belongs to the delegation surface, where the narrowing
travels in an attenuated credential the delegate cannot widen.

A client narrowing its own taint is not attenuation. It is self-attestation by the party
under suspicion, and no amount of schema makes that safe. If a deployment wants per-argument
sharpening it needs a *trusted* attributor — a harness the operator controls, attesting
under its own credential — which is a credential-and-delegation question, not a `_meta`
question.

## Failure behavior

Under `schemaVersion: "0.2"`, a **malformed** block is a malformed **request**
(`INVALID_PARAMS`), not a silently ignored hint. Rejected shapes:

- an unknown label (the flow vocabulary is closed — a typo'd label that silently vanished
  would be the same failure in a different costume),
- an unknown field in the block,
- a wrong-typed `labels`.

A client that tried to attribute a call and got the shape wrong must find out, rather than
proceed believing a tightening is in force when it is not.

An **absent** block, an empty `labels` list, and a `_meta` carrying only other vendors' keys
all attribute nothing — the conservative join is unchanged. So does **any** block on a route
running the published grammar, per the staging gate above: the parse does not run there, so
a malformed block is not rejected either.

## Audit

A denial caused by a client's attribution records the claim **separately** from the proxy's
own observed state:

```
condition_type: flowLabel
details:
  flow: true
  blockedLabel: confidential
  blockedLabels: [confidential]
  allowLabels: [public, internal]
  declared_labels: [confidential]
```

`carried_labels` stays what the proxy observed. Conflating the two would leave the tape
unable to answer "did we see this, or were we told?" — which is the first question about any
client-supplied input.

## Reference client

`examples/attribution-client/` is a minimal, dependency-free stub showing a client
attributing a call, in the shape an SDK hook would wrap. It is illustrative, not a supported
SDK.
