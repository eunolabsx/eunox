# Architecture Decision Records

This directory holds **Architecture Decision Records** (ADRs): short documents
that capture a single significant decision — the context that forced it, the
choice made, the alternatives rejected, and the consequences accepted.

An ADR answers *"why is it this way?"* for a decision that was not obvious and
had real alternatives. It is not a design doc and not a tutorial:
[architecture.md](../architecture.md) describes how the system works *today*;
an ADR records *why a specific decision was made* at a point in time, and is
not edited afterward.

## When to write one

Write an ADR when a decision is:

- **Load-bearing** — reversing it later would be expensive or ripple widely.
- **Contested** — there was a credible alternative a reasonable engineer might
  have picked.
- **Non-obvious** — the reasoning won't be self-evident from the code six
  months from now.

Don't write one for routine choices with a conventional default, or for
anything the code already makes obvious. Most PRs need no ADR.

## How to write one

1. Copy [`template.md`](./template.md) to `NNNN-short-kebab-title.md`, where
   `NNNN` is the next zero-padded number in sequence.
2. Fill it in. Keep it short — a screen or two. Link to the code
   (`file.go:line`) and to the spec or threat model where relevant.
3. Open it as **Draft** (the template's default). It moves through the process
   below; finalizing is a deliberate step, not a side effect of merging.
4. Add a row to the index below in the same PR.

## Process and lifecycle

An ADR moves through three states. The progression is intentional: drafting,
then a window to gather dissent, then a recorded decision.

| State | What it means | Who acts |
| ----- | ------------- | -------- |
| **Draft** | Authored and merged so it is visible, but still open to material change. **Strong guidance** — the current best-known direction, to be followed as the default — but **not yet binding**, and fair to challenge in discussion. | Author opens; anyone may comment. |
| **In Review** | Drafting has settled and consensus is being actively solicited. A standing comment window before finalizing. | Author signals readiness; maintainers + contributors weigh in. |
| **Final** | Ratified by maintainer consensus. Binding, and **append-only** from here. | Maintainers, by consensus — never a lone merge. |

Two terminal states close a record out:

- **Superseded by ADR-NNNN** — a later decision overturns it. Write the *new* ADR,
  and point both `Status` lines at each other (`Superseded by ADR-000X` /
  `Supersedes ADR-000Y`). The history of how thinking changed is the point.
- **Deprecated** — the decision no longer applies and nothing replaces it.

Statuses: `Draft` · `In Review` · `Final` · `Superseded by ADR-NNNN` · `Deprecated`.

**Append-only applies once `Final`.** A `Draft` or `In Review` ADR may still be
edited as the discussion moves it; once `Final`, it is not rewritten — a new ADR
supersedes it instead. Amendments to a `Final` ADR are additive and dated, never
silent edits.

> **Process introduced 2026-06-28.** All ADRs below predate this lifecycle and
> none have been ratified under it, so every one is reset to **Draft**. Treat them
> as strong guidance until maintainer consensus graduates each to `Final`. Records
> previously marked `Accepted` note that reset in their `Status` line.

## Index

| ADR | Title | Status |
| --- | ----- | ------ |
| [0001](./0001-jwt-claims-intersect-manifest.md) | JWT capability claims intersect the manifest, never expand it | Draft |
| [0002](./0002-oauth-protected-resource-metadata.md) | Serve OAuth protected-resource metadata in HTTP and gateway modes | Draft |
| [0003](./0003-redis-killswitch-fail-open.md) | Redis kill switch fails closed by default on a Redis outage (opt-in fail-open) | Draft |
| [0004](./0004-bearer-identity-session-anchor.md) | Anchor client correlation and revocation on bearer identity, not the protocol session | Draft |
| [0005](./0005-upstream-credential-delegation.md) | Resolve upstream credentials per request via a provider seam, prefer delegation over a shared static token | Draft |
