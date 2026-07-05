# Governance

`eunox` is a deny-by-default capability firewall for MCP servers. Its
job is to **say no correctly**, and other people deploy it in their
enforcement path. That makes write access to this repository closer to a key
to a security boundary than to a normal web project — a single bad commit
that weakens fail-closed behavior, loosens claim intersection, or breaks
list filtering is a supply-chain event for every downstream operator.

So the governing principle here is deliberately lopsided:

> **Be generous with merges. Be stingy with write access.**

You do **not** need any role to contribute. Anyone can fork, push to their
branch, and open a PR — see [`CONTRIBUTING.md`](./CONTRIBUTING.md). Roles
below are about *trust granted over the repository*, which is a separate
decision from whether a given contribution is good.

---

## Roles

| Role | What it grants | Who it's for |
| --- | --- | --- |
| **Contributor** | Nothing is granted. PRs come from a fork. | Anyone. The permanent home for most people, including excellent ones. |
| **Triager** | GitHub *Triage* role: label, close, and shepherd issues and PRs; no code-write. | Regulars with a track record of helpful issue/PR activity. |
| **Maintainer** | Write access; membership in `@eunolabs/eunox-leads` (the required reviewer in [`CODEOWNERS`](./CODEOWNERS)). | A small set of people who have earned the full bar below. |

Trust is managed through GitHub **teams**, not by adding individuals to
`CODEOWNERS`. Promotion means adding someone to the relevant team
(`@eunolabs/eunox-leads`, `@eunolabs/eunox-dx`); stepping back means removing
them. One place to look, one place to change.

---

## Becoming a Triager

The Triage role is low-risk and easy to grant or revoke, so the bar is
modest: a few months of genuinely helpful activity — good bug repros,
thoughtful reviews of other people's PRs, sensible issue hygiene. It lets us
reward and offload the gardening work without handing out the
security-critical key. If you've been doing this and want the role, ask.

---

## Becoming a Maintainer

Write access to this repository is a real trust grant. A merged PR — even a
brilliant one — earns a merge, not a key; those are unrelated decisions. We
promote someone only when **all** of the following are true:

1. **Sustained track record, not a heroic PR.** Several months and a number
   of merged PRs across more than one area of the code — not a single large
   contribution.
2. **The invariants are already internalized.** Their PRs fail closed by
   default, ship the table-driven allow/deny/malformed-input tests, update
   the threat model when they touch the audit shape, and don't fold behavior
   changes into refactors. We are no longer policing the fundamentals.
3. **Good judgment on the security boundary.** They route vulnerabilities
   through [`SECURITY.md`](./SECURITY.md) rather than public issues, and they
   push back correctly on changes that smell like detection-evasion or
   offensive tooling. This is the single most important signal for this
   project.
4. **They review well, not just code well.** A maintainer's main job is
   saying no to other people's PRs correctly. We watch how someone reviews
   before trusting them to merge.
5. **Accountable identity.** For a security tool, an anonymous account with
   no history is not eligible. We need someone reachable, with reputation at
   stake.
6. **The vacation test.** We'd be comfortable with them merging
   security-critical code while the rest of the maintainers are away. If the
   honest answer is "I'd want to double-check," they're not ready yet.

Promotion is by consensus of the existing maintainers. There is no
application form; it follows from the track record above. If you think you're
there, it's fine to ask — but the work comes first.

---

## How decisions get made

- **Routine PRs** — merged once they pass review and CI, per
  [`CONTRIBUTING.md`](./CONTRIBUTING.md).
- **User-visible contracts** — manifest grammar, audit-record shape, config
  keys, JWT/claim-intersection or fail-closed behavior — need design
  discussion *before* a large PR, and sign-off from a maintainer who owns the
  affected area.
- **Disagreements** — resolved by discussion among maintainers. The
  project's bias is toward the more conservative, fail-closed option; when in
  doubt, deny.

---

## Branch protection and review

These rules apply to everyone, maintainers included — they are properties of
the repository, not favors granted person by person:

- `main` takes changes only through pull requests; no direct pushes.
- Security-critical paths (`/pkg/`, `/internal/`, `/cmd/eunox/`,
  `/schemas/`, and repository/CI config) require review from
  `@eunolabs/eunox-leads` via [`CODEOWNERS`](./CODEOWNERS).
- CI gates (`make test && make lint && make check-license`, plus the demo
  integration suite) must be green.
- Commits carry a DCO sign-off (`git commit -s`).
- Maintainers do not merge their own security-critical changes unreviewed.

---

## Stepping back

Maintainers who are no longer active are moved out of `@eunolabs/eunox-leads`
to keep the set of people with write access small and current. This is
routine hygiene, not a judgment, and the door is open to return.

---

## Releases

Maintainers cut releases by tagging `vMAJOR.MINOR.PATCH`; the release
playbook is maintained internally. Contributors don't need to think about it
— but flag any breaking change in your PR description so the next release
notes call it out.

---

## Security

Vulnerabilities never go through public issues or PRs. Follow the private
channel in [`SECURITY.md`](./SECURITY.md).
