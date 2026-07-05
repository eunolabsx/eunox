# Adoption signals

`scripts/signals/collect.sh` produces a weekly Markdown snapshot of every
public adoption signal we can read. The eunox proxy itself collects no
client-side telemetry (see [SECURITY.md][verify]) — this script just
aggregates data the public can already see.

[verify]: ../../SECURITY.md#verifying-a-release

## How it runs

A scheduled workflow ([`.github/workflows/adoption-signals.yml`](../../.github/workflows/adoption-signals.yml))
runs the script every **Monday 09:00 UTC** and uploads the result as a
workflow artifact named `adoption-signals` with 90-day retention. You
can also trigger it manually from the Actions tab (`workflow_dispatch`),
and it also runs the script locally:

```bash
gh auth login                       # only if not already authenticated
./scripts/signals/collect.sh > signals.md
```

Run with `REPO=eunolabs/some-other-repo` to point it at a different
target (the launch checklist suggests dual-tracking
`eunolabs/homebrew-tap` once the cask has traffic).

## What each section means

| Section | What it tells you |
|---|---|
| **1. Repository** | Vanity totals: stars / forks / watchers / open issues. Star *velocity* week-over-week is more useful than the absolute number. |
| **2. Traffic** | 14-day rolling views + clones from the GitHub Traffic API. Only available with push access on the repo — under the default Actions `GITHUB_TOKEN` it may render zeros; run locally with an admin token for the real numbers. |
| **3. Releases** | Per-tag binary downloads (active-install proxy), `checksums.txt.sigstore.json` downloads (count of people verifying the supply chain — uniquely useful), and SBOM downloads (SCA-tool integration). |
| **4. Activity — 7d** | New / updated issues + PRs in the last week, with a per-author breakdown. This is the highest-signal "who's actually using it" feed — issue authors' bios and employers tell you more than any opt-in survey would. |
| **5. Public adoption** | GitHub code-search counts for the manifest shape and our distribution channels. Noisy (Search API indexing lag + rate limits) but rising over time = real adoption. |
| **6. Forks** | Per-fork owner type. Org-owned forks are the design-partner pipeline; personal forks are mostly noise. |
| **7. Known gaps** | Signals that need a manual check — ghcr.io pulls, Homebrew analytics, registry counters, press. |

## How to read the dashboard

Open the most recent artifact from the Actions tab. The git history of
these artifacts *is* the longitudinal view: if you want a trend, compare
two recent snapshots in your editor.

Three rules of thumb for skimming:

1. **The verification ratio matters more than raw downloads.** A high
   `checksums.txt.sigstore.json` count relative to binaries means the
   security audience is taking us seriously. A low count means
   downloaders are not the bar.
2. **Watch §4 author lists weekly.** New first-time issuers from a
   recognizable org are the leads worth pursuing. Add a `prospects`
   issue label or a private note.
3. **A flat §5 with active §4 means power users, not breadth.** A
   rising §5 with quiet §4 means many silent adopters. The two
   together mean a product that's working.

## Promoting to a private dashboard later

If we outgrow artifact-per-week, two upgrade paths:

- **Replicate to a private repo.** Add a step that commits the
  generated Markdown to `eunolabs/adoption-signals` with a fine-grained
  PAT. Pattern is identical to the internal Homebrew-tap bootstrap
  runbook (`brew-tap-bootstrap.md`, kept in `eunolabs/eunox-internal`)
  for the Homebrew tap.
- **Pipe to Grafana / Datadog.** Have the script emit JSON in addition
  to Markdown; a sidecar uploads it. Only worth doing if we have more
  than ten data points and an actual question we want to answer.

Don't do either until you've been reading the weekly artifacts for a
month and know what's missing — the cost of building a real dashboard
is in not knowing which axes you care about.

## What is not collected

- No client-side data. Ever. (Adding any would require an update to
  [SECURITY.md][verify] and a CHANGELOG entry — see the no-telemetry
  promise in `SECURITY.md`.)
- No user identities beyond what GitHub already publishes.
- No IP addresses.
- No headers, request bodies, or anything from the proxy's runtime.
