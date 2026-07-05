<!--
Thanks for contributing to eunox. Keep each PR focused on a single change —
open separate PRs for unrelated work. Fill in the sections below and delete any
that don't apply.
-->

## Summary

<!-- What does this PR change? One or two sentences. -->

## Why

<!-- The motivation: the bug, gap, or uncontrolled agent behavior this
     addresses. A concrete scenario is most useful. Link the issue it closes. -->

Closes #

## Type of change

<!-- Keep what applies, delete the rest. -->

- Bug fix
- New feature (condition type, transport, CLI flag, …)
- Security hardening
- Docs / site
- Refactor or chore (no behavior change)
- Breaking change (call it out above and note the migration path)

## How it was tested

<!-- The commands you ran and what you observed. New behavior needs new tests. -->

```
make test    # go test -race ./...
make lint    # go vet + golangci-lint
```

CI additionally gates coverage at 80% average for `pkg/` and separately for `cmd/`.

## Security considerations

<!-- eunox is a policy-enforcement boundary, so spell this out. Address
     whatever applies; write "no security impact" with a reason if none do.

     - Fail-closed preserved? On bad input, missing policy, version mismatch, or
       any ambiguity, does it deny / refuse to start rather than fail open?
     - Audit tape: does it touch record fields, signing, or rotation?
     - Secrets: does it read, log, or expand tokens / env vars / headers?
     - Authority: could it widen what a manifest or JWT permits? -->

## Checklist

- [ ] `make test` passes — race detector clean, `pkg/` and `cmd/` coverage stay ≥ 80%
- [ ] `make lint` passes — `go vet` + golangci-lint, no new findings
- [ ] `make check-license` passes — license header on every new file
- [ ] Docs updated (`README` / `docs/`) when behavior or config changed
- [ ] Schema updated (`schemas/`) when a config or manifest field changed, with docs to match
- [ ] PR description explains *why*, not just *what*

<!-- By submitting, you agree your contribution is licensed under the project's
     license (see LICENSE and NOTICE). -->
