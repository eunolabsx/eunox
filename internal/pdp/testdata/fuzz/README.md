# Committed fuzz corpora

Coverage-distinct inputs harvested from real fuzz campaigns against this package's
duplicate-key scanner and redactable-leaf guard, one directory per target.

## Why they are committed

CONTRIBUTING.md's bar for changing the scanner is "a real fuzz campaign, not just the seeds".
A campaign's value is in the inputs it discovers, and those live in `GOCACHE` — per-machine,
wiped by `go clean -cache`, and never seen by CI. So every campaign started from the handful of
hand-written seeds and rediscovered the same ground before reaching new ground.

Files here are picked up by `go test` as seeds with no `-fuzz` flag, so each is a permanent
regression case: the equivalence between `scanJSONKeys` and the tokenizer oracle
(`scan_oracle_test.go`) is re-asserted against every input a past campaign found interesting,
on every run, for a few hundredths of a second.

## Regenerating / extending

Run a campaign, then copy what it found:

    go test ./internal/pdp/ -run '^$' -fuzz 'FuzzScanJSONKeys$' -fuzztime=90s
    cp "$(go env GOCACHE)"/fuzz/github.com/eunolabs/eunox/internal/pdp/FuzzScanJSONKeys/* \
       internal/pdp/testdata/fuzz/FuzzScanJSONKeys/

Additive by design — an input that stopped being coverage-distinct after an unrelated change is
still a valid case the scanner must agree with the oracle on, so nothing here is pruned on a
later campaign's say-so.

A file that makes `go test` fail is a genuine divergence, not corpus rot. Do not delete it.
