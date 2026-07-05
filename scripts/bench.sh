#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/bench.sh — eunox performance benchmark runner
#
# Usage:
#   ./scripts/bench.sh              # default: -count=3 -benchtime=3s
#   COUNT=10 ./scripts/bench.sh     # more samples for benchstat analysis
#   BENCHTIME=5s ./scripts/bench.sh # longer per-benchmark run
#   BENCH=ManifestPDP ./scripts/bench.sh  # run only matching benchmarks
#
# After the run, analyze with benchstat:
#   go install golang.org/x/perf/cmd/benchstat@latest
#   ./scripts/bench.sh | tee bench.txt
#   benchstat bench.txt

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COUNT="${COUNT:-3}"
BENCHTIME="${BENCHTIME:-3s}"
BENCH="${BENCH:-.}"

echo "=== eunox benchmark (count=${COUNT}, benchtime=${BENCHTIME}) ==="
echo "    host: $(uname -srm)"
echo "    go:   $(go version)"
echo "    date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

go test \
    -run='^$' \
    -bench="^Benchmark${BENCH}" \
    -benchtime="${BENCHTIME}" \
    -benchmem \
    -count="${COUNT}" \
    ./internal/... \
    2>&1 | grep -v '^\[eunox\]'
