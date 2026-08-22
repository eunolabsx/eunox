#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/check-vulncheck-classifier.sh — prove scripts/govulncheck.sh gates on the
# right bucket, without a network.
#
# The classifier decides which advisories block a merge, so "it looked right when I ran
# it" is not enough: the interesting case is the one that is HARD to reach on demand,
# because reproducing it means waiting for the Go security team to publish. The fixtures
# in scripts/testdata/ are captured govulncheck streams that stand in for it -- notably
# the exact shape issue #380 hit (five called stdlib advisories against the pinned
# toolchain), which must now pass the PR gate rather than block every open branch.
#
# A fixture is a JSON stream, so this also pins the assumption the classifier rests on:
# that trace[0] is the vulnerable symbol's frame and that the levels are distinguished
# by the presence of .package / .function. If govulncheck's schema moves, this fails
# here rather than by silently classifying every finding as "required".

set -euo pipefail

cd "$(dirname "$0")/.."

CLASSIFIER="./scripts/govulncheck.sh"
DATA="./scripts/testdata"
fail=0

# check <fixture> <mode> <want-exit> <want-gating> <want-toolchain-called> <want-other>
check() {
	local fixture="$1" mode="$2" want_rc="$3" want_gate="$4" want_tc="$5" want_other="$6"
	local out rc
	set +e
	out=$("$CLASSIFIER" --mode "$mode" --json-in "$DATA/govulncheck-$fixture.json" 2>&1)
	rc=$?
	set -e

	if [ "$rc" -ne "$want_rc" ]; then
		echo "FAIL $fixture/$mode: exit $rc, want $want_rc" >&2
		echo "$out" >&2
		fail=1
		return
	fi

	# Read the counts back out of the summary table the classifier prints, so the
	# assertion is on what a reader is shown and not on some parallel accounting.
	local got_gate got_tc got_other
	got_gate=$(printf '%s\n' "$out" | sed -n 's/^| called, in a module we depend on | \([0-9]*\) |.*/\1/p')
	got_tc=$(printf '%s\n' "$out" | sed -n 's/^| called, in stdlib\/toolchain | \([0-9]*\) |.*/\1/p')
	got_other=$(printf '%s\n' "$out" | sed -n 's/^| not called | \([0-9]*\) |.*/\1/p')

	if [ "$got_gate" != "$want_gate" ] || [ "$got_tc" != "$want_tc" ] || [ "$got_other" != "$want_other" ]; then
		echo "FAIL $fixture/$mode: counts gating=$got_gate toolchain=$got_tc other=$got_other," \
			"want gating=$want_gate toolchain=$want_tc other=$want_other" >&2
		echo "$out" >&2
		fail=1
		return
	fi

	echo "ok   $fixture/$mode (exit $rc; gating=$got_gate toolchain-called=$got_tc not-called=$got_other)"
}

# The issue-#380 shape: five CALLED stdlib advisories, one stdlib advisory imported but
# not called, two required-only module advisories. Nothing in a branch can fix any of
# them, so the PR gate must PASS (exit 0) while still reporting all eight.
check toolchain-only gate 0 0 5 3
check toolchain-only report 0 0 5 3

# A called advisory in a module we depend on is exactly what the scan exists for: it
# gates, and the toolchain finding sitting beside it does not mask or inflate the count.
check module-called gate 1 1 1 0
check module-called report 0 1 1 0

# Nothing found: both modes pass, and neither reports a phantom finding.
check clean gate 0 0 0 0
check clean report 0 0 0 0

# A stream that never produced a config message is a scan that did not run. It must
# refuse rather than read as a clean pass -- the failure mode this gate cares most about.
set +e
: >/tmp/govulncheck-empty-$$.json
out=$("$CLASSIFIER" --mode gate --json-in /tmp/govulncheck-empty-$$.json 2>&1)
rc=$?
set -e
rm -f /tmp/govulncheck-empty-$$.json
if [ "$rc" -eq 2 ]; then
	echo "ok   empty-stream/gate (exit 2, refused as 'the scan did not run')"
else
	echo "FAIL empty-stream/gate: exit $rc, want 2 (an empty stream must not read as clean)" >&2
	echo "$out" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	echo "govulncheck classifier: FAILED" >&2
	exit 1
fi
echo "govulncheck classifier: all cases pass."
