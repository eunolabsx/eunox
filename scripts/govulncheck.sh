#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/govulncheck.sh — run govulncheck and split its findings by who can fix them.
#
# govulncheck queries a LIVE database, so a pinned toolchain goes red on the calendar
# rather than on a commit: the next stdlib advisory turns every open PR red at once,
# none of them at fault and none of them able to fix it, because the fix is a toolchain
# bump and no contributor's branch should carry one. A red check nobody's diff caused
# becomes the normal state and stops being read, which costs the findings that ARE a
# branch's fault the attention they need.
#
# So the two questions get two answers, on the axis of which module the vulnerable
# symbol lives in:
#
#   stdlib / toolchain -> reported, never gating. Fixed by moving the Go pin, which is
#                         its own change. The scheduled run (--mode report) is what
#                         carries these to an issue.
#   any other module   -> GATING when called. A branch that adds or keeps a dependency
#                         whose code we call is exactly what this scan exists for.
#
# The gate is on CALLED findings only, which is govulncheck's own exit-code rule too:
# a finding at "required" or "imported" level says a vulnerable module is reachable in
# the graph, not that this code can execute it. Those are reported at every mode and
# tracked in docs/dependency-advisories.md, where each one is either resolved by a bump
# or recorded with the reason it does not apply -- "not called" is a true statement
# about today's call graph, not a decision.
#
# Usage:
#   scripts/govulncheck.sh [--mode gate|report] [--json-out FILE] [--summary-out FILE]
#                          [--json-in FILE]
#
#   --mode gate      (default) exit 1 on a called finding outside stdlib/toolchain.
#   --mode report    never exit nonzero for findings; emit the full inventory.
#   --json-out FILE  keep the raw govulncheck JSON stream.
#   --summary-out F  write a Markdown summary (GitHub step summary / issue body).
#   --json-in FILE   classify a previously captured stream instead of scanning. The
#                    scan needs vuln.go.dev; this is what makes the classifier itself
#                    exercisable offline, including by scripts/testdata fixtures.
#
# Run it from anywhere; it cd's to the repository root.

set -euo pipefail

cd "$(dirname "$0")/.."

MODE="gate"
JSON_OUT=""
SUMMARY_OUT=""
JSON_IN=""

while [ $# -gt 0 ]; do
	case "$1" in
	--mode)
		MODE="${2:-}"
		shift 2
		;;
	--json-out)
		JSON_OUT="${2:-}"
		shift 2
		;;
	--summary-out)
		SUMMARY_OUT="${2:-}"
		shift 2
		;;
	--json-in)
		JSON_IN="${2:-}"
		shift 2
		;;
	-h | --help)
		sed -n '5,42p' "$0"
		exit 0
		;;
	*)
		echo "govulncheck.sh: unknown argument: $1" >&2
		exit 2
		;;
	esac
done

case "$MODE" in
gate | report) ;;
*)
	echo "govulncheck.sh: --mode must be 'gate' or 'report', got '$MODE'" >&2
	exit 2
	;;
esac

if ! command -v jq >/dev/null 2>&1; then
	echo "govulncheck.sh: jq is required to classify the JSON stream (apt install jq / brew install jq)." >&2
	exit 2
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
stream="$work/govulncheck.json"
PINNED_GO=""

if [ -n "$JSON_IN" ]; then
	cp "$JSON_IN" "$stream"
else
	VERSION=$(make -s --no-print-directory print-vulncheck-version)
	if [ -z "$VERSION" ]; then
		echo "govulncheck.sh: could not read GOVULNCHECK_VERSION from the Makefile" >&2
		exit 2
	fi

	# Analyze with the toolchain the release actually ships, not whatever GOTOOLCHAIN
	# resolves to. `go run pkg@version` honors the TOOL's own go directive, so an
	# x/vuln release requiring a newer Go than our pin would switch the whole
	# invocation -- and govulncheck reports stdlib advisories against the toolchain it
	# loaded packages with, so the scan would be describing a Go that does not ship.
	# Build the tool under GOTOOLCHAIN=auto (it must be allowed its own requirement),
	# then run the SCAN pinned. The go_version assertion below proves it held.
	PINNED_GO=$(awk '/^go /{print $2; exit}' go.mod)
	if [ -z "$PINNED_GO" ]; then
		echo "govulncheck.sh: could not read the 'go' directive from go.mod" >&2
		exit 2
	fi

	echo "govulncheck $VERSION, analyzing against go$PINNED_GO (go.mod pin)" >&2
	GOBIN="$work/bin" GOTOOLCHAIN=auto \
		go install "golang.org/x/vuln/cmd/govulncheck@$VERSION"

	# govulncheck exits 3 when it finds vulnerabilities; that is data here, not a
	# failure. Any OTHER nonzero status is a real failure (a database it could not
	# reach, a package it could not load) and must not read as "no findings" -- the
	# whole point of this script is that a scan which did not happen is not a pass.
	set +e
	GOTOOLCHAIN="go$PINNED_GO" "$work/bin/govulncheck" -format json ./... >"$stream" 2>"$work/err"
	rc=$?
	set -e
	if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
		echo "govulncheck.sh: govulncheck failed (exit $rc); the scan did not complete." >&2
		cat "$work/err" >&2
		exit 2
	fi
fi

if [ -n "$JSON_OUT" ]; then
	cp "$stream" "$JSON_OUT"
fi

# A stream with no config message is one that never started -- an empty file reads as
# "clean" to every query below, so refuse it rather than reporting a vacuous pass.
if ! jq -e -s 'any(.[]; has("config"))' "$stream" >/dev/null 2>&1; then
	echo "govulncheck.sh: no config message in the govulncheck stream; the scan did not run." >&2
	exit 2
fi

scanned_go=$(jq -r -s 'map(select(has("config")) | .config.go_version) | first // ""' "$stream")
if [ -n "$PINNED_GO" ] && [ -n "$scanned_go" ] && [ "$scanned_go" != "go$PINNED_GO" ]; then
	echo "govulncheck.sh: scan analyzed $scanned_go but go.mod pins go$PINNED_GO;" >&2
	echo "  stdlib findings would describe a toolchain that does not ship." >&2
	exit 2
fi

# Fold the stream into one row per (osv, module), keeping the deepest level seen for
# that pair. govulncheck emits a finding when it sees a vulnerable module is REQUIRED,
# again if the package is IMPORTED, and again per called symbol, so the same advisory
# arrives several times at different depths; the row that matters is the deepest one,
# which is the one the gate reads.
#
# trace[0] is the vulnerable symbol's own frame (frames run from the vulnerable symbol
# out to the entry point), so trace[0].module is the module to attribute the finding
# to, and the presence of .function / .package is what distinguishes the levels.
jq -r -s '
  (map(select(has("osv")) | {key: .osv.id, value: (.osv.summary // "")}) | from_entries) as $sum
  | map(select(has("finding")) | .finding)
  | map({
      osv: .osv,
      module: (.trace[0].module // "unknown"),
      fixed: (.fixed_version // ""),
      level: (if (.trace[0].function // "") != "" then 3
              elif (.trace[0].package // "") != "" then 2
              else 1 end),
      entry: (if (.trace[0].function // "") != "" then
                ((.trace[-1].package // "") + "." + (.trace[-1].function // ""))
              else "" end)
    })
  | group_by(.osv + " " + .module)
  | map(max_by(.level) + {summary: ($sum[(.[0].osv)] // "")})
  | sort_by(-.level, .module, .osv)
  | .[]
  | [ .osv, .module, .fixed, (.level|tostring), .summary, .entry ] | @tsv
' "$stream" >"$work/rows.tsv"

# stdlib packages report module "stdlib"; cmd/* toolchain findings report "toolchain".
# Both are fixed by moving the Go pin and by nothing a branch can do.
is_toolchain() { [ "$1" = "stdlib" ] || [ "$1" = "toolchain" ]; }

level_name() {
	case "$1" in
	3) echo "called" ;;
	2) echo "imported, not called" ;;
	*) echo "required, not imported" ;;
	esac
}

# Which of the four buckets a row falls in. The gate reads exactly one of them.
bucket_of() { # bucket_of <module> <level>
	if is_toolchain "$1"; then
		if [ "$2" = "3" ]; then echo "toolchain-called"; else echo "toolchain-other"; fi
	else
		if [ "$2" = "3" ]; then echo "module-called"; else echo "module-other"; fi
	fi
}

gating=0
tc_called=0
other=0

while IFS=$(printf '\t') read -r osv module fixed level _rest; do
	[ -n "$osv" ] || continue
	case "$(bucket_of "$module" "$level")" in
	module-called) gating=$((gating + 1)) ;;
	toolchain-called) tc_called=$((tc_called + 1)) ;;
	*) other=$((other + 1)) ;;
	esac
done <"$work/rows.tsv"

summary="$work/summary.md"
{
	printf '# govulncheck\n\n'
	printf 'Scanner `%s`, analyzed against `%s`.\n\n' \
		"$(jq -r -s 'map(select(has("config")) | .config.scanner_version) | first // "?"' "$stream")" \
		"${scanned_go:-unknown}"
	printf '| bucket | count | gates a PR |\n|---|---|---|\n'
	printf '| called, in a module we depend on | %d | yes |\n' "$gating"
	printf '| called, in stdlib/toolchain | %d | no - needs a Go pin bump |\n' "$tc_called"
	printf '| not called | %d | no - tracked in docs/dependency-advisories.md |\n' "$other"
} >"$summary"

# Every branch below is an `if` rather than a `&&` chain, and the function returns 0
# explicitly: a while loop yields the status of the LAST command run in its body, so a
# trailing `[ -n "$entry" ] && ...` that short-circuits on the final row makes emit
# return 1 and `set -e` kills the script after a clean scan.
emit() { # emit <heading> <bucket>
	local heading="$1" want="$2" wrote=0 osv module fixed level text entry
	while IFS=$(printf '\t') read -r osv module fixed level text entry; do
		if [ -z "$osv" ] || [ "$(bucket_of "$module" "$level")" != "$want" ]; then
			continue
		fi
		if [ "$wrote" -eq 0 ]; then
			printf '\n### %s\n\n' "$heading" >>"$summary"
			wrote=1
		fi
		printf -- '- **%s** - `%s`' "$osv" "$module" >>"$summary"
		if [ -n "$fixed" ]; then
			printf ', fixed in `%s`' "$fixed" >>"$summary"
		fi
		printf ' (%s)\n' "$(level_name "$level")" >>"$summary"
		if [ -n "$text" ]; then
			printf '  %s\n' "$text" >>"$summary"
		fi
		if [ -n "$entry" ]; then
			printf '  reached from `%s`\n' "$entry" >>"$summary"
		fi
	done <"$work/rows.tsv"
	return 0
}

emit "Called, in a module we depend on - these gate" "module-called"
emit "Called, in the Go toolchain - bump the pin, not a branch" "toolchain-called"
emit "Not called - a module in the graph" "module-other"
emit "Not called - stdlib or toolchain" "toolchain-other"

cat "$summary"
if [ -n "$SUMMARY_OUT" ]; then
	cp "$summary" "$SUMMARY_OUT"
fi

if [ "$MODE" = "report" ]; then
	# The scheduled run reports and never gates on findings: its caller decides what to
	# do with them, and a red scheduled job is the state this whole split exists to keep
	# off the PR checks. A scan that FAILED still exited 2 above.
	exit 0
fi

if [ "$gating" -gt 0 ]; then
	echo "::error::govulncheck: $gating called vulnerability finding(s) in a module this code calls; bump the dependency or drop the call path." >&2
	exit 1
fi

if [ "$tc_called" -gt 0 ]; then
	echo "::warning::govulncheck: $tc_called called stdlib/toolchain advisory finding(s) against the pinned toolchain. Not gating this PR; the scheduled scan tracks the Go pin bump." >&2
fi

exit 0
