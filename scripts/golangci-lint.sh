#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/golangci-lint.sh — run the golangci-lint version this repo pins, and no other.
#
# The pin lives in ONE place: GOLANGCI_LINT_VERSION in the Makefile, which the Lint job in
# .github/workflows/go-ci.yml reads too (`make print-lint-version`). This script is what
# makes `make lint` honor it.
#
# Why it is not enough to install golangci-lint "if missing": a binary already on PATH is
# used regardless of version, and a golangci-lint built with an older Go toolchain than the
# repo targets does not lint anything at all -- it refuses to load the config:
#
#   Error: can't load config: the Go language version (go1.25) used to build golangci-lint
#   is lower than the targeted Go version (1.26.6)
#
# That reads as "the linter is unavailable here", so a contributor falls back to `go vet`
# (clean) and pushes, and CI then fails on findings no local run could surface. The version
# that CI pins works fine on the same machine, so the whole gap is a version mismatch the
# tooling did not notice. This script notices: it accepts a candidate binary only when its
# version is EXACTLY the pin and it was built with a Go at least as new as go.mod targets,
# and otherwise installs that exact version itself.
#
# The install pins GOTOOLCHAIN to go.mod's Go version as a FLOOR ("go1.26.6+auto")
# deliberately. golangci-lint's own module names an older toolchain, and `go install` honors
# THAT -- downloading an older Go and producing a correctly versioned binary that still
# refuses this repo, even on a machine whose own Go is new enough. The "+auto" form is what
# makes that a floor rather than a pin: a contributor already on a newer Go keeps it and
# downloads nothing, which is why this is not the unconditional force it replaced.
#
# Usage: GOLANGCI_LINT_VERSION=vX.Y.Z ./scripts/golangci-lint.sh [run-args...]
#
# Run it from the repository root (`make lint` does): the script cd's there, so a relative
# path argument is resolved against the root, not against the caller's directory. With no
# arguments it lints ./... .

set -euo pipefail

cd "$(dirname "$0")/.."

GO="${GO:-go}"
WANT="${GOLANGCI_LINT_VERSION:-}"
if [ -z "$WANT" ]; then
	echo "golangci-lint.sh: GOLANGCI_LINT_VERSION is unset; run this through 'make lint' so the pin is single-sourced." >&2
	exit 2
fi
# Normalize to a leading "v" so a pin written either way compares equal to the version a
# binary reports (golangci-lint prints it bare).
WANT="v${WANT#v}"

TARGET_GO=$(awk '/^go /{print $2; exit}' go.mod)
if [ -z "$TARGET_GO" ]; then
	echo "golangci-lint.sh: could not read the 'go' directive from go.mod." >&2
	exit 2
fi

# The linter compares LANGUAGE versions (go1.26 vs 1.26.6 is fine), so both sides are
# truncated to major.minor before comparing.
lang_version() { printf '%s\n' "${1#go}" | cut -d. -f1,2; }

# version_ge A B — true when A >= B, comparing major then minor numerically.
#
# Deliberately NOT `sort -V`: that flag is a GNU/BSD extension, not POSIX, and a sort
# without it fails the comparison for EVERY candidate — so the script would install and then
# reject its own install, ending in the same "linter unavailable" state it exists to remove.
# Both operands are already truncated to major.minor by lang_version, so two integer
# comparisons are the whole job.
version_ge() {
	local a_maj a_min b_maj b_min
	a_maj=${1%%.*} a_min=${1#*.} b_maj=${2%%.*} b_min=${2#*.}
	[ "$a_min" = "$1" ] && a_min=0
	[ "$b_min" = "$2" ] && b_min=0
	case "$a_maj$a_min$b_maj$b_min" in
	*[!0-9]*) return 1 ;; # unparseable version: fail closed, reinstall
	esac
	[ "$a_maj" -gt "$b_maj" ] && return 0
	[ "$a_maj" -lt "$b_maj" ] && return 1
	[ "$a_min" -ge "$b_min" ]
}

# toolchain_name VERSION — go.mod's directive as a resolvable GOTOOLCHAIN name. Releases are
# always three-component (go1.26.6), while the directive may legally be two (go 1.27), and
# GOTOOLCHAIN=go1.27 resolves to nothing — reported as "could not install golangci-lint",
# which points the reader at the linter rather than at the toolchain name.
toolchain_name() {
	case "$1" in
	*.*.*) printf 'go%s\n' "$1" ;;
	*.*) printf 'go%s.0\n' "$1" ;;
	*) printf 'go%s.0.0\n' "$1" ;;
	esac
}

# binary_facts BIN — "<version> <goversion>" from ONE `version` invocation, or nothing.
#
# The long form carries both facts ("golangci-lint has version 2.12.2 built with go1.26.6
# from ..."), so probing them separately spawns the binary twice per candidate for no gain,
# and made the failure message compose to "built with gounknown" when the file was absent.
# `version --short` is the fallback for an output shape that stops matching, so a future
# upstream change degrades to a reinstall rather than to a wrong answer.
binary_facts() {
	local out ver go
	[ -n "$1" ] && [ -x "$1" ] || return 1
	out=$("$1" version 2>/dev/null) || return 1
	ver=$(printf '%s\n' "$out" | sed -n 's/.*has version v\{0,1\}\([0-9][^ ]*\).*/\1/p')
	go=$(printf '%s\n' "$out" | sed -n 's/.*built with go\([0-9][^ ]*\).*/\1/p')
	if [ -z "$ver" ]; then
		ver=$("$1" version --short 2>/dev/null | sed -n 's/^v\{0,1\}\([0-9].*\)$/\1/p')
	fi
	[ -n "$ver" ] || return 1
	printf 'v%s %s\n' "${ver#v}" "${go:-unknown}"
}

# usable BIN — exactly the pinned version, and built with a Go new enough to lint this repo.
usable() {
	local facts have have_go
	facts=$(binary_facts "$1") || return 1
	have=${facts%% *}
	have_go=${facts##* }
	[ "$have" = "$WANT" ] || return 1
	[ "$have_go" != "unknown" ] || return 1
	version_ge "$(lang_version "$have_go")" "$(lang_version "$TARGET_GO")"
}

# Where `go install` puts the binary: GOBIN when set, else GOPATH/bin — and the FIRST
# element of a multi-element GOPATH, which `go env GOPATH` prints in full. Reading only
# `go env GOPATH` made the post-install check look in the wrong directory and report a
# successful install as a failure, permanently, for anyone with GOBIN set.
INSTALL_BIN=$($GO env GOBIN)
if [ -z "$INSTALL_BIN" ]; then
	INSTALL_BIN="$(printf '%s\n' "$($GO env GOPATH)" | cut -d: -f1)/bin"
fi
INSTALL_BIN="$INSTALL_BIN/golangci-lint"

BIN=""
for cand in "${GOLANGCI_LINT:-}" "$(command -v golangci-lint 2>/dev/null || true)" "$INSTALL_BIN"; do
	if usable "$cand"; then
		BIN="$cand"
		break
	fi
done

if [ -z "$BIN" ]; then
	# A FLOOR rather than a pin, and never "auto". Auto honors the toolchain line in
	# golangci-lint's OWN module, which names an older Go than this repo targets -- so a
	# contributor on a perfectly new toolchain got a binary built with the older one and the
	# usable() check below rejected the script's own install, ending in the "linter
	# unavailable" state this file exists to remove. Pinning outright is the other wrong
	# answer: it downgrades a contributor already on a newer Go into downloading a toolchain
	# they do not need, which simply fails behind GOPROXY=off, an air gap, or a proxy that
	# does not mirror golang.org/toolchain. "<name>+auto" is neither: at least this version,
	# whatever is already there if it is newer.
	toolchain="$(toolchain_name "$TARGET_GO")+auto"
	echo "Installing golangci-lint $WANT (the version CI pins), built with $toolchain or newer..."
	if ! GOTOOLCHAIN="$toolchain" $GO install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$WANT"; then
		echo "" >&2
		echo "golangci-lint.sh: could not install golangci-lint $WANT." >&2
		echo "Install it manually (https://golangci-lint.run/docs/welcome/install/) and re-run," >&2
		echo "or point GOLANGCI_LINT at a $WANT binary built with go$(lang_version "$TARGET_GO") or newer." >&2
		exit 1
	fi
	if ! usable "$INSTALL_BIN"; then
		echo "" >&2
		echo "golangci-lint.sh: installed $INSTALL_BIN but it is not usable for this repo:" >&2
		echo "  want version $WANT, built with go$(lang_version "$TARGET_GO") or newer" >&2
		echo "  got  $(binary_facts "$INSTALL_BIN" || echo "no readable version from that path")" >&2
		exit 1
	fi
	BIN="$INSTALL_BIN"
fi

exec "$BIN" run "${@:-./...}"
