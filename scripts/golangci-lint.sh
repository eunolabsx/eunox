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
#   is lower than the targeted Go version (1.26.5)
#
# That reads as "the linter is unavailable here", so a contributor falls back to `go vet`
# (clean) and pushes, and CI then fails on findings no local run could surface. The version
# that CI pins works fine on the same machine, so the whole gap is a version mismatch the
# tooling did not notice. This script notices: it accepts a candidate binary only when its
# version is EXACTLY the pin and it was built with a Go at least as new as go.mod targets,
# and otherwise installs that exact version itself.
#
# The install forces GOTOOLCHAIN to go.mod's Go version deliberately. golangci-lint's own
# go.mod may name an older toolchain, and `go install` honors THAT -- producing a correctly
# versioned binary that still refuses this repo. Forcing the toolchain builds the pinned
# release with a new enough Go to lint us.
#
# Usage: GOLANGCI_LINT_VERSION=vX.Y.Z ./scripts/golangci-lint.sh [run-args...]

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

# The linter compares LANGUAGE versions (go1.26 vs 1.26.5 is fine), so both sides are
# truncated to major.minor before comparing.
lang_version() { printf '%s\n' "${1#go}" | cut -d. -f1,2; }

# version_ge A B — true when A >= B under version ordering.
version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# binary_version BIN — the version BIN reports, as vX.Y.Z, or nothing.
# `version --short` covers every release this repo has pinned; the long form is parsed as a
# fallback so a future output change degrades to a reinstall rather than a wrong answer.
binary_version() {
	local out
	out=$("$1" version --short 2>/dev/null || true)
	if [ -z "$out" ]; then
		out=$("$1" version 2>/dev/null | sed -n 's/.*has version v\{0,1\}\([0-9][^ ]*\).*/\1/p' || true)
	fi
	[ -n "$out" ] && printf 'v%s\n' "${out#v}"
}

# binary_go BIN — the Go language version BIN was built with (e.g. 1.26), or nothing.
binary_go() {
	local out
	out=$("$1" version 2>/dev/null | sed -n 's/.*built with go\([0-9][^ ]*\).*/\1/p' || true)
	[ -n "$out" ] && lang_version "$out"
}

# usable BIN — exactly the pinned version, and new enough to lint this repo.
usable() {
	local bin="$1" have have_go
	[ -n "$bin" ] && [ -x "$bin" ] || return 1
	have=$(binary_version "$bin")
	[ "$have" = "$WANT" ] || return 1
	have_go=$(binary_go "$bin")
	[ -n "$have_go" ] || return 1
	version_ge "$have_go" "$(lang_version "$TARGET_GO")"
}

GOPATH_BIN="$($GO env GOPATH)/bin/golangci-lint"

BIN=""
for cand in "${GOLANGCI_LINT:-}" "$(command -v golangci-lint 2>/dev/null || true)" "$GOPATH_BIN"; do
	if usable "$cand"; then
		BIN="$cand"
		break
	fi
done

if [ -z "$BIN" ]; then
	echo "Installing golangci-lint $WANT (the version CI pins), built with go$TARGET_GO..."
	if ! GOTOOLCHAIN="go$TARGET_GO" $GO install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$WANT"; then
		echo "" >&2
		echo "golangci-lint.sh: could not install golangci-lint $WANT." >&2
		echo "Install it manually (https://golangci-lint.run/docs/welcome/install/) and re-run," >&2
		echo "or point GOLANGCI_LINT at a $WANT binary built with go$(lang_version "$TARGET_GO") or newer." >&2
		exit 1
	fi
	if ! usable "$GOPATH_BIN"; then
		echo "" >&2
		echo "golangci-lint.sh: installed $GOPATH_BIN but it is not usable for this repo:" >&2
		echo "  want version $WANT, built with go$(lang_version "$TARGET_GO") or newer" >&2
		echo "  got  version $(binary_version "$GOPATH_BIN" || echo unknown), built with go$(binary_go "$GOPATH_BIN" || echo unknown)" >&2
		exit 1
	fi
	BIN="$GOPATH_BIN"
fi

exec "$BIN" run "$@"
