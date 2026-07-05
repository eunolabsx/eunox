#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/check-notice.sh — keep NOTICE in sync with the binary's dependencies.
#
# The NOTICE file ships with the eunox binary, so its third-party section
# must list every non-test third-party module in the binary's build closure --
# no more, no less. Test-only dependencies (testify, miniredis, ...) are not
# distributed and are intentionally excluded.
#
# This guards the *set* of modules only. The "License:" and "Copyright" lines in
# NOTICE stay hand-curated on purpose -- auto-detected license strings are a
# legal liability, so a human confirms them. When the dependency set drifts this
# check fails CI with an actionable list; for any newly added module it prints a
# best-effort stanza (license + copyright read from the module's LICENSE file)
# as a starting point -- always verify it against the actual license.

set -euo pipefail

cd "$(dirname "$0")/.."

NOTICE_FILE="NOTICE"
MODULE_PATH="github.com/eunolabs/eunox"

# want: modules whose code is linked into the distributed artifact -- the
# non-test build closure of the cmd/ entrypoint plus the pkg/ library -- minus
# this module itself.
#
# Capture `go list` into a variable and abort if it fails. Piping it straight
# into the `while read` loop's process substitution swallowed a `go list`
# failure (a compile error, a module-fetch failure): set -e and pipefail do not
# observe a process substitution's exit status, so `want` was left empty and the
# diff below then reported every NOTICE stanza as stale -- recommending deletion
# of the entire third-party list (and tripping "want[@]: unbound variable" under
# bash 3.2's set -u). Fail closed here with an actionable error instead.
#
# The binary's dependency set is platform-dependent: golang.org/x/sys, for
# example, is linked only on Windows (the audit-log file-locking path in
# internal/audit/lock_windows.go). The same NOTICE ships with every released
# artifact, so the check must list the UNION of the build closures across every
# released GOOS -- not just the host's, which would silently omit the
# Windows-only module and ship an incomplete NOTICE with the Windows binary.
deps=""
for goos in linux darwin windows; do
	if ! osdeps=$(GOOS="$goos" go list -deps -f '{{if and (not .Standard) .Module}}{{.Module.Path}}{{end}}' \
		./cmd/eunox ./pkg/...); then
		echo "check-notice: 'go list' failed for GOOS=$goos; cannot determine the binary's dependency set (see errors above)." >&2
		exit 2
	fi
	deps=$(printf '%s\n%s\n' "$deps" "$osdeps")
done
want=()
while IFS= read -r mod; do
	[ -n "$mod" ] && want+=("$mod")
done < <(printf '%s\n' "$deps" | sort -u | grep -vx "$MODULE_PATH")

# have: modules listed in NOTICE. A module line is any line immediately
# followed by a "License:" line, which uniquely identifies the stanza headers.
have=()
while IFS= read -r modline; do
	have+=("$modline")
done < <(
	awk 'prev != "" && /^License:/ { print prev } { prev = $0 }' "$NOTICE_FILE" |
		sort -u
)

# Expand both arrays through the "${arr[@]+...}" guard so an empty want or have
# does not trip "unbound variable" under bash 3.2's set -u, which treats an empty
# array as unset. When an array is empty the expansion yields no words and printf
# emits a single blank line, which sorts ahead of every module path and is
# stripped from the command substitution, so it never appears as a phantom diff
# entry.
missing=$(comm -23 <(printf '%s\n' "${want[@]+"${want[@]}"}") <(printf '%s\n' "${have[@]+"${have[@]}"}"))
stale=$(comm -13 <(printf '%s\n' "${want[@]+"${want[@]}"}") <(printf '%s\n' "${have[@]+"${have[@]}"}"))

if [ -z "$missing" ] && [ -z "$stale" ]; then
	echo "NOTICE third-party list is in sync (${#want[@]} modules)."
	exit 0
fi

echo "NOTICE is out of sync with the eunox binary's dependencies." >&2

if [ -n "$stale" ]; then
	echo "" >&2
	echo "Listed in NOTICE but no longer a dependency (remove these stanzas):" >&2
	echo "$stale" | sed 's/^/  - /' >&2
fi

if [ -n "$missing" ]; then
	echo "" >&2
	echo "Dependencies missing from NOTICE (add a stanza for each):" >&2
	echo "$missing" | sed 's/^/  + /' >&2
	echo "" >&2
	echo "Suggested stanzas -- VERIFY against each module's LICENSE before committing:" >&2
	while IFS= read -r mod; do
		[ -z "$mod" ] && continue
		dir=$(go list -m -f '{{.Dir}}' "$mod" 2>/dev/null || true)
		lic="UNKNOWN"
		cpy="Copyright (c) ..."
		if [ -n "$dir" ]; then
			lf=$(find "$dir" -maxdepth 1 -iregex '.*/\(license\|copying\)\(\.txt\|\.md\)?' 2>/dev/null | head -1 || true)
			if [ -n "$lf" ]; then
				if grep -qi 'Apache License' "$lf"; then
					lic="Apache-2.0"
				elif grep -qiE 'Neither the name' "$lf"; then
					lic="BSD-3-Clause"
				elif grep -qi 'Permission is hereby granted, free of charge' "$lf"; then
					lic="MIT"
				elif grep -qiE 'Redistribution and use' "$lf"; then
					lic="BSD-2-Clause"
				elif grep -qi 'ISC License' "$lf"; then
					lic="ISC"
				fi
				found=$(grep -m1 -iE 'copyright' "$lf" | sed 's/^[[:space:]]*//' || true)
				[ -n "$found" ] && cpy="$found"
			fi
		fi
		printf '\n%s\nLicense: %s\n%s\n' "$mod" "$lic" "$cpy" >&2
	done <<<"$missing"
fi

echo "" >&2
echo "Update $NOTICE_FILE to match, then re-run 'make check-notice'." >&2
exit 1
