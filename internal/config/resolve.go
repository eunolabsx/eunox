// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"
)

// ResolveBool returns *override when set, else def.
func ResolveBool(override *bool, def bool) bool {
	if override != nil {
		return *override
	}
	return def
}

// ResolveInt returns *override when set (a present pointer wins, INCLUDING an
// explicit 0 so config can express "unlimited"/"disabled" over a non-zero flag),
// else def. The int analogue of ResolveBool, shared by the transport's
// ResolveMaxSessions / ResolveSessionIdleTimeout so the pointer-override precedence
// lives in one place.
func ResolveInt(override *int, def int) int {
	if override != nil {
		return *override
	}
	return def
}

// ResolvePolicyPath resolves a route's policy: entry against baseDir (the gateway
// config file's directory) so a relative path finds its manifest regardless of the
// process working directory. An absolute path, or an empty baseDir (e.g. a
// programmatically built config), is returned verbatim. Shared by the proxy load
// path (LoadUpstreamPDP) and validate --config so the two cannot drift into
// resolving the same policy entry to different files.
func ResolvePolicyPath(baseDir, policyPath string) string {
	if baseDir != "" && !filepath.IsAbs(policyPath) {
		return filepath.Join(baseDir, policyPath)
	}
	return policyPath
}

// MaxDurationMs is the largest millisecond count that still fits in a
// time.Duration (int64 nanoseconds) once multiplied by time.Millisecond:
// math.MaxInt64 / 1e6 = 9223372036854. A larger value overflows the int64.
const MaxDurationMs = int64(math.MaxInt64) / int64(time.Millisecond)

// ExpandHome expands a leading "~" or "~/" in p to the current user's home
// directory, fail-closed: an unresolvable home directory is an error rather than
// a silent pass-through of the literal "~". Any other path (including one that
// merely contains a "~" elsewhere) is returned unchanged. Shared by
// internal/audit (the audit-log/key path defaults) and internal/transport (the
// control-token file path) so the two cannot silently re-diverge on "~"
// expansion — internal/config builds standalone, so both can import it without
// creating a cycle.
func ExpandHome(p string) (string, error) {
	if p == "~" || (len(p) >= 2 && p[:2] == "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot expand %q: home directory is unavailable: %w", p, err)
		}
		if p == "~" {
			return home, nil
		}
		return filepath.Join(home, p[2:]), nil
	}
	return p, nil
}
