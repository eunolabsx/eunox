// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ResolveBool returns *override when set, else def.
func ResolveBool(override *bool, def bool) bool {
	if override != nil {
		return *override
	}
	return def
}

// ResolveInt returns *override when set (including an explicit 0, so config can express
// "unlimited"/"disabled" over a non-zero flag), else def. Shared by the transport's
// ResolveMaxSessions / ResolveSessionIdleTimeout.
func ResolveInt(override *int, def int) int {
	if override != nil {
		return *override
	}
	return def
}

// ResolvePolicyPath resolves a route's policy: entry against baseDir (the gateway config
// file's directory) so a relative path finds its manifest regardless of the process working
// directory. An absolute path, or an empty baseDir, is returned verbatim. Shared by the proxy
// load path and validate --config so the two cannot resolve one entry to different files.
//
// A leading "~" is expanded FIRST via ExpandHome: without it, "~/policies/x.yaml" is not
// absolute, so the join below would resolve it to "<config-dir>/~/policies/x.yaml" instead.
func ResolvePolicyPath(baseDir, policyPath string) (string, error) {
	expanded, err := ExpandHome(policyPath)
	if err != nil {
		return "", fmt.Errorf("policy path: %w", err)
	}
	if baseDir != "" && !filepath.IsAbs(expanded) {
		return filepath.Join(baseDir, expanded), nil
	}
	return expanded, nil
}

// MaxDurationMs is the largest millisecond count that still fits in a
// time.Duration (int64 nanoseconds) once multiplied by time.Millisecond:
// math.MaxInt64 / 1e6 = 9223372036854. A larger value overflows the int64.
const MaxDurationMs = int64(math.MaxInt64) / int64(time.Millisecond)

// ExpandHome expands a leading "~" followed by a path separator (or a bare "~") in p to the
// current user's home directory, fail-closed: an unresolvable home directory is an error
// rather than a silent pass-through of the literal "~". Any other path is returned unchanged.
//
// The separator test is os.IsPathSeparator, not a literal '/', so the native Windows
// "~\eunox\audit.jsonl" spelling also expands rather than falling into the "~user/..." refusal.
func ExpandHome(p string) (string, error) {
	if p == "~" || (len(p) >= 2 && p[0] == '~' && os.IsPathSeparator(p[1])) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot expand %q: home directory is unavailable: %w", p, err)
		}
		if p == "~" {
			return home, nil
		}
		return filepath.Join(home, p[2:]), nil
	}
	// A "~user/..." form is NOT expanded (Go has no portable way to resolve another user's
	// home directory), so refuse rather than silently treat it as an ordinary relative path.
	if strings.HasPrefix(p, "~") {
		return "", fmt.Errorf("cannot expand %q: only %q and %q are supported (a %q form cannot be resolved portably); write the absolute path instead", p, "~", "~/...", "~user/...")
	}
	return p, nil
}

// RefuseNonRegularPath fails closed unless path is a regular file or genuinely absent.
// subject names what the path is, for the error message ("audit log path", "output file").
//
// It guards every writer that opens an operator-supplied destination without O_EXCL: once a
// writer drops O_EXCL for O_TRUNC or O_APPEND it will follow an attacker-planted symlink and
// write through to its target. Lstat lets through only a genuinely absent path
// (fs.ErrNotExist); any other stat error is refused rather than assumed benign, since gating
// on "stat succeeded" would let a stat fault skip the check and follow a symlink.
//
// This alone leaves a Lstat->open TOCTOU; closing that needs OpenNoFollow (a separate,
// build-tagged flag every truncating/appending caller ORs into its open), since O_NOFOLLOW
// atomicity is not portable. Both halves are needed: this one also refuses directories,
// devices and FIFOs; that one closes the race where the platform supports it.
func RefuseNonRegularPath(path, subject string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("refusing %s %q: cannot stat it (%v); a path that may be a symlink or other non-regular file is not safe to open", subject, path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing %s %q: it is a symbolic link, and following it would write through to the link's target — remove the link or choose a different path", subject, path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("refusing a non-regular %s %q (mode %v): it must be a regular file, not a symlink or other special file", subject, path, fi.Mode())
	}
	return nil
}
