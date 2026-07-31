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
//
// A leading "~" is expanded FIRST, through the same ExpandHome the audit-log and
// control-token paths use. Without it, "~/policies/x.yaml" is not absolute, so the
// join below would resolve it to "<config-dir>/~/policies/x.yaml" — a path that
// almost never exists, turning an operator's home-relative policy entry into a
// startup failure that names a directory they never wrote. The "~user/..." form
// ExpandHome cannot resolve portably fails closed with its message rather than
// silently resolving to a "~user" directory under the config dir.
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

// ExpandHome expands a leading "~" followed by a path separator (or a bare "~") in
// p to the current user's home directory, fail-closed: an unresolvable home
// directory is an error rather than a silent pass-through of the literal "~". Any
// other path (including one that merely contains a "~" elsewhere) is returned
// unchanged. Shared by internal/audit (the audit-log/key path defaults) and
// internal/transport (the control-token file path) so the two cannot silently
// re-diverge on "~" expansion — internal/config builds standalone, so both can
// import it without creating a cycle.
//
// The separator test is os.IsPathSeparator, not a literal '/', so the native
// "~\eunox\audit.jsonl" spelling expands on Windows. Matching only "~/" there sent
// every backslash spelling into the fail-closed "~user/..." arm below and refused a
// path the operator wrote correctly for their platform. On Unix, where '\' is an
// ordinary filename character, "~\foo" is still refused.
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
	// A "~user/..." form is NOT expanded — Go has no portable way to resolve another
	// user's home directory — so it used to fall through and be treated as an ordinary
	// RELATIVE path, silently creating a directory literally named "~alice" under the
	// process cwd. For an audit log or its HMAC key that means the tamper-evident artifact
	// lands somewhere the operator never chose and will not think to look. Refuse instead:
	// the operator asked for a path this function cannot honor, and fail-closed with a
	// clear message beats a silently wrong location.
	if strings.HasPrefix(p, "~") {
		return "", fmt.Errorf("cannot expand %q: only %q and %q are supported (a %q form cannot be resolved portably); write the absolute path instead", p, "~", "~/...", "~user/...")
	}
	return p, nil
}

// RefuseNonRegularPath fails closed unless path is a regular file or genuinely absent.
// subject names what the path is, for the error message ("audit log path", "output file").
//
// It guards every writer that opens an operator-supplied destination without O_EXCL.
// O_EXCL refuses to follow a symlink for free, so a create-only write needs nothing; the
// moment a writer drops it for O_TRUNC (an --output overwrite, the doctor bundle) or
// O_APPEND (the audit log), it will happily follow an attacker-planted link at that path
// and write through to the link's TARGET — and any subsequent fd Chmod re-modes that
// target too. A shared, world-writable directory is enough. For the audit log the
// consequence is sharper still: the tape is redirected AND the live log drops out of
// LogChainFiles' IsRegular() scan, so audit-verify passes without reading a record.
//
// Lstat inspects the final component itself rather than its target. Only a genuinely
// ABSENT path (fs.ErrNotExist) is let through — the ordinary fresh-install and
// post-rename case the caller's O_CREATE then fills. Any OTHER stat error (EIO, NFS
// ESTALE, ELOOP, EACCES on a path component) is REFUSED, not assumed benign: gating the
// refusal on "stat succeeded" would let a stat fault skip the check and follow a symlink,
// the fail-OPEN direction this guard exists to prevent.
//
// This check alone leaves a Lstat->open TOCTOU: a symlink planted between it and the open
// is still followed. Closing that needs O_NOFOLLOW-level atomicity, which is not portable,
// so it is a SEPARATE, build-tagged flag rather than something this function can do —
// OpenNoFollow, which every truncating/appending caller ORs into its open. Both halves are
// needed: this one is portable and also refuses directories, devices and FIFOs; that one
// closes the race where the platform supports it.
//
// It lives here, beside ExpandHome, because the binary and internal/audit each had their
// own hand-written copy and they had already drifted — one distinguished a symlink from
// another special file, the other did not — which is how a guard ends up weaker on one of
// the paths it protects.
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
