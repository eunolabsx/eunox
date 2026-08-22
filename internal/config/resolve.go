// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io"
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

// RefuseNonRegularHandle refuses an already-OPEN file that is not a regular file. It is the
// third guard in the substitution set, and none of the three subsumes another:
// RefuseNonRegularPath refuses what the PATH names, OpenNoFollow/OpenNonBlock make the open
// itself safe to attempt, and this one asks through the HANDLE — the only question with no
// TOCTOU window after it, since it describes the object the caller is about to read or write
// rather than whatever the name resolved to a syscall ago.
//
// subject names what the file is, for the error message, matching RefuseNonRegularPath's.
func RefuseNonRegularHandle(f *os.File, subject, path string) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("refusing %s %q: cannot stat the open file (%v)", subject, path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing a non-regular %s %q (mode %v): it must be a regular file, not a symlink or other special file", subject, path, info.Mode())
	}
	return nil
}

// BoundedRead is one bounded whole-file read's parameters — a struct rather than
// positional args, since Path/What are both strings that read identically at a call site
// and swapping them would garble every error message ReadBoundedFile produces.
type BoundedRead struct {
	// Path is the file to read; What names its kind for the error messages ("manifest",
	// "gateway config", "contract", "attestation trust store").
	Path, What string
	// Max is the inclusive byte bound: a file exactly this size still loads.
	Max int64
	// Flags are any extra open flags the caller's own threat model needs, beyond
	// O_RDONLY (e.g. OpenNoFollow for a trust root). Zero for a caller that needs none.
	Flags int
	// OverLimit completes the over-size error; each caller states what refusing buys IT,
	// since a truncated read means something different for a key set than a manifest.
	OverLimit string
	// Discovered marks a path eunox found by SCANNING a directory rather than one the
	// operator named, which is what decides whether the FIFO guard applies.
	//
	// A discovered path is attacker-influenceable: whoever can write the directory chooses
	// what the scan finds, and RefuseNonRegularPath runs against the NAME, so a FIFO swapped
	// in after that Lstat is opened directly — and a read-only open of a reader-less FIFO
	// blocks inside open(2) forever, which no size bound and no O_NOFOLLOW reaches. Such a
	// read takes OpenNonBlock so the open returns, plus RefuseNonRegularHandle through the
	// fd, which is the only check with no window after it.
	//
	// A path the OPERATOR named is theirs to point wherever they like, and pointing it at a
	// non-regular file is a supported spelling rather than an attack: `--config
	// <(envsubst < t.yaml)` is a FIFO, and `--config /dev/stdin` is a pipe. Refusing those
	// bought nothing — an operator who can pass --config can pass anything — and broke a
	// working invocation, so the guard is scoped to the paths whose CHOICE is not theirs.
	Discovered bool
}

// ReadBoundedFile reads Path whole, refusing anything past Max bytes rather than
// buffering an operator-supplied file of unbounded size — every loader here reads a path
// named on the command line or in another config file, so a fat-fingered path pointed at a
// data file or disk image must produce an error, not an OOM. Reads one byte past the bound
// so a file exactly at the limit still loads and anything larger is detectable without
// reading it all.
//
// The FIFO half of the substitution guard is applied for a DISCOVERED path only (see
// BoundedRead.Discovered), never for one the operator named.
func ReadBoundedFile(rd BoundedRead) ([]byte, error) {
	flags := rd.Flags
	if rd.Discovered {
		flags |= OpenNonBlock
	}
	f, err := os.OpenFile(rd.Path, os.O_RDONLY|flags, 0) //nolint:gosec // G304: operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("reading %s %q: %w", rd.What, rd.Path, err)
	}
	defer func() { _ = f.Close() }()
	if rd.Discovered {
		if err := RefuseNonRegularHandle(f, rd.What, rd.Path); err != nil {
			return nil, err
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, rd.Max+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s %q: %w", rd.What, rd.Path, err)
	}
	if int64(len(data)) > rd.Max {
		return nil, fmt.Errorf("%s %q is larger than %d bytes; %s", rd.What, rd.Path, rd.Max, rd.OverLimit)
	}
	return data, nil
}
