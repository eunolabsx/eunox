// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/eunolabs/eunox/internal/config"
)

// ControlTokenHeader carries the loopback control token on POST /control/kill. A
// dedicated header keeps the emergency-stop endpoint authenticated independently
// of the host-facing Authorization header (listen.authToken / JWT) on /mcp.
const ControlTokenHeader = "X-Eunox-Control-Token" //nolint:gosec // G101: header name, not a credential

// defaultControlTokenPath is where the auto-generated control token is written
// when --control-token-path is not set and EUNOX_CONTROL_TOKEN is not used.
const defaultControlTokenPath = "~/.eunox/control.token" //nolint:gosec // G101: a file path, not a credential

// GenerateControlToken returns a fresh 256-bit random token, hex-encoded. A
// rand.Read failure is returned (fail closed) rather than producing a weak token.
func GenerateControlToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating control token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// WriteControlTokenFile writes token to path (default defaultControlTokenPath)
// with 0600 perms under a 0700 directory, overwriting any previous token so a
// stale one cannot be replayed. Returns the expanded absolute path written.
//
// It writes a fresh temp file (0600 regardless of any pre-existing file's mode)
// and atomically renames it into place, so the secret never lands in a
// looser-mode file and a concurrent reader observes the old or new token, never a
// partial one.
func WriteControlTokenFile(path, token string) (string, error) {
	if path == "" {
		path = defaultControlTokenPath
	}
	expanded, err := config.ExpandHome(path)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(expanded)
	if dir == "" {
		dir = "."
	}
	if dir != "." {
		// Whether the directory ALREADY exists decides if we may tighten its mode: eunox
		// must not chmod a directory it did not create. A non-default --control-token-path
		// can point at a shared or operator-managed dir (/tmp, /var/run, /etc/eunox), and
		// forcing it to 0700 would strip /tmp's sticky bit + world access (system-wide
		// breakage as root) or fail with EPERM on a dir the user doesn't own (refusing to
		// start). MkdirAll creates any MISSING dirs at 0700 already, so a dir we create
		// needs no chmod; a pre-existing one we leave alone and only warn about.
		fi, statErr := os.Stat(dir)
		dirPreexisted := statErr == nil
		if err := os.MkdirAll(dir, 0o700); err != nil { //nolint:gosec // G301: 0700 is the intended restrictive mode
			return "", fmt.Errorf("creating control-token directory: %w", err)
		}
		if dirPreexisted {
			// Warn (do not mutate) if a pre-existing dir is looser than 0700, so the
			// operator can decide — the control token gates the loopback emergency stop, so
			// a group/world-accessible directory is worth flagging. Reuse the FileInfo from
			// the pre-existence stat above (MkdirAll does not touch an already-present dir),
			// so the mode is read exactly once.
			if fi.Mode().Perm()&0o077 != 0 {
				fmt.Fprintf(os.Stderr, "[eunox] WARNING: control-token directory %q has mode %v (group/world-accessible); eunox does not tighten a pre-existing directory it did not create — restrict it to 0700 yourself to protect the loopback control token\n", dir, fi.Mode().Perm())
			}
		}
	}
	tmp, err := os.CreateTemp(dir, ".control-token-*.tmp") //nolint:gosec // G304: dir derives from the operator-configured --control-token-path
	if err != nil {
		return "", fmt.Errorf("creating control-token temp file: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup: a no-op after a successful rename (tmpName is gone).
	defer func() { _ = os.Remove(tmpName) }()
	// CreateTemp already uses 0600, but set it explicitly to guarantee the mode
	// regardless of umask.
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("setting control-token file mode: %w", err)
	}
	if _, err := tmp.WriteString(token + "\n"); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("writing control token: %w", err)
	}
	// fsync the data before the rename so the durable on-disk ordering matches the
	// atomic-rename intent: without it a crash can leave the rename visible while the
	// data blocks are not yet persisted, yielding a zero-length control-token file —
	// ResolveControlToken then reads an empty token and the loopback emergency stop is
	// unusable exactly when it is most needed.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("syncing control-token temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("closing control-token temp file: %w", err)
	}
	if err := os.Rename(tmpName, expanded); err != nil {
		return "", fmt.Errorf("publishing control token to %s: %w", expanded, err)
	}
	// fsync the parent directory so the rename itself (the directory entry) is durable;
	// otherwise a crash could lose the rename even though the file data was synced.
	// Best-effort with a diagnostic, mirroring the audit key writer's syncDir: a
	// directory that cannot be opened or synced (some filesystems reject directory
	// fsync) is logged and tolerated rather than failing the write — the gap it closes
	// is a crash-recovery edge case, and the token data itself is already synced above.
	if d, err := os.Open(dir); err != nil { //nolint:gosec // G304: dir derives from the operator-configured --control-token-path
		fmt.Fprintf(os.Stderr, "[eunox] WARN: cannot open control-token dir %q to fsync: %v\n", dir, err)
	} else {
		if err := d.Sync(); err != nil {
			fmt.Fprintf(os.Stderr, "[eunox] WARN: cannot fsync control-token dir %q: %v\n", dir, err)
		}
		_ = d.Close()
	}
	return expanded, nil
}

// ResolveControlToken returns the control token for the kill subcommand, in
// precedence order: an explicit flag value, the EUNOX_CONTROL_TOKEN environment
// variable, then the token file at path (default defaultControlTokenPath) where
// the running proxy wrote it.
func ResolveControlToken(flagToken, path string) (string, error) {
	// TrimSpace each source for parity, so a token pasted with a trailing newline
	// compares equal regardless of where it came from.
	if t := strings.TrimSpace(flagToken); t != "" {
		return t, nil
	}
	// TrimSpace before the empty test so a whitespace-only EUNOX_CONTROL_TOKEN
	// falls through to the file source rather than short-circuiting empty.
	if env := strings.TrimSpace(os.Getenv("EUNOX_CONTROL_TOKEN")); env != "" {
		return env, nil
	}
	if path == "" {
		path = defaultControlTokenPath
	}
	expanded, err := config.ExpandHome(path)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(expanded) //nolint:gosec // G304: path is operator-configured via --control-token-path
	if err != nil {
		return "", fmt.Errorf("reading control token from %s: %w (start the proxy first, or pass --control-token / EUNOX_CONTROL_TOKEN)", expanded, err)
	}
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		return "", fmt.Errorf("control token file %s is empty", expanded)
	}
	return tok, nil
}
