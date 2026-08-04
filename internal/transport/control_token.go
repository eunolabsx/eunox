// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/eunolabs/eunox/internal/config"
)

// afterListenTimeout bounds the post-bind startup hook (see HTTPGatewayOptions.AfterListen),
// whose one production job is persisting the control token. Matches the budget `eunox kill`
// already gives its own request, so a client racing this window cannot wait longer.
const afterListenTimeout = 10 * time.Second

// ControlTokenHeader carries the loopback control token on POST /control/kill. A
// dedicated header keeps the emergency-stop endpoint authenticated independently
// of the host-facing Authorization header (listen.authToken / JWT) on /mcp.
const ControlTokenHeader = "X-Eunox-Control-Token" //nolint:gosec // G101: header name, not a credential

// defaultControlTokenPath is where the auto-generated control token is written
// when --control-token-path is not set and EUNOX_CONTROL_TOKEN is not used.
const defaultControlTokenPath = "~/.eunox/control.token" //nolint:gosec // G101: a file path, not a credential

// tightenTokenDir enforces the mode of a PRE-EXISTING control-token directory, split by who
// owns the location rather than by how loose the mode is:
//
//   - eunoxOwned (the default ~/.eunox, which only eunox writes): chmod to 0700, fail closed
//     if that fails. Repairs an older version/packaging step that left it 0755.
//   - operator-chosen (--control-token-path elsewhere): never chmod — forcing 0700 could strip
//     /tmp's sticky bit or fail with EPERM on a directory eunox doesn't own. A merely
//     group/world-readable directory is warned about (the token file itself is 0600); a
//     group/world-writable one with no sticky bit is refused outright, since any local user
//     could substitute their own token file and take over the emergency stop.
//
// fi is the RESOLVED directory (symlinks followed): eunoxOwned is false for a symlink so the
// chmod never fires through one — os.Chmod follows links and there is no portable lchmod, so
// tightening a symlinked ~/.eunox would silently rewrite whatever it points at.
func tightenTokenDir(dir string, fi os.FileInfo, eunoxOwned bool) error {
	perm := fi.Mode().Perm()
	if perm&0o077 == 0 {
		return nil
	}
	if eunoxOwned {
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: 0700 is the intended restrictive mode -- this call exists to REMOVE group/world access, matching the MkdirAll above
			return fmt.Errorf("restricting control-token directory %q (mode %v) to 0700: %w", dir, perm, err)
		}
		return nil
	}
	if perm&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("control-token directory %q has mode %v (group/world-writable, no sticky bit): another local user could replace the loopback control token and take over the emergency stop; restrict it to 0700 or point --control-token-path elsewhere", dir, perm)
	}
	fmt.Fprintf(os.Stderr, "[eunox] WARNING: control-token directory %q has mode %v (group/world-accessible); eunox does not tighten a pre-existing directory it did not create — restrict it to 0700 yourself to protect the loopback control token\n", dir, perm)
	return nil
}

// eunoxOwnedTokenDir reports whether dir is eunox's OWN control-token directory — the one the
// default --control-token-path lives in, which nothing else writes — and so may be tightened.
//
// Compares resolved LOCATIONS, not the spelling of the flag: keying on the raw string made an
// identical directory get different treatment depending on how the operator typed it (e.g. a
// systemd unit can't use "~"), missing exactly the deployments most likely to need the repair.
//
// A symlink is never eunox-owned however it resolves: see tightenTokenDir on why the chmod
// must not follow one.
func eunoxOwnedTokenDir(dir string) bool {
	if lfi, err := os.Lstat(dir); err != nil || lfi.Mode()&os.ModeSymlink != 0 {
		return false
	}
	expandedDefault, err := config.ExpandHome(defaultControlTokenPath)
	if err != nil {
		return false
	}
	return filepath.Clean(dir) == filepath.Clean(filepath.Dir(expandedDefault))
}

// GenerateControlToken returns a fresh 256-bit random token, hex-encoded. A
// rand.Read failure is returned (fail closed) rather than producing a weak token.
func GenerateControlToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating control token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// WriteControlTokenFile writes token to path (default defaultControlTokenPath) with 0600
// perms, overwriting any previous token, and returns the expanded absolute path written.
//
// Writes a fresh temp file (always 0600) and atomically renames it into place, so the secret
// never lands in a looser-mode file and a concurrent reader sees the old or new token, never a
// partial one. ctx bounds the write: the sequence includes an unbounded-on-a-stalled-mount
// fsync, and Serve runs this after the listener binds but before accepting — an unbounded hang
// here would leave `eunox kill` (the client most likely racing startup) hung instead of
// getting an immediate connection-refused.
func WriteControlTokenFile(ctx context.Context, path, token string) (string, error) {
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
		// Whether the directory ALREADY exists decides how its mode is handled: MkdirAll
		// creates any MISSING dir at 0700, so a dir eunox creates needs nothing further.
		// A pre-existing one splits by ownership of the location (see tightenTokenDir).
		fi, statErr := os.Stat(dir)
		dirPreexisted := statErr == nil
		if err := os.MkdirAll(dir, 0o700); err != nil { //nolint:gosec // G301: 0700 is the intended restrictive mode
			return "", fmt.Errorf("creating control-token directory: %w", err)
		}
		if dirPreexisted {
			// Reuse the FileInfo from the pre-existence stat above (MkdirAll does not
			// touch an already-present dir), so the mode is read exactly once.
			if err := tightenTokenDir(dir, fi, eunoxOwnedTokenDir(dir)); err != nil {
				return "", err
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
	// fsync before the rename: without it a crash can leave the rename visible while the data
	// blocks are not yet persisted, yielding a zero-length token file exactly when the
	// emergency stop is most needed.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("syncing control-token temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("closing control-token temp file: %w", err)
	}
	// Checked HERE, immediately before the rename, not by a watchdog around the whole call:
	// an abandoned caller's os.Rename could otherwise land seconds later, clobbering the token
	// of whatever proxy is actually serving. Directory work already done (MkdirAll,
	// tightenTokenDir's chmod) is deliberately NOT undone on abort -- both only restrict, so
	// reverting them would loosen a directory holding an emergency-stop token.
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("control token not published to %s: %w (the write did not complete in time; any existing token file is left untouched)", expanded, err)
	}
	if err := os.Rename(tmpName, expanded); err != nil {
		return "", fmt.Errorf("publishing control token to %s: %w", expanded, err)
	}
	// fsync the parent directory so the rename entry itself is durable. Best-effort with a
	// diagnostic (some filesystems reject directory fsync); a crash-recovery edge case, not
	// worth failing the write over since the token data itself is already synced.
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
