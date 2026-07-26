// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// HMAC key management for the audit log: resolving the key path, loading or
// creating the signing key, publishing the verification key set, and the file-mode
// tightening that keeps a key readable only by its owner.
//
// Split out of audit.go verbatim (writer core), alongside rotate.go (rotation and
// retention) and verify.go (chain verification). No behavior change.

package audit

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/eunolabs/eunox/internal/config"
)

// -----------------------------------------------------------------
// HMAC key management
// -----------------------------------------------------------------

// tightenLogMode drops any group/world access from an already-open log file,
// preserving owner bits, re-securing a log left readable by a looser umask, a
// restore, or a pre-created path (O_CREATE's restrictive mode applies only on
// creation). It does NOT add owner bits, so an owner-write-only (0200) log stays
// that way and its tail read still fails closed. Best-effort with a warning: some
// backends (FAT/exFAT, certain CIFS/NFS) cannot chmod, and refusing to start there
// is worse than the (HMAC-protected) log keeping its mode.
func tightenLogMode(f *os.File, logPath string) {
	info, err := f.Stat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: could not stat audit log %q to tighten its mode: %v\n", logPath, err)
		return
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		if cerr := f.Chmod(perm &^ 0o077); cerr != nil { //nolint:gosec // G302: clearing group/world bits is the intended restriction
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: could not tighten audit log %q (drop group/world access): %v\n", logPath, cerr)
		}
	}
}

// tightenKeyFileMode drops any group/world access from a pre-existing HMAC key
// file, preserving owner bits (the preceding ReadFile proves owner read). Unlike
// the log, a key found group/world-accessible is a possible prior-exposure signal
// (anyone who could read it may have copied it and can forge verifiable records),
// so the loose->tight transition is surfaced as a SECURITY warning recommending
// rotation rather than fixed silently. Best-effort (see tightenLogMode).
func tightenKeyFileMode(keyPath string) {
	info, err := os.Stat(keyPath) //nolint:gosec // G304: keyPath is the user-configured audit key location
	if err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: could not stat audit key file %q to tighten its mode: %v\n", keyPath, err)
		return
	}
	perm := info.Mode().Perm()
	if perm&0o077 == 0 {
		return
	}
	if cerr := os.Chmod(keyPath, perm&^0o077); cerr != nil { //nolint:gosec // G302: clearing group/world bits is the intended restriction
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: could not tighten audit key file %q (drop group/world access): %v\n", keyPath, cerr)
		return
	}
	fmt.Fprintf(os.Stderr,
		"[eunox] SECURITY: audit key file %q was group/world-accessible (mode %#o), now tightened to %#o. "+
			"The key may already have been read by another local user — consider rotating it (prepend a fresh key; see the audit key rotation docs).\n",
		keyPath, perm, perm&^0o077)
}

// LoadOrCreateKeys loads every HMAC key from the key file, active signing key
// first. The file holds one 64-hex-char key per line; blank and '#' lines are
// ignored. The first key is active; the rest are retired keys kept so audit-verify
// can validate records they signed before a rotation (§ 3.4). A missing file
// generates and writes a fresh single key; a file that exists but holds no valid
// key, or any malformed line, is a hard error rather than a silent regeneration
// (overwriting would invalidate every prior record's signature).
func LoadOrCreateKeys(keyPath string) ([][]byte, error) {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil { //nolint:gosec // G304: keyPath is user-configured via --audit-key-path; taint is intentional
		return nil, err
	}
	// A freshly created key directory is 0700; a pre-existing one is left as the
	// operator set it. We do NOT re-tighten an existing key directory: a 0600 key
	// file is unreadable by others regardless of directory mode, and --audit-key-path
	// targets deployments where the key often lives in a shared/read-only secret
	// mount the operator manages. The load-bearing fix is the key FILE mode below.

	data, err := os.ReadFile(keyPath) //nolint:gosec // G304: path is user-configured audit key location (--audit-key-path or EUNOX_AUDIT_KEY_PATH)
	if err == nil {
		// Drop any group/world access from a pre-existing key file: a readable HMAC
		// key lets any local user forge records. Freshly generated keys are written
		// 0600, so this only affects keys created outside that path. tightenKeyFileMode
		// warns, since a loose key is a possible prior-exposure signal.
		tightenKeyFileMode(keyPath)
		keys, parseErr := parseAuditKeys(data)
		if parseErr != nil {
			return nil, fmt.Errorf("audit key file %q: %w", keyPath, parseErr)
		}
		return keys, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading audit key file %q: %w", keyPath, err)
	}

	// Key file does not exist — generate, persist, and return a fresh key.
	return generateAndPersistAuditKey(keyPath)
}

// LoadKeys loads every HMAC key from the key file WITHOUT creating one when it is
// absent — the read-only counterpart to LoadOrCreateKeys, for verification paths
// (audit-verify) that must never mint a key as a side effect. A missing file is a
// clear error naming the path rather than a silent regeneration that would then make
// every record report UNKNOWN_KEY and misdiagnose a mistyped --audit-key-path or a
// wrong machine as a key rotation. Format and retired-key semantics match
// LoadOrCreateKeys.
func LoadKeys(keyPath string) ([][]byte, error) {
	data, err := os.ReadFile(keyPath) //nolint:gosec // G304: path is user-configured audit key location (--audit-key-path or EUNOX_AUDIT_KEY_PATH)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("audit key file %q not found — pass --audit-key-path pointing at the key that signed this log", keyPath)
		}
		return nil, fmt.Errorf("reading audit key file %q: %w", keyPath, err)
	}
	tightenKeyFileMode(keyPath)
	keys, parseErr := parseAuditKeys(data)
	if parseErr != nil {
		return nil, fmt.Errorf("audit key file %q: %w", keyPath, parseErr)
	}
	return keys, nil
}

// generateAndPersistAuditKey generates a fresh 32-byte HMAC key, persists it to
// keyPath with a crash- and race-safe write-temp-then-link handshake, and returns
// it (or, if a concurrent starter won the publish race, that starter's key read
// back from disk). Called by LoadOrCreateKeys only after the file is confirmed
// absent.
func generateAndPersistAuditKey(keyPath string) ([][]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating audit key: %w", err)
	}

	// Write the key with a trailing newline so the file conforms to the
	// one-key-per-line format. Without it, a shell append rotation
	// (echo "$NEWKEY" >> keyfile) would concatenate onto the existing line, yielding
	// a 128-hex-char line parseAuditKeys rejects (64 bytes, want 32). parseAuditKeys
	// trims each line, so the newline is consumed on read and existing files need no
	// migration.
	encoded := make([]byte, hex.EncodedLen(len(key))+1)
	hex.Encode(encoded, key)
	encoded[len(encoded)-1] = '\n'

	// Persist with a write-temp-then-link handshake so two concurrent starters on a
	// shared key path cannot each generate a different key and sign with divergent
	// in-memory keys while only one is persisted. The temp is written and closed in
	// full FIRST, then os.Link publishes it at keyPath; Link fails (EEXIST) if the
	// path exists, so the first linker wins and the path only ever becomes visible
	// fully written. A plain O_EXCL create would expose an empty file between create
	// and write.
	dir := filepath.Dir(keyPath)
	tmp, err := os.CreateTemp(dir, ".audit-key-*.tmp") //nolint:gosec // G304: dir derives from the user-configured key path
	if err != nil {
		return nil, fmt.Errorf("creating temp audit key file in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup: redundant after a successful link, must not linger on error.
	defer func() {
		_ = os.Remove(tmpName) //nolint:gosec // G304: tmpName derives from the user-configured key path; removing our own temp file is intentional
	}()
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("writing audit key: %w", err)
	}
	// fsync before publishing so the key's data blocks are durable, not just in the
	// page cache. Otherwise a power loss between Close and the flush can leave the
	// inode present but its data zero/stale, and on reboot parseAuditKeys fails on
	// the empty file — a hard error (never regenerated), so the proxy refuses to
	// start until an operator removes it.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("syncing temp audit key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("closing temp audit key file: %w", err)
	}

	if err := osLink(tmpName, keyPath); err != nil {
		if os.IsExist(err) {
			// Another process linked first; read and return its key. No syncDir: the
			// race winner owns the directory-entry fsync.
			return readPublishedAuditKeys(keyPath, "after create race")
		}
		if isNoHardlinkErr(err) {
			// The filesystem rejects hard links (CIFS/Samba, some NFS, FAT32/exFAT,
			// some bind-mount backends), so fall back to an atomic rename. This is a
			// deliberate downgrade, not a substitute: os.Rename overwrites silently, so
			// it cannot fail-on-exist to arbitrate two concurrent first-starts.
			// Re-reading converges the persisted key on the last rename, but does not
			// close the window where an earlier starter already re-read a key a later
			// rename overwrote. That residual divergence is confined to the rare
			// first-start race on a hard-link-less path; refusing to start is worse.
			if renameErr := os.Rename(tmpName, keyPath); renameErr != nil { //nolint:gosec // G304: keyPath is user-configured via --audit-key-path; taint is intentional
				return nil, fmt.Errorf("publishing audit key file %q: %w", keyPath, renameErr)
			}
			syncDir(dir)
			return readPublishedAuditKeys(keyPath, "after rename publish")
		}
		return nil, fmt.Errorf("publishing audit key file %q: %w", keyPath, err)
	}
	// fsync the parent directory so the new directory entry is durable: link(2)/
	// rename(2) only updates the directory inode in cache, so a power loss before the
	// next flush can leave the key absent on restart, rendering every prior record
	// unverifiable.
	syncDir(dir)
	return [][]byte{key}, nil
}

// syncDir fsyncs a directory so a just-published directory entry (from link or
// rename) survives a crash. Best-effort: a directory that cannot be opened or
// synced (some filesystems reject directory fsync) is logged and tolerated
// rather than failing audit-key creation — the durability gap it closes is a
// crash-recovery edge case, not a normal-operation correctness issue.
func syncDir(dir string) {
	d, err := os.Open(dir) //nolint:gosec // G304: dir derives from the user-configured key path
	if err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: cannot open audit key dir %q to fsync: %v\n", dir, err)
		return
	}
	if err := d.Sync(); err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: cannot fsync audit key dir %q: %v\n", dir, err)
	}
	_ = d.Close()
}

// osLink is a seam over os.Link so a test can force the no-hard-link fallback
// (filesystems that reject link(2) cannot be conjured in a unit test). Production
// always uses os.Link.
var osLink = os.Link

// isNoHardlinkErr (in audit_hardlink_posix.go / audit_hardlink_other.go) reports
// whether an os.Link error indicates the filesystem does not support hard links, so
// the right move is to fall back to an atomic rename. Its body is build-tagged: the
// syscall errnos it classifies (ENOSYS, EXDEV) are undefined on non-unix/non-windows
// targets (e.g. plan9), so referencing them in this shared file would break the
// cross-platform build.

// readPublishedAuditKeys re-reads keyPath after another writer may have published
// it — a lost create race, or our own rename fallback — and returns the parsed
// keys on disk so every process converges on the single persisted key rather than
// its own in-memory copy. phase labels the call site in any error.
func readPublishedAuditKeys(keyPath, phase string) ([][]byte, error) {
	data, readErr := os.ReadFile(keyPath) //nolint:gosec // G304: path is user-configured audit key location
	if readErr != nil {
		return nil, fmt.Errorf("reading audit key file %q %s: %w", keyPath, phase, readErr)
	}
	keys, parseErr := parseAuditKeys(data)
	if parseErr != nil {
		return nil, fmt.Errorf("audit key file %q: %w", keyPath, parseErr)
	}
	return keys, nil
}

// parseAuditKeys decodes the key file into one or more 32-byte keys, in file
// order. Blank and '#' lines are skipped. Every remaining line must decode to
// exactly 32 bytes of hex; any deviation, or no key lines, is an error so a corrupt
// file fails closed instead of being treated as keyless.
func parseAuditKeys(data []byte) ([][]byte, error) {
	var keys [][]byte
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key := make([]byte, hex.DecodedLen(len(line)))
		n, hexErr := hex.Decode(key, []byte(line))
		if hexErr != nil {
			return nil, fmt.Errorf("contains invalid hex data: %w", hexErr)
		}
		if n != 32 {
			return nil, fmt.Errorf("a key decoded to %d bytes (want 32); file may be truncated or corrupt", n)
		}
		// Reject an all-zero key: it carries no entropy, is the canonical placeholder
		// a misconfigured deployment supplies (a zeroed file, an unset secret rendered
		// as zeros), and makes the HMAC trivially forgeable. Fail closed rather than
		// silently sign a forgeable log. (Auto-generated keys from crypto/rand never
		// produce this; externally-supplied keys reach here via --audit-key-path /
		// EUNOX_AUDIT_KEY_PATH.)
		if isAllZeroKey(key[:n]) {
			return nil, fmt.Errorf("a key is all-zero (32 zero bytes), which is not a valid HMAC key; supply key material with sufficient entropy (e.g. `openssl rand -hex 32`)")
		}
		keys = append(keys, key[:n])
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("contains no key lines")
	}
	return keys, nil
}

// isAllZeroKey reports whether key is entirely zero bytes (rejected by
// parseAuditKeys as the canonical no-entropy placeholder).
func isAllZeroKey(key []byte) bool {
	for _, b := range key {
		if b != 0 {
			return false
		}
	}
	return true
}

// expandHome expands a leading "~/" or a bare "~" in p to the user's home
// directory, via config.ExpandHome (the shared implementation internal/transport
// also calls, so the two packages cannot silently re-diverge on "~" expansion).
// When home cannot be resolved (HOME unset, a container UID with no /etc/passwd
// entry, DynamicUser=yes) it returns an error rather than the literal "~" string:
// otherwise Open would MkdirAll a directory named "~" under the CWD and silently
// write the audit log there. Fail closed instead.
func expandHome(p string) (string, error) {
	return config.ExpandHome(p)
}

// ResolveLogPath returns the effective audit-log path: pref when non-empty, else
// the built-in default, expanded via expandHome. As the sole consumer of
// defaultAuditLog, it makes Open and the subcommands resolve "~" identically.
func ResolveLogPath(pref string) (string, error) {
	if pref == "" {
		pref = defaultAuditLog
	}
	return expandHome(pref)
}

// ResolveKeyPath returns the effective HMAC key path: pref when non-empty, else
// EUNOX_AUDIT_KEY_PATH, else the built-in default, expanded. Single-sources the
// env-var precedence across the proxy and subcommands.
func ResolveKeyPath(pref string) (string, error) {
	if pref == "" {
		if env := os.Getenv("EUNOX_AUDIT_KEY_PATH"); env != "" {
			pref = env
		} else {
			pref = defaultAuditKeyPath
		}
	}
	return expandHome(pref)
}
