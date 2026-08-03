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
	"io"
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
// file, preserving owner bits (the successful open proves owner read). Unlike
// the log, a key found group/world-accessible is a possible prior-exposure signal
// (anyone who could read it may have copied it and can forge verifiable records),
// so the loose->tight transition is surfaced as a SECURITY warning recommending
// rotation rather than fixed silently. Best-effort (see tightenLogMode).
//
// It works through the OPEN HANDLE (f.Stat/f.Chmod), not the path. A path-based
// stat+chmod pair is two fresh resolutions of an operator-supplied path: it follows a
// symlink, so it re-modes the link's TARGET, and it re-resolves between the two calls, so
// a path swapped in that window is chmod'd instead of the file just read. Dropping o+r
// from an arbitrary file a symlink points at is a local denial-of-service primitive that
// has nothing to do with the audit key. The handle names the exact inode readAuditKeyFile
// admitted, so neither is reachable.
func tightenKeyFileMode(f *os.File, keyPath string) {
	info, err := f.Stat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: could not stat audit key file %q to tighten its mode: %v\n", keyPath, err)
		return
	}
	perm := info.Mode().Perm()
	if perm&0o077 == 0 {
		return
	}
	if cerr := f.Chmod(perm &^ 0o077); cerr != nil { //nolint:gosec // G302: clearing group/world bits is the intended restriction
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

	// Drop any group/world access from a pre-existing key file: a readable HMAC key lets
	// any local user forge records. Freshly generated keys are written 0600, so this only
	// affects keys created outside that path. readAuditKeyFile tightens through the open
	// handle and warns, since a loose key is a possible prior-exposure signal.
	data, err := readAuditKeyFile(keyPath, true)
	if err == nil {
		keys, parseErr := parseAuditKeys(data)
		if parseErr != nil {
			return nil, fmt.Errorf("audit key file %q: %w", keyPath, parseErr)
		}
		return keys, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
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
//
// Read-only means read-only: it does NOT tighten the key file's mode. A plain
// `eunox audit-verify` chmod-ing a group-readable key to 0600 breaks the next read by a
// separate monitoring or verification user — an operator-visible side effect of a
// command that only reads. The proxy still tightens on its own path (LoadOrCreateKeys),
// which is where the file's permissions are that process's business.
func LoadKeys(keyPath string) ([][]byte, error) {
	data, err := readAuditKeyFile(keyPath, false)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("audit key file %q not found — pass --audit-key-path pointing at the key that signed this log", keyPath)
		}
		return nil, err
	}
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
			syncDir(dir, "audit key")
			return readPublishedAuditKeys(keyPath, "after rename publish")
		}
		return nil, fmt.Errorf("publishing audit key file %q: %w", keyPath, err)
	}
	// fsync the parent directory so the new directory entry is durable: link(2)/
	// rename(2) only updates the directory inode in cache, so a power loss before the
	// next flush can leave the key absent on restart, rendering every prior record
	// unverifiable.
	syncDir(dir, "audit key")
	return [][]byte{key}, nil
}

// syncDir fsyncs a directory so a just-published directory entry (from link, rename, or
// create) survives a crash. subject names what the directory holds, for the warning
// ("audit key", "audit log") — both the key publish and log rotation depend on it, and a
// warning that named only the key would misdirect an operator debugging a lost rotation.
//
// Best-effort: a directory that cannot be opened or synced (some filesystems reject
// directory fsync) is logged and tolerated rather than failing the operation — the
// durability gap it closes is a crash-recovery edge case, not a normal-operation
// correctness issue.
func syncDir(dir, subject string) {
	d, err := os.Open(dir) //nolint:gosec // G304: dir derives from the user-configured key/log path
	if err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: cannot open %s dir %q to fsync: %v\n", subject, dir, err)
		return
	}
	if err := d.Sync(); err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: cannot fsync %s dir %q: %v\n", subject, dir, err)
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

// EnvAuditKeyAllowSymlink opts the HMAC key file out of the symlink refusal below, for the
// one deployment shape where a symlinked key is normal rather than an attack: a
// Kubernetes-style projected secret mount, which materializes each key as a symlink into a
// timestamped ..data directory so the whole set can be swapped atomically. Set it to 1/
// true/yes when the key comes from such a mount.
//
// It is a deliberate downgrade with a narrow blast radius, not a general escape hatch. The
// non-regular-file refusal still applies to the RESOLVED file (checked through the open
// handle, so no re-resolution race), which keeps a FIFO or device out; what it gives up is
// the guarantee that the final path component was not redirected. Prefer mounting the
// secret's ..data directory directly, or copying the key to a regular file at startup, and
// keep this unset.
const EnvAuditKeyAllowSymlink = "EUNOX_AUDIT_KEY_ALLOW_SYMLINK"

// maxAuditKeyFileBytes bounds a key-file read. The format is one 64-hex-char key per line,
// so even a long rotation history is a few kilobytes; 1 MiB is orders of magnitude of
// headroom while still refusing to buffer a file that is not a key file at all.
const maxAuditKeyFileBytes = 1 << 20

// auditKeySymlinkAllowed reports whether EnvAuditKeyAllowSymlink opts this process out of
// the key-file symlink refusal (see the const doc).
func auditKeySymlinkAllowed() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvAuditKeyAllowSymlink))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// readAuditKeyFile reads the HMAC key file under the same symlink guard every other audit
// file already uses, optionally tightening its mode through the open handle.
//
// The key is the one audit file whose redirection is unrecoverable: the log is
// HMAC-protected, so redirecting it is detectable, but whoever chooses the KEY chooses
// what verifies — a key read through an attacker-planted symlink signs a tape the attacker
// can forge at will, and audit-verify confirms it. Every other file in this package (the
// log open, both rotation reopens, the tail read, even the never-written lock file) pairs
// config.RefuseNonRegularPath with config.OpenNoFollow; this one was read with a plain
// os.ReadFile, which follows symlinks. The guard is applied here, once, for all three
// readers rather than at each call site.
//
// A genuinely absent file is returned as an os.IsNotExist error so LoadOrCreateKeys can
// still mint a key; the caller distinguishes the two.
func readAuditKeyFile(keyPath string, tighten bool) ([]byte, error) {
	allowSymlink := auditKeySymlinkAllowed()
	flags := os.O_RDONLY
	if !allowSymlink {
		// Lstat first for the actionable error (it names the path and the opt-out); the
		// O_NOFOLLOW below closes the Lstat->open window the check itself cannot.
		if err := config.RefuseNonRegularPath(keyPath, "audit key file"); err != nil {
			return nil, fmt.Errorf("%w — if this key comes from a projected secret mount that publishes it as a symlink, set %s=1 to accept it", err, EnvAuditKeyAllowSymlink)
		}
		flags |= config.OpenNoFollow
	}
	f, err := os.OpenFile(keyPath, flags, 0) //nolint:gosec // G304: path is user-configured audit key location (--audit-key-path or EUNOX_AUDIT_KEY_PATH)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err // the caller decides whether absence is fatal or a create trigger
		}
		return nil, fmt.Errorf("reading audit key file %q: %w", keyPath, err)
	}
	defer func() { _ = f.Close() }()

	// Re-check regularity through the HANDLE. On the opt-out path this is the only
	// non-regular guard left (a symlink to a FIFO would otherwise block the read here
	// forever, wedging startup); on the default path it is a cheap confirmation that the
	// inode opened is the kind Lstat saw.
	info, statErr := f.Stat()
	if statErr != nil {
		return nil, fmt.Errorf("stat audit key file %q: %w", keyPath, statErr)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing audit key file %q: it resolves to a non-regular file (mode %v); the HMAC key must be a regular file", keyPath, info.Mode())
	}
	if tighten {
		tightenKeyFileMode(f, keyPath)
	}

	data, readErr := io.ReadAll(io.LimitReader(f, maxAuditKeyFileBytes+1))
	if readErr != nil {
		return nil, fmt.Errorf("reading audit key file %q: %w", keyPath, readErr)
	}
	if len(data) > maxAuditKeyFileBytes {
		return nil, fmt.Errorf("audit key file %q exceeds %d bytes; that is not a key file (one 64-hex-char key per line)", keyPath, maxAuditKeyFileBytes)
	}
	return data, nil
}

// readPublishedAuditKeys re-reads keyPath after another writer may have published
// it — a lost create race, or our own rename fallback — and returns the parsed
// keys on disk so every process converges on the single persisted key rather than
// its own in-memory copy. phase labels the call site in any error. No mode
// tightening: the file was just written 0600 by whichever starter won.
func readPublishedAuditKeys(keyPath, phase string) ([][]byte, error) {
	data, readErr := readAuditKeyFile(keyPath, false)
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

// ResolveLogPath returns the effective audit-log path: pref when non-empty, else
// the built-in default, expanded via config.ExpandHome. As the sole consumer of
// defaultAuditLog, it makes Open and the subcommands resolve "~" identically.
//
// ExpandHome fails closed when home cannot be resolved (HOME unset, a container
// UID with no /etc/passwd entry, DynamicUser=yes) rather than returning the
// literal "~" string: otherwise Open would MkdirAll a directory named "~" under
// the CWD and silently write the tamper-evident log there.
func ResolveLogPath(pref string) (string, error) {
	if pref == "" {
		pref = defaultAuditLog
	}
	return config.ExpandHome(pref)
}

// ResolveKeyPath returns the effective HMAC key path: pref when non-empty, else
// EUNOX_AUDIT_KEY_PATH, else the built-in default, expanded (fail-closed, as in
// ResolveLogPath). Single-sources the env-var precedence across the proxy and
// subcommands.
func ResolveKeyPath(pref string) (string, error) {
	if pref == "" {
		if env := os.Getenv("EUNOX_AUDIT_KEY_PATH"); env != "" {
			pref = env
		} else {
			pref = defaultAuditKeyPath
		}
	}
	return config.ExpandHome(pref)
}
