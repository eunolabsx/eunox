// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestOpen_TightensPreexistingLooseLogMode pins that opening an audit log that
// already exists with a group/world-readable mode drops the group/world bits on
// startup. O_CREATE applies the restrictive mode only when it creates the file, so
// a log left readable by a looser umask, a restore, or a deliberately pre-created
// path would otherwise keep leaking the signed audit tape to other local users.
func TestOpen_TightensPreexistingLooseLogMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file-mode bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// Pre-create a world/group-readable log, then chmod to defeat the umask so the
	// on-disk mode is deterministically loose before Open runs.
	if err := os.WriteFile(logPath, []byte(""), 0o600); err != nil {
		t.Fatalf("seed log: %v", err)
	}
	if err := os.Chmod(logPath, 0o644); err != nil {
		t.Fatalf("loosen log mode: %v", err)
	}

	s, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat log: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("audit log mode after Open = %#o, want 0600", got)
	}
}

// TestOpen_WriteOnlyLog_NotLoosened locks the documented invariant that the mode
// tighten clears only group/world bits and never adds owner bits: an operator's
// deliberately owner-write-only (0200) log is left untouched so its tail read
// still fails closed into the chain-resume-failed path rather than being silently
// made readable. (No permission dependency on the test user, so it runs as root
// too — a 0200 file has no group/world bits for the tighten to clear.)
func TestOpen_WriteOnlyLog_NotLoosened(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file-mode bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	if err := os.WriteFile(logPath, []byte(`{"seq":5,"_hmac":"sha256:abc"}`+"\n"), 0o600); err != nil {
		t.Fatalf("seed log: %v", err)
	}
	if err := os.Chmod(logPath, 0o200); err != nil {
		t.Fatalf("set write-only mode: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(logPath, 0o600) }) // so t.TempDir cleanup can remove it

	s, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open must succeed (audit-failure tradeoff): %v", err)
	}
	defer func() { _ = s.Close() }()

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat log: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o200 {
		t.Errorf("write-only audit log mode after Open = %#o, want 0200 (owner bits must be preserved, not loosened)", got)
	}
}

// TestLoadOrCreateKeys_TightensPreexistingLooseKeyMode pins that loading a
// pre-existing HMAC key file with a loose mode drops its group/world bits, emits a
// SECURITY warning (a loose key is a possible prior-exposure signal worth
// rotating), and — deliberately — leaves the key *directory* mode alone (a 0600
// key is unreadable regardless of directory mode, and re-tightening a shared
// secret mount would be collateral damage).
func TestLoadOrCreateKeys_TightensPreexistingLooseKeyMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file-mode bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")

	// A valid key file: one 64-hex-char (32-byte) key per LoadOrCreateKeys' format.
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("loosen key mode: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("loosen key dir mode: %v", err)
	}

	old := os.Stderr
	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatalf("pipe: %v", perr)
	}
	os.Stderr = w

	keys, err := LoadOrCreateKeys(keyPath)

	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("LoadOrCreateKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("loaded %d keys, want 1", len(keys))
	}

	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if got := keyInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("audit key file mode after load = %#o, want 0600", got)
	}
	// The directory is deliberately left as the operator set it.
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat key dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o755 {
		t.Errorf("audit key directory mode after load = %#o, want 0755 (directory must NOT be re-tightened)", got)
	}
	// A loose-key tighten is a possible-exposure signal and must be surfaced loudly.
	if out := buf.String(); !strings.Contains(out, "SECURITY") || !strings.Contains(out, "rotat") {
		t.Errorf("expected a SECURITY warning recommending rotation on the loose-key tighten, got: %q", out)
	}
}

// TestRotate_NewActiveLogIsRestrictiveMode pins that the active log a rotation
// opens carries no group/world access, matching the startup open.
func TestRotate_NewActiveLogIsRestrictiveMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file-mode bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// rotateSizeBytes=1 forces a rotation on the first record so the post-rotation
	// active log is the file under test.
	s, err := Open(logPath, keyPath, 1, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.RecordAllow(context.Background(), "sess", "tool", "tools/call", nil, nil, false, nil, nil)
	s.RecordAllow(context.Background(), "sess", "tool", "tools/call", nil, nil, false, nil, nil)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat rotated active log: %v", err)
	}
	if got := info.Mode().Perm(); got&0o077 != 0 {
		t.Errorf("post-rotation active log mode = %#o, want no group/world access", got)
	}
}
