// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

// Additional coverage for the unix advisory-lock helpers (lock_unix.go):
// acquire/release round-trips, the already-held EWOULDBLOCK error path, and
// releaseAuditLock's nil and non-nil branches.

package audit

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestAcquireReleaseAuditLock_RoundTrip covers acquireAuditLock's success path
// and releaseAuditLock's non-nil branch: the first acquire succeeds, releasing it
// returns no error, and re-acquiring after release succeeds (the lock was truly
// freed).
func TestAcquireReleaseAuditLock_RoundTrip(t *testing.T) {
	t.Parallel()
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	lf, err := acquireAuditLock(logPath)
	if err != nil {
		t.Fatalf("acquireAuditLock: %v", err)
	}
	if lf == nil {
		t.Fatal("acquireAuditLock returned a nil file on success")
	}
	// The sidecar lock file is a hidden dotfile next to the log so it stays out of
	// the rotation glob.
	wantLock := filepath.Join(filepath.Dir(logPath), "."+filepath.Base(logPath)+".lock")
	if lf.Name() != wantLock {
		t.Fatalf("lock file = %q, want %q", lf.Name(), wantLock)
	}

	if err := releaseAuditLock(lf); err != nil {
		t.Fatalf("releaseAuditLock: %v", err)
	}

	// Re-acquire after release must succeed, proving the lock was freed.
	lf2, err := acquireAuditLock(logPath)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	if err := releaseAuditLock(lf2); err != nil {
		t.Fatalf("releaseAuditLock (second): %v", err)
	}
}

// TestAcquireAuditLock_AlreadyHeld covers the EWOULDBLOCK branch: a second
// non-blocking acquire on a path already locked fails with a clear,
// chain-fork-refusing error rather than blocking.
func TestAcquireAuditLock_AlreadyHeld(t *testing.T) {
	t.Parallel()
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	first, err := acquireAuditLock(logPath)
	if err != nil {
		t.Fatalf("first acquireAuditLock: %v", err)
	}
	t.Cleanup(func() { _ = releaseAuditLock(first) })

	second, err := acquireAuditLock(logPath)
	if err == nil {
		_ = releaseAuditLock(second)
		t.Fatal("second acquireAuditLock on a held path must fail (non-blocking)")
	}
	if !strings.Contains(err.Error(), "already being written") {
		t.Fatalf("error = %v, want the already-being-written message", err)
	}
}

// TestReleaseAuditLock_Nil covers releaseAuditLock's nil branch: releasing a nil
// lock file is a no-op returning no error (the path taken when acquire never
// produced a file).
func TestReleaseAuditLock_Nil(t *testing.T) {
	t.Parallel()
	if err := releaseAuditLock(nil); err != nil {
		t.Fatalf("releaseAuditLock(nil) = %v, want nil", err)
	}
}

// TestGenerateAndPersistAuditKey_RenameFallbackError covers the rename-error
// branch inside generateAndPersistAuditKey's no-hard-link fallback: osLink reports
// EPERM (forcing the rename fallback), and the rename then fails because keyPath is
// an existing non-empty directory (rename onto it fails). The error must propagate
// as a publish failure. Lives in the unix-tagged file because it names
// syscall.EPERM.
func TestGenerateAndPersistAuditKey_RenameFallbackError(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")
	// Make keyPath a non-empty directory so os.Rename(tmp, keyPath) fails.
	if err := os.Mkdir(keyPath, 0o700); err != nil {
		t.Fatalf("mkdir keyPath dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyPath, "occupied"), []byte("x"), 0o600); err != nil {
		t.Fatalf("populate keyPath dir: %v", err)
	}

	orig := osLink
	t.Cleanup(func() { osLink = orig })
	osLink = func(string, string) error { return syscall.EPERM } // force the rename fallback

	if _, err := generateAndPersistAuditKey(keyPath); err == nil {
		t.Fatal("rename onto a non-empty directory must fail and propagate")
	} else if !strings.Contains(err.Error(), "publishing audit key file") {
		t.Fatalf("error = %v, want a 'publishing audit key file' wrap", err)
	}
}

// TestOpen_ChainResumeReadError covers Open's chain-resume read-error branch
// (FM): the base log is non-empty but unreadable (write-only mode), so
// readLastAuditLine returns an I/O error. Open must not silently reset to genesis;
// it warns, writes an in-band chain_resume_failed integrity marker, and restarts
// the chain. The append open (O_WRONLY) still succeeds on a 0200 file, so this
// isolates the read-tail failure. Unix-only and skipped under root (mode bits are
// bypassed there).
func TestOpen_ChainResumeReadError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses file permission bits")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// A non-empty, write-only log: OpenFile(O_APPEND|O_WRONLY) succeeds, but the
	// read-mode os.Open inside readLastAuditLine fails with EACCES (a non-IsNotExist
	// error), driving the chain-resume-failed path.
	if err := os.WriteFile(logPath, []byte(`{"seq":5,"_hmac":"sha256:abc"}`+"\n"), 0o200); err != nil {
		t.Fatalf("write write-only log: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(logPath, 0o600) })

	old := os.Stderr
	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatalf("pipe: %v", perr)
	}
	os.Stderr = w

	sink, err := Open(logPath, keyPath, 0, 0)

	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("Open must succeed (audit-failure tradeoff), got %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	if !strings.Contains(buf.String(), "could not read audit log tail") {
		t.Fatalf("expected a chain-resume read-failure warning, got: %q", buf.String())
	}
	// The chain restarted from genesis and the in-band marker is the first record,
	// so it must NOT have adopted the unreadable tail's seq (5).
	if sink.seq == 5 {
		t.Fatal("Open adopted the unreadable tail's seq; chain must restart from genesis")
	}
}
