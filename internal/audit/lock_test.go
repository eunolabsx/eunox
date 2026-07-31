// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestAuditSink_SecondOpenSamePath_FailsClosed verifies that two Sinks cannot
// write the same audit log path concurrently: the second Open fails while the
// first holds the path lock, so the tamper-evident HMAC chain cannot fork into
// two independently-sequenced writers. After the first closes, a reopen succeeds
// and the resulting single-writer chain verifies.
func TestAuditSink_SecondOpenSamePath_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	s1, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}

	// A second writer against the same path must be refused while s1 holds it.
	if s2, err := Open(logPath, keyPath, 0, 0); err == nil {
		_ = s2.Close()
		t.Fatal("second Open on the same audit path must fail while the first holds the lock")
	}

	// Write through the first sink and close it, releasing the lock.
	s1.RecordAllow(context.Background(), "sess", "tool:read", "tools/call", nil, nil, false, nil, nil)
	if err := s1.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	// Reopening after the lock is released must succeed, and the resumed chain
	// must verify (a single writer never forked it).
	s3, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("reopen after Close: %v", err)
	}
	s3.RecordAllow(context.Background(), "sess", "tool:read", "tools/call", nil, nil, false, nil, nil)
	if err := s3.Close(); err != nil {
		t.Fatalf("third Close: %v", err)
	}

	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join(logLines(t, logPath), []byte("\n"))),
		verifierFor(t, keyPath), "", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if !res.OK() {
		t.Errorf("single-writer chain must verify after sequential open/close; output:\n%s\nresult: %+v", sb.String(), res)
	}
}

// TestAcquireAuditLock_RefusesSymlink pins the symlink half of the audit-path guard on
// the lock file. Nothing is ever written through this handle, so what a planted link
// would redirect is the lock's EXCLUSIVITY: flock applies to whatever the open resolved
// to, so a second instance locking a different inode would believe it holds the audit
// log and append to it — forking the tamper-evident chain the lock exists to keep single-
// writer.
func TestAcquireAuditLock_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	lockPath := filepath.Join(dir, ".audit.jsonl.lock")

	// Plant the link at the exact path acquireAuditLock derives, pointing somewhere real
	// so an unguarded open would succeed rather than fail for an unrelated reason.
	elsewhere := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(elsewhere, nil, 0o600); err != nil {
		t.Fatalf("seed link target: %v", err)
	}
	if err := os.Symlink(elsewhere, lockPath); err != nil {
		t.Skipf("cannot create symlink in this environment: %v", err)
	}

	lf, err := acquireAuditLock(logPath)
	if err == nil {
		_ = releaseAuditLock(lf)
		t.Fatal("acquireAuditLock must refuse a symlinked lock path, not lock through it")
	}
	if !strings.Contains(err.Error(), "audit lock file") {
		t.Errorf("error should name the lock file as the subject, got: %v", err)
	}
}

// TestAcquireAuditLock_RefusesNonRegular covers the half O_NOFOLLOW alone would not
// catch: a FIFO (or any other non-regular file) at the lock path is refused outright,
// because locking it transfers the single-writer guarantee to an object that is not the
// sidecar the audit log's chain depends on.
func TestAcquireAuditLock_RefusesNonRegular(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	lockPath := filepath.Join(dir, ".audit.jsonl.lock")

	if err := syscall.Mkfifo(lockPath, 0o600); err != nil {
		t.Skipf("cannot create FIFO in this environment: %v", err)
	}

	lf, err := acquireAuditLock(logPath)
	if err == nil {
		_ = releaseAuditLock(lf)
		t.Fatal("acquireAuditLock must refuse a non-regular lock path")
	}
	if !strings.Contains(err.Error(), "audit lock file") {
		t.Errorf("error should name the lock file as the subject, got: %v", err)
	}
}

// TestAcquireAuditLock_OrdinaryPathStillLocks is the regression that matters most: a
// guard that breaks legitimate locking is worse than the hole it closes. The lock file
// is still created on first use, the lock is still exclusive, and a re-acquire after
// release still succeeds.
func TestAcquireAuditLock_OrdinaryPathStillLocks(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	lockPath := filepath.Join(dir, ".audit.jsonl.lock")

	lf, err := acquireAuditLock(logPath)
	if err != nil {
		t.Fatalf("acquireAuditLock on a clean path: %v", err)
	}
	if fi, statErr := os.Lstat(lockPath); statErr != nil {
		t.Fatalf("lock file must be created on first use: %v", statErr)
	} else if !fi.Mode().IsRegular() {
		t.Errorf("lock file should be a regular file, got mode %v", fi.Mode())
	}

	// The pre-existing regular lock file must not trip the guard on a second acquire —
	// the check refuses non-regular paths, not paths that already exist.
	if second, secondErr := acquireAuditLock(logPath); secondErr == nil {
		_ = releaseAuditLock(second)
		t.Error("a second acquire must fail while the first holds the lock")
	}

	if err := releaseAuditLock(lf); err != nil {
		t.Fatalf("releaseAuditLock: %v", err)
	}
	reacquired, err := acquireAuditLock(logPath)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	if err := releaseAuditLock(reacquired); err != nil {
		t.Fatalf("releaseAuditLock (second): %v", err)
	}
}
