// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Rotation durability: the directory-entry fsyncs that keep a rotation from being
// silently rolled back by a crash.

package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// recordSyncDirs swaps in a counting stand-in for the syncDir seam and returns a
// func yielding the (dir, subject) pairs it saw. Restores the real one at test end.
func recordSyncDirs(t *testing.T) func() [][2]string {
	t.Helper()
	var calls [][2]string
	prev := syncDirFn
	syncDirFn = func(dir, subject string) {
		calls = append(calls, [2]string{dir, subject})
		prev(dir, subject)
	}
	t.Cleanup(func() { syncDirFn = prev })
	return func() [][2]string { return calls }
}

// TestRotate_FsyncsLogDirectoryOnRenameAndFreshBase pins the durability half of
// rotation. rotateAttempt fsyncs the rotated file's DATA, but rename(2) and the fresh
// base's creation only dirty the parent directory inode: a power loss before that inode
// is written back replays the directory to its pre-rotation state, so the records the
// fresh base already fsynced sit in blocks nothing references. Restart then resumes
// cleanly from the old tail and audit-verify PASSES over a log that silently lost every
// post-rotation record — no attacker required. Both directory entries must be made
// durable, in that order: the rename before the data sync it precedes, the fresh base
// once it is open.
func TestRotate_FsyncsLogDirectoryOnRenameAndFreshBase(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.WriteString("seed record\n"); err != nil {
		t.Fatalf("seed log: %v", err)
	}

	seen := recordSyncDirs(t)
	s := &Sink{
		logPath:    logPath,
		activePath: logPath,
		maxBytes:   16,
		retain:     3,
		f:          f,
		written:    64, // over maxBytes: the next rotate() rotates for real
		now:        func() time.Time { return time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC) },
	}

	s.rotate()

	if s.activePath != logPath || s.f == f {
		t.Fatalf("expected a clean rotation onto a fresh base; activePath=%q swapped=%v", s.activePath, s.f != f)
	}
	calls := seen()
	if len(calls) != 2 {
		t.Fatalf("expected two directory fsyncs (rename, fresh base), got %d: %v", len(calls), calls)
	}
	for i, c := range calls {
		if c[0] != dir {
			t.Errorf("fsync %d targeted %q, want the log directory %q", i, c[0], dir)
		}
		if c[1] != "audit log" {
			t.Errorf("fsync %d subject = %q, want %q so the warning names the right file", i, c[1], "audit log")
		}
	}
}

// A rotation that never renames must not fsync anything: an empty base is a no-op, and a
// directory fsync per record-sized trigger would be pure I/O on the hot path.
func TestRotate_EmptyBaseDoesNotFsyncDirectory(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	seen := recordSyncDirs(t)
	s := &Sink{
		logPath:    logPath,
		activePath: logPath,
		maxBytes:   16,
		retain:     3,
		f:          f,
		written:    0, // fresh base: rotate() is a no-op
		now:        func() time.Time { return time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC) },
	}

	s.rotate()

	if calls := seen(); len(calls) != 0 {
		t.Fatalf("an empty-base rotation must not fsync the directory, got %v", calls)
	}
}
