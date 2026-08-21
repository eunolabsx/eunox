// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Regression suite for the rotation-races-the-verify hazard: VerifyLogFiles opens the
// chain LAZILY by name, base last, so a rotate() landing inside a long pass re-points the
// base after every sibling is already verified. ChainSnapshot brackets the pass; these
// tests pin what it must and must not call a race.

package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rotateChainInPlace simulates the rename-then-reopen half of rotate() without a live
// Sink: the base becomes a genuine rotated sibling and a fresh empty base takes its name.
func rotateChainInPlace(t *testing.T, logPath string) string {
	t.Helper()
	sibling := logPath + ".00000000000000000001.20260101T000000.000000000Z"
	if err := os.Rename(logPath, sibling); err != nil {
		t.Fatalf("rename base to sibling: %v", err)
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open fresh base: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close fresh base: %v", err)
	}
	return sibling
}

// TestChainSnapshot_RotationDuringPassIsReported is the A2 regression. Verifying the
// snapshot's paths after a rotation reports a clean PASS over a base that no longer holds
// any of the records it was discovered with — every one of them is now in a sibling
// outside the snapshot, a whole file escaping the chain check and indistinguishable from
// documented trailing truncation. Only the bracket can tell the operator that.
func TestChainSnapshot_RotationDuringPassIsReported(t *testing.T) {
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b", "c")

	snap, err := SnapshotLogChain(logPath)
	if err != nil {
		t.Fatalf("SnapshotLogChain: %v", err)
	}
	if len(snap.Files) != 1 {
		t.Fatalf("a never-rotated log is one file; got %v", snap.Files)
	}

	rotateChainInPlace(t, logPath)

	// The verdict the pass would report on its own: vacuously clean.
	res, err := VerifyLogFiles(snap.Files, verifierFor(t, keyPath), "", time.Time{}, &strings.Builder{})
	if err != nil {
		t.Fatalf("VerifyLogFiles: %v", err)
	}
	if !res.OK() || res.Total != 0 {
		t.Fatalf("expected the raced pass to look clean-but-empty; got OK=%v total=%d", res.OK(), res.Total)
	}

	err = snap.CheckUnchanged()
	if !errors.Is(err, ErrChainRotated) {
		t.Fatalf("CheckUnchanged after a rotation must report ErrChainRotated; got %v", err)
	}
}

// TestChainSnapshot_EqualFileCountStillNamesWhatMoved is the message regression: at the
// retention cap a rotation publishes one sibling and prunes another, so the chain holds
// the same NUMBER of files before and after. A report phrased in counts renders as "3
// file(s) when the pass started and 3 now" while asserting a rotation — the names are the
// only thing that carries the change.
func TestChainSnapshot_EqualFileCountStillNamesWhatMoved(t *testing.T) {
	dir := t.TempDir()
	logPath, _ := writeChainLog(t, dir, "a")

	oldest := logPath + ".00000000000000000001.20260101T000000.000000000Z"
	if err := os.WriteFile(oldest, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write oldest sibling: %v", err)
	}

	snap, err := SnapshotLogChain(logPath)
	if err != nil {
		t.Fatalf("SnapshotLogChain: %v", err)
	}
	if len(snap.Files) != 2 {
		t.Fatalf("expected sibling + base; got %v", snap.Files)
	}

	// A rotation at retain=1: the base becomes a new sibling, the oldest is pruned, and a
	// fresh base opens — two files before, two after.
	newest := logPath + ".00000000000000000002.20260101T000001.000000000Z"
	if err := os.Rename(logPath, newest); err != nil {
		t.Fatalf("rotate base: %v", err)
	}
	if err := os.Remove(oldest); err != nil {
		t.Fatalf("prune oldest: %v", err)
	}
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatalf("open fresh base: %v", err)
	}

	err = snap.CheckUnchanged()
	if !errors.Is(err, ErrChainRotated) {
		t.Fatalf("an equal-count rotation must still report ErrChainRotated; got %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"gained", filepath.Base(newest), "lost", filepath.Base(oldest)} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the report must name what moved; %q is missing %q", msg, want)
		}
	}
}

// TestChainSnapshot_BaseReplacedInPlaceIsReported covers the half the file-set comparison
// cannot see: a base swapped for a different file under the SAME name leaves the chain
// listing byte-identical, so only the directory entry's identity carries the change.
func TestChainSnapshot_BaseReplacedInPlaceIsReported(t *testing.T) {
	dir := t.TempDir()
	logPath, _ := writeChainLog(t, dir, "a")

	snap, err := SnapshotLogChain(logPath)
	if err != nil {
		t.Fatalf("SnapshotLogChain: %v", err)
	}

	replacement := logPath + ".replacement"
	if err := os.WriteFile(replacement, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	if err := os.Rename(replacement, logPath); err != nil {
		t.Fatalf("swap in replacement: %v", err)
	}

	if err := snap.CheckUnchanged(); !errors.Is(err, ErrChainRotated) {
		t.Fatalf("a base replaced in place must report ErrChainRotated; got %v", err)
	}
}

// TestChainSnapshot_AppendedRecordsAreNotARace pins the other direction: audit-verify runs
// against a LIVE proxy under traffic by design, so ordinary appends must not turn every
// pass inconclusive — the pass certified a prefix, which is all a verifier reading a live
// log ever can.
func TestChainSnapshot_AppendedRecordsAreNotARace(t *testing.T) {
	dir := t.TempDir()
	logPath, _ := writeChainLog(t, dir, "a")

	snap, err := SnapshotLogChain(logPath)
	if err != nil {
		t.Fatalf("SnapshotLogChain: %v", err)
	}

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	if _, err := f.WriteString("{\"seq\":99}\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if err := snap.CheckUnchanged(); err != nil {
		t.Fatalf("appended records must not be reported as a race; got %v", err)
	}
}

// TestChainSnapshot_BaseAppearingOrVanishingIsReported pins that "absent" is an identity
// of its own: a base created during the pass (the just-rotated window LogChainFiles omits
// the base for) and one removed during it are both changes, whichever half of the bracket
// sees it — a nil FileInfo must never read as "same".
func TestChainSnapshot_BaseAppearingOrVanishingIsReported(t *testing.T) {
	t.Run("appears", func(t *testing.T) {
		dir := t.TempDir()
		logPath, _ := writeChainLog(t, dir, "a")
		rotateChainInPlace(t, logPath)
		if err := os.Remove(logPath); err != nil {
			t.Fatalf("remove base: %v", err)
		}

		snap, err := SnapshotLogChain(logPath)
		if err != nil {
			t.Fatalf("SnapshotLogChain: %v", err)
		}
		if err := os.WriteFile(logPath, nil, 0o600); err != nil {
			t.Fatalf("recreate base: %v", err)
		}
		if err := snap.CheckUnchanged(); !errors.Is(err, ErrChainRotated) {
			t.Fatalf("a base that appeared during the pass must report ErrChainRotated; got %v", err)
		}
	})

	t.Run("vanishes", func(t *testing.T) {
		dir := t.TempDir()
		logPath, _ := writeChainLog(t, dir, "a")
		snap, err := SnapshotLogChain(logPath)
		if err != nil {
			t.Fatalf("SnapshotLogChain: %v", err)
		}
		if err := os.Remove(logPath); err != nil {
			t.Fatalf("remove base: %v", err)
		}
		if err := snap.CheckUnchanged(); !errors.Is(err, ErrChainRotated) {
			t.Fatalf("a base that vanished during the pass must report ErrChainRotated; got %v", err)
		}
	})
}
