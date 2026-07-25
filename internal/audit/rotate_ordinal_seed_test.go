// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRotatedSibling creates a rotated sibling of logPath carrying the given ordinal, in
// the "<logPath>.<020d ordinal>.<timestamp>Z" scheme rotatedAuditRe accepts.
func writeRotatedSibling(t *testing.T, logPath string, ordinal uint64, stamp string) string {
	t.Helper()
	name := fmt.Sprintf("%s.%020d.%s", logPath, ordinal, stamp)
	if err := os.WriteFile(name, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("writing rotated sibling: %v", err)
	}
	return name
}

// TestRotatedPath_OrdinalUncertainReadableDir_ResumesAboveHighestSibling is the other half
// of the stale-low-ordinal regression. Its sibling test covers the case where the sibling
// directory is STILL unreadable and the rotation must defer; this covers the recovery
// case, where the fault that set the flag has cleared.
//
// When Open could not scan the siblings it sets ordinalSeedUncertain and leaves
// rotateOrdinal at 0. If the directory is readable by the time a rotation happens,
// rotatedPath must re-derive the seed and stamp ABOVE the highest sibling already on disk.
// Stamping 1 instead would sort the newest file BEFORE the existing ones, so pruneRotated
// would delete the newest first and LogChainFiles would feed verify out of order — a
// spurious CHAIN BREAK. Only the comment guaranteed this before.
func TestRotatedPath_OrdinalUncertainReadableDir_ResumesAboveHighestSibling(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	// Siblings out of ordinal order on purpose: the seed must come from the HIGHEST
	// ordinal present, not the last one written or the lexically last name.
	writeRotatedSibling(t, logPath, 7, "20260101T000000.000000000Z")
	writeRotatedSibling(t, logPath, 42, "20260102T000000.000000000Z")
	writeRotatedSibling(t, logPath, 13, "20260103T000000.000000000Z")

	s := &Sink{logPath: logPath, ordinalSeedUncertain: true}
	got, err := s.rotatedPath()
	if err != nil {
		t.Fatalf("rotatedPath() = %v, want a path (the sibling dir is readable, so the seed can be re-derived)", err)
	}

	const wantOrdinal = 43 // highest sibling (42) + 1
	if s.rotateOrdinal != wantOrdinal {
		t.Errorf("rotateOrdinal = %d, want %d (highest sibling + 1)", s.rotateOrdinal, wantOrdinal)
	}
	if want := fmt.Sprintf(".%020d.", wantOrdinal); !strings.Contains(got, want) {
		t.Errorf("rotatedPath() = %q, want it to carry the zero-padded ordinal %q", got, want)
	}
	// The flag must clear once the seed is re-derived, so later rotations skip the rescan.
	if s.ordinalSeedUncertain {
		t.Error("ordinalSeedUncertain must clear once the seed has been re-derived")
	}

	// The re-derived ordinal must keep advancing normally on the next rotation rather
	// than rescanning and re-deriving the same value.
	next, err := s.rotatedPath()
	if err != nil {
		t.Fatalf("second rotatedPath() = %v, want a path", err)
	}
	if s.rotateOrdinal != wantOrdinal+1 {
		t.Errorf("after a second rotation rotateOrdinal = %d, want %d", s.rotateOrdinal, wantOrdinal+1)
	}
	if next == got {
		t.Error("two rotations produced the same path")
	}
}

// TestRotatedPath_OrdinalUncertainNeverLowersOrdinal pins the "only raise the counter"
// rule: if rotations already advanced rotateOrdinal past every sibling on disk,
// re-deriving the seed must not pull it back down and start reusing stamps.
func TestRotatedPath_OrdinalUncertainNeverLowersOrdinal(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	writeRotatedSibling(t, logPath, 3, "20260101T000000.000000000Z")

	// In-memory counter is already well above the highest sibling.
	s := &Sink{logPath: logPath, ordinalSeedUncertain: true, rotateOrdinal: 100}
	if _, err := s.rotatedPath(); err != nil {
		t.Fatalf("rotatedPath() = %v, want a path", err)
	}
	if s.rotateOrdinal != 101 {
		t.Errorf("rotateOrdinal = %d, want 101 — a lower on-disk seed must not lower the counter", s.rotateOrdinal)
	}
}

// TestRotatedPath_OrdinalCertainSkipsReseed pins that the reseed is gated on the flag: a
// sink whose seed is already trusted must not consult the directory at all, so a
// high-ordinal sibling appearing underneath it cannot jump the counter.
func TestRotatedPath_OrdinalCertainSkipsReseed(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	writeRotatedSibling(t, logPath, 500, "20260101T000000.000000000Z")

	s := &Sink{logPath: logPath, ordinalSeedUncertain: false, rotateOrdinal: 2}
	if _, err := s.rotatedPath(); err != nil {
		t.Fatalf("rotatedPath() = %v, want a path", err)
	}
	if s.rotateOrdinal != 3 {
		t.Errorf("rotateOrdinal = %d, want 3 — a trusted seed must not be re-derived from disk", s.rotateOrdinal)
	}
}
