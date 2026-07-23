// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// White-box tests for size-triggered rotation, retention pruning, rotated-sibling
// ordering, and chain resume across rotation/corruption (rotate.go + the
// resume-from-tail path).

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRecoverWrittenSize_BothStatsFailResumeFromZero guards against spurious
// rotation on a double stat failure: when
// both the pre-open probe and the post-open Stat fail (size genuinely unknown),
// recoverWrittenSize must resume size accounting from 0, NOT seed the rotation size.
// Seeding the rotation size (== maxBytes) made the very first writeRecord exceed the
// threshold and force a spurious rotation — restarting the HMAC chain and creating an
// empty rotated sibling — even on a brand-new/empty log and on every restart under
// persistent I/O degradation.
// TestRotateBackoffWritten_NonNegative pins that the post-rotation-failure fallback
// never returns a negative s.written. With maxBytes==0 (a directly-constructed Sink
// that bypasses Open's positive floor) the old maxBytes-headroom arithmetic underflowed
// to -1, which made the size check (written+n >= maxBytes) true for every record and
// spun a per-record rotation loop. Zero or positive maxBytes must both yield >= 0.
func TestRotateBackoffWritten_NonNegative(t *testing.T) {
	t.Parallel()
	for _, maxBytes := range []int64{0, -1, 1, 9, 10, 1024, 1 << 20} {
		s := &Sink{maxBytes: maxBytes}
		if got := s.rotateBackoffWritten(); got < 0 {
			t.Errorf("rotateBackoffWritten(maxBytes=%d) = %d, want >= 0", maxBytes, got)
		}
	}
	// The zero/negative cases specifically must return 0 ("start fresh"), not -1.
	for _, maxBytes := range []int64{0, -5} {
		s := &Sink{maxBytes: maxBytes}
		if got := s.rotateBackoffWritten(); got != 0 {
			t.Errorf("rotateBackoffWritten(maxBytes=%d) = %d, want 0", maxBytes, got)
		}
	}
}

func TestRecoverWrittenSize_BothStatsFailResumeFromZero(t *testing.T) {
	t.Parallel()
	f, err := os.CreateTemp(t.TempDir(), "audit-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	// Close the handle so f.Stat() fails, and pass preSize=-1 (pre-open probe also
	// failed) so both stat paths are exhausted and the default branch runs.
	_ = f.Close()
	if got := recoverWrittenSize(f, f.Name(), -1); got != 0 {
		t.Fatalf("recoverWrittenSize with both stats failing = %d, want 0 (no forced rotation)", got)
	}
	// A successful pre-open probe is still honored (continues the counter for an
	// existing large log without force-rotating it).
	if got := recoverWrittenSize(f, f.Name(), 1234); got != 1234 {
		t.Fatalf("recoverWrittenSize with a pre-open size = %d, want 1234", got)
	}
}

// TestBoundEnvelopeField_StaysWithinCap is the regression: an over-cap
// envelope string must be truncated so the returned value — marker included — is
// at most auditEnvelopeFieldCap bytes. Previously the marker was appended past the
// cap, so the returned string was ~cap+40 bytes, violating the invariant the
// auditEnvelopeFieldCap comment relies on to bound the serialized record.
func TestBoundEnvelopeField_StaysWithinCap(t *testing.T) {
	t.Parallel()

	// Short strings pass through unchanged.
	if got := boundEnvelopeField("hello"); got != "hello" {
		t.Fatalf("short string altered: %q", got)
	}
	// A string exactly at the cap passes through unchanged.
	atCap := strings.Repeat("a", auditEnvelopeFieldCap)
	if got := boundEnvelopeField(atCap); got != atCap {
		t.Fatalf("at-cap string altered: len %d", len(got))
	}
	// An over-cap string is truncated to <= cap, marker included.
	long := strings.Repeat("a", auditEnvelopeFieldCap*2)
	got := boundEnvelopeField(long)
	if len(got) > auditEnvelopeFieldCap {
		t.Fatalf("result is %d bytes, exceeds cap %d", len(got), auditEnvelopeFieldCap)
	}
	if !strings.Contains(got, "truncated") {
		t.Fatalf("missing truncation marker in result tail: %q", got[len(got)-40:])
	}
}

// TestRotatedStampParts pins the parse of a rotated sibling's embedded rotation
// seq, timestamp base, and numeric collision suffix used by the write-order sort.
func TestRotatedStampParts(t *testing.T) {
	t.Parallel()

	logPath := "/var/log/audit.jsonl"
	ts := ".20260615T000000.000000000Z"
	tsBase := "20260615T000000.000000000Z"
	seqPfx := ".00000000000000001000"
	cases := []struct {
		name       string
		wantSeq    uint64
		wantHasSeq bool
		wantBase   string
		wantN      int
	}{
		// Current scheme: 20-digit seq prefix + timestamp (+ optional collision N).
		{logPath + seqPfx + ts, 1000, true, tsBase, 0},
		{logPath + seqPfx + ts + ".2", 1000, true, tsBase, 2},
		{logPath + seqPfx + ts + ".10", 1000, true, tsBase, 10},
		// Legacy (pre-upgrade) scheme: timestamp with no seq prefix.
		{logPath + ts, 0, false, tsBase, 0},
		{logPath + ts + ".10", 0, false, tsBase, 10},
		// Unrelated sibling: whole suffix as base, no seq, no number.
		{logPath + ".bak", 0, false, "bak", 0},
	}
	for _, c := range cases {
		gotSeq, gotHas, gotBase, gotN := rotatedStampParts(c.name, logPath)
		if gotSeq != c.wantSeq || gotHas != c.wantHasSeq || gotBase != c.wantBase || gotN != c.wantN {
			t.Errorf("rotatedStampParts(%q) = (%d, %v, %q, %d), want (%d, %v, %q, %d)",
				c.name, gotSeq, gotHas, gotBase, gotN, c.wantSeq, c.wantHasSeq, c.wantBase, c.wantN)
		}
	}
}

// TestMaxRotatedOrdinal returns the highest rotation ordinal among existing siblings,
// ignoring legacy (seq-less) names and non-rotated files. Open seeds s.rotateOrdinal
// from it so the counter stays monotonic across restarts and chain resets.
func TestMaxRotatedOrdinal(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	for _, name := range []string{
		".00000000000000000005.20260615T120000.000000000Z",   // ordinal 5
		".00000000000000000042.20260615T120001.000000000Z",   // ordinal 42 (highest)
		".00000000000000000007.20260615T120002.000000000Z.3", // ordinal 7 with collision suffix
		".20260615T120003.000000000Z",                        // legacy (no ordinal) -> contributes 0
		".bak",                                               // unrelated -> ignored
	} {
		if err := os.WriteFile(logPath+name, []byte("x\n"), 0o600); err != nil {
			t.Fatalf("WriteFile %q: %v", name, err)
		}
	}
	if got, ok := maxRotatedOrdinal(logPath); got != 42 || !ok {
		t.Fatalf("maxRotatedOrdinal = (%d, %v), want (42, true)", got, ok)
	}
	// No siblings at all -> 0, but ok=true (the directory was readable).
	if got, ok := maxRotatedOrdinal(filepath.Join(t.TempDir(), "empty.jsonl")); got != 0 || !ok {
		t.Fatalf("maxRotatedOrdinal(no siblings) = (%d, %v), want (0, true)", got, ok)
	}
}

// TestRotateOrdinal_SeededPastSiblings_SurvivesSeqReset is the genesis-restart
// regression: the rotation ordinal must be seeded from existing siblings, NOT the chain
// seq. On a detected tail corruption / HMAC mismatch the chain resets to genesis (seq
// 1), so a fresh rotation writes a LOW seq while older siblings hold high seqs. Had the
// filename ordering keyed on seq, that new file would sort as OLDEST and retention would
// delete the newest audit records. Seeding rotateOrdinal past the siblings keeps the new
// file ordered LAST regardless of the seq reset.
func TestRotateOrdinal_SeededPastSiblings_SurvivesSeqReset(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// Two pre-existing siblings with HIGH ordinals (10, 11) but unparseable bodies, so
	// Open resumes onto them, fails to parse the tail, and restarts the chain from
	// genesis (seq resets low) — the exact corruption scenario. Their ordinals seed
	// rotateOrdinal to 11.
	for _, ord := range []string{"00000000000000000010", "00000000000000000011"} {
		name := logPath + "." + ord + ".20260615T120000.000000000Z"
		if err := os.WriteFile(name, []byte("not-json-corrupt-tail\n"), 0o600); err != nil {
			t.Fatalf("seed sibling: %v", err)
		}
	}

	// Tiny rotate size so the second record forces a rotation; retain=2.
	sink, err := Open(logPath, keyPath, 256, 2)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Enough records that at least one rotation fires (each record > 256 bytes with the
	// envelope), post-reset so their seq is low.
	for i := 0; i < 6; i++ {
		sink.RecordAllow(context.Background(), "sess", "tool-with-a-longish-name-to-exceed-the-tiny-rotate-threshold", "tools/call", nil, nil, false, nil, nil)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	files, err := sortedRotatedSiblings(logPath)
	if err != nil {
		t.Fatalf("sortedRotatedSiblings: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("expected at least one rotated sibling from the writes")
	}
	// The newest sibling (last in order) must be a freshly-written one with an ordinal
	// GREATER than the seeded siblings (>= 12), proving the seed advanced past 11 rather
	// than restarting from the low post-reset seq.
	newest := files[len(files)-1]
	ord, hasOrd, _, _ := rotatedStampParts(newest, logPath)
	if !hasOrd || ord <= 11 {
		t.Fatalf("newest sibling %q has ordinal %d (hasOrd=%v); want > 11 (seeded past existing siblings)", newest, ord, hasOrd)
	}
}

// TestRotatedOrderLess_SeqOrdersBackwardClock is the backward-clock-step regression:
// siblings are ordered by their embedded, monotonic rotation ordinal, not the wall clock. A rotation that
// stamps a LATER seq with an EARLIER wall-clock timestamp (a backward clock step
// between rotations) must still sort AFTER the earlier-seq file.
func TestRotatedOrderLess_SeqOrdersBackwardClock(t *testing.T) {
	t.Parallel()

	logPath := "/var/log/audit.jsonl"
	// older seq, LATER wall clock (T120005); newer seq, EARLIER wall clock (T120003).
	older := logPath + ".00000000000000001000.20260615T120005.000000000Z"
	newer := logPath + ".00000000000000002000.20260615T120003.000000000Z"
	if rotatedOrderLess(newer, older, logPath) {
		t.Fatal("newer-seq file must sort AFTER older-seq file despite an earlier wall-clock stamp")
	}
	if !rotatedOrderLess(older, newer, logPath) {
		t.Fatal("older-seq file must sort before newer-seq file")
	}
	// A legacy (seq-less) sibling predates any seq-stamped one and orders first.
	legacy := logPath + ".20260615T120009.000000000Z"
	if !rotatedOrderLess(legacy, older, logPath) {
		t.Fatal("a legacy seq-less sibling must sort before a seq-stamped one")
	}
	if rotatedOrderLess(older, legacy, logPath) {
		t.Fatal("a seq-stamped sibling must not sort before a legacy one")
	}
}

// TestRotatedOrderLess_NumericSuffix is the regression: the ".N" collision
// backstop must order numerically, so ".10" (created after ".2") sorts AFTER it.
// A bare lexical sort puts ".10" before ".2" ('1' < '2').
func TestRotatedOrderLess_NumericSuffix(t *testing.T) {
	t.Parallel()

	logPath := "/var/log/audit.jsonl"
	base := logPath + ".20260615T000000.000000000Z"
	if rotatedOrderLess(base+".10", base+".2", logPath) {
		t.Fatal(".10 must sort after .2 (numeric order), got .10 < .2")
	}
	if !rotatedOrderLess(base+".2", base+".10", logPath) {
		t.Fatal(".2 must sort before .10")
	}
	// The bare stamp (no collision suffix) is the oldest of its nanosecond group.
	if !rotatedOrderLess(base, base+".1", logPath) {
		t.Fatal("the bare stamp must sort before its collision suffixes")
	}
}

// TestNewestRotatedSibling_NumericCollisionOrder confirms the end-to-end effect:
// with >9 same-nanosecond collisions, newestRotatedSibling must return the
// numerically-highest suffix (".10"), not the lexical maximum (".9"/".2").
func TestNewestRotatedSibling_NumericCollisionOrder(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	stamp := ".20260615T000000.000000000Z"
	for _, sfx := range []string{stamp, stamp + ".2", stamp + ".9", stamp + ".10"} {
		if err := os.WriteFile(logPath+sfx, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	got := newestRotatedSibling(logPath)
	want := logPath + stamp + ".10"
	if got != want {
		t.Fatalf("newest = %q, want %q (a lexical sort would wrongly pick .9)", got, want)
	}
}

// TestWriteRecordPartialWriteTruncatesOrphan verifies the fix: when the backing
// writer reports a partial write (n > 0, err != nil) — as a Linux write() can on
// ENOSPC — the unterminated fragment it left at EOF is truncated back to the last
// clean record boundary, so the NEXT record is not glued onto the orphan. The chain
// head is NOT advanced on the failure, s.written is rolled back to match the on-disk
// file, and a subsequent record then writes cleanly so the whole log still verifies
// (no INVALID/CHAIN BREAK/SEQ GAP cascade from a benign disk hiccup).
func TestWriteRecordPartialWriteTruncatesOrphan(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	key := nonZeroTestKey()
	s := &Sink{
		key:      key,
		keyID:    hmacKeyID(key),
		maxBytes: 1 << 30, // never rotate during the test
		f:        f,
	}

	// First write: a partial flush that actually lands `partial` bytes on disk
	// (mirroring write(2) returning a positive count with ENOSPC), then fails. Later
	// writes go through in full so the chain can continue.
	const partial = 7
	failOnce := true
	s.writeLine = func(b []byte) (int, error) {
		if failOnce {
			failOnce = false
			n, _ := f.Write(b[:partial])
			return n, fmt.Errorf("simulated ENOSPC after partial flush")
		}
		return f.Write(b)
	}

	seqBefore := s.seq
	s.writeRecord(&auditRecord{Decision: "allow", Target: "tool:x", Time: s.clock().UTC().Format(time.RFC3339Nano)})

	if s.seq != seqBefore {
		t.Fatalf("chain head advanced on a failed write: seq %d, want %d", s.seq, seqBefore)
	}
	if s.writeFailures.Load() == 0 {
		t.Fatal("expected a recorded write failure")
	}
	// The orphan fragment was truncated away: both s.written and the on-disk file are
	// back at the pre-write boundary (0), so the next append starts at a clean record
	// boundary rather than concatenating onto the fragment.
	if s.written != 0 {
		t.Fatalf("s.written = %d, want 0 (orphan fragment not truncated from the size accounting)", s.written)
	}
	if fi, statErr := f.Stat(); statErr != nil {
		t.Fatalf("stat: %v", statErr)
	} else if fi.Size() != 0 {
		t.Fatalf("on-disk size = %d, want 0 (orphan fragment not truncated from the file)", fi.Size())
	}

	// Two subsequent records write cleanly; the log must verify with no glued line and
	// no chain break.
	s.writeRecord(&auditRecord{Decision: "allow", Target: "tool:y", Time: s.clock().UTC().Format(time.RFC3339Nano)})
	s.writeRecord(&auditRecord{Decision: "deny", Target: "tool:z", Time: s.clock().UTC().Format(time.RFC3339Nano)})
	if err := f.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	res, err := VerifyLog(bytes.NewReader(data), s, "", time.Time{}, io.Discard)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if !res.OK() || res.Invalid != 0 || res.ChainBreaks != 0 {
		t.Fatalf("after a partial write + truncate, log did not verify cleanly: %+v", res)
	}
	if res.Valid != 2 {
		t.Fatalf("valid records = %d, want 2 (the two records written after the failed one)", res.Valid)
	}
}

// TestWriteRecordPartialWriteTruncateFailureSetsTailOrphanPending guards the
// double-failure path (orphan-fragment fusion when the repair truncate itself
// fails): when the immediate Stat/Truncate repair cannot clean up a partial
// write's orphan fragment, writeRecord must mark the tail pending — NOT force a
// rotation via s.written = maxBytes, which a subsequent FAILED rotation (plausible
// on the same degraded filesystem) would not prevent from appending onto the same
// still-orphaned fd. While pending, the next writeRecord call must retry the
// repair and skip the write entirely (never touching writeLine/f.Write) rather
// than risk splicing a full record onto the un-terminated fragment.
func TestWriteRecordPartialWriteTruncateFailureSetsTailOrphanPending(t *testing.T) {
	// A directory fd gives a real, positive Stat().Size() (so the target-size
	// arithmetic proceeds) while Truncate on it always fails (EISDIR/EINVAL) —
	// simulating a truncate failure without needing a faulty filesystem.
	dir := t.TempDir()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatalf("open dir: %v", err)
	}
	defer func() { _ = f.Close() }()

	key := nonZeroTestKey()
	const maxBytes = 1 << 20
	s := &Sink{key: key, keyID: hmacKeyID(key), maxBytes: maxBytes, f: f}

	const partial = 7
	var writeLineCalls int
	s.writeLine = func(b []byte) (int, error) {
		writeLineCalls++
		return partial, fmt.Errorf("simulated ENOSPC after partial flush")
	}

	s.writeRecord(&auditRecord{Decision: "allow", Target: "tool:x", Time: s.clock().UTC().Format(time.RFC3339Nano)})

	if s.writeFailures.Load() == 0 {
		t.Fatal("expected a recorded write failure")
	}
	// tailOrphanBytes > 0 is the pending flag; here it holds the exact orphan size.
	if s.tailOrphanBytes != partial {
		t.Fatalf("s.tailOrphanBytes = %d, want %d (pending, unrepairable orphan)", s.tailOrphanBytes, partial)
	}
	if s.written == maxBytes {
		t.Fatalf("s.written = %d; must NOT be force-set to maxBytes anymore (that signal let a subsequent failed rotation append onto the same orphaned fd)", s.written)
	}
	if writeLineCalls != 1 {
		t.Fatalf("writeLine called %d times, want exactly 1 for the first (failing) attempt", writeLineCalls)
	}

	// A second record while still pending (Truncate still fails on the dir fd) must
	// retry the repair and skip the write WITHOUT ever calling writeLine again —
	// never append onto a known-dirty tail.
	failuresBefore := s.writeFailures.Load()
	s.writeRecord(&auditRecord{Decision: "allow", Target: "tool:y", Time: s.clock().UTC().Format(time.RFC3339Nano)})
	if writeLineCalls != 1 {
		t.Fatalf("writeLine called %d times after a second record while pending, want still 1 (the write must be skipped, not attempted)", writeLineCalls)
	}
	if s.tailOrphanBytes == 0 {
		t.Fatal("the pending flag (tailOrphanBytes > 0) should remain set: the repair is still failing")
	}
	if s.writeFailures.Load() <= failuresBefore {
		t.Fatal("the skipped second record must also count as a write failure")
	}
}

// TestWriteRecord_TailOrphanPendingRepairedOnRetry_ResumesNormalWrites is the
// success-path complement to the two tests above: once a pending orphan repair
// FINALLY succeeds (the degraded filesystem recovers), writeRecord must truncate
// the real orphan bytes off disk, clear the pending flag (tailOrphanBytes back to
// 0), and resume the normal write path for that same call — not just on some later
// one.
func TestWriteRecord_TailOrphanPendingRepairedOnRetry_ResumesNormalWrites(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Simulate a real prior partial write: valid committed bytes, then an
	// unterminated orphan fragment at EOF (no trailing '{...}\n').
	const valid = "VALID-COMMITTED-RECORD-LINE\n"
	const orphan = "garbag" // 6-byte fragment, deliberately no newline/closing brace
	if _, err := f.WriteString(valid + orphan); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	key := nonZeroTestKey()
	s := &Sink{
		key:      key,
		keyID:    hmacKeyID(key),
		maxBytes: 1 << 30,
		f:        f,
		// Pending from an earlier failed attempt (tailOrphanBytes > 0 is the pending
		// flag). Starts already in that state to isolate the retry-success behavior.
		tailOrphanBytes: int64(len(orphan)),
		written:         int64(len(valid) + len(orphan)),
	}

	var writeLineCalls int
	s.writeLine = func(b []byte) (int, error) {
		writeLineCalls++
		return len(b), nil // a normal successful write, once repair clears the way
	}

	s.writeRecord(&auditRecord{Decision: "allow", Target: "tool:z", Time: s.clock().UTC().Format(time.RFC3339Nano)})

	if s.tailOrphanBytes != 0 {
		t.Fatal("the pending flag (tailOrphanBytes) should be cleared to 0 once the repair succeeds")
	}
	if writeLineCalls != 1 {
		t.Fatalf("writeLine called %d times, want exactly 1: the record write must proceed in the SAME call once repair succeeds", writeLineCalls)
	}
	if s.writeFailures.Load() != 0 {
		t.Fatalf("writeFailures = %d, want 0: a successfully repaired-then-written record is not a failure", s.writeFailures.Load())
	}

	// The orphan bytes must actually be gone from disk (writeLine is a stub that
	// never touches the real file, so any remaining bytes beyond `valid` would be
	// the un-truncated orphan).
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Size() != int64(len(valid)) {
		t.Fatalf("file size = %d, want %d (orphan fragment must be truncated off)", fi.Size(), len(valid))
	}
}

// TestWriteRecordPartialWriteDoesNotTruncateValidRecords guards the failed-rotation
// hazard: after a failed rotation, rotate() backs s.written off to ~90% of maxBytes
// WITHOUT swapping s.f, so s.written no longer equals the on-disk file size. A
// partial write must truncate only the orphan it just appended (fileSize - n), never
// `s.written - n`, which would lop ~10% of maxBytes of VALID committed records off the
// (near-full) file.
func TestWriteRecordPartialWriteDoesNotTruncateValidRecords(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Pre-populate the file with valid committed bytes (stand-in for records already
	// on disk when a rotation fails near the size limit).
	valid := []byte("VALID-COMMITTED-RECORD-BYTES\n")
	if _, err := f.Write(valid); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	key := nonZeroTestKey()
	s := &Sink{key: key, keyID: hmacKeyID(key), maxBytes: 1 << 30, f: f}
	// Simulate the post-failed-rotation state: s.written is backed off FAR above the
	// real on-disk size (rotate() sets rotateBackoffWritten() without swapping s.f).
	s.written = 999_999

	const partial = 5
	s.writeLine = func(b []byte) (int, error) {
		n, _ := f.Write(b[:partial]) // orphan fragment appended at EOF
		return n, fmt.Errorf("simulated ENOSPC after partial flush")
	}
	s.writeRecord(&auditRecord{Decision: "allow", Target: "tool:x", Time: s.clock().UTC().Format(time.RFC3339Nano)})

	// Only the partial orphan (n bytes) must be removed; the valid prefix must survive
	// and the file must NOT be grown/zero-extended.
	fi, statErr := f.Stat()
	if statErr != nil {
		t.Fatalf("stat: %v", statErr)
	}
	if fi.Size() != int64(len(valid)) {
		t.Fatalf("file size = %d, want %d — valid records must survive; only the %d-byte orphan is removed (s.written - n would have destroyed data)", fi.Size(), len(valid), partial)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(data, valid) {
		t.Fatalf("valid prefix corrupted: got %q, want %q", data, valid)
	}
}

// TestOpenAuditSinkWarnsOnUnparseableTail: when the audit
// log tail fails to parse as JSON (a record truncated by a partial write at
// shutdown, mid-write power loss, or disk corruption), openAuditSink cannot
// resume the chain and restarts from genesis. The symmetric HMAC-verification
// failure already warned; the parse-failure path must warn too so an operator
// knows the chain restarted and can reconcile, rather than discovering the break
// only when audit-verify later reports it.
func TestOpenAuditSinkWarnsOnUnparseableTail(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// A last line that is not valid JSON — as if the process was killed mid-write
	// and the final record was truncated before its closing brace.
	truncated := `{"seq":3,"_hmac":"sha256:abcdef"` // no closing brace
	if err := os.WriteFile(logPath, []byte(truncated+"\n"), 0o600); err != nil {
		t.Fatalf("write truncated log: %v", err)
	}

	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w

	sink, err := Open(logPath, keyPath, 0, 0)

	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	logged := buf.String()

	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	if !strings.Contains(logged, "failed to parse") {
		t.Fatalf("expected a parse-failure warning on stderr, got: %q", logged)
	}

	// The chain could not be resumed, so it restarts from genesis rather than
	// silently adopting the truncated record's seq (3) / hmac (sha256:abcdef). The
	// parse failure is now also recorded in-band as a signed marker, so the
	// first appended record is that marker at seq 1, chained from genesis.
	if sink.seq != 1 {
		t.Fatalf("seq = %d, want 1 (genesis restart + in-band parse-failure marker)", sink.seq)
	}
	if sink.prevHMAC == "" || sink.prevHMAC == "sha256:abcdef" {
		t.Fatalf("prevHMAC = %q, want the marker's hmac (chain restarted from genesis; truncated tail not adopted)", sink.prevHMAC)
	}
}

// TestOpenAuditSinkResumesFromRotatedSiblingWhenBaseEmpty covers the fix:
// when the base log is empty/absent on startup (e.g. a rotation reopen-fallback
// renamed it away and never recreated it), the chain is resumed from the newest
// rotated sibling's tail rather than silently reset to the genesis sentinel,
// which would orphan every record written before the restart.
func TestOpenAuditSinkResumesFromRotatedSiblingWhenBaseEmpty(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// Phase 1: write a few signed records, then close to flush.
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	for _, tool := range []string{"a", "b", "c"} {
		sink.RecordAllow(context.Background(), "sess", tool, "tools/call", nil, nil, false, nil, nil)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var last auditRecord
	if err := json.Unmarshal([]byte(mustReadLastAuditLine(t, logPath)), &last); err != nil {
		t.Fatalf("decode original tail: %v", err)
	}
	if last.Seq == 0 || last.HMAC == "" {
		t.Fatalf("expected signed records, got seq=%d hmac=%q", last.Seq, last.HMAC)
	}

	// Phase 2: simulate the rotation reopen-fallback aftermath — the base log was
	// renamed to a rotated sibling and the base path is now absent.
	rotated := logPath + ".20260614T120000.000000000Z"
	if err := os.Rename(logPath, rotated); err != nil {
		t.Fatalf("rename to rotated sibling: %v", err)
	}

	// Phase 3: restart. The chain must resume from the rotated sibling's tail.
	sink2, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink (restart): %v", err)
	}
	t.Cleanup(func() { _ = sink2.Close() })

	if sink2.seq != last.Seq {
		t.Fatalf("resumed seq = %d, want %d (chain reset to genesis would orphan the rotated records)", sink2.seq, last.Seq)
	}
	if sink2.prevHMAC != last.HMAC {
		t.Fatalf("resumed prevHMAC = %q, want %q", sink2.prevHMAC, last.HMAC)
	}

	// Phase 4: the next record must continue the chain at seq+1, linked to the
	// rotated tail's HMAC — no break, no gap across the two files.
	sink2.RecordAllow(context.Background(), "sess", "d", "tools/call", nil, nil, false, nil, nil)
	if err := sink2.Close(); err != nil {
		t.Fatalf("Close (restart): %v", err)
	}
	var next auditRecord
	if err := json.Unmarshal([]byte(mustReadLastAuditLine(t, logPath)), &next); err != nil {
		t.Fatalf("decode new tail: %v", err)
	}
	if next.Seq != last.Seq+1 {
		t.Fatalf("new record seq = %d, want %d", next.Seq, last.Seq+1)
	}
	if next.PrevHMAC != last.HMAC {
		t.Fatalf("new record prev_hmac = %q, want %q (chain not continuous across the restart)", next.PrevHMAC, last.HMAC)
	}
}

// TestOpenAuditSinkSkipsEmptyNewestSiblingOnResume is the regression: when the
// chronologically NEWEST rotated sibling is empty (e.g. left by an empty-base
// rotation, or a race with an in-progress rotation) and an OLDER sibling still
// carries the real chain tail, resume must walk past the empty newest sibling to
// find it — not restart the chain from genesis and silently orphan the older
// sibling's records.
func TestOpenAuditSinkSkipsEmptyNewestSiblingOnResume(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// Phase 1: write a few signed records, then close to flush.
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	for _, tool := range []string{"a", "b", "c"} {
		sink.RecordAllow(context.Background(), "sess", tool, "tools/call", nil, nil, false, nil, nil)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var last auditRecord
	if err := json.Unmarshal([]byte(mustReadLastAuditLine(t, logPath)), &last); err != nil {
		t.Fatalf("decode original tail: %v", err)
	}
	if last.Seq == 0 || last.HMAC == "" {
		t.Fatalf("expected signed records, got seq=%d hmac=%q", last.Seq, last.HMAC)
	}

	// Phase 2: simulate the reopen-fallback aftermath (base renamed to a rotated
	// sibling holding the real tail), PLUS a chronologically newer but EMPTY
	// sibling — the shape an empty-base rotate() would otherwise have produced.
	realSibling := logPath + ".20260614T120000.000000000Z"
	if err := os.Rename(logPath, realSibling); err != nil {
		t.Fatalf("rename to rotated sibling: %v", err)
	}
	emptySibling := logPath + ".20260614T130000.000000000Z" // newer timestamp, empty
	if err := os.WriteFile(emptySibling, nil, 0o600); err != nil {
		t.Fatalf("write empty sibling: %v", err)
	}

	// Phase 3: restart. Resume must skip the empty newest sibling and find the
	// real tail in the older, non-empty one — not reset to genesis.
	sink2, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink (restart): %v", err)
	}
	t.Cleanup(func() { _ = sink2.Close() })

	if sink2.seq != last.Seq {
		t.Fatalf("resumed seq = %d, want %d (an empty newest sibling must not reset the chain to genesis)", sink2.seq, last.Seq)
	}
	if sink2.prevHMAC != last.HMAC {
		t.Fatalf("resumed prevHMAC = %q, want %q", sink2.prevHMAC, last.HMAC)
	}
}

// TestNewestRotatedSiblingIgnoresNonRotatedFiles covers the fix:
// newestRotatedSibling must filter the glob with rotatedAuditRe, exactly as
// pruneRotated does. A sibling whose name sorts lexically after every genuine
// rotated stamp (e.g. "audit.jsonl.bak" — lowercase letters sort after digits
// and 'Z' in ASCII) must not be returned as the "newest rotated" tail; doing so
// would seed the resumed chain's seq/prev_hmac from the wrong source.
func TestNewestRotatedSiblingIgnoresNonRotatedFiles(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	genuine := logPath + ".20260614T120000.000000000Z"
	if err := os.WriteFile(genuine, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write genuine rotated sibling: %v", err)
	}
	// Spurious siblings that sort after the genuine stamp and would be picked by an
	// unfiltered lexical-max.
	for _, name := range []string{logPath + ".bak", logPath + ".lock", logPath + ".zzz"} {
		if err := os.WriteFile(name, []byte("{}\n"), 0o600); err != nil {
			t.Fatalf("write spurious sibling %q: %v", name, err)
		}
	}

	if got := newestRotatedSibling(logPath); got != genuine {
		t.Fatalf("newestRotatedSibling = %q, want %q (must ignore non-rotated siblings)", got, genuine)
	}

	// With no genuine rotated sibling present at all, it must return "" rather than
	// any spurious file.
	if err := os.Remove(genuine); err != nil {
		t.Fatalf("remove genuine: %v", err)
	}
	if got := newestRotatedSibling(logPath); got != "" {
		t.Fatalf("newestRotatedSibling = %q, want \"\" when only non-rotated siblings exist", got)
	}
}

// A logPath containing glob metacharacters ('[', ']', '*', '?') must be
// treated literally. filepath.Glob would interpret "audit[1].jsonl.*" as a
// character-class pattern and either miss the genuine rotated sibling or match
// unrelated files; the directory-scan implementation must find the real sibling
// and ignore a decoy directory whose name the glob pattern would have matched.
func TestNewestRotatedSiblingHandlesGlobMetacharacters(t *testing.T) {
	root := t.TempDir()

	// Real log directory and log name both contain glob metacharacters.
	dir := filepath.Join(root, "eunox[1]")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	logPath := filepath.Join(dir, "audit?.jsonl")

	genuine := logPath + ".20260614T120000.000000000Z"
	if err := os.WriteFile(genuine, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write genuine rotated sibling: %v", err)
	}

	// A decoy whose name the glob expansion of "eunox[1]" -> "eunox1" could match.
	decoyDir := filepath.Join(root, "eunox1")
	if err := os.Mkdir(decoyDir, 0o700); err != nil {
		t.Fatalf("mkdir decoy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(decoyDir, "audit1.jsonl.20260614T130000.000000000Z"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write decoy: %v", err)
	}

	if got := newestRotatedSibling(logPath); got != genuine {
		t.Fatalf("newestRotatedSibling = %q, want %q (must treat metacharacters literally)", got, genuine)
	}
}

// TestLogChainFiles_OrdersChainAndExcludesUnrelated pins the verify-time
// chain discovery: rotated siblings come first oldest->newest, the current base
// log last, and unrelated siblings (a ".bak", a ".lock") are excluded so they are
// never fed into the cross-file chain walk. It also covers the base-absent case
// (just rotated away) and the fresh-install case (nothing on disk).
func TestLogChainFiles_OrdersChainAndExcludesUnrelated(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	older := logPath + ".20260601T000000.000000000Z"
	newer := logPath + ".20260602T000000.000000000Z"
	// Create out of chronological order on disk to prove the ordering is by the
	// embedded timestamp, not directory/mtime order.
	for _, p := range []string{newer, older, logPath, logPath + ".bak", logPath + ".lock"} {
		if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
			t.Fatalf("write %q: %v", p, err)
		}
	}

	files, err := LogChainFiles(logPath)
	if err != nil {
		t.Fatalf("LogChainFiles: %v", err)
	}
	want := []string{older, newer, logPath} // rotated oldest->newest, then base last
	if !equalStringSlices(files, want) {
		t.Fatalf("chain files = %v, want %v (ordering or exclusion of unrelated siblings)", files, want)
	}

	// Base log absent (just rotated away): the sibling chain is still returned so
	// the tail in the newest sibling is verified.
	if err := os.Remove(logPath); err != nil {
		t.Fatalf("remove base: %v", err)
	}
	files, err = LogChainFiles(logPath)
	if err != nil {
		t.Fatalf("LogChainFiles (no base): %v", err)
	}
	if want := []string{older, newer}; !equalStringSlices(files, want) {
		t.Fatalf("chain files (no base) = %v, want %v", files, want)
	}

	// Neither base nor siblings: empty slice (the caller then prints the first-run
	// hint instead of verifying an empty chain).
	files, err = LogChainFiles(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatalf("LogChainFiles (fresh install): %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected no chain files for a fresh install, got %v", files)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestOpenAuditSinkIgnoresSpuriousSiblingOnResume is the integration check:
// a spurious "audit.jsonl.bak" carrying an attacker-chosen JSON record must not
// seed the resumed chain. Resume must come from the genuine rotated sibling.
func TestOpenAuditSinkIgnoresSpuriousSiblingOnResume(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// Write genuine signed records, then rename the base to a genuine rotated
	// sibling so the base path is empty on the next startup.
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	for _, tool := range []string{"a", "b", "c"} {
		sink.RecordAllow(context.Background(), "sess", tool, "tools/call", nil, nil, false, nil, nil)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	var genuineTail auditRecord
	if err := json.Unmarshal([]byte(mustReadLastAuditLine(t, logPath)), &genuineTail); err != nil {
		t.Fatalf("decode genuine tail: %v", err)
	}
	rotated := logPath + ".20260614T120000.000000000Z"
	if err := os.Rename(logPath, rotated); err != nil {
		t.Fatalf("rename to rotated sibling: %v", err)
	}

	// Drop a spurious file that sorts after the genuine stamp with an
	// attacker-chosen seq. If newestRotatedSibling failed to filter, the chain
	// would resume from seq 9999.
	spurious := []byte(`{"seq":9999,"_hmac":"sha256:deadbeef"}` + "\n")
	if err := os.WriteFile(logPath+".zzz", spurious, 0o600); err != nil {
		t.Fatalf("write spurious sibling: %v", err)
	}

	sink2, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink (restart): %v", err)
	}
	t.Cleanup(func() { _ = sink2.Close() })

	if sink2.seq != genuineTail.Seq {
		t.Fatalf("resumed seq = %d, want %d (chain seeded from spurious sibling)", sink2.seq, genuineTail.Seq)
	}
	if sink2.prevHMAC != genuineTail.HMAC {
		t.Fatalf("resumed prevHMAC = %q, want %q (chain seeded from spurious sibling)", sink2.prevHMAC, genuineTail.HMAC)
	}
}

// TestRotateBackoffWritten_MinHeadroom pins that the rotation backoff always
// leaves at least one byte of headroom, even for a sub-10-byte rotate size where
// integer division of maxBytes/10 floors to zero. Without the floor, the backoff
// set written == maxBytes (zero headroom), so under a persistent rename fault
// rotate() re-fired on every single record — the tight retry loop the backoff
// exists to prevent.
func TestRotateBackoffWritten_MinHeadroom(t *testing.T) {
	cases := []struct {
		maxBytes int64
		want     int64
	}{
		{1, 0},    // 1 - max(1/10,1)=1 -> 0 headroom-from-max, i.e. 1 byte below cap
		{5, 4},    // 5 - 1
		{9, 8},    // 9 - 1
		{10, 9},   // 10 - 1 (10/10 == 1)
		{100, 90}, // 100 - 10
		{1000, 900},
	}
	for _, tc := range cases {
		s := &Sink{maxBytes: tc.maxBytes}
		got := s.rotateBackoffWritten()
		if got != tc.want {
			t.Errorf("rotateBackoffWritten(maxBytes=%d) = %d, want %d", tc.maxBytes, got, tc.want)
		}
		if headroom := tc.maxBytes - got; headroom < 1 {
			t.Errorf("maxBytes=%d: headroom %d < 1 — backoff would spin per record", tc.maxBytes, headroom)
		}
	}
}

// TestRotate_EmptyBase_NoOp is the regression: rotate() must not rename an empty
// active file. Without this guard, a single record whose serialized line alone
// exceeds maxBytes trips the size trigger while s.written is still 0 on a freshly
// opened base, and rotate() renamed the empty file to a timestamped sibling — a
// spurious zero-byte rotated file that carries the newest timestamp and, with a
// small retain budget, can evict a real historical sibling via pruneRotated.
func TestRotate_EmptyBase_NoOp(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer func() { _ = f.Close() }()

	// A real historical sibling that must survive: an empty-base rotation would
	// create a newer (empty) sibling and prune this one away under retain=1.
	oldSibling := logPath + ".20260101T000000.000000000Z"
	if err := os.WriteFile(oldSibling, []byte("real record\n"), 0o600); err != nil {
		t.Fatalf("write sibling: %v", err)
	}

	s := &Sink{
		logPath:    logPath,
		activePath: logPath,
		maxBytes:   1 << 20,
		retain:     1,
		f:          f,
		written:    0, // fresh base: nothing written yet
		now:        func() time.Time { return time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC) },
	}

	s.rotate()

	if s.f != f {
		t.Fatal("rotate() on an empty base must not swap the fd")
	}
	if s.activePath != logPath || s.written != 0 {
		t.Fatalf("rotate() on an empty base must be a no-op; got activePath=%q written=%d", s.activePath, s.written)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 2 { // logPath (still empty) + the one pre-existing sibling
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("rotate() on an empty base must not create a new rotated sibling; dir has %v", names)
	}
	if _, err := os.Stat(oldSibling); err != nil {
		t.Fatalf("the real historical sibling must survive untouched: %v", err)
	}
}

// TestRotateReopenFallbackStillPrunes is the regression: when os.Rename succeeds
// but the subsequent os.OpenFile of the fresh base log fails, rotate() takes the
// reopen-fallback path (keep writing to the already-renamed file). That path must
// still enforce retention — otherwise every rotation under a persistent reopen
// fault adds a rotated sibling without ever pruning, accumulating without bound.
func TestRotateReopenFallbackStillPrunes(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	// Make logPath a DIRECTORY so the post-rename os.OpenFile(logPath, O_CREATE|
	// O_WRONLY) fails (EISDIR), deterministically forcing the reopen-fallback
	// branch while the rename itself — the active file to a free timestamped
	// sibling name in the same writable dir — still succeeds.
	if err := os.Mkdir(logPath, 0o755); err != nil {
		t.Fatalf("mkdir logPath: %v", err)
	}

	// The active file the fd writes to (a name that is NOT a rotated sibling;
	// rotate renames it to the timestamped sibling).
	activePath := filepath.Join(dir, "active.tmp")
	f, err := os.OpenFile(activePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open active: %v", err)
	}
	defer func() { _ = f.Close() }()
	// rotate() no longer rotates an empty base (a companion fix — see
	// TestRotate_EmptyBase_NoOp), so the active file must carry real bytes
	// matching s.written below for the fallback-entry rename to proceed at all.
	const activeContent = "existing-record\n"
	if _, err := f.WriteString(activeContent); err != nil {
		t.Fatalf("seed active file: %v", err)
	}

	// Two pre-existing genuine rotated siblings whose stamps are older than the
	// fixed rotation clock below, so they sort oldest and are the prune candidates.
	for _, stamp := range []string{"20260101T000000.000000000Z", "20260101T000001.000000000Z"} {
		if err := os.WriteFile(logPath+"."+stamp, []byte("old\n"), 0o600); err != nil {
			t.Fatalf("write sibling: %v", err)
		}
	}

	fixed := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	key := nonZeroTestKey()
	s := &Sink{
		key:        key,
		keyID:      hmacKeyID(key),
		logPath:    logPath,
		activePath: activePath,
		maxBytes:   1 << 20,
		retain:     1,
		f:          f,
		written:    int64(len(activeContent)),
		now:        func() time.Time { return fixed },
	}

	s.rotate()

	// rotate() renamed active.tmp to audit.jsonl.<fixed> and failed to reopen
	// audit.jsonl (a directory), so s.activePath now points at that timestamped file,
	// which is still being written to. pruneRotated excludes that live fallback file
	// from the retain budget (it is not a closed historical file), so with retain=1 it
	// keeps exactly one historical sibling (the newer of the two pre-existing ones)
	// PLUS the live fallback file: two rotated-pattern files in total. Counting the
	// active file against the quota would silently reduce historical retention to
	// retain-1 and could delete the last historical record.
	if s.activePath == logPath {
		t.Fatalf("expected fallback mode (activePath != logPath); got activePath=%q", s.activePath)
	}
	if _, err := os.Stat(s.activePath); err != nil {
		t.Fatalf("active fallback file must survive pruning: %v", err)
	}
	// The oldest historical sibling is pruned; the newer one is retained.
	if _, err := os.Stat(logPath + ".20260101T000000.000000000Z"); !os.IsNotExist(err) {
		t.Fatalf("oldest historical sibling should have been pruned, stat err=%v", err)
	}
	if _, err := os.Stat(logPath + ".20260101T000001.000000000Z"); err != nil {
		t.Fatalf("newest historical sibling (retain=1) must survive: %v", err)
	}

	matches, err := rotatedSiblings(logPath)
	if err != nil {
		t.Fatalf("rotatedSiblings: %v", err)
	}
	var rotatedCount int
	for _, m := range matches {
		if rotatedAuditRe.MatchString(m[len(logPath):]) {
			rotatedCount++
		}
	}
	if rotatedCount != 2 {
		t.Fatalf("after reopen-fallback rotation, %d rotated-pattern files remain, want 2 (1 retained historical + the live fallback)", rotatedCount)
	}
}

// TestRotateReopenFallbackRespectsSizeBound pins the reopen-fallback backoff: when the
// rename succeeds but the fresh-base OpenFile fails, rotate() backs s.written off to
// rotateBackoffWritten() (a small headroom below maxBytes) rather than resetting to 0.
// Resetting under-counted the already-~maxBytes renamed file by a full maxBytes, so it
// was allowed to grow toward ~2x maxBytes before the next size check — a silent
// size-bound overshoot. The backoff makes the next record re-enter rotate() promptly,
// where the inFallback guard retries only the reopen.
func TestRotateReopenFallbackRespectsSizeBound(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	// logPath as a DIRECTORY forces the post-rename OpenFile (O_CREATE|O_WRONLY) to fail
	// with EISDIR, deterministically taking the reopen-fallback branch while the rename
	// of the active file to a free sibling still succeeds.
	if err := os.Mkdir(logPath, 0o755); err != nil {
		t.Fatalf("mkdir logPath: %v", err)
	}

	activePath := filepath.Join(dir, "active.tmp")
	f, err := os.OpenFile(activePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open active: %v", err)
	}
	defer func() { _ = f.Close() }()
	// rotate() no longer rotates an empty base (a companion fix — see
	// TestRotate_EmptyBase_NoOp), so the active file must carry real bytes
	// matching s.written below for the fallback-entry rename to proceed at all.
	const activeContent = "existing-record\n"
	if _, err := f.WriteString(activeContent); err != nil {
		t.Fatalf("seed active file: %v", err)
	}

	fixed := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	key := nonZeroTestKey()
	// maxBytes 1000 -> rotateBackoffWritten() == 900 (a non-zero backoff value), so the
	// assertion s.written != 0 distinguishes the backoff from the old reset-to-0 bug.
	s := &Sink{
		key:        key,
		keyID:      hmacKeyID(key),
		logPath:    logPath,
		activePath: activePath,
		maxBytes:   1000,
		retain:     0,
		f:          f,
		written:    int64(len(activeContent)),
		now:        func() time.Time { return fixed },
	}

	s.rotate()

	if !s.inFallback {
		t.Fatalf("expected s.inFallback=true after a failed reopen")
	}
	if s.activePath == s.logPath {
		t.Fatalf("expected fallback mode (activePath != logPath); got activePath=%q", s.activePath)
	}
	want := s.rotateBackoffWritten()
	if want == 0 {
		t.Fatalf("test precondition: rotateBackoffWritten()=0 for maxBytes=%d; pick a maxBytes that yields non-zero backoff", s.maxBytes)
	}
	if s.written != want {
		t.Fatalf("reopen-fallback set s.written=%d, want the backoff value %d (not 0)", s.written, want)
	}
	if s.written == 0 {
		t.Fatalf("reopen-fallback reset s.written to 0; the renamed ~maxBytes file could grow toward 2x maxBytes before the next check")
	}
}

// TestRetryRotateReopenRecovers pins the recovery side of the reopen-fallback state:
// once a fresh base can be opened again, the next rotation (routed through the inFallback
// guard to retryRotateReopen) completes the deferred rotation — it switches s.f to the
// fresh base, leaves the over-size fallback file as a normal rotated sibling, clears
// inFallback, restores activePath to the configured base, and resets written to 0.
func TestRetryRotateReopenRecovers(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	// Start in the fallback state as rotate() leaves it: logPath is briefly a directory
	// (the reopen kept failing), and the fd writes to a rotated-style sibling.
	if err := os.Mkdir(logPath, 0o755); err != nil {
		t.Fatalf("mkdir logPath: %v", err)
	}

	activePath := logPath + ".20260101T000000.000000000Z"
	f, err := os.OpenFile(activePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open fallback active: %v", err)
	}
	defer func() { _ = f.Close() }()

	fixed := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	key := nonZeroTestKey()
	s := &Sink{
		key:        key,
		keyID:      hmacKeyID(key),
		logPath:    logPath,
		activePath: activePath,
		maxBytes:   1000,
		retain:     0,
		f:          f,
		now:        func() time.Time { return fixed },
		inFallback: true,
	}
	s.written = s.rotateBackoffWritten() // high, so the size trigger fires

	// Clear the blocker: remove the directory so OpenFile(logPath) now succeeds and the
	// deferred rotation can complete to a fresh base.
	if err := os.Remove(logPath); err != nil {
		t.Fatalf("remove logPath dir: %v", err)
	}

	s.rotate()

	if s.inFallback {
		t.Fatalf("expected s.inFallback=false after reopen recovered")
	}
	if s.activePath != s.logPath {
		t.Fatalf("expected activePath restored to the base log %q; got %q", s.logPath, s.activePath)
	}
	if s.written != 0 {
		t.Fatalf("expected s.written=0 on recovery; got %d", s.written)
	}
	// The fd must now write to the fresh base, not the over-size fallback file.
	if _, err := s.f.WriteString("probe\n"); err != nil {
		t.Fatalf("write to recovered fd: %v", err)
	}
	if err := s.f.Sync(); err != nil {
		t.Fatalf("sync recovered fd: %v", err)
	}
	got, err := os.ReadFile(logPath) //nolint:gosec // G304: test-controlled temp dir
	if err != nil {
		t.Fatalf("read recovered base: %v", err)
	}
	if string(got) != "probe\n" {
		t.Fatalf("recovered fd wrote %q to the base; want it to write to the fresh base log", string(got))
	}
}
