// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestRecoverTailAfterReadError_ReasonIsStructuredSentinel guards the structured
// chain_resume_failed reason:
// when the base log is non-empty but unreadable (the default branch), the reason
// returned for the signed chain_resume_failed marker must be the structured,
// OS-independent sentinel — never the raw OS error string, which varies by platform
// and can embed the log file path in the append-only tape. Permission-based, so
// skipped under root (mode bits are bypassed there), matching TestOpen_ChainResumeReadError.
func TestRecoverTailAfterReadError_ReasonIsStructuredSentinel(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses file permission bits")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	// Non-empty, write-only (0200): the read-mode reopen inside readLastAuditLine
	// fails with EACCES, so recoverTailAfterReadError takes its default (unreadable)
	// branch and returns the chain_resume_failed reason.
	if err := os.WriteFile(logPath, []byte(`{"seq":5,"_hmac":"sha256:abc"}`+"\n"), 0o200); err != nil {
		t.Fatalf("write write-only log: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(logPath, 0o600) })

	// The readErr argument is a realistic OS error string with a path; it must NOT
	// leak into the returned reason.
	_, _, failed, reason := recoverTailAfterReadError(logPath, errors.New("read /var/log/audit.jsonl: input/output error"))
	if !failed {
		t.Fatalf("expected failed=true for a non-empty unreadable base")
	}
	if reason != auditReasonTailReadFailed {
		t.Fatalf("reason = %q, want the structured sentinel %q (no OS error string in the signed record)", reason, auditReasonTailReadFailed)
	}
}

// TestScanHighestSeq_ReportsMax verifies scanHighestSeq finds the largest seq in a
// populated log. It backs the chain-resume error path: when the bounded tail read
// fails on a non-empty log and no tail can be recovered, the resumed seq is seeded
// past this maximum so new records cannot duplicate existing seqs (a SEQ GAP plus a
// duplicate-seq cascade) the way a genesis (seq 1) restart did.
func TestScanHighestSeq_ReportsMax(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, _ := writeChainLog(t, dir, "a", "b", "c") // records seq 1, 2, 3
	got, ok := scanHighestSeq(logPath)
	if !ok || got != 3 {
		t.Fatalf("scanHighestSeq = (%d, %v), want (3, true)", got, ok)
	}
}

// TestScanHighestSeq_AbsentOrEmpty: an absent or empty log yields (0, false) so the
// caller leaves seq at 0 and the chain begins at genesis, as for a fresh install.
func TestScanHighestSeq_AbsentOrEmpty(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	if got, ok := scanHighestSeq(filepath.Join(dir, "absent.jsonl")); ok || got != 0 {
		t.Fatalf("scanHighestSeq(absent) = (%d, %v), want (0, false)", got, ok)
	}

	empty := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := scanHighestSeq(empty); ok || got != 0 {
		t.Fatalf("scanHighestSeq(empty) = (%d, %v), want (0, false)", got, ok)
	}
}

// TestScanHighestSeq_UnreadableBaseOverEstimates is the regression for the
// write-only (0200) audit-log deployment: os.Open fails EACCES, and returning
// (0, false) would seed the resumed counter at genesis, re-issuing every on-disk
// seq — a tamper-shaped duplicate-seq cascade on every restart. scanHighestSeq
// must instead stat the file (which needs no read permission) and over-estimate
// from its size, seeding PAST the on-disk maximum so the drift is a detectable
// SEQ GAP, not a duplicate. Permission-based, so skipped under root.
func TestScanHighestSeq_UnreadableBaseOverEstimates(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses file permission bits")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	content := []byte(`{"seq":5,"_hmac":"sha256:abc"}` + "\n")
	if err := os.WriteFile(logPath, content, 0o200); err != nil {
		t.Fatalf("write write-only log: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(logPath, 0o600) })

	got, ok := scanHighestSeq(logPath)
	if !ok {
		t.Fatal("scanHighestSeq on an unreadable non-empty base must report ok=true (over-estimate), not (0, false)")
	}
	if got < uint64(len(content)) {
		t.Fatalf("scanHighestSeq = %d, want >= the file size %d (an over-estimate past the on-disk max, not a genesis reset)", got, len(content))
	}
}

// TestScanHighestSeq_SkipsUnparseableLines: a corrupt or partial trailing record
// must not abort the scan or be counted; scanHighestSeq returns the max seq among
// the records that DO parse.
func TestScanHighestSeq_SkipsUnparseableLines(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, _ := writeChainLog(t, dir, "a", "b") // records seq 1, 2

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{ this is not valid json\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	got, ok := scanHighestSeq(logPath)
	if !ok || got != 2 {
		t.Fatalf("scanHighestSeq with a corrupt tail = (%d, %v), want (2, true)", got, ok)
	}
}

// TestRecoverTailAfterReadError_PrefersReadableBaseOverSibling is the regression for
// a genuine (non-shrink) tail-read failure resuming from an OLDER rotated sibling:
// rotated siblings carry lower seqs than the active base, so resuming from one and
// appending to the base would duplicate the base's newer seqs. When a re-read shows
// the base is readable and non-empty, recovery must resume from the base, never the
// sibling.
func TestRecoverTailAfterReadError_PrefersReadableBaseOverSibling(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, _ := writeChainLog(t, dir, "a", "b", "c") // base: seq 1..3, readable

	// An older rotated sibling exists; it must NOT be preferred over a readable base.
	sib := logPath + ".20250101T000000.000000000Z"
	if err := os.WriteFile(sib, []byte(`{"seq":1}`+"\n"+`{"seq":2}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	wantLast, err := readLastAuditLine(logPath)
	if err != nil || wantLast == "" {
		t.Fatalf("readLastAuditLine(base) = (%q, %v)", wantLast, err)
	}

	last, seedSeq, failed, _ := recoverTailAfterReadError(logPath, errors.New("transient blip"))
	if failed || seedSeq != 0 {
		t.Fatalf("readable base: got failed=%v seedSeq=%d, want false / 0", failed, seedSeq)
	}
	if last != wantLast {
		t.Fatalf("recovery must resume from the readable base tail, not the older sibling: got %q, want %q", last, wantLast)
	}
}

// TestRecoverTailAfterReadError_EmptyBaseFallsBackToSibling: an empty base is the
// shrink-race signature (a rotation moved the true tail into the newest sibling), so
// recovery resumes from the sibling — new records append to the fresh base and cannot
// collide.
func TestRecoverTailAfterReadError_EmptyBaseFallsBackToSibling(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(base, nil, 0o600); err != nil { // empty base
		t.Fatal(err)
	}
	sibLast := `{"seq":42}`
	sib := base + ".20250101T000000.000000000Z"
	if err := os.WriteFile(sib, []byte(`{"seq":41}`+"\n"+sibLast+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	last, seedSeq, failed, _ := recoverTailAfterReadError(base, errors.New("transient blip"))
	if failed || seedSeq != 0 {
		t.Fatalf("empty base + sibling: got failed=%v seedSeq=%d, want false / 0", failed, seedSeq)
	}
	if last != sibLast {
		t.Fatalf("empty base must resume from the sibling tail: got %q, want %q", last, sibLast)
	}
}

// TestRecoverTailAfterReadError_EmptyBaseNoSibling: an empty base with no sibling has
// nothing to orphan, so recovery resumes cleanly from genesis (no marker, no seed).
func TestRecoverTailAfterReadError_EmptyBaseNoSibling(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(base, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	last, seedSeq, failed, _ := recoverTailAfterReadError(base, errors.New("transient blip"))
	if last != "" || seedSeq != 0 || failed {
		t.Fatalf("empty base, no sibling: got (%q, %d, %v), want (\"\", 0, false)", last, seedSeq, failed)
	}
}

// TestScanHighestSeq_ReadsPastLargeLineInOnePass pins that the single wide-buffer pass
// reads PAST a record larger than the old 4 MiB primary buffer (but within the 64 MiB
// cap) and recovers the TRUE highest parseable seq (9999 here) — not the too-low partial
// max (1) before the large line, and not a file-size over-estimate. This is the case the
// former two-pass handled via its 64 MiB re-scan; the single pass sized at that cap
// handles it directly in one read (clean EOF, no scanner error).
func TestScanHighestSeq_ReadsPastLargeLineInOnePass(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	var b bytes.Buffer
	// A small parseable record first (a truncated pass would stop at seq 1).
	b.WriteString(`{"seq":1}` + "\n")
	// A line larger than the old 4 MiB primary buffer but well within the 64 MiB cap:
	// the single wide-buffer pass reads past it cleanly to the higher-seq record below.
	b.Write(append(bytes.Repeat([]byte("a"), auditScanBufferBytes+10), '\n'))
	// A higher-seq record AFTER the large line: the pass must reach it.
	b.WriteString(`{"seq":9999}` + "\n")
	if err := os.WriteFile(logPath, b.Bytes(), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat log: %v", err)
	}
	fileSize := uint64(info.Size())

	got, ok := scanHighestSeq(logPath)
	if !ok {
		t.Fatalf("scanHighestSeq = (%d, false), want ok=true", got)
	}
	// Must recover the TRUE max seq beyond the large line, not the partial max (1).
	if got != 9999 {
		t.Fatalf("scanHighestSeq = %d, want the true max seq 9999 read past the large line", got)
	}
	// And it must NOT be the file-size-in-bytes over-estimate: a within-cap line reads
	// cleanly, so the over-estimate fallback must not fire here.
	if got == fileSize {
		t.Fatalf("scanHighestSeq returned the file size in bytes (%d); a within-cap line must read cleanly", got)
	}
}

// TestScanHighestSeqCapped_OverCapLineOverEstimates pins the fail-closed fallback: a
// line larger than the per-line buffer cap aborts the scan (bufio.ErrTooLong), leaving
// only a LOWER bound on the true max, so scanHighestSeq seeds PAST the on-disk maximum
// from the file size rather than re-issuing existing seqs. The cap is injected small so
// the branch is exercised deterministically without allocating a >64 MiB line. This is
// the load-bearing fail-closed guarantee (a duplicate seq reads as tampering; a gap only
// as loss), so it must stay covered.
func TestScanHighestSeqCapped_OverCapLineOverEstimates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	const bufCap = 4096
	var b bytes.Buffer
	b.WriteString(`{"seq":1}` + "\n")
	// A line longer than the injected cap with no interior newline: the scan aborts here
	// (bufio.ErrTooLong) and never reaches seq 9999 below.
	b.Write(append(bytes.Repeat([]byte("a"), bufCap+10), '\n'))
	b.WriteString(`{"seq":9999}` + "\n")
	if err := os.WriteFile(logPath, b.Bytes(), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat log: %v", err)
	}
	fileSize := uint64(info.Size())

	got, ok := scanHighestSeqCapped(logPath, bufCap)
	if !ok {
		t.Fatalf("scanHighestSeqCapped over-cap = (%d, false), want ok=true (over-estimate)", got)
	}
	// The lower-bound partial max was 1; a bug returning it (or 9999, unreachable past the
	// over-cap line) would re-issue existing seqs. The fail-closed fallback seeds from the
	// file size, PAST the on-disk maximum.
	if got != fileSize {
		t.Fatalf("scanHighestSeqCapped over-cap = %d, want the file-size over-estimate %d", got, fileSize)
	}
}

// TestScanHighestSeq_CleanReadReportsTrueMax pins that a log reading cleanly to EOF
// reports the true max seq (not the conservative file-size over-estimate), and that a
// blank/recordless file — which reads cleanly but parses nothing — reports ok=false so
// scanHighestSeq's caller over-estimates rather than seeding from genesis. This covers
// the single-pass clean-EOF branch directly.
func TestScanHighestSeq_CleanReadReportsTrueMax(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(`{"seq":1}`+"\n"+`{"seq":7}`+"\n"+`{"seq":4}`+"\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	got, ok := scanHighestSeq(logPath)
	if !ok || got != 7 {
		t.Fatalf("scanHighestSeq = (%d, %v), want (7, true)", got, ok)
	}

	// A blank/recordless file reads cleanly to EOF but parses nothing: ok=false.
	emptyPath := filepath.Join(dir, "blank.jsonl")
	if err := os.WriteFile(emptyPath, []byte("\n\n"), 0o600); err != nil {
		t.Fatalf("write blank log: %v", err)
	}
	if h, ok := scanHighestSeq(emptyPath); ok || h != 0 {
		t.Fatalf("scanHighestSeq(recordless) = (%d, %v), want (0, false)", h, ok)
	}
}
