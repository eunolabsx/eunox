// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestOpen_ChainResumeFailedReasonIsStructuredSentinel guards the structured
// chain_resume_failed reason: when the log is non-empty but its tail cannot be read
// (a write-only 0200 log, whose tail the held append handle cannot probe), the reason
// written into the signed marker must be the structured, OS-independent sentinel —
// never a raw OS error string, which varies by platform and can embed the log file
// path in the append-only tape. Permission-based, so skipped under root (mode bits are
// bypassed there), matching TestOpen_ChainResumeReadError.
func TestOpen_ChainResumeFailedReasonIsStructuredSentinel(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses file permission bits")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	// Non-empty and write-only: O_RDWR is refused, so Open falls back to O_WRONLY and
	// the tail is unreadable — the one remaining chain-resume failure mode.
	if err := os.WriteFile(logPath, []byte(`{"seq":5,"_hmac":"sha256:abc"}`+"\n"), 0o200); err != nil {
		t.Fatalf("write write-only log: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(logPath, 0o600) })

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open must succeed (audit-failure tradeoff), got %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := os.Chmod(logPath, 0o600); err != nil {
		t.Fatalf("chmod for readback: %v", err)
	}
	data, err := os.ReadFile(logPath) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var marker map[string]interface{}
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var rec map[string]interface{}
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
		details, _ := rec["details"].(map[string]interface{})
		if details["kind"] == "chain_resume_failed" {
			marker = details
		}
	}
	if marker == nil {
		t.Fatalf("no chain_resume_failed marker was appended; log:\n%s", data)
	}
	if marker["reason"] != auditReasonTailReadFailed {
		t.Fatalf("reason = %v, want the structured sentinel %q (no OS error string in the signed record)", marker["reason"], auditReasonTailReadFailed)
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
	got, ok := seqViewForTest(logPath)
	if !ok || got != 3 {
		t.Fatalf("scanHighestSeq = (%d, %v), want (3, true)", got, ok)
	}
}

// TestScanHighestSeq_AbsentOrEmpty: an absent or empty log yields (0, false) so the
// caller leaves seq at 0 and the chain begins at genesis, as for a fresh install.
func TestScanHighestSeq_AbsentOrEmpty(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	if got, ok := seqViewForTest(filepath.Join(dir, "absent.jsonl")); ok || got != 0 {
		t.Fatalf("seqViewForTest(absent) = (%d, %v), want (0, false)", got, ok)
	}

	empty := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := seqViewForTest(empty); ok || got != 0 {
		t.Fatalf("seqViewForTest(empty) = (%d, %v), want (0, false)", got, ok)
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

	got, ok := seqViewForTest(logPath)
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

	got, ok := seqViewForTest(logPath)
	if !ok || got != 2 {
		t.Fatalf("scanHighestSeq with a corrupt tail = (%d, %v), want (2, true)", got, ok)
	}
}

// TestRecoverTailAfterReadError_PrefersReadableBaseOverSibling is the regression for
// a genuine (non-shrink) tail-read failure resuming from an OLDER rotated sibling:
// rotated siblings carry lower seqs than the active base, so resuming from one and
// TestOpen_PrefersReadableBaseTailOverSibling: an older rotated sibling exists
// alongside a readable, non-empty base. Siblings are OLDER than the active base, so
// resuming from one would rewind seq and reissue the base's newer numbers — a
// duplicate-seq cascade audit-verify cannot tell from tampering. The base tail wins.
func TestOpen_PrefersReadableBaseTailOverSibling(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b", "c") // base: seq 1..3

	// An older rotated sibling carrying a much HIGHER seq: if Open ever preferred it,
	// the resumed seq would jump to 99 instead of continuing the base at 3.
	sib := logPath + ".20250101T000000.000000000Z"
	if err := os.WriteFile(sib, []byte(`{"seq":99,"_hmac":"sha256:old"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	if sink.seq != 3 {
		t.Fatalf("resumed seq = %d, want 3 (the readable base tail, not the older sibling)", sink.seq)
	}
}

// TestOpen_EmptyBaseFallsBackToSiblingTail: an empty base is the just-rotated (or
// shrink-race) signature — the true tail lives in the newest rotated sibling. Resuming
// from the empty base would restart at genesis and silently orphan every prior record
// with no detectable gap, so Open resumes from the sibling's tail instead.
func TestOpen_EmptyBaseFallsBackToSiblingTail(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	if err := os.WriteFile(base, nil, 0o600); err != nil { // empty base
		t.Fatal(err)
	}
	sib := base + ".20250101T000000.000000000Z"
	if err := os.WriteFile(sib, []byte(`{"seq":41}`+"\n"+`{"seq":42}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sink, err := Open(base, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	// The sibling tail is unsigned (pre-chain), so the resume adopts its seq 42 and
	// then the legacy_tail_resumed marker consumes 43. Either way the point stands:
	// the counter continued from the sibling instead of restarting at genesis.
	if sink.seq != 43 {
		t.Fatalf("resumed seq = %d, want 43 (sibling tail seq 42, plus the legacy-resume marker)", sink.seq)
	}
}

// TestOpen_EmptyBaseNoSiblingStartsAtGenesis: an empty base with no sibling has
// nothing to orphan, so the chain starts cleanly at genesis — no seed, no marker.
func TestOpen_EmptyBaseNoSiblingStartsAtGenesis(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	if err := os.WriteFile(base, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	sink, err := Open(base, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	if sink.seq != 0 {
		t.Fatalf("resumed seq = %d, want 0 (genesis) for an empty base with no sibling", sink.seq)
	}
	data, err := os.ReadFile(base) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if len(bytes.TrimSpace(data)) != 0 {
		t.Fatalf("no marker should be written for a clean genesis start, got:\n%s", data)
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

	got, ok := seqViewForTest(logPath)
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

	got, ok := seqViewForTestCapped(logPath, bufCap)
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
	got, ok := seqViewForTest(logPath)
	if !ok || got != 7 {
		t.Fatalf("scanHighestSeq = (%d, %v), want (7, true)", got, ok)
	}

	// A blank/recordless file reads cleanly to EOF but parses nothing: ok=false.
	emptyPath := filepath.Join(dir, "blank.jsonl")
	if err := os.WriteFile(emptyPath, []byte("\n\n"), 0o600); err != nil {
		t.Fatalf("write blank log: %v", err)
	}
	if h, ok := seqViewForTest(emptyPath); ok || h != 0 {
		t.Fatalf("seqViewForTest(recordless) = (%d, %v), want (0, false)", h, ok)
	}
}

// seqViewForTest and seqViewForTestCapped reproduce the SINGLE-FILE "max of the highest
// parsed seq and the file's unread byte size" view these tests were written against.
//
// They live here, not in the package, because production does not use that rule: it folds
// the unread byte size ADDITIVELY across the whole chain (highestSeqAcrossChainCapped),
// precisely because one file's byte count is not a global seq and taking a per-file
// maximum under-seeds once the chain seq outgrows a sidecar's size. The package used to
// ship these two wrappers with no production caller at all, kept alive only by this file
// — dead code encoding the rule the real path rejects, with a green test suite pinning it,
// which is exactly how a future contributor concludes max-of-file-size is the house rule
// and reuses it for a new resume path. The scanning behavior below (parses records, skips
// unparseable lines, over-estimates on an unreadable file, reads past an over-cap line) is
// scanSeqContribution's and is what these tests actually cover.
func seqViewForTest(path string) (uint64, bool) {
	return seqViewForTestCapped(path, rescanBufferBytes)
}

func seqViewForTestCapped(path string, bufCap int) (uint64, bool) {
	parsedMax, parsed, unreadBytes := scanSeqContribution(path, bufCap)
	if unreadBytes > parsedMax {
		return unreadBytes, true
	}
	return parsedMax, parsed
}

// TestOpen_ResumesFromTailAfterPartialWriteRecovery pins the single-read startup: the
// tail is established from the very window truncatePartialTail probes through the held
// append handle, so a non-clean shutdown that left an orphan fragment resumes from the
// last COMPLETE record — with no second open of the log to re-fetch bytes already read.
func TestOpen_ResumesFromTailAfterPartialWriteRecovery(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b", "c") // seq 1..3, signed

	// Simulate a kill -9 mid-write: a newline-less fragment appended after seq 3.
	ap, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("reopen for append: %v", err)
	}
	if _, err := ap.WriteString(`{"seq":4,"partial`); err != nil {
		t.Fatalf("append orphan: %v", err)
	}
	if err := ap.Close(); err != nil {
		t.Fatalf("close append handle: %v", err)
	}

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	// The orphan was dropped and the chain resumed from seq 3; the recovery marker
	// then took seq 4. A resume that failed to read the tail would have restarted at
	// genesis instead, reissuing seqs 1..3.
	if sink.seq != 4 {
		t.Fatalf("resumed seq = %d, want 4 (tail seq 3 plus the tail_partial_write_recovered marker)", sink.seq)
	}
	if sink.prevHMAC == "" || sink.prevHMAC == auditGenesisPrev {
		t.Fatalf("prevHMAC = %q, want the resumed tail's chain link (not genesis)", sink.prevHMAC)
	}
	data, err := os.ReadFile(logPath) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if bytes.Contains(data, []byte(`"partial`)) {
		t.Fatal("the orphan fragment must be gone after recovery")
	}
	if !bytes.Contains(data, []byte("tail_partial_write_recovered")) {
		t.Fatalf("expected a tail_partial_write_recovered marker; log:\n%s", data)
	}
}
