// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// White-box tests for the audit writer core (audit.go): the async sink, record
// bounding, key load/parse, the tamper-evident chain as produced by the writer,
// and the detail/envelope/obligations caps.

package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"

	"github.com/eunolabs/eunox/pkg/capability"
)

// bigInt is 2^53 + 1: the smallest positive integer that float64 cannot
// represent exactly. A naive json.Unmarshal/Marshal round-trip in VerifyRecord
// would coerce it to float64 and rewrite it as 9007199254740992, changing the
// bytes and breaking the HMAC.
const bigInt int64 = 9007199254740993

// TestAuditChain_TrailingDataIsInvalid is the regression for the trailing-data
// gap surfaced in review: appending bytes after a valid signed record
// must be caught as INVALID. Decoder.Decode stops at the end of the record and
// ignores trailing bytes, and VerifyRecord re-signs the decoded fields, so
// without the !dec.More() guard a {…record…}GARBAGE line would slip past both the
// unmarshal gate and the HMAC check and the log would falsely verify clean.
func TestAuditChain_TrailingDataIsInvalid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b", "c")
	lines := logLines(t, logPath)
	// Append trailing garbage after the second record's closing brace.
	lines[1] = append(append([]byte{}, lines[1]...), []byte("GARBAGE")...)

	res := verifyBytes(t, lines, verifierFor(t, keyPath))
	if res.OK() {
		t.Fatalf("expected verification to fail for a record line with trailing data: %+v", res)
	}
	if res.Invalid < 1 {
		t.Errorf("expected at least one invalid record, got %+v", res)
	}
}

// TestAuditChain_ValidLogPasses confirms an untampered chain verifies cleanly:
// every record valid, no chain breaks, seq starts at 1.
func TestAuditChain_ValidLogPasses(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b", "c", "d", "e")
	res := verifyBytes(t, logLines(t, logPath), verifierFor(t, keyPath))

	if !res.OK() {
		t.Fatalf("expected clean log to pass: %+v", res)
	}
	if res.Total != 5 || res.Valid != 5 || res.Invalid != 0 || res.ChainBreaks != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.FirstSeq != 1 {
		t.Fatalf("expected firstSeq=1, got %d", res.FirstSeq)
	}
}

// TestAuditChain_DetectsInteriorDeletion is the F1 regression: deleting the
// records of an attacker's calls must now break the chain (per-record HMAC alone
// could not catch this).
func TestAuditChain_DetectsInteriorDeletion(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "list", "read", "exfiltrate", "delete_backups", "read")
	lines := logLines(t, logPath)

	// Delete records #3 and #4 (indices 2,3): the "unauthorized" calls.
	tampered := [][]byte{lines[0], lines[1], lines[4]}
	res := verifyBytes(t, tampered, verifierFor(t, keyPath))

	if res.OK() {
		t.Fatalf("deletion went undetected: %+v", res)
	}
	if res.ChainBreaks == 0 {
		t.Fatalf("expected a chain break from deletion, got none: %+v", res)
	}
	// The surviving records are still individually valid — proving the detection
	// comes from the chain, not from per-record HMAC.
	if res.Invalid != 0 {
		t.Fatalf("surviving records should be individually valid; got invalid=%d", res.Invalid)
	}
}

// TestAuditChain_InteriorDeletionReportsBothBreakAndGap is the regression for
// the chain-break switch that masked the seq gap: deleting interior records
// trips both the prev_hmac mismatch and the seq gap, and audit-verify must count
// and print BOTH so an auditor can size the deletion from the output alone.
func TestAuditChain_InteriorDeletionReportsBothBreakAndGap(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b", "c", "d", "e") // seq 1..5
	lines := logLines(t, logPath)

	// Delete records #3 and #4 (indices 2,3), leaving seq 1,2,5.
	tampered := [][]byte{lines[0], lines[1], lines[4]}
	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join(tampered, []byte("\n"))),
		verifierFor(t, keyPath), "", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if res.ChainBreaks != 2 {
		t.Fatalf("expected 2 chain breaks (prev_hmac mismatch + seq gap), got %d: %+v", res.ChainBreaks, res)
	}
	out := sb.String()
	if !strings.Contains(out, "CHAIN BREAK at seq 5") {
		t.Fatalf("missing CHAIN BREAK diagnostic; output:\n%s", out)
	}
	if !strings.Contains(out, "SEQ GAP: record seq 5 does not follow 2") {
		t.Fatalf("missing SEQ GAP diagnostic (the switch-masking bug is present); output:\n%s", out)
	}
}

// TestAuditChain_LegacyPreSigningRecordsExempt is the regression: records
// written before HMAC signing existed carry no _hmac and no seq, so they decode
// with HMAC=="" and Seq==0. audit-verify must NOT report them as INVALID (there
// is no HMAC to verify) nor emit a spurious SEQ GAP between consecutive Seq=0
// records, mirroring the exemption openAuditSink already grants when resuming a
// legacy tail. The post-upgrade signed records must still verify and chain.
func TestAuditChain_LegacyPreSigningRecordsExempt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// Two pre-signing legacy records: valid JSON, but no "seq" and no "_hmac".
	legacy := `{"request_id":"legacy-1","activity_name":"tools/call","session_id":"s","target":"a"}` + "\n" +
		`{"request_id":"legacy-2","activity_name":"tools/call","session_id":"s","target":"b"}` + "\n"
	if err := os.WriteFile(logPath, []byte(legacy), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Upgrade: a signing sink resumes onto the legacy tail (prev_hmac "") and
	// appends three signed records (seq 1..3).
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	for _, tool := range []string{"c", "d", "e"} {
		sink.RecordAllow(context.Background(), "sess", tool, "tools/call", nil, nil, false, nil, nil)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join(logLines(t, logPath), []byte("\n"))),
		verifierFor(t, keyPath), "", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if !res.OK() {
		t.Fatalf("a legacy+signed log must pass; output:\n%s\nresult: %+v", sb.String(), res)
	}
	if res.Legacy != 2 {
		t.Fatalf("expected legacy=2, got %+v", res)
	}
	if res.Valid != 4 {
		// 3 appended records + the signed legacy_tail_resumed integrity marker
		// openAuditSink now writes when it resumes onto an unsigned (legacy) tail.
		t.Fatalf("expected valid=4 (3 signed records + 1 legacy_tail_resumed marker), got %+v", res)
	}
	if res.Invalid != 0 {
		t.Fatalf("legacy records must not be counted invalid: %+v\noutput:\n%s", res, sb.String())
	}
	if res.ChainBreaks != 0 {
		t.Fatalf("no spurious chain breaks across the upgrade boundary: %+v\noutput:\n%s", res, sb.String())
	}
	if res.FirstSeq != 0 {
		t.Fatalf("the first record is a legacy record (seq 0); got firstSeq=%d", res.FirstSeq)
	}
}

// TestAuditChain_MalformedLineInvalidUnderFilter is the regression: a
// corrupted (non-JSON) line must be counted invalid even when a reporting filter
// is active. The reporting filter is display-only and must never downgrade a
// corrupted line to a silent "skipped", which previously produced a false PASS.
func TestAuditChain_MalformedLineInvalidUnderFilter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b", "c") // seq 1..3
	lines := logLines(t, logPath)

	// Corrupt the LAST record so no following valid record trips a chain break —
	// this isolates the per-record invalid accounting from chain detection.
	lines[2] = []byte("not valid json {{{")

	var sb strings.Builder
	// A request-id filter that matches no record. Under the old code every valid
	// record is skipped AND the corrupted line is skipped by the filter before
	// VerifyRecord runs, so invalid stays 0 and ok() falsely reports PASS.
	res, err := VerifyLog(bytes.NewReader(bytes.Join(lines, []byte("\n"))),
		verifierFor(t, keyPath), "no-such-request-id", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if res.OK() {
		t.Fatalf("corrupted line under a filter must NOT pass: %+v", res)
	}
	if res.Invalid != 1 {
		t.Fatalf("expected the malformed line counted invalid=1, got %+v", res)
	}
	if res.ChainBreaks != 0 {
		t.Fatalf("a trailing corruption should not trip a chain break; got %+v", res)
	}
	if !strings.Contains(sb.String(), "malformed record") {
		t.Fatalf("missing malformed-record diagnostic; output:\n%s", sb.String())
	}
}

// TestAuditChain_PerRecordHMACVerifiedUnderSinceFilter is the regression: a
// record whose content is modified while its _hmac is left intact must be caught
// as invalid even when a --since filter would exclude it from the report window.
// The chain check only compares the stored HMAC against the next record's
// prev_hmac and never recomputes it from content, so gating VerifyRecord behind
// --since previously let an attacker edit any record older than the
// investigator's --since value undetected (audit-verify exited 0).
//
// A tampered record whose per-record HMAC verification fails is treated as an
// untrustworthy chain anchor: its stored _hmac is the HMAC of the original
// (pre-tamper) content, not the current content, so it cannot reliably link the
// chain. VerifyLog therefore reports a chain break at the record immediately
// following the invalid one, in addition to counting the tampered record invalid.
func TestAuditChain_PerRecordHMACVerifiedUnderSinceFilter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b", "c") // seq 1..3
	lines := logLines(t, logPath)

	// Tamper the FIRST record's content (change its target) while preserving its
	// stored _hmac, exactly as an attacker editing a historical record would.
	var rec auditRecord
	if err := json.Unmarshal(lines[0], &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rec.Target = "tampered"
	tamperedLine, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	lines[0] = tamperedLine

	// A --since far in the future excludes every record from the report window.
	// Under the old code VerifyRecord was skipped for filtered records, so the
	// tampered record was never recomputed and audit-verify falsely PASSED.
	future := time.Now().Add(24 * time.Hour)
	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join(lines, []byte("\n"))),
		verifierFor(t, keyPath), "", future, &sb)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if res.OK() {
		t.Fatalf("content tampering under a --since filter must NOT pass: %+v\noutput:\n%s", res, sb.String())
	}
	if res.Invalid != 1 {
		t.Fatalf("expected the tampered record counted invalid=1, got %+v", res)
	}
	// A record that fails per-record HMAC verification is an untrustworthy chain
	// anchor; the verifier reports a chain break at the next record even though its
	// prev_hmac happens to match the preserved (but now-invalid) _hmac value.
	if res.ChainBreaks != 1 {
		t.Fatalf("expected chainBreaks=1 (preceding invalid record is untrustworthy anchor), got %+v\noutput:\n%s", res, sb.String())
	}
	// The two untouched records are verified OK but outside the report window, so
	// they are counted skipped (display-only), not valid.
	if res.Skipped != 2 {
		t.Fatalf("expected the 2 untampered records counted skipped, got %+v", res)
	}
}

// TestAuditChain_MalformedLineDoesNotPoisonChain is the regression:
// a line that fails json.Unmarshal (disk corruption, mid-write truncation, a
// non-JSON marker) decodes to the zero auditRecord (HMAC="", Seq=0). It must not
// be adopted as the chain's prev state, or the next valid record would be checked
// against "" / 0 and report spurious chain breaks. The malformed line is still
// caught by per-record HMAC verification (counted invalid) — it just no longer
// fabricates chain breaks at its own position.
func TestAuditChain_MalformedLineDoesNotPoisonChain(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b", "c") // seq 1,2,3
	lines := logLines(t, logPath)

	// Corrupt the LAST line into non-JSON garbage. Before the fix this produced
	// two spurious chain breaks (prev_hmac mismatch + seq gap) because the zeroed
	// record's HMAC/Seq were adopted as prev state; the line itself was the end of
	// the log, so there is no genuine following gap to report.
	tampered := [][]byte{lines[0], lines[1], []byte("GARBAGE-NOT-JSON")}
	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join(tampered, []byte("\n"))),
		verifierFor(t, keyPath), "", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if res.ChainBreaks != 0 {
		t.Fatalf("malformed line poisoned chain state: got %d spurious chain breaks\n%s", res.ChainBreaks, sb.String())
	}
	// The corruption is still detected — the malformed line fails its HMAC.
	if res.Invalid != 1 {
		t.Fatalf("expected the malformed line to count as 1 invalid record, got %d", res.Invalid)
	}
	if res.Valid != 2 {
		t.Fatalf("expected the 2 intact records to verify, got valid=%d", res.Valid)
	}
}

// TestAuditChain_FilterDoesNotDisableChainCheck is the regression for the
// chain check being silently skipped whenever a --request-id/--since filter was
// active: an attacker could hide an interior deletion just by getting the
// investigator to pass a filter. The chain must be verified over every record
// regardless of the filter; the filter narrows only per-record HMAC reporting.
func TestAuditChain_FilterDoesNotDisableChainCheck(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b", "c", "d", "e")
	lines := logLines(t, logPath)
	tampered := [][]byte{lines[0], lines[1], lines[4]} // delete seq 3,4

	// A --request-id filter that matches nothing must still catch the deletion.
	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join(tampered, []byte("\n"))),
		verifierFor(t, keyPath), "req-nomatch", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if res.ChainBreaks == 0 {
		t.Fatalf("filter disabled chain verification — deletion went undetected: %+v\n%s", res, sb.String())
	}
	// And a since filter that matches nothing must likewise still catch it.
	sb.Reset()
	res, err = VerifyLog(bytes.NewReader(bytes.Join(tampered, []byte("\n"))),
		verifierFor(t, keyPath), "", time.Now().Add(24*time.Hour), &sb)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if res.ChainBreaks == 0 {
		t.Fatalf("since filter disabled chain verification — deletion went undetected: %+v\n%s", res, sb.String())
	}
}

// TestAuditChain_DetectsReordering confirms swapping records breaks the chain.
func TestAuditChain_DetectsReordering(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b", "c", "d")
	lines := logLines(t, logPath)

	reordered := [][]byte{lines[0], lines[2], lines[1], lines[3]} // swap b and c
	res := verifyBytes(t, reordered, verifierFor(t, keyPath))

	if res.OK() || res.ChainBreaks == 0 {
		t.Fatalf("reordering went undetected: %+v", res)
	}
}

// TestAuditChain_SeqAndPrevAreSigned confirms the chain fields are covered by
// the HMAC: editing seq or prev_hmac makes the record fail per-record
// verification (so an attacker cannot rewrite the chain without the key).
func TestAuditChain_SeqAndPrevAreSigned(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b")
	verifier := verifierFor(t, keyPath)
	lines := logLines(t, logPath)

	for _, tc := range []struct {
		name string
		from string
		to   string
	}{
		{"forged seq", `"seq":2`, `"seq":99`},
		{"forged prev_hmac", `"prev_hmac":"sha256:genesis"`, `"prev_hmac":"sha256:deadbeef"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			edited := strings.Replace(string(lines[len(lines)-1]), tc.from, tc.to, 1)
			if tc.from == `"prev_hmac":"sha256:genesis"` {
				edited = strings.Replace(string(lines[0]), tc.from, tc.to, 1)
			}
			ok, err := verifier.VerifyRecord([]byte(edited))
			if err != nil {
				t.Fatalf("VerifyRecord: %v", err)
			}
			if ok {
				t.Fatalf("%s: tampered chain field still verified — seq/prev_hmac not signed", tc.name)
			}
		})
	}
}

// TestAuditChain_ResumesAcrossReopen confirms the chain is continuous across a
// process restart: reopening the sink continues seq numbering and links the
// first new record to the last old record's _hmac.
func TestAuditChain_ResumesAcrossReopen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b") // seq 1,2

	// Reopen and append two more.
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess", "c", "tools/call", nil, nil, false, nil, nil)
	sink.RecordAllow(context.Background(), "sess", "d", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	res := verifyBytes(t, logLines(t, logPath), verifierFor(t, keyPath))
	if !res.OK() {
		t.Fatalf("reopened chain should verify cleanly: %+v", res)
	}
	if res.Total != 4 || res.ChainBreaks != 0 {
		t.Fatalf("expected 4 records, no breaks: %+v", res)
	}
}

// TestAuditChain_ResumesFromLegacyTail is the regression: resuming from a
// pre-chain record (no _hmac) must chain the first appended record onto it with
// an empty prev_hmac — not the genesis sentinel — so audit-verify sees a
// continuous chain across the upgrade boundary instead of a spurious break. Both
// a pre-seq legacy tail (seq 0, indistinguishable from a fresh log by seq alone)
// and a seq-bearing legacy tail must resume cleanly. The resume also writes a
// signed legacy_tail_resumed integrity marker as the first appended record so the
// (unverifiable) splice point is recorded on the tamper-evident trail.
func TestAuditChain_ResumesFromLegacyTail(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		withSeq bool
		wantSeq uint64 // seq stamped on the first appended record
	}{
		{"pre-seq legacy tail (seq 0)", false, 1},
		{"seq-bearing legacy tail", true, 42},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			logPath := filepath.Join(dir, "audit.jsonl")
			keyPath := filepath.Join(dir, "audit.key")
			writeLegacyTail(t, logPath, tc.withSeq)

			// Resume from the legacy tail and append two signed records.
			sink, err := Open(logPath, keyPath, 0, 0)
			if err != nil {
				t.Fatalf("openAuditSink: %v", err)
			}
			sink.RecordAllow(context.Background(), "sess", "newtool", "tools/call", nil, nil, false, nil, nil)
			sink.RecordAllow(context.Background(), "sess", "newtool2", "tools/call", nil, nil, false, nil, nil)
			if err := sink.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			lines := logLines(t, logPath)
			// 1 legacy tail + 1 legacy_tail_resumed integrity marker (the first
			// appended record, chained from the legacy tail) + 2 appended records.
			if len(lines) != 4 {
				t.Fatalf("expected 4 lines (1 legacy + 1 marker + 2 appended), got %d", len(lines))
			}

			// The crux of the fix: the first appended record (now the
			// legacy_tail_resumed marker) links to the legacy tail with an empty
			// prev_hmac, not the genesis sentinel.
			var first auditRecord
			if err := json.Unmarshal(lines[1], &first); err != nil {
				t.Fatalf("unmarshal first appended record: %v", err)
			}
			if first.PrevHMAC == auditGenesisPrev {
				t.Fatalf("first appended record carries the genesis sentinel — the bug is present")
			}
			if first.PrevHMAC != "" {
				t.Fatalf("first appended record prev_hmac = %q, want \"\" (legacy chain continuation)", first.PrevHMAC)
			}
			if first.Seq != tc.wantSeq {
				t.Fatalf("first appended record seq = %d, want %d", first.Seq, tc.wantSeq)
			}

			// Verifying the full log (legacy + appended) reports no chain break.
			// The legacy line itself lands in the Legacy bucket (not Invalid) — it
			// predates signing and has no HMAC to verify — regardless of whether it
			// happens to carry a seq value: the writer's own resume rule (Open) is
			// seq-independent, so audit-verify must classify both shapes identically
			// or the two components disagree on what the same on-disk record means.
			// A prior regression here checked only ChainBreaks, so a seq-bearing
			// legacy tail being wrongly counted Invalid (and flipping the whole-log
			// verdict to FAILED) went unnoticed; assert OK()/Invalid/Legacy directly
			// so that gap cannot reopen.
			full := verifyBytes(t, lines, verifierFor(t, keyPath))
			if full.ChainBreaks != 0 {
				t.Fatalf("spurious chain break across the legacy boundary: %+v", full)
			}
			if !full.OK() {
				t.Fatalf("the legacy tail must not flip the whole-log verdict to FAILED: %+v", full)
			}
			if full.Legacy != 1 || full.Invalid != 0 {
				t.Fatalf("expected exactly the legacy tail counted Legacy and nothing Invalid: %+v", full)
			}

			// The appended records on their own (the legacy_tail_resumed marker plus
			// the two tool records) form a clean, verifiable chain.
			appended := verifyBytes(t, lines[1:], verifierFor(t, keyPath))
			if !appended.OK() {
				t.Fatalf("appended records should verify cleanly: %+v", appended)
			}
			if appended.Valid != 3 || appended.ChainBreaks != 0 {
				t.Fatalf("expected 3 valid appended records (marker + 2 tools), no breaks: %+v", appended)
			}
		})
	}
}

// TestAuditChain_ResumedLegacyTailClearedAfterOpen pins the fix binding the
// empty-prev_hmac emission strictly to the legacy_tail_resumed marker. writeRecord's
// resumedLegacyTail branch emits prev_hmac=="" for whatever record first finds
// s.prevHMAC=="". If the marker write fails (seq/prevHMAC do not advance) and the
// flag stayed set, the NEXT ordinary record would inherit seq 1 with an empty
// prev_hmac while NOT being the marker — the shape a later audit-verify reports as a
// spurious chain break. Clearing the flag after the marker write attempt routes any
// such record through the genesis branch instead, so verify sees a clean seq-1
// genesis start. This asserts the flag is cleared once Open returns.
func TestAuditChain_ResumedLegacyTailClearedAfterOpen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	writeLegacyTail(t, logPath, false)

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = sink.Close() }()

	// The clear happens in Open, before the drainer goroutine starts, so this read is
	// not racing a writer.
	if sink.resumedLegacyTail {
		t.Fatal("resumedLegacyTail must be cleared after Open's marker write attempt, so a failed marker cannot hand its empty-prev_hmac seq-1 slot to an ordinary record")
	}
}

// TestVerify_GenesisSeq1AfterLegacyHead covers the legacy->signed transition shapes:
// a bare genesis seq-1 record following a head legacy (unsigned) record does NOT chain
// break (the link check accepts it), but it FAILS the verdict as LegacyUnanchored,
// because that shape is indistinguishable from fabricated unsigned records prepended by
// a write-capable attacker without the key. A lone genesis seq-1 (legacy rotated away)
// still verifies clean, and a genesis-sentinel seq-1 following a SIGNED record must
// still break, so tamper detection is preserved.
func TestVerify_GenesisSeq1AfterLegacyHead(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")

	// A fresh signed log's sole record is seq 1 with prev_hmac = genesis sentinel.
	freshPath := filepath.Join(dir, "fresh.jsonl")
	s, err := Open(freshPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.RecordAllow(context.Background(), "sess", "tool", "tools/call", nil, nil, false, nil, nil)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	fresh := logLines(t, freshPath)
	if len(fresh) != 1 {
		t.Fatalf("want 1 fresh line, got %d", len(fresh))
	}

	legPath := filepath.Join(dir, "leg.jsonl")
	writeLegacyTail(t, legPath, false)
	leg := logLines(t, legPath)

	// Not-yet-rotated: [legacy head, genesis seq-1 signed] does not chain break, but the
	// verdict fails closed (LegacyUnanchored) — the marker-write-failed fallback and the
	// prepend-forgery attack are the same shape.
	notRotated := append(append([][]byte{}, leg...), fresh...)
	res := verifyBytes(t, notRotated, verifierFor(t, keyPath))
	if res.ChainBreaks != 0 {
		t.Fatalf("legacy head + genesis seq-1 must not chain break, got ChainBreaks=%d", res.ChainBreaks)
	}
	if !res.LegacyUnanchored || res.OK() {
		t.Fatalf("legacy head + genesis seq-1 must fail the verdict as LegacyUnanchored, got LegacyUnanchored=%v OK=%v", res.LegacyUnanchored, res.OK())
	}

	// Rotated-away: [genesis seq-1 signed] alone must verify clean (no legacy head).
	if res := verifyBytes(t, fresh, verifierFor(t, keyPath)); res.ChainBreaks != 0 || !res.OK() {
		t.Fatalf("lone genesis seq-1 must verify clean, got ChainBreaks=%d OK=%v", res.ChainBreaks, res.OK())
	}

	// Detection preserved: a genesis-sentinel seq-1 record following a SIGNED record
	// (not a legacy head) must still be reported as a chain break.
	afterSigned := append(append([][]byte{}, fresh...), fresh...)
	if res := verifyBytes(t, afterSigned, verifierFor(t, keyPath)); res.ChainBreaks == 0 {
		t.Fatal("a genesis-sentinel seq-1 record following a signed record must still break")
	}
}

// TestVerify_ForgedLegacyPrependFailsVerdict is the H1 regression: a write-capable
// attacker WITHOUT the signing key prepends fabricated unsigned "legacy" records ahead
// of an ordinary signed log (first record seq 1, prev_hmac = genesis sentinel). No
// CHAIN BREAK fires (the forged legacy head links to the genuine genesis seq-1 via the
// legacy->signed acceptance), but the verdict must NOT report PASS.
func TestVerify_ForgedLegacyPrependFailsVerdict(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")

	// A normal signed log whose first record is a genesis seq-1 record.
	signedPath := filepath.Join(dir, "signed.jsonl")
	s, err := Open(signedPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.RecordAllow(context.Background(), "sess", "tool", "tools/call", nil, nil, false, nil, nil)
	s.RecordDeny(context.Background(), "sess", "danger", "tools/call", "AUTHORIZATION_FAILED", "", nil, false)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	signed := logLines(t, signedPath)

	// The attacker (no key) fabricates unsigned legacy records and prepends them.
	forged := [][]byte{
		[]byte(`{"activity_id":1,"time":"2020-01-01T00:00:00Z","metadata":{"product":{"name":"eunox"}},"unmapped":{"session_id":"sess","target":"backdoor","method":"tools/call"}}`),
	}
	tampered := append(append([][]byte{}, forged...), signed...)
	res := verifyBytes(t, tampered, verifierFor(t, keyPath))
	if res.OK() {
		t.Fatal("a forged unsigned legacy prepend ahead of a signed log must NOT verify PASS")
	}
	if !res.LegacyUnanchored {
		t.Fatalf("forged legacy prepend must be flagged LegacyUnanchored, got %+v", res)
	}
}

// TestWriteRecord_PartialWrite_TargetBelowZero_SetsTailOrphanPending covers the
// guard fall-through on the partial-write orphan-truncation path: when a partial
// write reports more bytes than the file actually holds (target = fileSize - n < 0,
// the double-fault sibling of a failing Stat), truncation cannot establish the
// clean record boundary. This must mark the tail pending (retried before every
// subsequent write) rather than force a rotation via s.written = maxBytes — a
// forced rotation can itself fail and would leave the same un-terminated orphan on
// the same fd for the next O_APPEND write to fuse a full record line onto.
// Injecting a writeLine that reports a positive n without writing makes the on-disk
// size (0) smaller than n, driving target below zero.
func TestWriteRecord_PartialWrite_TargetBelowZero_SetsTailOrphanPending(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// writeLine set before any record is sent, so the channel send/recv establishes
	// happens-before with the drainer's read (matching the other writeLine-seam tests).
	sink.writeLine = func(_ []byte) (int, error) {
		return 100, errors.New("partial write (ENOSPC)")
	}
	sink.RecordAllow(context.Background(), "sess", "tool", "tools/call", nil, nil, false, nil, nil)
	_ = sink.Close() // drains and waits for the drainer to exit

	// After Close the drainer has exited, so reading these fields is race-free.
	// tailOrphanBytes > 0 is the pending flag (an unrepairable orphan of that size).
	if sink.tailOrphanBytes != 100 {
		t.Fatalf("sink.tailOrphanBytes = %d, want 100 (the pending unrepairable orphan)", sink.tailOrphanBytes)
	}
	if sink.written == sink.maxBytes {
		t.Fatalf("sink.written = %d; must NOT be force-set to maxBytes anymore (that signal let a subsequent failed rotation append onto the same orphaned fd)", sink.written)
	}
}

// TestAuditChain_EmptyLog confirms an empty log yields zero records and no
// failure (exit 0), matching the documented "indistinguishable from truncated"
// caveat.
func TestAuditChain_EmptyLog(t *testing.T) {
	t.Parallel()
	res, err := VerifyLog(bytes.NewReader(nil), &Sink{key: nonZeroTestKey()}, "", time.Time{}, &strings.Builder{})
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if res.Total != 0 || !res.OK() {
		t.Fatalf("empty log: expected 0 records and ok, got %+v", res)
	}
}

// TestAuditSink_RecordClonesDetailsAndObligations verifies that Record snapshots
// the caller's details map and obligations slice at call time, so a caller that
// mutates those structures after Record returns cannot alter (or corrupt) the
// record the drainer ultimately writes. The channel send copies the auditRecord
// value but not the backing map/slice, so without the clone the written record
// would reflect the post-Record mutation.
//
// The drainer is gated with the writeLine seam so the assertion is deterministic
// rather than racing the background goroutine: a warm-up record parks the drainer
// inside its first write, the record under test is enqueued behind it (still
// unmarshaled), the caller's structures are mutated, and only then is the drainer
// released to marshal the test record. With the clone the marshaled record holds
// the original values; without it, it would hold the mutated ones.
func TestAuditSink_RecordClonesDetailsAndObligations(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	// Gate the drainer: the first write blocks until released, signaling once it
	// is parked so the test knows the warm-up record (not the record under test)
	// is the one being held. Every write still goes to the real file so both
	// records are persisted and readable afterwards.
	var once sync.Once
	entered := make(chan struct{})
	release := make(chan struct{})
	sink.writeLine = func(b []byte) (int, error) {
		once.Do(func() {
			close(entered)
			<-release
		})
		return sink.f.Write(b)
	}

	// Warm-up record: the drainer marshals it, then parks in writeLine.
	sink.RecordAllow(context.Background(), "sess", "warmup", "tools/call", nil, nil, false, nil, nil)
	<-entered

	// Include nested containers (a JSON object and array, as arbitrary tool-call
	// arguments routinely do) so the test also guards the deep, not just shallow,
	// copy: a shallow clone would leave these aliased with the caller.
	details := map[string]interface{}{
		"path":   "/etc/passwd",
		"count":  float64(1),
		"nested": map[string]interface{}{"secret": "keep"},
		"list":   []interface{}{"a", []interface{}{"deep"}},
	}
	obligs := []string{"redactFields"}

	// Enqueued behind the parked warm-up record: not yet marshaled.
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", details, obligs, true, nil, nil)

	// Mutate the caller's structures, top-level and nested. With the deep clone
	// none of these reach the queued record; without it the drainer would
	// serialize them.
	details["path"] = "MUTATED"
	details["injected"] = true
	delete(details, "count")
	details["nested"].(map[string]interface{})["secret"] = "MUTATED"
	details["list"].([]interface{})[0] = "MUTATED"
	details["list"].([]interface{})[1].([]interface{})[0] = "MUTATED"
	obligs[0] = "MUTATED"

	// Release the drainer: it now marshals the test record, strictly after the
	// mutations above (close happens-before the drainer's resumed receive).
	close(release)

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	if len(lines) != 2 {
		t.Fatalf("expected 2 audit records (warmup + test), got %d", len(lines))
	}

	// The second record is the one under test.
	var rec auditRecord
	if err := json.Unmarshal(lines[1], &rec); err != nil {
		t.Fatalf("unmarshal record: %v", err)
	}
	if rec.Target != "read_file" {
		t.Fatalf("second record target = %q; want read_file", rec.Target)
	}

	recDetails := recordDetails(t, rec)
	if got := recDetails["path"]; got != "/etc/passwd" {
		t.Errorf("details[path] = %v; want /etc/passwd (caller mutation leaked into the record)", got)
	}
	if got, ok := recDetails["count"]; !ok || got != float64(1) {
		t.Errorf("details[count] = %v (present=%v); want 1 (caller deletion leaked into the record)", got, ok)
	}
	if _, ok := recDetails["injected"]; ok {
		t.Errorf("details[injected] present; caller-added key leaked into the record")
	}
	// Nested object and array values must reflect the originals: a shallow copy
	// would let the post-Record nested mutations leak into the signed record.
	if nested, ok := recDetails["nested"].(map[string]interface{}); !ok || nested["secret"] != "keep" {
		t.Errorf("details[nested][secret] = %v (ok=%v); want keep (nested caller mutation leaked into the record)", recDetails["nested"], ok)
	}
	if list, ok := recDetails["list"].([]interface{}); !ok || len(list) != 2 || list[0] != "a" {
		t.Errorf("details[list][0] = %v (ok=%v); want a (nested caller mutation leaked into the record)", recDetails["list"], ok)
	} else if inner, ok := list[1].([]interface{}); !ok || len(inner) != 1 || inner[0] != "deep" {
		t.Errorf("details[list][1] = %v; want [deep] (deeply nested caller mutation leaked into the record)", list[1])
	}
	if len(rec.Obligations) != 1 || rec.Obligations[0] != "redactFields" {
		t.Errorf("obligations = %v; want [redactFields] (caller mutation leaked into the record)", rec.Obligations)
	}

	// Cloning happens before signing, so the HMAC covers the snapshot and the log
	// still verifies end to end.
	verifier := verifierFor(t, keyPath)
	res := verifyBytes(t, lines, verifier)
	if !res.OK() {
		t.Errorf("audit log failed verification after clone: %+v", res)
	}
}

// TestAuditDrain_NilFile covers the s.f == nil continue branch inside drain.
// We trigger it by setting maxBytes=1 and then explicitly closing the file
// pointer to simulate a failed rotation.
func TestAuditDrain_NilFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := dir + "/audit.jsonl"

	sink, err := Open(logPath, dir+"/audit.key", 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	// Forcibly set s.f to nil to simulate a failed-rotation scenario.
	// The next record that lands in drain must hit the `continue` branch.
	sink.f = nil

	// Write a record — drain will see s.f == nil and continue.
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)

	if err := sink.Close(); err != nil {
		// Close may fail if f is nil; that is expected here.
		_ = err
	}
}

// TestAuditRotate_RenameError covers the rename-error branch in rotate()
// by removing the log file before calling rotate.
func TestAuditRotate_RenameError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := dir + "/audit.jsonl"

	sink, err := Open(logPath, dir+"/audit.key", 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	// Remove the log file so os.Rename fails.
	_ = sink.f.Close()
	_ = os.Remove(logPath)
	sink.f = nil

	// Calling rotate with nil f triggers the nil guard.
	sink.rotate()
}

// TestAuditRecord_DropsWhenQueueFull covers the default: s.dropped.Add(1)
// branch in Record() by creating a sink with a 0-capacity channel (no
// drainer started) so every enqueue hits the default branch.
func TestAuditRecord_DropsWhenQueueFull(t *testing.T) {
	t.Parallel()
	// Build an Sink directly without starting the drainer goroutine.
	// A 0-capacity channel means the first send always blocks → hits default.
	key := nonZeroTestKey() // 32-byte HMAC key
	s := &Sink{
		key:     key,
		records: make(chan auditRecord), // zero-capacity → always full
	}
	s.RecordAllow(context.Background(), "sess", "tool", "tools/call", nil, nil, false, nil, nil)
	if s.DroppedRecords() != 1 {
		t.Errorf("expected 1 dropped record, got %d", s.DroppedRecords())
	}
}

// TestAuditDropMarker_RecordsDropAndChainStaysValid verifies that records
// dropped under back-pressure are made visible as an explicit, signed
// "AUDIT_RECORDS_DROPPED" marker in the chain — so a flood-induced gap cannot
// pass audit-verify as a clean log — while the tamper-evident chain still
// verifies end to end (the marker is itself a chained, signed record).
func TestAuditDropMarker_RecordsDropAndChainStaysValid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := dir + "/audit.jsonl"
	sink, err := Open(logPath, dir+"/audit.key", 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	// First real record establishes the chain.
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	// Simulate two records lost under back-pressure.
	sink.dropped.Store(2)
	// Next real record: the drainer emits a drop marker before writing it (or the
	// final flush at Close does), accounting the loss exactly once.
	sink.RecordDeny(context.Background(), "sess", "write_file", "tools/call", "CAPABILITY_DENIED", "", nil, false)

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	markers := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var rec auditRecord
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec.DenialCode == "AUDIT_RECORDS_DROPPED" {
			markers++
			if recordDetails(t, rec)["dropped"] == nil {
				t.Errorf("drop marker missing dropped count: %s", rec.Details)
			}
		}
	}
	if markers != 1 {
		t.Fatalf("expected exactly 1 drop marker, got %d", markers)
	}

	// The chain must still verify end to end.
	res, err := VerifyLog(bytes.NewReader(data), sink, "", time.Time{}, io.Discard)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if !res.OK() {
		t.Errorf("chain verification failed after drop marker: %+v", res)
	}
}

// TestAuditDropMarker_NamesAffectedMethodTarget verifies the AUDIT_RECORDS_DROPPED
// marker carries a by_method_target breakdown alongside the aggregate count, so an
// operator can act on which method/target pairs were affected by the loss without
// the underlying dropped record's content.
func TestAuditDropMarker_NamesAffectedMethodTarget(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := dir + "/audit.jsonl"
	sink, err := Open(logPath, dir+"/audit.key", 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	// Simulate what the real enqueue-path drops in Record would produce: the
	// aggregate counter plus the per-method/target tally recordDropBucket
	// accumulates alongside it. The simulated state must be complete BEFORE the
	// first record is enqueued: the drainer runs flushDropMarker before writing
	// every drained record, and only the channel send orders these stores ahead
	// of that flush. Enqueuing first races the flush against the stores below —
	// a mid-store snapshot emits a marker with a partial bucket breakdown,
	// advances lastDroppedMarked past the aggregate count, and orphans the
	// remaining buckets with no later marker to carry them.
	sink.dropped.Store(3)
	sink.recordDropBucket("tools/call", "probe_tool")
	sink.recordDropBucket("tools/call", "probe_tool")
	sink.recordDropBucket("resources/read", "file:///etc/passwd")
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	sink.RecordDeny(context.Background(), "sess", "write_file", "tools/call", "CAPABILITY_DENIED", "", nil, false)

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	found := false
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var rec auditRecord
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec.DenialCode != "AUDIT_RECORDS_DROPPED" {
			continue
		}
		found = true
		details := recordDetails(t, rec)
		buckets, ok := details["by_method_target"].(map[string]interface{})
		if !ok {
			t.Fatalf("drop marker missing by_method_target buckets: %s", rec.Details)
		}
		if buckets["tools/call probe_tool"] != float64(2) {
			t.Errorf("expected 2 drops for %q, got %v (all: %v)", "tools/call probe_tool", buckets["tools/call probe_tool"], buckets)
		}
		if buckets["resources/read file:///etc/passwd"] != float64(1) {
			t.Errorf("expected 1 drop for %q, got %v (all: %v)", "resources/read file:///etc/passwd", buckets["resources/read file:///etc/passwd"], buckets)
		}
	}
	if !found {
		t.Fatalf("no AUDIT_RECORDS_DROPPED marker found")
	}

	res, err := VerifyLog(bytes.NewReader(data), sink, "", time.Time{}, io.Discard)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if !res.OK() {
		t.Errorf("chain verification failed after drop marker with buckets: %+v", res)
	}
}

// TestRecordDropBucket_CapsDistinctBuckets verifies the drop-bucket accumulator
// bounds itself: beyond auditDropBucketCap distinct method/target pairs, further
// distinct pairs fold into the single dropBucketOverflowKey bucket rather than
// growing the map without bound.
func TestRecordDropBucket_CapsDistinctBuckets(t *testing.T) {
	t.Parallel()
	s := &Sink{}
	const overflow = 5
	for i := 0; i < auditDropBucketCap+overflow; i++ {
		s.recordDropBucket("tools/call", fmt.Sprintf("tool-%d", i))
	}
	buckets := s.snapshotDropBuckets()
	if len(buckets) != auditDropBucketCap+1 { // the capped real buckets plus one overflow bucket
		t.Fatalf("expected %d distinct buckets (cap + overflow), got %d: %v", auditDropBucketCap+1, len(buckets), buckets)
	}
	if buckets[dropBucketOverflowKey] != overflow {
		t.Errorf("expected %d drops folded into the overflow bucket, got %d", overflow, buckets[dropBucketOverflowKey])
	}
}

// TestFlushDropMarker_RetriesPreserveBuckets mirrors
// TestAuditDropMarker_RetriesOnWriteFailure for the bucket data: a failed marker
// write must not clear the accumulated buckets, so a later successful retry still
// reports every method/target affected since the last durably-written marker.
func TestFlushDropMarker_RetriesPreserveBuckets(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	key := nonZeroTestKey()
	s := &Sink{
		key:      key,
		keyID:    hmacKeyID(key),
		maxBytes: 1 << 30,
		f:        f,
	}
	failing := true
	s.writeLine = func(b []byte) (int, error) {
		if failing {
			return 0, fmt.Errorf("simulated disk full")
		}
		return f.Write(b)
	}

	s.dropped.Store(2)
	s.recordDropBucket("tools/call", "a")
	s.recordDropBucket("tools/call", "b")

	s.flushDropMarker()
	if s.lastDroppedMarked != 0 {
		t.Fatalf("lastDroppedMarked must not advance on a failed write, got %d", s.lastDroppedMarked)
	}
	if buckets := s.snapshotDropBuckets(); len(buckets) != 2 {
		t.Fatalf("buckets must survive a failed write, got %v", buckets)
	}

	failing = false
	s.flushDropMarker()
	if s.lastDroppedMarked != 2 {
		t.Fatalf("lastDroppedMarked must advance once the retry succeeds, got %d", s.lastDroppedMarked)
	}
	if buckets := s.snapshotDropBuckets(); len(buckets) != 0 {
		t.Fatalf("buckets must be cleared once the marker carrying them is durably written, got %v", buckets)
	}
}

// TestResetDropBuckets_PreservesConcurrentAdditions is a regression test for the
// data-loss race in the original implementation: resetDropBuckets used to
// unconditionally nil the whole live map after a successful write, discarding any
// recordDropBucket call that landed between the snapshot (taken before the marker's
// disk write) and the reset (after it) — even though that drop was never included
// in the marker just written. The fix decrements only the snapshotted counts,
// deleting a key once it reaches zero, so a concurrent addition (to an
// already-snapshotted key, or an entirely new one) survives into the next marker.
func TestResetDropBuckets_PreservesConcurrentAdditions(t *testing.T) {
	t.Parallel()
	s := &Sink{}

	// Simulate the pre-write state and take a snapshot, exactly as flushDropMarker
	// does before the (potentially slow) disk write.
	s.recordDropBucket("tools/call", "probe_tool")
	s.recordDropBucket("resources/read", "file:///etc/passwd")
	snapshot := s.snapshotDropBuckets()
	if len(snapshot) != 2 {
		t.Fatalf("snapshot: got %v, want 2 entries", snapshot)
	}

	// Concurrent drops land "during" the write window: one more on an
	// already-snapshotted key, and one on a brand new key never seen before.
	s.recordDropBucket("tools/call", "probe_tool")
	s.recordDropBucket("prompts/get", "new_prompt")

	// The write "succeeds" — reset against the pre-write snapshot, matching
	// flushDropMarker's real sequence.
	s.resetDropBuckets(snapshot)

	remaining := s.snapshotDropBuckets()
	if got := remaining["tools/call probe_tool"]; got != 1 {
		t.Errorf("the concurrent addition to an already-snapshotted key must survive with only the snapshotted count removed: got %d, want 1 (all buckets: %v)", got, remaining)
	}
	if got := remaining["prompts/get new_prompt"]; got != 1 {
		t.Errorf("a concurrent addition to a brand new key must survive untouched: got %d, want 1 (all buckets: %v)", got, remaining)
	}
	if _, ok := remaining["resources/read file:///etc/passwd"]; ok {
		t.Errorf("a key fully captured by the snapshot with no further drops must be removed: got %v", remaining)
	}
}

// TestAuditVerify_LargeIntDetailsRoundTrip is the regression test for :
// VerifyRecord must preserve the exact numeric form of integer values in the
// interface-typed Details map. Before the fix, the JSON round-trip in
// VerifyRecord decoded Details numbers to float64, losing precision above 2^53
// and causing a correctly-signed record to fail HMAC verification.
func TestAuditVerify_LargeIntDetailsRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call",
		map[string]interface{}{"count": bigInt}, nil, false, nil, nil)

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Sanity: the large integer must be on disk verbatim, not as a lossy float.
	if !strings.Contains(string(data), strconv.FormatInt(bigInt, 10)) {
		t.Fatalf("expected exact integer %d in log, got: %s", bigInt, data)
	}

	verifier := verifierFor(t, keyPath)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		ok, err := verifier.VerifyRecord([]byte(line))
		if err != nil {
			t.Fatalf("VerifyRecord: %v", err)
		}
		if !ok {
			t.Errorf("record with large int64 detail failed HMAC verification: %s", line)
		}
	}
}

// TestWriteRecord_SpliceMatchesDoubleMarshal is the regression: writeRecord
// builds the on-disk line by splicing the _hmac field into the already-signed body
// instead of re-marshaling the record a second time. This test pins that the spliced
// bytes are BYTE-IDENTICAL to what the previous double-marshal scheme produced (so
// the on-disk format is unchanged) and that the resulting line still passes
// VerifyRecord (which re-marshals rec with HMAC cleared, reproducing the signing
// body). A range of records — including ones with Details carrying a large int64 and
// a string needing JSON escaping — exercises the splice across realistic shapes.
func TestWriteRecord_SpliceMatchesDoubleMarshal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call",
		map[string]interface{}{"big": bigInt, "needs\"escape": "a\tb\nc\"d"}, nil, false, nil, nil)
	sink.RecordDeny(context.Background(), "sess", "write_file", "tools/call", "CAPABILITY_DENIED", "", nil, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	key, err := loadOrCreateAuditKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateAuditKey: %v", err)
	}
	verifier := verifierFor(t, keyPath)

	for i, line := range logLines(t, logPath) {
		// 1. The on-disk line still passes per-record HMAC verification.
		ok, err := verifier.VerifyRecord(line)
		if err != nil {
			t.Fatalf("record %d: VerifyRecord: %v", i, err)
		}
		if !ok {
			t.Fatalf("record %d: spliced on-disk record failed HMAC verification: %s", i, line)
		}

		// 2. The on-disk bytes are byte-identical to the previous double-marshal
		// scheme: decode the record, clear HMAC, marshal the body (== signing body),
		// recompute the HMAC, set it, and marshal again. That is exactly what the old
		// writeRecord did, so it is the reference encoding the splice must reproduce.
		var rec auditRecord
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.UseNumber()
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("record %d: decode: %v", i, err)
		}
		rec.HMAC = ""
		body, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("record %d: marshal body: %v", i, err)
		}
		rec.HMAC = "sha256:" + hmacHex(key, body)
		reference, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("record %d: marshal reference: %v", i, err)
		}
		if !bytes.Equal(line, reference) {
			t.Fatalf("record %d: spliced on-disk line differs from the double-marshal reference\n got: %s\nwant: %s", i, line, reference)
		}
	}
}

// TestAuditVerify_LargeDropCountMarker reproduces the concrete case:
// a saturated AUDIT_RECORDS_DROPPED marker whose dropped counts exceed
// 2^53 must still verify, both per-record and across the tamper-evident chain.
func TestAuditVerify_LargeDropCountMarker(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	// First real record establishes the chain.
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	// Simulate a flood that dropped more records than float64 can count exactly.
	sink.dropped.Store(bigInt)
	// Next real record makes the drainer emit the drop marker before writing it
	// (or the final flush at Close does), stamping the int64 counts into Details.
	sink.RecordDeny(context.Background(), "sess", "write_file", "tools/call", "CAPABILITY_DENIED", "", nil, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)

	verifier := verifierFor(t, keyPath)
	sawMarker := false
	for _, line := range lines {
		ok, err := verifier.VerifyRecord(line)
		if err != nil {
			t.Fatalf("VerifyRecord: %v", err)
		}
		if !ok {
			t.Errorf("record failed HMAC verification: %s", line)
		}
		if strings.Contains(string(line), "AUDIT_RECORDS_DROPPED") {
			sawMarker = true
			if !strings.Contains(string(line), strconv.FormatInt(bigInt, 10)) {
				t.Errorf("drop marker lost precision on large count: %s", line)
			}
		}
	}
	if !sawMarker {
		t.Fatal("expected an AUDIT_RECORDS_DROPPED marker in the log")
	}

	// The tamper-evident chain must verify end to end.
	res := verifyBytes(t, lines, verifier)
	if !res.OK() {
		t.Errorf("chain verification failed with large drop-count marker: %+v", res)
	}
}

// TestAuditVerify_LargeDropCountTamperDetected is the negative companion to the
// round-trip tests: it confirms the UseNumber() decode preserves tamper-evidence
// above 2^53 rather than making verification blind to edits of large-integer
// details. AUDIT_RECORDS_DROPPED is security-relevant — an attacker who can edit
// the tape might shrink dropped_total to hide the scale of a loss window — and
// the existing chain tamper test exercises only seq/prev_hmac, not a large-int
// details value through the new decode path. Here the marker's dropped_total is
// shrunk to a smaller (still >2^53, still float64-inexact) value; VerifyRecord
// must report the line INVALID because json.Number preserves the exact textual
// bytes and the recomputed HMAC no longer matches.
func TestAuditVerify_LargeDropCountTamperDetected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	// 9999999999999999 (~1e16) is above 2^53 and odd, so float64 cannot represent
	// it exactly — the same precision class as the drop counts this guards.
	const bigDrop int64 = 9999999999999999
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	sink.dropped.Store(bigDrop)
	sink.RecordDeny(context.Background(), "sess", "write_file", "tools/call", "CAPABILITY_DENIED", "", nil, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Shrink dropped_total to bigInt (2^53 + 1): a smaller but still float64-inexact
	// count, mimicking an attacker hiding the scale of the loss. Match the full
	// "dropped_total":<n> field so the edit is unambiguous (the equal-valued
	// "dropped" field and the hmac/request_id hex are untouched).
	orig := `"dropped_total":` + strconv.FormatInt(bigDrop, 10)
	want := `"dropped_total":` + strconv.FormatInt(bigInt, 10)
	tampered := strings.Replace(string(data), orig, want, 1)
	if tampered == string(data) {
		t.Fatalf("test setup: %q not found in log: %s", orig, data)
	}

	verifier := verifierFor(t, keyPath)
	sawMarker := false
	for _, line := range strings.Split(strings.TrimSpace(tampered), "\n") {
		if !strings.Contains(line, "AUDIT_RECORDS_DROPPED") {
			continue
		}
		sawMarker = true
		ok, err := verifier.VerifyRecord([]byte(line))
		if err != nil {
			t.Fatalf("VerifyRecord: %v", err)
		}
		if ok {
			t.Errorf("tampered drop-count marker was accepted; tamper-evidence lost above 2^53: %s", line)
		}
	}
	if !sawMarker {
		t.Fatal("expected an AUDIT_RECORDS_DROPPED marker in the log")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: open a real audit sink in a temp dir
// ─────────────────────────────────────────────────────────────────────────────

func TestAuditRecord_AuditOnlyField_PresentWhenTrue(t *testing.T) {
	rec := auditRecord{Decision: "allow", AuditOnly: true, Target: "read_file"}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v, ok := m["audit_only"]; !ok || v != true {
		t.Errorf("audit_only must be true, got: %s", data)
	}
}

func TestAuditRecord_AuditOnlyField_OmittedWhenFalse(t *testing.T) {
	rec := auditRecord{Decision: "allow", AuditOnly: false, Target: "read_file"}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["audit_only"]; ok {
		t.Errorf("audit_only must be omitted when false: %s", data)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Sampling / server-initiated requests (stdio proxy)
// ─────────────────────────────────────────────────────────────────────────────

// TestAuditRotate_Success drives the happy path: an open sink with a live file
// is rotated, producing a timestamped sidecar and a fresh (empty) active log.
func TestAuditRotate_Success(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	sink, err := Open(logPath, filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	// Seed some bytes so the rotated file is non-empty and `written` is non-zero.
	if _, err := sink.f.WriteString("{\"seed\":1}\n"); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	sink.written = 10

	sink.rotate()

	// A timestamped rotated file must now exist alongside the (recreated) log.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var rotatedFound bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "audit.jsonl.") {
			rotatedFound = true
		}
	}
	if !rotatedFound {
		t.Errorf("expected a timestamped rotated file in %s, got %v", dir, entries)
	}
	if sink.written != 0 {
		t.Errorf("written counter must reset after rotate, got %d", sink.written)
	}
	// The active file must still be writable after rotation.
	if _, err := sink.f.WriteString("{\"after\":1}\n"); err != nil {
		t.Errorf("write after rotate failed: %v", err)
	}
}

// TestAuditRotate_RenameErrorKeepsFd covers the rename-failure branch with a
// still-valid file descriptor: rotate cannot rename an active path that no longer
// exists on disk, logs the error, backs the counter off by one ~10% burst (so a
// persistent rename fault cannot grow the file by a full maxBytes per failure),
// and keeps the open fd.
func TestAuditRotate_RenameErrorKeepsFd(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	sink, err := Open(logPath, filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	// Point the rename SOURCE (activePath) at a name with no on-disk file (the real
	// inode stays open via sink.f), so os.Rename fails but the fd remains usable.
	// logPath stays valid so rotatedPath produces a writable target — it is the
	// missing source that fails the rename.
	sink.activePath = filepath.Join(dir, "nonexistent", "audit.jsonl")
	sink.written = 999

	sink.rotate()

	if sink.f == nil {
		t.Fatal("file descriptor must survive a rename failure")
	}
	// The counter must back off to just below the threshold (one ~10% burst), not
	// reset to 0: that bounds growth under a persistent rename fault to ~10% of
	// maxBytes per failed attempt while still avoiding a tight retry loop.
	wantWritten := sink.maxBytes - sink.maxBytes/10
	if sink.written != wantWritten {
		t.Errorf("written counter after failed rotate = %d, want %d (backoff, not reset)", sink.written, wantWritten)
	}
	if sink.written >= sink.maxBytes {
		t.Errorf("written counter %d must stay below maxBytes %d to avoid a tight rotate loop", sink.written, sink.maxBytes)
	}
	if _, err := sink.f.WriteString("{\"still\":1}\n"); err != nil {
		t.Errorf("fd must remain writable after a failed rotate: %v", err)
	}
}

// TestAuditRotate_ReopenFailureKeepsBasePathAndRecovers is the regression:
// a rotation whose rename succeeds but whose reopen of the configured base path
// fails must keep writing to the renamed fd WITHOUT drifting logPath. logPath
// stays the configured base so pruneRotated keeps matching every "<base>.<ts>"
// sibling (including pre-fallback ones) and a later successful rotation returns
// the active file to the base path. Only activePath drifts during the fallback.
func TestAuditRotate_ReopenFailureKeepsBasePathAndRecovers(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := filepath.Join(dir, "audit.jsonl")

	// Pre-existing rotated siblings from earlier rotations; retention must still
	// find these after a fallback (the core bug: a drifted logPath glob misses them).
	old1 := base + ".20260614T100000.000000000Z"
	old2 := base + ".20260614T110000.000000000Z"
	for _, p := range []string{old1, old2} {
		if err := os.WriteFile(p, []byte("old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// The fd currently writes to a real file distinct from logPath.
	active := filepath.Join(dir, "active.current")
	f, err := os.OpenFile(active, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("live\n"); err != nil {
		t.Fatal(err)
	}

	// Block the reopen of logPath by making it a directory: after rotate renames
	// activePath to <base>.<ts>, os.OpenFile(base, O_CREATE|O_WRONLY) fails EISDIR,
	// driving the fallback branch.
	if err := os.Mkdir(base, 0o700); err != nil {
		t.Fatal(err)
	}

	// written must reflect the "live\n" already on disk: rotate() no longer rotates
	// an empty base (a companion fix — see TestRotate_EmptyBase_NoOp), so a
	// zero-valued written here would make phase 1's rotate() a no-op.
	s := &Sink{logPath: base, activePath: active, f: f, maxBytes: 1, retain: 2, written: int64(len("live\n"))}

	// --- Phase 1: rotate hits the reopen-failure fallback. ---
	s.rotate()

	if s.logPath != base {
		t.Fatalf("logPath must stay the configured base after a fallback; got %q", s.logPath)
	}
	if !strings.HasPrefix(s.activePath, base+".") {
		t.Fatalf("activePath must drift to the renamed file; got %q", s.activePath)
	}
	if s.f != f {
		t.Fatal("fd must be preserved across the fallback so records keep flowing")
	}
	if _, err := s.f.WriteString("after-fallback\n"); err != nil {
		t.Fatalf("fd must remain writable after the fallback: %v", err)
	}

	// --- Phase 2: clear the block and rotate again to recover. ---
	if err := os.Remove(base); err != nil { // remove the blocking directory
		t.Fatal(err)
	}
	s.rotate()

	if s.activePath != base {
		t.Fatalf("after a successful rotation the active file must return to the base path; got %q", s.activePath)
	}
	if _, err := os.Stat(base); err != nil {
		t.Fatalf("the configured base path must hold the active log after recovery: %v", err)
	}
	// Retention (retain=2) must have pruned the OLDEST pre-fallback rotated file —
	// proving the glob still sees them; a drifted logPath would have orphaned them.
	if _, err := os.Stat(old1); !os.IsNotExist(err) {
		t.Errorf("oldest pre-fallback rotated file should have been pruned, stat err = %v", err)
	}
}

// TestAuditRotate_NilFileGuard covers the early return when there is no file.
func TestAuditRotate_NilFileGuard(t *testing.T) {
	t.Parallel()
	s := &Sink{}
	s.rotate() // must not panic
}

// TestAuditRotate_TwoRotationsSameSecond is the regression guard: two
// rotations within the same wall-clock second must each produce a distinct
// rotated file. POSIX os.Rename atomically replaces an existing target, so a
// second-precision timestamp suffix let the second rotation silently overwrite
// the first rotated file and destroy its records. Calling rotate() twice in
// immediate succession lands both renames in the same second; both rotated
// files (and the records they hold) must survive.
func TestAuditRotate_TwoRotationsSameSecond(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	sink, err := Open(logPath, filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	// First rotation: seed a unique marker into the active log, rotate it out.
	if _, err := sink.f.WriteString(`{"marker":"first"}` + "\n"); err != nil {
		t.Fatalf("seed first: %v", err)
	}
	sink.written = 1
	sink.rotate()

	// Second rotation, immediately after (same wall-clock second): a different
	// marker into the freshly reopened log, rotate it out too.
	if _, err := sink.f.WriteString(`{"marker":"second"}` + "\n"); err != nil {
		t.Fatalf("seed second: %v", err)
	}
	sink.written = 1
	sink.rotate()

	// Both rotated files must survive, each retaining its distinct record.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	markers := map[string]bool{}
	var rotatedCount int
	for _, e := range entries {
		name := e.Name()
		if name == "audit.jsonl" || !strings.HasPrefix(name, "audit.jsonl.") {
			continue // skip the active log and the audit.key sidecar
		}
		rotatedCount++
		data, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // test-only read of temp file
		if err != nil {
			t.Fatalf("read rotated %s: %v", name, err)
		}
		switch {
		case strings.Contains(string(data), `"first"`):
			markers["first"] = true
		case strings.Contains(string(data), `"second"`):
			markers["second"] = true
		}
	}
	if rotatedCount != 2 {
		t.Errorf("expected exactly 2 rotated files, got %d (second rotation overwrote the first?)", rotatedCount)
	}
	if !markers["first"] || !markers["second"] {
		t.Errorf("both rotated records must survive; got markers=%v", markers)
	}
}

// TestUniqueRotatedPath_BackstopSuffix deterministically covers the collision
// backstop behind rotatedPath. The two-rotation test above only exercises
// the ".N" fallback on a coarse clock — on a fine-grained clock the nanosecond
// suffixes differ and the loop never advances — so the fallback is driven here
// directly with a fixed base, independent of host clock granularity.
func TestUniqueRotatedPath_BackstopSuffix(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := filepath.Join(dir, "audit.jsonl.20260613T200000.000000000Z")

	// Nothing on disk yet: the timestamped base name itself is free.
	if got, err := uniqueRotatedPath(base); err != nil || got != base {
		t.Fatalf("free base: got (%q, %v), want (%q, nil)", got, err, base)
	}

	// Occupy base and base.1; the next free name must be base.2, never a path
	// os.Rename would overwrite.
	for _, p := range []string{base, base + ".1"} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}
	if got, err := uniqueRotatedPath(base); err != nil || got != base+".2" {
		t.Fatalf("occupied base + base.1: got (%q, %v), want (%q, nil)", got, err, base+".2")
	}

	// A dangling symlink at the target must also count as occupied (Lstat, not
	// Stat) so a rename cannot clobber through it. Skip where symlinks are
	// unprivileged/unsupported rather than fail spuriously.
	dangling := filepath.Join(dir, "audit.jsonl.20260613T200001.000000000Z")
	if err := os.Symlink(filepath.Join(dir, "missing-target"), dangling); err != nil {
		t.Logf("skipping dangling-symlink case: %v", err)
		return
	}
	if got, err := uniqueRotatedPath(dangling); err != nil || got != dangling+".1" {
		t.Errorf("dangling symlink must be treated as occupied: got (%q, %v), want (%q, nil)", got, err, dangling+".1")
	}
}

// TestUniqueRotatedPath_ExhaustionReturnsError pins the ".N" search is
// bounded, so when every candidate up to the cap is occupied it returns an error
// instead of looping toward an int wraparound that would produce a negative-suffix
// filename. Driven through the bounded seam with a tiny cap so the exhaustion path
// is exercised without seeding maxRotateSuffix files. uniqueRotatedPathBounded(base,
// N) probes N+1 candidates: base, base.1 .. base.N, so cap 2 must have
// base, base.1, AND base.2 occupied to be exhausted.
func TestUniqueRotatedPath_ExhaustionReturnsError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := filepath.Join(dir, "audit.jsonl.20260613T210000.000000000Z")

	// cap of 2 probes base, base.1, base.2 — occupy all three so none are free.
	for _, p := range []string{base, base + ".1", base + ".2"} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}
	got, err := uniqueRotatedPathBounded(base, 2)
	if err == nil {
		t.Fatalf("expected an error when all candidates are occupied; got %q", got)
	}

	// A free slot within the cap still returns cleanly (base.3 is open at cap 3).
	if got, err := uniqueRotatedPathBounded(base, 3); err != nil || got != base+".3" {
		t.Fatalf("first free slot: got (%q, %v), want (%q, nil)", got, err, base+".3")
	}
}

// TestUniqueRotatedPath_FinalCandidateProbed is the regression: the loop
// must probe its FINAL candidate (base.maxSuffix) before returning an error. Earlier
// the loop updated the candidate to base.maxSuffix on its last iteration but exited
// before the next Lstat, so a free base.maxSuffix was wrongly reported as exhausted.
// Here base .. base.(N-1) are occupied and base.N is free, so the function must
// return base.N rather than an error.
func TestUniqueRotatedPath_FinalCandidateProbed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := filepath.Join(dir, "audit.jsonl.20260613T220000.000000000Z")

	const n = 3
	// Occupy base, base.1, base.2 (i.e. base .. base.(n-1)); leave base.3 free.
	for _, p := range []string{base, base + ".1", base + ".2"} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}
	got, err := uniqueRotatedPathBounded(base, n)
	if err != nil {
		t.Fatalf("the final candidate base.%d is free and must be returned, got error: %v", n, err)
	}
	if want := base + ".3"; got != want {
		t.Fatalf("got %q, want the free final candidate %q", got, want)
	}
}

// TestGenerateAndPersistAuditKey_GeneratesAndPersists exercises the generation
// path on its own ( B-2 extracted it from loadOrCreateAuditKeys): it
// returns a single fresh 32-byte key and leaves a file that parses back to that
// same key, with no dependence on the read-or-create dispatch.
func TestGenerateAndPersistAuditKey_GeneratesAndPersists(t *testing.T) {
	t.Parallel()
	keyPath := filepath.Join(t.TempDir(), "audit.key")

	keys, err := generateAndPersistAuditKey(keyPath)
	if err != nil {
		t.Fatalf("generateAndPersistAuditKey: %v", err)
	}
	if len(keys) != 1 || len(keys[0]) != 32 {
		t.Fatalf("expected one 32-byte key, got %d keys", len(keys))
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("reading persisted key: %v", err)
	}
	persisted, err := parseAuditKeys(data)
	if err != nil {
		t.Fatalf("parseAuditKeys on persisted file: %v", err)
	}
	if len(persisted) != 1 || !bytes.Equal(persisted[0], keys[0]) {
		t.Error("persisted file must round-trip to the returned key")
	}
}

// TestGenerateAndPersistAuditKey_TrailingNewlineEnablesShellAppendRotation pins
// : the generated key file must end with a newline so a standard shell
// append rotation (echo "$NEWKEY" >> keyfile) adds the new key as its own line,
// rather than concatenating it onto the existing key's line — which parseAuditKeys
// would decode to 64 bytes and reject, refusing to start.
func TestGenerateAndPersistAuditKey_TrailingNewlineEnablesShellAppendRotation(t *testing.T) {
	t.Parallel()
	keyPath := filepath.Join(t.TempDir(), "audit.key")

	keys, err := generateAndPersistAuditKey(keyPath)
	if err != nil {
		t.Fatalf("generateAndPersistAuditKey: %v", err)
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("reading persisted key: %v", err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatalf("generated key file must end with a newline; got %q", data)
	}

	// Simulate `echo "$NEWKEY" >> keyfile`: append a second hex key line.
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 1)
	}
	appended := append([]byte(nil), data...)
	appended = append(appended, []byte(hex.EncodeToString(newKey))...)
	appended = append(appended, '\n')

	parsed, err := parseAuditKeys(appended)
	if err != nil {
		t.Fatalf("parseAuditKeys after shell-append rotation: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 keys after rotation, got %d", len(parsed))
	}
	if !bytes.Equal(parsed[0], keys[0]) {
		t.Error("first line must remain the original active key")
	}
	if !bytes.Equal(parsed[1], newKey) {
		t.Error("second line must be the appended retired key")
	}
}

// TestSanitizeAuditField covers the helper directly: control characters are
// replaced with spaces and ordinary text is untouched.
func TestSanitizeAuditField(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"plain-tool":        "plain-tool",
		"a\nb":              "a b",
		"a\r\nb":            "a  b",
		"tab\there":         "tab here",
		"esc\x1b[31mred":    "esc [31mred",
		"resource://ok/uri": "resource://ok/uri",
		// U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR) are line terminators
		// for many parsers but are NOT category Cc, so unicode.IsControl misses them;
		// SanitizeAuditField must neutralize them too or a forged finding line could be
		// injected past the guard. U+0085 (NEL) is a Cc control and is the regression
		// anchor that the IsControl base case still fires.
		"ls\u2028forged":  "ls forged",
		"ps\u2029forged":  "ps forged",
		"nel\u0085forged": "nel forged",
	}
	for in, want := range cases {
		if got := SanitizeAuditField(in); got != want {
			t.Errorf("SanitizeAuditField(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestLoadOrCreateAuditKey_SingleView asserts the single-key convenience
// wrapper returns the active key.
func TestLoadOrCreateAuditKey_SingleView(t *testing.T) {
	t.Parallel()
	keyPath := filepath.Join(t.TempDir(), "audit.key")
	key, err := loadOrCreateAuditKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateAuditKey: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected a 32-byte key, got %d bytes", len(key))
	}
}

// TestAuditRecord_KeyIDStampedAndVerifies verifies that every record carries the
// active key's identifier and round-trips through VerifyRecord (§ 7.4).
func TestAuditRecord_KeyIDStampedAndVerifies(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	keys, err := LoadOrCreateKeys(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateAuditKeys: %v", err)
	}
	wantID := hmacKeyID(keys[0])

	recs := readAuditRecords(t, logPath)
	if got := recs[0]["key_id"]; got != wantID {
		t.Errorf("key_id=%v, want %q", got, wantID)
	}

	data, _ := os.ReadFile(logPath) //nolint:gosec // test-only temp file
	line := []byte(strings.TrimSpace(string(data)))

	// A verifier whose ring holds the key validates the record.
	verifier := &Sink{verifyKeys: map[string][]byte{wantID: keys[0]}}
	if ok, err := verifier.VerifyRecord(line); err != nil || !ok {
		t.Errorf("VerifyRecord ok=%v err=%v, want true/nil", ok, err)
	}

	// A verifier missing that key id cannot verify the record (fail closed), and
	// now reports the distinguishing errKeyIDNotInRing rather than a bare
	// (false, nil) — so audit-verify classifies it as UNKNOWN_KEY_ID (a retired-key
	// state) instead of INVALID (content tampering).
	other := make([]byte, 32)
	other[0] = 0xAB
	missing := &Sink{verifyKeys: map[string][]byte{hmacKeyID(other): other}}
	ok, err := missing.VerifyRecord(line)
	if !errors.Is(err, errKeyIDNotInRing) {
		t.Fatalf("VerifyRecord err=%v, want errKeyIDNotInRing", err)
	}
	if ok {
		t.Error("record verified against a keyring that lacks its key_id")
	}
}

// TestAuditKey_RotationVerifiesAcrossKeys writes records under one key, rotates
// the key file (new active key first, old key retained), writes more records,
// and confirms audit-verify validates the whole tape — each record against the
// key that signed it (§ 7.4).
func TestAuditKey_RotationVerifiesAcrossKeys(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// First epoch: a fresh key signs the first record.
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	oldKeys, _ := LoadOrCreateKeys(keyPath)
	oldKey := oldKeys[0]

	// Rotate: prepend a new active key, keep the old key for verification.
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(0x10 + i)
	}
	rotated := hex.EncodeToString(newKey) + "\n# retired keys below\n" + hex.EncodeToString(oldKey) + "\n"
	if err := os.WriteFile(keyPath, []byte(rotated), 0o600); err != nil {
		t.Fatalf("WriteFile rotated key: %v", err)
	}

	// Second epoch: the new key signs the next record (chain continues).
	sink2, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink (post-rotate): %v", err)
	}
	if sink2.keyID != hmacKeyID(newKey) {
		t.Errorf("post-rotate active keyID=%q, want %q", sink2.keyID, hmacKeyID(newKey))
	}
	sink2.RecordDeny(context.Background(), "sess", "write_file", "tools/call", "AUTHORIZATION_FAILED", "", nil, false)
	if err := sink2.Close(); err != nil {
		t.Fatalf("Close (post-rotate): %v", err)
	}

	// audit-verify with the full keyring: both records must verify and the chain
	// must be intact.
	keys, err := LoadOrCreateKeys(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateAuditKeys: %v", err)
	}
	ring := make(map[string][]byte, len(keys))
	for _, k := range keys {
		ring[hmacKeyID(k)] = k
	}
	verifier := &Sink{key: keys[0], keyID: hmacKeyID(keys[0]), verifyKeys: ring}

	f, err := os.Open(logPath) //nolint:gosec // test-only temp file
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer func() { _ = f.Close() }()
	var sb strings.Builder
	res, err := VerifyLog(f, verifier, "", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if res.Total != 2 || res.Valid != 2 || res.Invalid != 0 || res.ChainBreaks != 0 {
		t.Errorf("verify result = %+v; want 2 total / 2 valid / 0 invalid / 0 chain breaks\noutput:\n%s", res, sb.String())
	}
}

// TestAuditChain_UnknownKeyRecordIsNotAChainBreak is a regression: verifying a
// post-rotation log with a ring that LACKS the retired signing key must report the
// old-key record as UNKNOWN_KEY_ID but must NOT manufacture a chain break on the
// following (new-key) record. A named-but-absent key_id leaves the record's _hmac
// intact — it was computed by the legitimate signer — so its successor's prev_hmac
// still links correctly. Only a record whose HMAC is provably wrong under a held key
// (content tampered) is an untrustworthy chain anchor; a retired key is not tampering.
func TestAuditChain_UnknownKeyRecordIsNotAChainBreak(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// First epoch: the original key signs the first record (seq 1).
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	oldKeys, _ := LoadOrCreateKeys(keyPath)
	oldKey := oldKeys[0]

	// Rotate: a new active key first, the old key RETAINED below so the resumed sink
	// can verify the seq-1 tail and continue the chain (seq 2 chained onto seq 1).
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(0x30 + i)
	}
	rotated := hex.EncodeToString(newKey) + "\n" + hex.EncodeToString(oldKey) + "\n"
	if err := os.WriteFile(keyPath, []byte(rotated), 0o600); err != nil {
		t.Fatalf("WriteFile rotated key: %v", err)
	}

	// Second epoch: the new key signs record 2 (seq 2), chaining onto record 1.
	sink2, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink (post-rotate): %v", err)
	}
	sink2.RecordDeny(context.Background(), "sess", "write_file", "tools/call", "AUTHORIZATION_FAILED", "", nil, false)
	if err := sink2.Close(); err != nil {
		t.Fatalf("Close (post-rotate): %v", err)
	}

	// Verify with a ring holding ONLY the new key (the retired key was discarded after
	// rotation): record 1 is UNKNOWN_KEY_ID (its key is absent), record 2 is valid. The
	// chain — written continuously above — must still verify as intact.
	ring := map[string][]byte{hmacKeyID(newKey): newKey}
	verifier := &Sink{key: newKey, keyID: hmacKeyID(newKey), verifyKeys: ring}

	f, err := os.Open(logPath) //nolint:gosec // test-only temp file
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer func() { _ = f.Close() }()
	var sb strings.Builder
	res, err := VerifyLog(f, verifier, "", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if res.UnknownKey != 1 {
		t.Errorf("expected the retired-key record counted UnknownKey=1, got %+v\noutput:\n%s", res, sb.String())
	}
	if res.ChainBreaks != 0 {
		t.Fatalf("a retired-key (UNKNOWN_KEY_ID) record must NOT fabricate a chain break on its successor; got chainBreaks=%d\noutput:\n%s", res.ChainBreaks, sb.String())
	}
}

// TestAuditKey_RotatedTailVerifiesOnRestart guards the regression where the
// startup tail-HMAC check (openAuditSink) verified the resumed tail against the
// active key alone. After a rotation the tail was signed by a now-retired key,
// so a restart warned spuriously even though audit-verify accepts it. The signer
// sink now loads the full keyring, so VerifyRecord on the rotated tail succeeds.
func TestAuditKey_RotatedTailVerifiesOnRestart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// First epoch: the original key signs the tail record.
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	oldKeys, _ := LoadOrCreateKeys(keyPath)
	oldKey := oldKeys[0]

	// Rotate: new active key first, old (tail-signing) key retained below.
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(0x20 + i)
	}
	rotated := hex.EncodeToString(newKey) + "\n" + hex.EncodeToString(oldKey) + "\n"
	if err := os.WriteFile(keyPath, []byte(rotated), 0o600); err != nil {
		t.Fatalf("WriteFile rotated key: %v", err)
	}

	// Restart: reopening the sink runs the startup tail-HMAC check internally.
	sink2, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink (post-rotate): %v", err)
	}
	t.Cleanup(func() { _ = sink2.Close() })

	// The resumed tail was signed by the retired key; the signer sink must still
	// verify it via the full keyring (the fix), not just the new active key.
	tail := mustReadLastAuditLine(t, logPath)
	if tail == "" {
		t.Fatal("no tail line found")
	}
	ok, err := sink2.VerifyRecord([]byte(tail))
	if err != nil {
		t.Fatalf("VerifyRecord: %v", err)
	}
	if !ok {
		t.Error("rotated tail (signed by retired key) failed verification on restart; full keyring not loaded")
	}
}

// TestParseAuditKeys covers multi-key parsing, comments, and the fail-closed
// errors for malformed key files.
func TestParseAuditKeys(t *testing.T) {
	t.Parallel()
	good := strings.Repeat("ab", 32)
	good2 := strings.Repeat("cd", 32)

	t.Run("single key", func(t *testing.T) {
		keys, err := parseAuditKeys([]byte(good))
		if err != nil || len(keys) != 1 {
			t.Fatalf("got %d keys, err=%v", len(keys), err)
		}
	})
	t.Run("multiple keys with comment and blanks", func(t *testing.T) {
		content := good + "\n\n# a comment\n" + good2 + "\n"
		keys, err := parseAuditKeys([]byte(content))
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		if len(keys) != 2 {
			t.Fatalf("got %d keys, want 2", len(keys))
		}
		if hmacKeyID(keys[0]) == hmacKeyID(keys[1]) {
			t.Error("expected two distinct keys")
		}
	})
	t.Run("invalid hex fails closed", func(t *testing.T) {
		if _, err := parseAuditKeys([]byte("not-valid-hex!!!")); err == nil {
			t.Error("expected error for invalid hex")
		}
	})
	t.Run("wrong length fails closed", func(t *testing.T) {
		if _, err := parseAuditKeys([]byte(strings.Repeat("ab", 16))); err == nil {
			t.Error("expected error for short key")
		}
	})
	t.Run("empty fails closed", func(t *testing.T) {
		if _, err := parseAuditKeys([]byte("# only a comment\n")); err == nil {
			t.Error("expected error for a file with no key lines")
		}
	})
	// An all-zero 32-byte key carries no entropy and makes the HMAC signature
	// trivially forgeable, so an externally-supplied key file containing one must
	// be rejected (fail closed, ). 64 hex zeros decode to 32 zero bytes.
	t.Run("all-zero key fails closed", func(t *testing.T) {
		allZero := strings.Repeat("00", 32)
		if _, err := parseAuditKeys([]byte(allZero)); err == nil {
			t.Error("expected error for an all-zero 32-byte key")
		}
	})
	// A non-zero 32-byte key of the right length is accepted: the all-zero check
	// must reject only the no-entropy placeholder, not legitimate key material.
	t.Run("non-zero key accepted", func(t *testing.T) {
		keys, err := parseAuditKeys([]byte(good))
		if err != nil || len(keys) != 1 {
			t.Fatalf("expected a valid non-zero key to be accepted: got %d keys, err=%v", len(keys), err)
		}
	})
	// A multi-key file with a valid active key but an all-zero retired key is
	// rejected too — the check runs per line, not only on the first key.
	t.Run("all-zero retired key fails closed", func(t *testing.T) {
		content := good + "\n" + strings.Repeat("00", 32) + "\n"
		if _, err := parseAuditKeys([]byte(content)); err == nil {
			t.Error("expected error when any key line is all-zero")
		}
	})
}

// TestIsAllZeroKey checks the all-zero key predicate directly: a 32-byte zero
// slice is all-zero, and any slice with at least one non-zero byte is not.
func TestIsAllZeroKey(t *testing.T) {
	t.Parallel()
	if !isAllZeroKey(make([]byte, 32)) {
		t.Error("a 32-byte zero slice should be reported all-zero")
	}
	nonZero := make([]byte, 32)
	nonZero[31] = 1
	if isAllZeroKey(nonZero) {
		t.Error("a slice with a non-zero byte should not be reported all-zero")
	}
}

// TestVerifyRecord_LegacyNoKeyID confirms a record written before key_id existed
// (no key_id field) still verifies against a keyring by trying every key, so a
// tape that straddles the rotation-support format change verifies the same way
// the pre-chain format does.
func TestVerifyRecord_LegacyNokeyID(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	// Sign a record the legacy way: no KeyID field set, so no key_id is stamped.
	rec := auditRecord{
		ClassUID: 6003, CategoryUID: 6, ActivityID: 1,
		Time: "2026-01-01T00:00:00Z", RequestID: "r1", SessionID: "s1",
		TargetType: "tool", Target: "read_file", Method: "tools/call",
		Decision: "allow", PrevHMAC: auditGenesisPrev,
	}
	body, _ := json.Marshal(rec)
	rec.HMAC = "sha256:" + hmacHex(key, body)
	line, _ := json.Marshal(rec)
	if rec.KeyID != "" {
		t.Fatalf("precondition: legacy record must have no key_id, got %q", rec.KeyID)
	}

	// A multi-key verifier with no matching key_id still finds the right key by
	// trying all of them.
	other := make([]byte, 32)
	other[0] = 0xFF
	verifier := &Sink{verifyKeys: map[string][]byte{
		hmacKeyID(other): other,
		hmacKeyID(key):   key,
	}}
	ok, err := verifier.VerifyRecord(line)
	if err != nil || !ok {
		t.Errorf("legacy record verify ok=%v err=%v, want true/nil", ok, err)
	}
}

// TestVerifyRecord_RejectsUnknownTopLevelField is the regression for the
// unsigned-field gap: VerifyRecord re-marshals the decoded auditRecord struct to
// recompute the HMAC, so a lenient decode silently drops any top-level field the
// struct does not model — letting an attacker insert e.g. "operator_override" into a
// signed line without breaking verification (the dropped field is never part of the
// recomputed signing bytes). A signed record carrying an unknown top-level field must
// now fail closed.
func TestVerifyRecord_RejectsUnknownTopLevelField(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	rec := auditRecord{
		ClassUID: 6003, CategoryUID: 6, ActivityID: 1,
		Time: "2026-01-01T00:00:00Z", Seq: 1, RequestID: "r1", SessionID: "s1",
		TargetType: "tool", Target: "read_file", Method: "tools/call",
		Decision: "allow", PrevHMAC: auditGenesisPrev, KeyID: hmacKeyID(key),
	}
	body, _ := json.Marshal(rec)
	rec.HMAC = "sha256:" + hmacHex(key, body)
	line, _ := json.Marshal(rec)

	verifier := &Sink{key: key, keyID: hmacKeyID(key)}

	// Baseline: the untampered signed line verifies.
	if ok, err := verifier.VerifyRecord(line); !ok || err != nil {
		t.Fatalf("clean signed record: ok=%v err=%v, want true/nil", ok, err)
	}

	// Inject an unknown top-level field right after the opening brace, leaving _hmac
	// (and every signed field) byte-for-byte unchanged. Pre-fix this verified true
	// because the field is dropped before the HMAC is recomputed.
	tampered := append([]byte(`{"operator_override":"approved",`), line[1:]...)
	if ok, err := verifier.VerifyRecord(tampered); ok || err == nil {
		t.Fatalf("signed record with an injected unknown field: ok=%v err=%v, want false/non-nil (fail closed)", ok, err)
	}
}

// TestBoundAuditDetails_OversizedStringTruncated asserts a single string value
// over auditDetailValueCap is replaced with a self-describing placeholder while
// small values are left untouched.
func TestBoundAuditDetails_OversizedStringTruncated(t *testing.T) {
	t.Parallel()
	big := strings.Repeat("x", auditDetailValueCap+1)
	// cloneAndBound does the per-value bounding (marshalAndBoundDetails then marshals
	// the bounded clone once); test it directly so the assertion inspects the typed
	// map rather than a re-decoded blob.
	out := cloneAndBound(map[string]interface{}{
		"body": big,
		"path": "/etc/hosts",
	}).(map[string]interface{})
	got, _ := out["body"].(string)
	if got == big {
		t.Fatal("oversized string value was not truncated")
	}
	if !strings.Contains(got, "eunox") || len(got) > 256 {
		t.Errorf("placeholder not as expected: %q", got)
	}
	if out["path"] != "/etc/hosts" {
		t.Errorf("small value mutated: %v", out["path"])
	}
}

// TestBoundAuditDetails_Nested truncates oversized strings nested inside objects
// and arrays, the shapes a decoded argument map produces.
func TestBoundAuditDetails_Nested(t *testing.T) {
	t.Parallel()
	big := strings.Repeat("z", auditDetailValueCap+1)
	out := cloneAndBound(map[string]interface{}{
		"obj": map[string]interface{}{"inner": big},
		"arr": []interface{}{"ok", big},
	}).(map[string]interface{})
	inner := out["obj"].(map[string]interface{})["inner"].(string)
	if inner == big {
		t.Error("nested object string not truncated")
	}
	arr := out["arr"].([]interface{})
	if arr[0] != "ok" {
		t.Errorf("small array element mutated: %v", arr[0])
	}
	if arr[1].(string) == big {
		t.Error("nested array string not truncated")
	}
}

// TestAuditRecord_OversizedArgumentStaysVerifiable is the end-to-end guard:
// an audit-only record carrying a multi-megabyte tool argument is written
// bounded (well under the 4 MiB scanner buffer), audit-verify scans it without a
// "token too long" error, and the tamper-evident chain resumes correctly across
// a restart.
func TestAuditRecord_OversizedArgumentStaysVerifiable(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/audit.jsonl"
	keyPath := dir + "/audit.key"

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	// A ~5 MiB document body, the scenario the issue describes.
	huge := strings.Repeat("A", 5<<20)
	sink.RecordAllow(context.Background(), "sess", "write_file", "tools/call",
		map[string]interface{}{"path": "/tmp/doc", "body": huge}, nil, true, nil, nil)

	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call",
		map[string]interface{}{"path": "/tmp/doc"}, nil, true, nil, nil)

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Every written line must be comfortably below the 4 MiB scanner buffer.
	for i, line := range logLines(t, logPath) {
		if len(line) >= 4<<20 {
			t.Fatalf("record %d is %d bytes; exceeds the scanner buffer", i, len(line))
		}
	}

	// audit-verify must scan cleanly (no bufio.ErrTooLong) and find both records valid.
	verifier := verifierFor(t, keyPath)
	data, err := os.ReadFile(logPath) //nolint:gosec // G304: test-controlled temp dir
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	res, err := VerifyLog(bytes.NewReader(data), verifier, "", time.Time{}, io.Discard)
	if err != nil {
		t.Fatalf("verifyAuditLog returned error (regression: scanner token too long): %v", err)
	}
	if res.Invalid != 0 || res.ChainBreaks != 0 || res.Valid != 2 {
		t.Fatalf("verify result = %+v; want 2 valid, 0 invalid, 0 chainBreaks", res)
	}

	// Reopen the sink: the chain head must resume from the real last record, so the
	// next record gets seq 3 and links to record 2 — not a stale fragment.
	reopened, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	reopened.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, true, nil, nil)
	if err := reopened.Close(); err != nil {
		t.Fatalf("Close (reopened): %v", err)
	}
	res, err = VerifyLog(bytes.NewReader(mustReadFile(t, logPath)), verifierFor(t, keyPath), "", time.Time{}, io.Discard)
	if err != nil {
		t.Fatalf("verifyAuditLog after restart: %v", err)
	}
	if res.ChainBreaks != 0 || res.Valid != 3 {
		t.Fatalf("after restart: result = %+v; want 3 valid, 0 chainBreaks", res)
	}
}

// TestIsNoHardlinkErr classifies os.Link failures: the "filesystem does not
// support hard links" errnos (EPERM, ENOSYS, EXDEV, EOPNOTSUPP, ENOTSUP) must
// trigger the rename fallback, while a genuine failure (and the already-exists
// race signal) must not.
func TestIsNoHardlinkErr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"EPERM", syscall.EPERM, true},
		{"ENOSYS", syscall.ENOSYS, true},
		{"EXDEV", syscall.EXDEV, true},
		{"EOPNOTSUPP", syscall.EOPNOTSUPP, true},
		{"ENOTSUP", syscall.ENOTSUP, true},
		{"wrapped EPERM", fmt.Errorf("link: %w", syscall.EPERM), true},
		{"wrapped EOPNOTSUPP", fmt.Errorf("link: %w", syscall.EOPNOTSUPP), true},
		{"EEXIST (race, not fallback)", syscall.EEXIST, false},
		{"ENOENT", syscall.ENOENT, false},
		{"EIO", syscall.EIO, false},
		{"plain error", errors.New("boom"), false},
	}
	for _, tc := range cases {
		if got := isNoHardlinkErr(tc.err); got != tc.want {
			t.Errorf("isNoHardlinkErr(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestReadPublishedAuditKeys covers the helper used by both the create-race and
// the rename-fallback publish paths: a valid file parses, a missing file and a
// corrupt file each surface a labelled error.
func TestReadPublishedAuditKeys(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	good := filepath.Join(dir, "good.key")
	keyHex := strings.Repeat("ab", 32)
	if err := os.WriteFile(good, []byte(keyHex+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	keys, err := readPublishedAuditKeys(good, "after rename publish")
	if err != nil {
		t.Fatalf("readPublishedAuditKeys(good): %v", err)
	}
	if len(keys) != 1 || len(keys[0]) != 32 {
		t.Fatalf("expected one 32-byte key, got %d keys", len(keys))
	}

	if _, err := readPublishedAuditKeys(filepath.Join(dir, "missing.key"), "after create race"); err == nil {
		t.Error("expected error reading a missing key file")
	} else if !strings.Contains(err.Error(), "after create race") {
		t.Errorf("error should label the call site: %v", err)
	}

	corrupt := filepath.Join(dir, "corrupt.key")
	if err := os.WriteFile(corrupt, []byte("not-hex!!!\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := readPublishedAuditKeys(corrupt, "after rename publish"); err == nil {
		t.Error("expected error parsing a corrupt key file")
	}
}

// TestLoadOrCreateAuditKeys_RenameFallbackOnNoHardlink drives the real no-hardlink
// branch of loadOrCreateAuditKeys by making os.Link fail with EPERM via the osLink
// seam — the failure a CIFS/NFS/FAT volume produces. The proxy must still create a
// usable key (rather than erroring out), and that key must be durable and reload
// identically on the next start. Not parallel: it mutates the package-level
// osLink seam.
func TestLoadOrCreateAuditKeys_RenameFallbackOnNoHardlink(t *testing.T) {
	orig := osLink
	t.Cleanup(func() { osLink = orig })
	osLink = func(string, string) error { return syscall.EPERM }

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")

	keys, err := LoadOrCreateKeys(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateAuditKeys with link rejected: %v (regression: proxy refuses to start on a no-hardlink volume)", err)
	}
	if len(keys) != 1 || len(keys[0]) != 32 {
		t.Fatalf("expected one freshly generated 32-byte key, got %d keys", len(keys))
	}

	// The key must be on disk (published via rename), with no leftover temp files.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".audit-key-") {
			t.Errorf("temp file left behind after rename fallback: %s", e.Name())
		}
	}

	// A subsequent start must reload the very same persisted key (the file now
	// exists, so this hits the reload path and is independent of the seam).
	reloaded, err := LoadOrCreateKeys(keyPath)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !bytes.Equal(reloaded[0], keys[0]) {
		t.Fatal("reloaded key differs from the key published via the rename fallback")
	}
}

// TestCopyDetailValue_ClonesStringSlice is the regression for :
// cloneAndBound must copy []string values element-wise so the audit drainer
// never shares backing storage with the caller. The deep-clone contract must
// hold unconditionally rather than relying on the slice happening to be an
// immutable manifest constant.
func TestCopyDetailValue_ClonesStringSlice(t *testing.T) {
	t.Parallel()
	orig := []string{"10.0.0.0/8", "192.168.0.0/16"}
	cloned, ok := cloneAndBound(orig).([]string)
	if !ok {
		t.Fatalf("cloneAndBound did not return a []string for a []string input")
	}
	if len(cloned) != len(orig) {
		t.Fatalf("cloned length = %d, want %d", len(cloned), len(orig))
	}
	// Mutating the caller's slice must not reach the clone.
	orig[0] = "MUTATED"
	if cloned[0] != "10.0.0.0/8" {
		t.Fatalf("clone aliased the caller's []string: got %q", cloned[0])
	}
	// The clone must not share the backing array.
	if &cloned[0] == &orig[0] {
		t.Fatalf("clone shares the backing array with the caller")
	}

	// The same must hold for a []string nested inside a details map. cloneAndBound
	// (the per-value deep-clone marshalAndBoundDetails runs before its single
	// marshal) is tested directly: the storage-sharing check is meaningless after a
	// JSON round-trip, which would yield a fresh []interface{}.
	nested := cloneAndBound(map[string]interface{}{"allowedCIDRs": []string{"a", "b"}}).(map[string]interface{})
	ns := nested["allowedCIDRs"].([]string)
	src := []string{"a", "b"}
	if &ns[0] == &src[0] {
		t.Fatalf("nested []string clone unexpectedly shares storage")
	}
}

// cloneAndBound must apply auditDetailValueCap to each element of a []string,
// mirroring the scalar string case, so an oversized element is replaced with the
// self-describing placeholder rather than written verbatim.
func TestCopyDetailValue_BoundsStringSliceElements(t *testing.T) {
	t.Parallel()
	big := strings.Repeat("x", auditDetailValueCap+1)
	cloned, ok := cloneAndBound([]string{"short", big}).([]string)
	if !ok {
		t.Fatalf("cloneAndBound did not return a []string for a []string input")
	}
	if cloned[0] != "short" {
		t.Fatalf("under-cap element was altered: got %q", cloned[0])
	}
	if cloned[1] == big {
		t.Fatalf("oversized []string element was not truncated")
	}
	if !strings.Contains(cloned[1], "exceeding the") {
		t.Fatalf("oversized element placeholder missing: got %q", cloned[1])
	}
}

// TestAuditDropMarker_RetriesOnWriteFailure is the regression for :
// flushDropMarker must advance lastDroppedMarked only after the marker is
// durably written. If the marker write fails (full disk, EIO, a lost fd), the
// drop evidence must not be silently dropped from the tamper-evident chain — a
// later flush must retry and emit it once the writer recovers.
func TestAuditDropMarker_RetriesOnWriteFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
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

	// The backing writer is currently failing.
	failing := true
	s.writeLine = func(b []byte) (int, error) {
		if failing {
			return 0, fmt.Errorf("simulated disk full")
		}
		return f.Write(b)
	}

	// Two records were lost under back-pressure; the marker write fails, so the
	// marked count must stay put for a later retry.
	s.dropped.Store(2)
	s.flushDropMarker()
	if s.lastDroppedMarked != 0 {
		t.Fatalf("lastDroppedMarked advanced despite a failed marker write: got %d, want 0", s.lastDroppedMarked)
	}
	if s.writeFailures.Load() == 0 {
		t.Fatalf("expected a recorded write failure for the failed marker")
	}

	// Writer recovers: the next flush retries and durably writes the marker for
	// the full accumulated drop count.
	failing = false
	s.flushDropMarker()
	if s.lastDroppedMarked != 2 {
		t.Fatalf("lastDroppedMarked did not advance after a successful write: got %d, want 2", s.lastDroppedMarked)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	markers := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var rec auditRecord
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec.DenialCode == "AUDIT_RECORDS_DROPPED" {
			markers++
			if got := recordDetails(t, rec)["dropped_total"]; got != float64(2) {
				t.Errorf("drop marker dropped_total = %v, want 2", got)
			}
		}
	}
	if markers != 1 {
		t.Fatalf("expected exactly 1 durable drop marker after recovery, got %d", markers)
	}

	// The emitted marker must verify and chain cleanly.
	res := verifyBytes(t, logLines(t, logPath), &Sink{key: key})
	if !res.OK() {
		t.Fatalf("chain verification failed after retried drop marker: %+v", res)
	}
}

// TestAuditChain_DetectsRewrittenGenesis is the regression for : the
// first record of a fresh (non-rotated) log carries seq 1 and the genesis
// sentinel as its prev_hmac. An attacker who excises the true seq-1 record and
// rewrites the survivor to claim seq 1 leaves a prev_hmac that points at the
// deleted record rather than the genesis sentinel. verifyAuditLog must report a
// chain break for that first record even though the per-record chain comparison
// is otherwise skipped for the leading record.
func TestAuditChain_DetectsRewrittenGenesis(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b", "c") // seq 1,2,3
	lines := logLines(t, logPath)

	// Drop the real seq-1 record and present the seq-2 record rewritten to claim
	// seq 1. Its prev_hmac still links to the deleted seq-1 record (not genesis).
	survivor := strings.Replace(string(lines[1]), `"seq":2`, `"seq":1`, 1)
	if survivor == string(lines[1]) {
		t.Fatalf("test setup: seq field not found in record: %s", lines[1])
	}
	tampered := [][]byte{[]byte(survivor), lines[2]}

	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join(tampered, []byte("\n"))),
		verifierFor(t, keyPath), "", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if res.ChainBreaks == 0 {
		t.Fatalf("rewritten genesis went undetected: %+v\n%s", res, sb.String())
	}
	if !strings.Contains(sb.String(), "genesis") {
		t.Fatalf("expected a genesis-sentinel chain break message, got:\n%s", sb.String())
	}
}

// TestAuditChain_GenesisSentinelHonored guards against a false positive from the fix:
// a clean, untampered log (seq 1, genesis sentinel) must still pass
// with zero chain breaks.
func TestAuditChain_GenesisSentinelHonored(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b")
	res := verifyBytes(t, logLines(t, logPath), verifierFor(t, keyPath))
	if !res.OK() || res.ChainBreaks != 0 {
		t.Fatalf("clean genesis log flagged a chain break: %+v", res)
	}
	if res.FirstSeq != 1 {
		t.Fatalf("expected firstSeq=1, got %d", res.FirstSeq)
	}
}

// TestAuditSink_InjectedClock verifies the audit sink uses its injectable clock
// for both record timestamps and the rotation filename, so rotation and
// timestamping are testable with a fake clock without depending on host
// wall-clock granularity.
func TestAuditSink_InjectedClock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := dir + "/audit.jsonl"

	// 1-byte limit → the first record triggers rotation.
	sink, err := Open(logPath, dir+"/audit.key", 1, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	fixed := time.Date(2026, 6, 15, 7, 8, 9, 123456789, time.UTC)
	sink.now = func() time.Time { return fixed }

	// rotatedPath embeds the injected clock, not the host wall clock.
	got, err := sink.rotatedPath()
	if err != nil {
		t.Fatalf("rotatedPath: %v", err)
	}
	if !strings.Contains(got, "20260615T070809.123456789Z") {
		t.Errorf("rotatedPath() = %q, want it to embed the injected timestamp", got)
	}

	// A written record stamps the injected time in its Time field.
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	// The record landed in some file under dir (base or rotated sibling); find it
	// and confirm the injected time was stamped, not the host clock.
	want := `"time":"` + fixed.UTC().Format(time.RFC3339Nano) + `"`
	entries, _ := os.ReadDir(dir)
	found := false
	for _, e := range entries {
		if e.Name() == "audit.key" {
			continue
		}
		data, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if strings.Contains(string(data), want) {
			found = true
		}
	}
	if !found {
		t.Errorf("no audit record carried the injected time %s", want)
	}
}

// TestRecordBoundsDetailsBeforeEnqueue: record() must bound a
// record's Details before placing it on the queue, not in the drainer after
// dequeue. Otherwise the bounded channel could retain up to auditChannelSize
// un-truncated multi-MiB argument clones. The test inspects the queued record
// directly (the drainer is never started) and asserts the oversized value was
// already replaced with the placeholder at enqueue time.
func TestRecordBoundsDetailsBeforeEnqueue(t *testing.T) {
	s := &Sink{records: make(chan auditRecord, 1)}

	big := strings.Repeat("x", auditDetailValueCap+1)
	s.Record(context.Background(), RecordParams{
		SessionID: "sess", Identifier: "tool", Method: "tools/call", Decision: "allow",
		Details: map[string]interface{}{"body": big}, AuditOnly: true,
	})

	select {
	case rec := <-s.records:
		got, _ := recordDetails(t, rec)["body"].(string)
		if got == big {
			t.Fatal("queued record retained the un-truncated oversized value: bounding must happen before enqueue")
		}
		if !strings.Contains(got, "eunox") {
			t.Errorf("expected a truncation placeholder on the queued record, got %q", got)
		}
	default:
		t.Fatal("no record was enqueued")
	}
}

// TestBoundAuditDetails_TotalCapReplacesMap asserts a map made large by many
// moderate (individually under the per-value cap) values is replaced wholesale
// with the truncation marker.
func TestBoundAuditDetails_TotalCapReplacesMap(t *testing.T) {
	t.Parallel()
	m := make(map[string]interface{})
	// Each value is under the per-value cap, but together they exceed the total cap.
	chunk := strings.Repeat("y", 256<<10) // 256 KiB, < 512 KiB per-value cap
	for i := 0; i < 8; i++ {              // 8 * 256 KiB = 2 MiB > 1 MiB total cap
		m[fmt.Sprintf("k%d", i)] = chunk
	}
	// The total-cap collapse lives in marshalAndBoundDetails (it sizes the marshaled
	// clone); decode the returned blob to inspect the single-key marker.
	var out map[string]interface{}
	if err := json.Unmarshal(marshalAndBoundDetails(m), &out); err != nil {
		t.Fatalf("decode bounded details: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected a single-key marker map, got %d keys", len(out))
	}
	if _, ok := out[TruncatedKey]; !ok {
		t.Errorf("marker key %q missing: %v", TruncatedKey, out)
	}
}

func TestDeriveTargetFieldsBoundsEnvelope(t *testing.T) {
	bigName := strings.Repeat("a", auditEnvelopeFieldCap+1024)
	_, _, target := deriveTargetFields("tools/call", bigName)
	if len(target) >= len(bigName) {
		t.Fatalf("target not bounded: len=%d, want < %d", len(target), len(bigName))
	}
	if !strings.Contains(target, "truncated") {
		t.Errorf("expected a truncation marker in target, got prefix %q", target[:64])
	}

	// A short, legitimate value must pass through untouched.
	if _, _, got := deriveTargetFields("tools/call", "read_file"); got != "read_file" {
		t.Errorf("legitimate target altered: %q", got)
	}

	// An unrecognized raw method is also bounded.
	bigMethod := strings.Repeat("m", auditEnvelopeFieldCap+1024)
	gotMethod, _, _ := deriveTargetFields(bigMethod, "x")
	if len(gotMethod) >= len(bigMethod) {
		t.Fatalf("raw method not bounded: len=%d", len(gotMethod))
	}
}

// TestBoundFieldToHonorsLimitBelowMarker: boundFieldTo must
// honor its documented "returned string is always <= limit bytes" invariant even
// when the limit is smaller than the truncation marker itself. The old keep < 0
// branch returned the whole marker, which exceeds a tiny limit.
func TestBoundFieldToHonorsLimitBelowMarker(t *testing.T) {
	s := strings.Repeat("x", 1000)
	for _, limit := range []int{0, 1, 5, 12, 31} {
		got := boundFieldTo(s, limit)
		if len(got) > limit {
			t.Errorf("boundFieldTo(s, %d) returned %d bytes (%q), exceeding the limit", limit, len(got), got)
		}
	}
	// A value already within the limit is returned untouched even when the limit
	// is below the marker length.
	if got := boundFieldTo("abc", 5); got != "abc" {
		t.Errorf("under-limit value altered: %q", got)
	}
}

// TestBoundFieldToNeverSilentlyEmpties: when content is dropped
// (len(s) > limit) the result must carry a visible truncation marker for any
// usable limit, so an audit consumer can tell a silently-truncated field from a
// genuinely empty one. Only a non-positive limit — which cannot hold a single
// byte under the <= limit invariant — may return "".
func TestBoundFieldToNeverSilentlyEmpties(t *testing.T) {
	s := strings.Repeat("x", 1000)
	for limit := 1; limit <= 40; limit++ {
		got := boundFieldTo(s, limit)
		if len(got) > limit {
			t.Errorf("boundFieldTo(s, %d) = %q exceeds limit", limit, got)
		}
		if got == "" {
			t.Errorf("boundFieldTo(s, %d) silently returned empty for non-empty truncated content", limit)
		}
		// Once the limit can hold the short "..." marker, truncation is always
		// visibly signalled (either the short marker alone, or content + full marker).
		if limit >= len("...") && !strings.Contains(got, "...") {
			t.Errorf("boundFieldTo(s, %d) = %q carries no visible truncation marker", limit, got)
		}
	}
	// A zero limit cannot carry a marker; the empty return is the documented
	// caller-bug contract, not a silent drop for any real field cap.
	if got := boundFieldTo(s, 0); got != "" {
		t.Errorf("boundFieldTo(s, 0) = %q, want \"\"", got)
	}
}

// TestBoundFieldToTruncatesOnRuneBoundary: truncation must land
// on a UTF-8 rune boundary so the result is always valid UTF-8 — a byte-level cut
// can split a multi-byte rune, leaving orphaned continuation bytes that
// json.Marshal rewrites to the U+FFFD replacement character, corrupting the field
// in the log and in audit-verify output.
func TestBoundFieldToTruncatesOnRuneBoundary(t *testing.T) {
	// 300 bytes of 3-byte runes; the marker for a 300-byte value is 32 bytes, so as
	// limit sweeps the range many keep offsets land mid-rune (2 of every 3).
	s := strings.Repeat("世", 100)
	for limit := 36; limit < 90; limit++ {
		got := boundFieldTo(s, limit)
		if len(got) > limit {
			t.Errorf("boundFieldTo(s, %d) = %d bytes, exceeds the limit", limit, len(got))
		}
		if !utf8.ValidString(got) {
			t.Errorf("boundFieldTo(s, %d) produced invalid UTF-8: %q", limit, got)
		}
	}
}

// TestBoundFieldToSanitizesInvalidUTF8 is the regression for the false-positive
// audit-verify rejection found reviewing the canonical-form check: encoding/json's
// Marshal is not idempotent across a decode-then-re-encode round trip for a string
// holding invalid UTF-8 (a lone invalid byte marshals to the literal escape text
// `�` the first time, but decoding that and re-marshaling the resulting valid
// U+FFFD rune emits its raw UTF-8 bytes instead — two different on-disk forms for
// what is nominally one value). Every caller of boundFieldTo passes a field that can
// hold raw, unvalidated bytes (SessionID from the Mcp-Session-Id HTTP header,
// Target/Method envelope fields, JWT-claim identity fields), so normalizing here,
// before the value is ever marshaled the first time, is what restores the
// marshal round-trip idempotency both the HMAC recompute and VerifyRecord's
// canonical-form check depend on.
func TestBoundFieldToSanitizesInvalidUTF8(t *testing.T) {
	got := boundFieldTo("sess-\xc3-tail", auditSessionIDCap)
	if !utf8.ValidString(got) {
		t.Fatalf("boundFieldTo must always return valid UTF-8, got invalid: %q", got)
	}
	want := "sess-�-tail"
	if got != want {
		t.Fatalf("boundFieldTo(%q, %d) = %q, want %q (the invalid byte replaced with U+FFFD)", "sess-\xc3-tail", auditSessionIDCap, got, want)
	}

	// Idempotency: marshaling the sanitized value, decoding it, and marshaling again
	// must reproduce the identical bytes — the property the whole fix exists for.
	body1, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded string
	if err := json.Unmarshal(body1, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	body2, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(body1, body2) {
		t.Fatalf("sanitized value is not round-trip idempotent: first marshal %s, second marshal %s", body1, body2)
	}

	// A value that is already valid UTF-8 must pass through unchanged.
	if got := boundFieldTo("clean-session-id", auditSessionIDCap); got != "clean-session-id" {
		t.Errorf("boundFieldTo must not alter an already-valid string, got %q", got)
	}
}

// TestRecordOversizedSessionIDBounded: in HTTP mode the session
// ID comes from the client-controlled Mcp-Session-Id header and is stamped on every
// record, so a pathologically large value must be bounded like Target/Method to
// keep a single record from overflowing the 4 MiB audit-verify scanner buffer.
func TestRecordOversizedSessionIDBounded(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	hugeSession := strings.Repeat("S", 4<<20) // ~4 MiB attacker-controlled session id
	sink.RecordAllow(context.Background(), hugeSession, "read_file", "tools/call",
		nil, nil, false, nil, nil)

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	line := mustReadLastAuditLine(t, logPath)
	if line == "" {
		t.Fatal("no record written (or the oversized line overflowed the tail window)")
	}

	var rec auditRecord
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("written record does not parse: %v", err)
	}
	if len(rec.SessionID) > auditSessionIDCap {
		t.Fatalf("SessionID not bounded: len=%d, want <= %d", len(rec.SessionID), auditSessionIDCap)
	}
	if !strings.Contains(rec.SessionID, "truncated") {
		t.Errorf("expected a truncation marker in SessionID, got %d-byte value", len(rec.SessionID))
	}

	// A short, legitimate session id must pass through untouched.
	if got := boundFieldTo("0193b8e1-1f3a-7c0a-9b2e-9d3c4f5a6b7c", auditSessionIDCap); got != "0193b8e1-1f3a-7c0a-9b2e-9d3c4f5a6b7c" {
		t.Errorf("legitimate session id altered: %q", got)
	}

	// The record must verify against its own chain HMAC after bounding.
	if ok, err := sink.VerifyRecord([]byte(line)); err != nil || !ok {
		t.Fatalf("oversized-session-id record failed HMAC verification: ok=%v err=%v", ok, err)
	}
}

// TestRecordOversizedTargetStaysUnderVerifyWindow is an integration check:
// a ~4 MiB tool name (a denied unknown-tool request) must still produce an audit
// line far below the 4 MiB audit-verify / chain-resume window, and the record
// must remain readable and verifiable.
func TestRecordOversizedTargetStaysUnderVerifyWindow(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	hugeName := strings.Repeat("a", 4<<20) // ~4 MiB attacker-controlled tool name
	sink.RecordDeny(context.Background(), "sess", hugeName, "tools/call",
		"AUTHORIZATION_FAILED", "", nil, false)

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	line := mustReadLastAuditLine(t, logPath)
	if line == "" {
		t.Fatal("no record written (or the oversized line overflowed the tail window)")
	}
	if len(line) > 1<<20 {
		t.Fatalf("serialized record is %d bytes; the envelope was not bounded and approaches the 4 MiB window", len(line))
	}

	var rec auditRecord
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("written record does not parse: %v", err)
	}
	if !strings.Contains(rec.Target, "truncated") {
		t.Errorf("expected a truncated Target, got %d-byte value", len(rec.Target))
	}

	// The record must verify against its own chain HMAC.
	if ok, err := sink.VerifyRecord([]byte(line)); err != nil || !ok {
		t.Fatalf("oversized-target record failed HMAC verification: ok=%v err=%v", ok, err)
	}
}

// TestRecordBoundsAgentTaskID covers : AgentID and TaskID are
// IdP-supplied JWT claims whose length is not validated, so a misconfigured or
// compromised IdP could stamp a multi-megabyte value and push a single record
// past the 4 MiB audit-verify scanner buffer. They must be bounded to
// auditEnvelopeFieldCap like SessionID/Target/Method. This white-box test drives
// the identity extractor directly and asserts against the real constant; the
// package-main test exercises the same path through the live withJWTClaims wiring.
func TestRecordBoundsAgentTaskID(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	huge := strings.Repeat("A", 5<<20) // ~5 MiB attacker-controlled JWT claim
	sink, err := Open(logPath, keyPath, 0, 0, WithIdentity(func(context.Context) (string, string, string) {
		return huge, huge, huge
	}))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	line := mustReadLastAuditLine(t, logPath)
	if line == "" {
		t.Fatal("no record written (or the oversized line overflowed the tail window)")
	}
	if len(line) > 1<<20 {
		t.Fatalf("serialized record is %d bytes; AgentID/TaskID were not bounded", len(line))
	}

	var rec auditRecord
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("written record does not parse: %v", err)
	}
	if len(rec.AgentID) > auditEnvelopeFieldCap {
		t.Errorf("AgentID not bounded: len=%d, want <= %d", len(rec.AgentID), auditEnvelopeFieldCap)
	}
	if len(rec.TaskID) > auditEnvelopeFieldCap {
		t.Errorf("TaskID not bounded: len=%d, want <= %d", len(rec.TaskID), auditEnvelopeFieldCap)
	}
	if len(rec.UserID) > auditEnvelopeFieldCap {
		t.Errorf("UserID not bounded: len=%d, want <= %d", len(rec.UserID), auditEnvelopeFieldCap)
	}
	if !strings.Contains(rec.AgentID, "truncated") {
		t.Errorf("expected a truncation marker in AgentID, got %d-byte value", len(rec.AgentID))
	}

	// The record must verify against its own chain HMAC after bounding.
	if ok, err := sink.VerifyRecord([]byte(line)); err != nil || !ok {
		t.Fatalf("oversized-agent/task-id record failed HMAC verification: ok=%v err=%v", ok, err)
	}
}

// TestRecordUserID_SignAndVerifyRoundTrip pins the user_id audit field: a record
// stamped with the JWT subject signs and verifies, and is readable as a structured
// field. It also pins the extensibility guarantee that makes adding the field
// non-breaking — because user_id is `omitempty`, a record written WITHOUT it (an
// older record, or one with no JWT subject) carries no user_id key at all and still
// verifies. The HMAC is computed over the re-marshaled struct, so an absent
// omitempty field re-marshals identically and the signature is unaffected; a
// non-omitempty field would instead inject `"user_id":""` and break every prior
// record's signature. Required sign-and-verify round trip for a new audit field.
func TestRecordUserID_SignAndVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// First record carries a subject; second carries none (extractor returns "").
	subjects := []string{"user-7", ""}
	idx := 0
	sink, err := Open(logPath, keyPath, 0, 0, WithIdentity(func(context.Context) (string, string, string) {
		s := subjects[idx]
		idx++
		return "agent-1", "task-9", s
	}))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	recs := readAuditRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	if recs[0]["user_id"] != "user-7" {
		t.Errorf("record 0 user_id = %v, want user-7", recs[0]["user_id"])
	}
	// omitempty: an empty subject must leave the key absent, not present-and-empty.
	if _, present := recs[1]["user_id"]; present {
		t.Errorf("record 1 user_id must be omitted when the subject is empty, got %v", recs[1]["user_id"])
	}

	// Both records must verify: the one carrying user_id, and the one without it
	// (proving the omitempty field does not perturb the signature when absent).
	for _, line := range bytes.Split(bytes.TrimRight(mustReadFile(t, logPath), "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if ok, err := sink.VerifyRecord(line); err != nil || !ok {
			t.Fatalf("record failed HMAC verification: ok=%v err=%v (line: %s)", ok, err, line)
		}
	}
}

// TestBoundAuditObligations_NeverExceedsCap is a property test: for any
// obligations slice — including the adversarial shapes the incremental byte
// budget cuts closest on (many short entries that fill the budget to the byte,
// then a zero-length entry that triggers truncation with a long sentinel) — the
// returned slice MUST serialize within auditObligationsTotalCap, and when
// truncated must carry an in-order kept prefix plus a single sentinel whose count
// equals the number of omitted entries. This pins the cap invariant that
// previously held only in the arithmetic (and only by a single byte at the
// boundary), so a future change to the size estimate cannot silently breach it.
func TestBoundAuditObligations_NeverExceedsCap(t *testing.T) {
	rng := rand.New(rand.NewSource(619))

	check := func(in []string) {
		t.Helper()
		out := boundAuditObligations(in)
		encoded, err := json.Marshal(out)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if len(encoded) > auditObligationsTotalCap {
			t.Fatalf("result serializes to %d bytes, exceeding the %d-byte cap (input had %d entries)",
				len(encoded), auditObligationsTotalCap, len(in))
		}
		// If truncated, validate the sentinel shape and count.
		if len(out) > 0 && len(out) < len(in) {
			sentinel := out[len(out)-1]
			const prefix = "obligations_truncated:"
			if !strings.HasPrefix(sentinel, prefix) {
				t.Fatalf("truncated result last element = %q, want a %q sentinel", sentinel, prefix)
			}
			kept := out[:len(out)-1]
			for i := range kept {
				if kept[i] != in[i] {
					t.Fatalf("kept[%d] = %q is not an in-order prefix of the input", i, kept[i])
				}
			}
			var omitted int
			if _, err := fmt.Sscanf(sentinel, prefix+"%d", &omitted); err != nil {
				t.Fatalf("sentinel %q carries no count: %v", sentinel, err)
			}
			if want := len(in) - len(kept); omitted != want {
				t.Fatalf("sentinel count = %d, want %d", omitted, want)
			}
		}
	}

	// Randomized trials over a range of entry counts and lengths that straddle the
	// cap, so truncation fires across many different prefix/sentinel boundaries.
	for trial := 0; trial < 3000; trial++ {
		n := rng.Intn(4000) + 1
		in := make([]string, n)
		for i := range in {
			in[i] = strings.Repeat("x", rng.Intn(40)) // includes zero-length entries
		}
		check(in)
	}

	// Targeted boundary cases: a long prefix of length-1 entries filling the budget
	// to the byte, then a zero-length entry that triggers truncation — the exact
	// shape that argued could overflow. Sweep the prefix length across the boundary.
	for filler := 16300; filler <= 16400; filler++ {
		in := make([]string, 0, filler+1)
		for i := 0; i < filler; i++ {
			in = append(in, "a")
		}
		in = append(in, "")
		check(in)
	}
}

// TestBoundAuditObligations_EscapeHeavyRespectsCap: the
// slow path previously sized each entry by its raw byte length, but JSON encoding
// expands ", \, and control characters. A set of escape-heavy strings whose raw
// lengths sum under the cap can serialize well past it, so the old "all entries
// fit" return emitted an over-cap slice. With exact per-entry accounting the result
// must serialize within auditObligationsTotalCap.
func TestBoundAuditObligations_EscapeHeavyRespectsCap(t *testing.T) {
	// Each entry is 1000 double-quote characters: raw 1000 bytes, but ~2002 bytes
	// once JSON-escaped (\" plus the surrounding quotes). 40 entries are ~40 KB raw
	// (under the 64 KiB cap) yet ~80 KB encoded (over it) — exactly the shape that
	// fooled the raw-length estimate.
	const n = 40
	in := make([]string, n)
	for i := range in {
		in[i] = strings.Repeat(`"`, 1000)
	}

	// Sanity: the raw-length sum is under the cap (so the buggy estimate would have
	// returned everything), but the true encoding is over it.
	rawSum := 0
	for _, s := range in {
		rawSum += len(s)
	}
	if rawSum >= auditObligationsTotalCap {
		t.Fatalf("test precondition: raw sum %d should be under the %d cap", rawSum, auditObligationsTotalCap)
	}
	full, _ := json.Marshal(in)
	if len(full) <= auditObligationsTotalCap {
		t.Fatalf("test precondition: encoded input %d should exceed the %d cap", len(full), auditObligationsTotalCap)
	}

	out := boundAuditObligations(in)
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if len(encoded) > auditObligationsTotalCap {
		t.Fatalf("escape-heavy result serializes to %d bytes, exceeding the %d-byte cap", len(encoded), auditObligationsTotalCap)
	}
	// It must have truncated (fewer than n entries) and carry the sentinel.
	if len(out) >= n {
		t.Fatalf("expected truncation of escape-heavy input; got %d entries (input %d)", len(out), n)
	}
	if last := out[len(out)-1]; !strings.HasPrefix(last, "obligations_truncated:") {
		t.Errorf("truncated result missing sentinel; last = %q", last)
	}
}

// TestBoundAuditObligations_UnderCapUnchanged: a realistic obligations slice
// (well under the cap) is returned untouched, so the common path adds no overhead
// and loses no information.
func TestBoundAuditObligations_UnderCapUnchanged(t *testing.T) {
	in := []string{"redactFields", "redactFields:$.ssn", "redactFields:$.dob"}
	out := boundAuditObligations(in)
	if len(out) != len(in) {
		t.Fatalf("under-cap slice was modified: got %v, want %v", out, in)
	}
	for i := range in {
		if out[i] != in[i] {
			t.Errorf("out[%d] = %q, want %q", i, out[i], in[i])
		}
	}
}

// TestBoundAuditObligations_OverCapTruncatedWithSentinel: an oversized slice is
// truncated to a prefix plus a single "obligations_truncated:N" sentinel.
// The sentinel's N must equal the number of omitted entries, the kept entries must
// be a prefix of the input in order, and the result must serialize within the cap.
func TestBoundAuditObligations_OverCapTruncatedWithSentinel(t *testing.T) {
	// Each entry is ~1 KiB; ~256 of them blow past the 64 KiB cap.
	const n = 256
	entry := strings.Repeat("a", 1024)
	in := make([]string, n)
	for i := range in {
		in[i] = fmt.Sprintf("%s-%d", entry, i)
	}

	out := boundAuditObligations(in)

	if len(out) == 0 {
		t.Fatal("truncation dropped everything; expected a kept prefix plus a sentinel")
	}
	if len(out) >= len(in) {
		t.Fatalf("oversized slice was not truncated: got %d entries, input had %d", len(out), len(in))
	}

	// Last element is the sentinel; everything before it is an in-order prefix.
	sentinel := out[len(out)-1]
	const prefix = "obligations_truncated:"
	if !strings.HasPrefix(sentinel, prefix) {
		t.Fatalf("last element = %q, want an %q sentinel", sentinel, prefix)
	}
	kept := out[:len(out)-1]
	for i := range kept {
		if kept[i] != in[i] {
			t.Fatalf("kept[%d] = %q, not an in-order prefix of the input (%q)", i, kept[i], in[i])
		}
	}

	// N must be exactly the number of omitted entries.
	var omitted int
	if _, err := fmt.Sscanf(sentinel, prefix+"%d", &omitted); err != nil {
		t.Fatalf("sentinel %q does not carry a count: %v", sentinel, err)
	}
	if want := len(in) - len(kept); omitted != want {
		t.Errorf("sentinel count = %d, want %d (omitted = input %d - kept %d)", omitted, want, len(in), len(kept))
	}

	// The whole point of the cap: the truncated slice fits the budget.
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal truncated obligations: %v", err)
	}
	if len(encoded) > auditObligationsTotalCap {
		t.Errorf("truncated obligations serialize to %d bytes, exceeding the %d-byte cap", len(encoded), auditObligationsTotalCap)
	}
}

// TestIsOverCapValuePlaceholder pins the producer/detector round-trip: every value
// overCapPlaceholder emits is recognized by IsOverCapValuePlaceholder, while a
// genuine value that merely begins with the "[eunox: omitted " prefix (or omits
// the trailing structure) is NOT — so a consumer like `suggest` cannot mistake a
// real argument value for a redacted one and silently drop it from a draft.
func TestIsOverCapValuePlaceholder(t *testing.T) {
	t.Parallel()

	// Real placeholders, across a range of sizes, must all match.
	for _, n := range []int{0, 1, auditDetailValueCap, auditDetailValueCap + 1, 5_000_000} {
		if got := overCapPlaceholder(n); !IsOverCapValuePlaceholder(got) {
			t.Errorf("IsOverCapValuePlaceholder(%q) = false, want true (overCapPlaceholder output must round-trip)", got)
		}
	}

	// Non-placeholders, including the dangerous prefix-collision case, must not match.
	for _, s := range []string{
		"",
		"id",
		"[eunox: omitted ",          // bare prefix only
		"[eunox: omitted secrets]",  // prefix but not the structured form
		"[eunox: omitted 12 bytes]", // a plausible look-alike, wrong shape
		" [eunox: omitted 5-byte value exceeding the 4096-byte audit detail cap]", // leading space defeats the anchor
		"[eunox: omitted 5-byte value exceeding the 4096-byte audit detail cap] trailing",
	} {
		if IsOverCapValuePlaceholder(s) {
			t.Errorf("IsOverCapValuePlaceholder(%q) = true, want false (not a placeholder)", s)
		}
	}
}

// TestRecordBoundsObligationsBeforeEnqueue mirrors the Details bounding test
// : record() must bound the obligations slice before placing the record
// on the queue, so the bounded channel never retains an oversized obligations list.
// The drainer is never started; the queued record is inspected directly.
func TestRecordBoundsObligationsBeforeEnqueue(t *testing.T) {
	s := &Sink{records: make(chan auditRecord, 1)}

	big := make([]string, 100_000)
	for i := range big {
		big[i] = fmt.Sprintf("redactFields:$.deeply.nested.path.segment.%d", i)
	}
	s.Record(context.Background(), RecordParams{
		SessionID: "sess", Identifier: "tool", Method: "tools/call", Decision: "allow",
		Obligations: big, AuditOnly: true,
	})

	select {
	case rec := <-s.records:
		encoded, err := json.Marshal(rec.Obligations)
		if err != nil {
			t.Fatalf("marshal queued obligations: %v", err)
		}
		if len(encoded) > auditObligationsTotalCap {
			t.Fatalf("queued record retained oversized obligations (%d bytes > %d cap): bounding must happen before enqueue",
				len(encoded), auditObligationsTotalCap)
		}
		last := rec.Obligations[len(rec.Obligations)-1]
		if !strings.HasPrefix(last, "obligations_truncated:") {
			t.Errorf("expected an obligations_truncated sentinel on the queued record, got %q", last)
		}
	default:
		t.Fatal("no record was enqueued")
	}
}

// TestAuditVerify_LargeObligationsRoundTrip is an end-to-end guard: a record
// produced from a manifest with a huge obligations list must stay within the
// 4 MiB audit-verify scanner buffer and still verify, because record() bounds the
// obligations before signing. Without the cap the line would exceed the buffer and
// audit-verify would fail with bufio.ErrTooLong, making the log unverifiable.
func TestAuditVerify_LargeObligationsRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	obligs := make([]string, 200_000)
	for i := range obligs {
		obligs[i] = fmt.Sprintf("redactFields:$.a.b.c.d.e.f.g.h.i.j.k[%d]", i)
	}
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, obligs, true, nil, nil)

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	if len(lines) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(lines))
	}
	if len(lines[0]) >= 4<<20 {
		t.Fatalf("record line is %d bytes, at or past the 4 MiB audit-verify buffer", len(lines[0]))
	}

	verifier := verifierFor(t, keyPath)
	res := verifyBytes(t, lines, verifier)
	if !res.OK() {
		t.Errorf("audit log with a large (bounded) obligations slice failed verification: %+v", res)
	}
}

// TestAuditSink_ConcurrentRecordDuringClose: the close-time
// read of the drop counter now happens under the write lock so the shutdown
// warning counts every record() that has entered its critical section. The new
// lock acquisition must not deadlock against record()'s read lock. Run under -race
// with many producers racing Close; the test asserts no deadlock/panic and that
// the (authoritative) drop counter never exceeds the records attempted.
func TestAuditSink_ConcurrentRecordDuringClose(t *testing.T) {
	dir := t.TempDir()
	sink, err := Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	const producers = 64
	const perProducer = 5
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < perProducer; j++ {
				// Some of these race Close and hit the closed-drop path.
				sink.RecordAllow(context.Background(), "sess", "tool", "tools/call", nil, nil, false, nil, nil)
			}
		}()
	}
	close(start) // unleash producers
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wg.Wait()

	if d := sink.DroppedRecords(); d > producers*perProducer {
		t.Fatalf("dropped count %d exceeds %d attempted records", d, producers*perProducer)
	}
}

// TestAuditSink_Close_ReportsWriteFailures: records lost
// mid-operation (disk errors, marshal failures) are counted in writeFailures but
// never reach disk. A clean final Sync/Close must NOT mask that — Close() has to
// return a non-nil error so a caller checking only Close()'s result learns the
// audit trail is incomplete (fail-closed), not just the operator reading stderr.
func TestAuditSink_Close_ReportsWriteFailures(t *testing.T) {
	dir := t.TempDir()
	sink, err := Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	// Simulate records lost during the session. Sync/Close of the (healthy) file
	// will succeed, so the returned error must come from the write-failure count.
	sink.writeFailures.Add(3)

	closeErr := sink.Close()
	if closeErr == nil {
		t.Fatal("Close returned nil despite 3 mid-operation write failures")
	}
	if !strings.Contains(closeErr.Error(), "failed to write") || !strings.Contains(closeErr.Error(), "3") {
		t.Errorf("Close error %q does not report the 3 lost records", closeErr)
	}
}

// TestAuditSink_Close_JoinsSyncAndCloseErrors: when both
// s.f.Sync() and s.f.Close() fail in the Close() teardown, the old code set closeErr
// to the Close error then unconditionally overwrote it with the Sync error, silently
// discarding the Close error (a swallowed descriptor-release failure). errors.Join
// now preserves both.
//
// To force both calls to fail, the underlying file descriptor is closed out from
// under the sink before Close() runs, so the Close() path's own Sync() and Close()
// both return "file already closed".
func TestAuditSink_Close_JoinsSyncAndCloseErrors(t *testing.T) {
	dir := t.TempDir()
	sink, err := Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	// Pre-close the fd: now the teardown's Sync() AND Close() will both fail.
	if err := sink.f.Close(); err != nil {
		t.Fatalf("pre-closing the underlying fd: %v", err)
	}

	closeErr := sink.Close()
	if closeErr == nil {
		t.Fatal("Close returned nil; expected the joined Sync and Close errors")
	}

	// errors.Join packs both errors into a value whose Unwrap returns []error. The
	// old single-assignment code returned just one *PathError, which does not satisfy
	// this interface — so requiring exactly two joined errors fails on the old code
	// and passes only when both Sync and Close errors are preserved.
	joined, ok := closeErr.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("closeErr is not a joined error (%T); the Close error was dropped, not preserved", closeErr)
	}
	if n := len(joined.Unwrap()); n != 2 {
		t.Fatalf("joined error holds %d errors, want 2 (both Sync and Close must be preserved)", n)
	}
	// Both underlying failures are "file already closed"; errors.Is traverses the
	// join, so this confirms the joined value carries the real fd errors.
	if !errors.Is(closeErr, os.ErrClosed) {
		t.Errorf("joined error does not wrap os.ErrClosed: %v", closeErr)
	}
}

func TestAuditSink_AsyncWrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	const calls = 1000
	const ceiling = 250 * time.Millisecond // 250 µs/call amortized; a sync write would be orders of magnitude slower
	start := time.Now()
	for i := 0; i < calls; i++ {
		sink.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	}
	elapsed := time.Since(start)
	if elapsed > ceiling {
		t.Errorf("regression: %d Record calls took %v (%.2f µs/call); must not block on disk I/O",
			calls, elapsed, float64(elapsed.Microseconds())/float64(calls))
	}

	// All `calls` enqueues must fit the buffer — none dropped. This pins the
	// channel-capacity assumption (calls < auditChannelSize): a future shrink of
	// auditChannelSize below `calls` would fail here loudly rather than silently
	// turning the throughput check into a measurement of dropped, never-written
	// sends.
	if n := sink.DroppedRecords(); n != 0 {
		t.Errorf("regression: %d of %d records dropped; the %d-deep buffer must absorb them all",
			n, calls, auditChannelSize)
	}

	// Close drains the channel and flushes to disk.
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	if len(data) == 0 {
		t.Error("regression: audit log is empty after Close")
	}
	if !strings.Contains(string(data), `"target":"read_file"`) {
		t.Errorf("regression: expected target=read_file in log; got %q", string(data))
	}
}

// TestAuditSink_RecordDoesNotBlockOnSlowWriter proves the non-blocking property
// by construction rather than by a timing margin: with the drainer's backing
// write artificially stalled, Record must still return promptly because it only
// enqueues onto the buffered channel while the background drainer owns the
// write. This is the "artificially slow writer" case the original timing test
// described but never actually exercised, and unlike a wall-clock throughput
// ceiling it does not depend on how fast a real disk is. A regression that
// removed the buffer (an unbuffered channel) or otherwise made Record wait on
// the drainer would make the enqueue inherit the stall and overrun the ceiling.
func TestAuditSink_RecordDoesNotBlockOnSlowWriter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	// Stall the drainer on its first write for far longer than the enqueue
	// ceiling. Only the first write sleeps, so Close (which drains the rest)
	// stays fast. writeLine is set before any record is sent; the drainer reads
	// it only after a channel receive, so the send/receive ordering publishes it
	// race-free, and the `writes` counter is touched solely by the drainer.
	const stall = 300 * time.Millisecond
	const ceiling = 100 * time.Millisecond
	writes := 0
	sink.writeLine = func(b []byte) (int, error) {
		writes++
		if writes == 1 {
			time.Sleep(stall)
		}
		return len(b), nil
	}

	start := time.Now()
	for i := 0; i < 20; i++ {
		sink.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	}
	elapsed := time.Since(start)
	if elapsed > ceiling {
		t.Errorf("regression: 20 Record calls took %v with the writer stalled; Record must not wait on the drainer's write", elapsed)
	}

	// Close blocks until the drainer finishes the in-flight stalled write and
	// flushes the rest.
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestAuditSink_WriteFailuresCounted verifies that records which reach the
// drainer but cannot be written to disk (full disk / EIO) are counted via
// WriteFailures and are NOT misattributed to DroppedRecords. The two counters
// are deliberately distinct: DroppedRecords is a "queue is full" signal on a
// healthy file, WriteFailures is a "file is broken" completeness signal. The
// original gap this guards against: a persistent write failure degraded audit
// coverage while eunox_audit_dropped_records_total stayed at zero.
func TestAuditSink_WriteFailuresCounted(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	// Fail every write. writeLine is the sole disk seam and is touched only by
	// the single drainer goroutine, so a plain counter is race-free; it is set
	// before any record is sent, so the send/receive ordering publishes it.
	attempts := 0
	sink.writeLine = func(b []byte) (int, error) {
		attempts++
		return 0, errors.New("simulated disk failure (ENOSPC)")
	}

	const n = 50
	for i := 0; i < n; i++ {
		sink.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	}

	// Close drains the queue. The backing file is real, so its Sync/Close succeed;
	// the only error is the mid-operation write-failure report Close() now surfaces
	// so a caller learns the trail is incomplete.
	closeErr := sink.Close()
	if closeErr == nil {
		t.Fatal("Close() returned nil despite write failures; it must surface the incomplete audit trail")
	}
	if !strings.Contains(closeErr.Error(), "failed to write") {
		t.Errorf("Close() error %q does not report the write failures", closeErr)
	}

	// The queue absorbed every send (nothing dropped under back-pressure), so the
	// loss must surface as write failures, not as queue-full drops.
	if got := sink.DroppedRecords(); got != 0 {
		t.Errorf("DroppedRecords() = %d; want 0 (the queue absorbed every send)", got)
	}
	if got := sink.WriteFailures(); got != int64(n) {
		t.Errorf("WriteFailures() = %d; want %d (every write failed)", got, n)
	}
	if attempts < n {
		t.Errorf("drainer attempted %d writes; want >= %d", attempts, n)
	}
}

// TestAuditDegraded_Dropped pins the AuditDegraded signal the
// --require-audit=strict gate consults. A fresh sink is healthy; a record dropped
// under back-pressure (here, the deterministic post-close drop path) flips it to
// degraded. The reason string names the degradation without echoing record
// content. (The write-failure axis is covered by TestAuditDegraded_WriteFailure.)
func TestAuditDegraded_Dropped(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	if degraded, reason, detail := sink.AuditDegraded(); degraded {
		t.Fatalf("fresh sink reported degraded (%q, %v); want healthy", reason, detail)
	}

	// Close, then record: the post-close path counts the record as a drop
	// deterministically (TestAuditSink_RecordAfterClose_DropsWithoutPanic).
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)

	degraded, reason, detail := sink.AuditDegraded()
	if !degraded {
		t.Fatal("AuditDegraded() = false after a dropped record; want true")
	}
	if !strings.Contains(reason, "dropped") {
		t.Errorf("reason %q does not mention the drop", reason)
	}
	// The discrete detail carries the dropped count (no prose), suitable for a
	// structured audit field.
	if _, ok := detail["reason"]; ok {
		t.Errorf("detail must not carry a free-form \"reason\" key; got %v", detail)
	}
	if _, ok := detail["dropped_count"]; !ok {
		t.Errorf("detail = %v, want a discrete \"dropped_count\" key", detail)
	}
}

// TestAuditDegraded_WriteFailure drives the write-failure axis through the
// writeLine seam (mirroring TestAuditSink_WriteFailuresCounted) and confirms
// AuditDegraded reports it independently of any queue drop.
func TestAuditDegraded_WriteFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	sink.writeLine = func(b []byte) (int, error) {
		return 0, errors.New("simulated disk failure (ENOSPC)")
	}
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	_ = sink.Close() // drains the queue; the write fails and bumps writeFailures

	degraded, reason, detail := sink.AuditDegraded()
	if !degraded {
		t.Fatal("AuditDegraded() = false after a write failure; want true")
	}
	if !strings.Contains(reason, "write failure") {
		t.Errorf("reason %q does not mention the write failure", reason)
	}
	if _, ok := detail["reason"]; ok {
		t.Errorf("detail must not carry a free-form \"reason\" key; got %v", detail)
	}
	if _, ok := detail["write_failure_count"]; !ok {
		t.Errorf("detail = %v, want a discrete \"write_failure_count\" key", detail)
	}
}

// TestAuditDegraded_NilReceiver pins the nil-receiver contract the routeSink
// delegate and the strict gate rely on: a nil sink reports healthy, never panics.
func TestAuditDegraded_NilReceiver(t *testing.T) {
	t.Parallel()
	var s *Sink
	if degraded, _, detail := s.AuditDegraded(); degraded || detail != nil {
		t.Error("nil *Sink must report healthy (false, nil detail), not degraded")
	}
}

// TestAuditSink_DroppedRecordsCounter verifies that when the internal channel
// is full the dropped counter is incremented and Record does not block.
func TestAuditSink_DroppedRecordsCounter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	// Fill the channel beyond its capacity by writing more than auditChannelSize
	// records while keeping the drainer goroutine blocked.  We achieve this by
	// temporarily replacing the file with a pipe whose reader we never drain.
	// However, since the drainer is already running as a goroutine we cannot
	// block it cleanly in a unit test without a real slow filesystem.
	//
	// Instead we saturate the channel directly: drain is running concurrently,
	// so we need to send faster than it can drain.  We drain the sink's file
	// writes to /dev/null so the drainer is fast, then pre-fill the channel to
	// capacity by sending records in a tight loop.  The key invariant under test
	// is that after overflow Record does NOT block.
	const total = auditChannelSize + 256
	var wg sync.WaitGroup
	// Flood the channel with total records from many goroutines at once.
	// Some will be queued, the rest must be dropped non-blockingly.
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sink.RecordAllow(context.Background(), "sess", "tool", "tools/call", nil, nil, false, nil, nil)
		}()
	}
	wg.Wait() // Must complete quickly — no goroutine may be stuck.

	_ = sink.Close()

	dropped := sink.DroppedRecords()
	if dropped < 0 {
		t.Errorf("DroppedRecords() = %d; must be ≥ 0", dropped)
	}
	// We cannot assert a precise drop count because the drainer races with the
	// senders, but if any records were dropped the counter must reflect it.
	// The test's real assertion is that wg.Wait() above returned promptly.
	t.Logf("DroppedRecords() = %d / %d total", dropped, total)
}

// TestLoadOrCreateAuditKey_CorruptHex_HardError verifies that a key file with
// invalid hex data returns an error rather than being silently overwritten.
func TestLoadOrCreateAuditKey_CorruptHex_HardError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")

	if err := os.WriteFile(keyPath, []byte("not-valid-hex!!!"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := loadOrCreateAuditKey(keyPath)
	if err == nil {
		t.Fatal("regression: corrupt key file must return a hard error, not be silently regenerated")
	}
}

func TestLoadOrCreateAuditKey_ShortKey_HardError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")

	if err := os.WriteFile(keyPath, []byte(strings.Repeat("ab", 16)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := loadOrCreateAuditKey(keyPath)
	if err == nil {
		t.Fatal("regression: truncated key file must return a hard error")
	}
}

func TestLoadOrCreateAuditKey_ValidKey_Loads(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")

	want := make([]byte, 32)
	for i := range want {
		want[i] = byte(i)
	}
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(want)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := loadOrCreateAuditKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateAuditKey: %v", err)
	}
	for i, b := range got {
		if b != want[i] {
			t.Fatalf("loaded key byte %d = %d, want %d", i, b, want[i])
		}
	}
}

func TestLoadOrCreateAuditKey_Absent_Creates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "subdir", "newkey.key")

	got, err := loadOrCreateAuditKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateAuditKey: %v", err)
	}
	if len(got) != 32 {
		t.Errorf("expected 32-byte key, got %d bytes", len(got))
	}
}

func TestLoadOrCreateAuditKey_CorruptFile_DoesNotOverwrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")

	corrupt := []byte("not-valid-hex!!!")
	if err := os.WriteFile(keyPath, corrupt, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, _ = loadOrCreateAuditKey(keyPath)

	got, err := os.ReadFile(keyPath) //nolint:gosec // test-only read of temp file
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, corrupt) {
		t.Error("regression: corrupt key file was overwritten by loadOrCreateAuditKey")
	}
}

func TestSEC02_VerifyRecord_ConstantTimeHMAC(t *testing.T) {
	key := []byte("test-hmac-key-for-sec02")
	sink := &Sink{key: key}

	// Build a valid audit record using the same struct+marshal path as Record().
	// VerifyRecord now unmarshals into auditRecord before re-signing, so the
	// test record must use the real struct field names or the HMAC will mismatch.
	rec := auditRecord{
		ClassUID:    6003,
		CategoryUID: 6,
		ActivityID:  1,
		Time:        "2026-01-01T00:00:00Z",
		RequestID:   "test-req-id",
		SessionID:   "sess-123",
		Target:      "read_file",
		Decision:    "allow",
	}
	body, _ := json.Marshal(rec) // rec.HMAC is "" — omitted by omitempty
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	sig := "sha256:" + hex.EncodeToString(mac.Sum(nil))
	rec.HMAC = sig
	line, _ := json.Marshal(rec)

	t.Run("valid HMAC passes", func(t *testing.T) {
		ok, err := sink.VerifyRecord(line)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Error("expected VerifyRecord to return true for valid signature")
		}
	})

	t.Run("tampered body fails", func(t *testing.T) {
		tampered := strings.Replace(string(line), "allow", "deny", 1)
		ok, err := sink.VerifyRecord([]byte(tampered))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok {
			t.Error("expected VerifyRecord to return false for tampered body")
		}
	})

	t.Run("wrong HMAC fails", func(t *testing.T) {
		bad := strings.Replace(string(line), sig[:10], "sha256:0000", 1)
		ok, err := sink.VerifyRecord([]byte(bad))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok {
			t.Error("expected VerifyRecord to return false for wrong HMAC")
		}
	})

	t.Run("missing HMAC field fails", func(t *testing.T) {
		noHMAC := strings.Replace(string(line), `"`+sig+`"`, `""`, 1)
		ok, err := sink.VerifyRecord([]byte(noHMAC))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok {
			t.Error("expected VerifyRecord to return false when _hmac is empty")
		}
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		_, err := sink.VerifyRecord([]byte("not json"))
		if err == nil {
			t.Error("expected error for invalid JSON input")
		}
	})

	t.Run("trailing data after record fails", func(t *testing.T) {
		// {…valid signed record…}GARBAGE must not verify: Decoder.Decode stops at
		// the end of the record and would otherwise ignore the trailing bytes,
		// HMAC-verifying a tampered line. The HMAC is computed over the re-marshaled
		// fields, so without a trailing-data guard the appended bytes are invisible
		// to the signature check.
		appended := append(append([]byte{}, line...), []byte("GARBAGE")...)
		ok, err := sink.VerifyRecord(appended)
		if ok {
			t.Error("expected VerifyRecord to return false for a record line with trailing data")
		}
		if err == nil {
			t.Error("expected an error reporting the trailing data")
		}
	})
}

// TestMethodTargetType verifies the method→type mapping deriveTargetFields uses to
// record each MCP method under the correct namespace.
func TestMethodTargetType(t *testing.T) {
	cases := []struct {
		method string
		want   capability.TargetType
	}{
		{"tools/call", capability.TargetTypeTool},
		{"tools/list", capability.TargetTypeTool},
		{"resources/read", capability.TargetTypeResource},
		{"resources/subscribe", capability.TargetTypeResource},
		{"resources/list", capability.TargetTypeResource},
		{"prompts/get", capability.TargetTypePrompt},
		{"prompts/list", capability.TargetTypePrompt},
		{"sampling/createMessage", capability.TargetTypeSystem},
	}

	for _, tc := range cases {
		tt, ok := capability.MethodTargetType(tc.method)
		if !ok {
			t.Errorf("MethodTargetType(%q): unexpectedly unmapped", tc.method)
			continue
		}
		if tt != tc.want {
			t.Errorf("MethodTargetType(%q) = %q, want %q", tc.method, tt, tc.want)
		}
	}

	if _, ok := capability.MethodTargetType("unknown/method"); ok {
		t.Error("MethodTargetType(unknown) should report no mapping")
	}
}
func TestAuditPruneRotated(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	// The active log plus four rotated siblings with sortable, distinct stamps,
	// and one unrelated file that must never be touched.
	mustWrite := func(name string) {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	mustWrite(logPath)
	// Rotated siblings in the real nanosecond-resolution layout rotatedPath emits
	// (matched by rotatedAuditRe). The names are fixed-width, so lexical order is
	// chronological; the newest also carries the ".N" collision backstop that
	// uniqueRotatedPath can append, exercising that regex branch.
	rotated := []string{
		logPath + ".20260101T000000.000000000Z",
		logPath + ".20260102T000000.000000000Z",
		logPath + ".20260103T000000.000000000Z",
		logPath + ".20260104T000000.000000000Z.1",
	}
	for _, r := range rotated {
		mustWrite(r)
	}
	unrelated := logPath + ".keep" // does not match the rotated-suffix regex
	mustWrite(unrelated)
	// A legacy second-precision name is NOT a shape rotatedPath produces; it must
	// not be treated as a rotated sibling (guards against a too-loose regex).
	staleFormat := logPath + ".20251231T235959Z"
	mustWrite(staleFormat)

	s := &Sink{logPath: logPath, retain: 2}
	s.pruneRotated()

	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	// The two oldest rotated files are deleted; the two newest survive.
	if exists(rotated[0]) || exists(rotated[1]) {
		t.Errorf("oldest rotated files should have been pruned")
	}
	if !exists(rotated[2]) || !exists(rotated[3]) {
		t.Errorf("two newest rotated files must be retained")
	}
	if !exists(logPath) {
		t.Errorf("active log must never be pruned")
	}
	if !exists(unrelated) {
		t.Errorf("a non-rotated sibling must never be pruned")
	}
	if !exists(staleFormat) {
		t.Errorf("a non-matching second-precision sibling must never be pruned")
	}
}

func TestAuditPruneRotated_RetainZeroKeepsAll(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	suffixes := []string{".20260101T000000.000000000Z", ".20260102T000000.000000000Z"}
	for _, suffix := range suffixes {
		if err := os.WriteFile(logPath+suffix, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := &Sink{logPath: logPath, retain: 0}
	s.pruneRotated() // retain 0 = keep everything
	for _, suffix := range suffixes {
		if _, err := os.Stat(logPath + suffix); err != nil {
			t.Errorf("retain=0 must keep %s, got %v", suffix, err)
		}
	}
}

// TestRotatedAuditReMatchesProducer ties the pruning regex to the producer: a
// rotated name from rotatedPath() (and its ".N" collision backstop) must match
// rotatedAuditRe, or pruneRotated silently matches nothing and retention never
// fires. This is the regression guard for the format-drift that let the
// nanosecond-resolution suffix slip past a second-precision regex.
func TestRotatedAuditReMatchesProducer(t *testing.T) {
	dir := t.TempDir()
	s := &Sink{logPath: filepath.Join(dir, "audit.jsonl")}
	rotated, err := s.rotatedPath()
	if err != nil {
		t.Fatalf("rotatedPath: %v", err)
	}
	suffix := rotated[len(s.logPath):]
	if !rotatedAuditRe.MatchString(suffix) {
		t.Fatalf("rotatedAuditRe does not match rotatedPath() suffix %q — pruning would never fire", suffix)
	}
	if !rotatedAuditRe.MatchString(suffix + ".1") {
		t.Errorf("rotatedAuditRe must match the uniqueRotatedPath .N backstop, suffix=%q", suffix+".1")
	}
}

// -----------------------------------------------------------------
// Session cap and idle reaping (remote-upstream proxy harness)
// -----------------------------------------------------------------

// TestUnmappedMethod_TargetTypeMapUnknown confirms that
// capability.MethodTargetType — the lookup driving deriveTargetFields' fail-close
// decision — reports no mapping for any method not in the § 5.4 table.
func TestUnmappedMethod_TargetTypeMapUnknown(t *testing.T) {
	unknownMethods := []string{
		"agents/delegate",
		"vendor/custom",
		"",
		"notifications/initialized", // notification, not a request method
		"future/unknown",
	}
	for _, m := range unknownMethods {
		m := m
		t.Run(m, func(t *testing.T) {
			_, ok := capability.MethodTargetType(m)
			assert.False(t, ok, "MethodTargetType(%q) should report no mapping", m)
		})
	}
}

// TestCloneAndBound_ByteSliceBoundedByBase64Length verifies a []byte is capped by
// its BASE64-encoded length (the size json.Marshal actually writes), not its raw
// length. A 400000-byte blob is under the 512 KiB raw cap but base64-encodes
// to ~533 KiB, over the cap — the old raw-length check let it slip past; the
// encoded-length check replaces it with the placeholder. A 300000-byte blob (base64
// ~400 KiB) stays, cloned rather than aliased to the caller's backing array.
func TestCloneAndBound_ByteSliceBoundedByBase64Length(t *testing.T) {
	t.Parallel()
	oversized := cloneAndBound(make([]byte, 400000))
	s, ok := oversized.(string)
	if !ok || !strings.Contains(s, "eunox") {
		t.Fatalf("oversized []byte (base64 over cap) not replaced with placeholder: got %T", oversized)
	}
	src := make([]byte, 300000)
	kept, ok := cloneAndBound(src).([]byte)
	if !ok || len(kept) != len(src) {
		t.Fatalf("under-cap []byte not preserved: got %T len=%d", cloneAndBound(src), len(kept))
	}
	if &kept[0] == &src[0] {
		t.Fatal("under-cap []byte must be cloned, not aliased to the caller")
	}
}
