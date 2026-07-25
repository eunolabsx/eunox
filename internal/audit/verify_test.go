// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// White-box tests for signature and tamper-evident chain verification (verify.go):
// per-record HMAC, forged/legacy/seq-0/post-wrap handling, the integrity markers,
// and the audit-tail reader used to resume the chain.

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
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// signTestRecord signs rec with key, stamping rec.KeyID verbatim, and returns the
// on-disk line (body with _hmac spliced in) — mirroring writeRecord's signing so
// VerifyRecord accepts it. Passing an empty KeyID produces a pre-key_id-era record.
func signTestRecord(t *testing.T, key []byte, rec auditRecord) []byte {
	t.Helper()
	rec.HMAC = ""
	body, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	rec.HMAC = "sha256:" + hex.EncodeToString(mac.Sum(nil))
	line, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal signed record: %v", err)
	}
	return line
}

// TestVerifyAuditLog_EmptyKeyIDNoKeysIsUnverifiable: a signed record that names no
// key_id (a pre-key_id-era record) verified against an EMPTY ring cannot be checked
// at all — the signing key is unidentifiable AND absent — so it is reported
// UNVERIFIABLE, distinct from INVALID (which asserts tampering). When the ring DOES
// hold a (non-matching) key, a key was tried and failed, indistinguishable from
// tampering, so it stays INVALID. Either way the verdict fails (fail-closed).
func TestVerifyAuditLog_EmptyKeyIDNoKeysIsUnverifiable(t *testing.T) {
	t.Parallel()
	key := nonZeroTestKey()
	rec := auditRecord{
		ClassUID: 6003, CategoryUID: 6, ActivityID: 1,
		Time: "2026-06-15T10:00:00Z", Seq: 1, RequestID: "r",
		Decision: "allow", PrevHMAC: auditGenesisPrev,
		// KeyID intentionally empty: a pre-key_id-era signed record.
	}
	line := signTestRecord(t, key, rec)

	// Empty ring: no candidate key, so UNVERIFIABLE (not INVALID); verdict still fails.
	var out strings.Builder
	res, err := VerifyLog(bytes.NewReader(line), &Sink{verifyKeys: map[string][]byte{}}, "", time.Time{}, &out)
	if err != nil {
		t.Fatalf("VerifyLog (empty ring): %v", err)
	}
	if res.Unverifiable != 1 || res.Invalid != 0 {
		t.Fatalf("empty ring: got %+v, want Unverifiable=1 Invalid=0", res)
	}
	if res.OK() {
		t.Error("an unverifiable record must fail the verdict (fail-closed)")
	}
	if !strings.Contains(out.String(), "UNVERIFIABLE") {
		t.Errorf("expected an UNVERIFIABLE diagnostic, got %q", out.String())
	}

	// Ring holds a NON-matching key: a key was tried and failed, indistinguishable
	// from tampering, so it stays INVALID — the defensible fail-closed default.
	other := make([]byte, 32)
	other[0] = 0xAB
	res2, err := VerifyLog(bytes.NewReader(line), &Sink{verifyKeys: map[string][]byte{hmacKeyID(other): other}}, "", time.Time{}, &strings.Builder{})
	if err != nil {
		t.Fatalf("VerifyLog (wrong key): %v", err)
	}
	if res2.Invalid != 1 || res2.Unverifiable != 0 {
		t.Fatalf("wrong key: got %+v, want Invalid=1 Unverifiable=0", res2)
	}

	// Ring holds the MATCHING key: verifies clean.
	res3, err := VerifyLog(bytes.NewReader(line), &Sink{verifyKeys: map[string][]byte{hmacKeyID(key): key}}, "", time.Time{}, &strings.Builder{})
	if err != nil {
		t.Fatalf("VerifyLog (matching key): %v", err)
	}
	if !res3.OK() || res3.Valid != 1 {
		t.Fatalf("matching key: got %+v, want OK with Valid=1", res3)
	}
}

// TestInterpretAuditTail_FileShrinkReportsError: when Stat
// saw a non-empty file but ReadAt returns zero bytes with io.EOF (the file was
// truncated/rotated out from under us between the two syscalls), interpretAuditTail
// must return errAuditFileShrunk — NOT ("", nil) — so openAuditSink treats it as a
// resume failure and writes an in-band chain_resume_failed marker rather than
// silently starting a fresh chain and leaving an unmarked gap.
func TestInterpretAuditTail_FileShrinkReportsError(t *testing.T) {
	// Stat said 4096 bytes; ReadAt returned 0 with EOF (file vanished/truncated).
	buf := make([]byte, 4096)
	line, err := interpretAuditTail(buf, 0, io.EOF, 4096)
	if line != "" {
		t.Fatalf("expected empty line on shrink, got %q", line)
	}
	if !errors.Is(err, errAuditFileShrunk) {
		t.Fatalf("expected errAuditFileShrunk, got %v", err)
	}
}

// TestInterpretAuditTail_PartialAndFullReads confirms the shrink guard does not
// regress normal reads: a full read (err nil) and a partial read (n<len, EOF, but
// n>0 — a non-empty shrink) still extract the last line from the bytes read.
func TestInterpretAuditTail_PartialAndFullReads(t *testing.T) {
	full := []byte("{\"seq\":1}\n{\"seq\":2}\n")
	if got, err := interpretAuditTail(full, len(full), nil, int64(len(full))); err != nil || got != `{"seq":2}` {
		t.Fatalf("full read: got (%q, %v), want (`{\"seq\":2}`, nil)", got, err)
	}
	// Partial read paired with io.EOF: the buffer is sized to exactly the bytes
	// Stat reported in the tail window, so ReadAt returning fewer bytes means the
	// file shrank between Stat and ReadAt. It must fail closed with
	// errAuditFileShrunk so the chain-resume path writes an in-band marker rather
	// than validate a stale earlier record (or a mid-record fragment) as the tail
	// (fail-closed path, superseding the old "slice the short buffer and continue").
	content := "{\"seq\":1}\n{\"seq\":2}"
	buf := make([]byte, 64)
	copy(buf, content)
	if _, err := interpretAuditTail(buf, len(content), io.EOF, 64); !errors.Is(err, errAuditFileShrunk) {
		t.Fatalf("partial read: expected errAuditFileShrunk, got %v", err)
	}
}

// TestReadLastAuditLineExtraction: readLastAuditLine returns
// exactly the last COMPLETE (newline-terminated) record with no trailing null
// bytes. A trailing fragment with no terminating newline is a partial in-progress
// write and is skipped in favor of the last fully-written record; a lone fragment
// (nothing complete before it) is returned as-is so the parse-failure path can fire.
func TestReadLastAuditLineExtraction(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"multi-line trailing newline", "{\"seq\":1}\n{\"seq\":2}\n{\"seq\":3}\n", `{"seq":3}`},
		// A trailing fragment with no newline is a partial write: resume from the last
		// complete record, not the fragment.
		{"trailing partial write skipped", "{\"seq\":1}\n{\"seq\":2}", `{"seq":1}`},
		{"single line", "{\"seq\":1}\n", `{"seq":1}`},
		// A lone unterminated fragment has no complete predecessor, so it is returned
		// as-is (Open then handles a parse failure on it).
		{"lone fragment no newline", "{\"seq\":1}", `{"seq":1}`},
		{"blank trailing lines", "{\"seq\":1}\n\n\n", `{"seq":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "audit.jsonl")
			if err := os.WriteFile(p, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			got, err := readLastAuditLine(p)
			if err != nil {
				t.Fatalf("readLastAuditLine: unexpected error %v", err)
			}
			if got != tc.want {
				t.Fatalf("readLastAuditLine = %q, want %q", got, tc.want)
			}
			if strings.ContainsRune(got, '\x00') {
				t.Fatalf("result contains a null byte: %q", got)
			}
		})
	}

	// Empty and missing files yield ("", nil) — a genuine empty/absent file is not
	// an I/O error.
	empty := filepath.Join(t.TempDir(), "empty.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}
	if got, err := readLastAuditLine(empty); got != "" || err != nil {
		t.Fatalf("empty file: got (%q, %v), want (\"\", nil)", got, err)
	}
	if got, err := readLastAuditLine(filepath.Join(t.TempDir(), "missing.jsonl")); got != "" || err != nil {
		t.Fatalf("missing file: got (%q, %v), want (\"\", nil)", got, err)
	}
}

// TestOpenResumesPastTrailingPartialWrite is the F2 regression: a non-clean
// shutdown can leave a partial in-progress write — bytes after the final newline
// with no terminating newline. Before the fix, Open treated that fragment as the
// tail, failed to parse it, set tail_parse_failure, and restarted the chain from
// genesis even though the prior COMPLETE record was intact. After the fix, the
// fragment is skipped and the chain resumes from the last fully-written record:
// seq/prevHMAC match that record, no tail_parse_failure marker is written, and the
// next record links continuously.
func TestOpenResumesPastTrailingPartialWrite(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// Phase 1: write a few signed records, then close to flush them durably.
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
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

	// Phase 2: simulate a non-clean shutdown mid-write — append a partial record
	// with NO terminating newline. This is the trailing fragment Open must ignore.
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("reopen for append: %v", err)
	}
	if _, err := f.WriteString(`{"seq":99,"partial`); err != nil {
		t.Fatalf("append partial write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close after append: %v", err)
	}

	// Phase 3: restart. The chain must resume from the last COMPLETE record, not
	// from genesis. Open truncates the partial fragment and writes a
	// tail_partial_write_recovered marker that chains from the last complete record,
	// so the marker is the next seq after it (last.Seq+1) — definitively a resume, not
	// a genesis restart (which would make the marker seq 1).
	sink2, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open (restart): %v", err)
	}

	if sink2.seq != last.Seq+1 {
		t.Fatalf("after restart seq = %d, want %d (recovery marker chained onto the last complete record; a genesis restart would give 1)", sink2.seq, last.Seq+1)
	}

	// Phase 4: the partial fragment must have been truncated from disk (so the next
	// append cannot concatenate onto it), a tail_partial_write_recovered marker must
	// document the event, no tail_parse_failure marker must have been written, and
	// the resulting log must verify clean end to end.
	if err := sink2.Close(); err != nil {
		t.Fatalf("Close (restart): %v", err)
	}
	data, err := os.ReadFile(logPath) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if strings.Contains(string(data), "tail_parse_failure") {
		t.Fatalf("a tail_parse_failure marker was written for a trailing partial write; the chain spuriously restarted from genesis")
	}
	if strings.Contains(string(data), `"partial`) || strings.Contains(string(data), `"seq":99`) {
		t.Fatalf("the partial trailing fragment was left on disk; the next append would concatenate onto it and corrupt that line\n%s", data)
	}
	if !strings.Contains(string(data), "tail_partial_write_recovered") {
		t.Fatalf("no tail_partial_write_recovered marker was written; the partial-write recovery is not on the tamper-evident trail")
	}
	// Verify the raw on-disk bytes (not re-joined lines): a leftover orphan would
	// make the marker's line unparseable and surface here as a verify failure. Use
	// the sink's loaded key directly (the key file is encoded, not raw HMAC bytes).
	res, err := VerifyLog(bytes.NewReader(data), NewVerifier([][]byte{sink2.key}), "", time.Time{}, io.Discard)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if !res.OK() {
		t.Fatalf("recovered log failed verification: %+v", res)
	}
}

// TestReadLastAuditLineReportsIOError: an I/O failure on a
// present log (here a path that is a directory, whose ReadAt fails) must return a
// non-nil error so the caller can distinguish it from a genuinely empty file and
// avoid silently resetting the tamper-evident chain.
func TestReadLastAuditLineReportsIOError(t *testing.T) {
	dir := t.TempDir() // a directory: os.Open succeeds, but ReadAt on it fails
	got, err := readLastAuditLine(dir)
	if err == nil {
		t.Fatalf("expected an I/O error reading a directory as an audit log, got (%q, nil)", got)
	}
	if got != "" {
		t.Errorf("expected empty line on I/O error, got %q", got)
	}
}

// TestOpenAuditSink_WritesIntegrityMarkerOnTamperedTail:
// when the audit log tail parses but fails HMAC verification (tamper or
// truncation), openAuditSink must not only warn on stderr — which can be lost to
// container log rotation and is not part of the tamper-evident trail — but also
// write a signed, structured AUDIT_INTEGRITY_FAILURE record so the detection event
// itself appears in the audit log, audit-verify, and any external sink. The marker
// must be individually HMAC-valid and carry the suspect tail seq/_hmac in its
// Details. The marker chains from GENESIS (not from the unverified tail):
// the failed-HMAC tail is attacker-controllable, so its seq/_hmac must never seed
// the resumed chain — the suspect values are preserved only inside the marker's
// Details for forensics.
func TestOpenAuditSink_WritesIntegrityMarkerOnTamperedTail(t *testing.T) {
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b") // seq 1,2, valid chain

	lines := logLines(t, logPath)
	if len(lines) != 2 {
		t.Fatalf("expected 2 records in the seed log, got %d", len(lines))
	}

	// Tamper ONLY the tail record's stored _hmac (flip its last hex digit). The
	// body bytes are untouched, so VerifyRecord recomputes the original MAC and
	// finds it disagrees with the corrupted value — exactly a tampered tail.
	var tail auditRecord
	if err := json.Unmarshal(lines[1], &tail); err != nil {
		t.Fatalf("unmarshal tail: %v", err)
	}
	origHMAC := tail.HMAC
	tamperedHMAC := flipLastByte(origHMAC)
	tamperedLine := bytes.Replace(lines[1], []byte(origHMAC), []byte(tamperedHMAC), 1)
	if bytes.Equal(tamperedLine, lines[1]) {
		t.Fatal("tampering did not change the tail line")
	}
	rewriteLines(t, logPath, [][]byte{lines[0], tamperedLine})

	// Reopen, capturing stderr to confirm the warning still fires.
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	sink, openErr := Open(logPath, keyPath, 0, 0)
	_ = w.Close()
	os.Stderr = old
	var stderrBuf bytes.Buffer
	_, _ = io.Copy(&stderrBuf, r)

	if openErr != nil {
		t.Fatalf("openAuditSink: %v", openErr)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytes.Contains(stderrBuf.Bytes(), []byte("failed HMAC verification")) {
		t.Fatalf("expected the HMAC-failure warning on stderr, got: %q", stderrBuf.String())
	}

	// The log now holds the original two records plus the integrity marker.
	out := logLines(t, logPath)
	if len(out) != 3 {
		t.Fatalf("expected 3 records (2 original + 1 integrity marker), got %d", len(out))
	}
	markerLine := out[2]

	var marker auditRecord
	if err := json.Unmarshal(markerLine, &marker); err != nil {
		t.Fatalf("unmarshal marker: %v", err)
	}
	if marker.DenialCode != "AUDIT_INTEGRITY_FAILURE" {
		t.Fatalf("marker DenialCode = %q, want AUDIT_INTEGRITY_FAILURE", marker.DenialCode)
	}
	if marker.Decision != "deny" {
		t.Fatalf("marker Decision = %q, want deny", marker.Decision)
	}
	// The chain restarts from genesis on an integrity-failed tail rather
	// than chaining from the unverified (attacker-controllable) tail seq/_hmac.
	if marker.Seq != 1 {
		t.Fatalf("marker Seq = %d, want 1 (genesis restart; the unverified tail must not seed the chain)", marker.Seq)
	}
	if marker.PrevHMAC != auditGenesisPrev {
		t.Fatalf("marker PrevHMAC = %q, want the genesis sentinel %q (the suspect tail hmac must not be adopted)", marker.PrevHMAC, auditGenesisPrev)
	}
	markerDetails := recordDetails(t, marker)
	if got := markerDetails["kind"]; got != "tail_hmac_mismatch" {
		t.Fatalf("marker Details[kind] = %v, want tail_hmac_mismatch", got)
	}
	// JSON numbers decode to float64.
	if got, ok := markerDetails["tail_seq"].(float64); !ok || got != 2 {
		t.Fatalf("marker Details[tail_seq] = %v, want 2", markerDetails["tail_seq"])
	}
	if got := markerDetails["tail_hmac"]; got != tamperedHMAC {
		t.Fatalf("marker Details[tail_hmac] = %v, want the suspect tail hmac %q", got, tamperedHMAC)
	}

	// The marker is itself a properly signed record (its own _hmac verifies), so it
	// is real evidence in the tamper-evident trail, not free-floating text.
	ok, err := verifierFor(t, keyPath).VerifyRecord(markerLine)
	if err != nil {
		t.Fatalf("VerifyRecord(marker): %v", err)
	}
	if !ok {
		t.Fatal("the integrity marker must be individually HMAC-valid")
	}
}

// TestOpenAuditSink_WritesMarkerOnUnparseableTail is the regression: when
// the audit log tail fails to parse as JSON (truncated/corrupt last record),
// openAuditSink must write a signed, structured AUDIT_INTEGRITY_FAILURE record —
// not only warn on stderr — so the structural-corruption event appears in the
// audit log, audit-verify, and any external sink, symmetric with the HMAC-mismatch
// case. The marker chains from genesis (the corrupt tail yields no
// resumable predecessor), carries kind=tail_parse_failure, and is HMAC-valid.
func TestOpenAuditSink_WritesMarkerOnUnparseableTail(t *testing.T) {
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b") // seq 1,2, valid chain

	lines := logLines(t, logPath)
	if len(lines) != 2 {
		t.Fatalf("expected 2 records in the seed log, got %d", len(lines))
	}

	// Truncate the tail mid-record so it no longer parses as JSON (a partial write
	// at shutdown). The first record stays intact.
	corruptTail := []byte(`{"seq":2,"_hmac":"sha256:dead`) // no closing brace
	rewriteLines(t, logPath, [][]byte{lines[0], corruptTail})

	sink, openErr := Open(logPath, keyPath, 0, 0)
	if openErr != nil {
		t.Fatalf("openAuditSink: %v", openErr)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The log now holds the intact first record, the corrupt tail, and the marker.
	out := logLines(t, logPath)
	if len(out) != 3 {
		t.Fatalf("expected 3 records (1 intact + 1 corrupt + 1 marker), got %d", len(out))
	}
	markerLine := out[2]

	var marker auditRecord
	if err := json.Unmarshal(markerLine, &marker); err != nil {
		t.Fatalf("unmarshal marker: %v", err)
	}
	if marker.DenialCode != "AUDIT_INTEGRITY_FAILURE" {
		t.Fatalf("marker DenialCode = %q, want AUDIT_INTEGRITY_FAILURE", marker.DenialCode)
	}
	if marker.Decision != "deny" {
		t.Fatalf("marker Decision = %q, want deny", marker.Decision)
	}
	markerDetails := recordDetails(t, marker)
	if got := markerDetails["kind"]; got != "tail_parse_failure" {
		t.Fatalf("marker Details[kind] = %v, want tail_parse_failure", got)
	}
	// JSON numbers decode to float64; tail_bytes is the corrupt tail's length.
	if got, ok := markerDetails["tail_bytes"].(float64); !ok || got != float64(len(corruptTail)) {
		t.Fatalf("marker Details[tail_bytes] = %v, want %d", markerDetails["tail_bytes"], len(corruptTail))
	}
	// Chains from genesis: the corrupt tail provided no resumable predecessor.
	if marker.Seq != 1 {
		t.Fatalf("marker Seq = %d, want 1 (genesis restart)", marker.Seq)
	}
	if marker.PrevHMAC != auditGenesisPrev {
		t.Fatalf("marker PrevHMAC = %q, want the genesis sentinel %q", marker.PrevHMAC, auditGenesisPrev)
	}

	// The marker is itself a properly signed record, so it is real evidence in the
	// tamper-evident trail rather than free-floating text.
	ok, err := verifierFor(t, keyPath).VerifyRecord(markerLine)
	if err != nil {
		t.Fatalf("VerifyRecord(marker): %v", err)
	}
	if !ok {
		t.Fatal("the parse-failure marker must be individually HMAC-valid")
	}
}

// TestOpenAuditSink_IntegrityFailedTail_DoesNotInheritAttackerSeq: an attacker who lacks the signing key can still append a
// syntactically valid JSON record with an arbitrary _seq and _hmac as the audit
// tail. On restart, openAuditSink must NOT seed the new session's chain from those
// unverified values (which would inject a fabricated seq jump and an attacker-chosen
// prev_hmac into the chain). It must restart from genesis, exactly as the
// parse-failure path does, while still recording the integrity marker for forensics.
func TestOpenAuditSink_IntegrityFailedTail_DoesNotInheritAttackerSeq(t *testing.T) {
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a") // one valid record at seq 1

	lines := logLines(t, logPath)
	if len(lines) != 1 {
		t.Fatalf("expected 1 record in the seed log, got %d", len(lines))
	}

	// Forge a tail the attacker controls: a huge seq and a chosen _hmac, but a bad
	// signature (they lack the key). This is appended as the new tail.
	const attackerSeq = 999999
	const attackerHMAC = "sha256:attacker-chosen"
	forged := auditRecord{
		ClassUID:    6003,
		CategoryUID: 6,
		ActivityID:  1,
		Time:        "2026-06-15T10:00:00Z",
		Seq:         attackerSeq,
		RequestID:   "r-forged",
		SessionID:   "s",
		Decision:    "allow",
		PrevHMAC:    "sha256:whatever",
		HMAC:        attackerHMAC,
	}
	forgedLine, err := json.Marshal(forged)
	if err != nil {
		t.Fatalf("marshal forged tail: %v", err)
	}
	rewriteLines(t, logPath, [][]byte{lines[0], forgedLine})

	sink, openErr := Open(logPath, keyPath, 0, 0)
	if openErr != nil {
		t.Fatalf("openAuditSink: %v", openErr)
	}

	// The resumed chain must NOT have inherited the attacker's seq. The next record
	// the sink writes is the integrity marker at seq 1 (genesis restart), so the
	// in-memory seq after open is the marker's seq, far below the attacker's 999999.
	if sink.seq >= attackerSeq {
		t.Fatalf("sink.seq = %d, must not inherit the attacker seq %d (chain must restart from genesis)", sink.seq, attackerSeq)
	}
	if sink.prevHMAC == attackerHMAC {
		t.Fatalf("sink.prevHMAC = %q, must not adopt the attacker-chosen tail hmac", sink.prevHMAC)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The integrity marker lands chained from genesis (seq 1), not from the forged
	// tail's seq, so a SIEM doing seq-continuity analysis sees no ~999999-record gap.
	out := logLines(t, logPath)
	markerLine := out[len(out)-1]
	var marker auditRecord
	if err := json.Unmarshal(markerLine, &marker); err != nil {
		t.Fatalf("unmarshal marker: %v", err)
	}
	if marker.Seq != 1 {
		t.Fatalf("marker Seq = %d, want 1 (genesis restart, not chained from forged seq %d)", marker.Seq, attackerSeq)
	}
	if marker.PrevHMAC != auditGenesisPrev {
		t.Fatalf("marker PrevHMAC = %q, want genesis sentinel %q", marker.PrevHMAC, auditGenesisPrev)
	}
	// The suspect values are still preserved inside the marker for forensics.
	markerDetails := recordDetails(t, marker)
	if got, ok := markerDetails["tail_seq"].(float64); !ok || got != attackerSeq {
		t.Fatalf("marker Details[tail_seq] = %v, want the forensic record of the suspect seq %d", markerDetails["tail_seq"], attackerSeq)
	}
}

// flipLastByte returns s with its final byte changed, yielding a string of the
// same length that differs from the input.
func flipLastByte(s string) string {
	if s == "" {
		return "x"
	}
	b := []byte(s)
	if b[len(b)-1] == '0' {
		b[len(b)-1] = '1'
	} else {
		b[len(b)-1] = '0'
	}
	return string(b)
}

func rewriteLines(t *testing.T, logPath string, lines [][]byte) {
	t.Helper()
	joined := bytes.Join(lines, []byte("\n"))
	joined = append(joined, '\n')
	if err := os.WriteFile(logPath, joined, 0o600); err != nil {
		t.Fatalf("rewrite log: %v", err)
	}
}

// TestWriteChainResumeFailedMarker is the regression: when an I/O error
// prevents reading the prior log tail at startup, openAuditSink writes a signed,
// structured AUDIT_INTEGRITY_FAILURE record (kind=chain_resume_failed) instead of
// silently resetting the chain. The marker chains from genesis, carries the
// underlying reason, and is individually HMAC-valid — symmetric with the
// parse-failure and HMAC-mismatch markers.
func TestWriteChainResumeFailedMarker(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/audit.jsonl"
	keyPath := dir + "/audit.key"
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	const reason = "read audit log tail: input/output error"
	sink.writeIntegrityMarker("chain_resume_failed", map[string]interface{}{"reason": reason})
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	out := logLines(t, logPath)
	if len(out) != 1 {
		t.Fatalf("expected exactly 1 marker record, got %d", len(out))
	}
	var marker auditRecord
	if err := json.Unmarshal(out[0], &marker); err != nil {
		t.Fatalf("unmarshal marker: %v", err)
	}
	if marker.DenialCode != "AUDIT_INTEGRITY_FAILURE" {
		t.Errorf("marker DenialCode = %q, want AUDIT_INTEGRITY_FAILURE", marker.DenialCode)
	}
	if marker.Decision != "deny" {
		t.Errorf("marker Decision = %q, want deny", marker.Decision)
	}
	markerDetails := recordDetails(t, marker)
	if got := markerDetails["kind"]; got != "chain_resume_failed" {
		t.Errorf("marker Details[kind] = %v, want chain_resume_failed", got)
	}
	if got := markerDetails["reason"]; got != reason {
		t.Errorf("marker Details[reason] = %v, want %q", got, reason)
	}
	if marker.Seq != 1 || marker.PrevHMAC != auditGenesisPrev {
		t.Errorf("marker should chain from genesis: seq=%d prev=%q", marker.Seq, marker.PrevHMAC)
	}
	ok, err := verifierFor(t, keyPath).VerifyRecord(out[0])
	if err != nil {
		t.Fatalf("VerifyRecord(marker): %v", err)
	}
	if !ok {
		t.Error("the chain-resume-failed marker must be individually HMAC-valid")
	}
}

// TestWriteIntegrityMarker_CallerMapSafety locks the contract that
// writeIntegrityMarker builds a fresh Details map instead of mutating its argument:
// the caller's map must not gain a "kind" key, and a nil details map must not panic
// on the "kind" assignment. Both hold today only because all production call sites
// pass fresh non-nil literals; this pins the helper so a future caller cannot be
// surprised.
func TestWriteIntegrityMarker_CallerMapSafety(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/audit.jsonl"
	keyPath := dir + "/audit.key"
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	// The caller's map must be left untouched (no "kind" written back into it).
	caller := map[string]interface{}{"reason": "input/output error"}
	sink.writeIntegrityMarker("chain_resume_failed", caller)
	if _, mutated := caller["kind"]; mutated {
		t.Errorf("writeIntegrityMarker mutated the caller's map: %v", caller)
	}

	// A nil details map must not panic and still produces a kind-tagged marker.
	sink.writeIntegrityMarker("tail_parse_failure", nil)

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	out := logLines(t, logPath)
	if len(out) != 2 {
		t.Fatalf("expected 2 marker records, got %d", len(out))
	}
	for i, want := range []string{"chain_resume_failed", "tail_parse_failure"} {
		var marker auditRecord
		if err := json.Unmarshal(out[i], &marker); err != nil {
			t.Fatalf("unmarshal marker %d: %v", i, err)
		}
		if got := recordDetails(t, marker)["kind"]; got != want {
			t.Errorf("marker %d Details[kind] = %v, want %q", i, got, want)
		}
	}
}

// TestVerifyAuditLog_ForgedLegacySeq0DoesNotSuppressSeqGap is the
// regression: an HMAC-less seq-0 record (a forged "legacy" record) spliced into a
// signed chain to replace a deleted interior record must not poison the chain
// state. Before the fix, such a record was rejected as invalid only AFTER it had
// already overwritten prevHMAC/prevSeq with ("", 0). That let an attacker hide an
// interior deletion: the next crafted record could link with prev_hmac="" (no
// CHAIN BREAK) and the SEQ GAP check was suppressed because its `prevSeq > 0`
// guard was false. The forged legacy record must be excluded from the chain-state
// update so the next real record is still compared against the last LEGITIMATE
// record and BOTH diagnostics fire.
func TestVerifyAuditLog_ForgedLegacySeq0DoesNotSuppressSeqGap(t *testing.T) {
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b", "c", "d", "e") // seq 1..5
	lines := logLines(t, logPath)

	// Make the decoy stealthy: its prev_hmac links to the surviving seq-3 record so
	// the decoy itself does not trip a chain break. The whole attack then hinges on
	// whether the decoy poisons the chain state for the following seq-5 record.
	var seq3 auditRecord
	if err := json.Unmarshal(lines[2], &seq3); err != nil {
		t.Fatalf("unmarshal seq-3 record: %v", err)
	}

	// Delete the seq-4 record (index 3) and splice an HMAC-less seq-0 decoy in its
	// place. The surviving seq-5 record still references the deleted seq-4 HMAC, so
	// seq 5 must report BOTH a CHAIN BREAK and a SEQ GAP "5 does not follow 3".
	decoy := []byte(fmt.Sprintf(
		`{"time":"2026-06-15T01:00:00Z","request_id":"decoy","session_id":"s","target":"tool:exec","decision":"allow","seq":0,"prev_hmac":%q}`,
		seq3.HMAC))
	tampered := [][]byte{lines[0], lines[1], lines[2], decoy, lines[4]}

	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join(tampered, []byte("\n"))),
		verifierFor(t, keyPath), "", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if res.OK() {
		t.Fatalf("a forged legacy seq-0 splice must fail verification: %+v", res)
	}
	out := sb.String()
	if !strings.Contains(out, "forged legacy record spliced into a signed chain") {
		t.Fatalf("the forged legacy decoy must be reported invalid; output:\n%s", out)
	}
	if !strings.Contains(out, "SEQ GAP: record seq 5 does not follow 3") {
		t.Fatalf("the SEQ GAP for the displaced record must not be suppressed by the decoy; output:\n%s", out)
	}
}

// signedThreeRecordLog writes a fresh signed audit log with three records and
// returns its lines plus the key path for verification.
func signedThreeRecordLog(t *testing.T) (lines [][]byte, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath = filepath.Join(dir, "audit.key")
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
	lines = logLines(t, logPath)
	return lines, keyPath
}

// TestVerifyAuditLog_ForgedSeq0WithHMAC_Invalid covers the fix: a record
// with seq 0 but a non-empty HMAC is structurally impossible in a correct log
// (legacy records have no HMAC; signed records start at seq 1). Such a forged
// seq-0 decoy — used to substitute the genesis record or suppress the seq-gap
// check — must be rejected as invalid.
func TestVerifyAuditLog_ForgedSeq0WithHMAC_Invalid(t *testing.T) {
	lines, keyPath := signedThreeRecordLog(t)

	// A decoy carrying seq 0 with some HMAC value, prepended as a forged genesis.
	decoy := `{"time":"2026-06-14T20:00:00Z","request_id":"decoy","session_id":"s","target":"tool:exec","decision":"allow","seq":0,"_hmac":"sha256:deadbeef","prev_hmac":"sha256:genesis"}`
	forged := append([][]byte{[]byte(decoy)}, lines...)

	res := verifyBytes(t, forged, verifierFor(t, keyPath))
	if res.OK() {
		t.Fatalf("a seq-0 record with a non-empty HMAC must fail verification: %+v", res)
	}
	if res.Invalid == 0 {
		t.Fatalf("expected the forged seq-0 decoy counted invalid: %+v", res)
	}
}

// TestVerifyAuditLog_ForgedSeq0DoesNotSuppressSeqGap is the regression: a
// forged seq-0 decoy spliced in to replace a deleted record must not suppress the
// SEQ GAP diagnostic for the following real record. The decoy is structurally
// invalid and is rejected, but it must not poison the chain state — the next real
// record has to be compared against the last LEGITIMATE record so the gap size is
// reported for the investigator.
func TestVerifyAuditLog_ForgedSeq0DoesNotSuppressSeqGap(t *testing.T) {
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b", "c", "d", "e") // seq 1..5
	lines := logLines(t, logPath)

	// Delete the seq-4 record (index 3) and splice a forged seq-0 decoy in its
	// place. Its prev_hmac mimics linking to seq 3; the surviving seq-5 record still
	// references the deleted seq-4 HMAC, so seq 5 must report BOTH a CHAIN BREAK and
	// a SEQ GAP "5 does not follow 3".
	decoy := []byte(`{"time":"2026-06-15T01:00:00Z","request_id":"decoy","session_id":"s","target":"tool:exec","decision":"allow","seq":0,"_hmac":"sha256:deadbeef","prev_hmac":"sha256:cafef00d"}`)
	tampered := [][]byte{lines[0], lines[1], lines[2], decoy, lines[4]}

	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join(tampered, []byte("\n"))),
		verifierFor(t, keyPath), "", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if res.OK() {
		t.Fatalf("a forged seq-0 splice must fail verification: %+v", res)
	}
	out := sb.String()
	if !strings.Contains(out, "forged seq-0 decoy") {
		t.Fatalf("the decoy must be reported invalid; output:\n%s", out)
	}
	if !strings.Contains(out, "SEQ GAP: record seq 5 does not follow 3") {
		t.Fatalf("the SEQ GAP for the displaced record must not be suppressed by the decoy; output:\n%s", out)
	}
}

// TestVerifyAuditLog_ForgedLegacyAfterSigned_Invalid covers the fix: an
// HMAC-less seq-0 record appended after signed records is a forged "legacy"
// record spliced into a signed chain. It must be classified invalid (so the
// verdict fails), not laundered through the legacy exemption that audit-verify
// previously exited 0 on.
func TestVerifyAuditLog_ForgedLegacyAfterSigned_Invalid(t *testing.T) {
	lines, keyPath := signedThreeRecordLog(t)

	var lastRec auditRecord
	if err := json.Unmarshal(lines[len(lines)-1], &lastRec); err != nil {
		t.Fatalf("decode tail: %v", err)
	}

	// Link the forged record to the real tail so it does not trip a chain break;
	// the legacy-exemption laundering is what we are closing.
	forged := fmt.Sprintf(`{"time":"2026-06-14T21:00:00Z","request_id":"forged","session_id":"s","target":"tool:exec","decision":"allow","seq":0,"prev_hmac":%q}`, lastRec.HMAC)
	lines = append(lines, []byte(forged))

	res := verifyBytes(t, lines, verifierFor(t, keyPath))
	if res.OK() {
		t.Fatalf("forged HMAC-less seq-0 record after signed records must fail verification: %+v", res)
	}
	if res.Legacy != 0 {
		t.Fatalf("post-signing seq-0 record must not be classified legacy, got legacy=%d", res.Legacy)
	}
	if res.Invalid == 0 {
		t.Fatalf("expected the forged record counted invalid: %+v", res)
	}
}

// TestVerifyAuditLog_LegacyHeadStillExempt guards that the fix does not
// break the legitimate case: genuine pre-signing legacy records at the HEAD of a
// log (before any signed record) remain exempt.
func TestVerifyAuditLog_LegacyHeadStillExempt(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	legacy := `{"request_id":"legacy-1","method":"tools/call","session_id":"s","target":"a","decision":"allow"}` + "\n" +
		`{"request_id":"legacy-2","method":"tools/call","session_id":"s","target":"b","decision":"allow"}` + "\n"
	if err := os.WriteFile(logPath, []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy: %v", err)
	}
	// Resume onto the legacy tail and append signed records.
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess", "c", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	res := verifyBytes(t, logLines(t, logPath), verifierFor(t, keyPath))
	if !res.OK() {
		t.Fatalf("legacy-head + signed log must still pass: %+v", res)
	}
	if res.Legacy != 2 {
		t.Fatalf("expected legacy=2 for the two head records, got %+v", res)
	}
}

// TestVerifyAuditLog_ForgedEmptyPrevSeq1_IsChainBreak guards the genesis-sentinel
// empty-prev_hmac bypass: a
// signing-key holder truncates the leading records and forges an ORDINARY seq-1
// record with prev_hmac="" and a valid HMAC. The old blanket empty-prev_hmac
// exemption let that pass with no chain break; it must now be flagged. The genuine
// legacy_tail_resumed marker (the only record that legitimately starts a signed
// chain with prev_hmac="") must still verify cleanly.
func TestVerifyAuditLog_ForgedEmptyPrevSeq1_IsChainBreak(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := dir + "/audit.key"
	key, err := loadOrCreateAuditKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateAuditKey: %v", err)
	}

	// Forged ordinary allow record at seq 1 with an empty prev_hmac and a valid HMAC.
	forged := signAuditLine(t, key, auditRecord{
		Time:      "2026-06-15T10:00:00Z",
		Seq:       1,
		RequestID: "forged",
		SessionID: "s",
		Decision:  "allow",
		PrevHMAC:  "",
	})
	res := verifyBytes(t, [][]byte{forged}, verifierFor(t, keyPath))
	if res.ChainBreaks == 0 {
		t.Fatalf("forged empty-prev_hmac seq-1 record must be reported as a chain break: %+v", res)
	}

	// The genuine legacy_tail_resumed marker, same seq/prev_hmac shape, is exempt.
	marker := signAuditLine(t, key, auditRecord{
		Time:       "2026-06-15T10:00:00Z",
		Seq:        1,
		RequestID:  "marker",
		Decision:   "deny",
		DenialCode: auditIntegrityFailureCode,
		Details:    json.RawMessage(`{"kind":"` + auditKindLegacyTailResumed + `","tail_seq":0}`),
		PrevHMAC:   "",
	})
	res2 := verifyBytes(t, [][]byte{marker}, verifierFor(t, keyPath))
	if res2.ChainBreaks != 0 {
		t.Fatalf("a genuine legacy_tail_resumed marker must not be a chain break: %+v", res2)
	}
}

// signAuditLine signs rec under key exactly as the audit sink does (HMAC over the
// record with the _hmac field cleared) and returns the final JSON line. It lets a
// test craft records with arbitrary seq values — including the post-wrap seq 0 —
// that still verify, which the sink's monotonic counter cannot produce directly.
func signAuditLine(t *testing.T, key []byte, rec auditRecord) []byte {
	t.Helper()
	rec.HMAC = ""
	body, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal record body: %v", err)
	}
	rec.HMAC = "sha256:" + hmacHex(key, body)
	line, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal signed record: %v", err)
	}
	return line
}

// TestVerifyAuditLog_PostWrapSeq0_NotForged is the regression: after the
// uint64 sequence counter wraps (2^64 records), the next legitimately signed
// record carries seq 0 with a valid HMAC. Because such a record can only follow a
// seq == math.MaxUint64 record, verifyAuditLog must treat it as legitimate rather
// than as a forged seq-0 decoy, and the chain must verify cleanly.
func TestVerifyAuditLog_PostWrapSeq0_NotForged(t *testing.T) {
	dir := t.TempDir()
	keyPath := dir + "/audit.key"
	key, err := loadOrCreateAuditKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateAuditKey: %v", err)
	}

	// rec1: the record immediately before the wrap, seq == MaxUint64.
	rec1 := auditRecord{
		Time:      "2026-06-15T10:00:00Z",
		Seq:       math.MaxUint64,
		RequestID: "r-max",
		SessionID: "s",
		Decision:  "allow",
		PrevHMAC:  auditGenesisPrev,
	}
	line1 := signAuditLine(t, key, rec1)
	var signed1 auditRecord
	if err := json.Unmarshal(line1, &signed1); err != nil {
		t.Fatalf("unmarshal signed rec1: %v", err)
	}

	// rec2: the wrapped record, seq 0, chained to rec1.
	rec2 := auditRecord{
		Time:      "2026-06-15T10:00:01Z",
		Seq:       0,
		RequestID: "r-wrap",
		SessionID: "s",
		Decision:  "allow",
		PrevHMAC:  signed1.HMAC,
	}
	line2 := signAuditLine(t, key, rec2)

	res := verifyBytes(t, [][]byte{line1, line2}, verifierFor(t, keyPath))
	if !res.OK() {
		t.Fatalf("a post-wrap seq-0 record (following seq MaxUint64) must verify cleanly: %+v", res)
	}
	if res.Invalid != 0 {
		t.Fatalf("post-wrap seq-0 record must not be flagged forged/invalid: %+v", res)
	}
	if res.Valid != 2 || res.ChainBreaks != 0 {
		t.Fatalf("expected 2 valid records, no chain breaks: %+v", res)
	}
}

// TestVerifyAuditLog_SeqGapAfterWrap_StillReported is the regression: the
// SEQ GAP check was gated on prevSeq > 0, but after the counter wraps the record
// following the wrapped seq-0 record has prevSeq == 0, so a missing/renumbered
// record right after the wrap escaped the SEQ GAP diagnostic. Gating on signedSeen
// instead keeps the check live across the wrap. Here a record chains correctly to
// the wrapped seq-0 record (no CHAIN BREAK) but carries seq 2, skipping seq 1 — the
// gap must be reported.
func TestVerifyAuditLog_SeqGapAfterWrap_StillReported(t *testing.T) {
	dir := t.TempDir()
	keyPath := dir + "/audit.key"
	key, err := loadOrCreateAuditKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateAuditKey: %v", err)
	}

	// rec1: pre-wrap record at seq MaxUint64.
	rec1 := auditRecord{Time: "2026-06-15T10:00:00Z", Seq: math.MaxUint64, RequestID: "r-max", SessionID: "s", Decision: "allow", PrevHMAC: auditGenesisPrev}
	line1 := signAuditLine(t, key, rec1)
	var signed1 auditRecord
	if err := json.Unmarshal(line1, &signed1); err != nil {
		t.Fatalf("unmarshal rec1: %v", err)
	}

	// rec2: the wrapped record, seq 0, chained to rec1.
	rec2 := auditRecord{Time: "2026-06-15T10:00:01Z", Seq: 0, RequestID: "r-wrap", SessionID: "s", Decision: "allow", PrevHMAC: signed1.HMAC}
	line2 := signAuditLine(t, key, rec2)
	var signed2 auditRecord
	if err := json.Unmarshal(line2, &signed2); err != nil {
		t.Fatalf("unmarshal rec2: %v", err)
	}

	// rec3: chains correctly to rec2 (no CHAIN BREAK) but carries seq 2 instead of
	// the contiguous seq 1 — i.e. seq 1 was removed/renumbered right after the wrap.
	rec3 := auditRecord{Time: "2026-06-15T10:00:02Z", Seq: 2, RequestID: "r-gap", SessionID: "s", Decision: "allow", PrevHMAC: signed2.HMAC}
	line3 := signAuditLine(t, key, rec3)

	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join([][]byte{line1, line2, line3}, []byte("\n"))),
		verifierFor(t, keyPath), "", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if !strings.Contains(sb.String(), "SEQ GAP") {
		t.Fatalf("a seq gap immediately after the wrap must still be reported; output:\n%s", sb.String())
	}
	if res.ChainBreaks == 0 {
		t.Fatalf("the seq gap must count toward chainBreaks: %+v", res)
	}
}

// TestVerifyAuditLog_FirstRecordSeq0_LegitChainStart covers the case: a genuinely
// signed seq-0 record at the HEAD of a (rotated) file — the legitimate chain start
// after the counter wrapped past math.MaxUint64 and the log then rotated — must NOT
// be flagged as a forged seq-0 decoy when verified single-file (no --prev). With no
// in-stream predecessor the wrap context cannot be reconstructed, but the record is
// a real chain start and its own HMAC verifies, so it must pass.
func TestVerifyAuditLog_FirstRecordSeq0_LegitChainStart(t *testing.T) {
	dir := t.TempDir()
	keyPath := dir + "/audit.key"
	key, err := loadOrCreateAuditKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateAuditKey: %v", err)
	}

	// A genuinely-signed seq-0 record presented as the first and only record of the
	// stream.
	rec := auditRecord{
		Time:      "2026-06-15T10:00:01Z",
		Seq:       0,
		RequestID: "r-wrap",
		SessionID: "s",
		Decision:  "allow",
		PrevHMAC:  "sha256:deadbeef",
	}
	line := signAuditLine(t, key, rec)

	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(line), verifierFor(t, keyPath), "", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if !res.OK() {
		t.Fatalf("a genuinely-signed seq-0 head record must verify cleanly: %+v\noutput:\n%s", res, sb.String())
	}
	if res.Invalid != 0 {
		t.Fatalf("the legitimate seq-0 head record must not be flagged invalid: %+v", res)
	}
	if res.Valid != 1 {
		t.Fatalf("expected the seq-0 head record to count as valid: %+v", res)
	}
}

// TestVerifyAuditLog_FirstRecordSeq0_ForgedBadHMAC guards the other side of the
// change: not flagging a seq-0 head record as a structural decoy must NOT mean
// accepting an unsigned/forged one. A seq-0 head record whose HMAC does not verify
// is still caught by the unconditional per-record HMAC check and counted invalid.
func TestVerifyAuditLog_FirstRecordSeq0_ForgedBadHMAC(t *testing.T) {
	dir := t.TempDir()
	keyPath := dir + "/audit.key"
	if _, err := loadOrCreateAuditKey(keyPath); err != nil {
		t.Fatalf("loadOrCreateAuditKey: %v", err)
	}

	// A seq-0 head record carrying an attacker-chosen _hmac that was NOT produced by
	// the signing key.
	forged := auditRecord{
		Time:      "2026-06-15T10:00:01Z",
		Seq:       0,
		RequestID: "r-forged",
		SessionID: "s",
		Decision:  "allow",
		PrevHMAC:  "sha256:deadbeef",
		HMAC:      "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	line, err := json.Marshal(forged)
	if err != nil {
		t.Fatalf("marshal forged record: %v", err)
	}

	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(line), verifierFor(t, keyPath), "", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if res.OK() {
		t.Fatalf("a forged seq-0 head record with a bad HMAC must still fail: %+v", res)
	}
	if res.Invalid != 1 {
		t.Fatalf("the forged seq-0 head record must be counted invalid: %+v", res)
	}
}

// TestVerifyAuditLog_MissingHMACSeqGt0_DoesNotPoisonChain is the regression:
// a signed-era record (Seq > 0) whose _hmac is missing/empty (stripped by an
// attacker, truncated by a partial write, or dropped by a field-pruning tool)
// satisfies neither forged-seq-0 guard, so it previously reached updateChain and set
// prevHMAC = "" — poisoning the chain state and firing a spurious CHAIN BREAK on the
// NEXT (legitimate) record. The record itself must be counted invalid with a clear
// empty-_hmac diagnostic, and the following legitimate record must NOT be flagged.
func TestVerifyAuditLog_MissingHMACSeqGt0_DoesNotPoisonChain(t *testing.T) {
	dir := t.TempDir()
	keyPath := dir + "/audit.key"
	key, err := loadOrCreateAuditKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateAuditKey: %v", err)
	}

	// rec1: a normal signed record at seq 1.
	rec1 := auditRecord{Time: "2026-06-15T10:00:00Z", Seq: 1, RequestID: "r1", SessionID: "s", Decision: "allow", PrevHMAC: auditGenesisPrev}
	line1 := signAuditLine(t, key, rec1)
	var signed1 auditRecord
	if err := json.Unmarshal(line1, &signed1); err != nil {
		t.Fatalf("unmarshal rec1: %v", err)
	}

	// rec2: a signed-era record (seq 2) with its _hmac stripped (empty). omitempty
	// drops the empty field, exactly the "_hmac absent" shape the issue describes.
	rec2 := auditRecord{Time: "2026-06-15T10:00:01Z", Seq: 2, RequestID: "r2", SessionID: "s", Decision: "allow", PrevHMAC: signed1.HMAC}
	line2, err := json.Marshal(rec2)
	if err != nil {
		t.Fatalf("marshal rec2: %v", err)
	}

	// rec3: the next legitimate signed record. Because the stripped rec2 is excluded
	// from the chain state, the verifier's anchor stays at the LAST LEGITIMATE record
	// (rec1). A correctly chained successor therefore links to rec1's HMAC at seq 2,
	// and must verify with NO spurious CHAIN BREAK. (Before the fix, rec2 set
	// prevHMAC="" and this record tripped a fabricated break.)
	rec3 := auditRecord{Time: "2026-06-15T10:00:02Z", Seq: 2, RequestID: "r3", SessionID: "s", Decision: "allow", PrevHMAC: signed1.HMAC}
	line3 := signAuditLine(t, key, rec3)

	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join([][]byte{line1, line2, line3}, []byte("\n"))),
		verifierFor(t, keyPath), "", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	out := sb.String()

	// The empty-_hmac record is counted invalid with the dedicated diagnostic: it
	// follows a signed record (v.signedSeen), so it is a forged legacy splice, not a
	// genuine legacy record — the same diagnostic a seq-bearing legacy splice gets.
	if !strings.Contains(out, "unsigned record (seq=2) follows a signed record") {
		t.Fatalf("expected the empty-_hmac diagnostic for the stripped record; output:\n%s", out)
	}
	// Exactly one invalid (rec2), and crucially NO spurious chain break: rec3 chains
	// cleanly to the last legitimate record (rec1), so prevHMAC must not have been
	// poisoned to "" by rec2.
	if res.Invalid != 1 {
		t.Fatalf("exactly the empty-_hmac record must be invalid (not its successor): %+v\noutput:\n%s", res, out)
	}
	if res.ChainBreaks != 0 {
		t.Fatalf("the empty-_hmac record must not poison the chain state and fabricate a CHAIN BREAK on the next record: %+v\noutput:\n%s", res, out)
	}
}

// TestVerifyAuditLog_MultipleSeqBearingLegacyRecords_AllCountLegacy is the
// regression for a residual bug the forgedLegacySplice fix's own signedSeen gate
// exposed: signedSeen was set true by ANY record with Seq > 0 (updateChain),
// including an unsigned (HMAC=="") one. Since a genuine legacy record can itself
// carry a non-zero seq (the seq-bearing legacy tail case), a first legacy record
// with Seq > 0 would flip signedSeen true even though nothing was ever actually
// signed, causing a SECOND genuine legacy record — still preceding any real signed
// record — to be misclassified as a forged post-signing splice and counted
// Invalid. Two consecutive HMAC-less records, both carrying non-zero seq values
// and neither ever followed by a signed record, must both land in the Legacy
// bucket (with the log correctly reported UNANCHORED, since it is wholly legacy
// under a configured key — not INVALID).
func TestVerifyAuditLog_MultipleSeqBearingLegacyRecords_AllCountLegacy(t *testing.T) {
	dir := t.TempDir()
	keyPath := dir + "/audit.key"
	lines := []string{
		`{"class_uid":6003,"category_uid":6,"activity_id":1,"time":"2026-01-01T00:00:00Z","seq":10,"request_id":"r1","session_id":"s","target_type":"tool","target":"legacy_tool","method":"tools/call","decision":"allow"}`,
		`{"class_uid":6003,"category_uid":6,"activity_id":1,"time":"2026-01-01T00:00:01Z","seq":11,"request_id":"r2","session_id":"s","target_type":"tool","target":"legacy_tool2","method":"tools/call","decision":"allow"}`,
	}
	data := strings.Join(lines, "\n") + "\n"

	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader([]byte(data)), verifierFor(t, keyPath), "", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	out := sb.String()

	if res.Invalid != 0 {
		t.Fatalf("both seq-bearing legacy records must count Legacy, not Invalid: %+v\noutput:\n%s", res, out)
	}
	if res.Legacy != 2 {
		t.Fatalf("expected both records counted Legacy, got %+v\noutput:\n%s", res, out)
	}
	if strings.Contains(out, "forged legacy record spliced") {
		t.Fatalf("a genuine legacy record must not be misreported as a forged splice merely because an earlier legacy record also carried a non-zero seq:\n%s", out)
	}
}

// TestVerifyAuditLog_Seq0AfterNonWrap_StillForged guards the wrap exemption: it must
// be tight. A seq-0 record with an HMAC that is
// NOT preceded by a seq == MaxUint64 record is still a forged decoy and must be
// rejected — the exemption must not blanket-allow every seq-0 record.
func TestVerifyAuditLog_Seq0AfterNonWrap_StillForged(t *testing.T) {
	dir := t.TempDir()
	keyPath := dir + "/audit.key"
	key, err := loadOrCreateAuditKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateAuditKey: %v", err)
	}

	// A normal record at seq 5 (e.g. the head of a rotated log), then a seq-0
	// record spliced after it — not a wrap, since the predecessor is not MaxUint64.
	rec1 := auditRecord{
		Time:      "2026-06-15T10:00:00Z",
		Seq:       5,
		RequestID: "r5",
		SessionID: "s",
		Decision:  "allow",
		PrevHMAC:  auditGenesisPrev,
	}
	line1 := signAuditLine(t, key, rec1)
	var signed1 auditRecord
	if err := json.Unmarshal(line1, &signed1); err != nil {
		t.Fatalf("unmarshal signed rec1: %v", err)
	}

	rec2 := auditRecord{
		Time:      "2026-06-15T10:00:01Z",
		Seq:       0,
		RequestID: "r-decoy",
		SessionID: "s",
		Decision:  "allow",
		PrevHMAC:  signed1.HMAC,
	}
	line2 := signAuditLine(t, key, rec2)

	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join([][]byte{line1, line2}, []byte("\n"))),
		verifierFor(t, keyPath), "", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	if res.OK() {
		t.Fatalf("a seq-0 record not following a wrap must fail verification: %+v", res)
	}
	if !strings.Contains(sb.String(), "forged seq-0 decoy") {
		t.Fatalf("the non-wrap seq-0 record must be reported as a forged decoy; output:\n%s", sb.String())
	}
}

// writeChainSegment writes the given tool names as allow records to logPath
// (resuming any existing chain), flushes, then renames logPath to a timestamped
// rotated sibling — reproducing what rotation does, so the next segment opened on
// logPath resumes the chain from this sibling's tail and its head record links
// across the file boundary. The bare-base final segment is written by passing an
// empty sidecar stamp.
func writeChainSegment(t *testing.T, logPath, keyPath, sidecarStamp string, tools ...string) {
	t.Helper()
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open(%q): %v", logPath, err)
	}
	for _, tl := range tools {
		sink.RecordAllow(context.Background(), "sess", tl, "tools/call", nil, nil, false, nil, nil)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if sidecarStamp != "" {
		if err := os.Rename(logPath, logPath+sidecarStamp); err != nil {
			t.Fatalf("rename to rotated sibling %q: %v", sidecarStamp, err)
		}
	}
}

// TestRotatedSiblingOrdering_SurvivesBackwardClockStep is the regression for a
// backward wall-clock step (NTP correction, VM migration, manual set) landing
// between two rotations used to invert the on-disk sibling order, because siblings
// were named AND ordered purely by their wall-clock timestamp. That mis-ordering had
// two consequences the fix must prevent: retention deleting the NEWER-seq file, and
// cross-file verification tripping a spurious CHAIN BREAK / SEQ GAP. Siblings are now
// stamped and ordered by a monotonic rotation ordinal, so both stay correct even when
// the newer sibling carries an EARLIER timestamp.
func TestRotatedSiblingOrdering_SurvivesBackwardClockStep(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// Two rotated segments named as rotation does (seq prefix + timestamp), but with
	// the SECOND (newer-seq) segment carrying an EARLIER wall-clock stamp than the
	// first — exactly the inversion a backward clock step produces. The seq prefixes
	// reflect each segment's true max seq (3, then 6).
	seg1Stamp := ".00000000000000000003.20260615T120005.000000000Z" // seqs 1..3, LATER clock
	seg2Stamp := ".00000000000000000006.20260615T120003.000000000Z" // seqs 4..6, EARLIER clock
	writeChainSegment(t, logPath, keyPath, seg1Stamp, "a", "b", "c")
	writeChainSegment(t, logPath, keyPath, seg2Stamp, "d", "e", "f")
	writeChainSegment(t, logPath, keyPath, "", "g", "h", "i") // base, seqs 7..9

	// (b) Cross-file verification: LogChainFiles must order by seq (seg1 -> seg2 ->
	// base), so the concatenated stream is contiguous and verifies clean. Under the
	// old wall-clock ordering seg2 (T120003) would sort before seg1 (T120005),
	// inverting the stream and tripping a spurious break on an untampered chain.
	files, err := LogChainFiles(logPath)
	if err != nil {
		t.Fatalf("LogChainFiles: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 chain files, got %v", files)
	}
	if files[0] != logPath+seg1Stamp || files[1] != logPath+seg2Stamp {
		t.Fatalf("siblings must be ordered by seq (seg1 then seg2) despite the inverted clock; got %v", files)
	}
	verifier := verifierFor(t, keyPath)
	var out strings.Builder
	res, err := VerifyLogFiles(files, verifier, "", time.Time{}, &out)
	if err != nil {
		t.Fatalf("VerifyLogFiles: %v", err)
	}
	if !res.OK() || res.Valid != 9 || res.ChainBreaks != 0 {
		t.Fatalf("seq-ordered chain must verify clean (9 valid, 0 breaks) despite the backward clock step: %+v\noutput:\n%s", res, out.String())
	}

	// (a) Retention: with retain=1, pruning must keep the NEWER-seq sibling (seg2) and
	// delete the older (seg1). A wall-clock sort would treat seg2 (earlier stamp) as
	// oldest and delete it — discarding the newer records.
	key := nonZeroTestKey()
	s := &Sink{
		key:        key,
		keyID:      hmacKeyID(key),
		logPath:    logPath,
		activePath: logPath,
		retain:     1,
	}
	s.pruneRotated()
	if _, err := os.Stat(logPath + seg1Stamp); !os.IsNotExist(err) {
		t.Fatalf("older-seq sibling (seg1) should have been pruned, stat err=%v", err)
	}
	if _, err := os.Stat(logPath + seg2Stamp); err != nil {
		t.Fatalf("newer-seq sibling (seg2) must survive retention: %v", err)
	}
}

// TestVerifyLogFiles_DetectsInteriorWholeFileDeletion is the regression: the
// tamper-evident chain spans rotation, but audit-verify read only the current
// base log, so deleting an entire interior rotated file was undetectable — each
// surviving file still verified on its own and nothing compared the base head's
// prev_hmac/seq to the deleted file's tail. Verifying the whole rotated set as
// one chain (LogChainFiles + VerifyLogFiles) catches it: the file after the
// gap no longer chains to the file before it.
func TestVerifyLogFiles_DetectsInteriorWholeFileDeletion(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// A chain spanning three files: sidecar1[seq 1..3] -> sidecar2[seq 4..6] ->
	// current base[seq 7..9]. Each reopen resumes from the prior sibling's tail, so
	// the head of each file links to the previous file's tail exactly as rotate()
	// threads the chain in memory.
	writeChainSegment(t, logPath, keyPath, ".20260601T000000.000000000Z", "a", "b", "c")
	sidecar2Stamp := ".20260602T000000.000000000Z"
	writeChainSegment(t, logPath, keyPath, sidecar2Stamp, "d", "e", "f")
	writeChainSegment(t, logPath, keyPath, "", "g", "h", "i") // stays as the current base
	sidecar2 := logPath + sidecar2Stamp

	verifier := verifierFor(t, keyPath)

	// Sanity: the intact three-file chain verifies clean across both boundaries.
	files, err := LogChainFiles(logPath)
	if err != nil {
		t.Fatalf("LogChainFiles: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 chain files (two siblings + base), got %v", files)
	}
	res, err := VerifyLogFiles(files, verifier, "", time.Time{}, io.Discard)
	if err != nil {
		t.Fatalf("VerifyLogFiles (intact): %v", err)
	}
	if !res.OK() || res.Valid != 9 || res.ChainBreaks != 0 {
		t.Fatalf("intact three-file chain must verify clean (9 valid, 0 breaks): %+v", res)
	}

	// Delete the entire interior rotated file. The cross-file link from the base's
	// head (seq 7, prev_hmac = seq-6's hmac) to sidecar1's tail (seq 3) is now
	// broken; single-file verification never checked it.
	if err := os.Remove(sidecar2); err != nil {
		t.Fatalf("remove interior sidecar: %v", err)
	}

	files, err = LogChainFiles(logPath)
	if err != nil {
		t.Fatalf("LogChainFiles (after delete): %v", err)
	}
	var out strings.Builder
	res, err = VerifyLogFiles(files, verifier, "", time.Time{}, &out)
	if err != nil {
		t.Fatalf("VerifyLogFiles (after delete): %v", err)
	}
	if res.OK() {
		t.Fatalf("deletion of an entire interior rotated file must be detected, got a clean pass: %+v\noutput:\n%s", res, out.String())
	}
	if res.ChainBreaks == 0 {
		t.Fatalf("expected a cross-file chain break, got %+v\noutput:\n%s", res, out.String())
	}
	if !strings.Contains(out.String(), "CHAIN BREAK") || !strings.Contains(out.String(), "SEQ GAP") {
		t.Fatalf("interior whole-file deletion should trip BOTH a CHAIN BREAK and a SEQ GAP; output:\n%s", out.String())
	}
}

// TestVerifyLogFiles_MissingFileFailsClosed: a chain file that cannot be opened
// cannot be certified, so VerifyLogFiles must return an error rather than
// silently skip it (which would let an attacker hide a segment by making it
// unreadable).
func TestVerifyLogFiles_MissingFileFailsClosed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")
	missing := filepath.Join(dir, "audit.jsonl.20260601T000000.000000000Z")
	if _, err := VerifyLogFiles([]string{missing}, verifierFor(t, keyPath), "", time.Time{}, io.Discard); err == nil {
		t.Fatal("VerifyLogFiles must fail closed when a listed chain file cannot be opened")
	}
}

// TestVerifyLogFiles_MidStreamOpenErrorFailsClosed: lazy opening must still fail
// closed when a NON-first chain file cannot be opened — the open error has to
// surface after the earlier file(s) have already streamed, not be swallowed once
// some records have verified.
func TestVerifyLogFiles_MidStreamOpenErrorFailsClosed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// One real, verifiable file followed by a path that does not exist.
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess", "a", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	missing := filepath.Join(dir, "audit.jsonl.20260601T000000.000000000Z")

	if _, err := VerifyLogFiles([]string{logPath, missing}, verifierFor(t, keyPath), "", time.Time{}, io.Discard); err == nil {
		t.Fatal("VerifyLogFiles must fail closed when a non-first chain file cannot be opened")
	}
}

// TestVerifyLog_UnknownKeyIDNotTampering covers a record signed with a key
// the verifier's ring does not hold (the expected state after a key rotation that
// retired the signing key) is classified as UNKNOWN_KEY_ID, NOT as INVALID
// (content tampering). The verdict still fails — the record cannot be certified
// without the key — but the dedicated count and diagnostic let an operator
// distinguish a missing key from corruption.
func TestVerifyLog_UnknownKeyIDNotTampering(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// A verifier holding a DIFFERENT key id than the one that signed the record —
	// the retired-key state a key rotation produces.
	other := make([]byte, 32)
	other[0] = 0xCD
	verifier := &Sink{verifyKeys: map[string][]byte{hmacKeyID(other): other}}

	var out strings.Builder
	res, err := VerifyLog(bytes.NewReader(mustReadFile(t, logPath)), verifier, "", time.Time{}, &out)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if res.UnknownKey != 1 {
		t.Errorf("UnknownKey = %d, want 1", res.UnknownKey)
	}
	if res.Invalid != 0 {
		t.Errorf("Invalid = %d, want 0 (a missing key must not be miscounted as tampering)", res.Invalid)
	}
	if res.OK() {
		t.Error("OK() = true, want false (an unverifiable record cannot be certified)")
	}
	if !strings.Contains(out.String(), "UNKNOWN_KEY_ID") {
		t.Errorf("diagnostic = %q, want it to mention UNKNOWN_KEY_ID", out.String())
	}
}

// TestOpenLogChain_LazyConcatenation verifies OpenLogChain streams the rotated
// chain in order, newline-joined, while holding at most ONE underlying file open
// at a time — the fd bound the reporting commands (stats/suggest/doctor) rely on
// under the unbounded keep-all retention default — and releases every fd on Close.
func TestOpenLogChain_LazyConcatenation(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for _, c := range []string{"AAA\n", "BBB\n", "CCC\n"} {
		p := filepath.Join(dir, c[:3])
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		paths = append(paths, p)
	}

	rc := OpenLogChain(paths)
	cr := rc.(*chainReader)
	openCount := func() int {
		n := 0
		for _, lr := range cr.lazies {
			if lr.f != nil {
				n++
			}
		}
		return n
	}

	// Drain one byte at a time so the fd bound is checked across the whole stream.
	var got []byte
	buf := make([]byte, 1)
	for {
		n, err := rc.Read(buf)
		got = append(got, buf[:n]...)
		if open := openCount(); open > 1 {
			t.Fatalf("at most one chain file may be open at a time, got %d", open)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	if want := "AAA\n\nBBB\n\nCCC\n"; string(got) != want {
		t.Errorf("OpenLogChain stream = %q, want %q", got, want)
	}

	if err := rc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if open := openCount(); open != 0 {
		t.Errorf("Close must release every fd, %d still open", open)
	}
}

// TestRecoverPartialTail_ProbeOrTruncateErrorIsPropagated is a regression test: when
// the recovery cannot complete (here the tail probe/truncate on a closed fd, standing in
// for a kernel-level rejection or a transient EIO), recoverPartialTail must RETURN the
// error rather than swallow it and return 0. Swallowing left the orphan fragment in place
// for the next O_APPEND write to fuse onto, producing a physical line audit-verify reports
// as corruption; failing closed lets Open refuse to start instead.
//
// Forcing the failure INSIDE Open is not portable without a dedicated seam, so the
// recovery function — exactly what Open calls and then propagates — is exercised directly.
// A closed fd makes f.Stat fail, so this exercises the probe-failure fail-closed branch.
func TestRecoverPartialTail_ProbeOrTruncateErrorIsPropagated(t *testing.T) {
	dir := t.TempDir()
	logPath, _ := writeChainLog(t, dir, "a", "b", "c")

	// Append a partial (newline-less) fragment so a real orphan is present on disk.
	f, err := os.OpenFile(logPath, os.O_RDWR|os.O_APPEND, 0o600) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("reopen for append: %v", err)
	}
	if _, err := f.WriteString(`{"seq":99,"partial`); err != nil {
		t.Fatalf("append partial: %v", err)
	}
	// Close the fd: f.Stat/f.ReadAt then fail, simulating a rejected probe without an
	// OS-specific seam.
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// readable=true: this simulates a probe READ fault on a readable handle (the closed
	// fd makes f.Stat/f.ReadAt fail), which must fail closed — distinct from a genuinely
	// write-only log (readable=false), which skips the probe.
	tail, err := recoverPartialTail(logPath, f, true)
	if err == nil {
		t.Fatal("recoverPartialTail must return an error when the recovery cannot complete, not swallow it")
	}
	if tail.recovered != 0 {
		t.Fatalf("recovered bytes = %d, want 0 on a recovery failure", tail.recovered)
	}
	// The orphan must remain on disk (nothing was removed); Open's fail-closed caller
	// refuses to start rather than appending onto it.
	data, rerr := os.ReadFile(logPath) //nolint:gosec // G304: test-controlled path
	if rerr != nil {
		t.Fatalf("read log: %v", rerr)
	}
	if !strings.Contains(string(data), `"partial`) {
		t.Fatal("expected the un-truncated orphan to remain on disk after a recovery failure")
	}
}

// TestRecoverPartialTail_ProbeReadFailureOnNonEmptyLogIsFatal is the regression for the
// fail-open this fix closes: an orphan partial record is present AND the tail probe's read
// fails transiently (EIO/NFS blip). The old code reopened the log read-only to probe and
// treated any non-truncate error as benign ("no orphan was found") — proceeding, so the
// first O_APPEND write fused onto the still-present orphan, defeating the tamper-evident
// chain. The probe now runs through the same handle, and a read failure on a NON-EMPTY log
// escalates to fatal so Open refuses to start instead of fusing.
//
// The transient read failure is modeled with a WRITE-ONLY handle: f.Stat succeeds (size >
// 0, an orphan is present), but f.ReadAt returns EBADF — exactly "non-empty log, tail read
// failed" — without an OS-specific fault-injection seam.
func TestRecoverPartialTail_ProbeReadFailureOnNonEmptyLogIsFatal(t *testing.T) {
	dir := t.TempDir()
	logPath, _ := writeChainLog(t, dir, "a", "b", "c")

	// Append a partial (newline-less) orphan so the log is non-empty and ends in a real
	// partial record the next append would otherwise fuse onto.
	ap, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("reopen for append: %v", err)
	}
	if _, err := ap.WriteString(`{"seq":99,"partial`); err != nil {
		t.Fatalf("append partial: %v", err)
	}
	if err := ap.Close(); err != nil {
		t.Fatalf("close append handle: %v", err)
	}

	// Open WRITE-ONLY: Stat works (non-empty), but ReadAt fails (EBADF), standing in for a
	// transient read fault on a non-empty log with an orphan present.
	wf, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("reopen write-only: %v", err)
	}
	defer func() { _ = wf.Close() }()

	// readable=true: the write-only fd is just the mechanism to force ReadAt to fail; the
	// scenario under test is a transient read fault on a readable, non-empty log, which
	// must fail closed (errAuditTailProbe). A genuinely write-only log uses readable=false
	// and skips the probe (see TestRecoverPartialTail_WriteOnlyHandleSkipsProbe).
	tail, err := recoverPartialTail(logPath, wf, true)
	if err == nil {
		t.Fatal("recoverPartialTail must fail closed when the tail read fails on a non-empty log, not proceed and let the next append fuse onto the orphan")
	}
	if !errors.Is(err, errAuditTailProbe) {
		t.Fatalf("error = %v, want it to wrap errAuditTailProbe", err)
	}
	if tail.recovered != 0 {
		t.Fatalf("recovered bytes = %d, want 0 when the probe read failed", tail.recovered)
	}
	// The orphan must remain on disk; the operator resolves the I/O fault rather than the
	// proxy starting and fusing the next record.
	data, rerr := os.ReadFile(logPath) //nolint:gosec // G304: test-controlled path
	if rerr != nil {
		t.Fatalf("read log: %v", rerr)
	}
	if !strings.Contains(string(data), `"partial`) {
		t.Fatal("expected the orphan to remain on disk after a fail-closed probe read failure")
	}
}

// TestRecoverPartialTail_WriteOnlyHandleSkipsProbe pins the write-only-log tradeoff:
// when the log could only be opened append-only (readable=false, because O_RDWR was
// refused on a deliberately 0200 log under a non-root process), recoverPartialTail must
// NOT probe the tail — it skips recovery and returns (0, nil) so Open still proceeds.
// The orphan is left on disk (a non-clean shutdown on a write-only log falls into
// chain-resume-failed), the documented audit-failure tradeoff for an operator-chosen
// unreadable log. This must not be confused with a transient probe fault on a READABLE
// log, which fails closed (errAuditTailProbe) — see the sibling test. Guards the
// regression where switching to a single O_RDWR handle made a write-only log unopenable.
func TestRecoverPartialTail_WriteOnlyHandleSkipsProbe(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	// A non-empty log ending in a partial (no-newline) record: a readable handle would
	// truncate it; a write-only handle (readable=false) must skip the probe entirely.
	if err := os.WriteFile(logPath, []byte(`{"seq":1,"_hmac":"sha256:a"}`+"\n"+`{"partial`), 0o600); err != nil {
		t.Fatalf("seed log: %v", err)
	}
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("open write-only: %v", err)
	}
	defer func() { _ = f.Close() }()

	tail, err := recoverPartialTail(logPath, f, false)
	if err != nil {
		t.Fatalf("recoverPartialTail(readable=false) must skip the probe and proceed, got error: %v", err)
	}
	if tail.recovered != 0 {
		t.Fatalf("recovered bytes = %d, want 0 (the probe is skipped on a write-only handle)", tail.recovered)
	}
	// The orphan is left untouched: the write-only tradeoff cannot recover it, but it must
	// not have failed closed either.
	data, rerr := os.ReadFile(logPath) //nolint:gosec // G304: test-controlled path
	if rerr != nil {
		t.Fatalf("read log: %v", rerr)
	}
	if !strings.Contains(string(data), `{"partial`) {
		t.Fatal("the orphan must remain on disk; the write-only path skips recovery, it does not truncate")
	}
}

// TestTruncatePartialTail_CleanTailIsTruncatedViaSingleHandle confirms the happy path
// still works after switching to the single (O_RDWR) handle: a real orphan partial record
// is found and truncated to the last complete record boundary, and the byte count returned
// matches the dropped fragment. This guards against the single-handle change regressing
// normal partial-tail recovery.
func TestTruncatePartialTail_CleanTailIsTruncatedViaSingleHandle(t *testing.T) {
	dir := t.TempDir()
	logPath, _ := writeChainLog(t, dir, "a", "b", "c")

	before, err := os.ReadFile(logPath) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("read clean log: %v", err)
	}
	cleanLen := int64(len(before))

	// Append a newline-less orphan fragment.
	const orphan = `{"seq":99,"partial`
	ap, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("reopen for append: %v", err)
	}
	if _, err := ap.WriteString(orphan); err != nil {
		t.Fatalf("append partial: %v", err)
	}
	if err := ap.Close(); err != nil {
		t.Fatalf("close append handle: %v", err)
	}

	// Open O_RDWR exactly as openAndPrepareLog now does, and probe/truncate through it.
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_RDWR, 0o600) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("reopen O_RDWR: %v", err)
	}
	defer func() { _ = f.Close() }()

	tail, err := truncatePartialTail(f)
	if err != nil {
		t.Fatalf("truncatePartialTail: unexpected error %v", err)
	}
	if tail.recovered != int64(len(orphan)) {
		t.Fatalf("recovered bytes = %d, want %d (the orphan fragment length)", tail.recovered, len(orphan))
	}
	after, err := os.ReadFile(logPath) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("read truncated log: %v", err)
	}
	if int64(len(after)) != cleanLen {
		t.Fatalf("post-truncation size = %d, want %d (back to the clean boundary)", len(after), cleanLen)
	}
	if strings.Contains(string(after), `"partial`) {
		t.Fatal("orphan fragment must be gone after truncation")
	}
}

// TestTruncatePartialTail_EmptyLogIsNonFatal confirms the preserved benign case: an empty
// log (no orphan possible) returns (0, nil) rather than a probe error, so enforcement still
// starts on a brand-new install.
func TestTruncatePartialTail_EmptyLogIsNonFatal(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "empty.jsonl")

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("create empty log: %v", err)
	}
	defer func() { _ = f.Close() }()

	tail, err := truncatePartialTail(f)
	if err != nil {
		t.Fatalf("truncatePartialTail on an empty log must be non-fatal, got %v", err)
	}
	if tail.recovered != 0 {
		t.Fatalf("recovered bytes = %d, want 0 on an empty log", tail.recovered)
	}
}

// TestSessionID_OmittedWhenEmpty guards the omitempty tag: a record with no session
// (synthetic integrity/drop markers, or a pre-dispatch record) must omit session_id
// entirely rather than emit "session_id":"" — matching the omitempty convention its
// AgentID/TaskID/UserID siblings already follow.
func TestSessionID_OmittedWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Empty sessionID, e.g. a pre-dispatch JWT rejection that has no session yet.
	sink.RecordDeny(context.Background(), "", "read_file", "tools/call", "AUTHORIZATION_FAILED", "", nil, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data := mustReadFile(t, logPath)
	if bytes.Contains(data, []byte(`"session_id"`)) {
		t.Fatalf("a record with an empty session must omit session_id, but the log contains it:\n%s", data)
	}
	// A non-empty session, by contrast, still carries the field.
	logPath2 := filepath.Join(dir, "audit2.jsonl")
	keyPath2 := filepath.Join(dir, "audit2.key")
	sink2, err := Open(logPath2, keyPath2, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink2.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytes.Contains(mustReadFile(t, logPath2), []byte(`"session_id":"sess-1"`)) {
		t.Fatal("a record with a non-empty session must still carry session_id")
	}
}

// TestVerifyRejectsDuplicateTopLevelKeyTamper: a signed record rewritten on disk
// with a duplicate top-level key (last-wins agrees with the signed value, so the
// recomputed HMAC still matches) must be rejected. Otherwise an attacker with
// file-write access but no key could prepend {"decision":"allow", to a signed
// "decision":"deny" record: the HMAC verifies (it certifies the re-marshaled
// struct, not the raw bytes) while any first-wins JSON consumer reads "allow".
func TestVerifyRejectsDuplicateTopLevelKeyTamper(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordDeny(context.Background(), "sess-1", "tool:rm_rf", "tools/call", "AUTHORIZATION_FAILED", "", nil, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	idx := len(lines) - 1
	orig := lines[idx]
	if !bytes.Contains(orig, []byte(`"decision":"deny"`)) {
		t.Fatalf("expected a deny record, got: %s", orig)
	}

	// Sanity: the untampered record verifies.
	verifier := verifierFor(t, keyPath)
	if ok, verr := verifier.VerifyRecord(orig); !ok || verr != nil {
		t.Fatalf("untampered record must verify: ok=%v err=%v", ok, verr)
	}

	// Prepend a duplicate "decision":"allow" key. Last-wins decode still yields
	// "deny", so the HMAC would match — verification must reject the duplicate.
	tampered := append([]byte(`{"decision":"allow",`), orig[1:]...)
	ok, verr := verifier.VerifyRecord(tampered)
	if ok || verr == nil {
		t.Fatalf("duplicate-top-level-key tamper must fail closed, got ok=%v err=%v", ok, verr)
	}
	if !strings.Contains(verr.Error(), "duplicate top-level key") {
		t.Fatalf("expected a duplicate-key error, got: %v", verr)
	}

	// And the whole-log verdict must fail, not pass.
	lines[idx] = tampered
	out := append(bytes.Join(lines, []byte("\n")), '\n')
	res, _ := VerifyLog(bytes.NewReader(out), verifier, "", time.Time{}, io.Discard)
	if res.OK() {
		t.Fatalf("VerifyLog must not pass a log with a duplicate-key-tampered record: %+v", res)
	}
}

// TestVerifyRejectsCaseVariantDuplicateKeyTamper pins the case-variant vector: a
// prepended "Decision":"allow" is a *different* raw string from the signed
// "decision":"deny", so an exact-string duplicate check misses it — but
// encoding/json binds both to the single Decision field (last-wins keeps "deny"),
// so the HMAC still matches while a case-insensitive/first-wins consumer reads
// "allow". The guard rejects any key whose spelling doesn't byte-exactly match
// its canonical field tag, so the non-canonical "Decision" key is caught before
// the duplicate check ever runs, failing closed like the exact-duplicate form.
func TestVerifyRejectsCaseVariantDuplicateKeyTamper(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordDeny(context.Background(), "sess-1", "tool:rm_rf", "tools/call", "AUTHORIZATION_FAILED", "", nil, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	idx := len(lines) - 1
	orig := lines[idx]
	if !bytes.Contains(orig, []byte(`"decision":"deny"`)) {
		t.Fatalf("expected a deny record, got: %s", orig)
	}

	verifier := verifierFor(t, keyPath)
	if ok, verr := verifier.VerifyRecord(orig); !ok || verr != nil {
		t.Fatalf("untampered record must verify: ok=%v err=%v", ok, verr)
	}

	// Prepend a CASE-VARIANT of "decision". Last-wins decode still yields "deny"
	// (both keys bind to the Decision field), so the HMAC would match.
	tampered := append([]byte(`{"Decision":"allow",`), orig[1:]...)
	ok, verr := verifier.VerifyRecord(tampered)
	if ok || verr == nil {
		t.Fatalf("case-variant duplicate-key tamper must fail closed, got ok=%v err=%v", ok, verr)
	}
	if !strings.Contains(verr.Error(), "canonical field spelling") {
		t.Fatalf("expected a non-canonical-spelling error, got: %v", verr)
	}

	lines[idx] = tampered
	out := append(bytes.Join(lines, []byte("\n")), '\n')
	res, _ := VerifyLog(bytes.NewReader(out), verifier, "", time.Time{}, io.Discard)
	if res.OK() {
		t.Fatalf("VerifyLog must not pass a log with a case-variant-tampered record: %+v", res)
	}
}

// TestVerifyRejectsLoneCaseRenamedKeyTamper is the regression for the gap the
// duplicate-key guard alone did not cover: a SINGLE case-renamed key with no
// colliding sibling. Rewriting "decision" to "DECISION" (with no second
// "decision" key present) produces no collision for a duplicate check to catch,
// yet encoding/json still binds it to the Decision field (case-insensitively,
// even under DisallowUnknownFields) and re-marshaling re-canonicalizes it to
// lowercase, so the recomputed HMAC still matches. A case-sensitive downstream
// consumer (jq '.decision', a SIEM regex on "decision":"deny") silently stops
// matching the record while eunox certifies it as untampered. This must fail
// closed like the duplicate-key vectors.
func TestVerifyRejectsLoneCaseRenamedKeyTamper(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordDeny(context.Background(), "sess-1", "tool:rm_rf", "tools/call", "AUTHORIZATION_FAILED", "", nil, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	idx := len(lines) - 1
	orig := lines[idx]
	if !bytes.Contains(orig, []byte(`"decision":"deny"`)) {
		t.Fatalf("expected a deny record, got: %s", orig)
	}

	verifier := verifierFor(t, keyPath)
	if ok, verr := verifier.VerifyRecord(orig); !ok || verr != nil {
		t.Fatalf("untampered record must verify: ok=%v err=%v", ok, verr)
	}

	// Respell ONLY the "decision" key's case — no duplicate, no collision.
	tampered := bytes.Replace(orig, []byte(`"decision":"deny"`), []byte(`"DECISION":"deny"`), 1)
	if bytes.Equal(tampered, orig) {
		t.Fatal("test setup failed to rewrite the decision key")
	}
	ok, verr := verifier.VerifyRecord(tampered)
	if ok || verr == nil {
		t.Fatalf("lone case-renamed-key tamper must fail closed, got ok=%v err=%v", ok, verr)
	}
	if !strings.Contains(verr.Error(), "canonical field spelling") {
		t.Fatalf("expected a non-canonical-spelling error, got: %v", verr)
	}

	lines[idx] = tampered
	out := append(bytes.Join(lines, []byte("\n")), '\n')
	res, _ := VerifyLog(bytes.NewReader(out), verifier, "", time.Time{}, io.Discard)
	if res.OK() {
		t.Fatalf("VerifyLog must not pass a log with a lone case-renamed-key-tampered record: %+v", res)
	}
}

// TestIsEncodingJSONEmptyValue_CoversAllOmitemptyDroppedKinds guards against the
// fail-open corner in the zero-value tamper check: isEncodingJSONEmptyValue must
// recognize a zero value of EVERY kind that encoding/json's omitempty drops (not
// just the string/bool/slice kinds auditRecord uses today), because
// auditRecordTagSchema includes every omitempty field regardless of kind. A kind
// that omitempty drops but this predicate failed to call empty would let an
// attacker splice a zero-valued field of that kind into a signed record after
// signing and still verify clean — reopening the byte-malleability gap for any
// future numeric/pointer/interface omitempty field.
func TestIsEncodingJSONEmptyValue_CoversAllOmitemptyDroppedKinds(t *testing.T) {
	t.Parallel()

	var nilPtr *int
	// Every value here is one encoding/json's omitempty drops, so its on-disk
	// presence in a signed record is a tamper signal that must be recognized.
	empties := []interface{}{
		"",                         // string
		false,                      // bool
		[]string(nil),              // nil slice
		[]string{},                 // non-nil empty slice
		map[string]int{},           // empty map
		int(0), int64(0), int32(0), // signed
		uint(0), uint64(0), // unsigned
		float64(0), float32(0), // float
		nilPtr, // nil pointer
	}
	for _, e := range empties {
		if !isEncodingJSONEmptyValue(reflect.ValueOf(e)) {
			t.Errorf("isEncodingJSONEmptyValue(%#v of kind %s) = false, want true (omitempty drops it, so its on-disk presence is a tamper signal)", e, reflect.ValueOf(e).Kind())
		}
	}

	three := 3
	nonEmpties := []interface{}{"x", true, []string{"a"}, map[string]int{"a": 1}, int(1), uint(1), float64(0.5), &three}
	for _, e := range nonEmpties {
		if isEncodingJSONEmptyValue(reflect.ValueOf(e)) {
			t.Errorf("isEncodingJSONEmptyValue(%#v) = true, want false", e)
		}
	}
}

// TestVerifyRejectsForeignZeroValueOmitemptyFieldTamper is the sign-and-verify
// round-trip regression for the byte-malleability fix: writeRecord's omitempty
// NEVER emits a zero-valued field (it omits the key entirely instead — see
// auditRecord's json tags), so a record on disk carrying, say, "agent_id":""
// could only have gotten there by an attacker appending it AFTER signing. Because
// VerifyRecord recomputes the HMAC over a re-marshal (which drops a zero-valued
// omitempty field again via the same omitempty tag), the appended field is
// invisible to the HMAC check and would otherwise verify — the exact class of
// tamper rejectDuplicateTopLevelKeys' zero-value check exists to catch.
func TestVerifyRejectsForeignZeroValueOmitemptyFieldTamper(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// No JWT claims are wired in this test, so the record legitimately omits
	// agent_id entirely (omitempty drops the zero Go string value).
	sink.RecordDeny(context.Background(), "sess-1", "tool:rm_rf", "tools/call", "AUTHORIZATION_FAILED", "", nil, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	idx := len(lines) - 1
	orig := lines[idx]
	if bytes.Contains(orig, []byte(`"agent_id"`)) {
		t.Fatalf("test fixture must not already carry agent_id: %s", orig)
	}

	verifier := verifierFor(t, keyPath)
	if ok, verr := verifier.VerifyRecord(orig); !ok || verr != nil {
		t.Fatalf("untampered record must verify: ok=%v err=%v", ok, verr)
	}

	// Splice in a foreign zero-valued omitempty field right after the opening
	// brace — no duplicate key, byte-exact canonical spelling, HMAC untouched.
	tampered := bytes.Replace(orig, []byte(`{"class_uid"`), []byte(`{"agent_id":"","class_uid"`), 1)
	if bytes.Equal(tampered, orig) {
		t.Fatal("test setup failed to splice in the foreign field")
	}
	ok, verr := verifier.VerifyRecord(tampered)
	if ok || verr == nil {
		t.Fatalf("a foreign zero-valued omitempty field must fail closed, got ok=%v err=%v", ok, verr)
	}
	if !strings.Contains(verr.Error(), "zero value") {
		t.Fatalf("expected a zero-value error, got: %v", verr)
	}

	lines[idx] = tampered
	out := append(bytes.Join(lines, []byte("\n")), '\n')
	res, _ := VerifyLog(bytes.NewReader(out), verifier, "", time.Time{}, io.Discard)
	if res.OK() {
		t.Fatalf("VerifyLog must not pass a log with a foreign-zero-value-tampered record: %+v", res)
	}
}

// TestVerifyAcceptsGenuineNonZeroOmitemptyFields guards against the zero-value
// check above over-matching: a real, non-empty omitempty field (string, bool, and
// non-empty slice) must still verify normally.
func TestVerifyAcceptsGenuineNonZeroOmitemptyFields(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordDeny(context.Background(), "sess-1", "tool:rm_rf", "tools/call", "AUTHORIZATION_FAILED", "", nil, true /* auditOnly: true, a non-zero bool */)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	orig := lines[len(lines)-1]
	if !bytes.Contains(orig, []byte(`"audit_only":true`)) {
		t.Fatalf("expected audit_only:true in the record, got: %s", orig)
	}

	verifier := verifierFor(t, keyPath)
	if ok, verr := verifier.VerifyRecord(orig); !ok || verr != nil {
		t.Fatalf("a record with a genuine non-zero omitempty field must verify: ok=%v err=%v", ok, verr)
	}
}

// TestVerifyAuditLog_AllLegacyUnderKeyIsUnanchored: a log whose every record is
// pre-signing legacy shape (no _hmac, seq 0), verified while a signing key is
// configured, has no cryptographic anchor and must NOT pass. Otherwise a write-capable
// attacker without the key could replace the entire log (and its rotated siblings) with
// forged legacy-shaped records and clear audit-verify. A legitimate legacy->signed
// upgrade always leaves a signed record, so an all-legacy log under a key is not a
// normal state.
func TestVerifyAuditLog_AllLegacyUnderKeyIsUnanchored(t *testing.T) {
	t.Parallel()
	key := nonZeroTestKey()
	legacy := func(reqID string) []byte {
		return []byte(fmt.Sprintf(`{"time":"2026-06-15T10:00:00Z","request_id":%q,"session_id":"s","target":"tool:exec","decision":"allow"}`, reqID))
	}
	log := bytes.Join([][]byte{legacy("a"), legacy("b"), legacy("c")}, []byte("\n"))

	// With a key configured, the all-legacy log is unanchored and fails the verdict.
	var out strings.Builder
	res, err := VerifyLog(bytes.NewReader(log), &Sink{verifyKeys: map[string][]byte{hmacKeyID(key): key}}, "", time.Time{}, &out)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if res.Legacy != 3 || res.Total != 3 {
		t.Fatalf("got %+v, want Legacy=3 Total=3", res)
	}
	if !res.Unanchored {
		t.Error("an all-legacy log under a held key must be flagged Unanchored")
	}
	if res.OK() {
		t.Error("an unanchored log must fail the verdict (fail-closed)")
	}
	if res.ChainBreaks != 0 || res.Invalid != 0 {
		t.Errorf("unanchored detection must not fabricate chain breaks/invalids: got %+v", res)
	}
	if !strings.Contains(out.String(), "UNANCHORED") {
		t.Errorf("expected an UNANCHORED diagnostic, got %q", out.String())
	}

	// With an EMPTY (but non-nil) keyring there is no key to verify against, so the
	// all-legacy log is unverified legacy — NOT a failed anchor. Unanchored must not fire
	// (the nil-vs-empty distinction: an empty keyring holds no key).
	var out2 strings.Builder
	res2, err := VerifyLog(bytes.NewReader(log), &Sink{verifyKeys: map[string][]byte{}}, "", time.Time{}, &out2)
	if err != nil {
		t.Fatalf("VerifyLog (empty keyring): %v", err)
	}
	if res2.Unanchored {
		t.Error("an empty keyring holds no key, so an all-legacy log must not be flagged Unanchored")
	}
	if !res2.OK() {
		t.Errorf("all-legacy log under an empty keyring must pass (nothing to verify): %+v", res2)
	}
}

// TestTruncatePartialTail_YieldsTheChainResumeLine pins the property that lets Open
// resume the HMAC chain WITHOUT re-opening the log: the one bounded tail read performed
// through the already-open append handle also yields the last COMPLETE record line, and
// that line is byte-identical to what a second open (readLastAuditLine) would produce.
//
// The re-open is the failure mode openAndPrepareLog switched to a single handle to avoid
// — a transient EIO/NFS blip on a second open, with a perfectly readable tail sitting in
// the buffer, used to cost a permanent chain_resume_failed marker and a large seq jump.
// If these two ever disagree, resuming from the buffer silently changes prev_hmac
// linkage, so equality (not merely non-emptiness) is what this asserts.
func TestTruncatePartialTail_YieldsTheChainResumeLine(t *testing.T) {
	openRDWR := func(t *testing.T, logPath string) *os.File {
		t.Helper()
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_RDWR, 0o600) //nolint:gosec // G304: test-controlled path
		if err != nil {
			t.Fatalf("reopen O_RDWR: %v", err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}

	t.Run("clean tail", func(t *testing.T) {
		logPath, _ := writeChainLog(t, t.TempDir(), "a", "b", "c")
		tail, err := truncatePartialTail(openRDWR(t, logPath))
		if err != nil {
			t.Fatalf("truncatePartialTail: %v", err)
		}
		if !tail.lastOK {
			t.Fatal("a clean, readable tail must yield a usable chain-resume line, not force a re-read")
		}
		want, err := readLastAuditLine(logPath)
		if err != nil {
			t.Fatalf("readLastAuditLine: %v", err)
		}
		if tail.last != want {
			t.Fatalf("chain-resume line from the open handle differs from a re-read:\n got %q\nwant %q", tail.last, want)
		}
		if !strings.Contains(tail.last, `"c"`) {
			t.Errorf("expected the last recorded tool in the resume line, got %q", tail.last)
		}
	})

	t.Run("orphan truncated", func(t *testing.T) {
		logPath, _ := writeChainLog(t, t.TempDir(), "a", "b", "c")
		ap, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // G304: test-controlled path
		if err != nil {
			t.Fatalf("reopen for append: %v", err)
		}
		if _, err := ap.WriteString(`{"seq":99,"partial`); err != nil {
			t.Fatalf("append partial: %v", err)
		}
		if err := ap.Close(); err != nil {
			t.Fatalf("close append handle: %v", err)
		}

		tail, err := truncatePartialTail(openRDWR(t, logPath))
		if err != nil {
			t.Fatalf("truncatePartialTail: %v", err)
		}
		if !tail.lastOK || tail.recovered == 0 {
			t.Fatalf("want a recovered orphan and a usable resume line, got %+v", tail)
		}
		// The resume line must be the last COMPLETE record, never the dropped fragment.
		if strings.Contains(tail.last, "partial") {
			t.Fatalf("resume line must not be the truncated orphan fragment: %q", tail.last)
		}
		want, err := readLastAuditLine(logPath)
		if err != nil {
			t.Fatalf("readLastAuditLine after truncation: %v", err)
		}
		if tail.last != want {
			t.Fatalf("post-truncation resume line differs from a re-read:\n got %q\nwant %q", tail.last, want)
		}
	})

	t.Run("empty log resumes from genesis without a re-read", func(t *testing.T) {
		logPath := filepath.Join(t.TempDir(), "empty.jsonl")
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // G304: test-controlled path
		if err != nil {
			t.Fatalf("create empty log: %v", err)
		}
		defer func() { _ = f.Close() }()
		tail, err := truncatePartialTail(f)
		if err != nil {
			t.Fatalf("truncatePartialTail on an empty log: %v", err)
		}
		// "no tail" is authoritative on an empty log: Open must reach its rotated-sibling
		// fallback from this answer rather than re-reading to learn the same thing.
		if !tail.lastOK || tail.last != "" {
			t.Fatalf("want an authoritative empty resume line, got %+v", tail)
		}
	})

	t.Run("write-only log defers to a re-read", func(t *testing.T) {
		logPath, _ := writeChainLog(t, t.TempDir(), "a")
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: test-controlled path
		if err != nil {
			t.Fatalf("open write-only: %v", err)
		}
		defer func() { _ = f.Close() }()
		tail, err := recoverPartialTail(logPath, f, false)
		if err != nil {
			t.Fatalf("recoverPartialTail(readable=false): %v", err)
		}
		if tail.lastOK {
			t.Fatal("a write-only log never read its tail, so it must not claim a usable resume line")
		}
	})
}
