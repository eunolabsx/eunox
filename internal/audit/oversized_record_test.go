// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// authoredLabelSet builds n distinct labels of the shape a manifest can legally author:
// an imported class at close to the maximum value length, so the set is the one a POLICY
// produces rather than anything a caller supplies.
func authoredLabelSet(n int) []string {
	labels := make([]string, n)
	// 90 + at most five digits keeps the value inside the 96-byte bound the manifest
	// loader enforces, so every entry is one a policy could really author.
	pad := strings.Repeat("c", 90)
	for i := range labels {
		labels[i] = "purview:" + pad + strconv.Itoa(i)
	}
	return labels
}

// TestRecord_OversizedLabelSetStaysInsideTheScanWindow is the oversized-record shape: a
// record whose carried_labels union would, unbounded, put the line past
// auditScanBufferBytes. No attacker is involved — the union accrues across every
// labelOutput an anchor has hit, so the per-directive count cap the manifest loader
// applies does not bound it, and a policy with enough labelled constraints reaches this
// on its own.
//
// The consequences are what makes the record-side backstop load-bearing rather than
// tidiness: an over-window line aborts the whole verify/stats/suggest pass with
// bufio.ErrTooLong and NO per-record finding (the tape stops being verifiable at all),
// and as the tail it takes the window-clipped resume path on every restart. Both halves
// are asserted here.
func TestRecord_OversizedLabelSetStaysInsideTheScanWindow(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	const labelCount = 42000
	carried := authoredLabelSet(labelCount)

	// Precondition: this set alone does not fit the reader's window, so the assertions
	// below are about the bound and not about the fixture being too small to matter.
	unbounded, err := json.Marshal(carried)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if len(unbounded) <= auditScanBufferBytes {
		t.Fatalf("fixture is only %d bytes; it must exceed the %d-byte scan window to exercise the bound",
			len(unbounded), auditScanBufferBytes)
	}

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess-1", "read_secret", "tools/call", nil, nil, false,
		[]string{"confidential"}, carried)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	if len(lines) != 1 {
		t.Fatalf("expected 1 record, got %d", len(lines))
	}
	if len(lines[0]) > auditScanBufferBytes {
		t.Fatalf("record is %d bytes, over the %d-byte scan window", len(lines[0]), auditScanBufferBytes)
	}

	// The truncation is VISIBLE in the record rather than silent: a reader must be able
	// to tell a session that carried three labels from one whose set was cut.
	var rec auditRecord
	if err := json.Unmarshal(lines[0], &rec); err != nil {
		t.Fatalf("unmarshal record: %v", err)
	}
	if len(rec.CarriedLabels) >= labelCount {
		t.Fatalf("carried_labels kept %d entries, want the slice bounded below %d", len(rec.CarriedLabels), labelCount)
	}
	sentinel := rec.CarriedLabels[len(rec.CarriedLabels)-1]
	wantSentinel := truncationSentinel("labels", labelCount-(len(rec.CarriedLabels)-1))
	if sentinel != wantSentinel {
		t.Errorf("carried_labels sentinel = %q, want %q", sentinel, wantSentinel)
	}
	// labels_out was under the cap, so it is untouched — the bound is per field.
	if len(rec.LabelsOut) != 1 || rec.LabelsOut[0] != "confidential" {
		t.Errorf("labels_out = %v, want the unbounded-below-cap slice preserved", rec.LabelsOut)
	}

	// Half one: the pass READS the tape. An over-window line would abort it here with
	// bufio.ErrTooLong and no per-record verdict at all.
	res, err := VerifyLog(bytes.NewReader(bytes.Join(lines, []byte("\n"))), verifierFor(t, keyPath),
		VerifyOptions{Out: &strings.Builder{}})
	if err != nil {
		t.Fatalf("VerifyLog aborted: %v (an over-window record makes the tape permanently unverifiable)", err)
	}
	if !res.OK() || res.Total != 1 || res.Valid != 1 {
		t.Fatalf("verify verdict = %+v, want one valid record", res)
	}

	// Half two: the record is a tail the sink can RESUME from — the chain continues onto
	// it rather than restarting at genesis behind an integrity marker.
	resumed, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	resumed.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := resumed.Close(); err != nil {
		t.Fatalf("Close after resume: %v", err)
	}

	lines = logLines(t, logPath)
	if len(lines) != 2 {
		t.Fatalf("expected 2 records after resume, got %d (a marker line means the tail was not chained onto)", len(lines))
	}
	var next auditRecord
	if err := json.Unmarshal(lines[1], &next); err != nil {
		t.Fatalf("unmarshal resumed record: %v", err)
	}
	if next.PrevHMAC != rec.HMAC {
		t.Errorf("resumed record prev_hmac = %q, want the oversized tail's hmac %q", next.PrevHMAC, rec.HMAC)
	}
	if next.Seq != rec.Seq+1 {
		t.Errorf("resumed record seq = %d, want %d", next.Seq, rec.Seq+1)
	}
	if res := verifyBytes(t, lines, verifierFor(t, keyPath)); !res.OK() {
		t.Errorf("resumed log verdict = %+v, want a clean pass", res)
	}
}

// TestBoundAuditLabels_CapAndSentinel covers the label bound directly: a realistic slice
// is returned untouched, and an over-cap one is a kept prefix plus one sentinel that
// serializes within auditLabelsTotalCap. The sentinel is deliberately unmistakable for a
// label — an imported one's namespace is lowercase letters, digits and hyphens, so no
// authored label can spell it.
func TestBoundAuditLabels_CapAndSentinel(t *testing.T) {
	t.Parallel()

	in := []string{"confidential", "purview:highly-confidential"}
	if out := boundAuditLabels(in); len(out) != len(in) || out[0] != in[0] || out[1] != in[1] {
		t.Fatalf("an under-cap slice was modified: got %v, want %v", out, in)
	}

	oversized := authoredLabelSet(4000)
	out := boundAuditLabels(oversized)
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(encoded) > auditLabelsTotalCap {
		t.Fatalf("result serializes to %d bytes, over the %d-byte cap", len(encoded), auditLabelsTotalCap)
	}
	if len(out) >= len(oversized) {
		t.Fatalf("oversized slice was not truncated: %d entries from %d", len(out), len(oversized))
	}
	kept := out[:len(out)-1]
	for i, label := range kept {
		if label != oversized[i] {
			t.Fatalf("kept[%d] = %q, want the in-order prefix entry %q", i, label, oversized[i])
		}
	}
	if got, want := out[len(out)-1], fmt.Sprintf("labels_truncated:%d", len(oversized)-len(kept)); got != want {
		t.Fatalf("sentinel = %q, want %q", got, want)
	}
}
