// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Direct assertions on queueSize, the per-record estimate behind the aggregate
// queued-byte budget. The budget is what makes a slow disk shed records (counted,
// tamper-evident) instead of OOM-ing the proxy, and it is only as good as the
// estimate: anything queueSize does not count is heap the budget cannot see.

package audit

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// TestQueueSize_CountsVariableEnvelopeStrings is the regression: the envelope
// strings an attacker or IdP can grow — Target, an unrecognized raw Method, and the
// three JWT identity claims — are each bounded at auditEnvelopeFieldCap but were
// once folded into the flat auditRecordEnvelopeEstimate, which is orders of
// magnitude smaller. A flood of such records then held many times the byte budget
// they were supposed to be bounded by. Each must be counted individually.
func TestQueueSize_CountsVariableEnvelopeStrings(t *testing.T) {
	t.Parallel()

	base := &auditRecord{}
	baseSize := base.queueSize()
	if baseSize != auditRecordEnvelopeEstimate {
		t.Fatalf("empty record queueSize = %d, want the flat estimate %d", baseSize, auditRecordEnvelopeEstimate)
	}

	const fill = 4096
	cases := []struct {
		name string
		set  func(*auditRecord)
	}{
		{"Target", func(r *auditRecord) { r.Target = strings.Repeat("t", fill) }},
		{"Method", func(r *auditRecord) { r.Method = strings.Repeat("m", fill) }},
		{"TargetType", func(r *auditRecord) { r.TargetType = strings.Repeat("y", fill) }},
		{"SessionID", func(r *auditRecord) { r.SessionID = strings.Repeat("s", fill) }},
		{"AgentID", func(r *auditRecord) { r.AgentID = strings.Repeat("a", fill) }},
		{"TaskID", func(r *auditRecord) { r.TaskID = strings.Repeat("k", fill) }},
		{"UserID", func(r *auditRecord) { r.UserID = strings.Repeat("u", fill) }},
		{"Upstream", func(r *auditRecord) { r.Upstream = strings.Repeat("p", fill) }},
		{"PolicyVersion", func(r *auditRecord) { r.PolicyVersion = strings.Repeat("v", fill) }},
		{"PolicySHA256", func(r *auditRecord) { r.PolicySHA256 = strings.Repeat("d", fill) }},
		{"LabelsOut", func(r *auditRecord) { r.LabelsOut = []string{strings.Repeat("l", fill)} }},
		{"CarriedLabels", func(r *auditRecord) { r.CarriedLabels = []string{strings.Repeat("c", fill)} }},
		{"Obligations", func(r *auditRecord) { r.Obligations = []string{strings.Repeat("o", fill)} }},
		{"Details", func(r *auditRecord) { r.Details = json.RawMessage(strings.Repeat("x", fill)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &auditRecord{}
			tc.set(rec)
			if got, want := rec.queueSize(), baseSize+fill; got != want {
				t.Errorf("queueSize with a %d-byte %s = %d, want %d — the field is not counted, so the queue can hold heap the budget cannot see", fill, tc.name, got, want)
			}
		})
	}
}

// TestQueueSize_CountsEveryVariableFieldTogether pins the aggregate: a record that
// fills every counted field at once is sized as the sum, not as whichever single
// field happens to dominate.
func TestQueueSize_CountsEveryVariableFieldTogether(t *testing.T) {
	t.Parallel()

	const fill = 1024
	rec := &auditRecord{
		SessionID:     strings.Repeat("s", fill),
		AgentID:       strings.Repeat("a", fill),
		TaskID:        strings.Repeat("k", fill),
		UserID:        strings.Repeat("u", fill),
		Upstream:      strings.Repeat("p", fill),
		PolicyVersion: strings.Repeat("v", fill),
		PolicySHA256:  strings.Repeat("d", fill),
		TargetType:    strings.Repeat("y", fill),
		Target:        strings.Repeat("t", fill),
		Method:        strings.Repeat("m", fill),
		Details:       json.RawMessage(strings.Repeat("x", fill)),
		Obligations:   []string{strings.Repeat("o", fill), strings.Repeat("o", fill)},
		LabelsOut:     []string{strings.Repeat("l", fill)},
		CarriedLabels: []string{strings.Repeat("c", fill)},
	}
	// 11 single-valued fields + 2 obligations + 1 label out + 1 carried label.
	want := int64(15*fill) + auditRecordEnvelopeEstimate
	if got := rec.queueSize(); got != want {
		t.Errorf("queueSize = %d, want %d", got, want)
	}
}

// TestQueueSize_IsStableAcrossCalls pins what makes the accounting balance: the
// enqueue adds queueSize and the drainer subtracts a value it recomputes from the
// same record. queueSize reads only immutable fields, so the two calls must agree
// — a size that varied between them would leak (or credit) budget on every record
// and eventually wedge the queue closed or defeat the bound entirely.
func TestQueueSize_IsStableAcrossCalls(t *testing.T) {
	t.Parallel()

	rec := &auditRecord{
		SessionID:   "sess-1",
		Target:      "read_file",
		Method:      "tools/call",
		TargetType:  "tool",
		Details:     json.RawMessage(`{"path":"/etc/hosts"}`),
		Obligations: []string{"redactFields:token"},
		LabelsOut:   []string{"confidential"},
	}
	first := rec.queueSize()
	if second := rec.queueSize(); first != second {
		t.Fatalf("queueSize is not stable: %d then %d", first, second)
	}
}

// TestQueuedBytes_ReturnsToZeroAfterDrain is the end-to-end half: every byte the
// enqueue charges is credited back once the drainer writes the record. A mismatch
// between the add and the subtract accumulates silently until the budget is
// exhausted and a healthy proxy starts shedding audit records.
func TestQueuedBytes_ReturnsToZeroAfterDrain(t *testing.T) {
	dir := t.TempDir()
	sink, err := Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ctx := context.Background()
	for i := 0; i < 50; i++ {
		sink.RecordAllow(ctx, "sess-1", "read_file", "tools/call",
			map[string]interface{}{"path": strings.Repeat("p", 512)},
			[]string{"redactFields:token"}, false, []string{"confidential"}, []string{"public"})
		sink.RecordDeny(ctx, "sess-1", "write_file", "tools/call", "CAPABILITY_DENIED", "",
			map[string]interface{}{"path": strings.Repeat("q", 512)}, false)
	}

	// Close waits for the drainer to finish, so every queued record has been
	// accounted for by the time it returns.
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := sink.queuedBytes.Load(); got != 0 {
		t.Errorf("queuedBytes = %d after the queue drained, want 0 — the enqueue add and the drain subtract disagree", got)
	}
	if dropped := sink.DroppedRecords(); dropped != 0 {
		t.Errorf("DroppedRecords = %d, want 0 (the test load is far below the budget)", dropped)
	}
}
