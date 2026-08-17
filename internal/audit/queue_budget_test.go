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
	"sync"
	"sync/atomic"
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
		// The denial taxonomy is fixed-width only for the BUILT-IN engine. An external
		// PolicyEvaluator (OPA/Cedar) or a custom ConditionHandler returns a
		// *ConditionError whose Code and ConditionType are operator-supplied strings, so
		// both are variable-length on that path and must be counted like the rest.
		{"DenialCode", func(r *auditRecord) { r.DenialCode = strings.Repeat("D", fill) }},
		{"ConditionType", func(r *auditRecord) { r.ConditionType = strings.Repeat("C", fill) }},
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
		DenialCode:    strings.Repeat("D", fill),
		ConditionType: strings.Repeat("C", fill),
		Details:       json.RawMessage(strings.Repeat("x", fill)),
		Obligations:   []string{strings.Repeat("o", fill), strings.Repeat("o", fill)},
		LabelsOut:     []string{strings.Repeat("l", fill)},
		CarriedLabels: []string{strings.Repeat("c", fill)},
	}
	// 12 envelope strings + Details + 2 obligations + 1 label out + 1 carried label,
	// each of length fill.
	want := int64(17*fill) + auditRecordEnvelopeEstimate
	if got := rec.queueSize(); got != want {
		t.Errorf("queueSize = %d, want %d", got, want)
	}
}

// TestQueuedSize_SurvivesWriteRecordMutation pins what makes the accounting balance:
// the drain credits the charge STORED on the record, not a size recomputed after
// writeRecord has stamped Seq/PrevHMAC/HMAC through the record pointer. Recomputing
// balanced only while queueSize happened to count none of those three — an unenforced
// coincidence. This test breaks that coincidence deliberately: it charges a record,
// applies the same mutation writeRecord applies, and asserts the credit still returns
// the counter to zero. Under the old recompute it would not, and because queuedBytes
// is a process-lifetime accumulator the per-record skew would drift monotonically
// until a healthy proxy with an idle disk dropped every audit record.
func TestQueuedSize_SurvivesWriteRecordMutation(t *testing.T) {
	t.Parallel()

	s := &Sink{}
	rec := auditRecord{
		SessionID:   "sess-1",
		Target:      "read_file",
		Method:      "tools/call",
		TargetType:  "tool",
		Details:     json.RawMessage(`{"path":"/etc/hosts"}`),
		Obligations: []string{"redactFields:token"},
		LabelsOut:   []string{"confidential"},
	}

	rec.queuedSize = rec.queueSize()
	s.queuedBytes.Add(rec.queuedSize)

	// Exactly what writeRecord stamps through the pointer before the drainer credits.
	rec.Seq = 42
	rec.PrevHMAC = strings.Repeat("a", 64)
	rec.HMAC = strings.Repeat("b", 64)

	s.queuedBytes.Add(-rec.queuedSize)
	if got := s.queuedBytes.Load(); got != 0 {
		t.Errorf("queuedBytes = %d after crediting a record writeRecord had stamped, want 0", got)
	}
	if rec.queuedSize == 0 {
		t.Error("queuedSize was never charged")
	}
}

// TestEnqueue_ChargeIsNeverNegativeUnderConcurrency covers the add/subtract ordering.
// The enqueue used to charge its bytes AFTER the channel send, so the drainer could
// receive a record and run its credit before the producing goroutine reached the
// charge: queuedBytes went transiently negative and under-reported in-flight heap for
// the length of the skew, admitting more than the budget accounts for under exactly
// the burst-plus-slow-disk conditions the budget exists for. With the reservation
// taken before the send, the counter is non-negative at every observation.
func TestEnqueue_ChargeIsNeverNegativeUnderConcurrency(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Sample the counter continuously while many producers race the drainer. Under
	// add-after-send this observer is what catches the window.
	stop := make(chan struct{})
	var sawNegative atomic.Bool
	var observer sync.WaitGroup
	observer.Add(1)
	go func() {
		defer observer.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if sink.queuedBytes.Load() < 0 {
					sawNegative.Store(true)
					return
				}
			}
		}
	}()

	ctx := context.Background()
	var producers sync.WaitGroup
	for i := 0; i < 16; i++ {
		producers.Add(1)
		go func() {
			defer producers.Done()
			for j := 0; j < 200; j++ {
				sink.RecordAllow(ctx, "sess-1", "read_file", "tools/call",
					map[string]interface{}{"path": strings.Repeat("p", 256)},
					nil, false, nil, nil)
			}
		}()
	}
	producers.Wait()
	close(stop)
	observer.Wait()

	if sawNegative.Load() {
		t.Error("queuedBytes went negative: the enqueue charge is not taken before the send, so the drainer can credit a record that was never charged")
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := sink.queuedBytes.Load(); got != 0 {
		t.Errorf("queuedBytes = %d after the queue drained, want 0", got)
	}
}

// TestRecord_BoundsExternalPDPDenialTaxonomy is the bounding half of the same gap.
// DenialCode/ConditionType are constants for the built-in engine but operator-supplied
// for an external PolicyEvaluator (OPA/Cedar) or a custom ConditionHandler, whose
// *ConditionError fields reach RecordParams verbatim. Unbounded they could push a
// record past the 4 MiB scanner buffer the rest of the envelope is bounded to stay
// under.
func TestRecord_BoundsExternalPDPDenialTaxonomy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	sink, err := Open(logPath, filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	huge := strings.Repeat("E", 4*auditEnvelopeFieldCap)
	sink.RecordDeny(context.Background(), "sess-1", "read_file", "tools/call", huge, huge, nil, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	recs := readAuditRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	for _, field := range []string{"denial_code", "condition_type"} {
		got, _ := recs[0][field].(string)
		if len(got) > auditEnvelopeFieldCap {
			t.Errorf("%s is %d bytes, want <= the %d-byte envelope cap", field, len(got), auditEnvelopeFieldCap)
		}
		if !strings.Contains(got, "truncated") {
			t.Errorf("%s = %q, want a visible truncation marker", field, got)
		}
	}
}

// TestQueuedBytes_ReturnsToZeroAfterDrain is the end-to-end half: every byte the
// enqueue charges is credited back once the drainer writes the record. A mismatch
// between the add and the subtract accumulates silently until the budget is
// exhausted and a healthy proxy starts shedding audit records.
func TestQueuedBytes_ReturnsToZeroAfterDrain(t *testing.T) {
	t.Parallel()
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
	if dropped := sink.Health().Dropped; dropped != 0 {
		t.Errorf("Health().Dropped = %d, want 0 (the test load is far below the budget)", dropped)
	}
}
