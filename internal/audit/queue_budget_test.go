// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// TestQueueSize_CountsVariableEnvelopeFields pins that queueSize charges a record for
// its variable-length envelope strings rather than a flat allowance.
//
// AgentID/TaskID/UserID (IdP-supplied) and Target/Method (request-supplied) are each
// bounded only by auditEnvelopeFieldCap (8 KiB), so a single record can retain ~40 KiB of
// envelope. Charging every record a flat 512 B let a queue of such records overshoot
// auditQueueByteBudget several times over — the OOM the budget exists to prevent.
func TestQueueSize_CountsVariableEnvelopeFields(t *testing.T) {
	t.Parallel()

	big := strings.Repeat("x", auditEnvelopeFieldCap)
	rec := auditRecord{
		AgentID: big,
		TaskID:  big,
		UserID:  big,
		Target:  big,
		Method:  big,
	}
	got := rec.queueSize()
	want := int64(5*auditEnvelopeFieldCap) + auditRecordEnvelopeEstimate
	if got != want {
		t.Errorf("queueSize() = %d, want %d (5 x %d-byte fields + the flat remainder)", got, want, auditEnvelopeFieldCap)
	}
	// The point of the fix: a record like this must not be mistaken for a small one.
	if got <= auditRecordEnvelopeEstimate*2 {
		t.Errorf("queueSize() = %d for a ~40 KiB record; the budget cannot bound heap it does not count", got)
	}
}

// TestQueueSize_CountsDetailsObligationsAndLabels pins the other variable-length
// contributors, so a future field added to auditRecord that is retained on the queue is
// visibly either counted here or deliberately folded into the flat allowance.
func TestQueueSize_CountsDetailsObligationsAndLabels(t *testing.T) {
	t.Parallel()

	base := (&auditRecord{}).queueSize()
	if base != auditRecordEnvelopeEstimate {
		t.Fatalf("empty record queueSize() = %d, want the flat allowance %d", base, auditRecordEnvelopeEstimate)
	}

	for _, tc := range []struct {
		name string
		rec  auditRecord
		want int64
	}{
		{"details", auditRecord{Details: json.RawMessage(strings.Repeat("d", 100))}, 100},
		{"obligations", auditRecord{Obligations: []string{strings.Repeat("o", 40), strings.Repeat("o", 60)}}, 100},
		{"labels_out", auditRecord{LabelsOut: []string{strings.Repeat("l", 100)}}, 100},
		{"carried_labels", auditRecord{CarriedLabels: []string{strings.Repeat("c", 100)}}, 100},
		{"session_id", auditRecord{SessionID: strings.Repeat("s", 100)}, 100},
		{"upstream+policy", auditRecord{Upstream: strings.Repeat("u", 40), PolicyVersion: strings.Repeat("v", 30), PolicySHA256: strings.Repeat("h", 30)}, 100},
		{"decision fields", auditRecord{Decision: strings.Repeat("a", 40), DenialCode: strings.Repeat("b", 30), ConditionType: strings.Repeat("c", 30)}, 100},
		{"time+request+key", auditRecord{Time: strings.Repeat("t", 40), RequestID: strings.Repeat("r", 30), KeyID: strings.Repeat("k", 30)}, 100},
		{"target_type", auditRecord{TargetType: strings.Repeat("T", 100)}, 100},
	} {
		if got := tc.rec.queueSize() - base; got != tc.want {
			t.Errorf("%s: queueSize contribution = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestQueueSize_ExcludesDrainerAssignedFields pins the invariant the enqueue/drain
// accounting rests on: queueSize must depend only on fields Record fills. writeRecord
// stamps Seq/PrevHMAC/HMAC on the drainer goroutine BETWEEN the enqueue reservation and
// the drain release, so counting them would make the two disagree and leak (or negatively
// drift) the queuedBytes budget over a run.
func TestQueueSize_ExcludesDrainerAssignedFields(t *testing.T) {
	t.Parallel()

	rec := auditRecord{SessionID: "s", Method: "tools/call", Target: "read_file"}
	before := rec.queueSize()

	// Exactly what writeRecord does to a record after it is dequeued.
	rec.Seq = 12345
	rec.PrevHMAC = strings.Repeat("a", 71)
	rec.HMAC = strings.Repeat("b", 71)

	if after := rec.queueSize(); after != before {
		t.Errorf("queueSize changed from %d to %d after writeRecord's field assignments; the drain would release a different amount than the enqueue reserved", before, after)
	}
}

// TestQueuedBytes_ReservedThenReleased pins the add/subtract accounting end to end: bytes
// are reserved on enqueue and fully released once the drainer has written the records, so
// a long-running sink cannot slowly leak its way to the byte budget and start dropping.
func TestQueuedBytes_ReservedThenReleased(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	details := map[string]interface{}{"path": strings.Repeat("p", 4096)}
	for range 50 {
		sink.RecordDeny(t.Context(), "sess-1", "read_file", "tools/call", "AUTHORIZATION_FAILED", "", details, false)
	}
	// Close drains the queue and stops the drainer, so every reservation must be released
	// by the time it returns.
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := sink.queuedBytes.Load(); got != 0 {
		t.Errorf("queuedBytes = %d after the queue drained, want 0 (reservations must balance)", got)
	}
	if dropped := sink.DroppedRecords(); dropped != 0 {
		t.Errorf("dropped %d records well under the byte budget", dropped)
	}
}

// TestQueuedBytes_BudgetDropsOversizedBacklog pins that the byte budget actually sheds
// records once the aggregate reservation is exhausted, counting the loss instead of
// growing the heap without bound.
func TestQueuedBytes_BudgetDropsOversizedBacklog(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	// Pre-charge the budget so the next record is over it, without needing to actually
	// queue 256 MiB. This is the state a stalled disk produces.
	sink.queuedBytes.Store(auditQueueByteBudget)
	sink.RecordDeny(t.Context(), "sess-1", "read_file", "tools/call", "AUTHORIZATION_FAILED", "", nil, false)
	if got := sink.DroppedRecords(); got != 1 {
		t.Errorf("DroppedRecords = %d, want 1: a record over the byte budget must be shed and counted", got)
	}
}

// TestQueueSize_CoversEveryRetainedField is the staleness guard the value-based tests
// above cannot provide: it walks auditRecord by reflection and asserts that EVERY
// variable-length field either contributes to queueSize or is on the explicit exclusion
// list, so a field added later fails this test until someone decides which it is.
//
// Without it, a new IdP- or request-sourced envelope string — exactly the 8 KiB-capped
// class this accounting exists for — would be charged 0 bytes, auditQueueByteBudget would
// stop tracking retained heap, and the OOM it guards against would return silently with
// every other test still green.
func TestQueueSize_CoversEveryRetainedField(t *testing.T) {
	t.Parallel()

	// Assigned by writeRecord on the drainer AFTER the enqueue reservation and BEFORE the
	// drain release, so counting them would make the two disagree. Seq is a uint64 and
	// retains nothing beyond the struct either way.
	excluded := map[string]bool{"Seq": true, "PrevHMAC": true, "HMAC": true}

	const filler = 64
	rt := reflect.TypeOf(auditRecord{})
	for i := range rt.NumField() {
		f := rt.Field(i)
		if excluded[f.Name] {
			continue
		}

		// Build a record carrying content in exactly this one field.
		rv := reflect.New(rt).Elem()
		fv := rv.Field(i)
		switch f.Type.Kind() {
		case reflect.String:
			fv.SetString(strings.Repeat("x", filler))
		case reflect.Slice:
			switch f.Type.Elem().Kind() {
			case reflect.String: // []string (Obligations, LabelsOut, CarriedLabels)
				fv.Set(reflect.ValueOf([]string{strings.Repeat("x", filler)}))
			case reflect.Uint8: // json.RawMessage (Details)
				fv.SetBytes([]byte(strings.Repeat("x", filler)))
			default:
				t.Fatalf("field %s: unhandled slice element kind %s — decide whether it is retained heap and extend this test", f.Name, f.Type.Elem().Kind())
			}
		case reflect.Int, reflect.Bool, reflect.Uint64:
			continue // fixed-size, covered by the flat allowance
		default:
			t.Fatalf("field %s: unhandled kind %s — decide whether it is retained heap and extend this test", f.Name, f.Type.Kind())
		}

		rec := rv.Interface().(auditRecord)
		got := rec.queueSize() - auditRecordEnvelopeEstimate
		if got != filler {
			t.Errorf("field %s contributes %d bytes to queueSize, want %d: an uncounted field escapes the queue byte budget entirely", f.Name, got, filler)
		}
	}
}
