// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// at parses a test timestamp, failing the test rather than the assertion.
func at(tb testing.TB, s string) time.Time {
	tb.Helper()
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		tb.Fatalf("parsing %q: %v", s, err)
	}
	return t
}

// TestOrderJoinedRecords_OrdersByWriterClockAndBreaksTiesDeterministically pins the two
// halves of the ordering rule: records interleave across tapes by their own writers'
// timestamps, and a tie — two enforcement points stamping the same instant, which is
// common at any resolution coarser than the gap between two hops — resolves to a fixed
// (tape, seq) order rather than to whichever record the sort happened to see first. A
// report whose line order changes between two runs over the same bytes is one an auditor
// cannot diff.
func TestOrderJoinedRecords_OrdersByWriterClockAndBreaksTiesDeterministically(t *testing.T) {
	tie := "2026-08-22T10:00:01Z"
	recs := []JoinedRecord{
		{Tape: 2, Seq: 7, Time: tie, At: at(t, tie), TimeOK: true, PEP: "mcp:edge-2"},
		{Tape: 1, Seq: 3, Time: "2026-08-22T10:00:02Z", At: at(t, "2026-08-22T10:00:02Z"), TimeOK: true, PEP: "mcp:edge-1"},
		{Tape: 1, Seq: 2, Time: tie, At: at(t, tie), TimeOK: true, PEP: "mcp:edge-1"},
		{Tape: 1, Seq: 1, Time: "2026-08-22T10:00:00Z", At: at(t, "2026-08-22T10:00:00Z"), TimeOK: true, PEP: "mcp:edge-1"},
	}
	ord := OrderJoinedRecords(recs)
	got := make([][2]int, 0, len(ord.Ordered))
	for _, r := range ord.Ordered {
		got = append(got, [2]int{r.Tape, int(r.Seq)})
	}
	want := [][2]int{{1, 1}, {1, 2}, {2, 7}, {1, 3}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ordering: got %v, want %v", got, want)
	}
	// The caller's slice must survive: the per-tape sections print it in collection order.
	if recs[0].Tape != 2 || recs[0].Seq != 7 {
		t.Fatalf("OrderJoinedRecords must not reorder its input: %+v", recs[0])
	}
	if len(ord.ClockSkewedTapes) != 0 || len(ord.UnattributedTapes) != 0 || len(ord.Unordered) != 0 {
		t.Fatalf("clean input must produce no caveats: %+v", ord)
	}
}

// TestOrderJoinedRecords_ReportsClockSkewWithinATape covers the one part of the ordering
// assumption a local reader can FALSIFY. Across tapes nothing is provable — the clocks are
// independent — but within one tape seq order is signed and contiguity-checked, so a later
// seq carrying an earlier time is that writer disagreeing with itself, which makes every
// cross-tape position resting on that clock unreliable.
func TestOrderJoinedRecords_ReportsClockSkewWithinATape(t *testing.T) {
	recs := []JoinedRecord{
		{Tape: 1, Seq: 1, At: at(t, "2026-08-22T10:00:05Z"), TimeOK: true, PEP: "mcp:edge-1"},
		{Tape: 1, Seq: 2, At: at(t, "2026-08-22T10:00:01Z"), TimeOK: true, PEP: "mcp:edge-1"},
		{Tape: 2, Seq: 1, At: at(t, "2026-08-22T10:00:02Z"), TimeOK: true, PEP: "mcp:edge-2"},
		{Tape: 2, Seq: 2, At: at(t, "2026-08-22T10:00:03Z"), TimeOK: true, PEP: "mcp:edge-2"},
	}
	ord := OrderJoinedRecords(recs)
	if !reflect.DeepEqual(ord.ClockSkewedTapes, []int{1}) {
		t.Fatalf("tape 1's clock moved backwards and must be named: got %v", ord.ClockSkewedTapes)
	}
	// A tape whose records simply INTERLEAVE with another's is not skew: that is the
	// normal shape of a task crossing a hop, and reporting it would make the note noise.
	if len(ord.Ordered) != 4 {
		t.Fatalf("every record with a parseable time is orderable: %+v", ord.Ordered)
	}
}

// TestOrderJoinedRecords_UnparseableTimeHasNoPosition asserts a record whose signed
// `time` does not parse is neither sorted to an arbitrary place nor dropped: it belongs
// to the sequence (its task_id says so) but has no position in it, and dropping it would
// hide a record its own tape counted INVALID.
func TestOrderJoinedRecords_UnparseableTimeHasNoPosition(t *testing.T) {
	recs := []JoinedRecord{
		{Tape: 1, Seq: 2, Time: "not-a-time", Status: StatusInvalid, PEP: "mcp:edge-1"},
		{Tape: 1, Seq: 1, At: at(t, "2026-08-22T10:00:00Z"), TimeOK: true, PEP: "mcp:edge-1"},
	}
	ord := OrderJoinedRecords(recs)
	if len(ord.Ordered) != 1 || ord.Ordered[0].Seq != 1 {
		t.Fatalf("only the parseable record is ordered: %+v", ord.Ordered)
	}
	if len(ord.Unordered) != 1 || ord.Unordered[0].Seq != 2 {
		t.Fatalf("the unparseable record must still be reported: %+v", ord.Unordered)
	}
}

// TestOrderJoinedRecords_NamesUnattributedTapes covers the state the `pep` field exists to
// remove: a tape written by an instance with no configured enforcement-point name. Its
// records are placeable only by the file they came out of, which is precisely the
// attribution that does not survive a merge into a SIEM, so the join says so rather than
// printing a blank column.
func TestOrderJoinedRecords_NamesUnattributedTapes(t *testing.T) {
	recs := []JoinedRecord{
		{Tape: 1, Seq: 1, At: at(t, "2026-08-22T10:00:00Z"), TimeOK: true, PEP: "mcp:edge-1"},
		{Tape: 2, Seq: 1, At: at(t, "2026-08-22T10:00:01Z"), TimeOK: true},
	}
	ord := OrderJoinedRecords(recs)
	if !reflect.DeepEqual(ord.UnattributedTapes, []int{2}) {
		t.Fatalf("tape 2 carries no pep and must be named: got %v", ord.UnattributedTapes)
	}
}

// TestVerifyOptions_CollectCarriesTheVerdictOfTheSamePass is the property the collector
// exists for: a joined record's status comes from the pass that verified it, not from a
// second reading. A tampered record must reach the join marked invalid rather than being
// silently dropped — a sequence that omits the record whose signature failed hides
// exactly what the sequence is being read for.
func TestVerifyOptions_CollectCarriesTheVerdictOfTheSamePass(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0,
		WithEnforcementPoint(enforcementPointOrFatal(t, "edge-1")),
		WithIdentity(func(context.Context) Identity { return Identity{TaskID: "task-A"} }))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	sink.RecordAllow(ctx, "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	sink.RecordDeny(ctx, "sess-1", "wire_transfer", "tools/call", capability.ErrCodeAuthorizationFailed, "", nil, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	if len(lines) != 2 {
		t.Fatalf("expected 2 records, got %d", len(lines))
	}
	// Rewrite the second record's target while leaving its _hmac intact: content
	// tampering by an attacker without the key.
	tampered := strings.Replace(string(lines[1]), `"target":"wire_transfer"`, `"target":"read_file"`, 1)
	joined := string(lines[0]) + "\n" + tampered + "\n"

	var got []JoinedRecord
	res, err := VerifyLog(strings.NewReader(joined), verifierFor(t, keyPath), VerifyOptions{
		TaskID:  "task-A",
		Collect: func(r JoinedRecord) { got = append(got, r) },
	})
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if res.Invalid != 1 {
		t.Fatalf("the tampered record must be counted invalid: %+v", res)
	}
	if len(got) != 2 {
		t.Fatalf("both records carry task-A and must be collected: %+v", got)
	}
	if got[0].Status != StatusVerified || got[1].Status != StatusInvalid {
		t.Fatalf("collected statuses must match the pass's own verdicts: %q, %q", got[0].Status, got[1].Status)
	}
	if got[0].PEP != "mcp:edge-1" {
		t.Fatalf("a joined record must carry the writer that stamped it: %q", got[0].PEP)
	}
	if !got[0].TimeOK || got[0].At.IsZero() {
		t.Fatalf("a parseable time must reach the join parsed: %+v", got[0])
	}
}

// TestVerifyOptions_CollectSkipsOtherTasksAndIgnoresSince pins the join window. The task
// filter selects; --since deliberately does NOT, because a sequence read to reconstruct
// one task end to end must not lose its head because the investigator asked about the
// last hour — that would present a truncated sequence as a whole one.
func TestVerifyOptions_CollectSkipsOtherTasksAndIgnoresSince(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	task := "task-A"
	sink, err := Open(logPath, keyPath, 0, 0,
		WithIdentity(func(context.Context) Identity { return Identity{TaskID: task} }))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	sink.RecordAllow(ctx, "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	task = "task-B"
	sink.RecordAllow(ctx, "sess-1", "list_dir", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var got []JoinedRecord
	res, err := VerifyLog(strings.NewReader(string(mustReadFile(t, logPath))), verifierFor(t, keyPath), VerifyOptions{
		TaskID:  "task-A",
		Since:   time.Now().Add(24 * time.Hour),
		Collect: func(r JoinedRecord) { got = append(got, r) },
	})
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if !res.OK() {
		t.Fatalf("an untampered log must pass whatever the filters: %+v", res)
	}
	if len(got) != 1 || got[0].TaskID != "task-A" || got[0].Target != "read_file" {
		t.Fatalf("only task-A's record joins, and --since must not drop it: %+v", got)
	}
}

// TestVerifyOptions_UnsignedRecordJoinsWithItsTimestamp covers the record classify rejects
// BEFORE any signature check. It still belongs to the sequence — an attacker who strips a
// signature must not thereby remove the call from the reconstruction — and it keeps its
// position, because listing a record whose timestamp parses perfectly among the ones whose
// time does not parse would misreport why it has none. That its timestamp is covered by no
// signature this pass could check is what the row's STATUS says.
func TestVerifyOptions_UnsignedRecordJoinsWithItsTimestamp(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0,
		WithIdentity(func(context.Context) Identity { return Identity{TaskID: "task-A"} }))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	line := string(logLines(t, logPath)[0])
	// Strip the signature: the one edit possible without the key.
	start := strings.Index(line, `,"_hmac":"`)
	if start < 0 {
		t.Fatalf("test setup: no _hmac in %s", line)
	}
	stripped := line[:start] + "}"

	var got []JoinedRecord
	res, err := VerifyLog(strings.NewReader(stripped+"\n"), verifierFor(t, keyPath), VerifyOptions{
		TaskID:  "task-A",
		Collect: func(r JoinedRecord) { got = append(got, r) },
	})
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if res.Invalid != 1 {
		t.Fatalf("an unsigned record must fail the tape's verdict: %+v", res)
	}
	if len(got) != 1 {
		t.Fatalf("stripping a signature must not remove the call from the sequence: %+v", got)
	}
	if got[0].Status != StatusUnsigned {
		t.Fatalf("status must name the reason: %q", got[0].Status)
	}
	if !got[0].TimeOK {
		t.Fatalf("a parseable timestamp keeps its position: %+v", got[0])
	}
}
