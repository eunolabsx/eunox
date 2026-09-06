// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"math/rand"
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

// lastEntry returns the final element, failing rather than panicking on an empty slice:
// both label fields are omitempty, so a regression that emptied one would otherwise take
// the test binary down with an index-out-of-range instead of reporting what broke.
func lastEntry(t *testing.T, field string, entries []string) string {
	t.Helper()
	if len(entries) == 0 {
		t.Fatalf("%s is empty; expected a kept prefix plus a truncation sentinel", field)
	}
	return entries[len(entries)-1]
}

// TestRecord_OversizedLabelSetStaysInsideTheScanWindow is the oversized-record shape: a
// record whose flow-label fields would, unbounded, put the line past
// auditScanBufferBytes. No attacker is involved — each field is a union of many authored
// lists, so the per-list count cap the manifest loader applies bounds neither, and a
// policy with enough labelled constraints reaches this on its own.
//
// The consequences are what makes the record-side backstop load-bearing rather than
// tidiness: an over-window line aborts the whole verify/stats/suggest pass with
// bufio.ErrTooLong and NO per-record finding (the tape stops being verifiable at all),
// and as the tail it takes the window-clipped resume path on every restart. Both halves
// are asserted here.
//
// BOTH fields are driven oversized. labels_out is not along for the ride: it is its own
// union (every labelOutput on the matched constraint, and on the principal-blind legs
// across every capability naming the target), so dropping its bound has to fail here.
func TestRecord_OversizedLabelSetStaysInsideTheScanWindow(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	const labelCount = 42000
	// Native classes first, then imported — the canonical order NormalizeFlowLabels
	// renders and the engine therefore hands the sink. Keeping a leading PREFIX is what
	// makes the integrity classes survive truncation, which is the property an incident
	// reconstruction depends on: a set cut down to imported classes while `untrusted`
	// silently folds into the sentinel would leave the tape unable to say why
	// enforcement blocked.
	natives := []string{"untrusted", "pii"}
	carried := append(append([]string{}, natives...), authoredLabelSet(labelCount)...)
	out := authoredLabelSet(labelCount)

	// Precondition: either set alone does not fit the reader's window, so the assertions
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
	sink.RecordAllow(context.Background(), "sess-1", "read_secret", "tools/call", nil, nil, false, out, carried)
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
	for _, f := range []struct {
		name  string
		got   []string
		input int
	}{
		{"carried_labels", rec.CarriedLabels, len(carried)},
		{"labels_out", rec.LabelsOut, len(out)},
	} {
		if len(f.got) >= f.input {
			t.Fatalf("%s kept %d entries, want the slice bounded below %d", f.name, len(f.got), f.input)
		}
		want := labelsList.sentinel(f.input - (len(f.got) - 1))
		if got := lastEntry(t, f.name, f.got); got != want {
			t.Errorf("%s sentinel = %q, want %q", f.name, got, want)
		}
	}
	// The native classes lead the canonical order, so they are inside every kept prefix.
	for i, native := range natives {
		if rec.CarriedLabels[i] != native {
			t.Errorf("carried_labels[%d] = %q, want the native class %q to survive truncation",
				i, rec.CarriedLabels[i], native)
		}
	}

	// Half one: the pass READS the tape. An over-window line would abort it here with
	// bufio.ErrTooLong and no per-record verdict at all.
	res := verifyBytes(t, lines, verifierFor(t, keyPath))
	if !res.OK() || res.Total != 1 || res.Valid != 1 {
		t.Fatalf("verify verdict = %+v, want one valid record (an over-window record makes the tape permanently unverifiable)", res)
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
// serializes within auditLabelsTotalCap. The sentinel cannot be mistaken for a label —
// an imported one's namespace is lowercase letters, digits and hyphens, and both
// producers of these fields validate every entry, so nothing can mint one.
func TestBoundAuditLabels_CapAndSentinel(t *testing.T) {
	t.Parallel()

	in := []string{"confidential", "purview:highly-confidential"}
	if got := boundAuditLabels(in); len(got) != len(in) || got[0] != in[0] || got[1] != in[1] {
		t.Fatalf("an under-cap slice was modified: got %v, want %v", got, in)
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
	sentinel := lastEntry(t, "bounded labels", out)
	kept := out[:len(out)-1]
	for i, label := range kept {
		if label != oversized[i] {
			t.Fatalf("kept[%d] = %q, want the in-order prefix entry %q", i, label, oversized[i])
		}
	}
	if want := labelsList.sentinel(len(oversized) - len(kept)); sentinel != want {
		t.Fatalf("sentinel = %q, want %q", sentinel, want)
	}
}

// TestJSONEncodedStringLen_MatchesTheEncoder pins the fast path against json.Marshal
// itself. The whole cap arithmetic is built on this number, so a fast path that
// under-counts by even one byte per entry lets a record serialize over its field's
// budget — the failure the caps exist to prevent, reintroduced by an optimization. The
// adversarial cases are exactly the classes the predicate refuses to model: the escaped
// bytes, the HTML-safety trio, multi-byte runes, the line terminators json escapes, and
// invalid UTF-8 (which the encoder rewrites to U+FFFD, changing the length).
func TestJSONEncodedStringLen_MatchesTheEncoder(t *testing.T) {
	t.Parallel()

	cases := []string{
		"", "a", "confidential", "purview:highly-confidential", "redactFields:$.ssn",
		`"`, `\`, "<", ">", "&", "<script>", "a&b", "\x00", "\x1f", "\x7f",
		"héllo", "日本語", " ", " ", "\U0001F600",
		string([]byte{0xff}), string([]byte{0xc3, 0x28}), "ok" + string([]byte{0x80}) + "tail",
		strings.Repeat("c", 90), strings.Repeat("\"\n\\", 20),
	}
	rng := rand.New(rand.NewSource(31))
	for i := 0; i < 4000; i++ {
		b := make([]byte, rng.Intn(24))
		for j := range b {
			b[j] = byte(rng.Intn(256))
		}
		cases = append(cases, string(b))
	}

	for _, s := range cases {
		encoded, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("marshal %q: %v", s, err)
		}
		if got := jsonEncodedStringLen(s); got != len(encoded) {
			t.Fatalf("jsonEncodedStringLen(%q) = %d, encoder produces %d bytes (%s)",
				s, got, len(encoded), encoded)
		}
	}
}
