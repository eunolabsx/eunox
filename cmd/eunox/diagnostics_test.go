// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// A support bundle and a `suggest` draft are read by a human reconstructing what a proxy
// did. These pin the two places where the numbers on the page contradicted the tape.

// suggest counted a record that named a capability target but carried a decision this
// build does not model, then dropped it from every bucket — so allow+deny+escalate came
// up short of the record total printed beside it, which reads as a counting bug.
func TestSuggestBanner_UnknownDecisionsReconcile(t *testing.T) {
	content := `{"decision":"allow","target_type":"tool","target":"read_file","method":"tools/call"}` + "\n" +
		`{"decision":"deny","target_type":"tool","target":"write_file","method":"tools/call"}` + "\n" +
		`{"decision":"quantum","target_type":"tool","target":"read_file","method":"tools/call"}` + "\n"

	s, err := computeSuggestions(strings.NewReader(content), suggestMaxValuesDefault)
	if err != nil {
		t.Fatalf("computeSuggestions: %v", err)
	}
	if s.records != 3 {
		t.Fatalf("records = %d, want 3 (every record naming a target is mined)", s.records)
	}
	if got := s.allow + s.deny + s.escalate + s.unknownDecision; got != s.records {
		t.Errorf("allow(%d)+deny(%d)+escalate(%d)+unknown(%d) = %d, want the record total %d",
			s.allow, s.deny, s.escalate, s.unknownDecision, got, s.records)
	}

	out := renderSuggestedManifest(s, "draft", suggestMaxValuesDefault)
	if !strings.Contains(out, "decision this build does not model") {
		t.Errorf("the banner must account for the unmodelled decision rather than leave a silent gap:\n%s", out)
	}
}

// The common case must stay quiet: no unmodelled decisions, no extra banner line.
func TestSuggestBanner_NoUnknownDecisionsStaysQuiet(t *testing.T) {
	content := `{"decision":"allow","target_type":"tool","target":"read_file","method":"tools/call"}` + "\n"
	s, err := computeSuggestions(strings.NewReader(content), suggestMaxValuesDefault)
	if err != nil {
		t.Fatalf("computeSuggestions: %v", err)
	}
	if s.unknownDecision != 0 {
		t.Fatalf("unknownDecision = %d, want 0", s.unknownDecision)
	}
	if out := renderSuggestedManifest(s, "draft", suggestMaxValuesDefault); strings.Contains(out, "does not model") {
		t.Errorf("a clean tape must not carry the unmodelled-decision note:\n%s", out)
	}
}

// doctor dropped the escalated count its `stats` sibling reports over the same tape, so
// two views of one log disagreed for the human reading the bundle.
func TestWriteDoctorAudit_ReportsEscalatedCount(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	doctorWriteFile(t, logPath,
		`{"decision":"allow","target_type":"tool","target":"a","method":"tools/call"}`+"\n"+
			`{"decision":"escalate","target_type":"tool","target":"refund","method":"tools/call"}`+"\n")

	var buf bytes.Buffer
	writeDoctorAudit(&buf, logPath, filepath.Join(dir, "k.key"), 0)
	if !strings.Contains(buf.String(), "escalated=1") {
		t.Errorf("the totals line must surface the escalated count, as `eunox stats` does:\n%s", buf.String())
	}
}

// A tape with no escalations must not carry a zero-valued bucket.
func TestWriteDoctorAudit_OmitsZeroEscalatedCount(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	doctorWriteFile(t, logPath, `{"decision":"allow","target_type":"tool","target":"a","method":"tools/call"}`+"\n")

	var buf bytes.Buffer
	writeDoctorAudit(&buf, logPath, filepath.Join(dir, "k.key"), 0)
	if strings.Contains(buf.String(), "escalated=") {
		t.Errorf("a tape with no escalations must not print the bucket:\n%s", buf.String())
	}
}

// A negative --audit-tail is a different mistake from an explicit 0, and reporting it as
// "=0" told an operator who typed -50 that the skip was their own choice.
func TestWriteDoctorAudit_NegativeTailIsReportedAsNegative(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	doctorWriteFile(t, logPath, `{"decision":"allow","target_type":"tool","target":"a","method":"tools/call"}`+"\n")

	var buf bytes.Buffer
	writeDoctorAudit(&buf, logPath, filepath.Join(dir, "k.key"), -50)
	out := buf.String()
	if !strings.Contains(out, "-50") {
		t.Errorf("the bundle must echo the negative value the operator passed:\n%s", out)
	}
	if strings.Contains(out, "--audit-tail=0") {
		t.Errorf("a negative tail must not be reported as an explicit 0:\n%s", out)
	}
}

func TestWriteDoctorAudit_ZeroTailKeepsItsOwnWording(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	doctorWriteFile(t, logPath, `{"decision":"allow","target_type":"tool","target":"a","method":"tools/call"}`+"\n")

	var buf bytes.Buffer
	writeDoctorAudit(&buf, logPath, filepath.Join(dir, "k.key"), 0)
	if !strings.Contains(buf.String(), "--audit-tail=0") {
		t.Errorf("an explicit 0 must still read as a deliberate skip:\n%s", buf.String())
	}
}
