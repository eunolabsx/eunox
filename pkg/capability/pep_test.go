// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"strings"
	"testing"
)

// TestNewEnforcementPoint is the accept/refuse table for the operator-supplied half of the
// enforcement-point stamp. The value lands on a signed, append-only tape, so every refusal
// here is a value eunox would otherwise have had to sanitize — and a sanitized name is one
// the operator cannot join against whatever they configured elsewhere.
func TestNewEnforcementPoint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		id   string
		want EnforcementPoint // "" when the id must be refused
		why  string
	}{
		{name: "plain", id: "edge-1", want: "mcp:edge-1"},
		{name: "dotted", id: "gw.eu-west-1.acme", want: "mcp:gw.eu-west-1.acme"},
		{name: "underscored", id: "edge_1", want: "mcp:edge_1"},
		{name: "single char", id: "a", want: "mcp:a"},
		{name: "at the length limit", id: strings.Repeat("a", MaxEnforcementPointIDBytes), want: EnforcementPoint("mcp:" + strings.Repeat("a", MaxEnforcementPointIDBytes))},
		{name: "empty", id: "", why: "absence is spelled by omitting the setting, not by an empty name"},
		{name: "over the length limit", id: strings.Repeat("a", MaxEnforcementPointIDBytes+1), why: "it is stamped on every record, so it is a per-record cost"},
		{name: "carries the separator", id: "mcp:edge-1", why: "the two halves of the stamp must stay separable"},
		{name: "unexpanded env reference", id: "${EUNOX_PEP}", why: "an unset reference survives expansion as literal text and would name an enforcement point that does not exist"},
		{name: "leading space", id: " edge-1", why: "refused rather than trimmed: a repaired name is one the operator cannot join against"},
		{name: "inner space", id: "edge 1", why: "whitespace would have to be escaped by every consumer of the tape"},
		{name: "slash", id: "edge/1", why: "outside the accepted set"},
		{name: "quote", id: `edge"1`, why: "outside the accepted set"},
		{name: "newline", id: "edge\n1", why: "a record is one JSONL line"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := NewEnforcementPoint(tc.id)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("NewEnforcementPoint(%q) = %q, want an error (%s)", tc.id, got, tc.why)
				}
				if got != "" {
					t.Errorf("a refused name must yield no stamp, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewEnforcementPoint(%q): %v", tc.id, err)
			}
			if got != tc.want {
				t.Errorf("NewEnforcementPoint(%q) = %q, want %q", tc.id, got, tc.want)
			}
		})
	}
}

// TestEnforcementPoint_StringIsTheTapeValue: the audit sink stamps String() verbatim, so the
// zero value must render as the empty string the record's omitempty drops rather than as a
// binding with nothing behind it.
func TestEnforcementPoint_StringIsTheTapeValue(t *testing.T) {
	t.Parallel()
	if got := EnforcementPoint("").String(); got != "" {
		t.Errorf("zero EnforcementPoint renders %q, want \"\"", got)
	}
	ep, err := NewEnforcementPoint("edge-1")
	if err != nil {
		t.Fatalf("NewEnforcementPoint: %v", err)
	}
	if got, want := ep.String(), string(BindingMCP)+":edge-1"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
