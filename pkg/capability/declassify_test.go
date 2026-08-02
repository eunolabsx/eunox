// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// TestDeclassifyDirective_RoundTrip pins that the directive marshals with its
// discriminator and decodes back, and that a misspelled key is REJECTED rather than
// decoding to an empty label list. The latter is the load-bearing half: an empty list
// would mean a directive that clears nothing while still demanding an approval, i.e. a
// capability no caller could ever satisfy, arrived at by a typo.
func TestDeclassifyDirective_RoundTrip(t *testing.T) {
	t.Parallel()
	d := capability.DeclassifyDirective{Labels: []string{capability.FlowLabelPII}}
	b, err := json.Marshal(capability.DirectiveWrapper{Directive: d})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"type":"declassify"`) {
		t.Fatalf("marshaled directive lost its discriminator: %s", b)
	}

	var back capability.DirectiveWrapper
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, ok := capability.AsValueOrPointer[capability.DeclassifyDirective](back.Directive)
	if !ok || got == nil {
		t.Fatalf("round-trip produced %T, want a declassify directive", back.Directive)
	}
	if len(got.Labels) != 1 || got.Labels[0] != capability.FlowLabelPII {
		t.Fatalf("labels = %v, want [pii]", got.Labels)
	}
	if got.ToObligation().Type != capability.DirectiveTypeDeclassify {
		t.Fatalf("obligation type = %q", got.ToObligation().Type)
	}

	var bad capability.DirectiveWrapper
	err = json.Unmarshal([]byte(`{"type":"declassify","lables":["pii"]}`), &bad)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("a misspelled key must be rejected, got %v", err)
	}
}

// TestParseDeclassifyApprovals covers the claim decode: what a control plane may mint,
// and every malformed shape that must reject the TOKEN rather than evaluate to a grant
// that silently covers nothing.
func TestParseDeclassifyApprovals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		raw     string // JSON for the mcp.declassify claim value
		wantN   int
		wantErr string
	}{
		{
			name:  "one well-formed grant",
			raw:   `[{"labels":["pii"],"target":"tool:sanitize","approver":"alice@example.com","id":"apr-1"}]`,
			wantN: 1,
		},
		{
			name:  "several grants",
			raw:   `[{"labels":["pii"],"target":"tool:a","approver":"x"},{"labels":["confidential"],"target":"resource:b","approver":"y"}]`,
			wantN: 2,
		},
		{
			name:  "explicitly empty is a token that grants nothing",
			raw:   `[]`,
			wantN: 0,
		},
		{
			name:    "not an array",
			raw:     `{"labels":["pii"]}`,
			wantErr: "must be an array",
		},
		{
			name:    "unknown label",
			raw:     `[{"labels":["secret"],"target":"tool:a","approver":"x"}]`,
			wantErr: "unknown flow label",
		},
		{
			name:    "no labels",
			raw:     `[{"labels":[],"target":"tool:a","approver":"x"}]`,
			wantErr: "at least one label",
		},
		{
			name:    "no target",
			raw:     `[{"labels":["pii"],"approver":"x"}]`,
			wantErr: "must name the action it covers",
		},
		{
			// The load-bearing one: a glob in an approval target fails OPEN — it widens a
			// single human approval across every matching action.
			name:    "glob target",
			raw:     `[{"labels":["pii"],"target":"tool:*","approver":"x"}]`,
			wantErr: "glob metacharacter",
		},
		{
			name:    "unnamespaced target",
			raw:     `[{"labels":["pii"],"target":"sanitize","approver":"x"}]`,
			wantErr: "namespace prefix",
		},
		{
			name:    "no approver",
			raw:     `[{"labels":["pii"],"target":"tool:a"}]`,
			wantErr: "must name the human who approved",
		},
		{
			name:    "blank approver",
			raw:     `[{"labels":["pii"],"target":"tool:a","approver":"   "}]`,
			wantErr: "must name the human who approved",
		},
		{
			name:    "misspelled field",
			raw:     `[{"lables":["pii"],"target":"tool:a","approver":"x"}]`,
			wantErr: "unknown field",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := capability.ParseDeclassifyApprovals(json.RawMessage(tc.raw))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				if got != nil {
					t.Fatalf("a rejected claim must yield no approvals, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tc.wantN {
				t.Fatalf("got %d approvals, want %d", len(got), tc.wantN)
			}
		})
	}

	// The absent-claim fast path, in both spellings an IdP produces. A nil json.RawMessage
	// is what an omitted claim decodes to; an explicit JSON null is what a template that
	// always emits the key produces. Neither is an error and neither grants anything.
	for _, absent := range []json.RawMessage{nil, json.RawMessage("null")} {
		if got, err := capability.ParseDeclassifyApprovals(absent); got != nil || err != nil {
			t.Fatalf("an absent claim is not an error: got %v, %v", got, err)
		}
	}
}

// TestDeclassifyApproval_Covers is the authorization test itself: exact target, and a
// label set that must be a SUPERSET of what the directive clears.
func TestDeclassifyApproval_Covers(t *testing.T) {
	t.Parallel()
	full := capability.DeclassifyApproval{
		Labels:   []string{capability.FlowLabelPII, capability.FlowLabelConfidential},
		Target:   "tool:sanitize",
		Approver: "alice",
	}
	cases := []struct {
		name   string
		a      *capability.DeclassifyApproval
		target string
		want   []string
		ok     bool
	}{
		{"exact single", &full, "tool:sanitize", []string{capability.FlowLabelPII}, true},
		{"superset covers both", &full, "tool:sanitize", []string{capability.FlowLabelPII, capability.FlowLabelConfidential}, true},
		{"different target", &full, "tool:other", []string{capability.FlowLabelPII}, false},
		{"label outside the grant", &full, "tool:sanitize", []string{capability.FlowLabelUntrusted}, false},
		{"nothing wanted covers nothing", &full, "tool:sanitize", nil, false},
		{"nil approval", nil, "tool:sanitize", []string{capability.FlowLabelPII}, false},
		{
			"approver-less grant is inert even if constructed directly",
			&capability.DeclassifyApproval{Labels: []string{capability.FlowLabelPII}, Target: "tool:sanitize"},
			"tool:sanitize", []string{capability.FlowLabelPII}, false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.a.Covers(tc.target, tc.want); got != tc.ok {
				t.Fatalf("Covers = %v, want %v", got, tc.ok)
			}
		})
	}
}

// TestDeclassifyLabelsOf reports a constraint's cleared set in canonical vocabulary
// order, and is nil-safe against a typed-nil directive.
func TestDeclassifyLabelsOf(t *testing.T) {
	t.Parallel()
	c := &capability.Constraint{Directives: []capability.Directive{
		(*capability.DeclassifyDirective)(nil),
		capability.DeclassifyDirective{Labels: []string{capability.FlowLabelPII, capability.FlowLabelInternal}},
	}}
	got := capability.DeclassifyLabelsOf(c)
	want := []string{capability.FlowLabelInternal, capability.FlowLabelPII} // vocabulary order
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("labels = %v, want %v (canonical vocabulary order)", got, want)
	}
	if capability.DeclassifyLabelsOf(nil) != nil {
		t.Fatal("a nil constraint clears nothing")
	}
	if capability.DeclassifyLabelsOf(&capability.Constraint{}) != nil {
		t.Fatal("a constraint with no declassify directive clears nothing")
	}
}

// TestConstraintHasFlow_IncludesDeclassify pins that a declassify-only constraint counts
// as flow-relevant: without it the engine would skip the pre-call label peek the clear is
// computed against, and the audit record's carried_labels would be empty.
func TestConstraintHasFlow_IncludesDeclassify(t *testing.T) {
	t.Parallel()
	c := &capability.Constraint{Directives: []capability.Directive{
		capability.DeclassifyDirective{Labels: []string{capability.FlowLabelPII}},
	}}
	if !capability.ConstraintHasFlow(c) {
		t.Fatal("a declassify constraint participates in information-flow control")
	}
}
