// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestDeclassifyApproval_OnceRequiresAnID pins the one structural rule single-use adds. A
// single-use grant is burned by its id; with none there is nothing to burn, and both
// alternatives are wrong — treating it as standing gives the operator back the replay window
// they marked the grant to close, and burning by content makes two genuinely distinct
// approvals collide. So the token is refused.
func TestDeclassifyApproval_OnceRequiresAnID(t *testing.T) {
	a := capability.DeclassifyApproval{
		Labels:   []string{capability.FlowLabelPII},
		Target:   "tool:publish",
		Approver: "ada@example.com",
		Once:     true,
	}
	err := a.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'id'")

	a.ID = "apr-1"
	assert.NoError(t, a.Validate())
}

// TestParseDeclassifyApprovals_Once decodes the flag off a token exactly as an IdP emits it,
// and pins that a once-grant with no id rejects the TOKEN rather than degrading silently.
func TestParseDeclassifyApprovals_Once(t *testing.T) {
	got, err := capability.ParseDeclassifyApprovals(json.RawMessage(
		`[{"labels":["pii"],"target":"tool:publish","approver":"ada","id":"apr-1","once":true}]`))
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.True(t, got[0].Once)
	assert.NotEmpty(t, got[0].LedgerID())

	_, err = capability.ParseDeclassifyApprovals(json.RawMessage(
		`[{"labels":["pii"],"target":"tool:publish","approver":"ada","once":true}]`))
	assert.Error(t, err)
}

// TestDeclassifyApproval_LedgerIDScopesByTarget pins that one control-plane record minted per
// approved action burns per action: two grants sharing an id but naming different targets are
// two uses, not one.
func TestDeclassifyApproval_LedgerIDScopesByTarget(t *testing.T) {
	base := capability.DeclassifyApproval{
		Labels: []string{capability.FlowLabelPII}, Approver: "ada", ID: "apr-1", Once: true,
	}
	a, b := base, base
	a.Target, b.Target = "tool:publish", "tool:export"
	assert.NotEqual(t, a.LedgerID(), b.LedgerID())

	// A standing grant occupies no ledger slot at all.
	standing := a
	standing.Once = false
	assert.Empty(t, standing.LedgerID())
}

// TestCoveringDeclassifyApprovals_ReturnsEveryMatchInTokenOrder is what lets the engine pass
// over a spent grant for a live one: selecting first-covering and only then testing
// consumption would refuse a request the token was carrying a valid second approval for.
func TestCoveringDeclassifyApprovals_ReturnsEveryMatchInTokenOrder(t *testing.T) {
	approvals := []capability.DeclassifyApproval{
		{Labels: []string{capability.FlowLabelPII}, Target: "tool:publish", Approver: "ada", ID: "apr-1"},
		{Labels: []string{capability.FlowLabelPublic}, Target: "tool:publish", Approver: "bob", ID: "apr-2"},
		{Labels: []string{capability.FlowLabelPII}, Target: "tool:publish", Approver: "cy", ID: "apr-3"},
	}
	covering := capability.CoveringDeclassifyApprovals(approvals, "tool:publish", []string{capability.FlowLabelPII})
	require.Len(t, covering, 2)
	assert.Equal(t, "apr-1", covering[0].ID)
	assert.Equal(t, "apr-3", covering[1].ID)

	// A target no grant names covers nothing — an empty list rather than a nil-dereferencing
	// "first match".
	assert.Empty(t, capability.CoveringDeclassifyApprovals(approvals, "tool:other", []string{capability.FlowLabelPII}))
}

// TestCheckDeclassifyApprovalLifetime is the bound that makes `once` unconditional rather
// than "once per ledger window": a burn is remembered for DeclassifyLedgerWindowSec, so a
// token that outlives the window would present the same grant after the burn aged out and
// clear a second time. The token is refused instead.
func TestCheckDeclassifyApprovalLifetime(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	window := time.Duration(capability.DeclassifyLedgerWindowSec) * time.Second
	once := capability.DeclassifyApproval{
		Labels: []string{capability.FlowLabelPII}, Target: "tool:publish",
		Approver: "ada", ID: "apr-1", Once: true,
	}
	standing := once
	standing.Once = false

	cases := []struct {
		name      string
		approvals []capability.DeclassifyApproval
		exp       time.Time
		leeway    time.Duration
		wantErr   string
	}{
		{
			name:      "short-lived token carrying a once grant is admitted",
			approvals: []capability.DeclassifyApproval{once},
			exp:       now.Add(15 * time.Minute),
		},
		{
			name:      "a token exactly at the window is admitted",
			approvals: []capability.DeclassifyApproval{once},
			exp:       now.Add(window),
		},
		{
			name:      "a token past the window is refused",
			approvals: []capability.DeclassifyApproval{once},
			exp:       now.Add(window + time.Second),
			wantErr:   "longer than the",
		},
		{
			// The leeway the same validation accepted exp under counts against the window:
			// a token admitted at the edge of that grace must still be inside it.
			name:      "leeway counts against the window",
			approvals: []capability.DeclassifyApproval{once},
			exp:       now.Add(window),
			leeway:    time.Second,
			wantErr:   "longer than the",
		},
		{
			// A standing grant is replayable for the token's lifetime by design, so no
			// ledger memory has to outlive anything.
			name:      "a standing grant on a long-lived token is untouched",
			approvals: []capability.DeclassifyApproval{standing},
			exp:       now.Add(365 * 24 * time.Hour),
		},
		{
			name:      "no verified expiry cannot be inside any window",
			approvals: []capability.DeclassifyApproval{once},
			wantErr:   "no verified expiry",
		},
		{
			name: "no approvals at all is the overwhelmingly common case",
			exp:  now.Add(365 * 24 * time.Hour),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := capability.CheckDeclassifyApprovalLifetime(tc.approvals, tc.exp, now, tc.leeway)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			// The offending grant is named, so an operator fixes the approval rather than
			// hunting the whole claim.
			assert.Contains(t, err.Error(), "apr-1")
		})
	}
}

// TestDeclassifyLedgerWindow_OutlivesEveryAdmittedToken states the composition the two halves
// make, which neither states alone: the burn is written no earlier than the moment the token
// is presented, and the boundary admits no token whose remaining life exceeds the window, so
// the burn always outlives the token that could replay it.
func TestDeclassifyLedgerWindow_OutlivesEveryAdmittedToken(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	window := time.Duration(capability.DeclassifyLedgerWindowSec) * time.Second
	once := capability.DeclassifyApproval{
		Labels: []string{capability.FlowLabelPII}, Target: "tool:publish",
		Approver: "ada", ID: "apr-1", Once: true,
	}
	admitted := []time.Time{now.Add(time.Minute), now.Add(window / 2), now.Add(window)}
	for _, exp := range admitted {
		require.NoError(t, capability.CheckDeclassifyApprovalLifetime(
			[]capability.DeclassifyApproval{once}, exp, now, 0))
		// The burn happens no earlier than now (the token is being presented), so it is
		// remembered until at least now+window — never before exp.
		assert.False(t, now.Add(window).Before(exp),
			"an admitted token outlives the ledger memory of its own burn")
	}
}
