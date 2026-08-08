// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// newFlowManifestPDP builds a ManifestPDP whose engine carries an in-memory
// FlowLabelStore, so a source read records session taint that a later sink reads.
// A nil call counter is fine: with no sequenceBlock in the policy recordSessionCall
// self-guards on the nil counter, so the flow (labelOutput/flowLabel) path is exercised
// in isolation.
func newFlowManifestPDP(caps ...capability.Constraint) *ManifestPDP {
	eng := enforcement.New(enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()))
	return NewManifestPDP(caps, eng, killswitch.NewInMemory())
}

// TestFlowHardening_PrincipalScopedSiblingKeepsTaint is the constraint-shadowing
// regression: when a more-specific, principal-scoped
// source entry that declares NO labelOutput wins findConstraint selection over a general
// entry that HAS labelOutput, the source read must still record the general entry's taint
// (the labelOutput union across every matching entry), so a later sink in the same session
// denies. Before the union fix the winning sibling shadowed the labelOutput, the taint was
// silently dropped, and the sink failed OPEN.
func TestFlowHardening_PrincipalScopedSiblingKeepsTaint(t *testing.T) {
	t.Parallel()

	// A general read_file source labels its output confidential. A principal-scoped sibling
	// for the admin agent permits the same read but declares NO labelOutput and, being
	// principal-scoped, outranks the general entry in selection at equal specificity. A
	// send_email sink tolerates only public/internal.
	caps := []capability.Constraint{
		{
			Target:     "tool:read_file",
			Actions:    []string{"call"},
			Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelConfidential}}},
		},
		{
			Target:    "tool:read_file",
			Actions:   []string{"call"},
			Principal: map[string][]string{"agent_id": {"admin-bot"}},
		},
		{
			Target:     "tool:send_email",
			Actions:    []string{"call"},
			Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic, capability.FlowLabelInternal}}},
		},
	}
	p := newFlowManifestPDP(caps...)
	ctx := ctxWithAgent("admin-bot")

	// The admin agent's read_file selects the principal-scoped sibling (no labelOutput),
	// yet the union still records the general entry's confidential taint.
	src := callTool(p, ctx, "read_file", nil)
	require.Equal(t, capability.DecisionAllow, src.Decision)
	require.Equal(t, []string{capability.FlowLabelConfidential}, src.LabelsOut,
		"the source read must carry the general entry's taint though a labelOutput-less sibling won selection")

	// The sink now observes confidential and denies (fail closed) — the taint was not
	// dropped by the shadowing sibling.
	sink := callTool(p, ctx, "send_email", nil)
	require.Equal(t, capability.DecisionDeny, sink.Decision,
		"the sink must deny: the winning sibling must not have dropped the confidential taint")
	require.NotNil(t, sink.Denial)
	assert.Equal(t, capability.ConditionTypeFlowLabel, sink.Denial.ConditionType)
	assert.Equal(t, capability.FlowLabelConfidential, sink.Denial.Details["blockedLabel"])
}

// TestFlowHardening_NonPrincipalCallerStillTaints is the companion to the shadowing
// regression: a caller who does NOT satisfy the principal-scoped sibling selects the
// general entry directly (the ordinary path, no union needed), so the confidential taint
// is recorded and the sink denies. It pins that the fix does not silently disable the
// baseline labelOutput path, and that the union is scoped by principal — the sibling's
// missing label only unions in for a caller the sibling actually matches.
func TestFlowHardening_NonPrincipalCallerStillTaints(t *testing.T) {
	t.Parallel()

	caps := []capability.Constraint{
		{
			Target:     "tool:read_file",
			Actions:    []string{"call"},
			Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelConfidential}}},
		},
		{
			Target:    "tool:read_file",
			Actions:   []string{"call"},
			Principal: map[string][]string{"agent_id": {"admin-bot"}},
		},
		{
			Target:     "tool:send_email",
			Actions:    []string{"call"},
			Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic, capability.FlowLabelInternal}}},
		},
	}
	p := newFlowManifestPDP(caps...)
	// A different agent: the principal-scoped sibling does not match, so the general
	// labelOutput entry wins directly.
	ctx := ctxWithAgent("other-bot")

	src := callTool(p, ctx, "read_file", nil)
	require.Equal(t, capability.DecisionAllow, src.Decision)
	require.Equal(t, []string{capability.FlowLabelConfidential}, src.LabelsOut)

	sink := callTool(p, ctx, "send_email", nil)
	require.Equal(t, capability.DecisionDeny, sink.Decision)
	require.NotNil(t, sink.Denial)
	assert.Equal(t, capability.FlowLabelConfidential, sink.Denial.Details["blockedLabel"])
}

// faultingGetStore is a FlowLabelStore whose Get always errors, standing in for a backend
// fault (e.g. a Redis outage) on the read path. Add/Remove/Clear succeed so the test drives
// exactly the peek-fault branch.
type faultingGetStore struct{}

func (faultingGetStore) Add(_ context.Context, _ string, _ ...string) error    { return nil }
func (faultingGetStore) Remove(_ context.Context, _ string, _ ...string) error { return nil }
func (faultingGetStore) Clear(_ context.Context, _ string) error               { return nil }
func (faultingGetStore) Get(_ context.Context, _ string) ([]string, error) {
	return nil, errors.New("flow store backend unavailable")
}

// TestFlowHardening_AuditModePeekFailsClosed is the audit-mode peek fail-closed regression:
// when an audit-mode source read's deny is being downgraded
// to a forwarded observe-allow, recordAuditModeAntecedent peeks the carried label set to
// stamp the record AND to hand RecordSourceCall a correct rollback baseline. If that peek
// faults the carried set is unknown, so the antecedent path must HARD-deny (non-downgradable
// even under audit) rather than forward the read with unreliable flow state — a swallowed
// error would let a paired seq-write fault roll back a PRIOR source's label (a fail-open).
func TestFlowHardening_AuditModePeekFailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	engine := enforcement.New(enforcement.WithFlowLabelStore(faultingGetStore{}))

	// A flow-relevant (labelOutput) source constraint in audit mode: its deny is
	// downgradable, so the antecedent path runs and must peek the carried set.
	src := &capability.Constraint{
		Target:      "tool:read_secret",
		Actions:     []string{"call"},
		Enforcement: capability.EnforcementAudit,
		Directives:  []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelConfidential}}},
	}
	req := &capability.EnforceRequest{SessionID: "s", TargetName: "read_secret"}
	// A downgradable deny with no carried labels stamped yet (the structural early-return
	// shape), so recordAuditModeAntecedent must do the pre-write peek — which faults.
	resp := &capability.EnforceResponse{Decision: capability.DecisionDeny}
	override := recordAuditModeAntecedent(ctx, engine, engine.Clock(), req, src, resp)

	require.NotNil(t, override, "a peek fault must hard-deny, not forward with unreliable flow state")
	require.NotNil(t, override.Denial)
	assert.Equal(t, capability.ErrCodeEnforcementError, override.Denial.Code,
		"a store fault is not a policy verdict; the tape has to separate the two, and this is the code an observing route never downgrades")
	assert.True(t, override.Denial.HardDeny, "the peek-fault deny must be non-downgradable even under audit")
	assert.Contains(t, override.Denial.Message, "audit-mode flow-label peek failed")
}
