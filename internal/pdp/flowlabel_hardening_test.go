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
	override := recordAuditModeAntecedent(ctx, engine, engine.Clock(), req, src, true, resp)

	require.NotNil(t, override, "a peek fault must hard-deny, not forward with unreliable flow state")
	require.NotNil(t, override.Denial)
	assert.Equal(t, capability.ErrCodeEnforcementError, override.Denial.Code,
		"a store fault is not a policy verdict; the tape has to separate the two, and this is the code an observing route never downgrades")
	assert.True(t, override.Denial.BlockOverride, "the peek-fault deny must be non-downgradable even under audit")
	assert.Contains(t, override.Denial.Message, "audit-mode flow-label peek failed")
}

// TestFlowHardening_ForwardedNoMatchCommitsTaint is the no-match counterpart of the
// principal-scoped-miss leak the redaction fill closes. A source entry scoped to ANOTHER
// principal is skipped by findConstraint, so the call takes the no-match deny — which a
// route running --audit FORWARDS, and the tool actually runs, producing exactly the data the
// manifest declares confidential. With no taint committed for it, a later ENFORCED flowLabel
// sink on the same session Peeked an empty set and failed OPEN.
func TestFlowHardening_ForwardedNoMatchCommitsTaint(t *testing.T) {
	t.Parallel()

	caps := []capability.Constraint{
		{
			Target:     "tool:read_secret",
			Actions:    []string{"call"},
			Principal:  map[string][]string{"agent_id": {"admin-bot"}},
			Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelConfidential}}},
		},
		{
			Target:     "tool:send_email",
			Actions:    []string{"call"},
			Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic, capability.FlowLabelInternal}}},
		},
	}
	p := newFlowManifestPDP(caps...)
	enforced := ctxWithAgent("other-bot")
	observed := enforcement.WithSkipQuota(enforced)

	src := callTool(p, observed, "read_secret", nil)
	require.Equal(t, capability.DecisionDeny, src.Decision)
	require.NotNil(t, src.Denial)
	require.Equal(t, capability.ErrCodeAuthorizationFailed, src.Denial.Code)
	require.True(t, src.Denial.Downgradable(), "the no-match deny must still be the forwarded one this test is about")
	assert.Equal(t, []string{capability.FlowLabelConfidential}, src.LabelsOut,
		"the forwarded read produced confidential data, so the tape must say so")

	// The sink runs ENFORCED: the whole point is that an observe route beside an enforce
	// route cannot launder taint through a no-match forward.
	sink := callTool(p, enforced, "send_email", nil)
	require.Equal(t, capability.DecisionDeny, sink.Decision)
	require.NotNil(t, sink.Denial)
	assert.Equal(t, capability.FlowLabelConfidential, sink.Denial.Details["blockedLabel"])
}

// TestFlowHardening_ForwardedNoMatchTaintMintsNoAntecedentKeys pins the bound the two halves
// of that commit are gated by separately. The flow write is keyed on the state anchor, so
// any name may commit taint; the sequenceBlock antecedent is keyed on the TARGET NAME, and
// this branch is the one place that name is not bounded by the manifest — recording every
// unlisted name lets a caller on an observe route mint one counter key per made-up target
// until the counter caps and the record starts hard-denying an observe route outright.
func TestFlowHardening_ForwardedNoMatchTaintMintsNoAntecedentKeys(t *testing.T) {
	t.Parallel()

	counter := newCountingCallCounter()
	eng := enforcement.New(
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
		enforcement.WithCallCounter(counter),
	)
	// A principal-scoped wildcard source (so nothing matches this caller and every call takes
	// the no-match branch) beside a sequenceBlock naming exactly one antecedent.
	p := NewManifestPDP([]capability.Constraint{
		{
			Target:     "tool:*",
			Actions:    []string{"call"},
			Principal:  map[string][]string{"agent_id": {"admin-bot"}},
			Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelConfidential}}},
		},
		{
			Target:     "tool:sink",
			Actions:    []string{"call"},
			Conditions: []capability.Condition{capability.SequenceBlockCondition{AfterTools: []string{"known"}}},
		},
	}, eng, killswitch.NewInMemory())
	observed := enforcement.WithSkipQuota(ctxWithAgent("other-bot"))

	madeUp := callTool(p, observed, "made_up_"+t.Name(), nil)
	require.Equal(t, capability.DecisionDeny, madeUp.Decision)
	assert.Equal(t, []string{capability.FlowLabelConfidential}, madeUp.LabelsOut,
		"a forwarded call the manifest declares a source must commit its taint whatever its name")
	assert.Zero(t, counter.writes(),
		"an unqueryable name must mint no antecedent key; the taint commit must not smuggle one in")

	// The queryable name still records, so the split gate did not disable the antecedent
	// half it was factored out of.
	known := callTool(p, observed, "known", nil)
	require.Equal(t, capability.DecisionDeny, known.Decision)
	assert.NotZero(t, counter.writes(), "a name some sequenceBlock queries must still record its antecedent")
}

// TestFlowHardening_BroadSiblingCannotShadowAPrincipalScopedSource is the ALLOW-path
// counterpart of the no-match leak above, and the wider of the two. A source entry scoped to
// one principal declares the target confidential; a broad `tool:*` sibling with no
// labelOutput is what actually grants the call to everyone else. Selecting that sibling used
// to drop the taint entirely — the call was ALLOWED on an enforce route with no labels, and
// the later sink allowed too. labelOutput describes the DATA a target produces, and the
// target produces the same data whoever calls it.
func TestFlowHardening_BroadSiblingCannotShadowAPrincipalScopedSource(t *testing.T) {
	t.Parallel()

	caps := []capability.Constraint{
		{
			Target:     "tool:read_secret",
			Actions:    []string{"call"},
			Principal:  map[string][]string{"agent_id": {"admin-bot"}},
			Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelConfidential}}},
		},
		// The entry that actually selects for every other principal, declaring no taint.
		{Target: "tool:*", Actions: []string{"call"}},
		{
			Target:     "tool:send_email",
			Actions:    []string{"call"},
			Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic}}},
		},
	}
	p := newFlowManifestPDP(caps...)
	ctx := ctxWithAgent("other-bot")

	src := callTool(p, ctx, "read_secret", nil)
	require.Equal(t, capability.DecisionAllow, src.Decision, "the broad sibling still grants the call")
	assert.Equal(t, []string{capability.FlowLabelConfidential}, src.LabelsOut,
		"the taint of a target the manifest declares confidential must not turn on who called it")

	sink := callTool(p, ctx, "send_email", nil)
	require.Equal(t, capability.DecisionDeny, sink.Decision)
	require.NotNil(t, sink.Denial)
	assert.Equal(t, capability.FlowLabelConfidential, sink.Denial.Details["blockedLabel"])
}
