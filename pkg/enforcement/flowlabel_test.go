// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"context"
	"testing"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sourceCaps builds a source constraint that labels its output.
func sourceCaps(name string, labels ...string) []capability.Constraint {
	return []capability.Constraint{{
		Target:     "tool:" + name,
		Actions:    []string{"call"},
		Directives: []capability.Directive{capability.LabelOutputDirective{Labels: labels}},
	}}
}

// sinkCaps builds a sink constraint gated by a flowLabel subset check.
func sinkCaps(name string, allow ...string) []capability.Constraint {
	return []capability.Constraint{{
		Target:     "tool:" + name,
		Actions:    []string{"call"},
		Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: allow}},
	}}
}

func req(session, name string) *capability.EnforceRequest {
	return &capability.EnforceRequest{
		SessionID: session,
		ToolName:  name,
		Target:    &capability.EnforceRequestTarget{Type: "tool", Name: name},
	}
}

// TestFlowLabel_SourceToSinkDeny is coverage (a): a labeled source read flows
// into the session, then a sink whose allow-set excludes that label denies — and the
// denial is distinguishable from a capability denial (flowLabel conditionType + a
// "flow" detail + the offending label), the property the demo's contrast leg needs.
func TestFlowLabel_SourceToSinkDeny(t *testing.T) {
	eng := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()), enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()))
	ctx := context.Background()

	src := eng.ValidateAction(ctx, req("s", "read_secret"), sourceCaps("read_secret", capability.FlowLabelConfidential))
	require.Equal(t, capability.DecisionAllow, src.Decision)
	assert.Equal(t, []string{capability.FlowLabelConfidential}, src.LabelsOut, "the source read labels its output")
	assert.Empty(t, src.CarriedLabels, "nothing had flowed in before the source read")

	sink := eng.ValidateAction(ctx, req("s", "send_email"),
		sinkCaps("send_email", capability.FlowLabelPublic, capability.FlowLabelInternal))
	require.Equal(t, capability.DecisionDeny, sink.Decision)
	require.NotNil(t, sink.Denial)
	assert.Equal(t, capability.ConditionTypeFlowLabel, sink.Denial.ConditionType)
	assert.Equal(t, capability.ErrCodeConditionFailed, sink.Denial.Code)
	assert.Equal(t, true, sink.Denial.Details["flow"], "a flow denial is tagged flow=true, distinct from a capability denial")
	assert.Equal(t, capability.FlowLabelConfidential, sink.Denial.Details["blockedLabel"])

	// Contrast: a capability denial (no matching constraint) is a different code with no
	// flow tag — the audit tape can tell the two apart.
	capDeny := eng.ValidateAction(ctx, req("s", "unknown_tool"), sinkCaps("send_email"))
	require.Equal(t, capability.DecisionDeny, capDeny.Decision)
	assert.Equal(t, capability.ErrCodeAuthorizationFailed, capDeny.Denial.Code)
}

// TestFlowLabel_CleanContextAllows is coverage (b): the identical sink call in a
// session with no accumulated labels is allowed. This is the demo's within-scope
// contrast leg — the same egress that a tainted session blocks succeeds when clean.
func TestFlowLabel_CleanContextAllows(t *testing.T) {
	eng := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()), enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()))
	ctx := context.Background()

	resp := eng.ValidateAction(ctx, req("clean", "send_email"),
		sinkCaps("send_email", capability.FlowLabelPublic, capability.FlowLabelInternal))
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
	assert.Empty(t, resp.CarriedLabels, "a clean session carries no labels")
}

// TestFlowLabel_FailsClosedOnUnreadableState is coverage (c): flow state that
// cannot be read denies. Two ways it is unreadable — no flow-label store backend, and no
// session id (which would merge state across callers) — and a labelOutput source that
// cannot persist its label also fails closed rather than silently letting a later sink Get empty.
func TestFlowLabel_FailsClosedOnUnreadableState(t *testing.T) {
	ctx := context.Background()

	// No store: a flowLabel sink cannot read state -> deny.
	noStore := enforcement.New()
	sink := noStore.ValidateAction(ctx, req("s", "send_email"), sinkCaps("send_email", capability.FlowLabelPublic))
	require.Equal(t, capability.DecisionDeny, sink.Decision)
	assert.Equal(t, capability.ConditionTypeFlowLabel, sink.Denial.ConditionType)

	// No session: state would merge across anonymous callers -> deny (MISSING_CONTEXT). The
	// store is wired so the empty-session guard (not the missing-store guard) is what fires.
	withStore := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()), enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()))
	noSession := &capability.EnforceRequest{ToolName: "send_email", Target: &capability.EnforceRequestTarget{Type: "tool", Name: "send_email"}}
	sink = withStore.ValidateAction(ctx, noSession, sinkCaps("send_email", capability.FlowLabelPublic))
	require.Equal(t, capability.DecisionDeny, sink.Decision)
	assert.Equal(t, capability.ErrCodeMissingContext, sink.Denial.Code)

	// A labelOutput source that cannot persist its label (no store) fails closed with a
	// record-phase flowLabel deny, so the source->sink guarantee is never silently dropped.
	src := noStore.ValidateAction(ctx, req("s", "read_secret"), sourceCaps("read_secret", capability.FlowLabelConfidential))
	require.Equal(t, capability.DecisionDeny, src.Decision)
	assert.Equal(t, capability.ConditionTypeFlowLabel, src.Denial.ConditionType)
	assert.Equal(t, "record", src.Denial.Details["phase"])
}

// TestFlowLabel_MultiSourceUnion is coverage (d): labels from several sources
// accumulate as a set-union, and a sink denies on ANY accumulated label outside its
// allow-set. It also checks the accumulated set surfaces on an allowed sink as
// carried_labels, in the fixed vocabulary order.
func TestFlowLabel_MultiSourceUnion(t *testing.T) {
	eng := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()), enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()))
	ctx := context.Background()

	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read_a"), sourceCaps("read_a", capability.FlowLabelInternal)).Decision)
	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read_b"), sourceCaps("read_b", capability.FlowLabelPII)).Decision)

	// A sink allowing public+internal denies on the pii member of the union.
	deny := eng.ValidateAction(ctx, req("s", "send_email"),
		sinkCaps("send_email", capability.FlowLabelPublic, capability.FlowLabelInternal))
	require.Equal(t, capability.DecisionDeny, deny.Decision)
	assert.Equal(t, capability.FlowLabelPII, deny.Denial.Details["blockedLabel"])

	// A sink permitting both members allows, and reports the accumulated set (vocabulary
	// order: internal before pii) as carried_labels.
	allow := eng.ValidateAction(ctx, req("s", "archive"),
		sinkCaps("archive", capability.FlowLabelPublic, capability.FlowLabelInternal, capability.FlowLabelConfidential, capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, allow.Decision)
	assert.Equal(t, []string{capability.FlowLabelInternal, capability.FlowLabelPII}, allow.CarriedLabels)
}

// TestFlowLabel_IntegrityDual: an untrusted-class label on the control path blocks an
// otherwise-permitted action regardless of held capability — expressed as a deny (a
// distinct escalate outcome is not part of this grammar). The destructive sink permits
// every class but untrusted; a session touched by untrusted input is denied.
func TestFlowLabel_IntegrityDual(t *testing.T) {
	eng := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()), enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()))
	ctx := context.Background()

	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read_webpage"), sourceCaps("read_webpage", capability.FlowLabelUntrusted)).Decision)

	deny := eng.ValidateAction(ctx, req("s", "delete_records"),
		sinkCaps("delete_records", capability.FlowLabelPublic, capability.FlowLabelInternal, capability.FlowLabelConfidential, capability.FlowLabelPII))
	require.Equal(t, capability.DecisionDeny, deny.Decision)
	assert.Equal(t, capability.ConditionTypeFlowLabel, deny.Denial.ConditionType)
	assert.Equal(t, capability.FlowLabelUntrusted, deny.Denial.Details["blockedLabel"])

	// The same destructive action in a clean session is permitted — the deny is driven by
	// the flow, not the held capability.
	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("clean", "delete_records"),
			sinkCaps("delete_records", capability.FlowLabelPublic, capability.FlowLabelInternal, capability.FlowLabelConfidential, capability.FlowLabelPII)).Decision)
}

// TestFlowLabel_LabelsOutCanonicalOrder: labels_out is reported in the fixed vocabulary
// order and de-duplicated, regardless of the order the directive declared them, so the
// audit field is deterministic.
func TestFlowLabel_LabelsOutCanonicalOrder(t *testing.T) {
	eng := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()), enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()))
	ctx := context.Background()

	// Declared out of vocabulary order and with a duplicate.
	resp := eng.ValidateAction(ctx, req("s", "read_multi"),
		sourceCaps("read_multi", capability.FlowLabelPII, capability.FlowLabelConfidential, capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, resp.Decision)
	assert.Equal(t, []string{capability.FlowLabelConfidential, capability.FlowLabelPII}, resp.LabelsOut)
}

// TestFlowLabel_DenyReportsAllBlockedLabels: a sink deny names EVERY offending class,
// not only the first in vocabulary order, so an integrity (untrusted) signal is never
// masked; and carried_labels is stamped on the deny response too, so the tape / an
// observe-mode forward can reconstruct the accumulated set.
func TestFlowLabel_DenyReportsAllBlockedLabels(t *testing.T) {
	eng := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()), enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()))
	ctx := context.Background()

	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read_web"), sourceCaps("read_web", capability.FlowLabelUntrusted)).Decision)
	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read_pii"), sourceCaps("read_pii", capability.FlowLabelPII)).Decision)

	deny := eng.ValidateAction(ctx, req("s", "send_email"), sinkCaps("send_email", capability.FlowLabelPublic))
	require.Equal(t, capability.DecisionDeny, deny.Decision)
	blocked, _ := deny.Denial.Details["blockedLabels"].([]string)
	assert.ElementsMatch(t, []string{capability.FlowLabelPII, capability.FlowLabelUntrusted}, blocked,
		"the deny must name every blocked class, including the untrusted integrity signal")
	assert.Equal(t, []string{capability.FlowLabelPII, capability.FlowLabelUntrusted}, deny.CarriedLabels,
		"carried_labels is stamped on a flow-relevant deny for tape reconstruction")
}

// TestFlowLabel_NonFlowConstraintCarriesNoLabels: a plain constraint (no flowLabel, no
// labelOutput) reports neither label field, so a non-flow policy pays no label cost and
// the audit record stays lean.
func TestFlowLabel_NonFlowConstraintCarriesNoLabels(t *testing.T) {
	eng := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()), enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()))
	ctx := context.Background()

	resp := eng.ValidateAction(ctx, req("s", "plain"),
		[]capability.Constraint{{Target: "tool:plain", Actions: []string{"call"}}})
	require.Equal(t, capability.DecisionAllow, resp.Decision)
	assert.Nil(t, resp.LabelsOut)
	assert.Nil(t, resp.CarriedLabels)
}
