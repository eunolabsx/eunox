// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// declassifyCaps builds a constraint that clears the named labels under approval.
func declassifyCaps(name string, labels ...string) []capability.Constraint {
	return []capability.Constraint{{
		Target:     "tool:" + name,
		Actions:    []string{"call"},
		Directives: []capability.Directive{capability.DeclassifyDirective{Labels: labels}},
	}}
}

// approvedReq is a request carrying one approval covering labels at tool:name.
func approvedReq(session, name, approver string, labels ...string) *capability.EnforceRequest {
	r := req(session, name)
	r.DeclassifyApprovals = []capability.DeclassifyApproval{{
		Labels:   labels,
		Target:   "tool:" + name,
		Approver: approver,
		ID:       "apr-1",
	}}
	return r
}

func declassifyEngine() *enforcement.Engine {
	return enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
	)
}

// TestDeclassify_ApprovedClearsTheLabel is the happy path: a session tainted by a source
// read reaches a sink that would deny, an approved declassification drops the label, and
// the same sink then allows. The clear is recorded on the allow with the approver.
func TestDeclassify_ApprovedClearsTheLabel(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()

	src := eng.ValidateAction(ctx, req("s", "read_customer"), sourceCaps("read_customer", capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, src.Decision)

	blocked := eng.ValidateAction(ctx, req("s", "publish"), sinkCaps("publish", capability.FlowLabelPublic))
	require.Equal(t, capability.DecisionDeny, blocked.Decision, "the sink denies while the session carries pii")

	cleared := eng.ValidateAction(ctx,
		approvedReq("s", "sanitize", "alice@example.com", capability.FlowLabelPII),
		declassifyCaps("sanitize", capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, cleared.Decision)
	assert.Equal(t, []string{capability.FlowLabelPII}, cleared.LabelsCleared)
	assert.Equal(t, "alice@example.com", cleared.Approver, "the approving human is on the decision")
	assert.Equal(t, "apr-1", cleared.ApprovalID)
	assert.Equal(t, []string{capability.FlowLabelPII}, cleared.CarriedLabels, "carried_labels reports the pre-call set")

	allowed := eng.ValidateAction(ctx, req("s", "publish"), sinkCaps("publish", capability.FlowLabelPublic))
	assert.Equal(t, capability.DecisionAllow, allowed.Decision, "the sink allows once the label is cleared")
}

// TestDeclassify_WithoutApprovalEscalates is the fail-closed core: with no approval the
// call is neither allowed-and-cleared nor allowed-without-clearing — it ESCALATES, and
// the session's labels are untouched.
func TestDeclassify_WithoutApprovalEscalates(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()

	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read_customer"), sourceCaps("read_customer", capability.FlowLabelPII)).Decision)

	resp := eng.ValidateAction(ctx, req("s", "sanitize"), declassifyCaps("sanitize", capability.FlowLabelPII))
	require.Equal(t, capability.DecisionEscalate, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeEscalationRequired, resp.Denial.Code)
	assert.Equal(t, capability.DirectiveTypeDeclassify, resp.Denial.ConditionType)
	assert.True(t, resp.Denial.HardDeny, "an unapproved declassification must not be downgradable by --audit")
	assert.False(t, resp.AuditOnly, "AuditOnly stays unset so an audit route cannot forward it")
	assert.Equal(t, true, resp.Denial.Details["flow"])
	assert.Equal(t, "no_approval", resp.Denial.Details["reason"])
	assert.Equal(t, []string{capability.FlowLabelPII}, resp.CarriedLabels)

	// The refused call left the session exactly as it found it.
	stillBlocked := eng.ValidateAction(ctx, req("s", "publish"), sinkCaps("publish", capability.FlowLabelPublic))
	assert.Equal(t, capability.DecisionDeny, stillBlocked.Decision, "a refused declassification clears nothing")
}

// TestDeclassify_ApprovalScopeIsEnforced walks the three ways a presented approval fails
// to cover the call. Each escalates rather than partially clearing.
func TestDeclassify_ApprovalScopeIsEnforced(t *testing.T) {
	cases := []struct {
		name     string
		approval capability.DeclassifyApproval
	}{
		{
			name:     "wrong target",
			approval: capability.DeclassifyApproval{Labels: []string{capability.FlowLabelPII}, Target: "tool:other", Approver: "a@b"},
		},
		{
			name: "does not cover every label the directive clears",
			approval: capability.DeclassifyApproval{
				Labels: []string{capability.FlowLabelPII}, Target: "tool:sanitize", Approver: "a@b",
			},
		},
		{
			name:     "no approver named",
			approval: capability.DeclassifyApproval{Labels: []string{capability.FlowLabelPII, capability.FlowLabelConfidential}, Target: "tool:sanitize"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := declassifyEngine()
			ctx := context.Background()
			require.Equal(t, capability.DecisionAllow,
				eng.ValidateAction(ctx, req("s", "read"), sourceCaps("read", capability.FlowLabelPII, capability.FlowLabelConfidential)).Decision)

			r := req("s", "sanitize")
			r.DeclassifyApprovals = []capability.DeclassifyApproval{tc.approval}
			resp := eng.ValidateAction(ctx, r,
				declassifyCaps("sanitize", capability.FlowLabelPII, capability.FlowLabelConfidential))

			require.Equal(t, capability.DecisionEscalate, resp.Decision)
			assert.Equal(t, 1, resp.Denial.Details["approvals_presented"],
				"the count distinguishes an unwired integration from a scoping mistake")
			assert.NotContains(t, resp.Denial.Message, "a@b", "the token's contents are not echoed back")
		})
	}
}

// TestDeclassify_NoOpClearRecordsNothing pins that an approved directive whose labels the
// session never carried is a permitted no-op that stamps NO approver: the tape must not
// claim a declassification that did not happen.
func TestDeclassify_NoOpClearRecordsNothing(t *testing.T) {
	eng := declassifyEngine()

	resp := eng.ValidateAction(context.Background(),
		approvedReq("s", "sanitize", "alice@example.com", capability.FlowLabelPII),
		declassifyCaps("sanitize", capability.FlowLabelPII))

	require.Equal(t, capability.DecisionAllow, resp.Decision)
	assert.Empty(t, resp.LabelsCleared, "nothing was carried, so nothing changed")
	assert.Empty(t, resp.Approver, "no approver is stamped for a clear that changed nothing")
	assert.Empty(t, resp.ApprovalID)
}

// TestDeclassify_FailsClosedWithoutSessionOrStore covers the two states in which the
// clear cannot be applied at all. Both escalate rather than forwarding a call whose
// declassification silently did not happen.
func TestDeclassify_FailsClosedWithoutSessionOrStore(t *testing.T) {
	t.Run("no flow store", func(t *testing.T) {
		eng := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
		resp := eng.ValidateAction(context.Background(),
			approvedReq("s", "sanitize", "a@b", capability.FlowLabelPII),
			declassifyCaps("sanitize", capability.FlowLabelPII))
		require.Equal(t, capability.DecisionEscalate, resp.Decision)
		assert.Equal(t, "no_store", resp.Denial.Details["reason"])
	})
	t.Run("no session", func(t *testing.T) {
		eng := declassifyEngine()
		r := approvedReq("", "sanitize", "a@b", capability.FlowLabelPII)
		resp := eng.ValidateAction(context.Background(), r, declassifyCaps("sanitize", capability.FlowLabelPII))
		require.Equal(t, capability.DecisionEscalate, resp.Decision)
		assert.Equal(t, "no_session", resp.Denial.Details["reason"])
	})
}

// TestDeclassify_ClearFaultHardDenies pins the record-fault posture: when the store
// cannot apply an approved clear, the call is HARD denied rather than forwarded with the
// taint still in place — the mirror of labelRecordFailureDenial's reasoning.
func TestDeclassify_ClearFaultHardDenies(t *testing.T) {
	store := &removeFailingStore{FlowLabelStore: flowlabelstore.NewInMemory()}
	eng := enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(store),
	)
	ctx := context.Background()

	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read"), sourceCaps("read", capability.FlowLabelPII)).Decision)

	store.fail = true
	resp := eng.ValidateAction(ctx,
		approvedReq("s", "sanitize", "a@b", capability.FlowLabelPII),
		declassifyCaps("sanitize", capability.FlowLabelPII))

	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.True(t, resp.Denial.HardDeny, "an unapplied clear must not be downgraded to a forward")
	assert.Equal(t, capability.DirectiveTypeDeclassify, resp.Denial.ConditionType)
	assert.Equal(t, "record", resp.Denial.Details["phase"])
}

// removeFailingStore fails Remove on demand so the clear-fault path is reachable.
type removeFailingStore struct {
	capability.FlowLabelStore
	fail bool
}

func (s *removeFailingStore) Remove(ctx context.Context, key string, labels ...string) error {
	if s.fail {
		return errors.New("backend unavailable")
	}
	return s.FlowLabelStore.Remove(ctx, key, labels...)
}

// TestDeclassify_CarriesNoResponseObligation pins that declassify, like labelOutput, is an
// enforce-time state directive: it emits no post-allow obligation, so nothing tries to
// apply it to the response and the unknown-obligation guard never fires.
func TestDeclassify_CarriesNoResponseObligation(t *testing.T) {
	eng := declassifyEngine()
	resp := eng.ValidateAction(context.Background(),
		approvedReq("s", "sanitize", "a@b", capability.FlowLabelPII),
		declassifyCaps("sanitize", capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, resp.Decision)
	assert.Empty(t, resp.Obligations)
}
