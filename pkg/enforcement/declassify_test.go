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
//
// It also pins the ORDERING that makes the clear safe: the decision only AUTHORIZES the
// clear, and the sink is still blocked until the caller commits it. See
// TestDeclassify_PendingClearIsInvisibleUntilCommitted for why that matters.
func TestDeclassify_ApprovedClearsTheLabel(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()

	src := eng.ValidateAction(ctx, req("s", "read_customer"), sourceCaps("read_customer", capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, src.Decision)

	blocked := eng.ValidateAction(ctx, req("s", "publish"), sinkCaps("publish", capability.FlowLabelPublic))
	require.Equal(t, capability.DecisionDeny, blocked.Decision, "the sink denies while the session carries pii")

	sanitizeReq := approvedReq("s", "sanitize", "alice@example.com", capability.FlowLabelPII)
	cleared := eng.ValidateAction(ctx, sanitizeReq, declassifyCaps("sanitize", capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, cleared.Decision)
	assert.Equal(t, []string{capability.FlowLabelPII}, cleared.LabelsPendingClear)
	assert.Equal(t, "alice@example.com", cleared.Approver, "the approving human is on the decision")
	assert.Equal(t, "apr-1", cleared.ApprovalID)
	assert.Equal(t, []string{capability.FlowLabelPII}, cleared.CarriedLabels, "carried_labels reports the pre-call set")

	committed, err := eng.CommitDeclassification(ctx, sanitizeReq, cleared.LabelsPendingClear)
	require.NoError(t, err)
	assert.Equal(t, []string{capability.FlowLabelPII}, committed, "the commit reports what it changed")

	allowed := eng.ValidateAction(ctx, req("s", "publish"), sinkCaps("publish", capability.FlowLabelPublic))
	assert.Equal(t, capability.DecisionAllow, allowed.Decision, "the sink allows once the label is cleared")
}

// TestDeclassify_PendingClearIsInvisibleUntilCommitted is the concurrency property the
// two-phase clear exists for, and it is the whole reason the clear does not happen inside
// the decision.
//
// The transport releases the per-session decision lock immediately after the PDP decision,
// deliberately, so the slow upstream forward is not held under it. A clear applied inside
// the decision therefore became visible to every concurrent decision for the WHOLE upstream
// round trip — bounded only by --upstream-timeout, and by nothing at all when that is 0 —
// so a sink the taint existed to stop could be allowed and forwarded while the sanitizing
// call was still in flight. No compensating undo could close that: the undo ran after the
// round trip, i.e. after the window it was meant to cover.
//
// Deferring the clear removes the window instead of narrowing it, and does so without
// depending on any lock — which matters most under task-anchored state, where the lock is
// per-session and does not span a task key two sessions share.
func TestDeclassify_PendingClearIsInvisibleUntilCommitted(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()

	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read_customer"), sourceCaps("read_customer", capability.FlowLabelPII)).Decision)

	sanitizeReq := approvedReq("s", "sanitize", "alice@example.com", capability.FlowLabelPII)
	decided := eng.ValidateAction(ctx, sanitizeReq, declassifyCaps("sanitize", capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, decided.Decision)
	require.Equal(t, []string{capability.FlowLabelPII}, decided.LabelsPendingClear)

	// The sanitizing call is decided but has NOT run. A concurrent egress decided in this
	// window must still see the taint.
	concurrent := eng.ValidateAction(ctx, req("s", "publish"), sinkCaps("publish", capability.FlowLabelPublic))
	assert.Equal(t, capability.DecisionDeny, concurrent.Decision,
		"a sink decided between the declassification's decision and its commit must still be blocked")
	assert.Equal(t, []string{capability.FlowLabelPII}, concurrent.CarriedLabels,
		"and the taint is still on the tape for it")

	// Only once the sanitizing call has actually run does the label go.
	_, err := eng.CommitDeclassification(ctx, sanitizeReq, decided.LabelsPendingClear)
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "publish"), sinkCaps("publish", capability.FlowLabelPublic)).Decision)
}

// TestDeclassify_UncommittedClearLeavesTheTaint pins the fail-CLOSED direction of the
// deferred clear: a caller that never commits (a refusal below the decision, a crash, an
// embedder that forgets) leaves the session exactly as tainted as it found it. The old
// ordering failed in the opposite direction, which is what made it a security bug rather
// than a bookkeeping one.
func TestDeclassify_UncommittedClearLeavesTheTaint(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()

	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read_customer"), sourceCaps("read_customer", capability.FlowLabelPII)).Decision)
	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx,
			approvedReq("s", "sanitize", "alice@example.com", capability.FlowLabelPII),
			declassifyCaps("sanitize", capability.FlowLabelPII)).Decision)

	assert.Equal(t, capability.DecisionDeny,
		eng.ValidateAction(ctx, req("s", "publish"), sinkCaps("publish", capability.FlowLabelPublic)).Decision,
		"an authorized clear that was never committed must not have untainted the session")
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
// session never carried is a permitted no-op whose COMMIT reports no change: the tape must
// not claim a declassification that did not happen, and the record's approver rides on what
// the commit changed.
func TestDeclassify_NoOpClearRecordsNothing(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()
	r := approvedReq("s", "sanitize", "alice@example.com", capability.FlowLabelPII)

	resp := eng.ValidateAction(ctx, r, declassifyCaps("sanitize", capability.FlowLabelPII))

	require.Equal(t, capability.DecisionAllow, resp.Decision)
	// The decision reports the AUTHORIZATION — settled, and the same whether or not a label
	// turns out to move — while the commit reports the CHANGE, which is what the record's
	// labels_cleared/approver/approval_id triple rides on.
	assert.Equal(t, []string{capability.FlowLabelPII}, resp.LabelsPendingClear)
	assert.Equal(t, "alice@example.com", resp.Approver)

	cleared, err := eng.CommitDeclassification(ctx, r, resp.LabelsPendingClear)
	require.NoError(t, err)
	assert.Empty(t, cleared, "nothing was carried, so nothing changed")
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

// TestDeclassify_CommitFaultKeepsTheTaint pins the commit-fault posture. The clear now runs
// AFTER the authorized call, so a store fault cannot un-run it and must not be reported as a
// refusal: the honest outcome is that the label stays and the caller records that the clear
// did not land. The session then over-blocks a later sink — the fail-closed direction —
// until the operator retries under a new approval.
func TestDeclassify_CommitFaultKeepsTheTaint(t *testing.T) {
	store := &removeFailingStore{FlowLabelStore: flowlabelstore.NewInMemory()}
	eng := enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(store),
	)
	ctx := context.Background()

	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read"), sourceCaps("read", capability.FlowLabelPII)).Decision)

	r := approvedReq("s", "sanitize", "a@b", capability.FlowLabelPII)
	resp := eng.ValidateAction(ctx, r, declassifyCaps("sanitize", capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, resp.Decision, "the decision authorizes; it does not write")

	store.fail = true
	cleared, err := eng.CommitDeclassification(ctx, r, resp.LabelsPendingClear)
	require.Error(t, err, "the commit reports the fault rather than swallowing it")
	assert.Equal(t, []string{capability.FlowLabelPII}, cleared,
		"the set travels with the error so the caller can report which labels MAY have gone")

	store.fail = false
	assert.Equal(t, capability.DecisionDeny,
		eng.ValidateAction(ctx, req("s", "publish"), sinkCaps("publish", capability.FlowLabelPublic)).Decision,
		"a clear that could not be applied leaves the taint in place")
}

// removeFailingStore fails Remove on demand so the clear-fault path is reachable, in either
// of the two shapes that matter.
//
// deleteFirst is what separates them, and it is a flag rather than a second double because
// picking wrong is invisible at the construction site. With it unset the Remove errors
// having changed NOTHING, which exercises only the hard-deny posture; with it set the Remove
// COMMITS and then reports failure, which is what a lost reply (a timeout, a reset) or a
// partial multi-label removal looks like to the caller — and it is the only shape that
// reaches the fail-OPEN direction at all. A test that reached for the wrong one of two
// similarly-named doubles would pass while asserting nothing about the residual, which is
// how the missing restore went unnoticed in the first place.
type removeFailingStore struct {
	capability.FlowLabelStore
	fail        bool
	deleteFirst bool
}

func (s *removeFailingStore) Remove(ctx context.Context, key string, labels ...string) error {
	if s.deleteFirst {
		if err := s.FlowLabelStore.Remove(ctx, key, labels...); err != nil {
			return err
		}
		if s.fail {
			return errors.New("backend reply lost after the delete committed")
		}
		return nil
	}
	if s.fail {
		return errors.New("backend unavailable")
	}
	return s.FlowLabelStore.Remove(ctx, key, labels...)
}

// TestDeclassify_CommitFaultAfterDeleteReportsTheSet covers the second commit-fault shape,
// which the first does not: "Remove errored" is not "Remove changed nothing". A store can
// delete and then lose its reply (a timeout, a reset), or remove part of a multi-label set
// before erroring.
//
// The action the clear sanitizes has already RUN by this point, so a delete that landed is
// not a fail-open — it is the authorized outcome, merely unconfirmed. What the caller must
// not do is claim it: labels_cleared is a signed assertion that these labels are gone, and a
// set that may or may not have landed cannot back one. So the commit returns the set
// ALONGSIDE the error and the caller reports it as unapplied rather than as cleared.
func TestDeclassify_CommitFaultAfterDeleteReportsTheSet(t *testing.T) {
	store := &removeFailingStore{FlowLabelStore: flowlabelstore.NewInMemory(), deleteFirst: true}
	eng := enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(store),
	)
	ctx := context.Background()

	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read"), sourceCaps("read", capability.FlowLabelPII)).Decision)

	r := approvedReq("s", "sanitize", "a@b", capability.FlowLabelPII)
	resp := eng.ValidateAction(ctx, r, declassifyCaps("sanitize", capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, resp.Decision)

	store.fail = true
	cleared, err := eng.CommitDeclassification(ctx, r, resp.LabelsPendingClear)
	require.Error(t, err)
	assert.Equal(t, []string{capability.FlowLabelPII}, cleared,
		"the caller cannot report what it was never told about")
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
