// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
)

// TestRecordSessionCall_WritesUnderTheAnchorNotTheSession is the regression for an antecedent
// silently not written.
//
// Recording was gated on req.SessionID, but under WithTaskAnchoredState the key never reads
// SessionID at all — so a source call carrying a task claim and no session id returned nil
// having written nothing. The fail-OPEN is reached when a LATER call on the same task does
// carry a session: the sink handler's own empty-session guard is satisfied, it reads the task
// key, finds the antecedent missing, and allows the very sequence the policy blocks. That
// asymmetry — the read failing closed on an empty session while the write silently skipped —
// is what this closes.
//
// Reachable by an embedder that anchors on tasks and does not mint a session id for every
// call; the transports always do, but the exported seam is not theirs alone.
func TestRecordSessionCall_WritesUnderTheAnchorNotTheSession(t *testing.T) {
	t.Parallel()

	caps := []capability.Constraint{
		{Target: "tool:read_secrets", Actions: []string{"call"}},
		{
			Target:     "tool:send_email",
			Actions:    []string{"call"},
			Conditions: []capability.Condition{capability.SequenceBlockCondition{AfterTools: []string{"read_secrets"}}},
		},
	}
	ctx := context.Background()
	eng := enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
		enforcement.WithTaskAnchoredState(),
	)

	// The source carries NO session id — the task claim is what its state is keyed on, so the
	// antecedent has a perfectly good home.
	source := &capability.EnforceRequest{
		TargetName: "read_secrets",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "read_secrets"},
		Claims:     map[string]interface{}{"task_id": "t-1"},
	}
	require.Equal(t, capability.DecisionAllow, eng.ValidateAction(ctx, source, caps).Decision)

	// The sink DOES carry one, so it clears the handler's own empty-session guard and actually
	// reads the task key. Before the fix it found nothing there and allowed.
	sink := &capability.EnforceRequest{
		SessionID:  "s2",
		TargetName: "send_email",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "send_email"},
		Claims:     map[string]interface{}{"task_id": "t-1"},
	}
	assert.Equal(t, capability.DecisionDeny, eng.ValidateAction(ctx, sink, caps).Decision,
		"an antecedent recorded under the task must gate a later call on that task, whether or not the source carried a session")

	// A DIFFERENT task is unaffected: the write landed on the anchor, not on everything.
	otherTask := &capability.EnforceRequest{
		SessionID:  "s3",
		TargetName: "send_email",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "send_email"},
		Claims:     map[string]interface{}{"task_id": "t-2"},
	}
	assert.Equal(t, capability.DecisionAllow, eng.ValidateAction(ctx, otherTask, caps).Decision)
}

// TestRecordSessionCall_StillSkipsWithNoAnchorAtAll pins the other side: gating on the anchor
// must not turn "nothing to key on" into a write under an EMPTY key, which would pool every
// anonymous caller's antecedents into one bucket and gate unrelated sessions on each other.
func TestRecordSessionCall_StillSkipsWithNoAnchorAtAll(t *testing.T) {
	t.Parallel()

	eng := enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
	)
	caps := []capability.Constraint{
		{Target: "tool:read_secrets", Actions: []string{"call"}},
		{
			Target:     "tool:send_email",
			Actions:    []string{"call"},
			Conditions: []capability.Condition{capability.SequenceBlockCondition{AfterTools: []string{"read_secrets"}}},
		},
	}
	ctx := context.Background()

	// Session anchoring, no session id: there is no subject for this call's state at all.
	sessionless := &capability.EnforceRequest{
		TargetName: "read_secrets",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "read_secrets"},
	}
	require.Equal(t, capability.DecisionAllow, eng.ValidateAction(ctx, sessionless, caps).Decision)

	// An unrelated session must not be gated by it.
	other := &capability.EnforceRequest{
		SessionID:  "s2",
		TargetName: "send_email",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "send_email"},
	}
	assert.Equal(t, capability.DecisionAllow, eng.ValidateAction(ctx, other, caps).Decision,
		"with no anchor there is nothing to record against, and an empty key would pool every anonymous caller")
}

// TestExportedSeams_NilArgumentsDenyRatherThanPanic pins this package's fail-closed rule at
// the two exported verdict seams that were dereferencing unconditionally.
//
// A panic is the fail-OPEN reading of "on any ambiguity, deny": the rule is about the
// DECISION, and a decision point that crashes produces none — the proxy dies and whatever
// restarts it decides the traffic. Every sibling seam already guarded.
func TestExportedSeams_NilArgumentsDenyRatherThanPanic(t *testing.T) {
	t.Parallel()

	eng := enforcement.New()
	ctx := context.Background()
	caps := []capability.Constraint{{Target: "tool:t", Actions: []string{"call"}}}

	cases := []struct {
		name string
		call func() capability.EnforceResponse
	}{
		{"ValidateAction with a nil request", func() capability.EnforceResponse {
			return eng.ValidateAction(ctx, nil, caps)
		}},
		{"EvaluateConditions with a nil request", func() capability.EnforceResponse {
			return eng.EvaluateConditions(ctx, nil, &caps[0])
		}},
		{"EvaluateConditions with a nil constraint", func() capability.EnforceResponse {
			return eng.EvaluateConditions(ctx, &capability.EnforceRequest{TargetName: "t", Target: &capability.EnforceRequestTarget{Type: "tool", Name: "t"}}, nil)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := tc.call()
			require.Equal(t, capability.DecisionDeny, resp.Decision)
			require.NotNil(t, resp.Denial)
			// The FAULT code, so no posture forwards it: a caller's broken contract is not a
			// policy verdict an observing route may downgrade into a forward.
			assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
			assert.False(t, resp.Denial.Downgradable(), "a refusal with no decision behind it must not be downgradable")
		})
	}
}
