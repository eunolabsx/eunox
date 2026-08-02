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

// taskReq is a request on a session whose validated token carries a task id. The claim key
// is "task_id" — the reserved input.claims key the PDP fills from the token's canonical
// field, which a same-named custom claim cannot shadow.
func taskReq(session, task, name string) *capability.EnforceRequest {
	r := req(session, name)
	r.Claims = map[string]interface{}{"task_id": task}
	return r
}

// anchoredEngine builds an engine with both state backends and the given anchoring posture,
// sharing one counter and one store across every engine a test constructs so that "two
// enforcement points" is modeled as two engines over shared state — the deployment shape
// task anchoring exists for.
func anchoredEngine(counter capability.CallCounter, store capability.FlowLabelStore, taskAnchored bool) *enforcement.Engine {
	opts := []enforcement.Option{
		enforcement.WithCallCounter(counter),
		enforcement.WithFlowLabelStore(store),
	}
	if taskAnchored {
		opts = append(opts, enforcement.WithTaskAnchoredState())
	}
	return enforcement.New(opts...)
}

// TestTaskAnchor_TaintCrossesAPEPHop is the whole point of the feature: a source read on one
// enforcement point taints the TASK, and a sink on a second enforcement point — a different
// engine, a different session id, the same task — sees the taint and denies. Under session
// anchoring the same sequence allows, which is the gap task anchoring closes.
func TestTaskAnchor_TaintCrossesAPEPHop(t *testing.T) {
	for _, tc := range []struct {
		name    string
		anchor  bool
		wantErr capability.Decision
	}{
		{"session anchoring lets the taint stop at the hop", false, capability.DecisionAllow},
		{"task anchoring carries the taint across the hop", true, capability.DecisionDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counter, store := callcounter.NewInMemory(), flowlabelstore.NewInMemory()
			pepA := anchoredEngine(counter, store, tc.anchor)
			pepB := anchoredEngine(counter, store, tc.anchor)
			ctx := context.Background()

			src := pepA.ValidateAction(ctx, taskReq("session-a", "task-1", "read_customer"),
				sourceCaps("read_customer", capability.FlowLabelPII))
			require.Equal(t, capability.DecisionAllow, src.Decision)
			require.Equal(t, []string{capability.FlowLabelPII}, src.LabelsOut)

			// A DIFFERENT session on a DIFFERENT enforcement point, same task.
			sink := pepB.ValidateAction(ctx, taskReq("session-b", "task-1", "publish"),
				sinkCaps("publish", capability.FlowLabelPublic))
			assert.Equal(t, tc.wantErr, sink.Decision)
		})
	}
}

// TestTaskAnchor_FallsBackToSessionWithoutAClaim pins the property that makes the option safe
// to turn on: a request with no token (and so no task claim) is anchored on its session
// exactly as it is without anchoring. Two task-less sessions must not pool their state, which
// would be both a bypass and a denial-of-service.
func TestTaskAnchor_FallsBackToSessionWithoutAClaim(t *testing.T) {
	counter, store := callcounter.NewInMemory(), flowlabelstore.NewInMemory()
	eng := anchoredEngine(counter, store, true)
	ctx := context.Background()

	src := eng.ValidateAction(ctx, req("anon-a", "read_customer"), sourceCaps("read_customer", capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, src.Decision)

	// A second anonymous session must NOT inherit the first's taint.
	sink := eng.ValidateAction(ctx, req("anon-b", "publish"), sinkCaps("publish", capability.FlowLabelPublic))
	assert.Equal(t, capability.DecisionAllow, sink.Decision, "an unauthenticated caller must never join another caller's anchored state")

	// The same session does carry it, i.e. anchoring did not disable flow control.
	same := eng.ValidateAction(ctx, req("anon-a", "publish"), sinkCaps("publish", capability.FlowLabelPublic))
	assert.Equal(t, capability.DecisionDeny, same.Decision)
}

// TestTaskAnchor_DisjointFromASameNamedSession pins the key encoding: a task named "x" and a
// session named "x" must address different buckets, or one caller's taint would be another's.
func TestTaskAnchor_DisjointFromASameNamedSession(t *testing.T) {
	counter, store := callcounter.NewInMemory(), flowlabelstore.NewInMemory()
	eng := anchoredEngine(counter, store, true)
	ctx := context.Background()

	// Taint the TASK "x" (from a session with a different id).
	src := eng.ValidateAction(ctx, taskReq("s1", "x", "read_customer"), sourceCaps("read_customer", capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, src.Decision)

	// A token-less session whose id happens to be "x" is anchored on the SESSION "x".
	sink := eng.ValidateAction(ctx, req("x", "publish"), sinkCaps("publish", capability.FlowLabelPublic))
	assert.Equal(t, capability.DecisionAllow, sink.Decision, "a session id and a task id that collide as strings must not collide as anchors")
}

// TestTaskAnchor_QuotaFollowsTheTask covers the budget axis: a maxCalls quota is spent by the
// TASK, so a delegate re-entering through a fresh session cannot refill it. This is the
// semantic change the option is opt-in for, stated as a test rather than only as prose.
func TestTaskAnchor_QuotaFollowsTheTask(t *testing.T) {
	counter, store := callcounter.NewInMemory(), flowlabelstore.NewInMemory()
	caps := []capability.Constraint{{
		Target:     "tool:refund",
		Actions:    []string{"call"},
		Conditions: []capability.Condition{capability.MaxCallsCondition{Count: 1, WindowSeconds: 3600}},
	}}
	ctx := context.Background()

	anchored := anchoredEngine(counter, store, true)
	require.Equal(t, capability.DecisionAllow, anchored.ValidateAction(ctx, taskReq("s1", "t1", "refund"), caps).Decision)
	assert.Equal(t, capability.DecisionDeny, anchored.ValidateAction(ctx, taskReq("s2", "t1", "refund"), caps).Decision,
		"a fresh session on the same task must not refill the task's quota")

	// Session anchoring (the default) is the contrast: a new session is a new budget.
	plain := anchoredEngine(callcounter.NewInMemory(), flowlabelstore.NewInMemory(), false)
	require.Equal(t, capability.DecisionAllow, plain.ValidateAction(ctx, taskReq("s1", "t1", "refund"), caps).Decision)
	assert.Equal(t, capability.DecisionAllow, plain.ValidateAction(ctx, taskReq("s2", "t1", "refund"), caps).Decision)
}

// TestTaskAnchor_SequenceAntecedentFollowsTheTask covers the antecedent axis: a
// sequenceBlock antecedent recorded on one hop is visible to the gate on the next.
func TestTaskAnchor_SequenceAntecedentFollowsTheTask(t *testing.T) {
	counter, store := callcounter.NewInMemory(), flowlabelstore.NewInMemory()
	caps := []capability.Constraint{
		{Target: "tool:read_secrets", Actions: []string{"call"}},
		{
			Target:     "tool:send_email",
			Actions:    []string{"call"},
			Conditions: []capability.Condition{capability.SequenceBlockCondition{AfterTools: []string{"read_secrets"}}},
		},
	}
	ctx := context.Background()

	pepA := anchoredEngine(counter, store, true)
	pepB := anchoredEngine(counter, store, true)

	require.Equal(t, capability.DecisionAllow, pepA.ValidateAction(ctx, taskReq("s1", "t1", "read_secrets"), caps).Decision)
	blocked := pepB.ValidateAction(ctx, taskReq("s2", "t1", "send_email"), caps)
	assert.Equal(t, capability.DecisionDeny, blocked.Decision, "the antecedent must gate the second hop of the same task")
}

// TestTaskAnchor_TeardownDoesNotReclaimTaskState pins the deliberate asymmetry in
// ClearSessionLabels: a session's teardown releases what the SESSION owns and leaves the
// task's state alone. Reclaiming it would let an agent launder a task's taint by
// disconnecting, which is the exact move the anchor exists to prevent.
func TestTaskAnchor_TeardownDoesNotReclaimTaskState(t *testing.T) {
	counter, store := callcounter.NewInMemory(), flowlabelstore.NewInMemory()
	eng := anchoredEngine(counter, store, true)
	ctx := context.Background()

	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, taskReq("s1", "t1", "read_customer"), sourceCaps("read_customer", capability.FlowLabelPII)).Decision)
	require.NoError(t, eng.ClearSessionLabels(ctx, "s1"))

	sink := eng.ValidateAction(ctx, taskReq("s2", "t1", "publish"), sinkCaps("publish", capability.FlowLabelPublic))
	assert.Equal(t, capability.DecisionDeny, sink.Decision, "a task's taint must survive the teardown of the session that created it")
}

// TestTaskAnchor_RefusesAnAuthenticatedCallerWithNoTaskID is the fail-closed half of the
// fallback. Falling back to session keying is safe for a caller with NO token — it shares
// state with nobody. An authenticated caller whose token omits the claim is a different case:
// on an HTTP host each request carries its own Authorization header, so alternating tokens
// would split one caller's taint, budgets and antecedents across two buckets, and every
// direction of that split is a fail-open.
func TestTaskAnchor_RefusesAnAuthenticatedCallerWithNoTaskID(t *testing.T) {
	eng := anchoredEngine(callcounter.NewInMemory(), flowlabelstore.NewInMemory(), true)
	ctx := context.Background()
	caps := []capability.Constraint{{Target: "tool:read_customer", Actions: []string{"call"}}}

	// A token that authenticated but carries no task_id.
	authed := req("s", "read_customer")
	authed.Claims = map[string]interface{}{"sub": "svc@example.com"}
	resp := eng.ValidateAction(ctx, authed, caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
	assert.Equal(t, "no_task_id", resp.Denial.Details["reason"])

	// A caller with NO token still falls back to its session, unchanged.
	assert.Equal(t, capability.DecisionAllow, eng.ValidateAction(ctx, req("s", "read_customer"), caps).Decision)

	// And a token carrying the claim is anchored on the task.
	assert.Equal(t, capability.DecisionAllow, eng.ValidateAction(ctx, taskReq("s", "t1", "read_customer"), caps).Decision)
}

// TestTaskAnchor_NoRollbackAcrossASharedTaskKey pins why the label rollback stands down under
// task anchoring: the snapshot it computes its delta from is taken under ONE session's decision
// lock, and that lock does not span a task key two sessions share. Removing a label a
// concurrent session legitimately added would leave the task untainted for a source read that
// really happened.
func TestTaskAnchor_NoRollbackAcrossASharedTaskKey(t *testing.T) {
	counter, store := callcounter.NewInMemory(), flowlabelstore.NewInMemory()
	ctx := context.Background()

	// Session A taints the task legitimately.
	healthy := anchoredEngine(counter, store, true)
	require.Equal(t, capability.DecisionAllow,
		healthy.ValidateAction(ctx, taskReq("sA", "t1", "read_customer"), sourceCaps("read_customer", capability.FlowLabelPII)).Decision)

	// Session B's source faults after its own label write. Its rollback must not reach for a
	// key it does not exclusively own.
	broken := enforcement.New(
		enforcement.WithCallCounter(&faultyCounter{inner: counter, failIncrement: true}),
		enforcement.WithFlowLabelStore(store),
		enforcement.WithTaskAnchoredState(),
	)
	require.NotEqual(t, capability.DecisionAllow,
		broken.ValidateAction(ctx, taskReq("sB", "t1", "read_customer"), sourceCaps("read_customer", capability.FlowLabelPII)).Decision)

	sink := healthy.ValidateAction(ctx, taskReq("sA", "t1", "publish"), sinkCaps("publish", capability.FlowLabelPublic))
	assert.Equal(t, capability.DecisionDeny, sink.Decision,
		"a faulted call in one session must not launder the taint another session deposited on the task")
}
