// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"context"
	"errors"
	"testing"
	"time"

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
	// Non-downgradable. A forwarded refusal here is not a verdict being staged: the observe
	// path's own antecedent recorder would then write this call's labels and sequence marker
	// through the session key, performing the very state split the check refuses — on a route
	// whose other constraints read the task-keyed bucket.
	assert.True(t, resp.Denial.BlockOverride, "an unaccountable call must not be downgraded and forwarded")

	// A caller with NO token still falls back to its session, unchanged.
	assert.Equal(t, capability.DecisionAllow, eng.ValidateAction(ctx, req("s", "read_customer"), caps).Decision)

	// And a token carrying the claim is anchored on the task.
	assert.Equal(t, capability.DecisionAllow, eng.ValidateAction(ctx, taskReq("s", "t1", "read_customer"), caps).Decision)
}

// TestTaskAnchor_UnresolvedRefusalCarriesNoSessionEvidence pins the ORDER of the refusal
// against the flow-label peek beside it.
//
// The refusal's whole message is "refusing rather than accounting this call against a second,
// session-keyed bucket". With no task id the anchor falls back to the SESSION key, so peeking
// first read exactly that bucket and the carried-labels defer then stamped the snapshot onto
// the signed record — evidence drawn from the bucket the engine had just declared invalid. It
// also paid a label-store round trip and a delegation-gate evaluation per denied call, on a
// shape an HTTP caller produces at will by alternating token shapes.
func TestTaskAnchor_UnresolvedRefusalCarriesNoSessionEvidence(t *testing.T) {
	eng := anchoredEngine(callcounter.NewInMemory(), flowlabelstore.NewInMemory(), true)
	ctx := context.Background()

	// An unauthenticated call falls back to the session and taints THAT bucket.
	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read_customer"), sourceCaps("read_customer", capability.FlowLabelPII)).Decision)

	// Now the same session presents a token with no task_id, at a flow-relevant sink — the
	// one shape where the peek would have run before the anchor gate.
	authed := req("s", "publish")
	authed.Claims = map[string]interface{}{"sub": "svc@example.com"}
	resp := eng.ValidateAction(ctx, authed, sinkCaps("publish", capability.FlowLabelPublic))

	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	require.Equal(t, "no_task_id", resp.Denial.Details["reason"])
	assert.Nil(t, resp.CarriedLabels,
		"the refusal must not report labels read from the very bucket it refuses to account against")
}

// TestTaskAnchor_HardeningVerdictsCarryNoSessionEvidence extends the no-session-evidence
// property to the two composed-hardening verdicts a wrapping PDP calls on an already-refused
// request: both peek the flow bucket for record evidence, and for a caller the engine refuses
// as unanchorable that peek's session fallback reads the very bucket the refusal rejects.
// The refusals themselves must still fire — only the wrong-bucket snapshot is withheld.
func TestTaskAnchor_HardeningVerdictsCarryNoSessionEvidence(t *testing.T) {
	eng := enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
		enforcement.WithTaskAnchoredState(),
		enforcement.WithEffectCeiling(&capability.EffectCeiling{MaxEffectClass: capability.EffectReversible}),
	)
	ctx := context.Background()

	// An unauthenticated call falls back to the session and taints THAT bucket. Annotated
	// reversible: unannotated resolves to irreversible, which the ceiling would escalate.
	source := sourceCaps("read_customer", capability.FlowLabelPII)
	source[0].Effect = &capability.EffectContract{Class: capability.EffectReversible}
	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read_customer"), source).Decision)

	authed := req("s", "publish")
	authed.Claims = map[string]interface{}{"sub": "svc@example.com"}

	overCeiling := sinkCaps("publish", capability.FlowLabelPublic)[0]
	overCeiling.Effect = &capability.EffectContract{Class: capability.EffectIrreversible}
	verdict := eng.CeilingVerdictFor(ctx, authed, &overCeiling)
	require.NotNil(t, verdict, "the ceiling escalation itself must not stand down")
	assert.Nil(t, verdict.CarriedLabels,
		"the escalation must not report labels read from the very bucket the full path refuses to account against")
	assert.NotContains(t, verdict.Denial.Details, "carried_labels")
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

// TestTaskAnchor_RollbackStillRunsForASessionKeyedRequest is the other half of the stand-down
// above: it is a property of the REQUEST's key, not of the engine's mode. A task-anchored engine
// still keys a token-less caller on its session, where the decision lock does span the key and
// no concurrent writer exists — so declining to roll back there stranded a label for a hazard
// that cannot occur, over-blocking every unauthenticated caller the route serves for the rest of
// the session.
func TestTaskAnchor_RollbackStillRunsForASessionKeyedRequest(t *testing.T) {
	counter, store := callcounter.NewInMemory(), flowlabelstore.NewInMemory()
	ctx := context.Background()

	// A token-less caller (session-keyed even on a task-anchored engine) whose source faults
	// after its own label write.
	broken := enforcement.New(
		enforcement.WithCallCounter(&faultyCounter{inner: counter, failIncrement: true}),
		enforcement.WithFlowLabelStore(store),
		enforcement.WithTaskAnchoredState(),
	)
	require.NotEqual(t, capability.DecisionAllow,
		broken.ValidateAction(ctx, req("sA", "read_customer"), sourceCaps("read_customer", capability.FlowLabelPII)).Decision)

	// The refused call left nothing behind, so the session's next sink is not blocked by taint
	// from a read that never happened.
	healthy := anchoredEngine(counter, store, true)
	sink := healthy.ValidateAction(ctx, req("sA", "publish"), sinkCaps("publish", capability.FlowLabelPublic))
	assert.Equal(t, capability.DecisionAllow, sink.Decision,
		"a faulted source on a session-keyed request must roll its own label back")
}

// TestResolveStateAnchor_IsTheOneAnchorDecision pins the resolver both the engine's key
// builder and a transport's decision turn go through. Two independent readings of "is this
// request task-anchored, and under which id" is where a turn keyed on one thing and state
// stored under another come to disagree — silently, since nothing in the process ever compares
// the two keys.
func TestResolveStateAnchor_IsTheOneAnchorDecision(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		taskAnchored, hasTask bool
		taskID, sessionID     string
		wantKind              enforcement.AnchorKind
		wantID                string
	}{
		"task anchoring on, task presented": {true, true, "task-42", "sess-a", enforcement.AnchorKindTask, "task-42"},
		// The one safe fallback: a caller with no usable task claim keys on its own session,
		// never on a shared bucket.
		"task anchoring on, no task claim": {true, false, "", "sess-a", enforcement.AnchorKindSession, "sess-a"},
		// An operator who did not enable anchoring is unaffected by it, claim or no claim.
		"task anchoring off": {false, true, "task-42", "sess-a", enforcement.AnchorKindSession, "sess-a"},
	} {
		t.Run(name, func(t *testing.T) {
			got := enforcement.ResolveStateAnchor(tc.taskAnchored, tc.hasTask, tc.taskID, tc.sessionID)
			assert.Equal(t, tc.wantKind, got.Kind)
			assert.Equal(t, tc.wantID, got.ID)
		})
	}
}

// TestStateAnchorKey_KeepsTheKindsDisjoint is the property the turn registry depends on: a
// session named X and a task named X are different subjects and must not share a gate.
func TestStateAnchorKey_KeepsTheKindsDisjoint(t *testing.T) {
	t.Parallel()
	task := enforcement.ResolveStateAnchor(true, true, "x", "ignored").Key()
	session := enforcement.ResolveStateAnchor(false, false, "", "x").Key()
	assert.NotEqual(t, task, session, "one identity string under two kinds must address two turns")

	// Two sessions on one task reach the same key; that is the whole point of the anchor.
	assert.Equal(t, task, enforcement.ResolveStateAnchor(true, true, "x", "another-session").Key())
	// And the separator is not something an id can contain, so no pair of ids can collide by
	// concatenation.
	assert.NotEqual(t,
		enforcement.ResolveStateAnchor(false, false, "", "a\x00b").Key(),
		enforcement.ResolveStateAnchor(false, false, "", "a").Key()+"b")
}

// TestStateAnchor_AgreesWithTheEngineKey is the correspondence that matters: the exported
// resolver and the engine's own accounting must classify a request the same way. Here that is
// asserted through observable behavior — two sessions sharing a task share a maxCalls budget
// exactly when the resolver says they share an anchor.
func TestStateAnchor_AgreesWithTheEngineKey(t *testing.T) {
	t.Parallel()
	caps := []capability.Constraint{{
		Target: "tool:x", Actions: []string{"call"},
		Conditions: []capability.Condition{capability.MaxCallsCondition{Count: 1, WindowSeconds: 3600}},
	}}
	e := anchoredEngine(callcounter.NewInMemory(), flowlabelstore.NewInMemory(), true)
	ctx := context.Background()

	first := e.ValidateAction(ctx, taskReq("session-a", "task-1", "x"), caps)
	require.Equal(t, capability.DecisionAllow, first.Decision)

	// The resolver says these two requests share an anchor...
	assert.Equal(t,
		enforcement.ResolveStateAnchor(true, true, "task-1", "session-a").Key(),
		enforcement.ResolveStateAnchor(true, true, "task-1", "session-b").Key())
	// ...and the engine spends one budget across both, which is what sharing an anchor means.
	assert.Equal(t, capability.DecisionDeny,
		e.ValidateAction(ctx, taskReq("session-b", "task-1", "x"), caps).Decision,
		"the second session spends the same task's budget, so the resolver and the key builder agree")

	// A session-anchored request on the same engine (no task claim) keeps its own budget,
	// which is the fallback the resolver reports for it.
	assert.Equal(t, enforcement.AnchorKindSession,
		enforcement.ResolveStateAnchor(true, false, "", "session-c").Kind)
	assert.Equal(t, capability.DecisionAllow,
		e.ValidateAction(ctx, req("session-c", "x"), caps).Decision)
}

// faultyCounter injects backend faults into a real counter so a test can assert the engine's
// fail-closed posture on an unreadable or unwritable quota backend.
type faultyCounter struct {
	inner         capability.CallCounter
	failIncrement bool
	failPeek      bool
	failAdmit     bool
}

func (f *faultyCounter) IncrementAndGet(ctx context.Context, key string, windowSec, maxEntries int) (int64, error) {
	if f.failIncrement {
		return 0, errors.New("synthetic counter fault")
	}
	return f.inner.IncrementAndGet(ctx, key, windowSec, maxEntries)
}

func (f *faultyCounter) Peek(ctx context.Context, key string, windowSec int) (int64, error) {
	if f.failPeek {
		return 0, errors.New("synthetic peek fault")
	}
	return f.inner.Peek(ctx, key, windowSec)
}

func (f *faultyCounter) AdmitAll(ctx context.Context, buckets []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	if f.failAdmit {
		return false, 0, 0, 0, errors.New("synthetic admit fault")
	}
	return f.inner.AdmitAll(ctx, buckets)
}
