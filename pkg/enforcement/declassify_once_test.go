// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// onceApprovedReq is approvedReq's single-use twin: the same covering grant, marked once and
// carrying the id the ledger burns it under.
func onceApprovedReq(session, name, approver, id string, labels ...string) *capability.EnforceRequest {
	r := req(session, name)
	r.DeclassifyApprovals = []capability.DeclassifyApproval{{
		Labels:   labels,
		Target:   "tool:" + name,
		Approver: approver,
		ID:       id,
		Once:     true,
	}}
	return r
}

// taintAndClear runs the standard shape: taint the anchor via a labeled source, then present
// the request at a constraint that declassifies. Returns the declassifying call's response.
func taintAndClear(t *testing.T, eng *enforcement.Engine, source, declassifying *capability.EnforceRequest) capability.EnforceResponse {
	t.Helper()
	ctx := context.Background()
	src := eng.ValidateAction(ctx, source, sourceCaps(source.TargetName, capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, src.Decision)
	return eng.ValidateAction(ctx, declassifying, declassifyCaps(declassifying.TargetName, capability.FlowLabelPII))
}

// TestDeclassifyOnce_SecondPresentationEscalates closes the replay window a scope-only grant leaves open:
// the first call clears the label with the grant, and the SAME grant on the SAME token
// escalates the second time rather than clearing again.
func TestDeclassifyOnce_SecondPresentationEscalates(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()

	first := taintAndClear(t, eng,
		req("s", "read_customer"),
		onceApprovedReq("s", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, first.Decision)
	require.Equal(t, []string{capability.FlowLabelPII}, first.LabelsCleared)
	require.Equal(t, "ada@example.com", first.Approver)

	// Re-taint, then present the identical grant again.
	src := eng.ValidateAction(ctx, req("s", "read_customer"), sourceCaps("read_customer", capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, src.Decision)

	replay := eng.ValidateAction(ctx,
		onceApprovedReq("s", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII),
		declassifyCaps("publish", capability.FlowLabelPII))
	assert.Equal(t, capability.DecisionEscalate, replay.Decision)
	require.NotNil(t, replay.Denial)
	assert.Equal(t, capability.ErrCodeEscalationRequired, replay.Denial.Code)
	assert.Equal(t, "approval_consumed", replay.Denial.Details["reason"],
		"a spent grant must read as consumed, not as 'no approval covers this' — the two send an operator to different fixes")
	assert.Equal(t, "apr-1", replay.Denial.Details["consumed_approval_id"])
	assert.True(t, replay.Denial.HardDeny, "a consumed-approval escalation must not be downgraded and forwarded by an audit route")
}

// TestDeclassifyOnce_StandingGrantStillReplays pins that the mechanism is opt-in per grant: a
// grant without `once` behaves exactly as it did, so an operator whose control plane already
// mints short-lived per-approval tokens keeps no ledger.
func TestDeclassifyOnce_StandingGrantStillReplays(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()

	first := taintAndClear(t, eng, req("s", "read_customer"), approvedReq("s", "publish", "ada@example.com", capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, first.Decision)

	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read_customer"), sourceCaps("read_customer", capability.FlowLabelPII)).Decision)
	again := eng.ValidateAction(ctx, approvedReq("s", "publish", "ada@example.com", capability.FlowLabelPII),
		declassifyCaps("publish", capability.FlowLabelPII))
	assert.Equal(t, capability.DecisionAllow, again.Decision)
	assert.Equal(t, []string{capability.FlowLabelPII}, again.LabelsCleared)
}

// TestDeclassifyOnce_BurnsEvenWhenTheClearIsANoOp is the ordering property that makes the
// one-shot rule hold: presenting the grant on a CLEAN anchor spends it, so the grant cannot be
// preserved by presenting it first when there is nothing to clear and again when there is.
func TestDeclassifyOnce_BurnsEvenWhenTheClearIsANoOp(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()

	// Clean anchor: allowed, clears nothing, records no approver — and still spends the grant.
	noop := eng.ValidateAction(ctx,
		onceApprovedReq("s", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII),
		declassifyCaps("publish", capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, noop.Decision)
	require.Empty(t, noop.LabelsCleared, "nothing was carried, so nothing was cleared")
	require.Empty(t, noop.Approver, "a no-op clear must not put a declassification that did not happen on the tape")

	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read_customer"), sourceCaps("read_customer", capability.FlowLabelPII)).Decision)

	replay := eng.ValidateAction(ctx,
		onceApprovedReq("s", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII),
		declassifyCaps("publish", capability.FlowLabelPII))
	assert.Equal(t, capability.DecisionEscalate, replay.Decision,
		"burning only on a clear that changed something would make the grant replayable by ordering")
}

// TestDeclassifyOnce_ASecondLiveGrantIsSelected covers the selection rule: a token carrying a
// spent grant AND a fresh one uses the fresh one rather than refusing on the first match.
func TestDeclassifyOnce_ASecondLiveGrantIsSelected(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()

	spend := onceApprovedReq("s", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII)
	require.Equal(t, capability.DecisionAllow, eng.ValidateAction(ctx, spend, declassifyCaps("publish", capability.FlowLabelPII)).Decision)

	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read_customer"), sourceCaps("read_customer", capability.FlowLabelPII)).Decision)

	both := req("s", "publish")
	both.DeclassifyApprovals = []capability.DeclassifyApproval{
		{Labels: []string{capability.FlowLabelPII}, Target: "tool:publish", Approver: "ada@example.com", ID: "apr-1", Once: true},
		{Labels: []string{capability.FlowLabelPII}, Target: "tool:publish", Approver: "grace@example.com", ID: "apr-2", Once: true},
	}
	resp := eng.ValidateAction(ctx, both, declassifyCaps("publish", capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, resp.Decision)
	assert.Equal(t, "grace@example.com", resp.Approver, "the spent grant must be passed over for the live one, not refused on")
	assert.Equal(t, "apr-2", resp.ApprovalID)
}

// TestDeclassifyOnce_LedgerFaultEscalates is the fail-closed posture a use-count demands:
// a ledger fault while checking or burning a use-count must refuse, never silently allow.
func TestDeclassifyOnce_LedgerFaultEscalates(t *testing.T) {
	t.Run("peek fault escalates", func(t *testing.T) {
		eng := enforcement.New(
			enforcement.WithCallCounter(&faultyCounter{inner: callcounter.NewInMemory(), failPeek: true}),
			enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
		)
		resp := eng.ValidateAction(context.Background(),
			onceApprovedReq("s", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII),
			declassifyCaps("publish", capability.FlowLabelPII))
		require.Equal(t, capability.DecisionEscalate, resp.Decision)
		require.NotNil(t, resp.Denial)
		assert.Equal(t, "ledger_unavailable", resp.Denial.Details["reason"],
			"an unreadable ledger must not become the way to replay every one-shot grant in a token")
	})

	t.Run("burn fault hard-denies", func(t *testing.T) {
		eng := enforcement.New(
			enforcement.WithCallCounter(&faultyCounter{inner: callcounter.NewInMemory(), failAdmit: true}),
			enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
		)
		resp := eng.ValidateAction(context.Background(),
			onceApprovedReq("s", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII),
			declassifyCaps("publish", capability.FlowLabelPII))
		require.Equal(t, capability.DecisionDeny, resp.Decision)
		require.NotNil(t, resp.Denial)
		assert.True(t, resp.Denial.HardDeny, "a grant that could not be burned must not clear a label anyway")
	})
}

// TestDeclassifyOnce_ConcurrentBurnAdmitsExactlyOne is why the ledger sits on the counter's
// atomic admission rather than on a check-then-act against the flow store: two callers that
// both observe the grant as live must not both spend it. The loser is refused, which is the
// only outcome that keeps "once" meaning once.
func TestDeclassifyOnce_ConcurrentBurnAdmitsExactlyOne(t *testing.T) {
	counter, store := callcounter.NewInMemory(), flowlabelstore.NewInMemory()
	caps := declassifyCaps("publish", capability.FlowLabelPII)
	ctx := context.Background()

	const racers = 8
	var wg sync.WaitGroup
	results := make([]capability.Decision, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Distinct sessions on one shared backend: the per-session decision lock the
			// transport holds does not serialize these, which is exactly the shape that
			// double-spent the grant when the burn was a Get-then-Add.
			eng := enforcement.New(enforcement.WithCallCounter(counter), enforcement.WithFlowLabelStore(store))
			results[i] = eng.ValidateAction(ctx,
				onceApprovedReq(fmt.Sprintf("s%d", i), "publish", "ada@example.com", "apr-1", capability.FlowLabelPII),
				caps).Decision
		}(i)
	}
	wg.Wait()

	allowed := 0
	for _, d := range results {
		if d == capability.DecisionAllow {
			allowed++
		}
	}
	assert.Equal(t, 1, allowed, "exactly one racer may spend a single-use approval, got %d of %d", allowed, racers)
}

// TestDeclassifyOnce_SurvivesSessionTeardown is the property the ledger's whole shape exists
// for: a burn a session teardown could reclaim would make "approve this once" mean "once per
// connection", and session lifetime is entirely under the caller's control.
func TestDeclassifyOnce_SurvivesSessionTeardown(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()

	require.Equal(t, capability.DecisionAllow, eng.ValidateAction(ctx,
		onceApprovedReq("s1", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII),
		declassifyCaps("publish", capability.FlowLabelPII)).Decision)

	// Everything a session teardown reclaims.
	require.NoError(t, eng.ClearSessionLabels(ctx, "s1"))

	// A fresh session, same token, same grant.
	after := eng.ValidateAction(ctx,
		onceApprovedReq("s2", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII),
		declassifyCaps("publish", capability.FlowLabelPII))
	assert.Equal(t, capability.DecisionEscalate, after.Decision,
		"reconnecting must not restore a spent single-use approval")
	assert.Equal(t, "approval_consumed", after.Denial.Details["reason"])
}

// TestDeclassifyOnce_BurnIsAnchorIndependent pins that the burn is not scoped to a session or
// a task. "Approve clearing this once" means once; scoping the ledger to an anchor made it
// once-per-anchor, which is a different and much weaker promise than the grant advertises.
func TestDeclassifyOnce_BurnIsAnchorIndependent(t *testing.T) {
	counter, store := callcounter.NewInMemory(), flowlabelstore.NewInMemory()
	pepA := anchoredEngine(counter, store, true)
	pepB := anchoredEngine(counter, store, true)
	ctx := context.Background()

	spend := onceApprovedReq("s1", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII)
	spend.Claims = map[string]interface{}{"task_id": "t1"}
	require.Equal(t, capability.DecisionAllow, pepA.ValidateAction(ctx, spend, declassifyCaps("publish", capability.FlowLabelPII)).Decision)

	// A different session, a different enforcement point, and a DIFFERENT task: the grant is
	// still spent, because the human approved it once and not once per task.
	replay := onceApprovedReq("s2", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII)
	replay.Claims = map[string]interface{}{"task_id": "t2"}
	resp := pepB.ValidateAction(ctx, replay, declassifyCaps("publish", capability.FlowLabelPII))
	assert.Equal(t, capability.DecisionEscalate, resp.Decision)
	assert.Equal(t, "approval_consumed", resp.Denial.Details["reason"])
}

// TestDeclassifyOnce_ScopedByTargetNotJustID pins that one control-plane record minted per
// approved action burns per action rather than collapsing to one use across all of them.
func TestDeclassifyOnce_ScopedByTargetNotJustID(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()

	require.Equal(t, capability.DecisionAllow, eng.ValidateAction(ctx,
		onceApprovedReq("s", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII),
		declassifyCaps("publish", capability.FlowLabelPII)).Decision)

	// Same approval id, different target: a separate use.
	assert.Equal(t, capability.DecisionAllow, eng.ValidateAction(ctx,
		onceApprovedReq("s", "export", "ada@example.com", "apr-1", capability.FlowLabelPII),
		declassifyCaps("export", capability.FlowLabelPII)).Decision)
}

// faultyCounter selectively faults one of the three CallCounter operations, so a test can aim
// a fault at the antecedent write (IncrementAndGet), the ledger peek, or the ledger burn.
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

// TestUsableDeclassifyApproval_TracksConsumption is the predicate the wrapping-PDP hardening
// path asks. It has to answer the same question checkDeclassify answers — is there a covering
// approval that is still LIVE — because the scope-only test let a burned grant suppress the
// hardening, leaving a wrapping layer's soft refusal for an --audit route to forward while the
// same call without the wrapper met a hard escalation.
func TestUsableDeclassifyApproval_TracksConsumption(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()
	approvals := []capability.DeclassifyApproval{
		{Labels: []string{capability.FlowLabelPII}, Target: "tool:publish", Approver: "ada", ID: "apr-1", Once: true},
	}
	want := []string{capability.FlowLabelPII}

	usable, err := eng.UsableDeclassifyApproval(ctx, approvals, "tool:publish", want)
	require.NoError(t, err)
	assert.True(t, usable, "a fresh covering grant is usable")

	// A grant covering a DIFFERENT action is not usable here.
	usable, err = eng.UsableDeclassifyApproval(ctx, approvals, "tool:other", want)
	require.NoError(t, err)
	assert.False(t, usable)

	// Spend it through the decision path, then ask again.
	require.Equal(t, capability.DecisionAllow, eng.ValidateAction(ctx,
		onceApprovedReq("s", "publish", "ada", "apr-1", capability.FlowLabelPII),
		declassifyCaps("publish", capability.FlowLabelPII)).Decision)

	usable, err = eng.UsableDeclassifyApproval(ctx, approvals, "tool:publish", want)
	require.NoError(t, err)
	assert.False(t, usable, "a burned grant must not read as authorization to a layer above the engine")

	// A standing grant is always usable — it is never burned.
	standing := []capability.DeclassifyApproval{
		{Labels: []string{capability.FlowLabelPII}, Target: "tool:publish", Approver: "ada", ID: "apr-2"},
	}
	usable, err = eng.UsableDeclassifyApproval(ctx, standing, "tool:publish", want)
	require.NoError(t, err)
	assert.True(t, usable)
}

// TestUsableDeclassifyApproval_LedgerFaultSurfaces keeps the caller able to distinguish "no
// usable approval" from "could not tell". The hardening path turns the fault into the same hard
// escalation checkDeclassify raises on it, and it can only do that if the error reaches it —
// swallowing it would make an unreachable ledger the way past the control on a wrapped route.
func TestUsableDeclassifyApproval_LedgerFaultSurfaces(t *testing.T) {
	eng := enforcement.New(
		enforcement.WithCallCounter(&faultyCounter{inner: callcounter.NewInMemory(), failPeek: true}),
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
	)
	_, err := eng.UsableDeclassifyApproval(context.Background(),
		[]capability.DeclassifyApproval{{Labels: []string{capability.FlowLabelPII}, Target: "tool:publish", Approver: "ada", ID: "apr-1", Once: true}},
		"tool:publish", []string{capability.FlowLabelPII})
	assert.Error(t, err)

	// Exported, so it is reachable with no engine at all. That must report the fault rather
	// than panic, and the fault reads as "cannot tell live from spent" like any other.
	var none *enforcement.Engine
	_, err = none.UsableDeclassifyApproval(context.Background(), nil, "tool:publish", []string{capability.FlowLabelPII})
	assert.Error(t, err)
}
