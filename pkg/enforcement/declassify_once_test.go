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

// TestDeclassifyOnce_SecondPresentationEscalates is the replay window the issue names, closed:
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

// TestDeclassifyOnce_LedgerFaultEscalates is the fail-closed posture the issue requires: a
// store fault while checking or burning a use-count must escalate, never silently allow.
func TestDeclassifyOnce_LedgerFaultEscalates(t *testing.T) {
	t.Run("read fault", func(t *testing.T) {
		store := &faultyFlowStore{inner: flowlabelstore.NewInMemory(), failGetOn: "declassify"}
		eng := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()), enforcement.WithFlowLabelStore(store))
		resp := eng.ValidateAction(context.Background(),
			onceApprovedReq("s", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII),
			declassifyCaps("publish", capability.FlowLabelPII))
		require.Equal(t, capability.DecisionEscalate, resp.Decision)
		require.NotNil(t, resp.Denial)
		assert.Equal(t, "ledger_unavailable", resp.Denial.Details["reason"],
			"an unreadable ledger must not become the way to replay every one-shot grant in a token")
	})

	t.Run("burn fault", func(t *testing.T) {
		store := &faultyFlowStore{inner: flowlabelstore.NewInMemory(), failAddOn: "declassify"}
		eng := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()), enforcement.WithFlowLabelStore(store))
		resp := eng.ValidateAction(context.Background(),
			onceApprovedReq("s", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII),
			declassifyCaps("publish", capability.FlowLabelPII))
		require.Equal(t, capability.DecisionDeny, resp.Decision)
		require.NotNil(t, resp.Denial)
		assert.True(t, resp.Denial.HardDeny, "a grant that could not be burned must not clear a label anyway")
	})
}

// TestDeclassifyOnce_ClearedByTeardown pins that a session's spent grants are released with
// the rest of its state, so a reused session id does not inherit another session's ledger.
func TestDeclassifyOnce_ClearedByTeardown(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()

	require.Equal(t, capability.DecisionAllow, eng.ValidateAction(ctx,
		onceApprovedReq("s", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII),
		declassifyCaps("publish", capability.FlowLabelPII)).Decision)

	require.NoError(t, eng.ClearSessionApprovals(ctx, "s"))

	after := eng.ValidateAction(ctx,
		onceApprovedReq("s", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII),
		declassifyCaps("publish", capability.FlowLabelPII))
	assert.Equal(t, capability.DecisionAllow, after.Decision)
}

// TestDeclassifyOnce_BurnFollowsTheTaskAnchor is the composition with task anchoring: a
// one-shot approval spent on one enforcement point stays spent on the next, so re-entering
// through a fresh session does not restore it. That is the replay a session-keyed ledger
// would leave open in exactly the multi-PEP topology a one-shot approval is minted for.
func TestDeclassifyOnce_BurnFollowsTheTaskAnchor(t *testing.T) {
	counter, store := callcounter.NewInMemory(), flowlabelstore.NewInMemory()
	pepA := anchoredEngine(counter, store, true)
	pepB := anchoredEngine(counter, store, true)
	ctx := context.Background()

	spend := onceApprovedReq("s1", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII)
	spend.Claims = map[string]interface{}{"task_id": "t1"}
	require.Equal(t, capability.DecisionAllow, pepA.ValidateAction(ctx, spend, declassifyCaps("publish", capability.FlowLabelPII)).Decision)

	replay := onceApprovedReq("s2", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII)
	replay.Claims = map[string]interface{}{"task_id": "t1"}
	resp := pepB.ValidateAction(ctx, replay, declassifyCaps("publish", capability.FlowLabelPII))
	assert.Equal(t, capability.DecisionEscalate, resp.Decision)
	assert.Equal(t, "approval_consumed", resp.Denial.Details["reason"])
}

// faultyFlowStore fails Get or Add for keys carrying a marker substring, so a test can fault
// exactly one of the two logical stores (labels or the declassify ledger) sharing the backend.
type faultyFlowStore struct {
	inner     capability.FlowLabelStore
	failGetOn string
	failAddOn string
}

func (f *faultyFlowStore) Add(ctx context.Context, key string, labels ...string) error {
	if f.failAddOn != "" && hasPrefixToken(key, f.failAddOn) {
		return errors.New("synthetic add fault")
	}
	return f.inner.Add(ctx, key, labels...)
}

func (f *faultyFlowStore) Get(ctx context.Context, key string) ([]string, error) {
	if f.failGetOn != "" && hasPrefixToken(key, f.failGetOn) {
		return nil, errors.New("synthetic get fault")
	}
	return f.inner.Get(ctx, key)
}

func (f *faultyFlowStore) Remove(ctx context.Context, key string, labels ...string) error {
	return f.inner.Remove(ctx, key, labels...)
}

func (f *faultyFlowStore) Clear(ctx context.Context, key string) error {
	return f.inner.Clear(ctx, key)
}

// hasPrefixToken reports whether key begins with the given verbatim prefix token. Counter and
// store keys lead with their prefix ("flow:", "declassify:"), which is what lets a test aim a
// fault at one of them.
func hasPrefixToken(key, token string) bool {
	return len(key) > len(token) && key[:len(token)] == token && key[len(token)] == ':'
}

// TestDeclassifyOnce_UnburnedWhenTheCallIsRefusedAfterTheBurn covers the rollback leg: the
// burn commits, the sequenceBlock antecedent write then faults, and the call is hard-denied
// and never forwarded — so the use has to be handed back. Otherwise a backend hiccup would
// silently consume an approval for an action that did not happen.
func TestDeclassifyOnce_UnburnedWhenTheCallIsRefusedAfterTheBurn(t *testing.T) {
	store := flowlabelstore.NewInMemory()
	ctx := context.Background()

	// An engine whose antecedent write always faults, sharing the store with a healthy one.
	broken := enforcement.New(
		enforcement.WithCallCounter(&faultyCounter{inner: callcounter.NewInMemory()}),
		enforcement.WithFlowLabelStore(store),
	)
	refused := broken.ValidateAction(ctx,
		onceApprovedReq("s", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII),
		declassifyCaps("publish", capability.FlowLabelPII))
	require.NotEqual(t, capability.DecisionAllow, refused.Decision, "the antecedent fault must refuse the call")

	healthy := enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(store),
	)
	retry := healthy.ValidateAction(ctx,
		onceApprovedReq("s", "publish", "ada@example.com", "apr-1", capability.FlowLabelPII),
		declassifyCaps("publish", capability.FlowLabelPII))
	assert.Equal(t, capability.DecisionAllow, retry.Decision,
		"a grant burned for a call that was then refused must be handed back")
}

// faultyCounter fails every recorded call, which is what the sequenceBlock antecedent write
// uses, while leaving the read paths intact.
type faultyCounter struct{ inner capability.CallCounter }

func (f *faultyCounter) IncrementAndGet(context.Context, string, int, int) (int64, error) {
	return 0, errors.New("synthetic counter fault")
}

func (f *faultyCounter) Peek(ctx context.Context, key string, windowSec int) (int64, error) {
	return f.inner.Peek(ctx, key, windowSec)
}

func (f *faultyCounter) AdmitAll(ctx context.Context, buckets []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	return f.inner.AdmitAll(ctx, buckets)
}
