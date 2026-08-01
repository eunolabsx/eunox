// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The cumulative blastRadius bound: a weighted sliding-window sum over the SAME counter
// seam maxCalls uses. It is the bound per-call authorization structurally cannot express —
// four hundred individually-permitted $10 refunds are each legal, and only the aggregate is
// catastrophic.

// refundConstraint builds a capability whose blast radius is the call's `amount`, with the
// given per-call and cumulative bounds. An empty perCall leaves `max` unset.
func refundConstraint(perCall, maxTotal string, windowSeconds int) capability.Constraint {
	cond := &capability.BlastRadiusCondition{WindowSeconds: windowSeconds}
	if perCall != "" {
		cond.Max = effNum(perCall)
	}
	if maxTotal != "" {
		cond.MaxTotal = effNum(maxTotal)
	}
	return capability.Constraint{
		Target:  "tool:refund",
		Actions: []string{"call"},
		Effect: &capability.EffectContract{
			Class:              capability.EffectCompensable,
			CompensatingAction: "tool:reverse_refund",
			BlastRadius:        &capability.BlastRadiusSpec{Argument: "amount", Unit: "usd"},
		},
		Conditions: []capability.Condition{cond},
	}
}

// refund runs one refund of the given amount through the engine.
func refund(t *testing.T, e *enforcement.Engine, caps []capability.Constraint, amount string) capability.EnforceResponse {
	t.Helper()
	return e.ValidateAction(context.Background(),
		effectReq("refund", map[string]interface{}{"amount": jsonNumber(amount)}), caps)
}

// jsonNumber renders a manifest-style numeric argument, the shape a UseNumber decode
// produces on the real path.
func jsonNumber(s string) interface{} { return *effNum(s) }

// TestBlastRadiusVelocity_BoundsTheAggregate is the acceptance criterion: every call is
// individually permitted by the per-call bound, and the cumulative bound stops the run.
func TestBlastRadiusVelocity_BoundsTheAggregate(t *testing.T) {
	e := effectEngine(nil)
	caps := []capability.Constraint{refundConstraint("500", "2000", 3600)}

	// Two hundred $10 refunds would be $2,000 — the budget exactly. Drive the first 200.
	for i := 0; i < 200; i++ {
		resp := refund(t, e, caps, "10")
		require.Equal(t, capability.DecisionAllow, resp.Decision, "refund %d of $10 is within both bounds", i+1)
	}
	resp := refund(t, e, caps, "10")
	require.Equal(t, capability.DecisionDeny, resp.Decision,
		"the 201st $10 refund takes the hour past $2,000; no per-call bound can see this")
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeBlastRadius, resp.Denial.ConditionType)
	assert.Equal(t, "2000", resp.Denial.Details["blast_radius_max_total"])
	assert.Equal(t, 3600, resp.Denial.Details["blast_radius_window_seconds"])
	assert.Contains(t, resp.Denial.Message, "cumulative total")
}

// TestBlastRadiusVelocity_PerCallBoundRunsFirst pins the ordering: a call refused for being
// too large ON ITS OWN must not consume cumulative budget, or a burst of oversized attempts
// would exhaust the budget belonging to the calls that were actually permitted.
func TestBlastRadiusVelocity_PerCallBoundRunsFirst(t *testing.T) {
	e := effectEngine(nil)
	caps := []capability.Constraint{refundConstraint("500", "2000", 3600)}

	for i := 0; i < 10; i++ {
		resp := refund(t, e, caps, "5000")
		require.Equal(t, capability.DecisionDeny, resp.Decision)
		require.NotNil(t, resp.Denial)
		assert.Contains(t, resp.Denial.Message, "exceeds the permitted maximum",
			"the per-call bound must be the reported reason")
	}
	// $2,000 of budget is still entirely free.
	resp := refund(t, e, caps, "500")
	assert.Equal(t, capability.DecisionAllow, resp.Decision,
		"per-call refusals must not have charged the cumulative budget")
}

// TestBlastRadiusVelocity_DeniedCallRecordsNothing pins the commit rule at the engine
// level: an over-budget call must not spend, or a retry loop extends its own lockout.
func TestBlastRadiusVelocity_DeniedCallRecordsNothing(t *testing.T) {
	e := effectEngine(nil)
	caps := []capability.Constraint{refundConstraint("", "100", 3600)}

	require.Equal(t, capability.DecisionAllow, refund(t, e, caps, "90").Decision)
	for i := 0; i < 20; i++ {
		require.Equal(t, capability.DecisionDeny, refund(t, e, caps, "50").Decision)
	}
	assert.Equal(t, capability.DecisionAllow, refund(t, e, caps, "10").Decision,
		"the refused $50 attempts must not have consumed the remaining $10")
}

// TestBlastRadiusVelocity_UnquantifiedFailsTheBound pins the fail-closed rule the per-call
// bound already follows: an action whose size cannot be established must not contribute 0
// to a sum, or the unannotated call becomes the one way to spend nothing.
func TestBlastRadiusVelocity_UnquantifiedFailsTheBound(t *testing.T) {
	e := effectEngine(nil)
	caps := []capability.Constraint{refundConstraint("", "2000", 3600)}

	// The contract names `amount`; this call supplies none.
	resp := e.ValidateAction(context.Background(),
		effectReq("refund", map[string]interface{}{"note": "no amount here"}), caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Contains(t, resp.Denial.Message, "could not be quantified")
	assert.Contains(t, resp.Denial.Message, "cumulative bound")
}

// TestBlastRadiusVelocity_IsPerSessionAndPerTarget pins the bucket key. A shared budget
// would be both a bypass (one session's spend blocks another's) and a denial-of-service.
func TestBlastRadiusVelocity_IsPerSessionAndPerTarget(t *testing.T) {
	e := effectEngine(nil)
	caps := []capability.Constraint{
		refundConstraint("", "100", 3600),
		{
			Target:  "tool:payout",
			Actions: []string{"call"},
			Effect: &capability.EffectContract{
				Class:       capability.EffectIrreversible,
				BlastRadius: &capability.BlastRadiusSpec{Argument: "amount"},
			},
			Conditions: []capability.Condition{
				&capability.BlastRadiusCondition{MaxTotal: effNum("100"), WindowSeconds: 3600},
			},
		},
	}

	spend := func(session, tool string) capability.Decision {
		req := effectReq(tool, map[string]interface{}{"amount": jsonNumber("100")})
		req.SessionID = session
		return e.ValidateAction(context.Background(), req, caps).Decision
	}

	assert.Equal(t, capability.DecisionAllow, spend("a", "refund"))
	assert.Equal(t, capability.DecisionDeny, spend("a", "refund"), "session a's refund budget is spent")
	assert.Equal(t, capability.DecisionAllow, spend("b", "refund"), "session b has its own budget")
	assert.Equal(t, capability.DecisionAllow, spend("a", "payout"), "a different target has its own budget")
}

// TestBlastRadiusVelocity_NotConsumedUnderObserveMode pins the --audit posture: observe
// mode predicts what enforcement would do, and it must not spend the budget it is watching
// — the same inexactness maxCalls accepts there, for the same reason.
func TestBlastRadiusVelocity_NotConsumedUnderObserveMode(t *testing.T) {
	e := effectEngine(nil)
	caps := []capability.Constraint{refundConstraint("", "100", 3600)}
	ctx := enforcement.WithSkipQuota(context.Background())

	for i := 0; i < 5; i++ {
		resp := e.ValidateAction(ctx, effectReq("refund", map[string]interface{}{"amount": jsonNumber("100")}), caps)
		require.Equal(t, capability.DecisionAllow, resp.Decision, "observe mode must not consume the budget")
	}
	// Enforce mode still sees an untouched budget.
	assert.Equal(t, capability.DecisionAllow, refund(t, e, caps, "100").Decision)
}

// TestBlastRadiusVelocity_RunsAfterPurePredicates pins that the cumulative bound is a
// DEFERRED condition: a magnitude must never be charged to the window for a call some other
// predicate on the same constraint then denies.
func TestBlastRadiusVelocity_RunsAfterPurePredicates(t *testing.T) {
	e := effectEngine(nil)
	caps := []capability.Constraint{{
		Target:  "tool:refund",
		Actions: []string{"call"},
		Effect: &capability.EffectContract{
			Class:       capability.EffectIrreversible,
			BlastRadius: &capability.BlastRadiusSpec{Argument: "amount"},
		},
		Conditions: []capability.Condition{
			// Declared FIRST so a naive in-order evaluation would spend before this ran.
			&capability.BlastRadiusCondition{MaxTotal: effNum("100"), WindowSeconds: 3600},
			&capability.AllowedValuesCondition{Argument: "region", Values: []interface{}{"eu"}},
		},
	}}

	req := effectReq("refund", map[string]interface{}{"amount": jsonNumber("100"), "region": "us"})
	resp := e.ValidateAction(context.Background(), req, caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeAllowedValues, resp.Denial.ConditionType,
		"the pure predicate must decide before any budget is charged")

	// The budget was never touched, so a permitted call still fits.
	ok := effectReq("refund", map[string]interface{}{"amount": jsonNumber("100"), "region": "eu"})
	assert.Equal(t, capability.DecisionAllow, e.ValidateAction(context.Background(), ok, caps).Decision)
}

// TestBlastRadiusVelocity_PerCallOnlyCommitsNothing pins the other half of deferral: a
// per-call-only blastRadius consumes no budget, so it must keep behaving as the pure
// predicate it is even though its condition TYPE can commit. A constraint pairing it with a
// maxCalls must still work — that combination is legal and common.
func TestBlastRadiusVelocity_PerCallOnlyCommitsNothing(t *testing.T) {
	e := effectEngine(nil)
	caps := []capability.Constraint{{
		Target:  "tool:refund",
		Actions: []string{"call"},
		Effect: &capability.EffectContract{
			Class:       capability.EffectIrreversible,
			BlastRadius: &capability.BlastRadiusSpec{Argument: "amount"},
		},
		Conditions: []capability.Condition{
			&capability.BlastRadiusCondition{Max: effNum("500")},
			&capability.MaxCallsCondition{Count: 2, WindowSeconds: 3600},
		},
	}}

	assert.Equal(t, capability.DecisionAllow, refund(t, e, caps, "100").Decision)
	assert.Equal(t, capability.DecisionAllow, refund(t, e, caps, "100").Decision)
	third := refund(t, e, caps, "100")
	require.Equal(t, capability.DecisionDeny, third.Decision)
	assert.Equal(t, capability.ConditionTypeMaxCalls, third.Denial.ConditionType,
		"the maxCalls quota must still bind with a per-call blastRadius alongside it")

	// The per-call bound still fires on its own terms.
	over := e.ValidateAction(context.Background(),
		effectReq("refund", map[string]interface{}{"amount": jsonNumber("5000")}), caps)
	require.Equal(t, capability.DecisionDeny, over.Decision)
	assert.Equal(t, capability.ConditionTypeBlastRadius, over.Denial.ConditionType)
}

// TestBlastRadiusVelocity_RefusesAnUnenforceableCombination pins the engine's fail-closed
// backstop for the shape the manifest loader rejects. A weighted budget and a call count
// cannot be admitted in one atomic commit, so a programmatically built constraint carrying
// both must be REFUSED rather than committed separately — which would let a call the second
// bound denies spend the first's budget.
func TestBlastRadiusVelocity_RefusesAnUnenforceableCombination(t *testing.T) {
	e := effectEngine(nil)
	caps := []capability.Constraint{{
		Target:  "tool:refund",
		Actions: []string{"call"},
		Effect: &capability.EffectContract{
			Class:       capability.EffectIrreversible,
			BlastRadius: &capability.BlastRadiusSpec{Argument: "amount"},
		},
		Conditions: []capability.Condition{
			&capability.BlastRadiusCondition{MaxTotal: effNum("2000"), WindowSeconds: 3600},
			&capability.MaxCallsCondition{Count: 10, WindowSeconds: 3600},
		},
	}}

	resp := refund(t, e, caps, "10")
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.True(t, resp.Denial.HardDeny, "an unenforceable combination is a construction fault, not a downgradable verdict")
	assert.Contains(t, resp.Denial.Message, "cannot be admitted in one atomic commit")
}

// TestBlastRadiusVelocity_FailsClosedWithoutACounter pins that a policy declaring a
// cumulative bound with no counter backend wired denies rather than silently enforcing
// nothing.
func TestBlastRadiusVelocity_FailsClosedWithoutACounter(t *testing.T) {
	e := enforcement.New() // no WithCallCounter
	caps := []capability.Constraint{refundConstraint("", "2000", 3600)}

	resp := refund(t, e, caps, "10")
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Contains(t, resp.Denial.Message, "call counter not configured")
}

// TestBlastRadiusVelocity_FailsClosedWithoutASession pins the bucket-key guard: with no
// session id every anonymous caller's magnitude would merge into one budget.
func TestBlastRadiusVelocity_FailsClosedWithoutASession(t *testing.T) {
	e := effectEngine(nil)
	caps := []capability.Constraint{refundConstraint("", "2000", 3600)}

	req := effectReq("refund", map[string]interface{}{"amount": jsonNumber("10")})
	req.SessionID = ""
	resp := e.ValidateAction(context.Background(), req, caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
	assert.Contains(t, resp.Denial.Message, "sessionId is required")
}

// TestBlastRadiusVelocity_BoundlessConditionFailsClosed pins that a programmatically built
// condition carrying neither bound — or half a cumulative pair, which the loader rejects —
// denies rather than reading as "checked and fine".
func TestBlastRadiusVelocity_BoundlessConditionFailsClosed(t *testing.T) {
	e := effectEngine(nil)
	for _, cond := range []*capability.BlastRadiusCondition{
		{},                        // neither bound
		{MaxTotal: effNum("100")}, // a total with no window to sum it over
		{WindowSeconds: 3600},     // a window with nothing to bound
	} {
		caps := []capability.Constraint{{
			Target:     "tool:refund",
			Actions:    []string{"call"},
			Effect:     &capability.EffectContract{Class: capability.EffectReversible},
			Conditions: []capability.Condition{cond},
		}}
		resp := refund(t, e, caps, "10")
		require.Equal(t, capability.DecisionDeny, resp.Decision, "condition %+v must fail closed", cond)
		assert.True(t, strings.Contains(resp.Denial.Message, "bounds nothing"),
			"condition %+v: want a bounds-nothing refusal, got %q", cond, resp.Denial.Message)
	}
}

// TestBlastRadiusVelocity_UnsummableMagnitudeFailsClosed pins the precision rule: a
// magnitude the counter's IEEE-754 accumulator would have to ROUND is refused rather than
// summed approximately. A budget spent in approximated units is not the budget the operator
// authored.
func TestBlastRadiusVelocity_UnsummableMagnitudeFailsClosed(t *testing.T) {
	e := effectEngine(nil)
	caps := []capability.Constraint{refundConstraint("", "9007199254740992", 3600)}

	// 2^53 + 1: representable as a decimal literal and as a big.Float, not as a float64.
	resp := e.ValidateAction(context.Background(),
		effectReq("refund", map[string]interface{}{"amount": jsonNumber("9007199254740993")}), caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Contains(t, resp.Denial.Message, "too large to sum exactly")
}

// TestBlastRadiusVelocity_BackendFaultDenies pins the fail-closed posture on an
// infrastructure fault: an unreadable budget must never be mistaken for an unspent one.
func TestBlastRadiusVelocity_BackendFaultDenies(t *testing.T) {
	e := enforcement.New(enforcement.WithCallCounter(faultingWeightedCounter{}))
	caps := []capability.Constraint{refundConstraint("", "2000", 3600)}

	resp := refund(t, e, caps, "10")
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Contains(t, resp.Denial.Message, "could not be read")
}

// faultingWeightedCounter fails only the weighted path, so a test can isolate the
// backend-fault branch from a misconfiguration.
type faultingWeightedCounter struct{ *callcounter.InMemory }

func (faultingWeightedCounter) AddIfTotalBelow(_ context.Context, _ string, _ int, _, _ float64) (float64, bool, time.Duration, error) {
	return 0, false, 0, assert.AnError
}
