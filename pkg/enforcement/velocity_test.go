// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"context"
	"errors"
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

// TestBlastRadiusVelocity_ObserveStillEvaluatesThePerCallBound pins the half of a
// condition observe mode must NOT skip. Only the cumulative bound consumes quota; the
// per-call bound is a pure predicate that costs nothing to evaluate, so an --audit route
// must still report the deny it would have produced — that is the entire point of running
// one before enforcing.
//
// This is where the two evaluation paths had diverged. The per-call check lived on the
// commit side of the deferral, so a constraint routed through the deferred pass skipped it
// wholesale under observe while the same condition evaluated it when it reached the handler
// directly: the same policy predicting two different verdicts depending on how many
// deferred conditions the constraint happened to carry.
func TestBlastRadiusVelocity_ObserveStillEvaluatesThePerCallBound(t *testing.T) {
	e := effectEngine(nil)
	// One condition carrying BOTH bounds: the per-call bound must be reported, the
	// cumulative one must not be charged.
	caps := []capability.Constraint{refundConstraint("500", "100000", 3600)}
	ctx := enforcement.WithSkipQuota(context.Background())

	over := e.ValidateAction(ctx, effectReq("refund", map[string]interface{}{"amount": jsonNumber("5000")}), caps)
	require.Equal(t, capability.DecisionDeny, over.Decision,
		"observe mode must still predict the per-call deny; it consumes no quota to check")
	require.NotNil(t, over.Denial)
	assert.Equal(t, capability.ConditionTypeBlastRadius, over.Denial.ConditionType)

	// A call inside the per-call bound is allowed and spends nothing, so enforce mode still
	// sees the whole budget.
	under := e.ValidateAction(ctx, effectReq("refund", map[string]interface{}{"amount": jsonNumber("100")}), caps)
	assert.Equal(t, capability.DecisionAllow, under.Decision)

	// The same verdict must hold when the constraint carries a SECOND deferred condition,
	// which is what routes it through the multi-bucket commit rather than the single one.
	both := []capability.Constraint{{
		Target:  "tool:refund",
		Actions: []string{"call"},
		Effect: &capability.EffectContract{
			Class:       capability.EffectCompensable,
			BlastRadius: &capability.BlastRadiusSpec{Argument: "amount", Unit: "usd"},
		},
		Conditions: []capability.Condition{
			&capability.BlastRadiusCondition{Max: effNum("500"), MaxTotal: effNum("100000"), WindowSeconds: 3600},
			&capability.MaxCallsCondition{Count: 100, WindowSeconds: 3600},
		},
	}}
	multi := e.ValidateAction(ctx, effectReq("refund", map[string]interface{}{"amount": jsonNumber("5000")}), both)
	require.Equal(t, capability.DecisionDeny, multi.Decision,
		"the per-call bound must be reported identically on the multi-bucket path")
	assert.Equal(t, capability.ConditionTypeBlastRadius, multi.Denial.ConditionType)
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

// TestBlastRadiusVelocity_CumulativeAndMaxCallsCommitTogether pins the combination the
// two accountings exist to support: "at most 10 refunds AND at most 2000 units per hour",
// on ONE capability. The call count and the weighted budget are different questions about
// the same call, and a policy author needs both — so they are prepared together and
// admitted in ONE atomic commit, each bound binding on its own terms and neither spending
// the other's budget when it denies.
func TestBlastRadiusVelocity_CumulativeAndMaxCallsCommitTogether(t *testing.T) {
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
			&capability.MaxCallsCondition{Count: 3, WindowSeconds: 3600},
		},
	}}

	// Two small refunds sit inside both bounds.
	require.Equal(t, capability.DecisionAllow, refund(t, e, caps, "10").Decision)
	require.Equal(t, capability.DecisionAllow, refund(t, e, caps, "10").Decision)

	// A large one exceeds the weighted budget while the call count still has headroom:
	// the WEIGHTED bound is the one that denies.
	big := refund(t, e, caps, "5000")
	require.Equal(t, capability.DecisionDeny, big.Decision)
	assert.Equal(t, capability.ConditionTypeBlastRadius, big.Denial.ConditionType,
		"the weighted budget must be the reported blocker")

	// That denial spent no call slot: the third small refund is admitted, and only the
	// FOURTH trips the count.
	require.Equal(t, capability.DecisionAllow, refund(t, e, caps, "10").Decision,
		"a weighted denial must not have burned a call slot")
	fourth := refund(t, e, caps, "10")
	require.Equal(t, capability.DecisionDeny, fourth.Decision)
	assert.Equal(t, capability.ConditionTypeMaxCalls, fourth.Denial.ConditionType,
		"the call count must be the reported blocker once it binds")

	// And the count's denial spent no magnitude budget either: 30 units are recorded, so
	// a fresh capability with a 40-unit budget on the same session still admits 10 more.
	loose := []capability.Constraint{{
		Target:  "tool:refund",
		Actions: []string{"call"},
		Effect: &capability.EffectContract{
			Class:       capability.EffectIrreversible,
			BlastRadius: &capability.BlastRadiusSpec{Argument: "amount"},
		},
		Conditions: []capability.Condition{
			&capability.BlastRadiusCondition{MaxTotal: effNum("40"), WindowSeconds: 3600},
		},
	}}
	assert.Equal(t, capability.DecisionAllow, refund(t, e, loose, "10").Decision,
		"a count denial must not have charged the weighted sibling")
}

// TestBlastRadiusVelocity_FailsClosedWithoutACounter pins that a policy declaring a
// cumulative bound with no counter backend wired denies rather than silently enforcing
// nothing — and, load-bearingly, denies as a FAULT.
//
// The code is the whole security property, not a label: this refusal used to carry the policy
// code CONDITION_FAILED, which DenialInfo.Downgradable answers true for, so an observing
// posture (an --audit route, or a per-constraint enforcement: audit) forwarded the call with
// the cumulative budget neither checked nor counted. An unwired counter is the engine's own
// state and the bound was never evaluated, so there is no verdict for any posture to downgrade.
func TestBlastRadiusVelocity_FailsClosedWithoutACounter(t *testing.T) {
	e := enforcement.New() // no WithCallCounter
	caps := []capability.Constraint{refundConstraint("", "2000", 3600)}

	resp := refund(t, e, caps, "10")
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Contains(t, resp.Denial.Message, "call counter not configured")
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code,
		"an unwired counter is a fault, matching every sibling bucket derivation")
	assert.False(t, resp.Denial.Downgradable(),
		"no observing posture may forward this call: the cumulative budget was never checked")
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

// TestBlastRadiusVelocity_FractionalMagnitudesAreSummable is the regression for the
// feature's own headline case. The magnitude is parsed at 64-bit precision, so narrowing it
// to a float64 mantissa reports "inexact" for any decimal that is not dyadic — which is
// most currency amounts. Requiring exactness therefore DENIED a $19.99 refund under a
// $2,000-an-hour bound, with a message calling it "too large". A rounded fractional
// magnitude is summable; both counter backends accumulate in double precision by contract.
func TestBlastRadiusVelocity_FractionalMagnitudesAreSummable(t *testing.T) {
	e := effectEngine(nil)
	caps := []capability.Constraint{refundConstraint("", "2000", 3600)}

	for _, amount := range []string{"19.99", "0.1", "3.7", "1234.56"} {
		resp := refund(t, e, caps, amount)
		require.Equal(t, capability.DecisionAllow, resp.Decision,
			"a $%s refund is well inside a $2,000 bound and must be summable", amount)
	}
	// And the bound still binds: the accumulated fractional total is real.
	assert.Equal(t, capability.DecisionDeny, refund(t, e, caps, "1000").Decision,
		"19.99 + 0.1 + 3.7 + 1234.56 + 1000 exceeds 2000")
}

// TestBlastRadiusVelocity_UnsummableMagnitudeFailsClosed pins the range rule that survives:
// a magnitude the accumulator cannot represent AT ALL — above the 2^53 bound where the
// Redis backend's Lua arithmetic stops being exact — is refused rather than summed.
func TestBlastRadiusVelocity_UnsummableMagnitudeFailsClosed(t *testing.T) {
	e := effectEngine(nil)
	caps := []capability.Constraint{refundConstraint("", "9007199254740992", 3600)}

	resp := e.ValidateAction(context.Background(),
		effectReq("refund", map[string]interface{}{"amount": jsonNumber("1e30")}), caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Contains(t, resp.Denial.Message, "outside the range")
}

// TestBlastRadiusVelocity_CeilingRefusalSpendsNoBudget pins the ordering the two-pass
// evaluation exists for: the effect ceiling refuses a call that is never forwarded, so it
// must not have charged that call's magnitude to the window. With the commit inside the
// first pass, four over-ceiling escalations exhausted a session's whole hourly budget and
// denied the legal calls that followed — an injected agent locking out the budget with
// calls it was never allowed to make.
func TestBlastRadiusVelocity_CeilingRefusalSpendsNoBudget(t *testing.T) {
	e := effectEngine(&capability.EffectCeiling{MaxBlastRadius: effNum("100")})
	caps := []capability.Constraint{refundConstraint("", "2000", 3600)}

	for i := 0; i < 4; i++ {
		resp := refund(t, e, caps, "500")
		require.Equal(t, capability.DecisionEscalate, resp.Decision, "over-ceiling call %d", i+1)
	}
	resp := refund(t, e, caps, "10")
	require.Equal(t, capability.DecisionAllow, resp.Decision,
		"refusals that were never forwarded must not have spent the budget; got %+v", resp.Denial)
}

// TestBlastRadiusVelocity_RetryHintIsUsable pins that the retry estimate goes through the
// shared helper: a sub-second wait must round UP rather than truncate to 0 (which tells a
// caller to retry immediately into a guaranteed denial), and an unavailable estimate must
// fall back to the window rather than omitting the hint.
func TestBlastRadiusVelocity_RetryHintIsUsable(t *testing.T) {
	e := effectEngine(nil)
	caps := []capability.Constraint{refundConstraint("", "100", 3600)}
	require.Equal(t, capability.DecisionAllow, refund(t, e, caps, "100").Decision)

	resp := refund(t, e, caps, "100")
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	hint, ok := resp.Denial.Details["retry_after_seconds"].(int64)
	require.True(t, ok, "a cumulative denial must always carry a retry hint, got %v", resp.Denial.Details)
	assert.Positive(t, hint, "a retry hint of 0 sends the caller straight back into a denial")
}

// TestBlastRadiusVelocity_BackendFaultDenies pins the fail-closed posture on an
// infrastructure fault: an unreadable budget must never be mistaken for an unspent one.
// Which bound faulted is reported STRUCTURALLY (the denial's ConditionType), not in the
// message — the message names the counter fault and nothing else, so an operator selects
// on the field rather than parsing prose.
func TestBlastRadiusVelocity_BackendFaultDenies(t *testing.T) {
	e := enforcement.New(enforcement.WithCallCounter(erroringCounter{err: assert.AnError}))
	caps := []capability.Constraint{refundConstraint("", "2000", 3600)}

	resp := refund(t, e, caps, "10")
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeBlastRadius, resp.Denial.ConditionType,
		"the faulting bound must be identified structurally")
	assert.Contains(t, resp.Denial.Message, "call counter error")
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.False(t, resp.Denial.Downgradable())
}

// TestBlastRadiusVelocity_RetentionCeilingIsAFault pins the code docs/effect-contracts.md
// names for the weighted retention ceiling.
//
// The ceiling arrives from the counter as an ERROR, and commitDeferredConditions reads err
// before the refused-admission branch — so the refusal is ENFORCEMENT_ERROR, not the
// CONDITION_FAILED the doc used to promise, and an operator's SIEM rule for a session hitting
// the ceiling never fired. It is also the right code: nothing evaluated the bound, so no
// observing route may forward past it.
func TestBlastRadiusVelocity_RetentionCeilingIsAFault(t *testing.T) {
	e := enforcement.New(enforcement.WithCallCounter(erroringCounter{err: errors.New("callcounter: weighted entry limit reached (100000 entries in one window)")}))
	caps := []capability.Constraint{refundConstraint("", "2000", 3600)}

	resp := refund(t, e, caps, "10")
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.False(t, resp.Denial.Downgradable())
	assert.Contains(t, resp.Denial.Message, "weighted entry limit")
}

// erroringCounter fails the admission path with a caller-chosen error, so a test can isolate
// the backend-fault branch from a misconfiguration. Parameterized rather than one stub per
// error: a second copy has to be edited in lockstep with any change to the CallCounter
// interface, and a partial edit stops satisfying it at only one of the two call sites.
type erroringCounter struct {
	*callcounter.InMemory
	err error
}

func (c erroringCounter) AdmitAll(_ context.Context, _ []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	return false, 0, 0, 0, c.err
}
