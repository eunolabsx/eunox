// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"testing"

	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
	"github.com/eunolabs/eunox/pkg/killswitch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A session has two legs that decide, and only one of them has a request in scope. The host leg
// reads the current request's validated claims; the server-initiated (sampling) leg has no host
// request at all and reads the claims captured at initialize. Under task-anchored state those
// are two different state anchors for one session as soon as a caller sends a second token that
// differs only in mcp.task_id — which sub/iss alone accepted.
//
// These pin the fix: a session on a task-anchored route is bound to its ANCHOR, so the two legs
// cannot be reading different buckets, and the taint a host source records is the taint the
// sampling sink peeks.

// TestOwnerMismatch_TaskAnchoredSessionIsBoundToItsAnchor is the gate. The principal pin
// (iss+sub) accepts two tokens that differ only in task_id, which is exactly the pair that
// splits the two legs' state.
func TestOwnerMismatch_TaskAnchoredSessionIsBoundToItsAnchor(t *testing.T) {
	t.Parallel()
	anchored := &UpstreamRoute{taskAnchored: true}
	sessionOnly := &UpstreamRoute{}
	t1 := &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a", TaskID: "task-1"}
	t2 := &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a", TaskID: "task-2"}

	for name, tc := range map[string]struct {
		route      *UpstreamRoute
		sess, cur  *pdp.JWTClaims
		wantReason string
	}{
		"same principal, same task": {anchored, t1, t1, ""},
		"same principal, DIFFERENT task is refused": {
			anchored, t1, t2, "session_anchor_mismatch"},
		"another token for the same task still matches": {
			anchored, t1, &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a", TaskID: "task-1", AgentID: "agent-9"}, ""},
		"a token carrying no task at all is refused": {
			anchored, t1, &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a"}, "session_anchor_mismatch"},
		"an UNBOUND session cannot be joined by a tokened request either": {
			anchored, nil, t1, "session_anchor_mismatch"},
		"an unbound session with untokened requests is unaffected": {
			anchored, nil, nil, ""},
		"a different principal is still an owner mismatch": {
			anchored, t1, &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-b", TaskID: "task-1"}, "session_owner_mismatch"},
		"a route that does not anchor on the task ignores the task entirely": {
			sessionOnly, t1, t2, ""},
		"and still pins the principal there": {
			sessionOnly, t1, &pdp.JWTClaims{Issuer: "iss-b", Subject: "sub-a"}, "session_owner_mismatch"},
		"a bound session refuses an identity-less request": {
			sessionOnly, t1, nil, "session_owner_mismatch"},
	} {
		t.Run(name, func(t *testing.T) {
			sess := newTestSession(&httpSession{id: "sess-a", route: tc.route, claims: tc.sess})
			reason, mismatch := sess.ownerMismatch(tc.cur)
			assert.Equal(t, tc.wantReason != "", mismatch)
			assert.Equal(t, tc.wantReason, reason,
				"the deny record must name WHICH pin failed: an anchor refusal reported as an owner "+
					"mismatch sends an operator looking for a second client that does not exist")
		})
	}
}

// TestTaskAnchoredSession_SourceTaintIsVisibleToTheSamplingSink is the acceptance test for the
// whole shape. A flowLabel sink on system:sampling/createMessage exists to stop an egress the
// session is tainted for; on a task-anchored route the taint is keyed on the validated task.
//
// The host leg records it under the REQUEST's task and the sampling leg peeks under the
// SESSION's, so the two legs must be reading one anchor for the sink to see anything at all.
// The session gate is what guarantees that, and the two halves are asserted together here: with
// the tokens the gate admits, the sink denies; the token that would have split the buckets is
// refused before it can taint one of them.
func TestTaskAnchoredSession_SourceTaintIsVisibleToTheSamplingSink(t *testing.T) {
	t.Parallel()
	engine := enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
		enforcement.WithTaskAnchoredState(),
	)
	caps := []capability.Constraint{
		{Target: "tool:read_secret", Actions: []string{"call"},
			Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelConfidential}}}},
		{Target: "system:sampling/createMessage", Actions: []string{"allow"},
			Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic}}}},
	}
	dp := pdp.NewManifestPDP(caps, engine, killswitch.NewInMemory())
	rt := &UpstreamRoute{name: "up1", pdp: dp, taskAnchored: true, decideGates: newAnchorGates()}

	sessClaims := &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a", TaskID: "task-1"}
	sess := newTestSession(&httpSession{id: "sess-a", route: rt, claims: sessClaims})
	sess.holdDecisionGate()
	t.Cleanup(sess.dropDecideGate)

	// The token that would have split the two legs is refused before it can taint anything.
	splitting := &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a", TaskID: "task-2"}
	reason, mismatch := sess.ownerMismatch(splitting)
	require.True(t, mismatch, "a second task on this session must not be admitted")
	require.Equal(t, "session_anchor_mismatch", reason)

	// A sampling request BEFORE any source runs is clean, so the deny below is the taint and
	// not a deny-by-default.
	samplingLeg := func() capability.EnforceResponse {
		fp := serverRequestParams{
			sessionID: sess.id,
			claims:    sess.claims,
			decideLock: func() (func(), bool) {
				return sess.beginDecisionTurnWithin(samplingTurnWait)
			},
		}.withPDP(rt.pdp)
		// forwardServerRequest attaches fp.claims to the decision context; this drives the
		// decision half directly, so it does the same.
		return fp.decideSampling(pdp.WithJWTClaims(context.Background(), fp.claims))
	}
	require.Equal(t, capability.DecisionAllow, samplingLeg().Decision,
		"an untainted session must be allowed, or the assertion below proves nothing")

	// The host leg taints, reading the REQUEST's claims — a DISTINCT token for the same task,
	// which is what the gate admits and what a long-lived session actually carries.
	hostCtx := pdp.WithJWTClaims(context.Background(),
		&pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a", TaskID: "task-1", AgentID: "agent-9"})
	src := dp.Decide(hostCtx, sess.id,
		pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "read_secret"}, map[string]interface{}{}, "")
	require.Equal(t, capability.DecisionAllow, src.Decision, "the source read must be allowed: %+v", src.Denial)

	// ...and the sampling sink, reading the SESSION's claims, must see it.
	dec := samplingLeg()
	require.Equal(t, capability.DecisionDeny, dec.Decision,
		"the sampling sink peeked a different anchor than the source tainted — the egress the label exists to stop was forwarded")
	require.NotNil(t, dec.Denial)
	assert.Equal(t, capability.ConditionTypeFlowLabel, dec.Denial.ConditionType)

	// The negative control, and the reason the gate is a security fix rather than tidiness: the
	// SAME source tainting under a second task leaves the session's anchor clean, so the sink
	// allows. Driven against the PDP directly, below the gate — which is the only thing standing
	// between a caller holding two tokens and this outcome.
	splitCtx := pdp.WithJWTClaims(context.Background(), splitting)
	other := dp.Decide(splitCtx, sess.id,
		pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "read_secret"}, map[string]interface{}{}, "")
	require.Equal(t, capability.DecisionAllow, other.Decision)
	clean := serverRequestParams{
		sessionID: "sess-b",
		claims:    &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a", TaskID: "task-3"},
	}.withPDP(rt.pdp)
	assert.Equal(t, capability.DecisionAllow,
		clean.decideSampling(pdp.WithJWTClaims(context.Background(), clean.claims)).Decision,
		"a taint recorded under another task is invisible here — which is exactly what the session's anchor pin refuses to let happen")
}
