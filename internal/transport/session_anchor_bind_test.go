// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
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
// These pin where the refusal lands: on the SINK, not on the request. Each host request is
// decided, keyed and serialized on its own anchor, which is correct however many the session
// spans; the leg that cannot be decided that way is refused for the session's life.

// TestOwnerMismatch_PinsThePrincipalNotTheAnchor: the session gate is about IDENTITY. A second
// task on the same principal is admitted — spanning tasks over one long-lived connection is a
// normal shape for an agent runtime, and the reason task anchoring exists is that a task
// outlives a connection.
func TestOwnerMismatch_PinsThePrincipalNotTheAnchor(t *testing.T) {
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
		"same principal, DIFFERENT task is admitted (the sink pays, not the request)": {
			anchored, t1, t2, ""},
		"another token for the same task still matches": {
			anchored, t1, &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a", TaskID: "task-1", AgentID: "agent-9"}, ""},
		"a token carrying no task at all is admitted here (the engine refuses it on its own grounds)": {
			anchored, t1, &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a"}, ""},
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
				"the deny record must name WHICH pin failed, so an operator is not sent looking for a second client that does not exist")
		})
	}
}

// TestNoteRequestAnchor_SpanIsStickyAndScoped: the span is recorded per request, is one-way,
// and cannot arise at all on a route that does not anchor state on the task.
func TestNoteRequestAnchor_SpanIsStickyAndScoped(t *testing.T) {
	t.Parallel()
	t1 := &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a", TaskID: "task-1"}
	t2 := &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a", TaskID: "task-2"}

	sess := newTestSession(&httpSession{id: "sess-a", route: &UpstreamRoute{taskAnchored: true}, claims: t1})
	sess.noteRequestAnchor(t1)
	assert.False(t, sess.spansAnchors(), "the session's own anchor is not a span")
	sess.noteRequestAnchor(t2)
	assert.True(t, sess.spansAnchors(), "a second anchor is a span")
	sess.noteRequestAnchor(t1)
	assert.True(t, sess.spansAnchors(),
		"and it is STICKY: the taint written under the other anchor outlives the request that wrote it, "+
			"so returning to the original task does not make this leg decidable again")

	// On a session-anchored route every request resolves the session, so the question is vacuous.
	plain := newTestSession(&httpSession{id: "sess-b", route: &UpstreamRoute{}, claims: t1})
	plain.noteRequestAnchor(t2)
	assert.False(t, plain.spansAnchors())
}

// TestNoteRequestAnchor_LatchesOnlyOnADispatchedRequest: the span disables this session's
// sampling leg for its whole life, so only a message the leg actually DECIDES against an anchor
// may set it.
//
// The latch used to sit above the framing branches, right after negotiation, where the comment
// beside it said the opposite ("a refused message must not have written session state on its way
// to being refused"). Everything past negotiation was uncovered: one POST of a frame that is
// neither request, notification nor response — no id AND no method, which decodes fine because
// mcp.MsgReader does no framing validation — travelled to the bottom of the handler, was answered
// 202 as un-dispatchable, and had permanently disabled sampling on the way. So did a reply whose
// id this proxy never issued.
func TestNoteRequestAnchor_LatchesOnlyOnADispatchedRequest(t *testing.T) {
	t.Parallel()
	sessionTask := &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a", TaskID: "task-1"}
	otherTask := &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a", TaskID: "task-2"}

	for _, tc := range []struct {
		name string
		body string
		want bool
		// fill saturates the session's request pool first, so the POST below is refused by the
		// in-flight cap rather than dispatched.
		fill  bool
		notes string
	}{
		{
			name:  "a frame that is neither request, notification nor response",
			body:  `{"jsonrpc":"2.0","params":{"task":"other"}}`,
			notes: "discarded un-dispatched; one of these must not cost the connection its sampling leg",
		},
		{
			name:  "a reply whose id this proxy never issued",
			body:  `{"jsonrpc":"2.0","id":"never-issued","result":{}}`,
			notes: "routeHostServerResponse discards it unread, so it resolves no anchor",
		},
		{
			name:  "a refused notification",
			body:  `{"jsonrpc":"2.0","method":"agents/delegate"}`,
			notes: "a notification carries a token but is never decided against an anchor and commits no anchored state, so there is nothing for the sampling leg to peek past",
		},
		{
			name:  "a locally-answered request",
			body:  `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
			notes: "the re-initialize echo is answered from state captured at session start; it decides nothing against an anchor, so it must not cost the session its sampling leg",
		},
		{
			name:  "a request the in-flight cap refuses",
			body:  `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x","arguments":{}}}`,
			fill:  true,
			notes: "server-busy is retryable and decided nothing; latching here would let one saturating burst permanently disable sampling",
		},
		{
			name: "an enforced request",
			// Params the dispatcher refuses before the PDP, so the case needs no upstream: the
			// latch is about which requests are KEYED on an anchor, and this one is — it takes
			// the decision turn on the same predicate.
			body:  `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{}}`,
			want:  true,
			notes: "the case the latch exists for: an enforced method, admitted, keyed on an anchor that is not the session's",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			route := &UpstreamRoute{name: "up1", pdp: pdp.AlwaysAllowPDP{}, taskAnchored: true}
			proxy := newTestHTTPProxy()
			sess := newTestSession(&httpSession{
				id: "live-sess", route: route, claims: sessionTask, hostRev: handshakeRevision, done: make(chan struct{}),
			})
			proxy.sessions[sess.id] = sess
			if tc.fill {
				for sess.tryAcquireRequestSlot() { //nolint:revive // drain the pool: the next POST must meet a full one
				}
			}

			var msg mcp.RPCMsg
			if err := mcp.DecodeParams([]byte(tc.body), &msg); err != nil {
				t.Fatalf("decoding the test message: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(tc.body)).
				WithContext(pdp.WithJWTClaims(context.Background(), otherTask))
			req.Header.Set(SessionHeader, sess.id)
			proxy.handleSessionPost(httptest.NewRecorder(), req, route, sess.id, msg)

			if got := sess.spansAnchors(); got != tc.want {
				t.Errorf("spansAnchors() = %v, want %v — %s", got, tc.want, tc.notes)
			}
		})
	}
}

// TestTaskAnchoredSession_SourceTaintIsVisibleToTheSamplingSink is the acceptance test for the
// whole shape. A flowLabel sink on system:sampling/createMessage exists to stop an egress the
// session is tainted for; on a task-anchored route the taint is keyed on the validated task.
//
// The host leg records it under the REQUEST's task and the sampling leg peeks under the
// SESSION's, so the two legs must be reading one anchor for the sink to see anything at all.
// Both halves are asserted together: while the session stays on one anchor the sink sees the
// taint, and the moment it spans, the sink is refused outright rather than peeking a bucket
// nothing is tainting.
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

	// A sampling request BEFORE any source runs is clean, so the deny below is the taint and
	// not a deny-by-default.
	samplingLeg := func() capability.EnforceResponse {
		fp := serverRequestParams{
			sessionID: sess.id,
			claims:    sess.claims,
			decideLock: func() (func(), bool) {
				return sess.beginDecisionTurnWithin(samplingTurnWait)
			},
			anchorSplit: sess.spansAnchors,
			pdp:         rt.pdp,
		}
		// forwardServerRequest attaches fp.claims to the decision context; this drives the
		// decision half directly, so it does the same.
		return fp.decideSampling(pdp.WithJWTClaims(context.Background(), fp.claims))
	}
	require.Equal(t, capability.DecisionAllow, samplingLeg().Decision,
		"an untainted session must be allowed, or the assertion below proves nothing")

	// The host leg taints, reading the REQUEST's claims — a DISTINCT token for the same task,
	// which is what a long-lived session actually carries.
	hostClaims := &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a", TaskID: "task-1", AgentID: "agent-9"}
	sess.noteRequestAnchor(hostClaims)
	require.False(t, sess.spansAnchors(), "the same task is not a span")
	src := dp.Decide(pdp.WithJWTClaims(context.Background(), hostClaims), sess.id,
		pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "read_secret"}, map[string]interface{}{}, "")
	require.Equal(t, capability.DecisionAllow, src.Decision, "the source read must be allowed: %+v", src.Denial)

	// ...and the sampling sink, reading the SESSION's claims, must see it.
	dec := samplingLeg()
	require.Equal(t, capability.DecisionDeny, dec.Decision,
		"the sampling sink peeked a different anchor than the source tainted — the egress the label exists to stop was forwarded")
	require.NotNil(t, dec.Denial)
	assert.Equal(t, capability.ConditionTypeFlowLabel, dec.Denial.ConditionType)
}

// TestTaskAnchoredSession_SpanningRefusesTheSinkNotTheRequest is the other horn, and the
// security-relevant one. A source tainting under a SECOND task leaves the session's own anchor
// clean, so a sink that went on deciding against the captured claims would allow the very
// egress the label exists to stop. The host request is admitted (its own bucket is tainted
// correctly); the sink is refused for the rest of the session's life.
func TestTaskAnchoredSession_SpanningRefusesTheSinkNotTheRequest(t *testing.T) {
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

	sess := newTestSession(&httpSession{id: "sess-a", route: rt,
		claims: &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a", TaskID: "task-1"}})
	sess.holdDecisionGate()
	t.Cleanup(sess.dropDecideGate)

	samplingLeg := func() capability.EnforceResponse {
		fp := serverRequestParams{
			sessionID:   sess.id,
			claims:      sess.claims,
			anchorSplit: sess.spansAnchors,
			pdp:         rt.pdp,
		}
		return fp.decideSampling(pdp.WithJWTClaims(context.Background(), fp.claims))
	}
	require.Equal(t, capability.DecisionAllow, samplingLeg().Decision, "clean session, clean sink")

	// The second task's request is ADMITTED and taints its own bucket.
	second := &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a", TaskID: "task-2"}
	sess.noteRequestAnchor(second)
	require.True(t, sess.spansAnchors(), "a second anchor on one session is a span")
	src := dp.Decide(pdp.WithJWTClaims(context.Background(), second), sess.id,
		pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "read_secret"}, map[string]interface{}{}, "")
	require.Equal(t, capability.DecisionAllow, src.Decision,
		"a request for a second task is decided on its OWN anchor and must not be refused: %+v", src.Denial)

	// The sink cannot be decided at all now: the session's own anchor is clean, and allowing on
	// that basis is the fail-open this refusal exists to prevent.
	dec := samplingLeg()
	require.Equal(t, capability.DecisionDeny, dec.Decision,
		"the sink peeked the session's clean anchor while another task carried the taint")
	require.NotNil(t, dec.Denial)
	assert.True(t, dec.Denial.BlockOverride, "an --audit route must not downgrade this into the forward it prevents")
	assert.Equal(t, capability.ConditionTypeFlowLabel, dec.Denial.ConditionType)
	assert.Equal(t, "session_spans_anchors", dec.Denial.Details["reason"])

	// Sticky: even a sampling request while the session is back on its original task stays
	// refused, because the other task's taint outlives the request that wrote it.
	sess.noteRequestAnchor(sess.claims)
	require.True(t, sess.spansAnchors(), "the span does not clear")
	assert.Equal(t, capability.DecisionDeny, samplingLeg().Decision)
}

// TestSamplingLeg_AnchorSplitIsRecheckedAfterTheTurn: the gap between the first check and the
// flow peek it guards is the whole turn wait — bounded by samplingTurnWait, not by anything
// about this session — and the host leg can span its second anchor at any point inside it. The
// two anchors take different gates, so the turn provides no ordering; only a re-check does.
func TestSamplingLeg_AnchorSplitIsRecheckedAfterTheTurn(t *testing.T) {
	t.Parallel()
	dp := pdp.NewManifestPDP([]capability.Constraint{
		{Target: "system:sampling/createMessage", Actions: []string{"allow"}},
	}, enforcement.New(), killswitch.NewInMemory())

	spanned := false
	fp := serverRequestParams{
		sessionID:   "sess-a",
		anchorSplit: func() bool { return spanned },
		// The host leg spans its second anchor WHILE this leg waits for the turn.
		decideLock: func() (func(), bool) { spanned = true; return func() {}, true },
		pdp:        dp,
	}
	dec := fp.decideSampling(context.Background())
	require.Equal(t, capability.DecisionDeny, dec.Decision,
		"a span that lands during the turn wait must be caught: the peek that follows would read the wrong anchor")
	require.NotNil(t, dec.Denial)
	assert.Equal(t, "session_spans_anchors", dec.Denial.Details["reason"])
}
