// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The server-initiated leg's one rule, asserted per drop site rather than per transport: eunox
// answers a blocked initiator wherever it can do so without acting on a second identity's behalf,
// and the two exceptions (a revocation, and a refusal that turned on WHO SENT the reply) are the
// only sites that leave one hanging.

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// sinkFunc adapts a function to mcp.MsgSink, which is what serverRequestUnblocker holds now that
// the writer is resolved at answer time rather than at wiring time. A test that wants to observe
// (or fail) the answer supplies one of these instead of a live *mcp.MsgWriter.
type sinkFunc func(mcp.RPCMsg) error

func (f sinkFunc) Write(msg mcp.RPCMsg) error { return f(msg) }

// upstreamReplies decodes every JSON-RPC message a test's upstream sink received.
func upstreamReplies(t *testing.T, raw string) []mcp.RPCMsg {
	t.Helper()
	var out []mcp.RPCMsg
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if line == "" {
			continue
		}
		var msg mcp.RPCMsg
		require.NoError(t, json.Unmarshal([]byte(line), &msg), "upstream sink received a non-JSON frame: %q", line)
		out = append(out, msg)
	}
	return out
}

// fillServerReqTracker tracks maxTrackedServerReqs distinct ids through u, so the next track()
// must displace one. WHICH one is asserted separately (see the longest-waiting test); here the
// point is only that the set is at its cap.
func fillServerReqTracker(t *testing.T, u serverRequestUnblocker) {
	t.Helper()
	for i := range maxTrackedServerReqs {
		_, displaced := u.reqs.track(mcp.RPCMsg{ID: mcp.RawJSON(jsonNumber(i)), Method: "roots/list"}, io.Discard)
		require.False(t, displaced, "filling to the cap must displace nothing")
	}
}

func jsonNumber(i int) string { return string(mustJSON(i)) }

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// TestServerRequestDisplacement_AnswersAndRecordsTheDisplacedInitiator is the regression for a
// server-initiated request the bounded tracker dropped on the floor.
//
// Past the cap a tracked request is displaced to keep the set bounded. The displacement itself is
// the safe half; what was missing is that nothing then answered the request it removed. Its entry
// is gone, so both transports' routing arms drop even a CORRECT host reply to it as untracked —
// the upstream stays blocked on a request nothing could ever complete, on stdio until the host
// disconnects, and nothing on the tape said which request it cost.
//
// A displacement is neither of the leg's exceptions: not a refusal of the peer, not an emergency
// stop, but eunox running out of bookkeeping space — the case where it most clearly owes the
// upstream an answer it can produce entirely on its own.
func TestServerRequestDisplacement_AnswersAndRecordsTheDisplacedInitiator(t *testing.T) {
	t.Parallel()
	var up bytes.Buffer
	var reqs serverReqTracker
	u := serverRequestUnblocker{
		reqs:   &reqs,
		sink:   sinkFunc(func(m mcp.RPCMsg) error { _, _ = up.Write(append(mustJSON(m), '\n')); return nil }),
		errOut: io.Discard,
	}
	fillServerReqTracker(t, u)

	rec := &fwdRecorder{}
	trackServerRequest(context.Background(), u, refusalLimits{records: newRefusalRecordLimiter()}.recorders(rec), verifiedSession("sess-evict"), dropStdioDisplaced,
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`"the-newest"`), Method: "sampling/createMessage"})

	replies := upstreamReplies(t, up.String())
	require.Len(t, replies, 1, "the displaced request's initiator must be answered exactly once")
	require.NotNil(t, replies[0].Error, "the answer must be a JSON-RPC error; a result would claim the host performed something")
	assert.Equal(t, capability.JSONRPCCodeEnforcementError, replies[0].Error.Code)
	assert.Contains(t, replies[0].Error.Message, "displaced",
		"the answer names the proxy's own bookkeeping: a displacement relays nothing the host said, so the text is eunox's own")

	require.Len(t, rec.records, 1, "a displaced request is a call the proxy actively failed and must reach the tape")
	assert.Equal(t, "deny", rec.records[0].decision)
	assert.Equal(t, capability.ErrCodeEnforcementError, rec.records[0].code)
	assert.Equal(t, string(dropStdioDisplaced), rec.records[0].details["transport"],
		"the record must name the drop site, so a displacement is distinguishable from an undelivered broadcast")
	assert.Equal(t, "roots/list", rec.records[0].identifier,
		"the record names the DISPLACED request's method, which is why the tracker remembers more than an id")
}

// TestServerRequestDisplacement_TakesTheLongestWaiting pins WHICH request an over-capacity track
// sacrifices. An arbitrary map-order pick was tolerable while a displacement merely left a request
// to hang; it is not once the displacement actively answers the initiator, because a random pick
// is as likely to abort a request the host is about to answer correctly as one that is stuck.
func TestServerRequestDisplacement_TakesTheLongestWaiting(t *testing.T) {
	t.Parallel()
	var reqs serverReqTracker
	// The first id tracked is the one that has waited longest, so it is the one displaced.
	_, _ = reqs.track(mcp.RPCMsg{ID: mcp.RawJSON(`"oldest"`), Method: "roots/list"}, io.Discard)
	for i := 1; i < maxTrackedServerReqs; i++ {
		_, _ = reqs.track(mcp.RPCMsg{ID: mcp.RawJSON(jsonNumber(i)), Method: "roots/list"}, io.Discard)
	}
	displaced, ok := reqs.track(mcp.RPCMsg{ID: mcp.RawJSON(`"newest"`), Method: "roots/list"}, io.Discard)
	require.True(t, ok)
	assert.Equal(t, `"oldest"`, string(*displaced.id),
		"the displaced request must be the longest-waiting one, not whichever the map's randomized range yielded")
}

// TestServerRequestTracking_AReusedIDDisplacesRatherThanVanishing closes the second way an entry
// leaves the set. mcp.MsgKey canonicalizes by VALUE, so an upstream issuing `1` and then `1.0`
// collides two distinct wire requests onto one entry — and while the map's value was a struct{}
// the overwrite lost nothing, so nothing reported it. Now the entry carries what answering the
// first initiator needs, and losing it silently is the same hang the cap path was fixed for.
func TestServerRequestTracking_AReusedIDDisplacesRatherThanVanishing(t *testing.T) {
	t.Parallel()
	var up bytes.Buffer
	var reqs serverReqTracker
	rec := &fwdRecorder{}
	u := serverRequestUnblocker{
		reqs:   &reqs,
		sink:   sinkFunc(func(m mcp.RPCMsg) error { _, _ = up.Write(append(mustJSON(m), '\n')); return nil }),
		errOut: io.Discard,
	}
	ctx, lim := context.Background(), newRefusalRecordLimiter()
	trackServerRequest(ctx, u, refusalLimits{records: lim}.recorders(rec), verifiedSession("s"), dropStdioDisplaced,
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "roots/list"})
	require.Empty(t, up.String(), "the first track displaces nothing")

	trackServerRequest(ctx, u, refusalLimits{records: lim}.recorders(rec), verifiedSession("s"), dropStdioDisplaced,
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1.0`), Method: "sampling/createMessage"})

	replies := upstreamReplies(t, up.String())
	require.Len(t, replies, 1, "the request whose entry was overwritten must be answered: nothing can route a reply to it afterwards")
	assert.Equal(t, "n:1", mcp.MsgKey(replies[0].ID))
	require.Len(t, rec.records, 1)
	assert.Equal(t, "roots/list", rec.records[0].identifier, "the record names the DISPLACED request")
}

// TestServerRequestDisplacement_BelowTheCapAnswersNothing is the other half: the answer above must
// be forced by an actual displacement, not written for every tracked request.
func TestServerRequestDisplacement_BelowTheCapAnswersNothing(t *testing.T) {
	t.Parallel()
	var up bytes.Buffer
	var reqs serverReqTracker
	rec := &fwdRecorder{}
	u := serverRequestUnblocker{
		reqs:   &reqs,
		sink:   sinkFunc(func(m mcp.RPCMsg) error { _, _ = up.Write(append(mustJSON(m), '\n')); return nil }),
		errOut: io.Discard,
	}
	trackServerRequest(context.Background(), u, refusalLimits{records: newRefusalRecordLimiter()}.recorders(rec), verifiedSession("sess"), dropStdioDisplaced,
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "sampling/createMessage"})
	assert.Empty(t, up.String(), "tracking below the cap displaces nothing, so nothing may be answered")
	assert.Empty(t, rec.records)
	assert.True(t, reqs.tracked("n:1"), "the request just tracked must still be routable")
}

// TestServerRequestDisplacement_RecordIsMetered pins the bound on a record source the UPSTREAM
// drives. Once the set is full every further server-initiated request displaces one, so an
// upstream that outruns a slow host would otherwise turn an unbounded audit-write rate loose — and
// under --require-audit=strict enough dropped writes latch AuditDegraded and deny every route.
func TestServerRequestDisplacement_RecordIsMetered(t *testing.T) {
	t.Parallel()
	var reqs serverReqTracker
	rec := &fwdRecorder{}
	u := serverRequestUnblocker{reqs: &reqs, sink: sinkFunc(func(mcp.RPCMsg) error { return nil }), errOut: io.Discard}
	fillServerReqTracker(t, u)

	lim := newRefusalRecordLimiter()
	for i := range 200 {
		trackServerRequest(context.Background(), u, refusalLimits{records: lim}.recorders(rec), verifiedSession("s"), dropStdioDisplaced,
			mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(jsonNumber(maxTrackedServerReqs + i)), Method: "roots/list"})
	}
	assert.LessOrEqual(t, len(rec.records), int(perCategoryDenyBurst)+1,
		"a sustained displacement flood must be bounded by its own bucket, not written once per request")
	assert.NotEmpty(t, rec.records, "the leading edge of the flood must still reach the tape")
}

// TestUnblock_AnswersAndConsumesExactlyOnce pins the ordinary path: the id is consumed, so a
// second unblock (or a later host reply) finds nothing and writes nothing.
func TestUnblock_AnswersAndConsumesExactlyOnce(t *testing.T) {
	t.Parallel()
	var up bytes.Buffer
	var reqs serverReqTracker
	_, _ = reqs.track(mcp.RPCMsg{ID: mcp.RawJSON(`7`), Method: "sampling/createMessage"}, io.Discard)
	u := serverRequestUnblocker{
		reqs:   &reqs,
		sink:   sinkFunc(func(m mcp.RPCMsg) error { _, _ = up.Write(append(mustJSON(m), '\n')); return nil }),
		errOut: io.Discard,
	}
	require.True(t, u.unblock(mcp.RawJSON(`7`), "refused"))
	require.False(t, u.unblock(mcp.RawJSON(`7`), "refused"))
	assert.Len(t, upstreamReplies(t, up.String()), 1, "one forwarded request is answered exactly once")
}

// TestUnblock_NoUpstreamWriterReportsAndStillReclaims pins the nil-writer disposition that used to
// differ across the four hand-written copies of this sequence — two skipped silently, two warned —
// for the identical condition.
//
// The id is consumed even though nothing could be written. Leaving it was the tempting reading
// ("some later path might route it"), but no host reply to a request that was never delivered ever
// arrives, so the entry would sit in the bounded set for the session's life and eventually
// displace a LIVE request — which now actively answers an initiator rather than failing silently.
func TestUnblock_NoUpstreamWriterReportsAndStillReclaims(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	var reqs serverReqTracker
	_, _ = reqs.track(mcp.RPCMsg{ID: mcp.RawJSON(`7`), Method: "sampling/createMessage"}, io.Discard)
	u := serverRequestUnblocker{reqs: &reqs, errOut: &out}

	assert.True(t, u.unblock(mcp.RawJSON(`7`), "because"))
	assert.Contains(t, out.String(), "no upstream writer to answer it",
		"a request left blocked must be reported, not dropped silently: the alternative is a wedged upstream with nothing anywhere saying why")
	assert.False(t, reqs.tracked("n:7"), "the slot must be reclaimed; nothing will ever arrive to reclaim it later")

	// An id this proxy never issued is nothing that happened — so a peer cannot drive stderr by
	// replying to ids at random.
	out.Reset()
	assert.False(t, u.unblock(mcp.RawJSON(`999`), "because"))
	assert.Empty(t, out.String())
}

// TestSessionGateRefusedReply_AnswersOnlyAProvenOwner settles the arm that had a comment instead
// of a rule, and pins the half that comment did not cover.
//
// A host reply refused by the session gates left its upstream blocked for the session's remaining
// life. The fix is not "always unblock": these gates refuse the SENDER, and answering the initiator
// completes its request whether or not the tracked id is consumed — so answering on an
// unauthorized sender's message hands any second identity that learned a session id a way to abort
// the owner's pending reply, gated only on knowing the id.
//
// The disposition therefore turns on the sender being a PROVEN owner, not on the absence of a
// mismatch. The two differ exactly where an earlier version of this arm was wrong: ownerMismatch
// reports "no mismatch" for a session with no bound identity, which is right for a gate (nothing
// to enforce) and wrong for a decision that acts on the sender's behalf — an unbound session
// cannot tell its owner from anyone else, and the AUDIENCE gate refuses senders that binding never
// examines.
func TestSessionGateRefusedReply_AnswersOnlyAProvenOwner(t *testing.T) {
	t.Parallel()
	owner := &pdp.JWTClaims{Issuer: "https://idp.example", Subject: "alice"}
	cases := []struct {
		name        string
		sessClaims  *pdp.JWTClaims
		senderClaim *pdp.JWTClaims
		wantAnswer  bool
	}{
		{
			name:       "the session's own owner is answered",
			sessClaims: owner, senderClaim: owner, wantAnswer: true,
		},
		{
			name:       "a second identity is not",
			sessClaims: owner, senderClaim: &pdp.JWTClaims{Issuer: "https://idp.example", Subject: "mallory"}, wantAnswer: false,
		},
		{
			name:       "a sender with no identity at all is not",
			sessClaims: owner, senderClaim: nil, wantAnswer: false,
		},
		{
			// The regression. This is the audience-pin path: the owner binding never ran, and on
			// a session with nothing to bind it is vacuous anyway — so an earlier version read
			// "no mismatch" as "this is the owner" and handed the attacker the abort. A reply the
			// audience pin refuses would not otherwise reach the tracked id at all, so this was a
			// primitive that did not previously exist.
			name:        "a second identity on a session with no bound subject is not",
			sessClaims:  &pdp.JWTClaims{Issuer: "https://idp.example", Subject: ""},
			senderClaim: &pdp.JWTClaims{Issuer: "https://idp.example", Subject: "mallory"},
			wantAnswer:  false,
		},
		{
			// Nothing can be proven about a sender on a session with no creating identity, so
			// nothing is answered — the conservative reading, at the cost of leaving the upstream
			// blocked exactly where it was before.
			name:       "an unbound session proves nothing and is not answered",
			sessClaims: nil, senderClaim: nil, wantAnswer: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var up bytes.Buffer
			sess := newTestSession(&httpSession{
				id:       "gate-sess",
				route:    &UpstreamRoute{},
				done:     make(chan struct{}),
				upWriter: mcp.NewMsgWriter(&up),
				claims:   tc.sessClaims,
			})
			_, _ = sess.serverReqs.track(mcp.RPCMsg{ID: mcp.RawJSON(`5`), Method: "sampling/createMessage"}, io.Discard)

			ctx := context.Background()
			if tc.senderClaim != nil {
				ctx = pdp.WithJWTClaims(ctx, tc.senderClaim)
			}
			sess.unblockGateRefusedServerReply(ctx, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`5`), Result: json.RawMessage(`{}`)})

			replies := upstreamReplies(t, up.String())
			if !tc.wantAnswer {
				assert.Empty(t, replies,
					"answering on a refused sender's message aborts the real owner's pending reply, which is a denial of service on the sampling leg gated only on knowing a session id")
				assert.True(t, sess.serverReqs.tracked("n:5"), "the owner's reply must stay routable")
				return
			}
			require.Len(t, replies, 1, "a wedged upstream request must not outlive a refusal nobody else could have caused")
			require.NotNil(t, replies[0].Error)
			assert.Contains(t, replies[0].Error.Message, "security gates",
				"the answer is eunox's own: nothing the refused reply carried may be relayed")
			assert.False(t, sess.serverReqs.tracked("n:5"))
		})
	}
}

// TestSessionGateRefusedReply_OnlyForAResponseFraming: the gate's denial arm also acks refused
// NOTIFICATIONS (and an id-less initialize carrying a victim's session header). Neither answers
// any upstream request, so neither may consume or answer anything.
func TestSessionGateRefusedReply_OnlyForAResponseFraming(t *testing.T) {
	t.Parallel()
	var up bytes.Buffer
	sess := newTestSession(&httpSession{
		id:       "gate-sess",
		route:    &UpstreamRoute{},
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&up),
	})
	_, _ = sess.serverReqs.track(mcp.RPCMsg{ID: mcp.RawJSON(`5`), Method: "sampling/createMessage"}, io.Discard)

	sess.unblockGateRefusedServerReply(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", Method: "notifications/cancelled"})
	assert.Empty(t, up.String(), "a notification answers no upstream request, so it may unblock none")
	assert.True(t, sess.serverReqs.tracked("n:5"))
}

// TestHandleSessionPost_GateRefusedOwnerReplyUnblocksThroughTheRealHandler drives the production
// entry point rather than the helper, so the arm is reached where handleSessionPost actually
// places it — before revision negotiation, on the bodyless-202 path.
func TestHandleSessionPost_GateRefusedOwnerReplyUnblocksThroughTheRealHandler(t *testing.T) {
	t.Parallel()
	var up bytes.Buffer
	// A route whose audience pin refuses every caller: the gate fires without the owner binding
	// running at all, which is the case an owner can reach on their own — and the case that made
	// the earlier "no mismatch" reading exploitable. The session carries a bound owner, and the
	// POST is made under that same identity.
	owner := &pdp.JWTClaims{Issuer: "https://idp.example", Subject: "alice"}
	rt := &UpstreamRoute{name: "r", pdp: audienceDenyingPDP{}, sink: &routeSink{}}
	proxy := newTestHTTPProxy()
	sess := newTestSession(&httpSession{
		id:       "post-sess",
		route:    rt,
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&up),
		claims:   owner,
	})
	_, _ = sess.serverReqs.track(mcp.RPCMsg{ID: mcp.RawJSON(`5`), Method: "sampling/createMessage"}, io.Discard)
	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":5,"result":{}}`))
	req.Header.Set("Content-Type", CTJSON)
	req.Header.Set(SessionHeader, sess.id)
	req = req.WithContext(pdp.WithJWTClaims(req.Context(), owner))
	w := httptest.NewRecorder()
	proxy.handleMCPPost(w, req, rt)

	assert.Equal(t, http.StatusAccepted, w.Code, "a refused non-request is still acked with a bodyless 202")
	replies := upstreamReplies(t, up.String())
	require.Len(t, replies, 1, "the upstream must not stay blocked until the hard idle ceiling for a refusal the session's own owner caused")
	require.NotNil(t, replies[0].Error)
}

// audienceDenyingPDP refuses the per-route audience pin and nothing else, so a POST reaches the
// session-gate denial arm without the owner binding having fired.
type audienceDenyingPDP struct{ pdp.AlwaysAllowPDP }

func (audienceDenyingPDP) CheckAudience(context.Context) *capability.EnforceResponse {
	return &capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial:   &capability.DenialInfo{Code: capability.ErrCodeAuthorizationFailed},
	}
}
