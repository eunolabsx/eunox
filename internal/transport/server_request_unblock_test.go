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
// must evict one. The victim of that eviction is arbitrary (a map-order pick), which is exactly
// why the test asserts on the SHAPE of the answer rather than on which id was chosen.
func fillServerReqTracker(t *testing.T, u serverRequestUnblocker) {
	t.Helper()
	for i := range maxTrackedServerReqs {
		_, evicted := u.reqs.track(mcp.RPCMsg{ID: mcp.RawJSON(jsonNumber(i)), Method: "roots/list"}, io.Discard)
		require.False(t, evicted, "filling to the cap must not evict")
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

// TestServerRequestEviction_AnswersAndRecordsTheEvictedInitiator is the regression for a
// server-initiated request the bounded tracker dropped on the floor.
//
// Past the cap an arbitrary tracked request is evicted to keep the set bounded. The eviction
// itself is the safe half; what was missing is that nothing then answered the request it evicted.
// Its id is gone, so both transports' routing arms drop even a CORRECT host reply to it as
// untracked — the upstream stays blocked on a request nothing could ever complete, on stdio until
// the host disconnects, and nothing on the tape said which request it cost.
//
// An eviction is neither of the leg's exceptions: not a refusal of the peer, not an emergency
// stop, but eunox running out of bookkeeping space — the case where it most clearly owes the
// upstream an answer it can produce entirely on its own.
func TestServerRequestEviction_AnswersAndRecordsTheEvictedInitiator(t *testing.T) {
	t.Parallel()
	var up bytes.Buffer
	var reqs serverReqTracker
	u := serverRequestUnblocker{
		reqs:          &reqs,
		writeUpstream: func(m mcp.RPCMsg) { _, _ = up.Write(append(mustJSON(m), '\n')) },
		errOut:        io.Discard,
	}
	fillServerReqTracker(t, u)

	rec := &fwdRecorder{}
	trackServerRequest(context.Background(), u, rec, "sess-evict", dropStdioEvicted,
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`"the-newest"`), Method: "sampling/createMessage"})

	replies := upstreamReplies(t, up.String())
	require.Len(t, replies, 1, "the evicted request's initiator must be answered exactly once")
	require.NotNil(t, replies[0].Error, "the answer must be a JSON-RPC error; a result would claim the host performed something")
	assert.Equal(t, capability.JSONRPCCodeEnforcementError, replies[0].Error.Code)
	assert.Contains(t, replies[0].Error.Message, "evicted",
		"the answer names the proxy's own limit: an eviction relays nothing the host said, so the text is eunox's own")

	require.Len(t, rec.records, 1, "an evicted request is a call the proxy actively failed and must reach the tape")
	assert.Equal(t, "deny", rec.records[0].decision)
	assert.Equal(t, capability.ErrCodeEnforcementError, rec.records[0].code)
	assert.Equal(t, string(dropStdioEvicted), rec.records[0].details["transport"],
		"the record must name the drop site, so an eviction is distinguishable from an undelivered broadcast")
	assert.Equal(t, "roots/list", rec.records[0].identifier,
		"the record names the EVICTED request's method, which is why the tracker remembers more than an id")
}

// TestServerRequestEviction_BelowTheCapAnswersNothing is the other half: the answer above must be
// forced by an actual eviction, not written for every tracked request.
func TestServerRequestEviction_BelowTheCapAnswersNothing(t *testing.T) {
	t.Parallel()
	var up bytes.Buffer
	var reqs serverReqTracker
	rec := &fwdRecorder{}
	u := serverRequestUnblocker{
		reqs:          &reqs,
		writeUpstream: func(m mcp.RPCMsg) { _, _ = up.Write(append(mustJSON(m), '\n')) },
		errOut:        io.Discard,
	}
	trackServerRequest(context.Background(), u, rec, "sess", dropStdioEvicted,
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "sampling/createMessage"})
	assert.Empty(t, up.String(), "tracking below the cap evicts nothing, so nothing may be answered")
	assert.Empty(t, rec.records)
	assert.True(t, reqs.tracked("n:1"), "the request just tracked must still be routable")
}

// TestUnblock_NoUpstreamWriterReportsAndLeavesTheIDRoutable pins the nil-writer disposition that
// used to differ across the four hand-written copies of this sequence — two skipped silently, two
// warned — for the identical condition.
//
// Two properties, and the second is why the writer is tested BEFORE the take: consuming the id is
// what makes the reply unroutable by any later path, so consuming one with nothing to answer
// through strands the initiator strictly worse than leaving it alone.
func TestUnblock_NoUpstreamWriterReportsAndLeavesTheIDRoutable(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	var reqs serverReqTracker
	_, _ = reqs.track(mcp.RPCMsg{ID: mcp.RawJSON(`7`), Method: "sampling/createMessage"}, io.Discard)
	u := serverRequestUnblocker{reqs: &reqs, errOut: &out}

	assert.Equal(t, unblockNoUpstream, u.unblock(mcp.RawJSON(`7`), "because"))
	assert.Contains(t, out.String(), "no upstream writer to answer it",
		"a request left blocked must be reported, not dropped silently: the alternative is a wedged upstream with nothing anywhere saying why")
	assert.True(t, reqs.tracked("n:7"),
		"an unanswerable unblock must not consume the id; taking it is what makes a later, routable reply undeliverable")

	// An id this proxy never issued is nothing that happened, on the writerless path too — so a
	// peer cannot drive stderr by replying to ids at random.
	out.Reset()
	assert.Equal(t, unblockUntracked, u.unblock(mcp.RawJSON(`999`), "because"))
	assert.Empty(t, out.String())
}

// TestUnblock_AnswersAndConsumesExactlyOnce pins the ordinary path: the id is consumed, so a
// second unblock (or a later host reply) finds nothing and writes nothing.
func TestUnblock_AnswersAndConsumesExactlyOnce(t *testing.T) {
	t.Parallel()
	var up bytes.Buffer
	var reqs serverReqTracker
	_, _ = reqs.track(mcp.RPCMsg{ID: mcp.RawJSON(`7`), Method: "sampling/createMessage"}, io.Discard)
	u := serverRequestUnblocker{
		reqs:          &reqs,
		writeUpstream: func(m mcp.RPCMsg) { _, _ = up.Write(append(mustJSON(m), '\n')) },
		errOut:        io.Discard,
	}
	require.Equal(t, unblockAnswered, u.unblock(mcp.RawJSON(`7`), "refused"))
	require.Equal(t, unblockUntracked, u.unblock(mcp.RawJSON(`7`), "refused"))
	assert.Len(t, upstreamReplies(t, up.String()), 1, "one forwarded request is answered exactly once")
}

// TestSessionGateRefusedReply_AnswersTheOwnerAndNeverASecondIdentity settles the arm that had a
// comment instead of a rule.
//
// A host reply refused by the session gates left its upstream blocked for the session's remaining
// life. The fix is not "always unblock": this gate refuses the SENDER, and answering the initiator
// completes its request whether or not the tracked id is consumed — so answering on an
// unauthorized sender's message hands any same-audience second identity that learned a session id
// a way to abort the owner's pending reply, gated only on knowing the id.
//
// So the disposition turns on WHO was refused: the session's own owner (or an unbound session,
// where the primitive already exists) is answered; a second identity is not.
func TestSessionGateRefusedReply_AnswersTheOwnerAndNeverASecondIdentity(t *testing.T) {
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
			// No creating identity to enforce: anyone who can reach the session id can already
			// send a reply that consumes it outright, so answering adds no new primitive.
			name:       "an unbound session is answered",
			sessClaims: nil, senderClaim: nil, wantAnswer: true,
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
	// A route whose audience pin refuses every caller: the gate fires on something OTHER than the
	// sender's identity, which is the case an owner can reach on their own.
	rt := &UpstreamRoute{name: "r", pdp: audienceDenyingPDP{}, sink: &routeSink{}}
	proxy := newTestHTTPProxy()
	sess := newTestSession(&httpSession{
		id:       "post-sess",
		route:    rt,
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&up),
	})
	_, _ = sess.serverReqs.track(mcp.RPCMsg{ID: mcp.RawJSON(`5`), Method: "sampling/createMessage"}, io.Discard)
	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":5,"result":{}}`))
	req.Header.Set("Content-Type", CTJSON)
	req.Header.Set(SessionHeader, sess.id)
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
