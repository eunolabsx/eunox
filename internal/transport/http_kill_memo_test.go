// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The HTTP session leg's revocation lookup, counted. The kill switch is a per-request network
// round trip on a Redis-backed deployment, and both properties here are invisible to every
// behavioral test: they are about how many times the store is asked, not about the answer.

package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// killCountingPDP counts the revocation lookups a leg makes, delegating the answer.
type killCountingPDP struct {
	pdp.PolicyDecisionPoint
	calls atomic.Int64
}

func (p *killCountingPDP) CheckKill(ctx context.Context, sessionID string) *capability.EnforceResponse {
	p.calls.Add(1)
	return p.PolicyDecisionPoint.CheckKill(ctx, sessionID)
}

// TestSessionLeg_RevocationIsLookedUpAtMostOncePerPost pins what the notification gate's THUNK
// is for, on the leg that used to defeat it, and the boundary the sharing deliberately stops at.
//
// hostNotificationGate.checkKill is a thunk so a swallowed notification costs no revocation
// lookup — on a Redis-backed kill switch that is a network round trip. The session leg computed
// the answer eagerly before building the gate, so the thunk returned an already-paid value and
// the saving was never taken: every `notifications/initialized` a host sends after its handshake
// cost a round trip to be dropped for free, as did every message the leg went on to discard.
//
// The dispatcher is NOT given that answer: its gate can be reached after an unbounded wait for
// the decision turn, and a kill landing during that wait must be recorded as KILL_SWITCH rather
// than as the method's own refusal. So a locally-answered request asks twice, deliberately —
// once for the leg's own gates, once at dispatch — and that is the cell below saying so.
func TestSessionLeg_RevocationIsLookedUpAtMostOncePerPost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		body  string
		want  int64
		notes string
	}{
		{
			name: "a swallowed notification asks nothing",
			body: `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			want: 0,
			notes: "the proxy already handled the handshake this announces, so it is dropped " +
				"before revocation is even a question",
		},
		{
			name:  "an unmapped notification asks once",
			body:  `{"jsonrpc":"2.0","method":"agents/delegate"}`,
			want:  1,
			notes: "revocation precedes the fail-closed reject, and the idle-reaping gate reads that same answer",
		},
		{
			name:  "a response to a request this proxy never issued asks nothing",
			body:  `{"jsonrpc":"2.0","id":"never-issued","result":{}}`,
			want:  0,
			notes: "nothing acted on it: an untracked id is discarded before the routing leg needs an answer",
		},
		{
			name: "a locally answered request asks the leg once and the dispatcher once",
			body: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
			want: 2,
			notes: "the dispatcher's gate is deliberately FRESH — it can be reached after an unbounded " +
				"decision-turn wait, and an answer from before that wait would record the wrong code",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			counting := &killCountingPDP{PolicyDecisionPoint: pdp.AlwaysAllowPDP{}}
			route := &UpstreamRoute{name: "up1", pdp: counting}
			proxy := newTestHTTPProxy()
			sess := newTestSession(&httpSession{
				id: "live-sess", route: route, hostRev: handshakeRevision, done: make(chan struct{}),
			})
			proxy.sessions["live-sess"] = sess

			postToSession(t, proxy, route, sess, tc.body)

			if got := counting.calls.Load(); got != tc.want {
				t.Errorf("CheckKill called %d time(s), want %d — %s", got, tc.want, tc.notes)
			}
		})
	}
}

// TestSessionLeg_OnlyTrafficTheProxyActsOnDefersReaping states the rule the lazy lookup buys as
// a decision rather than a side effect: a session's idle timer is deferred by messages the proxy
// DOES something about — forwards, answers, or refuses onto the tamper-evident tape — and not by
// ones it discards.
//
// The distinction matters in both directions. A message dropped for free must not keep a session
// (and its upstream subprocess) alive: a peer that learned a session id could otherwise hold one
// open indefinitely with bogus responses, at no cost and with no record. But a notification the
// proxy REFUSES is work done on that session's behalf, so it still counts as activity — losing
// that would reap a live conversation whose host happens to send a method this build does not map.
func TestSessionLeg_OnlyTrafficTheProxyActsOnDefersReaping(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		body  string
		want  bool
		notes string
	}{
		{
			name:  "a swallowed notification defers nothing",
			body:  `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			notes: "dropped for free, before revocation is even asked",
		},
		{
			name:  "a response to a request this proxy never issued defers nothing",
			body:  `{"jsonrpc":"2.0","id":"never-issued","result":{}}`,
			notes: "discarded with no record; a peer holding a session id must not keep it alive this way",
		},
		{
			name:  "a refused notification is still activity",
			body:  `{"jsonrpc":"2.0","method":"agents/delegate"}`,
			want:  true,
			notes: "the proxy wrote a deny record for it, so the session is live traffic even though nothing was forwarded",
		},
		{
			name:  "an answered request is activity",
			body:  `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
			want:  true,
			notes: "the ordinary case: the proxy answered the host",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			route := &UpstreamRoute{name: "up1", pdp: pdp.AlwaysAllowPDP{}}
			proxy := newTestHTTPProxy()
			sess := newTestSession(&httpSession{
				id: "live-sess", route: route, hostRev: handshakeRevision, done: make(chan struct{}),
			})
			proxy.sessions["live-sess"] = sess

			postToSession(t, proxy, route, sess, tc.body)

			if deferred := sess.lastRequest.Load() != 0; deferred != tc.want {
				t.Errorf("idle reaping deferred = %v, want %v — %s", deferred, tc.want, tc.notes)
			}
		})
	}
}

// postToSession drives one host POST through the session leg, the shape both tables above need.
func postToSession(t *testing.T, proxy *HTTPProxy, route *UpstreamRoute, sess *httpSession, body string) {
	t.Helper()
	var msg mcp.RPCMsg
	if err := mcp.DecodeParams([]byte(body), &msg); err != nil {
		t.Fatalf("decoding the test message: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set(SessionHeader, sess.id)
	proxy.handleSessionPost(httptest.NewRecorder(), req, route, sess.id, msg)
}
