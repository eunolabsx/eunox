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
// is for, on the leg that used to defeat it.
//
// hostNotificationGate.checkKill is a thunk so a swallowed notification costs no revocation
// lookup — on a Redis-backed kill switch that is a network round trip. The session leg computed
// the answer eagerly before building the gate, so the thunk returned an already-paid value and
// the saving was never taken: every `notifications/initialized` a host sends after its
// handshake cost a round trip to be dropped for free. A locally-answered request then paid a
// SECOND one inside the dispatcher's gate for a question this leg had just answered.
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
			notes: "revocation precedes the fail-closed reject, and the idle-reaping gate reads the same answer",
		},
		{
			name:  "a locally answered request asks once",
			body:  `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
			want:  1,
			notes: "the dispatcher's boundary gate answers from the leg's lookup instead of making its own",
		},
		{
			name:  "a host response to a server-initiated request asks once",
			body:  `{"jsonrpc":"2.0","id":"nonce-1","result":{}}`,
			want:  1,
			notes: "the routing leg needs the answer, and the idle-reaping gate shares it",
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

			var msg mcp.RPCMsg
			if err := mcp.DecodeParams([]byte(tc.body), &msg); err != nil {
				t.Fatalf("decoding the test message: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(tc.body))
			req.Header.Set(SessionHeader, "live-sess")
			proxy.handleSessionPost(httptest.NewRecorder(), req, route, "live-sess", msg)

			if got := counting.calls.Load(); got != tc.want {
				t.Errorf("CheckKill called %d time(s), want %d — %s", got, tc.want, tc.notes)
			}
		})
	}
}

// TestSessionLeg_DroppedNotificationDoesNotDeferReaping is the behavioral half of the same
// change, stated so it is a decision rather than a side effect: idle reaping is deferred by
// traffic the proxy ACTS on, and a notification the gate drops is not that. Making the lookup
// lazy is what this buys — the gate that defers reaping cannot ask for an answer the swallowed
// path exists to avoid needing.
func TestSessionLeg_DroppedNotificationDoesNotDeferReaping(t *testing.T) {
	t.Parallel()
	route := &UpstreamRoute{name: "up1", pdp: pdp.AlwaysAllowPDP{}}
	proxy := newTestHTTPProxy()
	sess := newTestSession(&httpSession{
		id: "live-sess", route: route, hostRev: handshakeRevision, done: make(chan struct{}),
	})
	proxy.sessions["live-sess"] = sess

	post := func(body string) {
		var msg mcp.RPCMsg
		if err := mcp.DecodeParams([]byte(body), &msg); err != nil {
			t.Fatalf("decoding %s: %v", body, err)
		}
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		req.Header.Set(SessionHeader, "live-sess")
		proxy.handleSessionPost(httptest.NewRecorder(), req, route, "live-sess", msg)
	}

	post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if sess.lastRequest.Load() != 0 {
		t.Error("a swallowed notification must not defer idle reaping: the proxy dropped it without acting on it")
	}
	post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if sess.lastRequest.Load() == 0 {
		t.Error("a request the proxy answers is live host traffic and must defer idle reaping")
	}
}
