// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// TestHandleSessionPost_TeardownRaceAfterInFlightIncrement covers the teardown race across
// the whole handler: inFlight is incremented right after the route-binding check, before the
// session gates and the existing-session CheckKill this test hooks (see
// TestHandleSessionPost_InFlightCoversWholeHandler for that), so a session torn out of the
// registry from inside CheckKill can no longer land in the narrow resolve-to-Add(1) gap the
// dispatch branch's re-validation was originally added for. This test covers the WIDER window
// that re-validation is now kept as a fail-closed backstop for: a teardown landing between the
// initial getSession resolve and the enforced-dispatch branch's own re-check must still deny
// with a retryable error rather than take a decision turn on a gate/PDP state the teardown
// already released. It uses killGateHookPDP (defined alongside
// TestInitialize_ReapGenCapturedBeforeKillGate) to tear the session out of the registry from
// inside CheckKill.
func TestHandleSessionPost_TeardownRaceAfterInFlightIncrement(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	route := &UpstreamRoute{
		name: "up1",
		pdp:  newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sink: &routeSink{},
	}
	proxy := newTestHTTPProxy()
	sess := newTestSession(&httpSession{id: "sess-race", route: route, done: make(chan struct{})})
	proxy.sessions["sess-race"] = sess

	// Tear the session out of the registry from inside CheckKill, which runs after
	// handleSessionPost's initial getSession resolve but before its Add(1) — the exact
	// window H3 closes.
	route.pdp = killGateHookPDP{
		PolicyDecisionPoint: route.pdp,
		onCheckKill: func() {
			delete(proxy.sessions, "sess-race")
		},
	}

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/call", Params: json.RawMessage(`{"name":"x"}`)}
	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "sess-race")
	w := httptest.NewRecorder()

	proxy.handleSessionPost(w, req, route, "sess-race", msg)

	var resp mcp.RPCMsg
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON-RPC: %v (body=%q, status=%d)", err, w.Body.String(), w.Code)
	}
	if resp.Error == nil {
		t.Fatalf("expected a JSON-RPC error denying the stale request, got %s", w.Body.String())
	}
	if resp.Error.Code != jsonRPCCodeServerBusy {
		t.Errorf("error code = %d, want %d (retryable server-busy, not an allow on a torn-down session)", resp.Error.Code, jsonRPCCodeServerBusy)
	}
	if got := sess.inFlight.Load(); got != 0 {
		t.Errorf("inFlight = %d, want 0: the deferred release must still run on the fail-closed path", got)
	}
}

// TestHandleSessionPost_InFlightCoversWholeHandler pins where the counting window opens:
// inFlight is incremented right after the route-binding check, before the session gates and the
// existing-session CheckKill run — not only around the enforced-dispatch branch's upstream
// call, as it was before. It hooks CheckKill (which this request reaches well before the old
// Add(1) site) to observe inFlight mid-handler, proving the reaper would already spare this
// session at that point; and it drives a notification (which never reaches the old Add(1) site
// at all) to prove inFlight still returns to 0 on that path's own early return, so the wider
// counting window can't leak.
func TestHandleSessionPost_InFlightCoversWholeHandler(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()

	var observedDuringCheckKill int64
	route := &UpstreamRoute{name: "up1", sink: &routeSink{}}
	sess := newTestSession(&httpSession{id: "sess-wide", route: route, done: make(chan struct{})})
	route.pdp = killGateHookPDP{
		// No constraints: tools/call denies immediately after the decision, so this test
		// (which only cares about inFlight during CheckKill, run before that decision) never
		// reaches callUpstream, which this hand-built session has no working upWriter for.
		PolicyDecisionPoint: newTestManifestPDPWithKS(ks),
		onCheckKill: func() {
			observedDuringCheckKill = sess.inFlight.Load()
		},
	}
	proxy := newTestHTTPProxy()
	proxy.sessions["sess-wide"] = sess

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/call", Params: json.RawMessage(`{"name":"x"}`)}
	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "sess-wide")
	w := httptest.NewRecorder()

	proxy.handleSessionPost(w, req, route, "sess-wide", msg)

	if observedDuringCheckKill != 1 {
		t.Errorf("inFlight during CheckKill = %d, want 1: it must be counted before the session gates run, not only around the enforced dispatch below them", observedDuringCheckKill)
	}
	if got := sess.inFlight.Load(); got != 0 {
		t.Errorf("inFlight = %d, want 0 after the handler returns", got)
	}

	// A notification never reaches the old Add(1) site (inside the enforced-dispatch else
	// branch) at all, so it is the clearest proof the new site's defer still fires on a path
	// that isn't an enforced request.
	observedDuringCheckKill = -1
	notif := mcp.RPCMsg{JSONRPC: "2.0", Method: "notifications/does-not-exist"}
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req2.Header.Set(SessionHeader, "sess-wide")
	w2 := httptest.NewRecorder()

	proxy.handleSessionPost(w2, req2, route, "sess-wide", notif)

	if observedDuringCheckKill != 1 {
		t.Errorf("inFlight during CheckKill (notification path) = %d, want 1", observedDuringCheckKill)
	}
	if got := sess.inFlight.Load(); got != 0 {
		t.Errorf("inFlight = %d, want 0 after a notification-path return", got)
	}
}
