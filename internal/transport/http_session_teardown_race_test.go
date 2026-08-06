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

// TestHandleSessionPost_TeardownRaceAfterInFlightIncrement is the regression for H3: a
// request whose session is torn down in the window between handleSessionPost's initial
// getSession resolve and its own sess.inFlight.Add(1) must not take its decision turn on a
// stale, no-longer-registered session — every teardown drain
// (awaitInFlightDrained/dropDecideGate) only counts requests that already incremented, so
// without a re-validation this straggler would decide against a pinned gate and PDP state
// the teardown already released. It uses killGateHookPDP (defined alongside
// TestInitialize_ReapGenCapturedBeforeKillGate) to tear the session out of the registry
// exactly inside that window: handleSessionPost's existing-session CheckKill call sits
// between the initial resolve and Add(1).
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
