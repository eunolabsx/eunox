// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// killGateHookPDP runs a hook inside CheckKill, so a test can make a global kill fire and
// sweep the session registry DURING the pre-spawn kill gate — the window between the gate
// and the reap-generation capture. It embeds the interface so only CheckKill is overridden.
type killGateHookPDP struct {
	pdp.PolicyDecisionPoint
	onCheckKill func()
}

func (k killGateHookPDP) CheckKill(ctx context.Context, sessionID string) *capability.EnforceResponse {
	if k.onCheckKill != nil {
		k.onCheckKill()
	}
	return k.PolicyDecisionPoint.CheckKill(ctx, sessionID)
}

// TestInitialize_ReapGenCapturedBeforeKillGate is the regression for the undead-session
// window. The pre-spawn kill gate and the reap-generation capture used to sit in the wrong
// order: CheckKill ran first (a kill-store round-trip that may do I/O), and only then did
// newSession/newRemoteSession call currentReapGen. A global kill activating and completing
// its registry sweep inside that window produced a startGen EQUAL to the post-sweep
// generation, so registerSession saw nothing stale and admitted a session the sweep never
// had a chance to tear down. With the idle reaper disabled (sessionIdleTimeoutMs: 0 is
// valid config) that session pins an upstream and a maxSessions slot until the process
// exits — the exact leak the reap generation exists to close.
//
// Capturing the generation BEFORE the gate makes the same sweep observable: the session is
// refused and never lands in the registry.
func TestInitialize_ReapGenCapturedBeforeKillGate(t *testing.T) {
	fu := newFullFakeUpstream()
	upURL := startFakeUpstream(t, fu)

	proxy, proxySrv := newTestRemoteProxy(t, upURL, httpProxyOptions{})

	// A global kill fires and sweeps the registry while the pre-spawn kill gate is
	// running, i.e. after the gate's own kill lookup but before the session registers.
	// The gate itself still passes (CheckKill returns nil), which is what makes this a
	// window rather than an ordinary denial.
	swept := false
	for name, route := range proxy.routes {
		route.pdp = killGateHookPDP{
			PolicyDecisionPoint: route.pdp,
			onCheckKill: func() {
				if !swept {
					swept = true
					proxy.teardownAllSessionsForGlobalKill()
				}
			},
		}
		_ = name
	}

	msg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`1`),
		Method:  mcp.MethodInitialize,
		Params:  json.RawMessage(`{"protocolVersion":"` + MCPProtocolVersion + `","capabilities":{},"clientInfo":{"name":"t","version":"0"}}`),
	}
	resp := postMCP(t, proxySrv, msg, "")
	defer func() { _ = resp.Body.Close() }()

	if !swept {
		t.Fatal("the pre-spawn kill gate never ran, so this test proves nothing")
	}
	if sid := resp.Header.Get(SessionHeader); sid != "" {
		t.Errorf("a session established across a global kill sweep must not be handed to the client, got %q", sid)
	}
	if n := proxy.sessionCount(); n != 0 {
		t.Errorf("session registry holds %d session(s); a session racing a global kill sweep must not register (it would pin an upstream and a maxSessions slot with no reaper to collect it)", n)
	}
}
