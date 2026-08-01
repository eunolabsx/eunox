// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/mcp/mcptest"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// TestStdioRunBoundedStartup_KillsHungSubprocess is the regression for the stdio
// startup having no read deadline: a subprocess that launches but never answers
// the initialize handshake (here a plain `sleep` that reads nothing and writes
// nothing) must not hang Start forever. runBoundedStartup bounds the inline work
// and kills the subprocess on expiry, EOF-ing the pipe so the blocked Read returns.
func TestStdioRunBoundedStartup_KillsHungSubprocess(t *testing.T) {
	t.Parallel()

	p := &StdioProxy{
		command:        "sleep",
		args:           []string{"30"},
		startupTimeout: 200 * time.Millisecond,
		byUpstreamID:   make(map[string]chan upstreamResult),
	}
	if err := p.connectUpstream(context.Background()); err != nil {
		t.Skipf("could not spawn `sleep` subprocess (environment lacks it): %v", err)
	}
	t.Cleanup(func() { p.killUpstream(); p.waitUpstream() })

	errCh := make(chan error, 1)
	go func() {
		errCh <- p.runBoundedStartup(context.Background(), func() error {
			return p.initUpstream(context.Background())
		})
	}()

	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "did not complete startup") {
			t.Fatalf("expected a startup-timeout error, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runBoundedStartup hung on a non-responsive subprocess (the read deadline did not fire)")
	}
}

// TestAwaitUpstreamDrain_HostEOFBoundedThenKill is the regression for the stdio
// host-EOF teardown blocking forever on a daemon-style upstream. On host stdin close,
// Start closes the upstream's input and waits for readUpstream to finish (upstreamDone).
// A subprocess that ignores stdin EOF and keeps running never closes its stdout, so
// upstreamDone never closes on its own and a plain <-upstreamDone would hang until
// SIGKILL, skipping the deferred audit-sink flush. awaitUpstreamDrain must time out after
// shutdownMs, force-kill the upstream, and return.
func TestAwaitUpstreamDrain_HostEOFBoundedThenKill(t *testing.T) {
	t.Parallel()

	p := &StdioProxy{
		command:      "sleep",
		args:         []string{"30"},
		shutdownMs:   50,
		upstreamDone: make(chan struct{}),
		byUpstreamID: make(map[string]chan upstreamResult),
	}
	if err := p.connectUpstream(context.Background()); err != nil {
		t.Skipf("could not spawn `sleep` subprocess (environment lacks it): %v", err)
	}
	// Mirror readUpstream's contract: upstreamDone closes once the subprocess exits. The
	// `sleep` ignores its (closed) stdin, so this fires only after the forced kill.
	go func() { _ = p.upCmd.Wait(); close(p.upstreamDone) }()

	returned := make(chan struct{})
	go func() { p.awaitUpstreamDrain(); close(returned) }()

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		_ = p.upCmd.Process.Kill()
		t.Fatal("regression: awaitUpstreamDrain hung; the host-EOF teardown must be bounded and force-kill the upstream")
	}
}

// fakeListResult wraps a list of tools for tests that exercise filterToolsListResult.
func fakeToolsResult(names ...string) json.RawMessage {
	tools := make([]map[string]interface{}, len(names))
	for i, n := range names {
		tools[i] = map[string]interface{}{"name": n}
	}
	raw, _ := json.Marshal(map[string]interface{}{"tools": tools})
	return raw
}

func fakeResourcesResult(uris ...string) json.RawMessage {
	resources := make([]map[string]interface{}, len(uris))
	for i, u := range uris {
		resources[i] = map[string]interface{}{"uri": u}
	}
	raw, _ := json.Marshal(map[string]interface{}{"resources": resources})
	return raw
}

func fakePromptsResult(names ...string) json.RawMessage {
	prompts := make([]map[string]interface{}, len(names))
	for i, n := range names {
		prompts[i] = map[string]interface{}{"name": n}
	}
	raw, _ := json.Marshal(map[string]interface{}{"prompts": prompts})
	return raw
}

// ── handleToolsList success paths ─────────────────────────────────────────

func TestStdioHandleToolsList_Success_NoFilter(t *testing.T) {
	t.Parallel()
	p, hw := respondingProxy(t, mcp.RPCMsg{JSONRPC: "2.0", Result: fakeToolsResult("read_file")})
	p.handleHostRequest(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/list"})
	if len(hw.messages) != 1 || hw.messages[0].Error != nil {
		t.Fatalf("expected success, got: %+v", hw.messages)
	}
	if hw.messages[0].Result == nil {
		t.Error("expected result in response")
	}
}

func TestStdioHandleResourcesList_Success(t *testing.T) {
	t.Parallel()
	p, hw := respondingProxy(t, mcp.RPCMsg{JSONRPC: "2.0", Result: fakeResourcesResult("file:///a")})
	p.handleHostRequest(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "resources/list"})
	if len(hw.messages) != 1 || hw.messages[0].Error != nil {
		t.Fatalf("expected success, got: %+v", hw.messages)
	}
}

func TestStdioHandlePromptsList_Success(t *testing.T) {
	t.Parallel()
	p, hw := respondingProxy(t, mcp.RPCMsg{JSONRPC: "2.0", Result: fakePromptsResult("my-prompt")})
	p.handleHostRequest(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "prompts/list"})
	if len(hw.messages) != 1 || hw.messages[0].Error != nil {
		t.Fatalf("expected success, got: %+v", hw.messages)
	}
}

// ── handleResourcesRead success path ──────────────────────────────────────

func TestStdioHandleResourcesRead_Success(t *testing.T) {
	t.Parallel()
	raw, _ := json.Marshal(map[string]interface{}{"contents": []interface{}{}})
	p, hw := respondingProxy(t, mcp.RPCMsg{JSONRPC: "2.0", Result: raw})
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "resources/read",
		Params: json.RawMessage(`{"uri":"file:///allowed.txt"}`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error != nil {
		t.Fatalf("expected success, got: %+v", hw.messages)
	}
}

// ── handleResourcesSubscribe success path ─────────────────────────────────

func TestStdioHandleResourcesSubscribe_Success(t *testing.T) {
	t.Parallel()
	raw, _ := json.Marshal(map[string]interface{}{"ok": true})
	p, hw := respondingProxy(t, mcp.RPCMsg{JSONRPC: "2.0", Result: raw})
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "resources/subscribe",
		Params: json.RawMessage(`{"uri":"file:///allowed.txt"}`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error != nil {
		t.Fatalf("expected success, got: %+v", hw.messages)
	}
}

// ── handlePromptsGet with ManifestPDP ─────────────────────────────────────

func newTestManifestPDPWithPrompt(t *testing.T, promptName string) *pdp.ManifestPDP {
	t.Helper()
	return pdp.NewManifestPDP(
		[]capability.Constraint{
			{Target: "prompt:" + promptName, Actions: []string{"get"}},
		},
		enforcement.New(),
		killswitch.NewInMemory(),
	)
}

func TestStdioHandlePromptsGet_ManifestPDP_Allow(t *testing.T) {
	t.Parallel()
	raw, _ := json.Marshal(map[string]interface{}{"messages": []interface{}{}})
	p, hw := respondingProxy(t, mcp.RPCMsg{JSONRPC: "2.0", Result: raw})
	p.pdp = newTestManifestPDPWithPrompt(t, "my-prompt")

	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "prompts/get",
		Params: json.RawMessage(`{"name":"my-prompt"}`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error != nil {
		t.Fatalf("expected allow, got: %+v", hw.messages)
	}
}

func TestStdioHandlePromptsGet_ManifestPDP_InvalidParams(t *testing.T) {
	t.Parallel()
	p, hw := closedUpstream(t)
	p.pdp = newTestManifestPDPWithPrompt(t, "my-prompt")

	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: "prompts/get",
		Params: json.RawMessage(`"bad"`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error == nil {
		t.Fatal("expected error for invalid params")
	}
}

func TestStdioHandlePromptsGet_ManifestPDP_EmptyName(t *testing.T) {
	t.Parallel()
	p, hw := closedUpstream(t)
	p.pdp = newTestManifestPDPWithPrompt(t, "my-prompt")

	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`3`), Method: "prompts/get",
		Params: json.RawMessage(`{"name":""}`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error == nil {
		t.Fatal("expected error for empty name")
	}
	if hw.messages[0].Error.Code != -32602 {
		t.Errorf("error code = %d, want -32602 (INVALID_PARAMS), not an upstream error", hw.messages[0].Error.Code)
	}
}

func TestStdioHandlePromptsGet_ManifestPDP_Deny(t *testing.T) {
	t.Parallel()
	p, hw := closedUpstream(t)
	p.pdp = newTestManifestPDPWithPrompt(t, "allowed-only")

	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`4`), Method: "prompts/get",
		Params: json.RawMessage(`{"name":"blocked-prompt"}`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error == nil {
		t.Fatal("expected denial")
	}
}

func TestStdioHandlePromptsGet_ManifestPDP_DenyDryRun(t *testing.T) {
	t.Parallel()
	raw, _ := json.Marshal(map[string]interface{}{"messages": []interface{}{}})
	p, hw := respondingProxy(t, mcp.RPCMsg{JSONRPC: "2.0", Result: raw})
	p.pdp = newTestManifestPDPWithPrompt(t, "allowed-only")
	p.audit = true

	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`5`), Method: "prompts/get",
		Params: json.RawMessage(`{"name":"blocked-prompt"}`),
	})
	// dry-run: forwarded despite denial
	if len(hw.messages) != 1 || hw.messages[0].Error != nil {
		t.Fatalf("dry-run: expected forwarded response, got: %+v", hw.messages)
	}
}

func TestStdioHandlePromptsGet_ManifestPDP_UpstreamError(t *testing.T) {
	t.Parallel()
	p, hw := closedUpstream(t)
	p.pdp = newTestManifestPDPWithPrompt(t, "my-prompt")

	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`6`), Method: "prompts/get",
		Params: json.RawMessage(`{"name":"my-prompt"}`),
	})
	// Allow decision but upstream error
	if len(hw.messages) != 1 || hw.messages[0].Error == nil {
		t.Fatal("expected upstream error response")
	}
}

// ── handleToolsCall with sink (audit logging) ────────────────────────────

func TestStdioHandleToolsCall_AllowWithSink(t *testing.T) {
	t.Parallel()
	fakeResult, _ := json.Marshal(mcptest.ToolCallResult{
		Content: []mcptest.Content{{Type: "text", Text: "result"}},
	})
	p, hw := respondingProxy(t, mcp.RPCMsg{JSONRPC: "2.0", Result: fakeResult})

	sink, _ := newTempAuditSink(t)
	p.sink = sink

	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"read_file","arguments":{"path":"/ok"}}`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error != nil {
		t.Fatalf("expected success, got: %+v", hw.messages)
	}
}

// ── handleResourcesRead with dry-run deny ────────────────────────────────

func TestStdioHandleResourcesRead_DenyDryRun(t *testing.T) {
	t.Parallel()
	raw, _ := json.Marshal(map[string]interface{}{"contents": []interface{}{}})
	hw := &mockHostWriter{}
	done := make(chan struct{})

	p := &StdioProxy{
		pdp:          denyAllPDP{},
		sessionID:    "dr-sess",
		audit:        true,
		hostWriter:   mcp.NewMsgWriter(&writerAdapter{hw}),
		upstreamDone: done,
	}

	upR, upW := io.Pipe()
	p.upWriter = mcp.NewMsgWriter(upW)

	// Goroutine: respond to the upstream request
	go func() {
		defer upR.Close()
		reader := mcp.NewMsgReader(upR)
		for {
			req, err := reader.Read()
			if err != nil {
				return
			}
			key := mcp.MsgKey(req.ID)
			p.pendingMu.Lock()
			ch, ok := p.byUpstreamID[key]
			p.pendingMu.Unlock()
			if ok {
				resp := mcp.RPCMsg{JSONRPC: "2.0", Result: raw}
				resp.ID = req.ID
				ch <- upstreamResult{msg: resp}
			}
		}
	}()
	defer upW.Close()

	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "resources/read",
		Params: json.RawMessage(`{"uri":"file:///secret.txt"}`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error != nil {
		t.Fatalf("dry-run: expected forwarded response, got: %+v", hw.messages)
	}
}

// ── handleResourcesSubscribe with dry-run deny ───────────────────────────

func TestStdioHandleResourcesSubscribe_DenyDryRun(t *testing.T) {
	t.Parallel()
	raw, _ := json.Marshal(map[string]interface{}{"ok": true})
	hw := &mockHostWriter{}
	done := make(chan struct{})

	p := &StdioProxy{
		pdp:          denyAllPDP{},
		sessionID:    "dr-sub",
		audit:        true,
		hostWriter:   mcp.NewMsgWriter(&writerAdapter{hw}),
		upstreamDone: done,
	}

	upR, upW := io.Pipe()
	p.upWriter = mcp.NewMsgWriter(upW)

	go func() {
		defer upR.Close()
		reader := mcp.NewMsgReader(upR)
		for {
			req, err := reader.Read()
			if err != nil {
				return
			}
			key := mcp.MsgKey(req.ID)
			p.pendingMu.Lock()
			ch, ok := p.byUpstreamID[key]
			p.pendingMu.Unlock()
			if ok {
				resp := mcp.RPCMsg{JSONRPC: "2.0", Result: raw}
				resp.ID = req.ID
				ch <- upstreamResult{msg: resp}
			}
		}
	}()
	defer upW.Close()

	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "resources/subscribe",
		Params: json.RawMessage(`{"uri":"file:///secret.txt"}`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error != nil {
		t.Fatalf("dry-run: expected forwarded response, got: %+v", hw.messages)
	}
}

// ── handleResourcesSubscribe: audit-only deny ────────────────────────────

func TestStdioHandleResourcesSubscribe_AuditOnlyDeny(t *testing.T) {
	t.Parallel()
	raw, _ := json.Marshal(map[string]interface{}{"ok": true})
	hw := &mockHostWriter{}
	done := make(chan struct{})

	p := &StdioProxy{
		pdp:          denyAllPDP{},
		sessionID:    "ao-sub",
		audit:        true,
		hostWriter:   mcp.NewMsgWriter(&writerAdapter{hw}),
		upstreamDone: done,
	}

	upR, upW := io.Pipe()
	p.upWriter = mcp.NewMsgWriter(upW)

	go func() {
		defer upR.Close()
		reader := mcp.NewMsgReader(upR)
		for {
			req, err := reader.Read()
			if err != nil {
				return
			}
			key := mcp.MsgKey(req.ID)
			p.pendingMu.Lock()
			ch, ok := p.byUpstreamID[key]
			p.pendingMu.Unlock()
			if ok {
				resp := mcp.RPCMsg{JSONRPC: "2.0", Result: raw}
				resp.ID = req.ID
				ch <- upstreamResult{msg: resp}
			}
		}
	}()
	defer upW.Close()

	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "resources/subscribe",
		Params: json.RawMessage(`{"uri":"file:///secret.txt"}`),
	})
	// audit-only: forwarded despite denial
	if len(hw.messages) != 1 || hw.messages[0].Error != nil {
		t.Fatalf("audit-only: expected forwarded response, got: %+v", hw.messages)
	}
}

// ── handleToolsCall: timeout path and audit-only ──────────────────────────

func TestStdioHandleToolsCall_WithTimeout(t *testing.T) {
	t.Parallel()
	fakeResult, _ := json.Marshal(mcptest.ToolCallResult{
		Content: []mcptest.Content{{Type: "text", Text: "result"}},
	})
	p, hw := respondingProxy(t, mcp.RPCMsg{JSONRPC: "2.0", Result: fakeResult})
	p.upstreamTimeMs = 5000 // generous timeout → call succeeds

	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"read_file","arguments":{"path":"/ok"}}`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error != nil {
		t.Fatalf("expected success with timeout path, got: %+v", hw.messages)
	}
}

func TestStdioHandleToolsCall_AuditOnlyAllow(t *testing.T) {
	t.Parallel()
	fakeResult, _ := json.Marshal(mcptest.ToolCallResult{
		Content: []mcptest.Content{{Type: "text", Text: "result"}},
	})
	p, hw := respondingProxy(t, mcp.RPCMsg{JSONRPC: "2.0", Result: fakeResult})
	p.audit = true
	sink, _ := newTempAuditSink(t)
	p.sink = sink

	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"read_file","arguments":{"path":"/ok"}}`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error != nil {
		t.Fatalf("audit-only allow: expected success, got: %+v", hw.messages)
	}
}

// ── handleUpstreamRequest: sampling with audit-only and sink ─────────────

func TestHandleUpstreamRequest_SamplingAllow_WithSink(t *testing.T) {
	t.Parallel()
	hw := &mockHostWriter{}
	uw := &mockUpstreamWriter{}
	sink, _ := newTempAuditSink(t)

	dp := newTestManifestPDP(
		capability.Constraint{Target: "system:sampling/createMessage", Actions: []string{"allow"}},
	)
	p := &StdioProxy{
		pdp:        dp,
		sessionID:  "sess",
		hostWriter: mcp.NewMsgWriter(&writerAdapter{hw}),
		upWriter:   mcp.NewMsgWriter(&writerAdapter{uw}),
		sink:       sink,
	}

	samplingReq := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`1`),
		Method:  "sampling/createMessage",
		Params:  json.RawMessage(`{}`),
	}
	p.handleUpstreamRequest(context.Background(), samplingReq)

	// Allowed: host should receive the message.
	if len(hw.messages) != 1 {
		t.Errorf("expected 1 host message for allowed sampling, got %d", len(hw.messages))
	}
}

func TestHandleUpstreamRequest_SamplingDeny_AuditOnly(t *testing.T) {
	t.Parallel()
	hw := &mockHostWriter{}
	uw := &mockUpstreamWriter{}

	p := &StdioProxy{
		pdp:        pdp.AlwaysAllowPDP{}, // not ManifestPDP → sampling denied
		sessionID:  "sess",
		audit:      true,
		hostWriter: mcp.NewMsgWriter(&writerAdapter{hw}),
		upWriter:   mcp.NewMsgWriter(&writerAdapter{uw}),
	}

	samplingReq := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`2`),
		Method:  "sampling/createMessage",
		Params:  json.RawMessage(`{}`),
	}
	p.handleUpstreamRequest(context.Background(), samplingReq)

	// Audit-only: denied but forwarded to host.
	if len(hw.messages) != 1 {
		t.Errorf("audit-only: expected 1 host message for forwarded sampling, got %d", len(hw.messages))
	}
}

// ── sampling round-trip: host response routed back to upstream ──────────────

// TestStdioSamplingRoundTrip_HostResponseRoutedToUpstream verifies that when the PDP
// allows a server-initiated sampling/createMessage, the proxy forwards it to the
// host and must route the host's response back to the upstream. Before the fix
// serveHost dropped the response (it is neither a request nor a notification),
// hanging the upstream forever.
func TestStdioSamplingRoundTrip_HostResponseRoutedToUpstream(t *testing.T) {
	t.Parallel()
	dp := newTestManifestPDP(capability.Constraint{Target: "system:sampling/createMessage", Actions: []string{"allow"}})
	p, hw, uw := newStdioProxyForSamplingTest(t, dp)

	// Upstream initiates sampling; the proxy allows and forwards it to the host,
	// tracking the ID for the response route-back.
	samplingReq := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: "sampling/createMessage", Params: json.RawMessage(`{"messages":[],"maxTokens":10}`)}
	p.handleUpstreamRequest(context.Background(), samplingReq)
	if len(hw.messages) != 1 {
		t.Fatalf("expected the sampling request forwarded to the host, got %d host messages", len(hw.messages))
	}

	// The host replies with the LLM result (same ID). serveHost must route it back
	// to the upstream rather than dropping it.
	hostResp := `{"jsonrpc":"2.0","id":7,"result":{"role":"assistant","content":{"type":"text","text":"hi"}}}`
	p.hostReader = mcp.NewMsgReader(strings.NewReader(hostResp + "\n"))
	p.serveHost(context.Background())

	if len(uw.messages) != 1 {
		t.Fatalf("host response to the sampling request must be routed to the upstream; got %d upstream messages", len(uw.messages))
	}
	if got := mcp.MsgKey(uw.messages[0].ID); got != "n:7" {
		t.Errorf("routed response has ID %s, want n:7", got)
	}
	if uw.messages[0].Result == nil {
		t.Error("routed response should carry the LLM result")
	}
}

// TestStdioSamplingRoundTrip_KilledSessionResponseNotRouted verifies that a kill
// landing after the server-initiated request was forwarded but before the host's
// reply arrives stops the reply from reaching the killed session's upstream —
// mirroring the HTTP transport, which consumes the tracked id but does not route.
func TestStdioSamplingRoundTrip_KilledSessionResponseNotRouted(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	dp := newTestManifestPDPWithKS(ks, capability.Constraint{Target: "system:sampling/createMessage", Actions: []string{"allow"}})
	p, hw, uw := newStdioProxyForSamplingTest(t, dp)

	// Upstream initiates sampling; the proxy allows and forwards it to the host,
	// tracking the ID for the response route-back.
	samplingReq := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: "sampling/createMessage", Params: json.RawMessage(`{"messages":[],"maxTokens":10}`)}
	p.handleUpstreamRequest(context.Background(), samplingReq)
	if len(hw.messages) != 1 {
		t.Fatalf("expected the sampling request forwarded to the host, got %d host messages", len(hw.messages))
	}

	// Operator kills the session while the host computes its reply.
	if err := ks.KillSession(context.Background(), p.sessionID); err != nil {
		t.Fatalf("KillSession: %v", err)
	}

	// The host replies with the LLM result (same ID). serveHost must NOT route it
	// to the killed session's upstream.
	hostResp := `{"jsonrpc":"2.0","id":7,"result":{"role":"assistant","content":{"type":"text","text":"hi"}}}`
	p.hostReader = mcp.NewMsgReader(strings.NewReader(hostResp + "\n"))
	p.serveHost(context.Background())

	if len(uw.messages) != 0 {
		t.Fatalf("killed session: host response must not be routed to the upstream; got %d upstream messages", len(uw.messages))
	}
}

// TestStdioServeHost_MalformedLineAnsweredAndSessionContinues verifies that a
// malformed host line is answered with JSON-RPC -32700 and the session keeps serving
// instead of tearing down. Two bad lines must produce two parse-error replies, proving
// the loop continued past the first rather than breaking the whole session.
func TestStdioServeHost_MalformedLineAnsweredAndSessionContinues(t *testing.T) {
	t.Parallel()
	p, hw, uw := newStdioProxyForSamplingTest(t, pdp.AlwaysAllowPDP{})

	input := "this is not json\n" + "also not json\n"
	p.hostReader = mcp.NewMsgReader(strings.NewReader(input))
	p.serveHost(context.Background())

	if len(hw.messages) != 2 {
		t.Fatalf("want two parse-error replies (session kept serving), got %d: %+v", len(hw.messages), hw.messages)
	}
	for i, m := range hw.messages {
		if m.Error == nil || m.Error.Code != -32700 {
			t.Errorf("reply %d = %+v, want a -32700 parse error", i, m)
		}
		// JSON-RPC 2.0 requires "id":null on a parse-error response — an explicit null
		// member, not an omitted one. RPCMsg.ID is `json:"id,omitempty"`, so a nil id
		// would drop the member entirely; the response must carry a present null id.
		if m.ID == nil || string(*m.ID) != "null" {
			t.Errorf("reply %d has id %v, want a present null id per JSON-RPC 2.0", i, m.ID)
		}
	}
	if len(uw.messages) != 0 {
		t.Errorf("a malformed line must not route anything to the upstream; got %d", len(uw.messages))
	}
}

// TestStdioServeHost_UntrackedResponseIgnored verifies the route-back is bounded:
// a host response whose ID was never forwarded as a server-initiated request is
// ignored, not blindly written to the upstream.
func TestStdioServeHost_UntrackedResponseIgnored(t *testing.T) {
	t.Parallel()
	p, _, uw := newStdioProxyForSamplingTest(t, pdp.AlwaysAllowPDP{})

	hostResp := `{"jsonrpc":"2.0","id":123,"result":{}}`
	p.hostReader = mcp.NewMsgReader(strings.NewReader(hostResp + "\n"))
	p.serveHost(context.Background())

	if len(uw.messages) != 0 {
		t.Errorf("an untracked host response must not be forwarded to the upstream; got %d", len(uw.messages))
	}
}

// ── callUpstream: write error ─────────────────────────────────────────────

// TestStdioCallUpstream_WriteError covers the upWriter.Write error path.
func TestStdioCallUpstream_WriteError(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	p := &StdioProxy{
		upstreamDone: done,
		upWriter:     mcp.NewMsgWriter(&failingWriter{}), // always fails
	}
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`50`), Method: "tools/call"}
	_, err := p.callUpstream(context.Background(), msg)
	if err == nil {
		t.Error("expected error from failing writer")
	}
}

// TestStdioHandleToolsCall_PerEntryAudit_AllowRecordMarkedAuditOnly pins that
// when a per-entry audit-mode constraint observes-and-forwards its own
// deny, the subsequent ALLOW record (written after the upstream call) must also
// be marked audit_only=true. Otherwise SIEM/stats queries see a record that
// looks like a genuine policy-allow rather than a forwarded-under-observation
// call.
func TestStdioHandleToolsCall_PerEntryAudit_AllowRecordMarkedAuditOnly(t *testing.T) {
	t.Parallel()
	fakeResult, _ := json.Marshal(mcptest.ToolCallResult{
		Content: []mcptest.Content{{Type: "text", Text: "result"}},
	})
	p, hw := respondingProxy(t, mcp.RPCMsg{JSONRPC: "2.0", Result: fakeResult})
	sink, logPath := newTempAuditSink(t)
	p.sink = sink
	// Normal mode (p.audit stays false): only the matched entry is in audit mode.
	p.pdp = newTestManifestPDP(auditToolEntry())

	// path "/blocked" fails the allowedValues condition → deny, but audit-only, so
	// the call is forwarded and an allow record is written.
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`8`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"read_file","arguments":{"path":"/blocked"}}`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error != nil {
		t.Fatalf("per-entry audit: expected forwarded success, got: %+v", hw.messages)
	}

	_ = sink.Close() // flush barrier (see sibling test)
	var allowRec map[string]interface{}
	for _, r := range readAuditRecords(t, logPath) {
		if r["decision"] == "allow" {
			allowRec = r
		}
	}
	if allowRec == nil {
		t.Fatal("expected an allow audit record for the forwarded call")
	}
	if allowRec["audit_only"] != true {
		t.Errorf("expected audit_only=true on the forwarded allow record, got %v", allowRec["audit_only"])
	}
}

// failingWriter is an io.Writer that always returns an error.
type failingWriter struct{}

func (f *failingWriter) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("write failed")
}

// ── handleInitialize error branch ─────────────────────────────────────────

func TestHandleInitialize_SuccessResponseError(t *testing.T) {
	// Test the successResponse error branch in handleInitialize.
	// In practice this can't fail (the result is always marshalable),
	// but the test exercises the happy-path error branch by checking
	// that the response has no error.
	t.Parallel()
	p := &StdioProxy{sessionID: "sess-e"}
	resp := p.buildInitResponse(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`99`), Method: "initialize"})
	// Result should be set (not the error fallback path)
	if resp.Result == nil {
		t.Error("expected result from buildInitResponse")
	}
}

// TestStdioHandleToolsCall_PerEntryAudit_DenyForwarded: in NORMAL mode (no
// route-level audit-only/dry-run), a tool whose matched entry is in audit mode
// has its condition failure logged but forwarded — not blocked — and the deny
// record is marked audit_only.
func TestStdioHandleToolsCall_PerEntryAudit_DenyForwarded(t *testing.T) {
	t.Parallel()
	fakeResult, _ := json.Marshal(mcptest.ToolCallResult{
		Content: []mcptest.Content{{Type: "text", Text: "result"}},
	})
	p, hw := respondingProxy(t, mcp.RPCMsg{JSONRPC: "2.0", Result: fakeResult})
	sink, logPath := newTempAuditSink(t)
	p.sink = sink
	// Normal mode: p.audit stays false — only the matched entry is in audit mode.
	p.pdp = newTestManifestPDP(auditToolEntry())

	// path "/blocked" fails the allowedValues condition → would deny.
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"read_file","arguments":{"path":"/blocked"}}`),
	})

	// Forwarded: host received the upstream result, not a CapabilityDenied error.
	if len(hw.messages) != 1 || hw.messages[0].Error != nil {
		t.Fatalf("per-entry audit: expected forwarded success, got: %+v", hw.messages)
	}

	// The deny was recorded and marked audit_only. Close the sink first: the
	// drainer writes records asynchronously, so Close() (drain + fsync) is the
	// flush barrier that makes the record readable — without it the read races
	// the drainer. Close is idempotent, so the deferred Cleanup Close is fine.
	_ = sink.Close()
	var denyRec map[string]interface{}
	for _, r := range readAuditRecords(t, logPath) {
		if r["decision"] == "deny" {
			denyRec = r
		}
	}
	if denyRec == nil {
		t.Fatal("expected a deny audit record for the observed denial")
	}
	if denyRec["audit_only"] != true {
		t.Errorf("expected audit_only=true on per-entry audit deny, got %v", denyRec["audit_only"])
	}
}

// idCapturingSink records the ID of every message written to the upstream, so a
// test can recover the proxy-generated nonce ID callUpstream rewrote onto the
// outbound request.
type idCapturingSink struct {
	mu  sync.Mutex
	ids []*json.RawMessage
}

func (c *idCapturingSink) Write(m mcp.RPCMsg) error {
	c.mu.Lock()
	c.ids = append(c.ids, m.ID)
	c.mu.Unlock()
	return nil
}

func (c *idCapturingSink) lastID() *json.RawMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.ids) == 0 {
		return nil
	}
	return c.ids[len(c.ids)-1]
}

// TestCallUpstream_TimedOutResponseNotMisrouted verifies that a late
// upstream response for a request that already timed out must NOT be delivered to
// a SUBSEQUENT request that reuses the same host JSON-RPC ID. The proxy keys the
// in-flight response router by a per-call nonce (the rewritten upstream ID), so a
// stale response carrying call A's nonce has nowhere to land once A has left.
func TestCallUpstream_TimedOutResponseNotMisrouted(t *testing.T) {
	t.Parallel()

	capSink := &idCapturingSink{}
	p := &StdioProxy{
		byUpstreamID: make(map[string]chan upstreamResult),
		upstreamDone: make(chan struct{}),
		upWriter:     capSink,
		// upstreamTimeMs stays 0: callUpstream applies it to BOTH A and B, so A is
		// timed out via its own per-call context while B remains in flight.
	}

	hostID := mcp.RawJSON(`42`)

	// ── Call A: same host ID, times out (no response is ever delivered). ──
	ctxA, cancelA := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelA()
	_, errA := p.callUpstream(ctxA, mcp.RPCMsg{JSONRPC: "2.0", ID: hostID, Method: "tools/call"})
	if errA == nil {
		t.Fatal("call A: expected a timeout error, got nil")
	}
	upIDA := capSink.lastID()
	if upIDA == nil {
		t.Fatal("call A: proxy did not rewrite the upstream ID")
	}
	if mcp.MsgKey(upIDA) == mcp.MsgKey(hostID) {
		t.Fatalf("call A: upstream ID %q must differ from the host ID (no nonce applied)", mcp.MsgKey(upIDA))
	}

	// ── Call B: reuses the SAME host ID, runs concurrently and stays in flight. ──
	type result struct {
		resp mcp.RPCMsg
		err  error
	}
	bDone := make(chan result, 1)
	go func() {
		resp, err := p.callUpstream(context.Background(),
			mcp.RPCMsg{JSONRPC: "2.0", ID: hostID, Method: "tools/call"})
		bDone <- result{resp, err}
	}()

	// Wait until B has registered its own (distinct) nonce on the wire.
	var upIDB *json.RawMessage
	for i := 0; i < 200; i++ {
		if id := capSink.lastID(); id != nil && mcp.MsgKey(id) != mcp.MsgKey(upIDA) {
			upIDB = id
			break
		}
		time.Sleep(time.Millisecond)
	}
	if upIDB == nil {
		t.Fatal("call B: did not observe a fresh upstream nonce ID distinct from A's")
	}

	// ── The LATE response for A arrives, carrying A's stale nonce ID. ──
	staleResult, _ := json.Marshal(map[string]interface{}{"stale": "A"})
	deliverUpstreamResponse(&p.pendingMu, p.byUpstreamID,
		mcp.RPCMsg{JSONRPC: "2.0", ID: upIDA, Result: staleResult})

	// B must NOT have received A's stale response.
	select {
	case r := <-bDone:
		t.Fatalf("call B received a response it should not have (err=%v, result=%s)", r.err, string(r.resp.Result))
	case <-time.After(50 * time.Millisecond):
		// Good: the stale response had nowhere to land.
	}

	// ── B's own response (its nonce) is delivered correctly. ──
	bResult, _ := json.Marshal(map[string]interface{}{"correct": "B"})
	deliverUpstreamResponse(&p.pendingMu, p.byUpstreamID,
		mcp.RPCMsg{JSONRPC: "2.0", ID: upIDB, Result: bResult})

	select {
	case r := <-bDone:
		if r.err != nil {
			t.Fatalf("call B: expected its own response, got error %v", r.err)
		}
		if string(r.resp.Result) != string(bResult) {
			t.Fatalf("call B: got wrong result %s, want %s", string(r.resp.Result), string(bResult))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("call B: never received its own (correctly routed) response")
	}
}

// TestCallUpstream_MalformedResponseRejected pins that awaitNonced refuses any reply that
// is not a valid JSON-RPC response: one carrying neither result/error (an empty
// {"jsonrpc":"2.0","id":...}) or both, AND a method-bearing reply that echoes a live nonce
// (a response has no method — refused by !IsResponse(), matching correlateUpstreamReply on
// the HTTP-upstream bridge). Without the method check, {"id":nonce,"method":X,"result":Y}
// slips through the result/error-only test and is forwarded to the host as a response.
func TestCallUpstream_MalformedResponseRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		resp mcp.RPCMsg
	}{
		{
			name: "neither result nor error",
			resp: mcp.RPCMsg{JSONRPC: "2.0"},
		},
		{
			name: "both result and error",
			resp: mcp.RPCMsg{JSONRPC: "2.0", Result: json.RawMessage(`{"ok":true}`), Error: &mcp.RPCError{Code: -32000, Message: "boom"}},
		},
		{
			// Method-bearing WITH a result: passes the result/error invariant but is not a
			// response (it carries a method), so it must still be refused — the divergence
			// from the HTTP bridge that the result/error-only check missed.
			name: "method-bearing with result",
			resp: mcp.RPCMsg{JSONRPC: "2.0", Method: "roots/list", Result: json.RawMessage(`{"ok":true}`)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			capSink := &idCapturingSink{}
			p := &StdioProxy{
				byUpstreamID: make(map[string]chan upstreamResult),
				upstreamDone: make(chan struct{}),
				upWriter:     capSink,
			}

			hostID := mcp.RawJSON(`7`)
			type result struct {
				resp mcp.RPCMsg
				err  error
			}
			done := make(chan result, 1)
			go func() {
				resp, err := p.callUpstream(context.Background(),
					mcp.RPCMsg{JSONRPC: "2.0", ID: hostID, Method: "tools/call"})
				done <- result{resp, err}
			}()

			var upID *json.RawMessage
			for i := 0; i < 200; i++ {
				if id := capSink.lastID(); id != nil {
					upID = id
					break
				}
				time.Sleep(time.Millisecond)
			}
			if upID == nil {
				t.Fatal("proxy did not rewrite and send the upstream nonce ID")
			}

			resp := tt.resp
			resp.ID = upID
			deliverUpstreamResponse(&p.pendingMu, p.byUpstreamID, resp)

			select {
			case r := <-done:
				if r.err == nil {
					t.Fatalf("expected a fail-closed error for a malformed response, got resp=%+v", r.resp)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("callUpstream never returned")
			}
		})
	}
}

// TestReadUpstream_MethodBearingReplyOnLiveNonceNotForwarded pins the nonce-reply
// correlation guard on the subprocess path: a message from the upstream that echoes a
// LIVE outstanding nonce AND carries a method (IsRequest()==true) must be routed to the
// waiting caller, NOT reclassified as a server-initiated request and forwarded to the
// host. This mirrors correlateUpstreamReply's refusal on the HTTP-upstream bridge, so the
// invariant holds symmetrically on both transports.
func TestReadUpstream_MethodBearingReplyOnLiveNonceNotForwarded(t *testing.T) {
	t.Parallel()

	upR, upW := io.Pipe()
	hw := &mockHostWriter{}
	ch := make(chan upstreamResult, 1)
	nonce := mcp.RawJSON(`"eunox-up-7"`)

	p := &StdioProxy{
		pdp:          pdp.AlwaysAllowPDP{},
		sessionID:    "unit-test-sess",
		byUpstreamID: map[string]chan upstreamResult{mcp.MsgKey(nonce): ch},
		hostWriter:   mcp.NewMsgWriter(&writerAdapter{hw}),
		upReader:     mcp.NewMsgReader(upR),
		upstreamDone: make(chan struct{}),
	}

	readerDone := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		p.readUpstream(ctx)
		close(readerDone)
	}()

	// A method-bearing message echoing the live nonce — the reclassification the guard
	// must prevent.
	line, err := json.Marshal(mcp.RPCMsg{JSONRPC: "2.0", ID: nonce, Method: "roots/list"})
	if err != nil {
		t.Fatalf("marshal poisoned reply: %v", err)
	}
	if _, err := upW.Write(append(line, '\n')); err != nil {
		t.Fatalf("write to upstream pipe: %v", err)
	}

	select {
	case got := <-ch:
		if mcp.MsgKey(got.msg.ID) != mcp.MsgKey(nonce) {
			t.Fatalf("delivered reply has id %s, want %s", mcp.MsgKey(got.msg.ID), mcp.MsgKey(nonce))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a method-bearing reply on a live nonce was not routed to the waiting caller")
	}

	// Stop the reader and confirm nothing was forwarded to the host as a server-initiated
	// request (the guard path never touches hostWriter).
	upW.Close()
	<-readerDone
	for _, m := range hw.messages {
		if m.Method == "roots/list" {
			t.Fatalf("a method-bearing reply on a live nonce was forwarded to the host as a server-initiated request: %+v", m)
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// closedUpstream returns a StdioProxy whose upstreamDone channel is already
// closed, so callUpstream returns "upstream exited" immediately.
func closedUpstream(t *testing.T) (*StdioProxy, *mockHostWriter) {
	t.Helper()
	hw := &mockHostWriter{}
	done := make(chan struct{})
	close(done)
	p := &StdioProxy{
		pdp:          pdp.AlwaysAllowPDP{},
		sessionID:    "unit-test-sess",
		hostWriter:   mcp.NewMsgWriter(&writerAdapter{hw}),
		upWriter:     mcp.NewMsgWriter(io.Discard),
		upstreamDone: done,
	}
	return p, hw
}

// respondingProxy returns a StdioProxy backed by a pair of io.Pipe goroutines
// that echo back a static response for each upstream request.
func respondingProxy(t *testing.T, resp mcp.RPCMsg) (*StdioProxy, *mockHostWriter) {
	t.Helper()
	hw := &mockHostWriter{}

	upR, upW := io.Pipe() // proxy writes requests here; goroutine reads
	done := make(chan struct{})

	p := &StdioProxy{
		pdp:          pdp.AlwaysAllowPDP{},
		sessionID:    "unit-test-sess",
		hostWriter:   mcp.NewMsgWriter(&writerAdapter{hw}),
		upWriter:     mcp.NewMsgWriter(upW),
		upstreamDone: done,
	}

	// Goroutine: read the request from upR, push canned response into pending.
	go func() {
		defer upR.Close()
		reader := mcp.NewMsgReader(upR)
		for {
			req, err := reader.Read()
			if err != nil {
				return
			}
			key := mcp.MsgKey(req.ID)
			p.pendingMu.Lock()
			ch, ok := p.byUpstreamID[key]
			p.pendingMu.Unlock()
			if ok {
				canned := resp
				canned.ID = req.ID
				ch <- upstreamResult{msg: canned}
			}
		}
	}()

	t.Cleanup(func() { upW.Close() })
	return p, hw
}

// ── NewStdioProxy ─────────────────────────────────────────────────────────

func TestNewStdioProxy_Defaults(t *testing.T) {
	t.Parallel()
	p := NewStdioProxy(StdioProxyOptions{
		Command:    "echo",
		Args:       []string{"hello"},
		SessionID:  "test-sid",
		ShutdownMs: 0, // should default to 5000
	})
	if p == nil {
		t.Fatal("NewStdioProxy returned nil")
	}
	if p.shutdownMs != 5000 {
		t.Errorf("shutdownMs default: want 5000, got %d", p.shutdownMs)
	}
	if _, ok := p.pdp.(pdp.DenyAllPDP); !ok {
		t.Errorf("pdp should default to fail-closed pdp.DenyAllPDP{}, got %T", p.pdp)
	}
	if p.hostToUp == nil {
		t.Error("hostToUp map (the in-flight host-ID set) should be initialized")
	}
}

func TestNewStdioProxy_WithExplicitPDP(t *testing.T) {
	t.Parallel()
	p := NewStdioProxy(StdioProxyOptions{
		Command:    "echo",
		PDP:        pdp.AlwaysAllowPDP{},
		ShutdownMs: 200,
	})
	if p.shutdownMs != 200 {
		t.Errorf("shutdownMs: want 200, got %d", p.shutdownMs)
	}
}

// ── handleToolsCall ───────────────────────────────────────────────────────

func TestStdioHandleToolsCall_InvalidParams(t *testing.T) {
	t.Parallel()
	p, hw := closedUpstream(t)
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/call",
		Params: json.RawMessage(`"not-an-object"`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error == nil {
		t.Fatal("expected JSON-RPC error for invalid params")
	}
	if hw.messages[0].Error.Code != -32602 {
		t.Errorf("want -32602, got %d", hw.messages[0].Error.Code)
	}
}

func TestStdioHandleToolsCall_UpstreamError(t *testing.T) {
	t.Parallel()
	p, hw := closedUpstream(t)
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"read_file","arguments":{"path":"/x"}}`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error == nil {
		t.Fatal("expected error from closed upstream")
	}
}

func TestStdioHandleToolsCall_DenyNotDryRun(t *testing.T) {
	t.Parallel()
	hw := &mockHostWriter{}
	done := make(chan struct{})
	close(done)
	p := &StdioProxy{
		pdp:          denyAllPDP{},
		sessionID:    "deny-sess",
		hostWriter:   mcp.NewMsgWriter(&writerAdapter{hw}),
		upWriter:     mcp.NewMsgWriter(io.Discard),
		upstreamDone: done,
	}
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`3`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"blocked_tool","arguments":{}}`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error == nil {
		t.Fatal("expected denial response")
	}
	if hw.messages[0].Error.Code != capability.JSONRPCCodeCapabilityDenied {
		t.Errorf("want CAPABILITY_DENIED code, got %d", hw.messages[0].Error.Code)
	}
}

func TestStdioHandleToolsCall_DenyDryRun(t *testing.T) {
	t.Parallel()
	fakeResult, _ := json.Marshal(mcptest.ToolCallResult{
		Content: []mcptest.Content{{Type: "text", Text: "ok"}},
	})
	p, hw := respondingProxy(t, mcp.RPCMsg{JSONRPC: "2.0", Result: fakeResult})
	p.pdp = denyAllPDP{}
	p.audit = true

	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`5`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"blocked_tool","arguments":{}}`),
	})
	if len(hw.messages) != 1 {
		t.Fatalf("want 1 message, got %d", len(hw.messages))
	}
	if hw.messages[0].Error != nil {
		t.Errorf("dry-run should forward despite denial; got error: %+v", hw.messages[0].Error)
	}
}

// TestStdioHandleToolsCall_KillSwitchHardBlocksInAuditMode pins that a
// kill switch denial must hard-block even when the proxy is in audit (observe)
// mode. Otherwise /control/kill is inoperative for audit-mode routes — the
// request would be forwarded to the upstream and merely logged as a would-be
// deny.
func TestStdioHandleToolsCall_KillSwitchHardBlocksInAuditMode(t *testing.T) {
	t.Parallel()
	fakeResult, _ := json.Marshal(mcptest.ToolCallResult{
		Content: []mcptest.Content{{Type: "text", Text: "ok"}},
	})
	p, hw := respondingProxy(t, mcp.RPCMsg{JSONRPC: "2.0", Result: fakeResult})

	ks := killswitch.NewInMemory()
	if err := ks.KillSession(context.Background(), p.sessionID); err != nil {
		t.Fatalf("KillSession: %v", err)
	}
	p.pdp = newTestManifestPDPWithKS(ks,
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	p.audit = true // audit mode: policy denials would normally be forwarded

	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"read_file","arguments":{"path":"/x"}}`),
	})
	if len(hw.messages) != 1 {
		t.Fatalf("want 1 message, got %d", len(hw.messages))
	}
	if hw.messages[0].Error == nil {
		t.Fatal("kill switch must hard-block in audit mode, not forward; got a non-error response")
	}
	if hw.messages[0].Error.Code != capability.JSONRPCCodeAuthorizationFailed {
		t.Errorf("want AUTHORIZATION_FAILED (kill switch), got code %d", hw.messages[0].Error.Code)
	}
}

// TestStdioHandleToolsCall_AllowedValuesLargeIntPrecision is the end-to-end
// regression for the large-integer authorization bug. A manifest authorizes
// amount == 9007199254740992 (2^53) only; a caller sending 9007199254740993
// (2^53+1) must be denied. The two share a single float64 representation, so when
// request arguments were decoded with the default float64 path the attacker's
// value rounded down to the allowed one and was wrongly authorized — while the
// upstream still received the original, distinct bytes. decodeParams now decodes
// arguments with UseNumber so the engine compares them at full int64 precision.
func TestStdioHandleToolsCall_AllowedValuesLargeIntPrecision(t *testing.T) {
	t.Parallel()

	manifestPDP := newTestManifestPDP(capability.Constraint{
		Target:  "tool:transfer",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.AllowedValuesCondition{
				Argument: "amount",
				Values:   []interface{}{int64(9007199254740992)},
			},
		},
	})

	call := func(amount string) mcp.RPCMsg {
		fakeResult, _ := json.Marshal(mcptest.ToolCallResult{Content: []mcptest.Content{{Type: "text", Text: "ok"}}})
		p, hw := respondingProxy(t, mcp.RPCMsg{JSONRPC: "2.0", Result: fakeResult})
		p.pdp = manifestPDP
		p.handleHostRequest(context.Background(), mcp.RPCMsg{
			JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/call",
			Params: json.RawMessage(`{"name":"transfer","arguments":{"amount":` + amount + `}}`),
		})
		if len(hw.messages) != 1 {
			t.Fatalf("amount %s: want 1 message, got %d", amount, len(hw.messages))
		}
		return hw.messages[0]
	}

	// The exact allowed value is forwarded (allowed).
	if got := call("9007199254740992"); got.Error != nil {
		t.Errorf("amount 9007199254740992 should be allowed, got error %+v", got.Error)
	}
	// The distinct large integer must be denied, not conflated with the allowed one.
	if got := call("9007199254740993"); got.Error == nil {
		t.Error("amount 9007199254740993 is distinct from the allowed 9007199254740992 (they only collide as float64); it must be denied, got a forwarded result")
	}
}

// ── handleResourcesRead ───────────────────────────────────────────────────

func TestStdioHandleResourcesRead_InvalidParams(t *testing.T) {
	t.Parallel()
	p, hw := closedUpstream(t)
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "resources/read",
		Params: json.RawMessage(`"bad"`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error == nil {
		t.Fatal("expected error for invalid params")
	}
}

func TestStdioHandleResourcesRead_EmptyURI(t *testing.T) {
	t.Parallel()
	p, hw := closedUpstream(t)
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: "resources/read",
		Params: json.RawMessage(`{"uri":""}`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error == nil {
		t.Fatal("expected error for empty URI")
	}
}

func TestStdioHandleResourcesRead_UpstreamError(t *testing.T) {
	t.Parallel()
	p, hw := closedUpstream(t)
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`3`), Method: "resources/read",
		Params: json.RawMessage(`{"uri":"file:///test.txt"}`),
	})
	if len(hw.messages) == 0 {
		t.Fatal("expected error response from closed upstream")
	}
}

func TestStdioHandleResourcesRead_Deny(t *testing.T) {
	t.Parallel()
	hw := &mockHostWriter{}
	done := make(chan struct{})
	close(done)
	p := &StdioProxy{
		pdp:          denyAllPDP{},
		sessionID:    "deny-sess",
		hostWriter:   mcp.NewMsgWriter(&writerAdapter{hw}),
		upWriter:     mcp.NewMsgWriter(io.Discard),
		upstreamDone: done,
	}
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`4`), Method: "resources/read",
		Params: json.RawMessage(`{"uri":"file:///secret.txt"}`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error == nil {
		t.Fatal("expected denial")
	}
}

// ── handleResourcesSubscribe ──────────────────────────────────────────────

func TestStdioHandleResourcesSubscribe_InvalidParams(t *testing.T) {
	t.Parallel()
	p, hw := closedUpstream(t)
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "resources/subscribe",
		Params: json.RawMessage(`"bad"`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error == nil {
		t.Fatal("expected error for invalid params")
	}
}

func TestStdioHandleResourcesSubscribe_EmptyURI(t *testing.T) {
	t.Parallel()
	p, hw := closedUpstream(t)
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: "resources/subscribe",
		Params: json.RawMessage(`{"uri":""}`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error == nil {
		t.Fatal("expected error for empty URI")
	}
}

func TestStdioHandleResourcesSubscribe_UpstreamError(t *testing.T) {
	t.Parallel()
	p, hw := closedUpstream(t)
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`3`), Method: "resources/subscribe",
		Params: json.RawMessage(`{"uri":"file:///watch.txt"}`),
	})
	if len(hw.messages) == 0 {
		t.Fatal("expected response when upstream is closed")
	}
}

func TestStdioHandleResourcesSubscribe_Deny(t *testing.T) {
	t.Parallel()
	hw := &mockHostWriter{}
	done := make(chan struct{})
	close(done)
	p := &StdioProxy{
		pdp:          denyAllPDP{},
		sessionID:    "deny-sub",
		hostWriter:   mcp.NewMsgWriter(&writerAdapter{hw}),
		upWriter:     mcp.NewMsgWriter(io.Discard),
		upstreamDone: done,
	}
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`4`), Method: "resources/subscribe",
		Params: json.RawMessage(`{"uri":"file:///secret.txt"}`),
	})
	if len(hw.messages) != 1 || hw.messages[0].Error == nil {
		t.Fatal("expected denial")
	}
}

// ── handleToolsList / handleResourcesList / handlePromptsList ─────────────

func TestStdioHandleToolsList_UpstreamError(t *testing.T) {
	t.Parallel()
	p, hw := closedUpstream(t)
	p.handleHostRequest(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/list"})
	if len(hw.messages) == 0 {
		t.Fatal("expected error response")
	}
}

func TestStdioHandleResourcesList_UpstreamError(t *testing.T) {
	t.Parallel()
	p, hw := closedUpstream(t)
	p.handleHostRequest(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "resources/list"})
	if len(hw.messages) == 0 {
		t.Fatal("expected error response")
	}
}

func TestStdioHandlePromptsList_UpstreamError(t *testing.T) {
	t.Parallel()
	p, hw := closedUpstream(t)
	p.handleHostRequest(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "prompts/list"})
	if len(hw.messages) == 0 {
		t.Fatal("expected error response")
	}
}

// TestStdioHandleToolsList_SuccessWritesAllowRecord verifies that a successful
// */list enumeration writes an allow audit record, so the audit tape is not
// blind to tool/resource/prompt listing.
func TestStdioHandleToolsList_SuccessWritesAllowRecord(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)

	raw, _ := json.Marshal(map[string]interface{}{"tools": []interface{}{}})
	p, hw := respondingProxy(t, mcp.RPCMsg{JSONRPC: "2.0", Result: raw})
	p.sink = sink
	p.sessionID = "stdio-list-allow"

	p.handleHostRequest(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/list"})
	if len(hw.messages) != 1 || hw.messages[0].Error != nil {
		t.Fatalf("expected a successful list response, got %+v", hw.messages)
	}

	_ = sink.Close()
	rec := findAuditRecord(readAuditRecords(t, logPath), "tools/list", "allow")
	if rec == nil {
		t.Fatal("no allow audit record written for the successful tools/list")
	}
}

// ── handlePromptsGet ──────────────────────────────────────────────────────

func TestStdioHandlePromptsGet_NotManifestPDP(t *testing.T) {
	t.Parallel()
	// prompts/get flows through dispatchRequest → dispatchPromptsGet →
	// enforcedForwardCore; with a closed upstream the forward fails and the host
	// gets an upstream-error response.
	p, hw := closedUpstream(t)
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "prompts/get",
		Params: json.RawMessage(`{"name":"my-prompt"}`),
	})
	if len(hw.messages) == 0 {
		t.Fatal("expected upstream-error response when upstreamDone is closed")
	}
}

// ── readUpstream (stdio) ──────────────────────────────────────────────────

func TestStdioReadUpstream_Paths(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	hw := &mockHostWriter{}

	p := &StdioProxy{
		pdp:          pdp.AlwaysAllowPDP{},
		sessionID:    "read-sess",
		hostWriter:   mcp.NewMsgWriter(&writerAdapter{hw}),
		upWriter:     mcp.NewMsgWriter(io.Discard),
		upReader:     mcp.NewMsgReader(pr),
		upstreamDone: make(chan struct{}),
	}

	// Start readUpstream in a goroutine first (io.Pipe is unbuffered).
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		p.readUpstream(context.Background())
	}()

	writer := mcp.NewMsgWriter(pw)
	// Notification → forwarded to host
	_ = writer.Write(mcp.RPCMsg{JSONRPC: "2.0", Method: "notifications/something"})
	// Server-initiated request (sampling denied by default with alwaysAllowPDP)
	_ = writer.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`10`), Method: "sampling/createMessage",
		Params: json.RawMessage(`{}`)})
	// Response with no matching pending entry → silently dropped
	_ = writer.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`99`)})
	// Close the pipe → EOF → readUpstream returns
	pw.Close()

	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("readUpstream did not return after pipe was closed")
	}

	// Notification should have been forwarded to host
	found := false
	for _, m := range hw.messages {
		if m.Method == "notifications/something" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("notification not found in host messages; got: %+v", hw.messages)
	}
}

// TestStdioReadUpstream_KilledSessionDropsNotification is the regression for the
// stdio upstream->host notification relay ignoring the kill switch: a killed
// session must stop receiving upstream notifications (the stdio equivalent of the
// HTTP transport shutting its SSE relay), and a live session keeps receiving them.
func TestStdioReadUpstream_KilledSessionDropsNotification(t *testing.T) {
	t.Parallel()

	run := func(killed bool) []mcp.RPCMsg {
		ks := killswitch.NewInMemory()
		if killed {
			_ = ks.KillSession(context.Background(), "sess")
		}
		hw := &mockHostWriter{}
		input := `{"jsonrpc":"2.0","method":"notifications/progress","params":{"p":1}}` + "\n"
		p := &StdioProxy{
			pdp:          pdp.NewAlwaysAllowPDP(ks),
			sessionID:    "sess",
			hostWriter:   mcp.NewMsgWriter(&writerAdapter{hw}),
			upWriter:     mcp.NewMsgWriter(io.Discard),
			upReader:     mcp.NewMsgReader(strings.NewReader(input)),
			upstreamDone: make(chan struct{}),
		}
		p.readUpstream(context.Background()) // returns at EOF
		return hw.messages
	}

	if got := run(true); len(got) != 0 {
		t.Fatalf("killed session must not relay upstream notifications, got %+v", got)
	}
	if got := run(false); len(got) != 1 || got[0].Method != "notifications/progress" {
		t.Fatalf("live session must relay the upstream notification, got %+v", got)
	}
}

// ── stdio list-handler upstream-failure audit ─────────────────────────────

// TestStdioHandleList_UpstreamErrorWritesAuditRecord verifies that a stdio
// list-handler upstream failure leaves a deny record with a structured
// infrastructure code, matching the HTTP transport.
func TestStdioHandleList_UpstreamErrorWritesAuditRecord(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)

	p, hw := closedUpstream(t)
	p.sink = sink
	p.sessionID = "stdio-list-audit"
	p.audit = true // even in audit mode, an upstream failure is enforced (host gets the error)

	p.handleHostRequest(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/list"})
	if len(hw.messages) != 1 || hw.messages[0].Error == nil {
		t.Fatal("expected an error response from the closed upstream")
	}

	_ = sink.Close() // flush the drainer; idempotent with t.Cleanup
	rec := findAuditRecord(readAuditRecords(t, logPath), "tools/list", "deny")
	if rec == nil {
		t.Fatal("no deny audit record written for the failed tools/list")
	}
	if code, _ := rec["denial_code"].(string); code != "UPSTREAM_ERROR" {
		t.Errorf("denial_code = %q, want UPSTREAM_ERROR", code)
	}
	if ao, _ := rec["audit_only"].(bool); ao {
		t.Error("upstream-failure record marked audit_only; infrastructure failures are enforced outcomes")
	}
}

func TestWithUpstreamTimeout_StdioProxy(t *testing.T) {
	t.Parallel()
	p := &StdioProxy{upstreamTimeMs: 50}
	ctx, cancel := p.withUpstreamTimeout(context.Background())
	defer cancel()

	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Errorf("expected DeadlineExceeded, got %v", ctx.Err())
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("regression: StdioProxy.withUpstreamTimeout did not fire")
	}
}

func TestWithUpstreamTimeout_StdioProxy_NoTimeout(t *testing.T) {
	t.Parallel()
	p := &StdioProxy{upstreamTimeMs: 0}
	ctx, cancel := p.withUpstreamTimeout(context.Background())
	defer cancel()

	select {
	case <-ctx.Done():
		t.Error("regression: context must not be canceled when no timeout is set")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestCallUpstream_DuplicateID_Stdio(t *testing.T) {
	t.Parallel()
	proxy := &StdioProxy{
		upstreamDone: make(chan struct{}),
		upWriter:     mcp.NewMsgWriter(io.Discard),
	}

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`99`), Method: "tools/call"}
	key := mcp.MsgKey(msg.ID)

	// hostToUp IS the in-flight host-ID set; seeding it makes this ID look in-flight.
	proxy.pendingMu.Lock()
	proxy.hostToUp = map[string]*json.RawMessage{key: nil}
	proxy.pendingMu.Unlock()

	_, err := proxy.callUpstream(context.Background(), msg)
	if err == nil {
		t.Error("regression: duplicate ID must return an error in StdioProxy.callUpstream")
	}

	proxy.pendingMu.Lock()
	_, stillHeld := proxy.hostToUp[key]
	proxy.pendingMu.Unlock()
	if !stillHeld {
		t.Error("regression: the existing in-flight host ID must not be evicted")
	}
}

// ── Stdio proxy goroutine lifecycle ─────────────────────────────

// TestStdioProxy_CallUpstreamExitsOnUpstreamDone verifies that callUpstream
// returns promptly with a non-nil error when p.upstreamDone is closed.
func TestStdioProxy_CallUpstreamExitsOnUpstreamDone(t *testing.T) {
	proxy := &StdioProxy{
		upstreamDone: make(chan struct{}),
		upWriter:     mcp.NewMsgWriter(io.Discard),
	}

	close(proxy.upstreamDone)

	ctx := context.Background()
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/call"}

	result := make(chan error, 1)
	go func() {
		_, err := proxy.callUpstream(ctx, msg)
		result <- err
	}()

	select {
	case err := <-result:
		if err == nil {
			t.Error("regression: callUpstream returned nil error when upstream exited")
		}
	case <-time.After(2 * time.Second):
		t.Error("regression: callUpstream did not return after upstreamDone was closed")
	}
}

// TestStdioProxy_CallUpstreamExitsOnUpstreamDoneWhilePending verifies that a
// goroutine already blocked inside callUpstream returns promptly when the
// upstream exits mid-flight.
func TestStdioProxy_CallUpstreamExitsOnUpstreamDoneWhilePending(t *testing.T) {
	upstreamDone := make(chan struct{})

	proxy := &StdioProxy{
		upstreamDone: upstreamDone,
		upWriter:     mcp.NewMsgWriter(io.Discard),
	}

	ctx := context.Background()
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`99`), Method: "tools/call"}

	result := make(chan error, 1)
	go func() {
		_, err := proxy.callUpstream(ctx, msg)
		result <- err
	}()

	time.Sleep(20 * time.Millisecond)
	close(upstreamDone)

	select {
	case err := <-result:
		if err == nil {
			t.Error("regression: callUpstream returned nil error when upstream exited mid-flight")
		}
	case <-time.After(2 * time.Second):
		t.Error("regression: callUpstream did not unblock after upstreamDone was closed mid-flight")
	}
}

// blockingDeadlineWriter models a subprocess stdin pipe whose reader stopped draining:
// once a per-write deadline is armed, Write blocks until it passes and returns an error
// wrapping os.ErrDeadlineExceeded, exactly as a pollable *os.File pipe write does. It
// implements the write-deadline interface so mcp.NewMsgWriterWithTimeout arms it.
type blockingDeadlineWriter struct {
	mu       sync.Mutex
	deadline time.Time
}

func (w *blockingDeadlineWriter) SetWriteDeadline(t time.Time) error {
	w.mu.Lock()
	w.deadline = t
	w.mu.Unlock()
	return nil
}

func (w *blockingDeadlineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	d := w.deadline
	w.mu.Unlock()
	if d.IsZero() {
		return len(p), nil
	}
	if rem := time.Until(d); rem > 0 {
		time.Sleep(rem)
	}
	return 0, &os.PathError{Op: "write", Path: "pipe", Err: os.ErrDeadlineExceeded}
}

// TestCallUpstream_WriteWedgeTearsDownUpstream is the regression for the stdio sampling +
// write-wedge deadlock: when a bounded upstream pipe write times out (the upstream stopped
// draining its stdin), callUpstream must NOT hang holding the MsgWriter mutex and a
// fwdHostWrites slot. Instead it returns ErrUpstreamWriteTimeout promptly, and the writer's
// onPoison hook (killUpstream) tears the upstream down so readUpstream EOFs and the session
// recovers rather than hanging until SIGINT. Uses a real subprocess (for killUpstream to
// reap) with the real pipe writer replaced by a bounded MsgWriter over a blocking fake.
func TestCallUpstream_WriteWedgeTearsDownUpstream(t *testing.T) {
	t.Parallel()

	p := &StdioProxy{
		command:      "sleep",
		args:         []string{"60"},
		byUpstreamID: make(map[string]chan upstreamResult),
		hostToUp:     make(map[string]*json.RawMessage),
	}
	if err := p.connectUpstream(context.Background()); err != nil {
		t.Skipf("could not spawn `sleep` subprocess (environment lacks it): %v", err)
	}
	// Best-effort kill on any exit path; the assertion below owns the single Wait.
	t.Cleanup(func() {
		if p.upCmd != nil && p.upCmd.Process != nil {
			_ = p.upCmd.Process.Kill()
		}
	})
	// Replace the real pipe writer with a bounded MsgWriter over a writer that wedges, wired
	// to the SAME onPoison teardown hook production uses (killUpstream), so the write times
	// out at ~50ms and tears the subprocess down.
	p.upWriter = mcp.NewMsgWriterWithTimeout(&blockingDeadlineWriter{}, 50*time.Millisecond, p.killUpstream)

	done := make(chan error, 1)
	go func() {
		_, err := p.callUpstream(context.Background(),
			mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/call"})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, mcp.ErrUpstreamWriteTimeout) {
			t.Fatalf("callUpstream err = %v, want ErrUpstreamWriteTimeout", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("callUpstream hung on a wedged upstream write instead of returning the timeout error")
	}

	// The write wedge must have torn the upstream down via onPoison=killUpstream, so Wait
	// (owned solely here) reaps the signalled process promptly.
	waited := make(chan error, 1)
	go func() { waited <- p.upCmd.Wait() }()
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream subprocess was not killed on the write timeout")
	}
}
