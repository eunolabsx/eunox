// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Tests for the remote HTTP upstream mode (--upstream-url).
//
// Each test starts a fake MCP HTTP server using httptest.NewServer, wires an
// HTTPProxy against it, and exercises the proxy's handleMCP handler directly
// (bypassing Serve so no real TCP port is needed).

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/mcp/mcptest"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// -----------------------------------------------------------------
// Fake upstream MCP server
// -----------------------------------------------------------------

// fakeRequest records a single HTTP request received by the fake upstream.
type fakeRequest struct {
	Method    string
	SessionID string
	Body      mcp.RPCMsg
}

// fakeUpstream is a minimal MCP HTTP server for testing.
// It handles initialize + notifications/initialized correctly, and returns
// configurable responses for tools/call.
type fakeUpstream struct {
	mu       sync.Mutex
	received []fakeRequest

	toolResult json.RawMessage // returned for tools/call; defaults to a text result

	// toolCallback, when non-nil, is called instead of using toolResult.
	// It receives the tool name and arguments and returns a raw JSON result.
	toolCallback func(name string, args map[string]interface{}) json.RawMessage
}

func newFakeUpstream() *fakeUpstream {
	defaultResult, _ := json.Marshal(mcptest.ToolCallResult{
		Content: []mcptest.Content{{Type: "text", Text: `{"ok":true}`}},
	})
	return &fakeUpstream{toolResult: defaultResult}
}

func (f *fakeUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var msg mcp.RPCMsg
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	f.received = append(f.received, fakeRequest{
		Method:    msg.Method,
		SessionID: r.Header.Get(SessionHeader),
		Body:      msg,
	})
	f.mu.Unlock()

	switch msg.Method {
	case "initialize":
		w.Header().Set(SessionHeader, "upstream-sess-1")
		w.Header().Set("Content-Type", "application/json")
		caps, _ := json.Marshal(map[string]interface{}{"tools": map[string]interface{}{}})
		result := mcp.InitResult{
			ProtocolVersion: capability.Revision20251125.String(),
			Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
			ServerInfo:      map[string]interface{}{"name": "fake-upstream", "version": "0.0.1"},
		}
		_ = caps
		resp, _ := mcp.SuccessResponse(msg.ID, result)
		_ = json.NewEncoder(w).Encode(resp)

	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)

	case "tools/call":
		var params mcp.ToolCallParams
		_ = json.Unmarshal(msg.Params, &params)

		var resultBytes json.RawMessage
		f.mu.Lock()
		if f.toolCallback != nil {
			resultBytes = f.toolCallback(params.Name, params.Arguments)
		} else {
			resultBytes = f.toolResult
		}
		f.mu.Unlock()

		resp := mcp.RPCMsg{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Result:  resultBytes,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)

	default:
		// Forward all other methods: echo back a generic success.
		resp, _ := mcp.SuccessResponse(msg.ID, map[string]interface{}{"method": msg.Method})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// Received returns a copy of all requests received so far.
func (f *fakeUpstream) Received() []fakeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]fakeRequest, len(f.received))
	copy(cp, f.received)
	return cp
}

// CountByMethod returns the number of requests with the given method.
func (f *fakeUpstream) CountByMethod(method string) int {
	received := f.Received()
	n := 0
	for i := range received {
		if received[i].Body.Method == method {
			n++
		}
	}
	return n
}

// -----------------------------------------------------------------
// Test helper: proxy server backed by a fake upstream
// -----------------------------------------------------------------

// newTestRemoteProxy creates an HTTPProxy wired to the given fake upstream URL,
// and returns both the proxy and a test HTTP server that routes through its
// handleMCP handler.  The test server is cleaned up automatically.
func newTestRemoteProxy(t *testing.T, upstreamURL string, opts httpProxyOptions) (*HTTPProxy, *httptest.Server) {
	t.Helper()
	opts.UpstreamURL = upstreamURL
	if opts.Port == 0 {
		opts.Port = 3000 // ignored — we're using httptest.Server directly
	}
	// newHTTPProxy now fails closed (DenyAllPDP) on an omitted PDP. These
	// remote-bridge/plumbing tests exercise non-enforcement paths and expect
	// passthrough, so default to AlwaysAllowPDP here; enforcement tests set an
	// explicit PDP in opts.
	if opts.PDP == nil {
		opts.PDP = pdp.AlwaysAllowPDP{}
	}
	proxy := newHTTPProxy(opts)

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", proxy.handleMCP)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return proxy, srv
}

// testHTTPClient is the shared client for postMCP.  The timeout is a backstop
// so a hung proxy fails the test instead of stalling the binary; it sits above
// the proxy's 20-second session-start budget so a test exercising a slow
// initialize fails in the server path under test, not at the client.
var testHTTPClient = &http.Client{Timeout: 30 * time.Second}

// postMCP sends a POST /mcp request to the proxy test server with the given
// rpcMsg body.  Optional sessionID is set as the Mcp-Session-Id header.
func postMCP(t *testing.T, srv *httptest.Server, msg mcp.RPCMsg, sessionID string) *http.Response {
	t.Helper()
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/mcp", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if sessionID != "" {
		req.Header.Set(SessionHeader, sessionID)
	}
	resp, err := testHTTPClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// decodeRPC decodes a JSON-RPC message from an HTTP response body.
func decodeRPC(t *testing.T, resp *http.Response) mcp.RPCMsg {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var msg mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&msg); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return msg
}

// initSession sends an initialize request to the proxy and returns the session ID.
func initSession(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	initMsg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`1`),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{}}`),
	}
	resp := postMCP(t, srv, initMsg, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize: unexpected status %d", resp.StatusCode)
	}
	sid := resp.Header.Get(SessionHeader)
	if sid == "" {
		t.Fatal("initialize: no Mcp-Session-Id in response")
	}
	_ = resp.Body.Close()
	return sid
}

// -----------------------------------------------------------------
// Tests
// -----------------------------------------------------------------

// TestRemoteUpstream_Initialize verifies that an initialize request creates a
// proxy session, returns a session ID, and performs the upstream handshake.
func TestRemoteUpstream_Initialize(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{})

	sid := initSession(t, proxySrv)
	if sid == "" {
		t.Fatal("expected a session ID from proxy")
	}

	// Upstream should have received: initialize + notifications/initialized.
	reqs := fake.Received()
	if len(reqs) < 2 {
		t.Fatalf("expected at least 2 upstream requests, got %d", len(reqs))
	}
	if reqs[0].Body.Method != "initialize" {
		t.Errorf("first upstream request: want initialize, got %q", reqs[0].Body.Method)
	}
	if reqs[1].Body.Method != "notifications/initialized" {
		t.Errorf("second upstream request: want notifications/initialized, got %q", reqs[1].Body.Method)
	}
}

// TestRemoteUpstream_InitializeRejected regression for the remote
// path: when the remote upstream returns a JSON-RPC error to initialize,
// initRemoteUpstream must fail the handshake so no session is created — it must
// not fall through to notifications/initialized and hand the client a session
// backed by an un-initialized upstream.
func TestRemoteUpstream_InitializeRejected(t *testing.T) {
	var mu sync.Mutex
	gotInitialized := false
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg mcp.RPCMsg
		_ = json.NewDecoder(r.Body).Decode(&msg)
		switch msg.Method {
		case "initialize":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(mcp.ErrorResponse(msg.ID, -32600, "unsupported protocol version"))
		case "notifications/initialized":
			mu.Lock()
			gotInitialized = true
			mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusOK)
		}
	})))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{})

	initMsg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("1"), Method: "initialize", Params: json.RawMessage(`{}`)}
	resp := postMCP(t, proxySrv, initMsg, "")
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK && resp.Header.Get(SessionHeader) != "" {
		t.Fatalf("proxy created a session despite the upstream rejecting initialize (status %d, session %q)",
			resp.StatusCode, resp.Header.Get(SessionHeader))
	}
	mu.Lock()
	defer mu.Unlock()
	if gotInitialized {
		t.Error("proxy sent notifications/initialized after the upstream rejected initialize")
	}
}

// TestRemoteUpstream_ToolsCallAllowed verifies that a permitted tools/call is
// forwarded to the upstream and its result returned to the client.
func TestRemoteUpstream_ToolsCallAllowed(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{
		PDP: pdp.AlwaysAllowPDP{},
	})

	sid := initSession(t, proxySrv)

	callMsg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`2`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}`),
	}
	resp := postMCP(t, proxySrv, callMsg, sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/call: unexpected status %d", resp.StatusCode)
	}
	msg := decodeRPC(t, resp)
	if msg.Error != nil {
		t.Errorf("tools/call: unexpected error %+v", msg.Error)
	}
	if msg.Result == nil {
		t.Error("tools/call: expected non-nil result")
	}

	// Upstream must have received the tools/call.
	if n := fake.CountByMethod("tools/call"); n != 1 {
		t.Errorf("upstream tools/call count: want 1, got %d", n)
	}
}

// TestRemoteUpstream_MethodBearingReplyFailsClosed verifies callRemoteUpstream
// rejects a reply that echoes the request id but ALSO carries a `method` field. Such
// a non-response reply (IsResponse()==false) must fail closed rather than be forwarded
// to the host as a malformed response — a forged server-initiated request the upstream
// must not be able to inject by echoing the proxy-known id.
func TestRemoteUpstream_MethodBearingReplyFailsClosed(t *testing.T) {
	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in mcp.RPCMsg
		_ = json.NewDecoder(r.Body).Decode(&in)
		w.Header().Set("Content-Type", "application/json")
		switch in.Method {
		case "initialize":
			w.Header().Set(SessionHeader, "upstream-sess-1")
			resp, _ := mcp.SuccessResponse(in.ID, mcp.InitResult{
				ProtocolVersion: capability.Revision20251125.String(),
				Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
				ServerInfo:      map[string]interface{}{"name": "fake", "version": "0"},
			})
			_ = json.NewEncoder(w).Encode(resp)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			if in.ID == nil {
				// A notification (no id to echo, e.g. notifications/cancelled): nothing to
				// forge. Guard the deref so the shared handler can't panic if this test
				// grows to exercise a notification or teardown path.
				w.WriteHeader(http.StatusAccepted)
				return
			}
			// Forge: echo the request id but carry a method (a request/notification shape).
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(*in.ID) + `,"method":"sampling/createMessage","params":{}}`))
		}
	}))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{PDP: pdp.AlwaysAllowPDP{}})
	sid := initSession(t, proxySrv)

	callMsg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`2`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"read_file","arguments":{}}`),
	}
	resp := postMCP(t, proxySrv, callMsg, sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
	msg := decodeRPC(t, resp)
	if msg.Method != "" {
		t.Fatalf("a method-bearing upstream reply must not be forwarded to the host, got method %q", msg.Method)
	}
	if msg.Error == nil {
		t.Fatalf("expected an error response (fail closed) for a non-response reply, got: %+v", msg)
	}
}

// TestRemoteUpstream_UncorrelatableInitializeLeaksNoSession verifies that when a
// remote upstream ALLOCATES a session (sets Mcp-Session-Id) but returns an
// uncorrelatable initialize reply (one echoing the request id but carrying a
// `method` field, so IsResponse()==false), initRemoteUpstream captures the
// upstream session ID BEFORE the correlate gate — so the failed handshake's
// close() teardown still fires a session-termination DELETE rather than leaking
// the remote's server-side state. The forge mirrors
// TestRemoteUpstream_MethodBearingReplyFailsClosed.
func TestRemoteUpstream_UncorrelatableInitializeLeaksNoSession(t *testing.T) {
	var mu sync.Mutex
	var deletedSess string
	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			mu.Lock()
			deletedSess = r.Header.Get(SessionHeader)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var in mcp.RPCMsg
		_ = json.NewDecoder(r.Body).Decode(&in)
		w.Header().Set("Content-Type", "application/json")
		if in.Method == "initialize" {
			// Allocate a session, then forge an uncorrelatable reply: echo the
			// request id but carry a method (a request/notification shape).
			w.Header().Set(SessionHeader, "upstream-sess-leak")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(*in.ID) + `,"method":"sampling/createMessage","params":{}}`))
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{PDP: pdp.AlwaysAllowPDP{}})

	initMsg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`1`),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{}}`),
	}
	resp := postMCP(t, proxySrv, initMsg, "")
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK && resp.Header.Get(SessionHeader) != "" {
		t.Fatalf("proxy created a session despite the uncorrelatable initialize reply (status %d, session %q)",
			resp.StatusCode, resp.Header.Get(SessionHeader))
	}

	// close()'s teardown DELETE runs on a detached background context, so poll
	// briefly for it rather than reading immediately.
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		got := deletedSess
		mu.Unlock()
		if got == "upstream-sess-leak" {
			return // teardown DELETE fired with the allocated session id
		}
		if time.Now().After(deadline) {
			t.Fatalf("teardown DELETE did not fire with the allocated upstream session id (got %q); the captured-before-correlate session leaked", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRemoteUpstream_ToolsCallDenied verifies that a denied tools/call is NOT
// forwarded to the upstream — the proxy returns a denial result directly.
func TestRemoteUpstream_ToolsCallDenied(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	denyPDP := denyAllPDP{}
	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{
		PDP: denyPDP,
	})

	sid := initSession(t, proxySrv)
	beforeCount := fake.CountByMethod("tools/call")

	callMsg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`2`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"write_file","arguments":{"path":"/etc/passwd"}}`),
	}
	resp := postMCP(t, proxySrv, callMsg, sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/call denied: unexpected status %d", resp.StatusCode)
	}
	msg := decodeRPC(t, resp)
	// Denial is a JSON-RPC error response, not a tool result.
	if msg.Error == nil {
		t.Fatal("tools/call denied: expected JSON-RPC error, got nil error")
	}
	if msg.Error.Code != capability.JSONRPCCodeCapabilityDenied {
		t.Errorf("error.code = %d, want %d (CAPABILITY_DENIED)", msg.Error.Code, capability.JSONRPCCodeCapabilityDenied)
	}

	// Upstream must NOT have received any tools/call.
	afterCount := fake.CountByMethod("tools/call")
	if afterCount != beforeCount {
		t.Errorf("upstream received %d tools/call(s) after denial, want 0", afterCount-beforeCount)
	}
}

// TestRemoteUpstream_NonToolsCallForwarded verifies that methods other than
// tools/call are forwarded transparently to the upstream.
func TestRemoteUpstream_NonToolsCallForwarded(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{})

	sid := initSession(t, proxySrv)

	listMsg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`3`),
		Method:  "tools/list",
	}
	resp := postMCP(t, proxySrv, listMsg, sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list: unexpected status %d", resp.StatusCode)
	}
	msg := decodeRPC(t, resp)
	if msg.Error != nil {
		t.Errorf("tools/list: unexpected error: %+v", msg.Error)
	}
	if fake.CountByMethod("tools/list") != 1 {
		t.Error("tools/list was not forwarded to upstream")
	}
}

// TestRemoteUpstream_ListSuccessWritesAllowRecord verifies that a successful
// */list call leaves an allow audit record, so enumeration is on the tape and
// not just the upstream-failure path.
func TestRemoteUpstream_ListSuccessWritesAllowRecord(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	sink, logPath := newTempAuditSink(t)
	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{
		PDP:  pdp.AlwaysAllowPDP{},
		Sink: sink,
	})

	sid := initSession(t, proxySrv)
	resp := postMCP(t, proxySrv, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`3`), Method: "tools/list"}, sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list: unexpected status %d", resp.StatusCode)
	}
	if msg := decodeRPC(t, resp); msg.Error != nil {
		t.Fatalf("tools/list: unexpected error: %+v", msg.Error)
	}

	_ = sink.Close() // flush the drainer; idempotent with t.Cleanup
	rec := findAuditRecordByMethod(readAuditRecords(t, logPath), "tools/list", "allow")
	if rec == nil {
		t.Fatal("no allow audit record written for the successful tools/list")
	}
}

// TestRemoteUpstream_AuthHeaderForwarded verifies that the configured
// upstream-auth-header is sent on every request to the remote upstream.
func TestRemoteUpstream_AuthHeaderForwarded(t *testing.T) {
	const wantHeader = "Authorization"
	const wantValue = "Bearer test-token-123"

	var receivedAuth string
	var mu sync.Mutex

	fake := newFakeUpstream()
	// Wrap fake to capture the Authorization header.
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedAuth = r.Header.Get(wantHeader)
		mu.Unlock()
		fake.ServeHTTP(w, r)
	})
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", wrapped))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{
		UpstreamAuthHeader: wantHeader + ": " + wantValue,
	})

	initSession(t, proxySrv)

	mu.Lock()
	got := receivedAuth
	mu.Unlock()

	if got != wantValue {
		t.Errorf("upstream auth header: want %q, got %q", wantValue, got)
	}
}

// TestRemoteUpstream_SessionDelete verifies that DELETE /mcp closes the proxy
// session and subsequent requests with that session ID return 404.
func TestRemoteUpstream_SessionDelete(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{})

	sid := initSession(t, proxySrv)

	// Send DELETE /mcp with the session ID.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, proxySrv.URL+"/mcp", http.NoBody)
	req.Header.Set(SessionHeader, sid)
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE /mcp: %v", err)
	}
	_ = delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE /mcp: want 204, got %d", delResp.StatusCode)
	}

	// A subsequent POST with the now-deleted session ID should return 404.
	callMsg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`5`),
		Method:  "tools/list",
	}
	resp := postMCP(t, proxySrv, callMsg, sid)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("after DELETE: want 404, got %d", resp.StatusCode)
	}
}

// TestRemoteUpstream_TLSSkipVerify verifies that proxy connects to a TLS
// upstream when --upstream-tls-skip-verify is set.
func TestRemoteUpstream_TLSSkipVerify(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewTLSServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{
		UpstreamTLSSkipVerify: true,
	})

	// Should succeed despite the test server's self-signed certificate.
	sid := initSession(t, proxySrv)
	if sid == "" {
		t.Fatal("expected session ID from TLS upstream")
	}
}

// TestRemoteUpstream_TLSVerifyFails verifies that without skip-verify the
// proxy fails to connect to a TLS upstream with a self-signed certificate.
func TestRemoteUpstream_TLSVerifyFails(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewTLSServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	// No TLS skip — default verification should reject the self-signed cert.
	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{
		UpstreamTLSSkipVerify: false,
	})

	initMsg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`1`),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{}}`),
	}
	resp := postMCP(t, proxySrv, initMsg, "")
	_ = resp.Body.Close()
	// Expect 500 because the upstream TLS handshake fails.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("TLS verify failure: want 500, got %d", resp.StatusCode)
	}
}

// TestRemoteUpstream_UpstreamAuthHeaderParsing verifies edge cases in the
// "Header-Name: Header-Value" parsing (splitHeaderLine) used to attach the upstream
// auth header on every remote request (DoMCPHTTP / DeleteMCPHTTPSession).
func TestRemoteUpstream_UpstreamAuthHeaderParsing(t *testing.T) {
	cases := []struct {
		input     string
		wantName  string
		wantValue string
	}{
		{"Authorization: Bearer tok", "Authorization", "Bearer tok"},
		{"X-Api-Key:  secret", "X-Api-Key", "secret"},
		// Value contains a colon — only the first colon is the separator.
		{"Authorization: Bearer a:b:c", "Authorization", "Bearer a:b:c"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			var gotName, gotValue string
			capture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotName = tc.wantName
				gotValue = r.Header.Get(tc.wantName)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			})
			srv := httptest.NewServer(capture)
			defer srv.Close()

			req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, strings.NewReader("{}"))
			// Exercise the production header parser directly — the same splitHeaderLine
			// path DoMCPHTTP/DeleteMCPHTTPSession use to attach the upstream auth header.
			if name, value, ok := splitHeaderLine(tc.input); ok {
				req.Header.Set(name, value)
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			_ = resp.Body.Close()

			if gotName != tc.wantName || gotValue != tc.wantValue {
				t.Errorf("auth header: got %q=%q, want %q=%q", gotName, gotValue, tc.wantName, tc.wantValue)
			}
		})
	}
}

// TestRemoteUpstream_mcpEndpointURL verifies URL construction.
func TestRemoteUpstream_mcpEndpointURL(t *testing.T) {
	cases := []struct {
		base string
		want string
	}{
		{"https://mcp.stripe.com", "https://mcp.stripe.com/mcp"},
		{"https://mcp.stripe.com/", "https://mcp.stripe.com/mcp"},
		{"https://api.example.com/v1", "https://api.example.com/v1/mcp"},
	}
	for _, tc := range cases {
		s := newTestSession(&httpSession{route: &UpstreamRoute{upstreamURL: tc.base}})
		if got := s.mcpEndpointURL(); got != tc.want {
			t.Errorf("mcpEndpointURL(%q) = %q, want %q", tc.base, got, tc.want)
		}
	}
}

// TestRemoteUpstream_MultipleSessionsIndependent verifies that two concurrent
// sessions each get their own upstream session context and don't interfere.
func TestRemoteUpstream_MultipleSessionsIndependent(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{
		PDP: pdp.AlwaysAllowPDP{},
	})

	sid1 := initSession(t, proxySrv)
	sid2 := initSession(t, proxySrv)

	if sid1 == sid2 {
		t.Fatal("two sessions received the same session ID")
	}

	// Both sessions can make independent tool calls.
	for i, sid := range []string{sid1, sid2} {
		callMsg := mcp.RPCMsg{
			JSONRPC: "2.0",
			ID:      mcp.RawJSON(`10`),
			Method:  "tools/call",
			Params:  json.RawMessage(`{"name":"read_file","arguments":{"path":"/reports/test.pdf"}}`),
		}
		resp := postMCP(t, proxySrv, callMsg, sid)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("session %d: tools/call: unexpected status %d", i+1, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

// -----------------------------------------------------------------
// Helper PDPs used in tests
// -----------------------------------------------------------------

// denyAllPDP always denies every request (tools, resources, prompts).
type denyAllPDP struct{}

func (denyAllPDP) Decide(_ context.Context, _ string, target pdp.EnforceTarget, _ map[string]interface{}, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial: &capability.DenialInfo{
			Code:    "CAPABILITY_DENIED",
			Message: "denied by test policy: " + target.Name,
		},
	}
}

func (denyAllPDP) DecideResourceRead(_ context.Context, _, uri, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial:   &capability.DenialInfo{Code: "CAPABILITY_DENIED", Message: "denied by test policy: " + uri},
	}
}

func (denyAllPDP) DecideResourceCancel(_ context.Context, _, uri, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial:   &capability.DenialInfo{Code: "CAPABILITY_DENIED", Message: "denied by test policy: " + uri},
	}
}

func (denyAllPDP) DecidePromptGet(_ context.Context, _, promptName, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial:   &capability.DenialInfo{Code: "CAPABILITY_DENIED", Message: "denied by test policy: " + promptName},
	}
}

func (denyAllPDP) DecideSampling(_ context.Context, _, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial: &capability.DenialInfo{
			Code:    "SAMPLING_DENIED",
			Message: "denied by test policy: sampling",
		},
	}
}

// HardenRefusal is the identity: a deny-all test PDP holds no pin, no ceiling and no
// obligations, so it has nothing to contribute to another layer's refusal.
func (denyAllPDP) HardenRefusal(_ context.Context, _ string, r capability.EnforceResponse, _ pdp.EnforceTarget, _ map[string]interface{}) capability.EnforceResponse {
	return r
}

func (denyAllPDP) EvaluateClaimCondition(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) (*enforcement.ConditionError, bool) {
	return enforcement.NonCommittingConditionVerdict(ctx, cond, req)
}

// ConditionHandlerOverridden: this fake holds no condition engine, so nothing in it
// can have been overridden.
func (denyAllPDP) ConditionHandlerOverridden(_ string) bool { return false }

func (denyAllPDP) CheckKill(_ context.Context, _ string) *capability.EnforceResponse {
	return nil
}
func (denyAllPDP) CheckAudience(_ context.Context) *capability.EnforceResponse {
	return nil
}
func (denyAllPDP) RecordObservedToolHashes(_ context.Context, _ json.RawMessage) int { return 0 }
func (denyAllPDP) ReleaseSession(_ context.Context, _ string)                        {}
func (denyAllPDP) CommitDeclassified(_ context.Context, _ string, _ *capability.Declassification) ([]string, error) {
	return nil, nil
}
func (denyAllPDP) FilterToolsList(_ context.Context, result json.RawMessage) pdp.ListFilterResult {
	return pdp.ListFilterResult{Result: result}
}
func (denyAllPDP) FilterResourcesList(_ context.Context, result json.RawMessage) pdp.ListFilterResult {
	return pdp.ListFilterResult{Result: result}
}
func (denyAllPDP) FilterPromptsList(_ context.Context, result json.RawMessage) pdp.ListFilterResult {
	return pdp.ListFilterResult{Result: result}
}

// ── DoMCPHTTP: SSE decode + spec headers + transport fallback ────

// TestDoMCPHTTP_SSEResponseDecoded verifies that a 200 OK carrying a
// text/event-stream (SSE) body is correctly decoded into the JSON-RPC message
// by extracting the first complete "data:" event payload.
func TestDoMCPHTTP_SSEResponseDecoded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg mcp.RPCMsg
		_ = json.NewDecoder(r.Body).Decode(&msg)
		resp, _ := mcp.SuccessResponse(msg.ID, map[string]interface{}{"ok": true})
		payload, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", ctSSE+"; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		// An SSE event: an "event:" line, the JSON payload as a "data:" line, and
		// a terminating blank line.
		_, _ = w.Write([]byte("event: message\ndata: " + string(payload) + "\n\n"))
	}))
	t.Cleanup(srv.Close)

	req := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: "tools/call", Params: json.RawMessage(`{}`)}
	out, _, err := DoMCPHTTP(context.Background(), &http.Client{}, srv.URL, req, "", "", capability.Revision20251125)
	if err != nil {
		t.Fatalf("DoMCPHTTP over SSE: %v", err)
	}
	if out.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", out.Error)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(out.Result, &got); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if got["ok"] != true {
		t.Errorf("SSE-decoded result = %v, want ok:true", got)
	}
}

// TestSSEResponseForID_LineTerminatorsAndBOM verifies the SSE parser frames
// events on CR, LF, or CRLF (per WHATWG/EventSource, which MCP Streamable HTTP's
// text/event-stream framing follows) and strips a leading UTF-8 BOM, so a
// spec-conformant upstream using any of these terminators (or a BOM) is still
// decoded by id rather than failing with "no SSE event matched request id".
func TestSSEResponseForID_LineTerminatorsAndBOM(t *testing.T) {
	const payload = `{"jsonrpc":"2.0","id":7,"result":{"ok":true}}`
	const bom = "\ufeff"
	cases := []struct {
		name   string
		stream string
	}{
		{"LF", "event: message\ndata: " + payload + "\n\n"},
		{"CRLF", "event: message\r\ndata: " + payload + "\r\n\r\n"},
		{"bare CR", "event: message\rdata: " + payload + "\r\r"},
		{"leading BOM + LF", bom + "data: " + payload + "\n\n"},
		{"BOM + CRLF", bom + "event: message\r\ndata: " + payload + "\r\n\r\n"},
		{"no trailing blank line", "data: " + payload},
	}
	wantID := mcp.RawJSON(`7`)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := sseResponseForID(strings.NewReader(tc.stream), wantID)
			if err != nil {
				t.Fatalf("sseResponseForID: %v", err)
			}
			if mcp.MsgKey(out.ID) != mcp.MsgKey(wantID) {
				t.Fatalf("id = %s, want %s", mcp.MsgKey(out.ID), mcp.MsgKey(wantID))
			}
			var got map[string]interface{}
			if err := json.Unmarshal(out.Result, &got); err != nil {
				t.Fatalf("decode result: %v", err)
			}
			if got["ok"] != true {
				t.Errorf("result = %v, want ok:true", got)
			}
		})
	}
}

// TestDoMCPHTTP_202ToRequestFailsClosed verifies that a 202 Accepted with no body
// returned to a REQUEST (msg.ID != nil) is a transport error, not a bogus empty
// allow — so the forward core denies rather than recording an allow and handing
// the host a malformed result-less response. A 202 to a NOTIFICATION (msg.ID ==
// nil) remains a valid no-body ack.
func TestDoMCPHTTP_202ToRequestFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	// Request (has an id): a 202 must surface as an error.
	req := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: "tools/call", Params: json.RawMessage(`{}`)}
	if _, _, err := DoMCPHTTP(context.Background(), &http.Client{}, srv.URL, req, "", "", capability.Revision20251125); err == nil {
		t.Fatal("DoMCPHTTP: 202 to a request must return an error (fail closed), got nil")
	}

	// Notification (no id): a 202 is a valid ack, no error.
	notif := mcp.RPCMsg{JSONRPC: "2.0", Method: "notifications/initialized"}
	out, _, err := DoMCPHTTP(context.Background(), &http.Client{}, srv.URL, notif, "", "", capability.Revision20251125)
	if err != nil {
		t.Fatalf("DoMCPHTTP: 202 to a notification must be a clean ack, got %v", err)
	}
	if out.ID != nil || out.Method != "" {
		t.Errorf("202-ack for a notification should be an empty RPCMsg, got %+v", out)
	}
}

// TestDoMCPHTTP_SSEResponseSkipsInterleavedNotification verifies that when an SSE
// stream interleaves an unrelated message (a notification with no id) ahead of the
// actual response, DoMCPHTTP correlates on the JSON-RPC id and returns the response
// rather than mis-decoding the leading notification.
func TestDoMCPHTTP_SSEResponseSkipsInterleavedNotification(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg mcp.RPCMsg
		_ = json.NewDecoder(r.Body).Decode(&msg)
		resp, _ := mcp.SuccessResponse(msg.ID, map[string]interface{}{"ok": true})
		payload, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", ctSSE)
		w.WriteHeader(http.StatusOK)
		// A leading notification (no id), then the real response for our id.
		_, _ = w.Write([]byte(`event: message` + "\n" +
			`data: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}` + "\n\n" +
			"event: message\ndata: " + string(payload) + "\n\n"))
	}))
	t.Cleanup(srv.Close)

	req := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`9`), Method: "tools/call", Params: json.RawMessage(`{}`)}
	out, _, err := DoMCPHTTP(context.Background(), &http.Client{}, srv.URL, req, "", "", capability.Revision20251125)
	if err != nil {
		t.Fatalf("DoMCPHTTP over SSE: %v", err)
	}
	if out.Method != "" {
		t.Fatalf("returned the interleaved notification (method=%q) instead of the response", out.Method)
	}
	if mcp.MsgKey(out.ID) != mcp.MsgKey(req.ID) {
		t.Fatalf("returned id %s, want the request id %s", mcp.MsgKey(out.ID), mcp.MsgKey(req.ID))
	}
	var got map[string]interface{}
	if err := json.Unmarshal(out.Result, &got); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if got["ok"] != true {
		t.Errorf("SSE-decoded result = %v, want ok:true", got)
	}
}

// The gateway remote path must reject an application/json upstream response whose
// JSON-RPC id (here 999) does not match the request id (1): a result with the wrong
// id may carry data computed for a different request, and enforcedForwardCore would
// otherwise overwrite the id with the host's and bind the wrong result to the
// caller, masking the protocol violation.
func TestCallRemoteUpstream_RejectsMismatchedResultID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", CTJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":999,"result":{"ok":true}}`))
	}))
	t.Cleanup(srv.Close)

	s := newTestSession(&httpSession{upHTTPClient: &http.Client{}, route: &UpstreamRoute{upstreamURL: srv.URL}})
	req := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/call", Params: json.RawMessage(`{}`)}
	if _, err := s.callRemoteUpstream(context.Background(), req); err == nil {
		t.Fatal("callRemoteUpstream must reject a mismatched result id")
	}
}

// An error response whose id does not echo the request may carry an error
// message/data computed for a DIFFERENT call, so the gateway REFUSES it (fail closed)
// rather than re-stamping the request id and delivering it — re-stamping would let an
// adversarial upstream inject one caller's error into another's reply (cross-call
// leakage). The caller surfaces a generic upstream error for its own request instead.
func TestCallRemoteUpstream_RejectsMismatchedErrorID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", CTJSON)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32601,"message":"Method not found"}}`))
	}))
	t.Cleanup(srv.Close)

	s := newTestSession(&httpSession{upHTTPClient: &http.Client{}, route: &UpstreamRoute{upstreamURL: srv.URL}})
	req := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/call", Params: json.RawMessage(`{}`)}
	if _, err := s.callRemoteUpstream(context.Background(), req); err == nil {
		t.Fatal("callRemoteUpstream must REJECT a mismatched error id (no cross-call injection), not preserve it")
	}
}

// TestDoMCPHTTP_SetsSpecHeaders verifies that DoMCPHTTP advertises both the JSON
// and SSE Accept types and sends MCP-Protocol-Version on a normal request
// but omits it on the initialize request.
func TestDoMCPHTTP_SetsSpecHeaders(t *testing.T) {
	var mu sync.Mutex
	var accept, protoVer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		accept = r.Header.Get("Accept")
		protoVer = r.Header.Get("MCP-Protocol-Version")
		mu.Unlock()
		var msg mcp.RPCMsg
		_ = json.NewDecoder(r.Body).Decode(&msg)
		resp, _ := mcp.SuccessResponse(msg.ID, map[string]interface{}{})
		w.Header().Set("Content-Type", CTJSON)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)

	// Non-initialize request: Accept set, protocol version present.
	call := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/list"}
	if _, _, err := DoMCPHTTP(context.Background(), &http.Client{}, srv.URL, call, "", "", capability.Revision20251125); err != nil {
		t.Fatalf("DoMCPHTTP tools/list: %v", err)
	}
	mu.Lock()
	gotAccept, gotProto := accept, protoVer
	mu.Unlock()
	if !strings.Contains(gotAccept, CTJSON) || !strings.Contains(gotAccept, ctSSE) {
		t.Errorf("Accept header = %q, want both %q and %q", gotAccept, CTJSON, ctSSE)
	}
	if gotProto != capability.Revision20251125.String() {
		t.Errorf("MCP-Protocol-Version = %q, want %q", gotProto, capability.Revision20251125.String())
	}

	// initialize request: Accept still set, protocol version omitted.
	initMsg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: "initialize", Params: json.RawMessage(`{}`)}
	if _, _, err := DoMCPHTTP(context.Background(), &http.Client{}, srv.URL, initMsg, "", "", capability.Revision20251125); err != nil {
		t.Fatalf("DoMCPHTTP initialize: %v", err)
	}
	mu.Lock()
	gotAccept, gotProto = accept, protoVer
	mu.Unlock()
	if !strings.Contains(gotAccept, CTJSON) || !strings.Contains(gotAccept, ctSSE) {
		t.Errorf("initialize Accept header = %q, want both %q and %q", gotAccept, CTJSON, ctSSE)
	}
	if gotProto != "" {
		t.Errorf("initialize MCP-Protocol-Version = %q, want empty (no negotiated version yet)", gotProto)
	}
}

// TestBuildUpstreamClient_NonDefaultTransportNoPanic verifies that
// BuildUpstreamClient falls back to a fresh transport (rather than panicking)
// when http.DefaultTransport is not a *http.Transport.
func TestBuildUpstreamClient_NonDefaultTransportNoPanic(t *testing.T) {
	saved := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = saved })

	// Replace the default transport with a non-*http.Transport implementation,
	// as a tracing shim or test spy would.
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, http.ErrUseLastResponse
	})

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("BuildUpstreamClient panicked with non-*http.Transport default: %v", rec)
		}
	}()
	client := BuildUpstreamClient(false, 0)
	if client == nil || client.Transport == nil {
		t.Fatal("BuildUpstreamClient returned a client without a transport")
	}
	if _, ok := client.Transport.(*http.Transport); !ok {
		t.Errorf("fallback transport type = %T, want *http.Transport", client.Transport)
	}
}

// TestUpstreamRoute_SharedTransportReusedAcrossSessions pins that a route builds its
// remote-upstream *http.Transport once and reuses it, so client sessions pool warm
// connections instead of each cloning a fresh transport (and its own connection pool).
func TestUpstreamRoute_SharedTransportReusedAcrossSessions(t *testing.T) {
	rt := &UpstreamRoute{name: "r", upstreamTLSSkipVerify: false}
	first := rt.sharedUpstreamTransport(0)
	if first == nil {
		t.Fatal("sharedUpstreamTransport returned nil")
	}
	if second := rt.sharedUpstreamTransport(0); second != first {
		t.Errorf("route must reuse one shared transport across sessions; got distinct instances %p vs %p", first, second)
	}
	// Idle-conn accumulation is bounded by the transport's own caps (the property that
	// makes sharing safe without a per-session CloseIdleConnections).
	if first.MaxIdleConnsPerHost <= 0 {
		t.Errorf("shared transport must bound idle conns per host; MaxIdleConnsPerHost = %d", first.MaxIdleConnsPerHost)
	}
	// Releasing idle conns on a route that opened a transport is a safe no-op here (none
	// are open) and must not panic.
	rt.closeIdleUpstreamConns()
}

// roundTripFunc adapts a function to http.RoundTripper for the transport fallback test.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// ── HTTP session lifecycle ───────────────────────────────────────

// TestHTTPSession_CleanupAfterUpstreamExit verifies that a session registered
// in p.sessions is always removed when its done channel is closed.
func TestHTTPSession_CleanupAfterUpstreamExit(t *testing.T) {
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	sess := newTestSession(&httpSession{
		id:    "test-sess-f01",
		proxy: proxy,
		done:  make(chan struct{}),
	})

	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-sess.done
		proxy.mu.Lock()
		delete(proxy.sessions, sess.id)
		proxy.mu.Unlock()
	}()

	close(sess.done)
	wg.Wait()

	proxy.mu.Lock()
	_, leaked := proxy.sessions[sess.id]
	proxy.mu.Unlock()

	if leaked {
		t.Error("regression: session not removed from map after upstream exit")
	}
}

// TestHTTPSession_NoLeakWhenDoneClosedBeforeCleanupStarts verifies the race
// scenario: done is closed before the cleanup goroutine is scheduled.
func TestHTTPSession_NoLeakWhenDoneClosedBeforeCleanupStarts(t *testing.T) {
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	sess := newTestSession(&httpSession{
		id:    "test-sess-f01b",
		proxy: proxy,
		done:  make(chan struct{}),
	})

	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	close(sess.done)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-sess.done
		proxy.mu.Lock()
		delete(proxy.sessions, sess.id)
		proxy.mu.Unlock()
	}()
	wg.Wait()

	proxy.mu.Lock()
	_, leaked := proxy.sessions[sess.id]
	proxy.mu.Unlock()

	if leaked {
		t.Error("regression: session not removed when done closed before cleanup goroutine started")
	}
}

// ── Upstream timeout on list handlers ────────────────────────────

// stuckUpstream returns an MCP HTTP handler that completes the initialize
// handshake normally and then blocks every other request until the proxy
// aborts it, simulating a hung upstream.  The failsafe timer makes a
// regression fail fast on the elapsed-time check instead of deadlocking
// the test binary.
func stuckUpstream() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg mcp.RPCMsg
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		switch msg.Method {
		case "initialize":
			w.Header().Set(SessionHeader, "upstream-sess-stuck")
			w.Header().Set("Content-Type", CTJSON)
			resp, _ := mcp.SuccessResponse(msg.ID, mcp.InitResult{
				ProtocolVersion: capability.Revision20251125.String(),
				Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
				ServerInfo:      map[string]interface{}{"name": "stuck-upstream", "version": "0.0.1"},
			})
			_ = json.NewEncoder(w).Encode(resp)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			failsafe := time.NewTimer(5 * time.Second)
			defer failsafe.Stop()
			select {
			case <-r.Context().Done():
			case <-failsafe.C:
				resp, _ := mcp.SuccessResponse(msg.ID, map[string]interface{}{})
				w.Header().Set("Content-Type", CTJSON)
				_ = json.NewEncoder(w).Encode(resp)
			}
		}
	})
}

// TestRemoteUpstream_ListHandlersApplyUpstreamTimeout verifies that
// tools/list, resources/list, and prompts/list bound a hung upstream with
// --upstream-timeout instead of hanging the host request, and
// that the failure is audited as a deny with code UPSTREAM_TIMEOUT.
func TestRemoteUpstream_ListHandlersApplyUpstreamTimeout(t *testing.T) {
	for _, method := range []string{"tools/list", "resources/list", "prompts/list"} {
		t.Run(method, func(t *testing.T) {
			upSrv := httptest.NewServer(http.StripPrefix("/mcp", stuckUpstream()))
			t.Cleanup(upSrv.Close)

			sink, logPath := newTempAuditSink(t)
			// Audit (observe) mode: an upstream timeout is still an enforced
			// outcome (the host gets the error), so the record must NOT be
			// marked audit_only even here.
			_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{
				PDP:            pdp.AlwaysAllowPDP{},
				UpstreamTimeMs: 100,
				Sink:           sink,
				Audit:          true,
			})

			sid := initSession(t, proxySrv)

			start := time.Now()
			resp := postMCP(t, proxySrv, mcp.RPCMsg{
				JSONRPC: "2.0",
				ID:      mcp.RawJSON(`2`),
				Method:  method,
			}, sid)
			elapsed := time.Since(start)

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: unexpected status %d", method, resp.StatusCode)
			}
			msg := decodeRPC(t, resp)
			if msg.Error == nil {
				t.Fatalf("%s: expected upstream-timeout error, got result %s", method, string(msg.Result))
			}
			if !strings.Contains(msg.Error.Message, "did not respond within") {
				t.Errorf("%s: error message %q does not contain timeout message", method, msg.Error.Message)
			}
			if elapsed > 2*time.Second {
				t.Errorf("%s: request took %v; upstream timeout was not applied", method, elapsed)
			}

			// The timeout must leave a forensic trace: a deny record with the
			// structured UPSTREAM_TIMEOUT code, never marked audit_only (the
			// error was enforced — the host received it).
			_ = sink.Close() // flush the drainer; idempotent with t.Cleanup
			rec := findAuditRecordByMethod(readAuditRecords(t, logPath), method, "deny")
			if rec == nil {
				t.Fatalf("%s: no deny audit record written for the timed-out list call", method)
			}
			if code, _ := rec["denial_code"].(string); code != "UPSTREAM_TIMEOUT" {
				t.Errorf("%s: denial_code = %q, want UPSTREAM_TIMEOUT", method, code)
			}
			if ao, _ := rec["audit_only"].(bool); ao {
				t.Errorf("%s: timeout record marked audit_only; infrastructure failures are enforced outcomes", method)
			}
		})
	}
}

// TestRemoteUpstream_NotificationForwardingAppliesUpstreamTimeout verifies
// that forwarding a host notification to a hung remote upstream is bounded by
// --upstream-timeout: the proxy must return 202 promptly instead of pinning
// the handler goroutine until the host disconnects.
func TestRemoteUpstream_NotificationForwardingAppliesUpstreamTimeout(t *testing.T) {
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", stuckUpstream()))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{
		PDP:            pdp.AlwaysAllowPDP{},
		UpstreamTimeMs: 100,
	})

	sid := initSession(t, proxySrv)

	start := time.Now()
	resp := postMCP(t, proxySrv, mcp.RPCMsg{
		JSONRPC: "2.0",
		Method:  "notifications/progress",
		Params:  json.RawMessage(`{"progressToken":"t1","progress":1}`),
	}, sid)
	elapsed := time.Since(start)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("notification: unexpected status %d", resp.StatusCode)
	}
	if elapsed > 2*time.Second {
		t.Errorf("notification took %v; upstream timeout was not applied to forwardNotification", elapsed)
	}
}

// ── Drift probe decoupled from --upstream-timeout ────────────────

// slowToolsListUpstream returns an MCP HTTP handler that answers initialize
// immediately but delays its tools/list response by `delay`, returning a single
// tool with the given name and description.  It models an upstream whose
// startup catalog assembly is slower than the per-request --upstream-timeout
// but well within the session-start budget.
func slowToolsListUpstream(toolName, toolDesc string, delay time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg mcp.RPCMsg
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		switch msg.Method {
		case "initialize":
			w.Header().Set(SessionHeader, "upstream-sess-slow")
			w.Header().Set("Content-Type", CTJSON)
			resp, _ := mcp.SuccessResponse(msg.ID, mcp.InitResult{
				ProtocolVersion: capability.Revision20251125.String(),
				Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
				ServerInfo:      map[string]interface{}{"name": "slow-upstream", "version": "0.0.1"},
			})
			_ = json.NewEncoder(w).Encode(resp)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			select {
			case <-r.Context().Done():
				return
			case <-time.After(delay):
			}
			result := map[string]interface{}{
				"tools": []map[string]interface{}{
					{"name": toolName, "description": toolDesc, "inputSchema": map[string]interface{}{}},
				},
			}
			resp, _ := mcp.SuccessResponse(msg.ID, result)
			w.Header().Set("Content-Type", CTJSON)
			_ = json.NewEncoder(w).Encode(resp)
		default:
			resp, _ := mcp.SuccessResponse(msg.ID, map[string]interface{}{})
			w.Header().Set("Content-Type", CTJSON)
			_ = json.NewEncoder(w).Encode(resp)
		}
	})
}

// TestRemoteUpstream_DriftProbeNotBoundedByUpstreamTimeout is a regression test
// for the session-start coupling: a descriptionHash-pinned manifest makes a
// drift-fetch failure fatal, so a tight --upstream-timeout must NOT abort
// session establishment when the upstream answers tools/list within the
// session-start budget (just not within --upstream-timeout).
func TestRemoteUpstream_DriftProbeNotBoundedByUpstreamTimeout(t *testing.T) {
	const (
		toolName = "read_file"
		toolDesc = "Reads a file from the filesystem."
		// 300ms tools/list: far above the 100ms --upstream-timeout below, far
		// below the 20s session-start budget.
		listDelay = 300 * time.Millisecond
	)
	hash := capability.ComputeToolHash(toolDesc, nil)

	upSrv := httptest.NewServer(http.StripPrefix("/mcp", slowToolsListUpstream(toolName, toolDesc, listDelay)))
	t.Cleanup(upSrv.Close)

	manifest := &config.LocalManifest{
		Capabilities: []capability.Constraint{
			{Target: "tool:" + toolName, Actions: []string{"call"}, DescriptionHash: hash},
		},
	}

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{
		PDP:            pdp.AlwaysAllowPDP{},
		UpstreamTimeMs: 100, // shorter than listDelay; would kill a per-request call
		DriftCheck:     drift.MakeDriftCheck(manifest, false),
	})

	// Session start runs the drift probe synchronously. With the probe bounded
	// by --upstream-timeout it would time out at 100ms, the descriptionHash pin
	// would make that fatal, and initialize would return 500. Bounded by the
	// session-start budget instead, the 300ms tools/list completes, the hash
	// verifies, and the session is established.
	sid := initSession(t, proxySrv)
	if sid == "" {
		t.Fatal("expected a session ID — drift probe must not be killed by --upstream-timeout")
	}
}

// TestBuildUpstreamClient_ResponseHeaderTimeoutHonorsConfig verifies the
// transport-level ResponseHeaderTimeout never undercuts the configured per-call
// upstream timeout (the old hardcoded 30s silently capped a larger configured value
// and ignored the documented --upstream-timeout=0 disable). It is set to
// max(configured, sessionStartTimeout): a configured value above the session-start
// budget survives verbatim; a tight value is clamped up to the session-start budget
// (so the drift probe's header wait is not shortened — the foreground per-call
// context deadline still enforces the tight value); a disabled timeout leaves the
// cap unset.
func TestBuildUpstreamClient_ResponseHeaderTimeoutHonorsConfig(t *testing.T) {
	cases := []struct {
		name      string
		timeoutMs int
		want      time.Duration
	}{
		{"above session-start budget survives", 120000, 120 * time.Second},
		{"tight value clamps up to session-start budget", 5000, sessionStartTimeout},
		{"disabled", 0, 0},
		{"negative treated as disabled", -1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := BuildUpstreamClient(false, tc.timeoutMs)
			tr, ok := c.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("client transport is %T, want *http.Transport", c.Transport)
			}
			if tr.ResponseHeaderTimeout != tc.want {
				t.Errorf("ResponseHeaderTimeout = %v, want %v", tr.ResponseHeaderTimeout, tc.want)
			}
		})
	}
}

// TestCallRemoteUpstream_SessionTeardownCancelsInFlight verifies the session-scoped
// context binds a remote call's lifetime to session teardown: with --upstream-timeout=0
// (no deadline), a call blocked on a silent upstream must unblock the instant the session
// is closed, rather than hang forever holding the handler goroutine and the inFlight
// counter. This is the teardown dimension the per-call context.AfterFunc supplies off
// s.sessCtx (canceled in close()).
func TestCallRemoteUpstream_SessionTeardownCancelsInFlight(t *testing.T) {
	t.Parallel()

	// A hanging upstream: it accepts the request and blocks until the request context is
	// canceled (the behavior under test) OR the test releases it during cleanup. The
	// release channel guarantees the handler exits so Server.Close never blocks on wg.Wait
	// (which would mask the real pass/fail as a timeout); it runs before Close (defers are
	// LIFO). The assertion on callReturned below is the actual proof of teardown cancellation.
	reached := make(chan struct{}, 1)
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case reached <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer upstream.Close()
	defer close(release)

	// A real proxy so withUpstreamTimeout(0) yields a live context (not the nil-proxy
	// no-op), matching production wiring; --upstream-timeout=0 so only teardown can cancel.
	sess := newTestSession(&httpSession{
		id:           "teardown-test",
		proxy:        &HTTPProxy{upstreamTimeMs: 0},
		route:        &UpstreamRoute{upstreamURL: upstream.URL},
		done:         make(chan struct{}),
		upHTTPClient: BuildUpstreamClient(false, 0), // --upstream-timeout=0: no deadline
	})

	callReturned := make(chan error, 1)
	go func() {
		_, err := sess.callRemoteUpstream(context.Background(),
			mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/list"})
		callReturned <- err
	}()

	// Wait until the request has actually reached the (hanging) upstream, so the AfterFunc
	// teardown hook is registered before we tear down.
	select {
	case <-reached:
	case <-time.After(2 * time.Second):
		t.Fatal("request never reached the upstream")
	}
	select {
	case <-callReturned:
		t.Fatal("callRemoteUpstream returned before session teardown; upstream should be hanging")
	case <-time.After(100 * time.Millisecond):
	}

	// Tear the session down — sessCancel() must cancel the in-flight call promptly.
	sess.close(0)
	select {
	case err := <-callReturned:
		if err == nil {
			t.Fatal("expected an error from the canceled in-flight call, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session teardown did not cancel the in-flight remote call")
	}
}

// TestCallRemoteUpstream_RequestContextCancelUnblocks pins that cancelling the per-call
// request context unblocks a remote call even though the session's live teardown dimension
// (the sessCtx-derived AfterFunc) is also registered: the two bounds are independent, and a
// client disconnect must end the call without waiting on session teardown.
func TestCallRemoteUpstream_RequestContextCancelUnblocks(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer upstream.Close()

	sess := newTestSession(&httpSession{
		id:           "req-cancel",
		route:        &UpstreamRoute{upstreamURL: upstream.URL},
		done:         make(chan struct{}),
		upHTTPClient: BuildUpstreamClient(false, 0),
	})

	ctx, cancel := context.WithCancel(context.Background())
	callReturned := make(chan error, 1)
	go func() {
		_, err := sess.callRemoteUpstream(ctx,
			mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/list"})
		callReturned <- err
	}()
	cancel() // client disconnect cancels the request-scoped parent
	select {
	case err := <-callReturned:
		if err == nil {
			t.Fatal("expected an error from the canceled request, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request cancellation did not unblock the call")
	}
}
