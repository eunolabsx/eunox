// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Tests for the stdio introspector (runStdioHandshake / fetchLiveToolsStdio).
// runStdioHandshake takes a msgWriter/msgReader pair, so we drive it with an
// io.Pipe and an in-memory server goroutine — no subprocess required.

package main

import (
	"context"
	"encoding/json"
	"github.com/eunolabs/eunox/pkg/capability"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/transport"
)

// TestFetchLiveTools_HappyPath verifies the full handshake sequence and that
// the returned tools match the upstream's tools/list response.
func TestFetchLiveTools_HappyPath(t *testing.T) {
	tools := []mcp.ToolEntry{
		{
			Name: "read_file",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{"type": "string"},
				},
				"required": []interface{}{"path"},
			},
		},
		{Name: "write_file"},
	}
	fake := newFakeUpstreamWithTools(tools)
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	info, err := fetchLiveTools(context.Background(), srv.URL, "", false, "")
	if err != nil {
		t.Fatalf("fetchLiveTools: %v", err)
	}
	got := info.Tools
	if len(got) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(got))
	}
	if got[0].Name != "read_file" {
		t.Errorf("got[0].Name: want read_file, got %q", got[0].Name)
	}
	if got[1].Name != "write_file" {
		t.Errorf("got[1].Name: want write_file, got %q", got[1].Name)
	}
	if got[0].InputSchema == nil {
		t.Error("got[0].InputSchema: want non-nil")
	}
	if got[1].InputSchema != nil {
		t.Error("got[1].InputSchema: want nil for tool without schema")
	}
	// Server version should be captured from initialize serverInfo.
	if info.ServerVersion != "0.0.1" {
		t.Errorf("ServerVersion: want 0.0.1, got %q", info.ServerVersion)
	}

	// Verify the handshake sequence: initialize → notifications/initialized → tools/list.
	reqs := fake.Received()
	counts := make(map[string]int)
	for _, r := range reqs {
		counts[r.Body.Method]++
	}
	if counts["initialize"] != 1 {
		t.Errorf("initialize count: want 1, got %d", counts["initialize"])
	}
	if counts["notifications/initialized"] != 1 {
		t.Errorf("notifications/initialized count: want 1, got %d", counts["notifications/initialized"])
	}
	if counts["tools/list"] != 1 {
		t.Errorf("tools/list count: want 1, got %d", counts["tools/list"])
	}
}

// TestFetchLiveTools_EmptyToolList verifies that a tools/list with no tools
// returns an empty slice without error.
func TestFetchLiveTools_EmptyToolList(t *testing.T) {
	fake := newFakeUpstreamWithTools(nil)
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	info, err := fetchLiveTools(context.Background(), srv.URL, "", false, "")
	if err != nil {
		t.Fatalf("fetchLiveTools: %v", err)
	}
	if len(info.Tools) != 0 {
		t.Errorf("expected 0 tools, got %d", len(info.Tools))
	}
}

// TestFetchLiveTools_ConnectionRefused verifies that a refused connection
// produces an error.
func TestFetchLiveTools_ConnectionRefused(t *testing.T) {
	_, err := fetchLiveTools(context.Background(), "http://127.0.0.1:1", "", false, "")
	if err == nil {
		t.Error("expected error for refused connection, got nil")
	}
}

// TestFetchLiveTools_InitializeRPCError verifies that a JSON-RPC error in the
// initialize response is surfaced as a Go error.
func TestFetchLiveTools_InitializeRPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg mcp.RPCMsg
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp := mcp.RPCMsg{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Error:   &mcp.RPCError{Code: -32000, Message: "server initialize rejected"},
		}
		w.Header().Set("Content-Type", transport.CTJSON)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)

	_, err := fetchLiveTools(context.Background(), srv.URL, "", false, "")
	if err == nil {
		t.Fatal("expected error for RPC error response, got nil")
	}
	if !strings.Contains(err.Error(), "initialize") {
		t.Errorf("error should mention 'initialize', got %q", err.Error())
	}
}

// TestFetchLiveTools_UpstreamHTTP500 verifies that an HTTP 500 from the
// upstream is surfaced as an error.
func TestFetchLiveTools_UpstreamHTTP500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	_, err := fetchLiveTools(context.Background(), srv.URL, "", false, "")
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

// TestFetchLiveTools_AuthHeaderForwarded verifies that --upstream-auth-header
// is sent on every upstream request.
func TestFetchLiveTools_AuthHeaderForwarded(t *testing.T) {
	var mu sync.Mutex
	captured := make(map[string]string) // method → Authorization value

	fake := newFakeUpstreamWithTools([]mcp.ToolEntry{{Name: "tool_a"}})
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg mcp.RPCMsg
		_ = json.NewDecoder(r.Body).Decode(&msg)
		mu.Lock()
		captured[msg.Method] = r.Header.Get("Authorization")
		mu.Unlock()
		// Replay the body for the real handler — body already consumed, so
		// re-encode and serve.
		fake.serveMsg(w, r, msg)
	})
	srv := httptest.NewServer(http.StripPrefix("/mcp", wrapped))
	t.Cleanup(srv.Close)

	const wantAuth = "Bearer live-test-token"
	_, err := fetchLiveTools(context.Background(), srv.URL, "Authorization: "+wantAuth, false, "")
	if err != nil {
		t.Fatalf("fetchLiveTools: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for method, got := range captured {
		if got != wantAuth {
			t.Errorf("method %q: want Authorization=%q, got %q", method, wantAuth, got)
		}
	}
}

// TestFetchLiveTools_TLSSkipVerify verifies TLS behavior in both modes.
func TestFetchLiveTools_TLSSkipVerify(t *testing.T) {
	fake := newFakeUpstreamWithTools([]mcp.ToolEntry{{Name: "tool_a"}})
	tlsSrv := httptest.NewTLSServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(tlsSrv.Close)

	// Without skip-verify: self-signed cert should cause an error.
	_, err := fetchLiveTools(context.Background(), tlsSrv.URL, "", false, "")
	if err == nil {
		t.Error("expected TLS error without skip-verify, got nil")
	}

	// With skip-verify: should succeed despite the self-signed certificate.
	info, err := fetchLiveTools(context.Background(), tlsSrv.URL, "", true, "")
	if err != nil {
		t.Fatalf("fetchLiveTools with skip-verify: %v", err)
	}
	if len(info.Tools) != 1 || info.Tools[0].Name != "tool_a" {
		t.Errorf("skip-verify: expected [{tool_a}], got %v", info.Tools)
	}
}

// TestFetchLiveTools_BaseURLTrailingSlash verifies that a trailing slash in the
// base URL does not result in a double-slash in the MCP endpoint path.
func TestFetchLiveTools_BaseURLTrailingSlash(t *testing.T) {
	fake := newFakeUpstreamWithTools([]mcp.ToolEntry{{Name: "tool_a"}})
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	// Pass URL with trailing slash.
	info, err := fetchLiveTools(context.Background(), srv.URL+"/", "", false, "")
	if err != nil {
		t.Fatalf("fetchLiveTools with trailing slash: %v", err)
	}
	if len(info.Tools) != 1 {
		t.Errorf("expected 1 tool, got %d", len(info.Tools))
	}
}

// TestFetchLiveTools_ContextCanceled verifies that a pre-canceled context
// causes fetchLiveTools to return an error immediately.
func TestFetchLiveTools_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call

	_, err := fetchLiveTools(ctx, "http://127.0.0.1:19999", "", false, "")
	if err == nil {
		t.Error("expected error for canceled context, got nil")
	}
}

// TestFetchLiveTools_SendsTerminatingDelete verifies the one-shot HTTP probe
// terminates the upstream session it established: after the initialize handshake
// captures a session id, fetchLiveTools must send an MCP DELETE on the way out
// so the upstream frees its server-side session state instead of leaking it.
// The stdio peer already tears down its subprocess; this pins the HTTP
// peer's equivalent teardown.
func TestFetchLiveTools_SendsTerminatingDelete(t *testing.T) {
	fake := newFakeUpstreamWithTools([]mcp.ToolEntry{{Name: "tool_a"}})
	var mu sync.Mutex
	var deletes []string // session id seen on each DELETE
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			mu.Lock()
			deletes = append(deletes, r.Header.Get(transport.SessionHeader))
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		fake.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(http.StripPrefix("/mcp", wrapped))
	t.Cleanup(srv.Close)

	if _, err := fetchLiveTools(context.Background(), srv.URL, "", false, ""); err != nil {
		t.Fatalf("fetchLiveTools: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(deletes) != 1 {
		t.Fatalf("expected exactly one terminating DELETE, got %d", len(deletes))
	}
	if deletes[0] != "upstream-sess-1" {
		t.Errorf("DELETE should carry the upstream session id; want upstream-sess-1, got %q", deletes[0])
	}
}

// TestFetchLiveTools_DeletesSessionOnFailedInitialize verifies the probe terminates
// a server-side session even when initialize fails at the transport layer. A lenient
// upstream may ALLOCATE a session (stamp Mcp-Session-Id) on the very response that
// carries a non-2xx status; fetchLiveTools must capture that id and issue the DELETE
// before returning the initialize error, so the session does not leak. Mirrors the
// "capture before the gate" guard in internal/transport/http_remote.go.
func TestFetchLiveTools_DeletesSessionOnFailedInitialize(t *testing.T) {
	const allocatedSess = "leaked-sess-9"
	var mu sync.Mutex
	var deletes []string
	srv := httptest.NewServer(http.StripPrefix("/mcp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			mu.Lock()
			deletes = append(deletes, r.Header.Get(transport.SessionHeader))
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		// initialize POST: allocate a session, then fail at the HTTP layer.
		w.Header().Set(transport.SessionHeader, allocatedSess)
		http.Error(w, "initialize rejected", http.StatusInternalServerError)
	})))
	t.Cleanup(srv.Close)

	_, err := fetchLiveTools(context.Background(), srv.URL, "", false, "")
	if err == nil {
		t.Fatal("expected an initialize error from the non-2xx response, got nil")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(deletes) != 1 {
		t.Fatalf("expected exactly one terminating DELETE for the allocated session, got %d", len(deletes))
	}
	if deletes[0] != allocatedSess {
		t.Errorf("DELETE should carry the allocated session id; want %q, got %q", allocatedSess, deletes[0])
	}
}

// TestFetchRouteLive_AppliesPerRouteTimeout verifies that fetchRouteLive imposes
// its OWN liveUpstreamTimeout per introspection rather than relying on a single
// timeout shared across every route by the caller. Given a base context
// with no deadline, a hanging upstream must still be bounded by a deadline that
// fetchRouteLive itself installed. We assert via the dispatched context: a
// per-route deadline must be present and not already (near-)exhausted, which is
// the guarantee a shared budget across slow routes would violate.
func TestFetchRouteLive_AppliesPerRouteTimeout(t *testing.T) {
	// fetchRouteLive must install its OWN per-route deadline rather than
	// relying on a deadline-bearing caller context (validateConfigRoutes now passes
	// a deadline-less base context so a slow early route cannot starve later ones).
	// With a deadline-less caller context, a hanging upstream must still be bounded
	// by liveUpstreamTimeout — proving the timeout originates inside fetchRouteLive.
	// HTTP does not propagate a client context deadline to the server, so this is
	// verified by observing that the call returns (bounded) instead of hanging.
	orig := liveUpstreamTimeout
	liveUpstreamTimeout = 300 * time.Millisecond
	t.Cleanup(func() { liveUpstreamTimeout = orig })

	fake := newFakeUpstreamWithTools([]mcp.ToolEntry{{Name: "tool_a"}})
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second) // far exceeds the per-route budget
		fake.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(http.StripPrefix("/mcp", slow))
	t.Cleanup(srv.Close)

	u := &config.UpstreamConfig{
		Name:        "r1",
		Transport:   config.HostTransportHTTP,
		UpstreamURL: srv.URL,
	}

	start := time.Now()
	// Deadline-less base context: the only bound can come from fetchRouteLive.
	_, err := fetchRouteLive(context.Background(), u)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a deadline error from the per-route timeout, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("fetchRouteLive did not bound the call with its own per-route deadline: took %v with a deadline-less caller context", elapsed)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// serveMsg allows fakeUpstreamWithTools to be used from a wrapper handler that
// has already decoded the JSON body.  It re-dispatches based on Method.
func (f *fakeUpstreamWithTools) serveMsg(w http.ResponseWriter, _ *http.Request, msg mcp.RPCMsg) {
	f.mu.Lock()
	f.received = append(f.received, fakeRequest{
		Method: msg.Method,
		Body:   msg,
	})
	f.mu.Unlock()

	switch msg.Method {
	case "initialize":
		w.Header().Set(transport.SessionHeader, "upstream-sess-1")
		w.Header().Set("Content-Type", transport.CTJSON)
		result := mcp.InitResult{
			ProtocolVersion: capability.Revision20251125.String(),
			Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
			ServerInfo:      map[string]interface{}{"name": "fake", "version": "0.0.1"},
		}
		resp, _ := mcp.SuccessResponse(msg.ID, result)
		_ = json.NewEncoder(w).Encode(resp)
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		result := mcp.ToolsListResult{Tools: f.tools}
		resp, _ := mcp.SuccessResponse(msg.ID, result)
		w.Header().Set("Content-Type", transport.CTJSON)
		_ = json.NewEncoder(w).Encode(resp)
	default:
		resp, _ := mcp.SuccessResponse(msg.ID, map[string]interface{}{})
		w.Header().Set("Content-Type", transport.CTJSON)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// stdioMockServer wires an in-memory MCP server onto a pair of io.Pipes and
// returns the client-side reader/writer plus a done channel that closes once
// the server goroutine exits. handler is invoked with a serverR/serverW pair
// and should send/receive responses; closing both pipe writers signals EOF.
type stdioMockServer struct {
	clientW *mcp.MsgWriter
	clientR *mcp.MsgReader
	done    chan struct{}
	// closers writeable so tests can shut both directions down at cleanup.
	cToS_w *io.PipeWriter
	sToC_w *io.PipeWriter
}

func newStdioMockServer(handler func(r *mcp.MsgReader, w *mcp.MsgWriter)) *stdioMockServer {
	cToS_r, cToS_w := io.Pipe() // client → server
	sToC_r, sToC_w := io.Pipe() // server → client

	m := &stdioMockServer{
		clientW: mcp.NewMsgWriter(cToS_w),
		clientR: mcp.NewMsgReader(sToC_r),
		done:    make(chan struct{}),
		cToS_w:  cToS_w,
		sToC_w:  sToC_w,
	}
	go func() {
		defer close(m.done)
		handler(mcp.NewMsgReader(cToS_r), mcp.NewMsgWriter(sToC_w))
	}()
	return m
}

func (m *stdioMockServer) close() {
	_ = m.cToS_w.Close()
	_ = m.sToC_w.Close()
	<-m.done
}

// happyPathHandler implements the minimum MCP server contract: respond to
// initialize, accept notifications/initialized, then respond to tools/list.
// Between the initialize response and the tools/list response it emits a
// spurious notification — regression coverage that readResponseWithID skips
// notifications instead of treating them as out-of-order responses.
func happyPathHandler(t *testing.T, serverVersion string, tools []map[string]interface{}) func(*mcp.MsgReader, *mcp.MsgWriter) {
	t.Helper()
	return func(r *mcp.MsgReader, w *mcp.MsgWriter) {
		// initialize
		msg, err := r.Read()
		if err != nil {
			return
		}
		if msg.Method != "initialize" {
			t.Errorf("first message: want initialize, got %q", msg.Method)
			return
		}
		initResult, _ := json.Marshal(mcp.InitResult{
			ProtocolVersion: capability.Revision20251125.String(),
			Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
			ServerInfo:      map[string]interface{}{"name": "mock", "version": serverVersion},
		})
		_ = w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: initResult})

		// notifications/initialized
		notifMsg, err := r.Read()
		if err != nil {
			return
		}
		if !notifMsg.IsNotification() || notifMsg.Method != "notifications/initialized" {
			t.Errorf("second message: want notifications/initialized notification, got method=%q id=%v", notifMsg.Method, notifMsg.ID)
		}

		// tools/list — read first, then emit a spurious notification *before*
		// the response. Confirms readResponseWithID skips notifications instead
		// of treating them as out-of-order responses. (The notification must be
		// sent after reading the request, not before, because io.Pipe is
		// unbuffered — both sides would block on Write otherwise.)
		listMsg, err := r.Read()
		if err != nil {
			return
		}
		if listMsg.Method != "tools/list" {
			t.Errorf("third message: want tools/list, got %q", listMsg.Method)
			return
		}
		announce, _ := mcp.NotificationMsg("server/announcement", nil)
		_ = w.Write(announce)
		toolsResult, _ := json.Marshal(map[string]interface{}{"tools": tools})
		_ = w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: listMsg.ID, Result: toolsResult})
	}
}

// TestRunStdioHandshake_RejectsServerInitiatedRequest verifies the probe answers an
// unsolicited server-initiated request with a JSON-RPC error and still completes,
// rather than ignoring the request (which would wedge the probe until the deadline if
// the upstream blocked awaiting a reply).
func TestRunStdioHandshake_RejectsServerInitiatedRequest(t *testing.T) {
	srv := newStdioMockServer(func(r *mcp.MsgReader, w *mcp.MsgWriter) {
		// initialize
		msg, err := r.Read()
		if err != nil {
			return
		}
		initResult, _ := json.Marshal(mcp.InitResult{
			ProtocolVersion: capability.Revision20251125.String(),
			Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
			ServerInfo:      map[string]interface{}{"name": "mock", "version": "1"},
		})
		_ = w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: initResult})

		// notifications/initialized
		if _, err := r.Read(); err != nil {
			return
		}

		// tools/list — read the request, then emit a server-initiated request BEFORE
		// answering. A well-behaved upstream blocks until that request is answered.
		listMsg, err := r.Read()
		if err != nil {
			return
		}
		_ = w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`99`), Method: "roots/list"})
		// The probe must reply an error to id 99; read it (io.Pipe is synchronous, so
		// the probe's reply unblocks here) and check it before answering tools/list.
		reply, err := r.Read()
		if err != nil {
			t.Errorf("probe did not reply to the server-initiated request: %v", err)
			return
		}
		if reply.Error == nil || mcp.MsgKey(reply.ID) != "n:99" {
			t.Errorf("probe reply = %+v, want a JSON-RPC error for id 99", reply)
		}
		toolsResult, _ := json.Marshal(map[string]interface{}{"tools": []map[string]interface{}{{"name": "read_file"}}})
		_ = w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: listMsg.ID, Result: toolsResult})
	})

	info, err := runStdioHandshake(context.Background(), srv.clientW, srv.clientR, "")
	srv.close()
	if err != nil {
		t.Fatalf("handshake must complete despite the server-initiated request: %v", err)
	}
	if len(info.Tools) != 1 || info.Tools[0].Name != "read_file" {
		t.Errorf("tools = %+v, want [read_file]", info.Tools)
	}
}

func TestRunStdioHandshake_HappyPath(t *testing.T) {
	srv := newStdioMockServer(happyPathHandler(t, "1.2.3", []map[string]interface{}{
		{"name": "read_file", "inputSchema": map[string]interface{}{"type": "object"}},
		{"name": "write_file"},
	}))

	info, err := runStdioHandshake(context.Background(), srv.clientW, srv.clientR, "")
	srv.close()
	if err != nil {
		t.Fatalf("runStdioHandshake: %v", err)
	}
	if info.ServerVersion != "1.2.3" {
		t.Errorf("server version = %q, want 1.2.3", info.ServerVersion)
	}
	if len(info.Tools) != 2 {
		t.Fatalf("got %d tool(s), want 2", len(info.Tools))
	}
	if info.Tools[0].Name != "read_file" || info.Tools[1].Name != "write_file" {
		t.Errorf("tool names = %q,%q; want read_file,write_file", info.Tools[0].Name, info.Tools[1].Name)
	}
}

func TestRunStdioHandshake_InitializeErrorPropagates(t *testing.T) {
	srv := newStdioMockServer(func(r *mcp.MsgReader, w *mcp.MsgWriter) {
		msg, err := r.Read()
		if err != nil {
			return
		}
		_ = w.Write(mcp.RPCMsg{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Error:   &mcp.RPCError{Code: -32601, Message: "method not found"},
		})
	})

	_, err := runStdioHandshake(context.Background(), srv.clientW, srv.clientR, "")
	srv.close()
	if err == nil {
		t.Fatal("want error from initialize failure, got nil")
	}
	if !strings.Contains(err.Error(), "initialize") || !strings.Contains(err.Error(), "method not found") {
		t.Errorf("error should surface initialize failure; got %v", err)
	}
}

func TestRunStdioHandshake_ToolsListErrorPropagates(t *testing.T) {
	srv := newStdioMockServer(func(r *mcp.MsgReader, w *mcp.MsgWriter) {
		// initialize ok
		msg, _ := r.Read()
		initResult, _ := json.Marshal(mcp.InitResult{
			ProtocolVersion: capability.Revision20251125.String(),
			Capabilities:    map[string]interface{}{},
			ServerInfo:      map[string]interface{}{"version": "0.0.1"},
		})
		_ = w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: initResult})
		// drain notifications/initialized
		_, _ = r.Read()
		// tools/list → error
		listMsg, _ := r.Read()
		_ = w.Write(mcp.RPCMsg{
			JSONRPC: "2.0",
			ID:      listMsg.ID,
			Error:   &mcp.RPCError{Code: -32000, Message: "tools unavailable"},
		})
	})

	_, err := runStdioHandshake(context.Background(), srv.clientW, srv.clientR, "")
	srv.close()
	if err == nil {
		t.Fatal("want error from tools/list failure, got nil")
	}
	if !strings.Contains(err.Error(), "tools/list") || !strings.Contains(err.Error(), "tools unavailable") {
		t.Errorf("error should surface tools/list failure; got %v", err)
	}
}

// TestRunStdioHandshake_UnexpectedResponseID covers the protocol-error path in
// readResponseWithID: a response carrying an id the client never sent.
func TestRunStdioHandshake_UnexpectedResponseID(t *testing.T) {
	srv := newStdioMockServer(func(r *mcp.MsgReader, w *mcp.MsgWriter) {
		_, _ = r.Read()
		_ = w.Write(mcp.RPCMsg{
			JSONRPC: "2.0",
			ID:      mcp.RawJSON(`"_someone_elses_id"`),
			Result:  json.RawMessage(`{}`),
		})
	})

	_, err := runStdioHandshake(context.Background(), srv.clientW, srv.clientR, "")
	srv.close()
	if err == nil {
		t.Fatal("want protocol error for mismatched response id, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected response id") {
		t.Errorf("error should mention unexpected response id; got %v", err)
	}
}

// TestRunStdioHandshake_InvalidInitializeResultFailsClosed asserts a structurally
// invalid initialize result (JSON `null`, or one missing a mandatory MCP field) is
// rejected rather than silently accepted with an empty server version.
func TestRunStdioHandshake_InvalidInitializeResultFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		result json.RawMessage
	}{
		{name: "null result", result: json.RawMessage(`null`)},
		{name: "empty object", result: json.RawMessage(`{}`)},
		{
			name:   "missing protocolVersion",
			result: json.RawMessage(`{"capabilities":{},"serverInfo":{"version":"1.0"}}`),
		},
		{
			name:   "missing capabilities",
			result: json.RawMessage(`{"protocolVersion":"2025-06-18","serverInfo":{"version":"1.0"}}`),
		},
		{
			name:   "missing serverInfo",
			result: json.RawMessage(`{"protocolVersion":"2025-06-18","capabilities":{}}`),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newStdioMockServer(func(r *mcp.MsgReader, w *mcp.MsgWriter) {
				msg, err := r.Read()
				if err != nil {
					return
				}
				_ = w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: tc.result})
				// Drain any further client writes so the server goroutine does not
				// block on an unread pipe if the handshake (incorrectly) continued.
				for {
					if _, err := r.Read(); err != nil {
						return
					}
				}
			})

			_, err := runStdioHandshake(context.Background(), srv.clientW, srv.clientR, "")
			srv.close()
			if err == nil {
				t.Fatalf("want fail-closed error for %s, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), "initialize") {
				t.Errorf("error should surface the initialize failure; got %v", err)
			}
		})
	}
}
