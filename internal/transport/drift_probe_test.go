// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

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
	"time"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// fakeUpstreamWithTools extends fakeUpstream to respond to tools/list.
type fakeUpstreamWithTools struct {
	*fakeUpstream
	tools []mcp.ToolEntry
}

func newFakeUpstreamWithTools(tools []mcp.ToolEntry) *fakeUpstreamWithTools {
	return &fakeUpstreamWithTools{fakeUpstream: newFakeUpstream(), tools: tools}
}

func (f *fakeUpstreamWithTools) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var msg mcp.RPCMsg
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.received = append(f.received, fakeRequest{
		Method: msg.Method, SessionID: r.Header.Get(SessionHeader), Body: msg,
	})
	f.mu.Unlock()

	switch msg.Method {
	case "initialize":
		w.Header().Set(SessionHeader, "upstream-sess-1")
		w.Header().Set("Content-Type", "application/json")
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
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	default:
		resp, _ := mcp.SuccessResponse(msg.ID, map[string]interface{}{"method": msg.Method})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// TestHTTPDriftCheck_FM1_Background verifies that FM-1 drift is detected and
// logged when a glob-matched tool is returned by tools/list (non-strict mode).
func TestHTTPDriftCheck_FM1_Background(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:delete_*", Actions: []string{"call"}},
	)
	tools := []mcp.ToolEntry{{Name: "delete_all_records"}}

	fake := newFakeUpstreamWithTools(tools)
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	var logBuf bytes.Buffer
	origStderr := overrideStderr(&logBuf)
	defer restoreStderr(origStderr)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{
		DriftCheck: drift.MakeDriftCheck(manifest, false),
	})
	initSession(t, proxySrv)

	waitForLog(t, &logBuf, "fm1")
}

// TestHTTPDriftCheck_FM2_Background verifies that FM-2 drift is detected when
// a manifest entry matches no live tool (non-strict mode).
func TestHTTPDriftCheck_FM2_Background(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:legacy_search", Actions: []string{"call"}},
	)

	tools := []mcp.ToolEntry{{Name: "search_v2"}}

	fake := newFakeUpstreamWithTools(tools)
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	var logBuf bytes.Buffer
	origStderr := overrideStderr(&logBuf)
	defer restoreStderr(origStderr)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{
		DriftCheck: drift.MakeDriftCheck(manifest, false),
	})
	initSession(t, proxySrv)

	waitForLog(t, &logBuf, "fm2")
}

// TestHTTPDriftCheck_StrictMode_FM1_Aborts verifies that a new glob-matched
// tool causes session establishment to fail in strict mode.
func TestHTTPDriftCheck_StrictMode_FM1_Aborts(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:delete_*", Actions: []string{"call"}},
	)
	tools := []mcp.ToolEntry{{Name: "delete_all_records"}}

	fake := newFakeUpstreamWithTools(tools)
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{
		DriftCheck: drift.MakeDriftCheck(manifest, true),
	})

	initMsg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`1`),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{}}`),
	}
	resp := postMCP(t, proxySrv, initMsg, "")
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("strict FM-1: want HTTP 500, got %d", resp.StatusCode)
	}
}

// TestHTTPDriftCheck_StrictMode_FM2_Aborts verifies that a dead manifest entry
// causes session establishment to fail in strict mode.
func TestHTTPDriftCheck_StrictMode_FM2_Aborts(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:legacy_search", Actions: []string{"call"}},
	)
	tools := []mcp.ToolEntry{{Name: "search_v2"}}

	fake := newFakeUpstreamWithTools(tools)
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{
		DriftCheck: drift.MakeDriftCheck(manifest, true),
	})

	initMsg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`1`),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{}}`),
	}
	resp := postMCP(t, proxySrv, initMsg, "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("strict FM-2: want HTTP 500, got %d", resp.StatusCode)
	}
}

// TestHTTPDriftCheck_StrictMode_FM3_DoesNotAbort verifies that FM-3 findings
// are advisory and do not abort the session in strict mode.
func TestHTTPDriftCheck_StrictMode_FM3_DoesNotAbort(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{
			Target:  "tool:read_file",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/reports/*"}},
			},
		},
	)

	tools := []mcp.ToolEntry{{
		Name: "read_file",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"file_path": map[string]interface{}{"type": "string"},
			},
		},
	}}

	fake := newFakeUpstreamWithTools(tools)
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{
		DriftCheck: drift.MakeDriftCheck(manifest, true),
	})

	sid := initSession(t, proxySrv)
	if sid == "" {
		t.Error("FM-3 must not abort session even in strict mode")
	}
}

// TestHTTPDriftCheck_CleanManifest_SessionSucceeds verifies that a clean
// manifest (all tools exactly matched) produces no drift and the session starts.
func TestHTTPDriftCheck_CleanManifest_SessionSucceeds(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		capability.Constraint{Target: "tool:query_db", Actions: []string{"call"}},
	)
	tools := []mcp.ToolEntry{
		{Name: "read_file"},
		{Name: "query_db"},
	}

	fake := newFakeUpstreamWithTools(tools)
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{
		DriftCheck: drift.MakeDriftCheck(manifest, true),
	})
	sid := initSession(t, proxySrv)
	if sid == "" {
		t.Error("clean manifest: expected session to succeed")
	}
}

// TestHTTPDriftCheck_NoManifest_NoCheck verifies that without a manifest the
// drift check is skipped and session creation succeeds.
func TestHTTPDriftCheck_NoManifest_NoCheck(t *testing.T) {

	fake := newFakeUpstream()
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{})
	sid := initSession(t, proxySrv)
	if sid == "" {
		t.Error("no manifest: expected session to succeed without drift check")
	}
}

// manifestWith builds a config.LocalManifest from the given constraints.
func manifestWith(caps ...capability.Constraint) *config.LocalManifest {
	return &config.LocalManifest{
		Name:         "test-policy",
		Version:      "1.0.0",
		Capabilities: caps,
	}
}

// TestFetchHTTPSessionTools_UpstreamError covers the callUpstream error path
// in (*httpSession).fetchUpstreamToolsRaw by using a closed session.
func TestFetchHTTPSessionTools_UpstreamError(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	close(done)
	sess := newClosedTestSession(&httpSession{
		done:     done,
		upWriter: mcp.NewMsgWriter(io.Discard),
	})
	_, err := sess.fetchUpstreamToolsRaw(context.Background())
	if err == nil {
		t.Error("expected error when session upstream is closed")
	}
}

// TestFetchHTTPSessionTools_UpstreamRPCError covers the resp.Error != nil path.
func TestFetchHTTPSessionTools_UpstreamRPCError(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})

	upR, upW := io.Pipe()
	sess := newTestSession(&httpSession{
		done:     done,
		upWriter: mcp.NewMsgWriter(upW),
		upReader: mcp.NewMsgReader(upR),
	})

	errResp := mcp.RPCMsg{
		JSONRPC: "2.0",
		Error:   &mcp.RPCError{Code: -32601, Message: "method not found"},
	}

	go func() {
		defer upR.Close()
		reader := mcp.NewMsgReader(upR)
		req, readErr := reader.Read()
		if readErr != nil {
			return
		}
		key := mcp.MsgKey(req.ID)
		sess.pendingMu.Lock()
		ch, ok := sess.byUpstreamID[key]
		sess.pendingMu.Unlock()
		if ok {
			resp := errResp
			resp.ID = req.ID
			ch <- upstreamResult{msg: resp}
		}
	}()
	defer upW.Close()

	_, err := sess.fetchUpstreamToolsRaw(context.Background())
	if err == nil {
		t.Error("expected error for RPC error response")
	}
}

// TestFetchStdioTools_WriteError covers the upWriter.Write error path in
// (*StdioProxy).fetchUpstreamToolsRaw by using a proxy with a broken upWriter.
func TestFetchStdioTools_WriteError(t *testing.T) {
	t.Parallel()

	proxy := &StdioProxy{
		upWriter: mcp.NewMsgWriter(&brokenWriter{}),
		upReader: mcp.NewMsgReader(&closedReader{}),
	}
	_, err := proxy.fetchUpstreamToolsRaw(context.Background())
	if err == nil {
		t.Error("expected error from broken writer")
	}
}

// brokenWriter is an io.Writer that always returns an error.
type brokenWriter struct{}

func (b *brokenWriter) Write(_ []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

// closedReader returns EOF immediately on Read.
type closedReader struct{}

func (c *closedReader) Read(p []byte) (int, error) {
	return 0, io.EOF
}

// cannedToolsSession returns an httpSession backed by io.Pipe that answers a
// single tools/list request with the supplied tool set, then a cleanup func.
func cannedToolsSession(t *testing.T, serverVersion string, toolNames ...string) (sess *httpSession, cleanup func()) {
	t.Helper()
	upR, upW := io.Pipe()

	sess = newTestSession(&httpSession{
		done:                  make(chan struct{}),
		upWriter:              mcp.NewMsgWriter(upW),
		upstreamServerVersion: serverVersion,
	})

	tools := make([]map[string]interface{}, len(toolNames))
	for i, n := range toolNames {
		tools[i] = map[string]interface{}{"name": n}
	}
	result, _ := json.Marshal(map[string]interface{}{"tools": tools})

	go func() {
		reader := mcp.NewMsgReader(upR)
		for {
			req, err := reader.Read()
			if err != nil {
				return
			}
			key := mcp.MsgKey(req.ID)
			sess.pendingMu.Lock()
			ch, ok := sess.byUpstreamID[key]
			sess.pendingMu.Unlock()
			if ok {
				ch <- upstreamResult{msg: mcp.RPCMsg{JSONRPC: "2.0", ID: req.ID, Result: result}}
			}
		}
	}()
	return sess, func() { _ = upW.Close() }
}

func TestRunHTTPDriftCheck_Clean(t *testing.T) {
	t.Parallel()
	sess, cleanup := cannedToolsSession(t, "1.0.0", "read_file", "write_file")
	defer cleanup()

	manifest := &config.LocalManifest{
		Name:    "m",
		Version: "1.0.0",
		Capabilities: []capability.Constraint{
			{Target: "tool:read_file", Actions: []string{"call"}},
			{Target: "tool:write_file", Actions: []string{"call"}},
		},
	}
	raw, probeErr := sess.fetchUpstreamToolsRaw(context.Background())
	if err := drift.MakeDriftCheck(manifest, true)(raw, sess.upstreamServerVersion, probeErr); err != nil {
		t.Errorf("expected clean drift, got %v", err)
	}
}

// TestRunHTTPDriftCheck_SkippedWhenNoPins exercises the best-effort skip: the
// session is already closed so tools/list fails, but the manifest pins no
// description hashes and strict is off, so the failure is non-fatal. Under
// --strict-drift the same failure is fatal — see
// TestRunHTTPDriftCheck_StrictFatalWhenNoPins.
func TestRunHTTPDriftCheck_SkippedWhenNoPins(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	close(done)
	sess := newClosedTestSession(&httpSession{
		done:     done,
		upWriter: mcp.NewMsgWriter(io.Discard),
	})
	manifest := &config.LocalManifest{
		Name:         "m",
		Version:      "1.0.0",
		Capabilities: []capability.Constraint{{Target: "tool:read_file", Actions: []string{"call"}}},
	}
	raw, probeErr := sess.fetchUpstreamToolsRaw(context.Background())
	if err := drift.MakeDriftCheck(manifest, false)(raw, sess.upstreamServerVersion, probeErr); err != nil {
		t.Errorf("expected skipped (no pins, non-strict), got %v", err)
	}
}

// TestRunHTTPDriftCheck_StrictFatalWhenNoPins asserts that under --strict-drift a
// tools/list probe failure is fatal even with no descriptionHash pins: an upstream
// we cannot inspect must not silently bypass the fatal-on-drift guarantee by
// withholding tools/list.
func TestRunHTTPDriftCheck_StrictFatalWhenNoPins(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	close(done)
	sess := newClosedTestSession(&httpSession{
		done:     done,
		upWriter: mcp.NewMsgWriter(io.Discard),
	})
	manifest := &config.LocalManifest{
		Name:         "m",
		Version:      "1.0.0",
		Capabilities: []capability.Constraint{{Target: "tool:read_*", Actions: []string{"call"}}},
	}
	raw, probeErr := sess.fetchUpstreamToolsRaw(context.Background())
	if err := drift.MakeDriftCheck(manifest, true)(raw, sess.upstreamServerVersion, probeErr); err == nil {
		t.Error("expected fatal drift error under --strict-drift when tools/list unavailable")
	}
}

// TestRunHTTPDriftCheck_FatalWhenPinsAndNoToolsList asserts the fail-closed
// branch: tools/list is unavailable and the manifest pins a description hash.
func TestRunHTTPDriftCheck_FatalWhenPinsAndNoToolsList(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	close(done)
	sess := newClosedTestSession(&httpSession{
		done:     done,
		upWriter: mcp.NewMsgWriter(io.Discard),
	})
	manifest := &config.LocalManifest{
		Name:    "m",
		Version: "1.0.0",
		Capabilities: []capability.Constraint{
			{
				Target:          "tool:read_file",
				Actions:         []string{"call"},
				DescriptionHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}
	raw, probeErr := sess.fetchUpstreamToolsRaw(context.Background())
	if err := drift.MakeDriftCheck(manifest, true)(raw, sess.upstreamServerVersion, probeErr); err == nil {
		t.Error("expected fatal drift error when pins set and tools/list unavailable")
	}
}

// TestFetchStdioTools_ManyNotificationsBeforeResponse verifies that
// (*StdioProxy).fetchUpstreamToolsRaw succeeds even when the upstream sends more
// than 20 notifications before the tools/list response arrives.
//
// We fabricate a pipe pair, pre-write N JSON-RPC notifications followed by the
// tools/list response, and confirm that fetchUpstreamToolsRaw returns the
// correct tool list.
func TestFetchStdioTools_ManyNotificationsBeforeResponse(t *testing.T) {
	t.Parallel()

	const numNotifications = 100 // well above the old maxDiscard=20

	// Build the byte stream: N notifications then the real response.
	var buf bytes.Buffer

	writeLine := func(v interface{}) {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	for i := 0; i < numNotifications; i++ {
		writeLine(map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "notifications/progress",
			"params":  map[string]interface{}{"step": i},
		})
	}

	toolsResult, _ := json.Marshal(map[string]interface{}{
		"tools": []map[string]interface{}{
			{"name": "read_file", "description": "Reads a file"},
			{"name": "write_file", "description": "Writes a file"},
		},
	})
	writeLine(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "_drift",
		"result":  json.RawMessage(toolsResult),
	})

	proxy := &StdioProxy{
		upWriter: mcp.NewMsgWriter(io.Discard),
		upReader: mcp.NewMsgReader(&buf),
	}

	raw, err := proxy.fetchUpstreamToolsRaw(context.Background())
	if err != nil {
		t.Fatalf("regression: fetchUpstreamToolsRaw returned error after %d notifications: %v",
			numNotifications, err)
	}
	tools, err := drift.ParseToolsListResult(raw)
	if err != nil {
		t.Fatalf("regression: parseToolsListResult failed after %d notifications: %v",
			numNotifications, err)
	}
	if len(tools) != 2 {
		t.Errorf("regression: expected 2 tools, got %d", len(tools))
	}
	names := make([]string, len(tools))
	for i, tool := range tools {
		names[i] = tool.Name
	}
	if names[0] != "read_file" || names[1] != "write_file" {
		t.Errorf("regression: unexpected tool names: %v", names)
	}
}

// TestRunInitHandshake_RepliesToServerInitiatedRequest is the regression for the
// HTTP session's initialize handshake silently dropping a server-initiated request
// that arrives before the initialize response. runInitHandshake runs before
// readUpstream starts, so an unanswered request wedges the upstream; it must reply
// a JSON-RPC error (mirroring the stdio handshake) and still complete the handshake.
func TestRunInitHandshake_RepliesToServerInitiatedRequest(t *testing.T) {
	t.Parallel()

	var in bytes.Buffer
	writeLine := func(v interface{}) {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		in.Write(data)
		in.WriteByte('\n')
	}

	// A server-initiated request arrives before the initialize response (id "1",
	// the first idCounter value runInitHandshake builds).
	writeLine(map[string]interface{}{"jsonrpc": "2.0", "id": "srv-9", "method": "sampling/createMessage"})
	initResult, _ := json.Marshal(map[string]interface{}{
		"protocolVersion": capability.Revision20251125.String(),
		"capabilities":    map[string]interface{}{},
		"serverInfo":      map[string]interface{}{"name": "up", "version": "1.0"},
	})
	writeLine(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": json.RawMessage(initResult)})

	var out bytes.Buffer
	sess := newTestSession(&httpSession{
		upWriter: mcp.NewMsgWriter(&out),
		upReader: mcp.NewMsgReader(&in),
	})
	if err := sess.runInitHandshake(); err != nil {
		t.Fatalf("runInitHandshake: %v", err)
	}
	if got := out.String(); !strings.Contains(got, `"srv-9"`) ||
		!strings.Contains(got, "during session startup; not yet routable") {
		t.Errorf("handshake must reply a JSON-RPC error to the stray server-initiated request so the upstream unblocks; upWriter output was:\n%s", got)
	}
}

// TestFetchStdioTools_RepliesToServerInitiatedRequest is the regression for the
// drift probe silently dropping a server-initiated request: a JSON-RPC request
// blocks its initiator until answered, and the probe runs inline before
// readUpstream starts, so an unanswered request wedges the upstream. The probe
// must reply a JSON-RPC error (mirroring the init handshake) and still return the
// tool list.
func TestFetchStdioTools_RepliesToServerInitiatedRequest(t *testing.T) {
	t.Parallel()

	var in bytes.Buffer
	writeLine := func(v interface{}) {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		in.Write(data)
		in.WriteByte('\n')
	}

	// A server-initiated request (roots/list) arrives before the _drift response.
	writeLine(map[string]interface{}{"jsonrpc": "2.0", "id": "srv-1", "method": "roots/list"})
	toolsResult, _ := json.Marshal(map[string]interface{}{
		"tools": []map[string]interface{}{{"name": "read_file", "description": "Reads a file"}},
	})
	writeLine(map[string]interface{}{"jsonrpc": "2.0", "id": "_drift", "result": json.RawMessage(toolsResult)})

	var out bytes.Buffer
	proxy := &StdioProxy{
		upWriter: mcp.NewMsgWriter(&out),
		upReader: mcp.NewMsgReader(&in),
	}

	raw, err := proxy.fetchUpstreamToolsRaw(context.Background())
	if err != nil {
		t.Fatalf("fetchUpstreamToolsRaw: %v", err)
	}
	if tools, err := drift.ParseToolsListResult(raw); err != nil || len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %v (err=%v)", tools, err)
	}
	// The probe must have replied a JSON-RPC error addressed to the stray request.
	if got := out.String(); !strings.Contains(got, `"srv-1"`) ||
		!strings.Contains(got, "during session startup; not yet routable") {
		t.Errorf("probe must reply a JSON-RPC error to the stray server-initiated request so the upstream unblocks; upWriter output was:\n%s", got)
	}
}

// TestFetchStdioTools_HTTPBridge_TightUpstreamTimeoutDoesNotFailStartup pins the
// fix for the stdio->remote-HTTP drift probe being bound to --upstream-timeout.
// The probe is session-start work and must be bounded by the session-start budget
// (sessionStartTimeout), NOT by the per-call latency knob — exactly as the
// httpSession probe is (withoutUpstreamTimeout). Otherwise the same upstream,
// manifest, and --upstream-timeout would start cleanly behind an HTTP host but fail
// startup behind a stdio one. Here the upstream answers tools/list well past a tight
// --upstream-timeout but comfortably within the session-start budget; the probe must
// succeed. Before the fix it failed with an "upstream error" deadline.
func TestFetchStdioTools_HTTPBridge_TightUpstreamTimeoutDoesNotFailStartup(t *testing.T) {
	t.Parallel()

	const probeDelay = 150 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg mcp.RPCMsg
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if msg.Method == "tools/list" {
			time.Sleep(probeDelay) // slower than the tight --upstream-timeout below
		}
		result, _ := json.Marshal(map[string]interface{}{"tools": []map[string]interface{}{{"name": "read_file"}}})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: result})
	}))
	defer srv.Close()

	up := newHTTPUpstream(context.Background(), srv.URL, "", false, 0)
	defer up.close()

	p := &StdioProxy{
		upHTTP:         up,
		upReader:       up,
		upstreamTimeMs: 30, // tight per-call latency budget; must NOT bound the probe
	}

	raw, err := p.fetchUpstreamToolsRaw(context.Background())
	if err != nil {
		t.Fatalf("tight --upstream-timeout must not fail the session-start drift probe: %v", err)
	}
	tools, err := drift.ParseToolsListResult(raw)
	if err != nil {
		t.Fatalf("ParseToolsListResult: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "read_file" {
		t.Fatalf("unexpected probe result: %+v", tools)
	}
}

// TestFetchStdioTools_HTTPBridge_CanceledContextReturnsPromptly pins the fix for
// the stdio->remote-HTTP drift probe hanging forever when the parent context is
// canceled during startup (e.g. SIGINT after initUpstream). spawnPost can drop the
// POST on an already-canceled ctx, leaving nothing in-flight, and the bridge's plain
// Read selects only on incoming/done — done is closed only by close(), which the
// stuck startup never reaches. The probe read now honors the context, so a canceled
// probe returns an error promptly instead of blocking until SIGKILL.
func TestFetchStdioTools_HTTPBridge_CanceledContextReturnsPromptly(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg mcp.RPCMsg
		_ = json.NewDecoder(r.Body).Decode(&msg)
		result, _ := json.Marshal(map[string]interface{}{"tools": []map[string]interface{}{}})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: result})
	}))
	defer srv.Close()

	up := newHTTPUpstream(context.Background(), srv.URL, "", false, 0)
	defer up.close()
	p := &StdioProxy{upHTTP: up, upReader: up}

	// Context already canceled at probe time: the POST under it cannot succeed, so a
	// non-context-aware read would block forever.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		_, err := p.fetchUpstreamToolsRaw(ctx)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a probe whose parent context was canceled during startup must return an error, not a tool list")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("regression: the HTTP-bridge drift probe hung after its parent context was canceled")
	}
}

// TestInitUpstream_HTTPBridge_CanceledContextReturnsPromptly is the regression for
// the stdio->remote-HTTP initialize handshake hanging forever when the parent context
// is canceled during startup (e.g. SIGINT during the handshake). spawnPost can drop the
// initialize POST on an already-canceled ctx, leaving nothing in-flight, and the bridge's
// plain Read selects only on incoming/done — done is closed only by close(), which the
// stuck startup never reaches. initUpstream now reads via readProbeReply (readCtx), so it
// returns promptly on cancellation instead of wedging Start until SIGKILL.
func TestInitUpstream_HTTPBridge_CanceledContextReturnsPromptly(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg mcp.RPCMsg
		_ = json.NewDecoder(r.Body).Decode(&msg)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID})
	}))
	defer srv.Close()

	up := newHTTPUpstream(context.Background(), srv.URL, "", false, 0)
	defer up.close()
	p := &StdioProxy{upHTTP: up, upReader: up, upWriter: up}

	// Context already canceled at handshake time: spawnPost may drop the POST, so a
	// non-context-aware read would block forever waiting for a response that never comes.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- p.initUpstream(ctx) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("initUpstream with a canceled parent context must return an error, not complete silently")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("regression: initUpstream hung after its parent context was canceled")
	}
}

// TestInitUpstream_HTTPBridge_HungUpstreamBoundedByStartupBudget pins that the
// remote-HTTP initialize handshake is bounded by the session-start budget even with an
// UNCANCELED parent ctx and --upstream-timeout disabled. The old upWriter.Write path
// bounded the POST at notifyPostTimeout; the context-aware rewrite must not drop that
// bound, or a hung upstream (accepts the connection, never answers initialize) would
// wedge `eunox proxy` at startup forever with no per-call http.Client timeout to save it.
func TestInitUpstream_HTTPBridge_HungUpstreamBoundedByStartupBudget(t *testing.T) {
	t.Parallel()

	// The handler never answers within the budget, but unblocks on teardown so
	// httptest.Server.Close does not itself hang on a wedged handler goroutine.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() { close(release); srv.Close() })

	up := newHTTPUpstream(context.Background(), srv.URL, "", false, 0) // --upstream-timeout disabled
	defer up.close()
	p := &StdioProxy{upHTTP: up, upReader: up, upWriter: up, startupTimeout: 150 * time.Millisecond}

	done := make(chan error, 1)
	go func() { done <- p.initUpstream(context.Background()) }() // parent ctx never canceled
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("initUpstream against a hung upstream must fail, not succeed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("regression: initUpstream hung with --upstream-timeout disabled and an uncanceled parent ctx; the session-start budget must bound the handshake")
	}
}

// TestFetchStdioTools_HTTPBridge_OverallDeadlineBoundsAllPages pins that the
// stdio->remote-HTTP drift probe bounds the ENTIRE multi-page tools/list once, not
// each page with a fresh budget. With the per-page reset, an upstream answering each
// page just under the budget could stretch startup to pages*budget (~maxToolsListPages
// * sessionStartTimeout). Here the session-start budget (500ms) is smaller than two
// page delays (2*400ms) but larger than one, so the overall bound must make the probe
// fail; under the old reset both pages would have fit in their own fresh budgets.
func TestFetchStdioTools_HTTPBridge_OverallDeadlineBoundsAllPages(t *testing.T) {
	t.Parallel()

	const pageDelay = 400 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg mcp.RPCMsg
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if msg.Method != "tools/list" {
			result, _ := json.Marshal(map[string]interface{}{})
			_ = json.NewEncoder(w).Encode(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: result})
			return
		}
		var params struct {
			Cursor string `json:"cursor"`
		}
		if len(msg.Params) > 0 {
			_ = json.Unmarshal(msg.Params, &params)
		}
		time.Sleep(pageDelay)
		page := map[string]interface{}{"tools": []map[string]interface{}{{"name": "t_" + params.Cursor}}}
		if params.Cursor == "" {
			page["nextCursor"] = "p2" // first page asks for a second
		}
		result, _ := json.Marshal(page)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: result})
	}))
	defer srv.Close()

	up := newHTTPUpstream(context.Background(), srv.URL, "", false, 0)
	defer up.close()
	p := &StdioProxy{
		upHTTP:         up,
		upReader:       up,
		startupTimeout: 500 * time.Millisecond, // one overall budget < 2*pageDelay
	}

	done := make(chan error, 1)
	go func() {
		_, err := p.fetchUpstreamToolsRaw(context.Background())
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("multi-page probe must be bounded overall by the session-start budget, not reset per page")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not return within the overall deadline")
	}
}

// TestFetchStdioTools_UpstreamErrorPropagated confirms that a JSON-RPC error
// response is correctly surfaced as a Go error.
func TestFetchStdioTools_UpstreamErrorPropagated(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	data, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "_drift",
		"error":   map[string]interface{}{"code": -32601, "message": "method not found"},
	})
	buf.Write(data)
	buf.WriteByte('\n')

	proxy := &StdioProxy{
		upWriter: mcp.NewMsgWriter(io.Discard),
		upReader: mcp.NewMsgReader(&buf),
	}

	_, err := proxy.fetchUpstreamToolsRaw(context.Background())
	if err == nil {
		t.Fatal("expected error for upstream error response, got nil")
	}
	if !strings.Contains(err.Error(), "upstream error") {
		t.Errorf("unexpected error string: %v", err)
	}
}

// TestFetchStdioTools_IOErrorPropagated confirms that a pipe EOF (upstream
// crash) is surfaced rather than looping forever.
func TestFetchStdioTools_IOErrorPropagated(t *testing.T) {
	t.Parallel()

	proxy := &StdioProxy{
		upWriter: mcp.NewMsgWriter(io.Discard),
		upReader: mcp.NewMsgReader(strings.NewReader("")),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = proxy.fetchUpstreamToolsRaw(context.Background())
	}()

	select {
	case <-done:

	case <-time.After(2 * time.Second):
		t.Error("regression: fetchUpstreamToolsRaw hung on empty reader (infinite loop?)")
	}
}
