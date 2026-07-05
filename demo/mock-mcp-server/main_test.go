// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// post sends a POST /mcp request and returns the ResponseRecorder.
func post(t *testing.T, srv *server, body, sessionID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if sessionID != "" {
		req.Header.Set(sessionHeader, sessionID)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// decodeMsg parses the response body as a JSON-RPC message.
func decodeMsg(t *testing.T, w *httptest.ResponseRecorder) rpcMsg {
	t.Helper()
	var msg rpcMsg
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatalf("decoding response: %v\nbody: %s", err, w.Body.String())
	}
	return msg
}

// initSession calls initialize and returns the session ID from the response header.
func initSession(t *testing.T, srv *server) string {
	t.Helper()
	w := post(t, srv, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "")
	if w.Code != http.StatusOK {
		t.Fatalf("initialize: expected 200, got %d", w.Code)
	}
	sid := w.Header().Get(sessionHeader)
	if sid == "" {
		t.Fatal("initialize: missing Mcp-Session-Id header")
	}
	return sid
}

func TestInitialize_CreatesSession(t *testing.T) {
	srv := newServer()
	w := post(t, srv, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	sid := w.Header().Get(sessionHeader)
	if sid == "" {
		t.Fatal("expected Mcp-Session-Id header")
	}

	// Session must be registered.
	srv.mu.RLock()
	_, ok := srv.sessions[sid]
	srv.mu.RUnlock()
	if !ok {
		t.Fatal("session not found in server map")
	}

	// Response must be a valid JSON-RPC success.
	msg := decodeMsg(t, w)
	if msg.Error != nil {
		t.Fatalf("unexpected error: %+v", msg.Error)
	}
	if msg.Result == nil {
		t.Fatal("expected result, got nil")
	}

	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name string `json:"name"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	if result.ProtocolVersion != mcpProtocolVersion {
		t.Errorf("protocolVersion: want %q, got %q", mcpProtocolVersion, result.ProtocolVersion)
	}
	if result.ServerInfo.Name != serverName {
		t.Errorf("serverInfo.name: want %q, got %q", serverName, result.ServerInfo.Name)
	}
}

// TestHealthz_NoSessionLeak pins that the container-healthcheck endpoint is
// side-effect-free: a GET /healthz returns 200 and leaves the session map empty, so a
// periodic liveness probe cannot grow resident sessions the way a real `initialize`
// probe did.
func TestHealthz_NoSessionLeak(t *testing.T) {
	srv := newServer()
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET /healthz: expected 200, got %d", w.Code)
		}
	}
	srv.mu.RLock()
	n := len(srv.sessions)
	srv.mu.RUnlock()
	if n != 0 {
		t.Errorf("healthcheck probes leaked sessions: got %d, want 0", n)
	}
}

func TestInitialize_EachCallCreatesUniqueSession(t *testing.T) {
	srv := newServer()
	s1 := initSession(t, srv)
	s2 := initSession(t, srv)
	if s1 == s2 {
		t.Error("expected distinct session IDs for separate initialize calls")
	}
}

func TestToolsCall_RequiresSession(t *testing.T) {
	srv := newServer()
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}`
	w := post(t, srv, body, "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestToolsCall_UnknownSession(t *testing.T) {
	srv := newServer()
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}`
	w := post(t, srv, body, "no-such-session")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestToolsList(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)

	w := post(t, srv, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	msg := decodeMsg(t, w)
	if msg.Error != nil {
		t.Fatalf("unexpected error: %+v", msg.Error)
	}

	var result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("parsing tools/list result: %v", err)
	}

	names := make([]string, len(result.Tools))
	for i, t2 := range result.Tools {
		names[i] = t2.Name
	}
	want := map[string]bool{"read_file": true, "write_file": true, "query_db": true}
	for _, n := range names {
		delete(want, n)
	}
	if len(want) > 0 {
		t.Errorf("missing tools: %v; got %v", want, names)
	}
}

func TestReadFile(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)

	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}`
	w := post(t, srv, body, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	msg := decodeMsg(t, w)
	if msg.Error != nil {
		t.Fatalf("unexpected error: %+v", msg.Error)
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	if result.IsError {
		t.Error("isError should be false")
	}
	if len(result.Content) == 0 {
		t.Fatal("expected at least one content item")
	}
	if !strings.Contains(result.Content[0].Text, "/reports/q3.pdf") {
		t.Errorf("result text should mention the path; got: %s", result.Content[0].Text)
	}
}

func TestWriteFile(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)

	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/test.txt","content":"hello world"}}}`
	w := post(t, srv, body, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	msg := decodeMsg(t, w)
	if msg.Error != nil {
		t.Fatalf("unexpected error: %+v", msg.Error)
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content")
	}
	// "11 bytes" because "hello world" is 11 chars
	if !strings.Contains(result.Content[0].Text, "11 bytes") {
		t.Errorf("expected byte count in response; got: %s", result.Content[0].Text)
	}
}

func TestQueryDB_Select(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)

	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"SELECT * FROM reports"}}}`
	w := post(t, srv, body, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	msg := decodeMsg(t, w)
	if msg.Error != nil {
		t.Fatalf("unexpected error: %+v", msg.Error)
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content")
	}
	if !strings.Contains(result.Content[0].Text, "rows") {
		t.Errorf("SELECT response should mention rows; got: %s", result.Content[0].Text)
	}
}

func TestQueryDB_NonSelect(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)

	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"DELETE FROM reports"}}}`
	w := post(t, srv, body, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	msg := decodeMsg(t, w)
	if msg.Error != nil {
		t.Fatalf("unexpected error: %+v", msg.Error)
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	if !strings.Contains(result.Content[0].Text, "affected") {
		t.Errorf("non-SELECT response should mention rows affected; got: %s", result.Content[0].Text)
	}
}

func TestUnknownTool(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)

	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"drop_table","arguments":{}}}`
	w := post(t, srv, body, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (JSON-RPC error in body), got %d", w.Code)
	}

	msg := decodeMsg(t, w)
	if msg.Error == nil {
		t.Fatal("expected JSON-RPC error for unknown tool")
	}
	if !strings.Contains(msg.Error.Message, "drop_table") {
		t.Errorf("error message should mention tool name; got: %s", msg.Error.Message)
	}
}

func TestUnknownMethod(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)

	body := `{"jsonrpc":"2.0","id":4,"method":"resources/list","params":{}}`
	w := post(t, srv, body, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	msg := decodeMsg(t, w)
	if msg.Error == nil || msg.Error.Code != -32601 {
		t.Errorf("expected -32601 method-not-found error; got %+v", msg.Error)
	}
}

func TestNotification_Accepted(t *testing.T) {
	srv := newServer()
	// Notifications have no ID.
	body := `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`
	w := post(t, srv, body, "")
	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202 for notification, got %d", w.Code)
	}
}

func TestSessionDelete(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)

	req := httptest.NewRequest(http.MethodDelete, "/mcp", http.NoBody)
	req.Header.Set(sessionHeader, sid)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}

	// Session must be gone.
	srv.mu.RLock()
	_, ok := srv.sessions[sid]
	srv.mu.RUnlock()
	if ok {
		t.Error("session should have been deleted")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	srv := newServer()
	req := httptest.NewRequest(http.MethodPut, "/mcp", http.NoBody)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestNotFoundPath(t *testing.T) {
	srv := newServer()
	req := httptest.NewRequest(http.MethodGet, "/unknown", http.NoBody)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestDispatchTool(t *testing.T) {
	cases := []struct {
		name string
		args map[string]interface{}
		want string
	}{
		{"read_file", map[string]interface{}{"path": "/data/x.txt"}, "/data/x.txt"},
		{"write_file", map[string]interface{}{"path": "/out.txt", "content": "abc"}, "3 bytes"},
		{"query_db", map[string]interface{}{"query": "SELECT id FROM t"}, "rows"},
		{"query_db", map[string]interface{}{"query": "INSERT INTO t VALUES(1)"}, "affected"},
	}
	for _, tc := range cases {
		got := dispatchTool(tc.name, tc.args)
		if !strings.Contains(got, tc.want) {
			t.Errorf("dispatchTool(%q): want substring %q in %q", tc.name, tc.want, got)
		}
	}

	// Unknown tool returns "".
	if got := dispatchTool("unknown_tool", nil); got != "" {
		t.Errorf("expected empty string for unknown tool, got %q", got)
	}
}

func TestConcurrentSessions(t *testing.T) {
	srv := newServer()
	const n = 20
	sids := make([]string, n)
	for i := range n {
		sids[i] = initSession(t, srv)
	}

	// All sessions should be distinct.
	seen := make(map[string]bool)
	for _, sid := range sids {
		if seen[sid] {
			t.Fatalf("duplicate session ID: %s", sid)
		}
		seen[sid] = true
	}

	// Each session can call tools independently.
	for _, sid := range sids {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
		w := post(t, srv, body, sid)
		if w.Code != http.StatusOK {
			t.Errorf("session %s: tools/list returned %d", sid, w.Code)
		}
	}
}

func TestInvalidJSONBody(t *testing.T) {
	srv := newServer()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

// TestTrailingJSONTokenRejected asserts a body whose first value is a clean
// initialize but which carries a second JSON-RPC token afterwards is rejected with
// 400 and never allocates a session: handlePost requires EOF after the first decode,
// so a malformed multi-token body cannot smuggle a clean-looking initialize through.
func TestTrailingJSONTokenRejected(t *testing.T) {
	srv := newServer()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	w := post(t, srv, body, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON token: expected 400, got %d", w.Code)
	}
	if sid := w.Header().Get(sessionHeader); sid != "" {
		t.Errorf("a malformed body must not allocate a session; got Mcp-Session-Id %q", sid)
	}
	srv.mu.RLock()
	n := len(srv.sessions)
	srv.mu.RUnlock()
	if n != 0 {
		t.Errorf("expected no sessions after a rejected body, got %d", n)
	}
}

// TestGetSSE exercises the GET /mcp SSE path. The request context is
// pre-canceled so the handler returns immediately after writing the headers.
func TestGetSSE(t *testing.T) {
	srv := newServer()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so <-r.Context().Done() fires at once
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody).WithContext(ctx)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("SSE GET: expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "text/event-stream" {
		t.Errorf("SSE GET: expected text/event-stream Content-Type, got %q", ct)
	}
}

// TestDeleteWithoutSessionID covers the DELETE branch when no session header is
// provided (the session map is left unchanged, 204 is still returned).
func TestDeleteWithoutSessionID(t *testing.T) {
	srv := newServer()
	req := httptest.NewRequest(http.MethodDelete, "/mcp", http.NoBody)
	// No Mcp-Session-Id header set.
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

// TestHandlePost_NonRequestResponse covers the handlePost branch for a message
// that has an ID but no Method (i.e. a JSON-RPC response), which is neither
// a request nor a notification.
func TestHandlePost_NonRequestResponse(t *testing.T) {
	srv := newServer()
	// Message with an ID but no method — not a request, not a notification.
	body := `{"jsonrpc":"2.0","id":5,"result":{"ok":true}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202 for non-request, got %d", w.Code)
	}
}

// TestHandleToolsCall_InvalidParams covers the json.Unmarshal error path in
// handleToolsCall when the params field is not a valid object.
func TestHandleToolsCall_InvalidParams(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)

	body := `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":"not-an-object"}`
	w := post(t, srv, body, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (JSON-RPC error body), got %d", w.Code)
	}
	msg := decodeMsg(t, w)
	if msg.Error == nil {
		t.Fatal("expected JSON-RPC error for invalid params")
	}
	if msg.Error.Code != -32602 {
		t.Errorf("expected code -32602, got %d", msg.Error.Code)
	}
}

// TestHandleToolsCall_NilArguments covers the params.Arguments == nil branch: a
// tools/call with a valid name but no "arguments" key normalizes to {} and is then
// rejected with -32602, because read_file's advertised schema requires "path". The
// HTTP mock no longer fabricates a successful result with a blank substituted path.
func TestHandleToolsCall_NilArguments(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)

	// No "arguments" key — params.Arguments is nil and is filled with {}, which then
	// fails the required-argument check.
	body := `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"read_file"}}`
	w := post(t, srv, body, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (JSON-RPC error body), got %d", w.Code)
	}
	msg := decodeMsg(t, w)
	if msg.Error == nil {
		t.Fatal("expected a -32602 error for read_file with no required path argument, got success")
	}
	if msg.Error.Code != -32602 {
		t.Errorf("expected code -32602, got %d", msg.Error.Code)
	}
}

// TestHandleToolsCall_WrongTypedArgument asserts a required argument supplied with the
// wrong JSON type (here a number for the string "query") is rejected with -32602
// rather than coerced to a blank string and answered with a fabricated success.
func TestHandleToolsCall_WrongTypedArgument(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)

	body := `{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"query_db","arguments":{"query":42}}}`
	w := post(t, srv, body, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (JSON-RPC error body), got %d", w.Code)
	}
	msg := decodeMsg(t, w)
	if msg.Error == nil {
		t.Fatal("expected a -32602 error for a non-string query argument, got success")
	}
	if msg.Error.Code != -32602 {
		t.Errorf("expected code -32602, got %d", msg.Error.Code)
	}
}
