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

// rawID returns a json.RawMessage id for the given literal id string (e.g. "1" or `"x"`).
func rawID(t *testing.T, lit string) *json.RawMessage {
	t.Helper()
	raw := json.RawMessage(lit)
	return &raw
}

func TestToolCallResult_Dispatch(t *testing.T) {
	cases := []struct {
		name string
		args map[string]interface{}
		want string
	}{
		{"read_file", map[string]interface{}{"path": "/reports/q3.pdf"}, "/reports/q3.pdf"},
		{"read_any_report", map[string]interface{}{"path": "/reports/2025/q4.pdf"}, "/reports/2025/q4.pdf"},
		{"write_file", map[string]interface{}{"path": "/x", "content": "abc"}, "3 bytes"},
		{"query_db", map[string]interface{}{"query": "SELECT 1"}, "row"},
		{"query_db", map[string]interface{}{"query": "DELETE FROM t"}, "affected"},
		{"read_doc", map[string]interface{}{"path": "/a/b.csv"}, "col_a"},
		{"send_email", map[string]interface{}{"to": "a@example.com"}, "a@example.com"},
		{"get_plaintext", map[string]interface{}{"id": "1"}, "Revenue"},
	}
	for _, tc := range cases {
		res, rerr := toolCallResult(tc.name, tc.args, nil)
		if rerr != nil {
			t.Errorf("%s: unexpected rpcError %+v", tc.name, rerr)
			continue
		}
		raw, _ := json.Marshal(res)
		if !strings.Contains(string(raw), tc.want) {
			t.Errorf("%s: want substring %q in %s", tc.name, tc.want, raw)
		}
	}
}

func TestToolCallResult_UnknownTool(t *testing.T) {
	res, rerr := toolCallResult("does_not_exist", nil, nil)
	if res != nil || rerr == nil {
		t.Fatalf("want rpcError for unknown tool, got res=%v err=%v", res, rerr)
	}
	if rerr.Code != -32602 {
		t.Errorf("want code -32602, got %d", rerr.Code)
	}
}

// TestGetSecretRecord_RedactablePayload confirms the upstream emits the
// sensitive fields the policy's redactFields directive is expected to mask,
// in BOTH the text content and structuredContent. The proxy is what masks
// them; this test only guards the fixture so a silent payload change cannot
// make the redaction assertion vacuous.
func TestGetSecretRecord_RedactablePayload(t *testing.T) {
	res, rerr := toolCallResult("get_secret_record", map[string]interface{}{"id": "1"}, nil)
	if rerr != nil {
		t.Fatalf("unexpected error: %+v", rerr)
	}
	content := res["content"].([]map[string]interface{})
	text := content[0]["text"].(string)
	var body map[string]interface{}
	if err := json.Unmarshal([]byte(text), &body); err != nil {
		t.Fatalf("content text must be valid JSON: %v", err)
	}
	if _, ok := body["ssn"]; !ok {
		t.Error("fixture must contain top-level ssn")
	}
	nested, _ := body["nested"].(map[string]interface{})
	if _, ok := nested["token"]; !ok {
		t.Error("fixture must contain nested.token")
	}
	sc := res["structuredContent"].(map[string]interface{})
	if _, ok := sc["api_key"]; !ok {
		t.Error("fixture must contain structuredContent.api_key")
	}
}

// TestGetMalformed_LooksLikeJSON guards that the malformed fixture is
// JSON-looking (leading '{') yet invalid — the shape that passes through
// unredacted (redactFields parses clean JSON only and never fails closed over
// content it cannot parse).
func TestGetMalformed_LooksLikeJSON(t *testing.T) {
	res, _ := toolCallResult("get_malformed", nil, nil)
	text := res["content"].([]map[string]interface{})[0]["text"].(string)
	if !strings.HasPrefix(text, "{") {
		t.Errorf("fixture must look like a JSON object, got %q", text)
	}
	if json.Valid([]byte(text)) {
		t.Errorf("fixture must be INVALID JSON, got valid: %q", text)
	}
}

func TestDispatch_ListMethods(t *testing.T) {
	for _, m := range []string{"tools/list", "resources/list", "prompts/list", "resources/templates/list"} {
		msg := rpcMsg{Method: m}
		res, rerr := dispatch(&msg, nil)
		if rerr != nil {
			t.Errorf("%s: unexpected error %+v", m, rerr)
		}
		if res == nil {
			t.Errorf("%s: nil result", m)
		}
	}
}

func TestDispatch_UnknownMethod(t *testing.T) {
	msg := rpcMsg{Method: "no/such/method"}
	_, rerr := dispatch(&msg, nil)
	if rerr == nil || rerr.Code != -32601 {
		t.Fatalf("want -32601 method-not-found, got %+v", rerr)
	}
}

func TestInitializeResult_AdvertisesCapabilities(t *testing.T) {
	res := initializeResult()
	caps, ok := res["capabilities"].(map[string]interface{})
	if !ok {
		t.Fatal("missing capabilities")
	}
	for _, want := range []string{"tools", "resources", "prompts", "sampling"} {
		if _, ok := caps[want]; !ok {
			t.Errorf("capabilities missing %q", want)
		}
	}
}

// ── HTTP transport ──────────────────────────────────────────────────────────

func httpPost(t *testing.T, srv *httpServer, body, sid string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if sid != "" {
		req.Header.Set(sessionHeader, sid)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func TestHTTP_InitializeAndCall(t *testing.T) {
	srv := newHTTPServer()
	w := httpPost(t, srv, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "")
	if w.Code != http.StatusOK {
		t.Fatalf("initialize: want 200, got %d", w.Code)
	}
	sid := w.Header().Get(sessionHeader)
	if sid == "" {
		t.Fatal("initialize: missing session id header")
	}

	w = httpPost(t, srv, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}`, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("tools/call: want 200, got %d", w.Code)
	}
	var msg rpcMsg
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.Error != nil {
		t.Fatalf("unexpected error: %+v", msg.Error)
	}
}

func TestHTTP_RequiresSession(t *testing.T) {
	srv := newHTTPServer()
	w := httpPost(t, srv, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 without session, got %d", w.Code)
	}
}

func TestHTTP_UnknownSession(t *testing.T) {
	srv := newHTTPServer()
	w := httpPost(t, srv, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, "nope")
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404 for unknown session, got %d", w.Code)
	}
}

func TestHTTP_InvalidBody(t *testing.T) {
	srv := newHTTPServer()
	w := httpPost(t, srv, "not json {", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid body, got %d", w.Code)
	}
}

// TestHTTP_InitializeNotificationDoesNotCreateSession is the regression for the
// id-less-initialize bug: an initialize NOTIFICATION (no id) must not allocate a
// session, set Mcp-Session-Id, or return an initialize result — per JSON-RPC/MCP a
// notification gets no response and mutates no state.
func TestHTTP_InitializeNotificationDoesNotCreateSession(t *testing.T) {
	srv := newHTTPServer()
	srv.mu.RLock()
	before := len(srv.sessions)
	srv.mu.RUnlock()

	w := httpPost(t, srv, `{"jsonrpc":"2.0","method":"initialize","params":{}}`, "")

	if got := w.Header().Get(sessionHeader); got != "" {
		t.Errorf("initialize notification must not set a session id header, got %q", got)
	}
	srv.mu.RLock()
	after := len(srv.sessions)
	srv.mu.RUnlock()
	if after != before {
		t.Errorf("initialize notification must not create a session: len(sessions) %d -> %d", before, after)
	}
	if w.Code == http.StatusOK {
		t.Errorf("initialize notification must not return an initialize result (200); got %d", w.Code)
	}
}

// TestHTTP_NotificationWithoutSessionRejected is the regression for the
// accept-without-session bug: a post-initialize notification (e.g.
// notifications/initialized) with no Mcp-Session-Id must be rejected before the
// notification fast path, not accepted with 202, so the fixture stays honest to the
// request path.
func TestHTTP_NotificationWithoutSessionRejected(t *testing.T) {
	srv := newHTTPServer()
	w := httpPost(t, srv, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("notification without a session must be rejected (400), got %d", w.Code)
	}
}

// TestHTTP_RejectsTrailingJSONTokens pins the fail-closed fix: a POST /mcp body is
// exactly one JSON value, so a valid initialize followed by a second JSON-RPC token
// must be rejected with 400 before either object is dispatched — never 200-acking
// the first value with a session allocated while a smuggled trailer is silently
// dropped.
func TestHTTP_RejectsTrailingJSONTokens(t *testing.T) {
	srv := newHTTPServer()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}} {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	w := httpPost(t, srv, body, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON token: status = %d, want 400 (body=%q)", w.Code, w.Body.String())
	}
	if sid := w.Header().Get(sessionHeader); sid != "" {
		t.Errorf("malformed body allocated a session: %s = %q", sessionHeader, sid)
	}
}

func TestHTTP_Get(t *testing.T) {
	srv := newHTTPServer()
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	ctx, cancel := context.WithCancel(req.Context())
	cancel() // already-done context so the GET handler returns immediately
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /mcp: want 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("GET /mcp: want text/event-stream, got %q", ct)
	}
}

func TestHTTP_DeleteWithSession(t *testing.T) {
	srv := newHTTPServer()
	w := httpPost(t, srv, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "")
	sid := w.Header().Get(sessionHeader)

	req := httptest.NewRequest(http.MethodDelete, "/mcp", http.NoBody)
	req.Header.Set(sessionHeader, sid)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("DELETE with session: want 204, got %d", w.Code)
	}

	srv.mu.RLock()
	_, ok := srv.sessions[sid]
	srv.mu.RUnlock()
	if ok {
		t.Error("DELETE must remove the session")
	}
}

func TestHTTP_DeleteWithoutSession(t *testing.T) {
	srv := newHTTPServer()
	req := httptest.NewRequest(http.MethodDelete, "/mcp", http.NoBody)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("DELETE without session: want 204, got %d", w.Code)
	}
}

func TestHTTP_NotFoundPath(t *testing.T) {
	srv := newHTTPServer()
	req := httptest.NewRequest(http.MethodGet, "/other", http.NoBody)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404 for unknown path, got %d", w.Code)
	}
}

func TestHTTP_MethodNotAllowed(t *testing.T) {
	srv := newHTTPServer()
	req := httptest.NewRequest(http.MethodPut, "/mcp", http.NoBody)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("want 405 for PUT, got %d", w.Code)
	}
}

func TestHTTP_DispatchErrorPath(t *testing.T) {
	srv := newHTTPServer()
	w := httpPost(t, srv, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "")
	sid := w.Header().Get(sessionHeader)

	w = httpPost(t, srv, `{"jsonrpc":"2.0","id":2,"method":"no/such/method","params":{}}`, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 (JSON-RPC error body, not HTTP error), got %d", w.Code)
	}
	var msg rpcMsg
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.Error == nil || msg.Error.Code != -32601 {
		t.Fatalf("want -32601 method-not-found error, got %+v", msg.Error)
	}
}

func TestWriteHTTPError(t *testing.T) {
	w := httptest.NewRecorder()
	id := rawID(t, "1")
	writeHTTPError(w, id, -32602, "bad params")
	var msg rpcMsg
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.Error == nil || msg.Error.Code != -32602 || msg.Error.Message != "bad params" {
		t.Errorf("want error code -32602 message 'bad params', got %+v", msg.Error)
	}
}

// ── stdio transport ─────────────────────────────────────────────────────────

func TestStdioConn_WriteAndReadLine(t *testing.T) {
	in := bytes.NewBufferString("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n")
	var out bytes.Buffer
	conn := newStdioConnIO(in, &out)

	line, ok := conn.readLine()
	if !ok {
		t.Fatal("want first line ok")
	}
	if !strings.Contains(string(line), `"id":1`) {
		t.Errorf("want id 1 line, got %s", line)
	}
	// blank line is skipped.
	line, ok = conn.readLine()
	if !ok {
		t.Fatal("want second line ok (blank skipped)")
	}
	if !strings.Contains(string(line), `"id":2`) {
		t.Errorf("want id 2 line, got %s", line)
	}
	_, ok = conn.readLine()
	if ok {
		t.Error("want EOF after last line")
	}

	conn.writeMsg(rpcMsg{JSONRPC: "2.0", ID: rawID(t, "1"), Result: json.RawMessage(`{}`)})
	if !strings.Contains(out.String(), `"jsonrpc":"2.0"`) {
		t.Errorf("writeMsg output missing jsonrpc field: %s", out.String())
	}
}

func TestRunStdioLoop_RequestResponse(t *testing.T) {
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n")
	var out bytes.Buffer
	conn := newStdioConnIO(in, &out)
	runStdioLoop(conn)

	var msg rpcMsg
	if err := json.Unmarshal(out.Bytes(), &msg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.Error != nil {
		t.Fatalf("unexpected error: %+v", msg.Error)
	}
}

func TestRunStdioLoop_DispatchError(t *testing.T) {
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"no/such/method"}` + "\n")
	var out bytes.Buffer
	conn := newStdioConnIO(in, &out)
	runStdioLoop(conn)

	var msg rpcMsg
	if err := json.Unmarshal(out.Bytes(), &msg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.Error == nil || msg.Error.Code != -32601 {
		t.Fatalf("want -32601, got %+v", msg.Error)
	}
}

func TestRunStdioLoop_SkipsUnparseableNotificationsAndResponses(t *testing.T) {
	in := bytes.NewBufferString(strings.Join([]string{
		`not json at all`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":1,"result":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
	}, "\n") + "\n")
	var out bytes.Buffer
	conn := newStdioConnIO(in, &out)
	runStdioLoop(conn)

	// Only the ping request should have produced output.
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want exactly 1 response line, got %d: %v", len(lines), lines)
	}
	var msg rpcMsg
	if err := json.Unmarshal([]byte(lines[0]), &msg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(*msg.ID) != "2" {
		t.Errorf("want response to id 2, got id %s", *msg.ID)
	}
}

func TestTriggerSampling_NilConn(t *testing.T) {
	res := triggerSampling(nil)
	text := res["content"].([]map[string]interface{})[0]["text"].(string)
	if text != "sampling:skipped-http" {
		t.Errorf("want sampling:skipped-http, got %q", text)
	}
}

func TestTriggerSampling_Allowed(t *testing.T) {
	var out bytes.Buffer
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":"e2e-sampling-1","result":{}}` + "\n")
	conn := newStdioConnIO(in, &out)

	res := triggerSampling(conn)
	text := res["content"].([]map[string]interface{})[0]["text"].(string)
	if text != "sampling:allowed" {
		t.Errorf("want sampling:allowed, got %q", text)
	}
	if !strings.Contains(out.String(), "sampling/createMessage") {
		t.Errorf("want the server-initiated request to be written, got %s", out.String())
	}
}

func TestTriggerSampling_Denied(t *testing.T) {
	var out bytes.Buffer
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":"e2e-sampling-1","error":{"code":-32000,"message":"denied"}}` + "\n")
	conn := newStdioConnIO(in, &out)

	res := triggerSampling(conn)
	text := res["content"].([]map[string]interface{})[0]["text"].(string)
	if text != "sampling:denied" {
		t.Errorf("want sampling:denied, got %q", text)
	}
}

func TestTriggerSampling_SkipsStrayLinesThenMatches(t *testing.T) {
	var out bytes.Buffer
	in := bytes.NewBufferString(strings.Join([]string{
		`not json`,
		`{"jsonrpc":"2.0","id":"other-id","result":{}}`,
		`{"jsonrpc":"2.0","id":"e2e-sampling-1","result":{}}`,
	}, "\n") + "\n")
	conn := newStdioConnIO(in, &out)

	res := triggerSampling(conn)
	text := res["content"].([]map[string]interface{})[0]["text"].(string)
	if text != "sampling:allowed" {
		t.Errorf("want sampling:allowed, got %q", text)
	}
}

func TestTriggerSampling_NoResponse(t *testing.T) {
	var out bytes.Buffer
	in := bytes.NewBufferString("")
	conn := newStdioConnIO(in, &out)

	res := triggerSampling(conn)
	text := res["content"].([]map[string]interface{})[0]["text"].(string)
	if text != "sampling:no-response" {
		t.Errorf("want sampling:no-response, got %q", text)
	}
}

// ── dispatch: remaining methods ─────────────────────────────────────────────

func TestDispatch_Initialize(t *testing.T) {
	msg := rpcMsg{Method: "initialize"}
	res, rerr := dispatch(&msg, nil)
	if rerr != nil {
		t.Fatalf("unexpected error: %+v", rerr)
	}
	if _, ok := res.(map[string]interface{})["serverInfo"]; !ok {
		t.Error("want serverInfo in initialize result")
	}
}

func TestDispatch_ToolsCallInvalidParams(t *testing.T) {
	msg := rpcMsg{Method: "tools/call", Params: json.RawMessage(`not json`)}
	_, rerr := dispatch(&msg, nil)
	if rerr == nil || rerr.Code != -32602 {
		t.Fatalf("want -32602, got %+v", rerr)
	}
}

func TestDispatch_ToolsCallDefaultsNilArguments(t *testing.T) {
	msg := rpcMsg{Method: "tools/call", Params: json.RawMessage(`{"name":"send_email"}`)}
	res, rerr := dispatch(&msg, nil)
	if rerr != nil {
		t.Fatalf("unexpected error: %+v", rerr)
	}
	if res == nil {
		t.Fatal("want non-nil result")
	}
}

func TestDispatch_ResourcesRead(t *testing.T) {
	msg := rpcMsg{Method: "resources/read", Params: json.RawMessage(`{"uri":"file:///x"}`)}
	res, rerr := dispatch(&msg, nil)
	if rerr != nil {
		t.Fatalf("unexpected error: %+v", rerr)
	}
	contents := res.(map[string]interface{})["contents"].([]map[string]interface{})
	if contents[0]["uri"] != "file:///x" {
		t.Errorf("want uri echoed, got %+v", contents[0])
	}
}

func TestDispatch_ResourcesSubscribe(t *testing.T) {
	msg := rpcMsg{Method: "resources/subscribe", Params: json.RawMessage(`{"uri":"file:///x"}`)}
	res, rerr := dispatch(&msg, nil)
	if rerr != nil {
		t.Fatalf("unexpected error: %+v", rerr)
	}
	if res == nil {
		t.Fatal("want non-nil result")
	}
}

func TestDispatch_PromptsGet(t *testing.T) {
	msg := rpcMsg{Method: "prompts/get", Params: json.RawMessage(`{"name":"greeting"}`)}
	res, rerr := dispatch(&msg, nil)
	if rerr != nil {
		t.Fatalf("unexpected error: %+v", rerr)
	}
	desc := res.(map[string]interface{})["description"].(string)
	if desc != "prompt greeting" {
		t.Errorf("want 'prompt greeting', got %q", desc)
	}
}

func TestDispatch_Ping(t *testing.T) {
	msg := rpcMsg{Method: "ping"}
	res, rerr := dispatch(&msg, nil)
	if rerr != nil {
		t.Fatalf("unexpected error: %+v", rerr)
	}
	if res == nil {
		t.Fatal("want non-nil result")
	}
}

func TestDispatch_CompletionComplete(t *testing.T) {
	msg := rpcMsg{Method: "completion/complete"}
	res, rerr := dispatch(&msg, nil)
	if rerr != nil {
		t.Fatalf("unexpected error: %+v", rerr)
	}
	completion := res.(map[string]interface{})["completion"].(map[string]interface{})
	if completion["total"] != 2 {
		t.Errorf("want total 2, got %+v", completion)
	}
}

// ── toolCallResult: remaining cases ─────────────────────────────────────────

func TestToolCallResult_RemainingCases(t *testing.T) {
	cases := []struct {
		name string
		args map[string]interface{}
		want string
	}{
		{"read_credentials", map[string]interface{}{"name": "db-pass"}, "db-pass"},
		{"write_external", map[string]interface{}{"url": "https://example.com"}, "example.com"},
		{"rate_limited", map[string]interface{}{"n": "1"}, "rate_limited ok n=1"},
		{"time_gated", nil, "time_gated ok"},
		{"big_response", nil, strings.Repeat("A", bigResponseSize)},
		{"secret_tool", nil, "secret_tool ran"},
	}
	for _, tc := range cases {
		res, rerr := toolCallResult(tc.name, tc.args, nil)
		if rerr != nil {
			t.Errorf("%s: unexpected rpcError %+v", tc.name, rerr)
			continue
		}
		raw, _ := json.Marshal(res)
		if !strings.Contains(string(raw), tc.want) {
			t.Errorf("%s: want substring %q in result", tc.name, tc.want)
		}
	}
}

func TestToolCallResult_TriggerSamplingNilConn(t *testing.T) {
	res, rerr := toolCallResult("trigger_sampling", nil, nil)
	if rerr != nil {
		t.Fatalf("unexpected error: %+v", rerr)
	}
	text := res["content"].([]map[string]interface{})[0]["text"].(string)
	if text != "sampling:skipped-http" {
		t.Errorf("want sampling:skipped-http, got %q", text)
	}
}
