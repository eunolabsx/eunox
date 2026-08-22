// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func msgWithResult(raw string) rpcMsg {
	r := json.RawMessage(raw)
	return rpcMsg{JSONRPC: "2.0", Result: r}
}

func TestToolText(t *testing.T) {
	m := msgWithResult(`{"content":[{"type":"text","text":"hello "},{"type":"text","text":"world"}]}`)
	if got := toolText(m); got != "hello world" {
		t.Errorf("toolText = %q, want %q", got, "hello world")
	}
}

func TestFirstContentJSONAndStructured(t *testing.T) {
	m := msgWithResult(`{"content":[{"type":"text","text":"{\"name\":\"alice\",\"nested\":{\"keep\":\"yes\"}}"}],"structuredContent":{"public":"ok"}}`)
	body := firstContentJSON(m)
	if !has(body, "name") {
		t.Error("expected name key in parsed content")
	}
	if !has(subObject(body, "nested"), "keep") {
		t.Error("expected nested.keep in parsed content")
	}
	if has(subObject(body, "missing"), "x") {
		t.Error("subObject of missing key should be empty")
	}
	sc := structuredContent(m)
	if !has(sc, "public") {
		t.Error("expected public key in structuredContent")
	}
}

func TestListNames(t *testing.T) {
	m := msgWithResult(`{"tools":[{"name":"b"},{"name":"a"},{"name":"c"}]}`)
	got := listNames(m, "tools", "name")
	want := []string{"a", "b", "c"} // listNames sorts
	if !slicesEqual(got, want) {
		t.Errorf("listNames = %v, want %v", got, want)
	}

	res := msgWithResult(`{"resources":[{"uri":"db://x"},{"uri":"file:///y"}]}`)
	if !slicesEqual(listNames(res, "resources", "uri"), []string{"db://x", "file:///y"}) {
		t.Errorf("resource uri extraction failed: %v", listNames(res, "resources", "uri"))
	}
}

func TestSlicesEqual(t *testing.T) {
	if !slicesEqual([]string{"a", "b"}, []string{"a", "b"}) {
		t.Error("equal slices should compare equal")
	}
	if slicesEqual([]string{"a"}, []string{"a", "b"}) {
		t.Error("different lengths should not be equal")
	}
	if slicesEqual([]string{"a", "b"}, []string{"a", "c"}) {
		t.Error("different elements should not be equal")
	}
}

func TestContains(t *testing.T) {
	xs := []string{"x", "y"}
	if !contains(xs, "y") {
		t.Error("contains should find present element")
	}
	if contains(xs, "z") {
		t.Error("contains should not find absent element")
	}
}

func TestDenialDataParsing(t *testing.T) {
	m := rpcMsg{Error: &rpcError{
		Code:    -32003,
		Message: "CONDITION_FAILED: ...",
		Data:    json.RawMessage(`{"code":"CONDITION_FAILED","type":"allowedValues","target":"read_file","argument":"path"}`),
	}}
	var d denialData
	if err := json.Unmarshal(m.Error.Data, &d); err != nil {
		t.Fatalf("unmarshal denial data: %v", err)
	}
	if d.Code != "CONDITION_FAILED" || d.Type != "allowedValues" || d.Argument != "path" {
		t.Errorf("denial data parsed wrong: %+v", d)
	}
}

// TestExpectHelpers drives the suite assertion helpers against synthetic
// messages to confirm they classify allow/deny/error correctly.
func TestExpectHelpers(t *testing.T) {
	s := &suite{}
	s.expectAllow("allow ok", msgWithResult(`{"ok":true}`), nil)

	deny := rpcMsg{Error: &rpcError{Code: -32001, Data: json.RawMessage(`{"code":"AUTHORIZATION_FAILED"}`)}}
	s.expectDeny("deny ok", "AUTHORIZATION_FAILED", "", deny, nil)

	internal := rpcMsg{Error: &rpcError{Code: -32603, Message: "response redaction failed"}}
	s.expectErrorCode("internal ok", -32603, internal, nil)

	if s.fail != 0 || s.pass != 3 {
		t.Errorf("want 3 pass / 0 fail, got %d / %d", s.pass, s.fail)
	}

	// Negative classifications.
	f := &suite{}
	f.expectAllow("should fail: allow on error", deny, nil)
	f.expectDeny("should fail: wrong code", "CONDITION_FAILED", "", deny, nil)
	f.expectAllow("should fail: transport err", rpcMsg{}, errSentinel)
	if f.fail != 3 {
		t.Errorf("want 3 fail classifications, got %d (pass=%d)", f.fail, f.pass)
	}
}

var errSentinel = errTest("boom")

type errTest string

func (e errTest) Error() string { return string(e) }

// TestHTTPInitialize_RejectsMalformedResponses is the regression: the e2e
// HTTP client must reject a malformed or truncated initialize response instead of
// accepting it on the strength of a 200 + Mcp-Session-Id header alone.
func TestHTTPInitialize_RejectsMalformedResponses(t *testing.T) {
	cases := []struct {
		name string
		body string // initialize response body the fake gateway returns
	}{
		{"not json", "not-json"},
		{"truncated json", `{"jsonrpc":"2.0","id":1,"result":{`},
		{"empty body with session", ""},
		{"valid envelope but no result", `{"jsonrpc":"2.0","id":1}`},
		{"wrong id", `{"jsonrpc":"2.0","id":999,"result":{"protocolVersion":"x"}}`}, // first initialize id is 1
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				// Always hand back a session and 200, the way a regressed gateway
				// might, regardless of body validity.
				w.Header().Set("Mcp-Session-Id", "fake-session")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()

			h := &httpConn{base: srv.URL, route: "main", client: srv.Client()}
			// newHTTPConn embeds the route under /mcp/<route>; the fake server ignores
			// the path, so set base so endpoint() resolves to the test server.
			h.base = srv.URL
			if err := h.initialize(); err == nil {
				t.Fatalf("initialize accepted a malformed response (%s)", tc.name)
			}
		})
	}
}

// TestHTTPInitialize_AcceptsValidResponse confirms the hardening does not
// reject a well-formed initialize response.
func TestHTTPInitialize_AcceptsValidResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Mcp-Session-Id", "real-session")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"mock","version":"1"}}}`)
	}))
	defer srv.Close()

	h := &httpConn{base: srv.URL, route: "main", client: srv.Client()}
	if err := h.initialize(); err != nil {
		t.Fatalf("initialize rejected a valid response: %v", err)
	}
}

// TestHTTPInitialize_RejectsRejectedNotification verifies that a gateway which
// answers the initialize request validly (200 + result + session) but then
// rejects the notifications/initialized POST with a non-2xx status fails
// initialization, instead of being treated as a completed handshake.
func TestHTTPInitialize_RejectsRejectedNotification(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte("notifications/initialized")) {
			// Reject the notification with a plain-text 500.
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "internal error")
			return
		}
		w.Header().Set("Mcp-Session-Id", "real-session")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"mock","version":"1"}}}`)
	}))
	defer srv.Close()

	h := &httpConn{base: srv.URL, route: "main", client: srv.Client()}
	if err := h.initialize(); err == nil {
		t.Fatal("initialize must fail when notifications/initialized is rejected with a non-2xx status")
	}
}

// TestHTTPPost_StrictJSONOnlyFor2xx pins the hardening to success
// responses: a 2xx body that is not valid JSON-RPC is an error (transport-framing
// regression), but a non-2xx response (e.g. a 404 with a plain-text "unknown
// upstream route" body) must NOT error — the caller inspects the status code.
func TestHTTPPost_StrictJSONOnlyFor2xx(t *testing.T) {
	t.Run("404 plain-text body does not error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, "unknown upstream route\n")
		}))
		defer srv.Close()
		h := &httpConn{base: srv.URL, route: "bogus", client: srv.Client()}
		_, code, err := h.post(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
		if err != nil {
			t.Fatalf("non-2xx plain-text body must not error, got %v", err)
		}
		if code != http.StatusNotFound {
			t.Fatalf("code = %d, want 404", code)
		}
	})

	t.Run("2xx malformed body errors", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "not-json")
		}))
		defer srv.Close()
		h := &httpConn{base: srv.URL, route: "main", client: srv.Client()}
		if _, _, err := h.post(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); err == nil {
			t.Fatal("a 2xx response with a malformed JSON body must error")
		}
	})
}

// TestHTTPCall_RejectsBadEnvelope verifies call() validates the response envelope:
// a wrong-id reply (the first call's id is 1), a version-less reply, or one carrying
// neither or both of result/error must surface a framing error instead of being
// accepted whenever its result/error happens to match the expected outcome.
func TestHTTPCall_RejectsBadEnvelope(t *testing.T) {
	cases := []struct {
		name string
		resp string
	}{
		{"wrong id accepted", `{"jsonrpc":"2.0","id":999,"result":{"content":[{"type":"text","text":"wrong id accepted"}]}}`},
		{"missing jsonrpc version", `{"id":1,"result":{"content":[]}}`},
		{"both result and error", `{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"x"}}`},
		{"neither result nor error", `{"jsonrpc":"2.0","id":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, tc.resp)
			}))
			defer srv.Close()
			h := &httpConn{base: srv.URL, route: "main", client: srv.Client()}
			if _, err := h.call("tools/call", map[string]interface{}{}); err == nil {
				t.Fatalf("call accepted a bad envelope (%s)", tc.name)
			}
		})
	}
}

// TestHTTPCall_AcceptsValidEnvelope confirms the hardening does not reject a
// well-formed response whose id echoes the request's.
func TestHTTPCall_AcceptsValidEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var in rpcMsg
		_ = json.Unmarshal(body, &in)
		id := "0"
		if in.ID != nil {
			id = string(*in.ID)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+id+`,"result":{"content":[{"type":"text","text":"ok"}]}}`)
	}))
	defer srv.Close()
	h := &httpConn{base: srv.URL, route: "main", client: srv.Client()}
	if _, err := h.call("tools/call", map[string]interface{}{}); err != nil {
		t.Fatalf("call rejected a valid echoed-id response: %v", err)
	}
}

// TestHTTPCall_RejectsNon2xx confirms call() surfaces a non-2xx response as a
// framing error even when the body is a well-formed, matching-id JSON-RPC result:
// post() returns no error for a non-2xx (the caller inspects the status), so
// validateRPCEnvelope's status check is the only thing that catches it.
func TestHTTPCall_RejectsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		// id 1 matches the first call's id and the envelope is otherwise valid, so
		// only the 500 status distinguishes this from an acceptable response.
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)
	}))
	defer srv.Close()
	h := &httpConn{base: srv.URL, route: "main", client: srv.Client()}
	if _, err := h.call("tools/call", map[string]interface{}{}); err == nil {
		t.Fatal("call accepted a non-2xx response carrying a result-shaped body")
	}
}

// TestHTTPCall_PostError covers the h.post error path inside call() (2xx + non-JSON body).
func TestHTTPCall_PostError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "not-valid-json")
	}))
	defer srv.Close()
	h := &httpConn{base: srv.URL, route: "main", client: srv.Client()}
	if _, err := h.call("tools/call", nil); err == nil {
		t.Error("expected error from post returning 2xx non-JSON")
	}
}

// TestHTTPPost_NewRequestError covers the http.NewRequest error path in post().
func TestHTTPPost_NewRequestError(t *testing.T) {
	h := &httpConn{base: "://not-a-url", route: "main", client: &http.Client{}}
	if _, _, err := h.post(`{}`); err == nil {
		t.Error("expected error from invalid base URL")
	}
}

// TestHTTPPost_ClientDoError covers the client.Do error path in post().
func TestHTTPPost_ClientDoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	addr := srv.Listener.Addr().String()
	srv.Close()
	h := &httpConn{base: "http://" + addr, route: "main", client: &http.Client{Timeout: time.Second}}
	if _, _, err := h.post(`{"jsonrpc":"2.0","id":1,"method":"ping"}`); err == nil {
		t.Error("expected connection-refused error")
	}
}

// TestHTTPInitialize_NoSession covers the session-empty branch in initialize()
// (envelope is valid but server did not set Mcp-Session-Id).
func TestHTTPInitialize_NoSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"f","version":"1"}}}`)
	}))
	defer srv.Close()
	h := &httpConn{base: srv.URL, route: "main", client: srv.Client()}
	if err := h.initialize(); err == nil {
		t.Fatal("initialize must fail when server omits Mcp-Session-Id")
	}
}

// TestHTTPInitialize_NotificationPostError covers the error path for the
// notifications/initialized POST when the server returns 200 + non-JSON body.
func TestHTTPInitialize_NotificationPostError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte("notifications/initialized")) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "not-json")
			return
		}
		w.Header().Set("Mcp-Session-Id", "sess-err")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"f","version":"1"}}}`)
	}))
	defer srv.Close()
	h := &httpConn{base: srv.URL, route: "main", client: srv.Client()}
	if err := h.initialize(); err == nil {
		t.Fatal("initialize must fail when notifications/initialized response is 200 non-JSON")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Simple helper coverage
// ─────────────────────────────────────────────────────────────────────────────

// TestSimpleHelpers covers toolCall, idStr, truncateBody, newHTTPConn, and the
// nil branch of structuredContent.
func TestSimpleHelpers(t *testing.T) {
	method, params := toolCall("read_file", map[string]interface{}{"path": "/x"})
	if method != "tools/call" {
		t.Errorf("toolCall method = %q, want %q", method, "tools/call")
	}
	if params == nil {
		t.Error("toolCall params nil")
	}

	if got := idStr(nil); got != "<nil>" {
		t.Errorf("idStr(nil) = %q, want \"<nil>\"", got)
	}
	raw := json.RawMessage(`"abc-123"`)
	if got := idStr(&raw); got != `"abc-123"` {
		t.Errorf("idStr = %q, want %q", got, `"abc-123"`)
	}

	long := bytes.Repeat([]byte("x"), 300)
	if got := truncateBody(long); !strings.HasSuffix(got, "...(truncated)") {
		t.Errorf("truncateBody did not truncate: %s", got[:20])
	}

	h := newHTTPConn("http://localhost:9999", "main")
	if h == nil || h.client == nil {
		t.Error("newHTTPConn returned nil or nil client")
	}

	// structuredContent nil branch: result has no structuredContent field.
	m := msgWithResult(`{"content":[{"type":"text","text":"x"}]}`)
	if sc := structuredContent(m); len(sc) != 0 {
		t.Errorf("structuredContent without field: want empty map, got %v", sc)
	}
}

// TestExpectHelpers_MissingBranches covers assertion helper branches not
// exercised by the existing TestExpectHelpers test.
func TestExpectHelpers_MissingBranches(t *testing.T) {
	// expectAllow: m.Result == nil and m.Error == nil.
	s := &suite{}
	s.expectAllow("no-result-no-error", rpcMsg{JSONRPC: "2.0"}, nil)
	if s.fail != 1 {
		t.Errorf("expectAllow no-result: want 1 fail, got %d", s.fail)
	}

	// expectDeny: transport error.
	s2 := &suite{}
	s2.expectDeny("transport-err", "AUTHORIZATION_FAILED", "", rpcMsg{}, fmt.Errorf("boom"))
	if s2.fail != 1 {
		t.Errorf("expectDeny transport-err: want 1 fail, got %d", s2.fail)
	}

	// expectDeny: got ALLOW (no error field).
	s3 := &suite{}
	s3.expectDeny("got-allow", "AUTHORIZATION_FAILED", "", msgWithResult(`{}`), nil)
	if s3.fail != 1 {
		t.Errorf("expectDeny got-allow: want 1 fail, got %d", s3.fail)
	}

	// expectDeny: wrong condition type.
	deny := rpcMsg{Error: &rpcError{
		Code:    -32003,
		Message: "CONDITION_FAILED",
		Data:    json.RawMessage(`{"code":"CONDITION_FAILED","type":"allowedValues"}`),
	}}
	s4 := &suite{}
	s4.expectDeny("wrong-type", "CONDITION_FAILED", "maxCalls", deny, nil)
	if s4.fail != 1 {
		t.Errorf("expectDeny wrong-type: want 1 fail, got %d", s4.fail)
	}

	// expectErrorCode: transport error.
	s5 := &suite{}
	s5.expectErrorCode("transport-err", -32603, rpcMsg{}, fmt.Errorf("boom"))
	if s5.fail != 1 {
		t.Errorf("expectErrorCode transport-err: want 1 fail, got %d", s5.fail)
	}

	// expectErrorCode: got ALLOW (no error field).
	s6 := &suite{}
	s6.expectErrorCode("got-allow", -32603, msgWithResult(`{}`), nil)
	if s6.fail != 1 {
		t.Errorf("expectErrorCode got-allow: want 1 fail, got %d", s6.fail)
	}

	// expectErrorCode: wrong numeric code.
	s7 := &suite{}
	s7.expectErrorCode("wrong-code", -32603, rpcMsg{Error: &rpcError{Code: -32001, Message: "x"}}, nil)
	if s7.fail != 1 {
		t.Errorf("expectErrorCode wrong-code: want 1 fail, got %d", s7.fail)
	}
}

// TestReadControlToken covers all three branches of readControlToken.
func TestReadControlToken(t *testing.T) {
	orig := httpControlTokenPath
	defer func() { httpControlTokenPath = orig }()

	httpControlTokenPath = ""
	if got := readControlToken(); got != "" {
		t.Errorf("empty path: got %q, want empty", got)
	}

	dir := t.TempDir()
	f := filepath.Join(dir, "token")
	_ = os.WriteFile(f, []byte("my-secret-tok\n"), 0o600)
	httpControlTokenPath = f
	if got := readControlToken(); got != "my-secret-tok" {
		t.Errorf("with file: got %q, want %q", got, "my-secret-tok")
	}

	httpControlTokenPath = filepath.Join(dir, "nonexistent")
	if got := readControlToken(); got != "" {
		t.Errorf("missing file: got %q, want empty", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// checkRedaction
// ─────────────────────────────────────────────────────────────────────────────

func TestCheckRedaction(t *testing.T) {
	// Pass: all fields correctly redacted, non-sensitive fields preserved.
	body := map[string]interface{}{
		"name":   "Alice",
		"email":  "alice@example.com",
		"ssn":    "[redacted]",
		"nested": map[string]interface{}{"token": "[redacted]", "keep": "yes"},
	}
	bodyJSON, _ := json.Marshal(body)
	result := map[string]interface{}{
		"content":           []interface{}{map[string]interface{}{"type": "text", "text": string(bodyJSON)}},
		"structuredContent": map[string]interface{}{"public": "ok", "api_key": "[redacted]"},
	}
	resultJSON, _ := json.Marshal(result)
	m := rpcMsg{JSONRPC: "2.0", Result: json.RawMessage(resultJSON)}
	s := &suite{}
	checkRedaction(s, m, nil)
	if s.fail != 0 || s.pass != 1 {
		t.Errorf("pass case: want 0 fail/1 pass, got %d/%d", s.fail, s.pass)
	}

	// Error: transport error path.
	s2 := &suite{}
	checkRedaction(s2, rpcMsg{}, fmt.Errorf("transport error"))
	if s2.fail != 1 {
		t.Errorf("error case: want 1 fail, got %d", s2.fail)
	}

	// Fail: secrets not redacted — exercises all problem-detection branches.
	leaky := map[string]interface{}{
		"name":   "Bob",
		"email":  "b@b.com",
		"ssn":    "123-45-6789",
		"nested": map[string]interface{}{"token": "tok_abc123", "keep": "yes"},
	}
	leakyJSON, _ := json.Marshal(leaky)
	leakyResult := map[string]interface{}{
		"content":           []interface{}{map[string]interface{}{"type": "text", "text": string(leakyJSON)}},
		"structuredContent": map[string]interface{}{"public": "ok", "api_key": "sk-live-9999"},
	}
	leakyResultJSON, _ := json.Marshal(leakyResult)
	m3 := rpcMsg{JSONRPC: "2.0", Result: json.RawMessage(leakyResultJSON)}
	s3 := &suite{}
	checkRedaction(s3, m3, nil)
	if s3.fail != 1 {
		t.Errorf("leaky case: want 1 fail, got %d", s3.fail)
	}

	// Missing metadata: covers !has(body,"name"), !has(nested,"keep"), !has(sc,"public").
	noMeta := rpcMsg{JSONRPC: "2.0", Result: json.RawMessage(`{"content":[{"type":"text","text":"{}"}],"structuredContent":{}}`)}
	s4 := &suite{}
	checkRedaction(s4, noMeta, nil)
	if s4.fail != 1 {
		t.Errorf("no-meta case: want 1 fail, got %d", s4.fail)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// stdio connection via in-process pipes
// ─────────────────────────────────────────────────────────────────────────────

// newPipeConn creates a stdioConn backed by io.Pipe pairs and starts its
// readLoop. serverFunc runs in its own goroutine and must close srvWrite when
// done. The returned cleanup func closes the client-write pipe.
func newPipeConn(serverFunc func(srvRead io.Reader, srvWrite io.WriteCloser)) (c *stdioConn, cleanup func()) {
	srvRead, cliWrite := io.Pipe()
	cliRead, srvWrite := io.Pipe()
	c = &stdioConn{stdin: cliWrite, resp: make(chan rpcMsg, 64), nextID: 0}
	go c.readLoop(cliRead)
	go serverFunc(srvRead, srvWrite)
	return c, func() { _ = cliWrite.Close() }
}

// TestStdioConn_CallAndInitialize covers writeRaw, call, callRawID, and the
// stdio initialize method using an in-process echo server.
func TestStdioConn_CallAndInitialize(t *testing.T) {
	c, cleanup := newPipeConn(func(srvRead io.Reader, srvWrite io.WriteCloser) {
		defer srvWrite.Close()
		sc := bufio.NewScanner(srvRead)
		sc.Buffer(make([]byte, 1<<20), 8<<20)
		for sc.Scan() {
			var req rpcMsg
			if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
				continue
			}
			if req.ID == nil {
				continue // notification
			}
			var result json.RawMessage
			if req.Method == "initialize" {
				result = json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"test","version":"1"}}`)
			} else {
				result = json.RawMessage(`{"ok":true}`)
			}
			resp := rpcMsg{JSONRPC: "2.0", ID: req.ID, Result: result}
			data, _ := json.Marshal(resp)
			_, _ = srvWrite.Write(append(data, '\n'))
		}
	})
	defer cleanup()

	m, err := c.call("ping", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if m.Result == nil {
		t.Error("call: want result, got nil")
	}

	m, err = c.callRawID(`"my-id"`, "ping", nil)
	if err != nil {
		t.Fatalf("callRawID: %v", err)
	}
	if m.ID == nil || string(*m.ID) != `"my-id"` {
		t.Errorf("callRawID id = %v, want %q", m.ID, `"my-id"`)
	}

	if err := c.initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
}

// TestStdioConn_AnswerServerRequest covers readLoop's server-request dispatch
// and answerServerRequest: the fake server emits a sampling/createMessage and
// we verify that the client automatically replies.
func TestStdioConn_AnswerServerRequest(t *testing.T) {
	sampReplied := make(chan struct{}, 1)
	_, cleanup := newPipeConn(func(srvRead io.Reader, srvWrite io.WriteCloser) {
		defer srvWrite.Close()
		sc := bufio.NewScanner(srvRead)
		sc.Buffer(make([]byte, 1<<20), 8<<20)

		// Emit a server-initiated sampling/createMessage.
		sampID := json.RawMessage(`999`)
		sampReq := rpcMsg{
			JSONRPC: "2.0",
			ID:      &sampID,
			Method:  "sampling/createMessage",
			Params:  json.RawMessage(`{"messages":[],"maxTokens":1}`),
		}
		data, _ := json.Marshal(sampReq)
		_, _ = srvWrite.Write(append(data, '\n'))

		// Read the client's reply (written by answerServerRequest).
		if sc.Scan() {
			var reply rpcMsg
			if err := json.Unmarshal(sc.Bytes(), &reply); err == nil && reply.Result != nil {
				sampReplied <- struct{}{}
			}
		}
	})
	defer cleanup()

	select {
	case <-sampReplied:
	case <-time.After(5 * time.Second):
		t.Error("timeout: answerServerRequest did not reply to sampling/createMessage")
	}
}

// TestNewStdioConn_StartError covers the cmd.Start() error path in newStdioConn.
func TestNewStdioConn_StartError(t *testing.T) {
	if _, err := newStdioConn("/nonexistent/binary/path", ""); err == nil {
		t.Error("expected error for nonexistent binary")
	}
}

// TestNewStdioConn_And_Close covers the happy path of newStdioConn and close.
func TestNewStdioConn_And_Close(t *testing.T) {
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Skip("cat not found in PATH")
	}
	c, err := newStdioConn(cat, "")
	if err != nil {
		t.Fatalf("newStdioConn: %v", err)
	}
	// Drain resp so readLoop goroutine doesn't block forever.
	go func() {
		for range c.resp {
		}
	}()
	c.close()
}

// ─────────────────────────────────────────────────────────────────────────────
// Full stdio suites via in-process fake MCP server
// ─────────────────────────────────────────────────────────────────────────────

// fullFakeStdioServer is a goroutine-based fake MCP server for TestRunStdioFull.
// It implements all the policy behaviours expected by runStdioFull so that most
// of the assertion helpers record PASS rather than FAIL, while ensuring every
// source line in runStdioFull (and checkRedaction) is executed.
func fullFakeStdioServer(t *testing.T, srvRead io.Reader, srvWrite io.WriteCloser) {
	t.Helper()
	defer srvWrite.Close()

	sc := bufio.NewScanner(srvRead)
	sc.Buffer(make([]byte, 4<<20), 32<<20)

	writeResp := func(m rpcMsg) {
		data, _ := json.Marshal(m)
		_, _ = srvWrite.Write(append(data, '\n'))
	}
	allow := func(req rpcMsg, result interface{}) {
		data, _ := json.Marshal(result)
		writeResp(rpcMsg{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(data)})
	}
	deny := func(req rpcMsg, code, condType string) {
		d := fmt.Sprintf(`{"code":%q}`, code)
		if condType != "" {
			d = fmt.Sprintf(`{"code":%q,"type":%q}`, code, condType)
		}
		writeResp(rpcMsg{
			JSONRPC: "2.0", ID: req.ID,
			Error: &rpcError{Code: -32001, Message: code, Data: json.RawMessage(d)},
		})
	}

	rateLimitCount := 0
	credRead := false

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcMsg
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		if req.ID == nil {
			continue // notification
		}

		switch req.Method {
		case "initialize":
			allow(req, map[string]interface{}{
				"protocolVersion": "2025-11-25",
				"capabilities":    map[string]interface{}{},
				"serverInfo":      map[string]interface{}{"name": "fake", "version": "1"},
			})

		case "tools/list":
			allow(req, map[string]interface{}{
				"tools": []interface{}{
					map[string]interface{}{"name": "big_response"},
					map[string]interface{}{"name": "get_malformed"},
					map[string]interface{}{"name": "get_plaintext"},
					map[string]interface{}{"name": "get_secret_record"},
					map[string]interface{}{"name": "query_db"},
					map[string]interface{}{"name": "rate_limited"},
					map[string]interface{}{"name": "read_any_report"},
					map[string]interface{}{"name": "read_credentials"},
					map[string]interface{}{"name": "read_doc"},
					map[string]interface{}{"name": "read_file"},
					map[string]interface{}{"name": "send_email"},
					map[string]interface{}{"name": "time_gated"},
					map[string]interface{}{"name": "trigger_sampling"},
					map[string]interface{}{"name": "write_external"},
				},
			})

		case "resources/list":
			allow(req, map[string]interface{}{
				"resources": []interface{}{
					map[string]interface{}{"uri": "db://warehouse/orders"},
					map[string]interface{}{"uri": "file:///data/live/metrics"},
					map[string]interface{}{"uri": "file:///data/reports/q3.pdf"},
					map[string]interface{}{"uri": "file:///data/reports/q4.pdf"},
				},
			})

		case "prompts/list":
			allow(req, map[string]interface{}{
				"prompts": []interface{}{
					map[string]interface{}{"name": "code_review"},
					map[string]interface{}{"name": "summarize_doc"},
					map[string]interface{}{"name": "summarize_pr"},
				},
			})

		case "resources/read":
			var p struct {
				URI string `json:"uri"`
			}
			_ = json.Unmarshal(req.Params, &p)
			switch p.URI {
			case "file:///data/reports/q3.pdf", "file:///data/live/metrics":
				allow(req, map[string]interface{}{"contents": []interface{}{}})
			default:
				deny(req, "AUTHORIZATION_FAILED", "")
			}

		case "resources/subscribe":
			var p struct {
				URI string `json:"uri"`
			}
			_ = json.Unmarshal(req.Params, &p)
			if p.URI == "file:///data/live/metrics" {
				allow(req, map[string]interface{}{})
			} else {
				deny(req, "AUTHORIZATION_FAILED", "")
			}

		case "prompts/get":
			var p struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(req.Params, &p)
			switch p.Name {
			case "code_review", "summarize_doc", "summarize_pr":
				allow(req, map[string]interface{}{"messages": []interface{}{}})
			default:
				deny(req, "AUTHORIZATION_FAILED", "")
			}

		case "tools/call":
			var p struct {
				Name      string                 `json:"name"`
				Arguments map[string]interface{} `json:"arguments"`
			}
			_ = json.Unmarshal(req.Params, &p)

			switch p.Name {
			case "read_file":
				path, _ := p.Arguments["path"].(string)
				switch {
				case path == "/reports/q3.pdf":
					allow(req, map[string]interface{}{"content": []interface{}{map[string]interface{}{"type": "text", "text": "report"}}})
				case path == "/reports/2025/q4.pdf":
					deny(req, "VALUE_NOT_PERMITTED", "allowedValues")
				case path == "/etc/shadow":
					deny(req, "VALUE_NOT_PERMITTED", "allowedValues")
				case p.Arguments["path"] == nil:
					deny(req, "MISSING_CONTEXT", "allowedValues")
				default:
					if _, isNum := p.Arguments["path"].(float64); isNum {
						deny(req, "VALUE_NOT_PERMITTED", "allowedValues")
					} else {
						allow(req, map[string]interface{}{"content": []interface{}{map[string]interface{}{"type": "text", "text": "ok"}}})
					}
				}

			case "read_any_report":
				allow(req, map[string]interface{}{"content": []interface{}{map[string]interface{}{"type": "text", "text": "ok"}}})

			case "query_db":
				q, _ := p.Arguments["query"].(string)
				if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(q)), "SELECT") {
					allow(req, map[string]interface{}{"content": []interface{}{map[string]interface{}{"type": "text", "text": "rows"}}})
				} else {
					deny(req, "OPERATION_NOT_PERMITTED", "allowedOperations")
				}

			case "write_file", "secret_tool":
				deny(req, "AUTHORIZATION_FAILED", "")

			case "read_doc":
				path, _ := p.Arguments["path"].(string)
				if strings.HasSuffix(path, ".exe") {
					deny(req, "CONDITION_FAILED", "allowedExtensions")
				} else {
					allow(req, map[string]interface{}{"content": []interface{}{map[string]interface{}{"type": "text", "text": "ok"}}})
				}

			case "send_email":
				to, _ := p.Arguments["to"].(string)
				if strings.HasSuffix(to, "@example.com") {
					allow(req, map[string]interface{}{"content": []interface{}{map[string]interface{}{"type": "text", "text": "sent"}}})
				} else {
					deny(req, "CONDITION_FAILED", "recipientDomain")
				}

			case "time_gated":
				deny(req, "CONDITION_FAILED", "timeWindow")

			case "rate_limited":
				rateLimitCount++
				if rateLimitCount <= 2 {
					allow(req, map[string]interface{}{"content": []interface{}{map[string]interface{}{"type": "text", "text": "ok"}}})
				} else {
					deny(req, "RATE_LIMITED", "maxCalls")
				}

			case "read_credentials":
				credRead = true
				allow(req, map[string]interface{}{"content": []interface{}{map[string]interface{}{"type": "text", "text": "cred"}}})

			case "write_external":
				if credRead {
					deny(req, "CONDITION_FAILED", "sequenceBlock")
				} else {
					allow(req, map[string]interface{}{"content": []interface{}{map[string]interface{}{"type": "text", "text": "ok"}}})
				}

			case "get_secret_record":
				body := map[string]interface{}{
					"name":   "Alice",
					"email":  "alice@example.com",
					"ssn":    "[redacted]",
					"nested": map[string]interface{}{"token": "[redacted]", "keep": "yes"},
				}
				bodyJSON, _ := json.Marshal(body)
				allow(req, map[string]interface{}{
					"content":           []interface{}{map[string]interface{}{"type": "text", "text": string(bodyJSON)}},
					"structuredContent": map[string]interface{}{"public": "ok", "api_key": "[redacted]"},
				})

			case "get_malformed":
				allow(req, map[string]interface{}{
					"content": []interface{}{map[string]interface{}{
						"type": "text",
						"text": `{"secret":"x", "oops"`,
					}},
				})

			case "get_plaintext":
				allow(req, map[string]interface{}{
					"content": []interface{}{map[string]interface{}{
						"type": "text",
						"text": "Revenue report Q3",
					}},
				})

			case "trigger_sampling":
				// Server-initiated sampling round-trip: send sampling/createMessage
				// first, read the client's reply, then respond to the tool call.
				sampID := json.RawMessage(`9999`)
				sampReq := rpcMsg{
					JSONRPC: "2.0",
					ID:      &sampID,
					Method:  "sampling/createMessage",
					Params:  json.RawMessage(`{"messages":[],"maxTokens":1}`),
				}
				data, _ := json.Marshal(sampReq)
				_, _ = srvWrite.Write(append(data, '\n'))
				// Consume the client's sampling reply, verifying it actually is
				// the reply (not some other in-flight request line) rather than
				// blindly discarding whatever line arrives next.
				if !sc.Scan() {
					t.Errorf("trigger_sampling: client closed before replying to the sampling request")
				} else {
					var reply rpcMsg
					if err := json.Unmarshal(sc.Bytes(), &reply); err != nil || reply.ID == nil || string(*reply.ID) != string(sampID) {
						t.Errorf("trigger_sampling: expected the client's reply to sampling id %s, got %q", sampID, sc.Bytes())
					}
				}
				allow(req, map[string]interface{}{
					"content": []interface{}{map[string]interface{}{"type": "text", "text": "sampling:allowed"}},
				})

			case "big_response":
				big := strings.Repeat("A", 2*1024*1024)
				allow(req, map[string]interface{}{
					"content": []interface{}{map[string]interface{}{"type": "text", "text": big}},
				})

			default:
				deny(req, "AUTHORIZATION_FAILED", "")
			}

		default:
			deny(req, "AUTHORIZATION_FAILED", "")
		}
	}
}

// TestRunStdioFull_FakeServer exercises every statement in runStdioFull
// (and checkRedaction) against an in-process fake MCP server.
func TestRunStdioFull_FakeServer(t *testing.T) {
	c, cleanup := newPipeConn(func(r io.Reader, w io.WriteCloser) {
		fullFakeStdioServer(t, r, w)
	})
	defer cleanup()

	if err := c.initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	s := &suite{}
	runStdioFull(c, s)
	_ = s.fail // fake server responses may not match policy assertions
}

// TestRunStdioSamplingDeny_FakeServer covers runStdioSamplingDeny.
func TestRunStdioSamplingDeny_FakeServer(t *testing.T) {
	c, cleanup := newPipeConn(func(srvRead io.Reader, srvWrite io.WriteCloser) {
		defer srvWrite.Close()
		sc := bufio.NewScanner(srvRead)
		sc.Buffer(make([]byte, 1<<20), 8<<20)
		for sc.Scan() {
			var req rpcMsg
			if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
				continue
			}
			if req.ID == nil {
				continue
			}
			result := json.RawMessage(`{"content":[{"type":"text","text":"sampling:denied"}]}`)
			resp := rpcMsg{JSONRPC: "2.0", ID: req.ID, Result: result}
			data, _ := json.Marshal(resp)
			_, _ = srvWrite.Write(append(data, '\n'))
		}
	})
	defer cleanup()

	if err := c.initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	s := &suite{}
	runStdioSamplingDeny(c, s)
	_ = s.fail
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP suite via in-process fake gateway
// ─────────────────────────────────────────────────────────────────────────────

// fakeGateway is a minimal in-process MCP HTTP gateway for HTTP transport tests.
type fakeGateway struct {
	mu       sync.Mutex
	sessions map[string]string // sessionID → route
	credRead map[string]bool   // sessionID → read_credentials called
	killed   map[string]bool   // sessionID → session killed
	token    string            // /control/kill bearer token
}

func newFakeGateway(token string) *fakeGateway {
	return &fakeGateway{
		sessions: map[string]string{},
		credRead: map[string]bool{},
		killed:   map[string]bool{},
		token:    token,
	}
}

func (g *fakeGateway) writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

func (g *fakeGateway) mcpDeny(req *rpcMsg, code, condType string) rpcMsg {
	d := fmt.Sprintf(`{"code":%q}`, code)
	if condType != "" {
		d = fmt.Sprintf(`{"code":%q,"type":%q}`, code, condType)
	}
	return rpcMsg{
		JSONRPC: "2.0", ID: req.ID,
		Error: &rpcError{Code: -32001, Message: code, Data: json.RawMessage(d)},
	}
}

func (g *fakeGateway) mcpAllow(req *rpcMsg, result interface{}) rpcMsg {
	data, _ := json.Marshal(result)
	return rpcMsg{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(data)}
}

func (g *fakeGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/control/kill" {
		tok := r.Header.Get("X-Eunox-Control-Token")
		if tok == "" || tok != g.token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body struct {
			SessionID string `json:"sessionId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		g.mu.Lock()
		g.killed[body.SessionID] = true
		g.mu.Unlock()
		g.writeJSON(w, map[string]interface{}{"ok": true})
		return
	}

	if !strings.HasPrefix(r.URL.Path, "/mcp/") {
		http.NotFound(w, r)
		return
	}
	route := strings.TrimPrefix(r.URL.Path, "/mcp/")
	if route == "" || route == "bogus" {
		http.NotFound(w, r)
		return
	}

	raw, _ := io.ReadAll(r.Body)
	var req rpcMsg
	if err := json.Unmarshal(raw, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if req.Method == "notifications/initialized" {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if req.Method == "initialize" {
		sessID := fmt.Sprintf("sess-%s-%d", route, time.Now().UnixNano())
		g.mu.Lock()
		g.sessions[sessID] = route
		g.mu.Unlock()
		w.Header().Set("Mcp-Session-Id", sessID)
		g.writeJSON(w, rpcMsg{
			JSONRPC: "2.0", ID: req.ID,
			Result: json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fake","version":"1"}}`),
		})
		return
	}

	sessID := r.Header.Get("Mcp-Session-Id")
	g.mu.Lock()
	_, ok := g.sessions[sessID]
	isKilled := g.killed[sessID]
	g.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var resp rpcMsg
	if isKilled {
		g.writeJSON(w, g.mcpDeny(&req, "KILL_SWITCH", ""))
		return
	}

	switch req.Method {
	case "tools/list":
		resp = g.mcpAllow(&req, map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "read_file"},
				map[string]interface{}{"name": "query_db"},
				map[string]interface{}{"name": "read_credentials"},
				map[string]interface{}{"name": "write_external"},
			},
		})

	case "resources/list":
		resp = g.mcpAllow(&req, map[string]interface{}{
			"resources": []interface{}{
				map[string]interface{}{"uri": "db://warehouse/orders"},
				map[string]interface{}{"uri": "file:///data/live/metrics"},
			},
		})

	case "tools/call":
		var p struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		_ = json.Unmarshal(req.Params, &p)

		switch p.Name {
		case "read_file":
			path, _ := p.Arguments["path"].(string)
			if path == "/etc/shadow" {
				resp = g.mcpDeny(&req, "VALUE_NOT_PERMITTED", "allowedValues")
			} else {
				resp = g.mcpAllow(&req, map[string]interface{}{"content": []interface{}{
					map[string]interface{}{"type": "text", "text": "ok"},
				}})
			}
		case "write_file":
			resp = g.mcpDeny(&req, "AUTHORIZATION_FAILED", "")
		case "query_db":
			resp = g.mcpAllow(&req, map[string]interface{}{"content": []interface{}{
				map[string]interface{}{"type": "text", "text": "rows"},
			}})
		case "read_credentials":
			g.mu.Lock()
			g.credRead[sessID] = true
			g.mu.Unlock()
			resp = g.mcpAllow(&req, map[string]interface{}{"content": []interface{}{
				map[string]interface{}{"type": "text", "text": "cred"},
			}})
		case "write_external":
			g.mu.Lock()
			armed := g.credRead[sessID]
			g.mu.Unlock()
			if armed {
				resp = g.mcpDeny(&req, "CONDITION_FAILED", "sequenceBlock")
			} else {
				resp = g.mcpAllow(&req, map[string]interface{}{"content": []interface{}{
					map[string]interface{}{"type": "text", "text": "ok"},
				}})
			}
		default:
			resp = g.mcpDeny(&req, "AUTHORIZATION_FAILED", "")
		}

	default:
		resp = g.mcpDeny(&req, "AUTHORIZATION_FAILED", "")
	}

	g.writeJSON(w, resp)
}

// TestRunHTTPSuite_FakeGateway exercises runHTTPSuite (and the sub-functions
// runHTTPSessionIsolation, runHTTPKillSwitch, httpToolCall, newHTTPConn) against
// an in-process fake gateway.
func TestRunHTTPSuite_FakeGateway(t *testing.T) {
	const controlToken = "fake-control-token-xyz"
	gw := newFakeGateway(controlToken)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	dir := t.TempDir()
	tokFile := filepath.Join(dir, "control.token")
	if err := os.WriteFile(tokFile, []byte(controlToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := httpControlTokenPath
	httpControlTokenPath = tokFile
	defer func() { httpControlTokenPath = orig }()

	s := &suite{}
	runHTTPSuite(srv.URL, s)
	_ = s.fail
}

// ─────────────────────────────────────────────────────────────────────────────
// runAuditCheck
// ─────────────────────────────────────────────────────────────────────────────

// TestRunAuditCheck_InProcess covers the happy path of runAuditCheck with a
// crafted JSONL file that satisfies all assertion predicates.
// conformingAuditFixture is a tape runAuditCheck accepts with ZERO failures: it satisfies every
// assertion that function makes.
//
// Shared with the negative tests, and that sharing is the point. A negative built from a
// partial fixture fails whether or not the property under test is checked at all — the seven
// content assertions fail on it regardless — so the test passes with the check deleted. Mutating
// a fixture that otherwise passes cleanly is what makes the failure count attributable to the
// mutation.
//
// The revisions mirror the real tape the suite produces: the interop matrix drives cells under
// both, and a pre-negotiation refusal legitimately carries none.
func conformingAuditFixture() []auditRecord {
	return []auditRecord{
		{
			Decision: "allow", Target: "get_secret_record", Method: "tools/call",
			TargetType:       "tool",
			Obligations:      []string{"redactFields:ssn", "redactFields:nested.token", "redactFields:api_key"},
			ProtocolRevision: revisionHandshake,
		},
		{Decision: "deny", DenialCode: "AUTHORIZATION_FAILED", Target: "write_file", Method: "tools/call", TargetType: "tool", ProtocolRevision: revisionHandshake},
		{Decision: "deny", DenialCode: "VALUE_NOT_PERMITTED", ConditionType: "allowedValues", Target: "read_file", Method: "tools/call", TargetType: "tool", ProtocolRevision: revisionDeclaring},
		{Decision: "deny", DenialCode: "RATE_LIMITED", Target: "rate_limited", Method: "tools/call", TargetType: "tool", ProtocolRevision: revisionDeclaring},
		{Decision: "allow", Target: "file:///data/reports/q3.pdf", Method: "resources/read", TargetType: "resource", ProtocolRevision: revisionDeclaring},
		{Decision: "allow", Target: "code_review", Method: "prompts/get", TargetType: "prompt", ProtocolRevision: revisionHandshake},
		{Decision: "allow", Method: "sampling/createMessage", TargetType: "sampling"},
	}
}

func TestRunAuditCheck_InProcess(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	recs := conformingAuditFixture()

	var buf bytes.Buffer
	for _, r := range recs {
		line, _ := json.Marshal(r)
		buf.Write(line)
		buf.WriteByte('\n')
	}
	buf.WriteByte('\n') // empty line to exercise the continue branch
	if err := os.WriteFile(logPath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &suite{}
	runAuditCheck(logPath, s)
	if s.fail != 0 {
		t.Errorf("runAuditCheck happy path: want 0 fail, got %d (pass=%d)", s.fail, s.pass)
	}
}

// writeAuditFixture writes recs as JSONL and returns the path.
func writeAuditFixture(t *testing.T, recs []auditRecord) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	var buf bytes.Buffer
	for i := range recs {
		line, err := json.Marshal(&recs[i])
		if err != nil {
			t.Fatalf("marshal record %d: %v", i, err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The protocol-revision assertion has to FAIL on the two shapes it exists to catch, or it is
// decoration: a tape covering only one revision (a matrix cell that silently did not run) and
// a record stamped with a revision nobody published.
//
// Each case MUTATES a fixture runAuditCheck otherwise accepts with zero failures, and asserts
// the failure count moves from 0 to exactly 1. Asserting only "something failed" against a
// hand-built partial tape is what this test did first, and it passed with the whole
// seenRevisions block deleted: the partial fixtures failed seven unrelated content assertions,
// so the count was non-zero either way and the property under test was never exercised.
func TestRunAuditCheck_ProtocolRevisionNegatives(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]auditRecord) []auditRecord
	}{
		{
			name: "only one revision on the tape",
			mutate: func(recs []auditRecord) []auditRecord {
				for i := range recs {
					if recs[i].ProtocolRevision == revisionDeclaring {
						recs[i].ProtocolRevision = revisionHandshake
					}
				}
				return recs
			},
		},
		{
			name: "a revision nobody published",
			mutate: func(recs []auditRecord) []auditRecord {
				recs[0].ProtocolRevision = "2099-01-01"
				return recs
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := &suite{}
			runAuditCheck(writeAuditFixture(t, conformingAuditFixture()), base)
			if base.fail != 0 {
				t.Fatalf("the shared fixture is not clean: %d failures — the differential below would be meaningless", base.fail)
			}

			got := &suite{}
			runAuditCheck(writeAuditFixture(t, tc.mutate(conformingAuditFixture())), got)
			if got.fail != 1 {
				t.Fatalf("runAuditCheck reported %d failures for %s, want exactly 1 — the only difference from the clean fixture is the revision", got.fail, tc.name)
			}
		})
	}
}

// A record with no revision is not a failure: a refusal recorded before negotiation ran has
// nothing to stamp, and the tape has to be able to say so.
//
// Asserted as a DIFFERENTIAL because suite keeps counts rather than messages — the same
// fixture with and without the unstamped record must fail identically, which isolates that
// record's contribution without depending on what else the minimal fixture fails.
func TestRunAuditCheck_AbsentProtocolRevisionIsNotAFailure(t *testing.T) {
	stamped := []auditRecord{
		{Decision: "allow", Method: "tools/call", ProtocolRevision: revisionHandshake},
		{Decision: "allow", Method: "tools/call", ProtocolRevision: revisionDeclaring},
	}
	withUnstamped := append(append([]auditRecord{}, stamped...),
		auditRecord{Decision: "deny", DenialCode: "UNSUPPORTED_PROTOCOL_VERSION", Method: "tools/call"})

	base := &suite{}
	runAuditCheck(writeAuditFixture(t, stamped), base)
	got := &suite{}
	runAuditCheck(writeAuditFixture(t, withUnstamped), got)

	if got.fail != base.fail {
		t.Fatalf("an unstamped record changed the failure count: %d -> %d", base.fail, got.fail)
	}
}

// TestRunAuditCheck_NoFile covers the os.Open error path.
func TestRunAuditCheck_NoFile(t *testing.T) {
	s := &suite{}
	runAuditCheck("/nonexistent/audit.jsonl", s)
	if s.fail != 1 {
		t.Errorf("runAuditCheck no-file: want 1 fail, got %d", s.fail)
	}
}

// TestRunAuditCheck_EmptyFile covers the len(recs)==0 path.
func TestRunAuditCheck_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "empty.jsonl")
	_ = os.WriteFile(logPath, []byte(""), 0o644)
	s := &suite{}
	runAuditCheck(logPath, s)
	if s.fail != 1 {
		t.Errorf("runAuditCheck empty: want 1 fail, got %d", s.fail)
	}
}

// TestRunAuditCheck_BadJSON covers the json.Unmarshal error path.
func TestRunAuditCheck_BadJSON(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "bad.jsonl")
	_ = os.WriteFile(logPath, []byte("not-json\n"), 0o644)
	s := &suite{}
	runAuditCheck(logPath, s)
	if s.fail != 1 {
		t.Errorf("runAuditCheck bad-json: want 1 fail, got %d", s.fail)
	}
}

// TestRunAuditCheck_BadDecision covers the unknown-decision path.
func TestRunAuditCheck_BadDecision(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "bad.jsonl")
	_ = os.WriteFile(logPath, []byte(`{"decision":"unknown"}`+"\n"), 0o644)
	s := &suite{}
	runAuditCheck(logPath, s)
	if s.fail != 1 {
		t.Errorf("runAuditCheck bad-decision: want 1 fail, got %d", s.fail)
	}
}

// TestRunAuditCheck_MissingRecord covers the "no matching audit record" path by
// providing a log that satisfies some but not all assertion predicates.
func TestRunAuditCheck_MissingRecord(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "partial.jsonl")
	_ = os.WriteFile(logPath, []byte(`{"decision":"allow","target":"x","method":"tools/call"}`+"\n"), 0o644)
	s := &suite{}
	runAuditCheck(logPath, s)
	if s.fail == 0 {
		t.Error("runAuditCheck partial records: want at least 1 fail for missing predicates")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// readLoop and answerServerRequest branch coverage
// ─────────────────────────────────────────────────────────────────────────────

// TestStdioConn_ReadLoopContinuePaths covers the two continue statements inside
// readLoop: the empty-line guard and the bad-JSON guard.
func TestStdioConn_ReadLoopContinuePaths(t *testing.T) {
	c, cleanup := newPipeConn(func(srvRead io.Reader, srvWrite io.WriteCloser) {
		defer srvWrite.Close()
		sc := bufio.NewScanner(srvRead)
		sc.Buffer(make([]byte, 1<<20), 8<<20)
		for sc.Scan() {
			var req rpcMsg
			if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
				continue
			}
			if req.ID == nil {
				continue
			}
			// Send noise before the real response: empty line and invalid JSON.
			_, _ = srvWrite.Write([]byte("\n"))
			_, _ = srvWrite.Write([]byte("not-valid-json\n"))
			resp := rpcMsg{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(`{}`)}
			data, _ := json.Marshal(resp)
			_, _ = srvWrite.Write(append(data, '\n'))
		}
	})
	defer cleanup()

	if _, err := c.call("ping", nil); err != nil {
		t.Errorf("call after noise lines: %v", err)
	}
}

// TestStdioConn_AnswerNonSamplingRequest covers the early return in
// answerServerRequest when the incoming method is not "sampling/createMessage".
func TestStdioConn_AnswerNonSamplingRequest(t *testing.T) {
	c, cleanup := newPipeConn(func(srvRead io.Reader, srvWrite io.WriteCloser) {
		defer srvWrite.Close()
		sc := bufio.NewScanner(srvRead)
		sc.Buffer(make([]byte, 1<<20), 8<<20)
		// Push a server-initiated request with an unexpected method first.
		bogusID := json.RawMessage(`777`)
		bogus := rpcMsg{JSONRPC: "2.0", ID: &bogusID, Method: "foo/bar"}
		data, _ := json.Marshal(bogus)
		_, _ = srvWrite.Write(append(data, '\n'))
		// Then answer the client's real call.
		for sc.Scan() {
			var req rpcMsg
			if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
				continue
			}
			if req.ID == nil {
				continue
			}
			resp := rpcMsg{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(`{}`)}
			out, _ := json.Marshal(resp)
			_, _ = srvWrite.Write(append(out, '\n'))
		}
	})
	defer cleanup()

	if _, err := c.call("ping", nil); err != nil {
		t.Errorf("call after non-sampling server request: %v", err)
	}
}

// TestStdioConn_ClosedDuringCall covers the closed-channel paths in call(),
// callRawID(), and initialize(): when the server closes its write pipe the
// readLoop sees EOF and closes c.resp, causing all pending calls to return a
// "proxy closed connection" error immediately.
func TestStdioConn_ClosedDuringCall(t *testing.T) {
	c, cleanup := newPipeConn(func(srvRead io.Reader, srvWrite io.WriteCloser) {
		// Drain client writes so c.writeRaw does not block.
		go func() { _, _ = io.Copy(io.Discard, srvRead) }()
		// Close immediately: readLoop sees EOF and closes c.resp.
		srvWrite.Close()
	})
	defer cleanup()

	if _, err := c.call("ping", nil); err == nil {
		t.Error("call: want error after server close, got nil")
	}
	if _, err := c.callRawID("1", "ping", nil); err == nil {
		t.Error("callRawID: want error after server close, got nil")
	}
	if err := c.initialize(); err == nil {
		t.Error("initialize: want error after server close, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// runStdioFull bad-response branches
// ─────────────────────────────────────────────────────────────────────────────

// TestRunStdioFull_AllBadBranches uses a server that returns wrong or absent
// content so every s.bad branch inside runStdioFull is executed:
//   - get_malformed / get_plaintext text checks
//   - tools/list, resources/list, prompts/list filtering checks
//   - id-preservation (string and numeric) checks
//   - sampling-allow check
//   - big_response length check
func TestRunStdioFull_AllBadBranches(t *testing.T) {
	c, cleanup := newPipeConn(func(srvRead io.Reader, srvWrite io.WriteCloser) {
		defer srvWrite.Close()
		sc := bufio.NewScanner(srvRead)
		sc.Buffer(make([]byte, 4<<20), 32<<20)

		writeResp := func(m rpcMsg) {
			data, _ := json.Marshal(m)
			_, _ = srvWrite.Write(append(data, '\n'))
		}
		denyResp := func(req rpcMsg) {
			d := json.RawMessage(`{"code":"AUTHORIZATION_FAILED"}`)
			writeResp(rpcMsg{
				JSONRPC: "2.0", ID: req.ID,
				Error: &rpcError{Code: -32001, Message: "denied", Data: d},
			})
		}

		seenLists := 0
		for sc.Scan() {
			var req rpcMsg
			if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
				continue
			}
			if req.ID == nil {
				continue // notification
			}

			switch req.Method {
			case "initialize":
				r := json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"bad","version":"1"}}`)
				writeResp(rpcMsg{JSONRPC: "2.0", ID: req.ID, Result: r})

			case "tools/list":
				// Return wrong (empty) list → s.bad tools/list filtering.
				writeResp(rpcMsg{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(`{"tools":[]}`)})
				seenLists++

			case "resources/list":
				// Return wrong (empty) list → s.bad resources/list filtering.
				writeResp(rpcMsg{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(`{"resources":[]}`)})
				seenLists++

			case "prompts/list":
				// Return wrong (empty) list → s.bad prompts/list filtering.
				writeResp(rpcMsg{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(`{"prompts":[]}`)})
				seenLists++
				if seenLists >= 3 {
					// Drain remaining client writes so c.writeRaw doesn't block,
					// then close: readLoop sees EOF → close(c.resp) → all
					// subsequent call/callRawID return "proxy closed connection".
					go func() { _, _ = io.Copy(io.Discard, srvRead) }()
					return
				}

			case "tools/call":
				var p struct {
					Name string `json:"name"`
				}
				_ = json.Unmarshal(req.Params, &p)
				switch p.Name {
				case "get_malformed":
					// No "secret" in text → s.bad get_malformed.
					writeResp(rpcMsg{JSONRPC: "2.0", ID: req.ID,
						Result: json.RawMessage(`{"content":[{"type":"text","text":"no-match"}]}`)})
				case "get_plaintext":
					// No "Revenue" in text → s.bad get_plaintext.
					writeResp(rpcMsg{JSONRPC: "2.0", ID: req.ID,
						Result: json.RawMessage(`{"content":[{"type":"text","text":"no-match"}]}`)})
				default:
					denyResp(req)
				}

			default:
				denyResp(req)
			}
		}
	})
	defer cleanup()

	if err := c.initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	s := &suite{}
	runStdioFull(c, s)
	_ = s.fail // failures expected; coverage is the goal
}

// TestRunStdioSamplingDeny_WrongText covers the s.bad branch inside
// runStdioSamplingDeny when the tool call succeeds but the text is not
// "sampling:denied".
func TestRunStdioSamplingDeny_WrongText(t *testing.T) {
	c, cleanup := newPipeConn(func(srvRead io.Reader, srvWrite io.WriteCloser) {
		defer srvWrite.Close()
		sc := bufio.NewScanner(srvRead)
		sc.Buffer(make([]byte, 1<<20), 8<<20)
		for sc.Scan() {
			var req rpcMsg
			if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
				continue
			}
			if req.ID == nil {
				continue
			}
			// Wrong text — not "sampling:denied" → s.bad in runStdioSamplingDeny.
			result := json.RawMessage(`{"content":[{"type":"text","text":"unexpected"}]}`)
			resp := rpcMsg{JSONRPC: "2.0", ID: req.ID, Result: result}
			data, _ := json.Marshal(resp)
			_, _ = srvWrite.Write(append(data, '\n'))
		}
	})
	defer cleanup()

	if err := c.initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	s := &suite{}
	runStdioSamplingDeny(c, s)
	if s.fail != 1 {
		t.Errorf("want 1 fail for wrong sampling-deny response, got %d", s.fail)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP suite error-branch coverage
// ─────────────────────────────────────────────────────────────────────────────

// alwaysFailHandler returns a minimal HTTP handler that rejects every request
// with 500, causing any httpConn.initialize() call to fail.
func alwaysFailHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
}

// okInitHandler builds a handler that responds to initialize + notifications,
// then applies extraHandler for everything else.
func okInitHandler(extraHandler http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req rpcMsg
		_ = json.Unmarshal(body, &req)
		if req.Method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if req.Method == "initialize" {
			sessID := fmt.Sprintf("sess-%d", time.Now().UnixNano())
			w.Header().Set("Mcp-Session-Id", sessID)
			w.Header().Set("Content-Type", "application/json")
			result := json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fake","version":"1"}}`)
			resp := rpcMsg{JSONRPC: "2.0", ID: req.ID, Result: result}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		if extraHandler != nil {
			extraHandler(w, r)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
}

// TestRunHTTPSuite_InitFails covers the s.bad("http initialize /mcp/main") +
// return branch in runHTTPSuite when the gateway rejects the initial handshake.
func TestRunHTTPSuite_InitFails(t *testing.T) {
	srv := httptest.NewServer(alwaysFailHandler())
	defer srv.Close()
	s := &suite{}
	runHTTPSuite(srv.URL, s)
	if s.fail == 0 {
		t.Error("want at least 1 fail when init rejected, got 0")
	}
}

// TestRunHTTPSessionIsolation_AInitFails covers the s.bad("http session A init")
// + return branch when session A's initialize fails.
func TestRunHTTPSessionIsolation_AInitFails(t *testing.T) {
	srv := httptest.NewServer(alwaysFailHandler())
	defer srv.Close()
	s := &suite{}
	runHTTPSessionIsolation(srv.URL, s)
	if s.fail == 0 {
		t.Error("want fail for session A init failure, got 0")
	}
}

// TestRunHTTPSessionIsolation_BInitFails covers the s.bad("http session B init")
// + return branch: session A succeeds but session B's initialize is rejected.
func TestRunHTTPSessionIsolation_BInitFails(t *testing.T) {
	var mu sync.Mutex
	initCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req rpcMsg
		_ = json.Unmarshal(body, &req)
		if req.Method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if req.Method != "initialize" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		n := initCount
		initCount++
		mu.Unlock()
		if n == 0 {
			sessID := fmt.Sprintf("sess-%d", n)
			w.Header().Set("Mcp-Session-Id", sessID)
			w.Header().Set("Content-Type", "application/json")
			result := json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fake","version":"1"}}`)
			resp := rpcMsg{JSONRPC: "2.0", ID: req.ID, Result: result}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	s := &suite{}
	runHTTPSessionIsolation(srv.URL, s)
	if s.fail == 0 {
		t.Error("want fail for session B init failure, got 0")
	}
}

// TestRunHTTPSessionIsolation_ReadCredsFails covers the s.bad("http session A
// read_credentials") + return branch: both inits succeed but the tools/call
// request fails.
func TestRunHTTPSessionIsolation_ReadCredsFails(t *testing.T) {
	srv := httptest.NewServer(okInitHandler(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	s := &suite{}
	runHTTPSessionIsolation(srv.URL, s)
	if s.fail == 0 {
		t.Error("want fail for read_credentials failure, got 0")
	}
}

// TestRunHTTPKillSwitch_InitFails covers the s.bad("http kill-switch session
// init") + return branch when the session cannot be established.
func TestRunHTTPKillSwitch_InitFails(t *testing.T) {
	srv := httptest.NewServer(alwaysFailHandler())
	defer srv.Close()
	s := &suite{}
	runHTTPKillSwitch(srv.URL, s)
	if s.fail == 0 {
		t.Error("want fail for kill-switch init failure, got 0")
	}
}
