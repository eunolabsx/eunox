// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// captureHandle redirects os.Stdout, calls handle(msg), then returns whatever
// was written as a decoded rpcMsg.
func captureHandle(t *testing.T, msg rpcMsg) rpcMsg { //nolint:gocritic
	t.Helper()

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	handle(msg)

	w.Close()
	os.Stdout = origStdout

	data, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatalf("reading captured output: %v", err)
	}

	line := strings.TrimRight(string(data), "\n")
	var out rpcMsg
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		t.Fatalf("decoding handle output: %v\nraw: %s", err, line)
	}
	return out
}

// rawID wraps an integer as a *json.RawMessage suitable for rpcMsg.ID.
func rawID(v int) *json.RawMessage {
	b, _ := json.Marshal(v)
	r := json.RawMessage(b)
	return &r
}

// ---- rpcMsg helper methods ----

func TestIsRequest(t *testing.T) {
	id := rawID(1)
	cases := []struct {
		msg  rpcMsg
		want bool
	}{
		{rpcMsg{ID: id, Method: "foo"}, true},
		{rpcMsg{ID: nil, Method: "foo"}, false}, // notification
		{rpcMsg{ID: id, Method: ""}, false},     // response
		{rpcMsg{}, false},
	}
	for _, tc := range cases {
		if got := tc.msg.isRequest(); got != tc.want {
			t.Errorf("isRequest(%+v) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}

func TestIsNotification(t *testing.T) {
	id := rawID(1)
	cases := []struct {
		msg  rpcMsg
		want bool
	}{
		{rpcMsg{ID: nil, Method: "foo"}, true},
		{rpcMsg{ID: id, Method: "foo"}, false},
		{rpcMsg{ID: nil, Method: ""}, false},
	}
	for _, tc := range cases {
		if got := tc.msg.isNotification(); got != tc.want {
			t.Errorf("isNotification(%+v) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}

// ---- dispatchTool ----

func TestDispatchTool(t *testing.T) {
	cases := []struct {
		name string
		args map[string]interface{}
		want string
	}{
		{"read_file", map[string]interface{}{"path": "/data/q3.pdf"}, "/data/q3.pdf"},
		{"write_file", map[string]interface{}{"path": "/out.txt", "content": "hello"}, "5 bytes"},
		{"query_db", map[string]interface{}{"query": "SELECT * FROM t"}, "rows"},
		{"query_db", map[string]interface{}{"query": "DELETE FROM t WHERE id=1"}, "affected"},
	}
	for _, tc := range cases {
		got := dispatchTool(tc.name, tc.args)
		if !strings.Contains(got, tc.want) {
			t.Errorf("dispatchTool(%q): want substring %q in %q", tc.name, tc.want, got)
		}
	}

	if got := dispatchTool("no_such_tool", nil); got != "" {
		t.Errorf("unknown tool: expected empty string, got %q", got)
	}
}

func TestDispatchTool_ReadFile_MentionsPath(t *testing.T) {
	path := "/reports/annual.pdf"
	out := dispatchTool("read_file", map[string]interface{}{"path": path})
	if !strings.Contains(out, path) {
		t.Errorf("read_file output should contain path %q; got: %s", path, out)
	}
}

func TestDispatchTool_WriteFile_ByteCount(t *testing.T) {
	content := "hello world" // 11 bytes
	out := dispatchTool("write_file", map[string]interface{}{"path": "/x", "content": content})
	if !strings.Contains(out, "11 bytes") {
		t.Errorf("write_file output should contain byte count; got: %s", out)
	}
}

func TestDispatchTool_QueryDB_SelectVsNonSelect(t *testing.T) {
	selectOut := dispatchTool("query_db", map[string]interface{}{"query": "select id from t"})
	if !strings.Contains(selectOut, "rows") {
		t.Errorf("SELECT should mention rows; got: %s", selectOut)
	}

	insertOut := dispatchTool("query_db", map[string]interface{}{"query": "INSERT INTO t VALUES(1)"})
	if strings.Contains(insertOut, "rows") {
		t.Errorf("non-SELECT should not mention rows; got: %s", insertOut)
	}
	if !strings.Contains(insertOut, "affected") {
		t.Errorf("non-SELECT should mention affected; got: %s", insertOut)
	}
}

// An id-less "initialize" is a notification: JSON-RPC servers must never respond
// to notifications regardless of method name, so handle must emit nothing. This
// guards the switch ordering (the notification guard precedes the method
// branches).
func TestHandle_NotificationProducesNoResponse(t *testing.T) {
	for _, m := range []rpcMsg{
		{JSONRPC: "2.0", Method: "initialize"}, // id absent: a notification
		{JSONRPC: "2.0", Method: "notifications/initialized"},
	} {
		origStdout := os.Stdout
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe: %v", err)
		}
		os.Stdout = w
		handle(m)
		w.Close()
		os.Stdout = origStdout
		data, _ := io.ReadAll(r)
		r.Close()
		if strings.TrimSpace(string(data)) != "" {
			t.Errorf("notification %q must produce no response, got: %s", m.Method, data)
		}
	}
}

// ---- handle: initialize ----

func TestHandle_Initialize(t *testing.T) {
	msg := rpcMsg{JSONRPC: "2.0", ID: rawID(1), Method: "initialize"}
	out := captureHandle(t, msg)

	if out.Error != nil {
		t.Fatalf("unexpected error: %+v", out.Error)
	}
	if out.Result == nil {
		t.Fatal("expected result")
	}

	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(out.Result, &result); err != nil {
		t.Fatalf("parsing initialize result: %v", err)
	}
	if result.ProtocolVersion != revisionHandshake {
		t.Errorf("protocolVersion: want %q, got %q", revisionHandshake, result.ProtocolVersion)
	}
	if result.ServerInfo.Name != serverName {
		t.Errorf("serverInfo.name: want %q, got %q", serverName, result.ServerInfo.Name)
	}
	if result.ServerInfo.Version != serverVersion {
		t.Errorf("serverInfo.version: want %q, got %q", serverVersion, result.ServerInfo.Version)
	}
}

// ---- handle: tools/list ----

func TestHandle_ToolsList(t *testing.T) {
	msg := rpcMsg{JSONRPC: "2.0", ID: rawID(2), Method: "tools/list"}
	out := captureHandle(t, msg)

	if out.Error != nil {
		t.Fatalf("unexpected error: %+v", out.Error)
	}

	var result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(out.Result, &result); err != nil {
		t.Fatalf("parsing tools/list result: %v", err)
	}

	names := make(map[string]bool)
	for _, tool := range result.Tools {
		names[tool.Name] = true
	}
	for _, want := range []string{"read_file", "write_file", "query_db"} {
		if !names[want] {
			t.Errorf("missing tool %q in list", want)
		}
	}
}

// ---- handle: tools/call ----

func callMsg(t *testing.T, id int, name string, args map[string]interface{}) rpcMsg {
	t.Helper()
	params, _ := json.Marshal(map[string]interface{}{"name": name, "arguments": args})
	p := json.RawMessage(params)
	return rpcMsg{JSONRPC: "2.0", ID: rawID(id), Method: "tools/call", Params: p}
}

func toolText(t *testing.T, result json.RawMessage) string {
	t.Helper()
	var r struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(result, &r); err != nil {
		t.Fatalf("parsing tools/call result: %v", err)
	}
	if r.IsError {
		t.Error("isError should be false")
	}
	if len(r.Content) == 0 {
		t.Fatal("expected at least one content item")
	}
	return r.Content[0].Text
}

// A tools/call with missing, null, or wrong-typed required arguments must be
// rejected with JSON-RPC -32602, not answered with a fabricated success result.
func TestHandle_ToolsCall_InvalidArgsRejected(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args map[string]interface{}
	}{
		{"read_file missing path", "read_file", map[string]interface{}{}},
		{"read_file null path", "read_file", map[string]interface{}{"path": nil}},
		{"read_file wrong-type path", "read_file", map[string]interface{}{"path": 42}},
		{"write_file missing content", "write_file", map[string]interface{}{"path": "/x"}},
		{"query_db missing query", "query_db", map[string]interface{}{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := captureHandle(t, callMsg(t, 3, tc.tool, tc.args))
			if out.Error == nil {
				t.Fatalf("invalid args must be rejected, got result: %s", out.Result)
			}
			if out.Error.Code != -32602 {
				t.Errorf("error code = %d, want -32602 (invalid params)", out.Error.Code)
			}
			if out.Result != nil {
				t.Errorf("a rejected call must carry no result, got: %s", out.Result)
			}
		})
	}
}

func TestHandle_ReadFile(t *testing.T) {
	out := captureHandle(t, callMsg(t, 3, "read_file", map[string]interface{}{"path": "/reports/q3.pdf"}))
	if out.Error != nil {
		t.Fatalf("unexpected error: %+v", out.Error)
	}
	text := toolText(t, out.Result)
	if !strings.Contains(text, "/reports/q3.pdf") {
		t.Errorf("read_file result should mention path; got: %s", text)
	}
}

func TestHandle_WriteFile(t *testing.T) {
	out := captureHandle(t, callMsg(t, 3, "write_file", map[string]interface{}{
		"path":    "/tmp/test.txt",
		"content": "hello world",
	}))
	if out.Error != nil {
		t.Fatalf("unexpected error: %+v", out.Error)
	}
	text := toolText(t, out.Result)
	if !strings.Contains(text, "11 bytes") {
		t.Errorf("write_file result should report byte count; got: %s", text)
	}
}

func TestHandle_QueryDB_Select(t *testing.T) {
	out := captureHandle(t, callMsg(t, 3, "query_db", map[string]interface{}{"query": "SELECT * FROM reports"}))
	if out.Error != nil {
		t.Fatalf("unexpected error: %+v", out.Error)
	}
	text := toolText(t, out.Result)
	if !strings.Contains(text, "rows") {
		t.Errorf("SELECT result should mention rows; got: %s", text)
	}
}

func TestHandle_QueryDB_NonSelect(t *testing.T) {
	out := captureHandle(t, callMsg(t, 3, "query_db", map[string]interface{}{"query": "DELETE FROM reports"}))
	if out.Error != nil {
		t.Fatalf("unexpected error: %+v", out.Error)
	}
	text := toolText(t, out.Result)
	if !strings.Contains(text, "affected") {
		t.Errorf("non-SELECT result should mention affected; got: %s", text)
	}
}

func TestHandle_UnknownTool(t *testing.T) {
	out := captureHandle(t, callMsg(t, 3, "drop_table", map[string]interface{}{}))
	if out.Error == nil {
		t.Fatal("expected JSON-RPC error for unknown tool")
	}
	if !strings.Contains(out.Error.Message, "drop_table") {
		t.Errorf("error message should mention tool name; got: %s", out.Error.Message)
	}
}

func TestHandle_InvalidToolCallParams(t *testing.T) {
	bad := json.RawMessage(`not-json`)
	msg := rpcMsg{JSONRPC: "2.0", ID: rawID(4), Method: "tools/call", Params: bad}
	out := captureHandle(t, msg)
	if out.Error == nil {
		t.Fatal("expected error for invalid params")
	}
	if out.Error.Code != -32602 {
		t.Errorf("expected code -32602, got %d", out.Error.Code)
	}
}

// ---- handle: notifications ----

func TestHandle_Notification_NoOutput(t *testing.T) {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	// Notification: no ID, has Method.
	msg := rpcMsg{JSONRPC: "2.0", Method: "notifications/initialized"}
	handle(msg)

	w.Close()
	os.Stdout = origStdout

	data, _ := io.ReadAll(r)
	r.Close()

	if strings.TrimSpace(string(data)) != "" {
		t.Errorf("notification should produce no output; got: %s", data)
	}
}

// ---- handle: unknown method ----

func TestHandle_UnknownMethod(t *testing.T) {
	msg := rpcMsg{JSONRPC: "2.0", ID: rawID(5), Method: "resources/list"}
	out := captureHandle(t, msg)
	if out.Error == nil || out.Error.Code != -32601 {
		t.Errorf("expected -32601 method-not-found; got %+v", out.Error)
	}
}

func TestHandle_UnknownMethod_Notification_NoOutput(t *testing.T) {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	// Unknown method as a notification (no ID) — must produce no output.
	msg := rpcMsg{JSONRPC: "2.0", Method: "resources/subscribe"}
	handle(msg)

	w.Close()
	os.Stdout = origStdout

	data, _ := io.ReadAll(r)
	r.Close()

	if strings.TrimSpace(string(data)) != "" {
		t.Errorf("unknown-method notification should produce no output; got: %s", data)
	}
}

// TestHandle_EmptyMessage covers the default branch in handle where the message
// is neither a known method, a notification, nor a request (empty rpcMsg).
func TestHandle_EmptyMessage(t *testing.T) {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	// Empty message: no ID, no Method → hits default, isRequest() is false → no output.
	handle(rpcMsg{JSONRPC: "2.0"})

	w.Close()
	os.Stdout = origStdout

	data, _ := io.ReadAll(r)
	r.Close()

	if strings.TrimSpace(string(data)) != "" {
		t.Errorf("empty message should produce no output; got: %s", data)
	}
}

// TestMain_ProcessesMessages drives main() via redirected stdin/stdout,
// exercising the scanner loop including empty lines and invalid JSON paths.
func TestMain_ProcessesMessages(t *testing.T) {
	origStdin := os.Stdin
	origStdout := os.Stdout
	defer func() {
		os.Stdin = origStdin
		os.Stdout = origStdout
	}()

	// Capture stdout.
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stdout: %v", err)
	}
	os.Stdout = stdoutW

	// Write test messages to stdin.
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stdin: %v", err)
	}
	os.Stdin = stdinR

	go func() {
		defer stdinW.Close()
		// Empty line — must be skipped (len(line)==0 branch).
		_, _ = stdinW.WriteString("\n")
		// Invalid JSON — must be skipped (json.Unmarshal error branch).
		_, _ = stdinW.WriteString("not-json\n")
		// Valid initialize request.
		msg, _ := json.Marshal(rpcMsg{JSONRPC: "2.0", ID: rawID(1), Method: "initialize"})
		_, _ = stdinW.Write(append(msg, '\n'))
	}()

	main()

	stdoutW.Close()
	out, _ := io.ReadAll(stdoutR)
	stdoutR.Close()

	if len(out) == 0 {
		t.Error("expected output from initialize request; got none")
	}
	// The output should contain a valid JSON response.
	var resp rpcMsg
	if err := json.Unmarshal([]byte(strings.TrimRight(string(out), "\n")), &resp); err != nil {
		t.Errorf("parsing main output: %v\nraw: %s", err, out)
	}
	if resp.Error != nil {
		t.Errorf("unexpected error in response: %+v", resp.Error)
	}
}
