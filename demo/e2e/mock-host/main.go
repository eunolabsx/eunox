// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// mock-host is the MCP host (client) for the eunox end-to-end test suite. It
// drives the real compiled eunox binary as a black box, over real transports,
// to catch bugs in-process unit tests can't: transport framing, subprocess
// lifecycle, list filtering, redaction, and audit-log integrity.
//
// Modes (--mode): stdio spawns `eunox proxy` and talks over its stdio pipes;
// http drives an already-running gateway; audit parses --audit-log's JSONL.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// JSON-RPC envelope and assertion bookkeeping
// ─────────────────────────────────────────────────────────────────────────────

type rpcMsg struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *rpcError        `json:"error,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// denialData is the structured payload eunox attaches to a policy denial.
type denialData struct {
	Code     string `json:"code"`
	Type     string `json:"type"`
	Target   string `json:"target"`
	Argument string `json:"argument"`
}

// suite accumulates pass/fail counts and prints a PASS/FAIL line per check.
type suite struct {
	pass int
	fail int
}

func (s *suite) ok(desc string) {
	s.pass++
	fmt.Printf("PASS  %s\n", desc)
}

func (s *suite) bad(desc, detail string) {
	s.fail++
	fmt.Printf("FAIL  %s\n      %s\n", desc, detail)
}

// expectAllow asserts the call succeeded (no JSON-RPC error, result present).
func (s *suite) expectAllow(desc string, m rpcMsg, err error) { //nolint:gocritic // hugeParam: rpcMsg by value mirrors the proxy convention.
	switch {
	case err != nil:
		s.bad(desc, "transport error: "+err.Error())
	case m.Error != nil:
		s.bad(desc, fmt.Sprintf("want ALLOW, got error %d %s", m.Error.Code, m.Error.Message))
	case m.Result == nil:
		s.bad(desc, "want ALLOW with a result, got neither result nor error")
	default:
		s.ok(desc)
	}
}

// expectDeny asserts a policy denial carrying the given symbolic code (and, when
// non-empty, condition type). wantType "" skips the condition-type check.
func (s *suite) expectDeny(desc, wantCode, wantType string, m rpcMsg, err error) { //nolint:gocritic // hugeParam.
	if err != nil {
		s.bad(desc, "transport error: "+err.Error())
		return
	}
	if m.Error == nil {
		s.bad(desc, "want DENY "+wantCode+", got ALLOW")
		return
	}
	var d denialData
	_ = json.Unmarshal(m.Error.Data, &d)
	if d.Code != wantCode {
		s.bad(desc, fmt.Sprintf("want denial_code %q, got %q (msg: %s)", wantCode, d.Code, m.Error.Message))
		return
	}
	if wantType != "" && d.Type != wantType {
		s.bad(desc, fmt.Sprintf("want condition_type %q, got %q", wantType, d.Type))
		return
	}
	s.ok(desc)
}

// expectErrorCode asserts a numeric JSON-RPC error code, for fail-closed
// internal errors (e.g. redaction failure) that carry no structured denial data.
func (s *suite) expectErrorCode(desc string, want int, m rpcMsg, err error) { //nolint:gocritic,unparam // hugeParam; want is intentionally explicit for readability.
	switch {
	case err != nil:
		s.bad(desc, "transport error: "+err.Error())
	case m.Error == nil:
		s.bad(desc, fmt.Sprintf("want error code %d, got ALLOW", want))
	case m.Error.Code != want:
		s.bad(desc, fmt.Sprintf("want error code %d, got %d (%s)", want, m.Error.Code, m.Error.Message))
	default:
		s.ok(desc)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Result inspection helpers
// ─────────────────────────────────────────────────────────────────────────────

// toolText returns the concatenated text of a tools/call result's content items.
func toolText(m rpcMsg) string { //nolint:gocritic // hugeParam.
	var r struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	_ = json.Unmarshal(m.Result, &r)
	var b strings.Builder
	for _, c := range r.Content {
		b.WriteString(c.Text)
	}
	return b.String()
}

// firstContentJSON parses the first text content item of a tools/call result as
// a JSON object.
func firstContentJSON(m rpcMsg) map[string]interface{} { //nolint:gocritic // hugeParam.
	var r struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	_ = json.Unmarshal(m.Result, &r)
	out := map[string]interface{}{}
	if len(r.Content) > 0 {
		_ = json.Unmarshal([]byte(r.Content[0].Text), &out)
	}
	return out
}

func structuredContent(m rpcMsg) map[string]interface{} { //nolint:gocritic // hugeParam.
	var r struct {
		Structured map[string]interface{} `json:"structuredContent"`
	}
	_ = json.Unmarshal(m.Result, &r)
	if r.Structured == nil {
		return map[string]interface{}{}
	}
	return r.Structured
}

// listNames extracts the value at result.<field>[].<key> for a */list response.
func listNames(m rpcMsg, field, key string) []string { //nolint:gocritic // hugeParam.
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(m.Result, &raw)
	var entries []map[string]interface{}
	_ = json.Unmarshal(raw[field], &entries)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if v, ok := e[key].(string); ok {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func has(m map[string]interface{}, key string) bool { _, ok := m[key]; return ok }

// subObject returns m[key] as a JSON object, or an empty map if absent/not an
// object.
func subObject(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	return map[string]interface{}{}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// stdio connection: spawns the proxy and talks over its pipes
// ─────────────────────────────────────────────────────────────────────────────

type stdioConn struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	writeMu sync.Mutex
	resp    chan rpcMsg
	nextID  int
}

func newStdioConn(proxyBin, config string) (*stdioConn, error) {
	cmd := exec.Command(proxyBin, "proxy", "--config", config) //nolint:gosec,noctx // G204: proxy path/config are test-controlled args; lifecycle managed via stdin close + Wait, not ctx.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &stdioConn{cmd: cmd, stdin: stdin, resp: make(chan rpcMsg, 64), nextID: 1}
	go c.readLoop(stdout)
	return c, nil
}

// readLoop dispatches each line: server-initiated requests are answered
// inline, responses go to resp for call() to match by id, notifications skipped.
func (c *stdioConn) readLoop(stdout io.Reader) {
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var m rpcMsg
		if err := json.Unmarshal(line, &m); err != nil {
			continue
		}
		switch {
		case m.Method != "" && m.ID != nil:
			c.answerServerRequest(m)
		case m.ID != nil:
			c.resp <- m
		default:
			// notification: ignore
		}
	}
	close(c.resp)
}

// answerServerRequest satisfies the only server-initiated request the suite
// expects, sampling/createMessage, with a canned result so the round-trip completes.
func (c *stdioConn) answerServerRequest(m rpcMsg) { //nolint:gocritic // hugeParam.
	if m.Method != "sampling/createMessage" {
		return
	}
	result := json.RawMessage(`{"role":"assistant","content":{"type":"text","text":"e2e mock sample"},` +
		`"model":"mock-model","stopReason":"endTurn"}`)
	c.writeRaw(rpcMsg{JSONRPC: "2.0", ID: m.ID, Result: result})
}

func (c *stdioConn) writeRaw(m rpcMsg) { //nolint:gocritic // hugeParam.
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	data, _ := json.Marshal(m)
	_, _ = c.stdin.Write(append(data, '\n'))
}

// call sends a request and blocks until the matching-id response arrives,
// servicing inbound server-initiated requests in the meantime.
func (c *stdioConn) call(method string, params interface{}) (rpcMsg, error) {
	c.nextID++
	idNum := c.nextID
	rawID := json.RawMessage(fmt.Sprintf("%d", idNum))
	pb, _ := json.Marshal(params)
	c.writeRaw(rpcMsg{JSONRPC: "2.0", ID: &rawID, Method: method, Params: pb})

	want := fmt.Sprintf("%d", idNum)
	timeout := time.After(15 * time.Second)
	for {
		select {
		case m, ok := <-c.resp:
			if !ok {
				return rpcMsg{}, fmt.Errorf("proxy closed connection awaiting id=%s", want)
			}
			if m.ID != nil && string(*m.ID) == want {
				return m, nil
			}
		case <-timeout:
			return rpcMsg{}, fmt.Errorf("timeout awaiting response to %s id=%s", method, want)
		}
	}
}

// callRawID sends a request with a caller-chosen raw id and returns the response
// matched by that exact raw id (used to assert id-type preservation).
func (c *stdioConn) callRawID(rawID, method string, params interface{}) (rpcMsg, error) {
	id := json.RawMessage(rawID)
	pb, _ := json.Marshal(params)
	c.writeRaw(rpcMsg{JSONRPC: "2.0", ID: &id, Method: method, Params: pb})
	timeout := time.After(15 * time.Second)
	for {
		select {
		case m, ok := <-c.resp:
			if !ok {
				return rpcMsg{}, fmt.Errorf("proxy closed connection awaiting id=%s", rawID)
			}
			if m.ID != nil && string(*m.ID) == rawID {
				return m, nil
			}
		case <-timeout:
			return rpcMsg{}, fmt.Errorf("timeout awaiting id=%s", rawID)
		}
	}
}

func (c *stdioConn) initialize() error {
	_, err := c.call("initialize", map[string]interface{}{
		"protocolVersion": "2025-11-25",
		"capabilities":    map[string]interface{}{"sampling": map[string]interface{}{}},
		"clientInfo":      map[string]interface{}{"name": "e2e-mock-host", "version": "1.0"},
	})
	if err != nil {
		return err
	}
	c.writeRaw(rpcMsg{JSONRPC: "2.0", Method: "notifications/initialized"})
	return nil
}

func (c *stdioConn) close() {
	_ = c.stdin.Close()
	_ = c.cmd.Wait()
}

func toolCall(name string, args map[string]interface{}) (method string, params interface{}) {
	return "tools/call", map[string]interface{}{"name": name, "arguments": args}
}

// ─────────────────────────────────────────────────────────────────────────────
// stdio suites
// ─────────────────────────────────────────────────────────────────────────────

func runStdioFull(c *stdioConn, s *suite) {
	tc := func(name string, args map[string]interface{}) (rpcMsg, error) {
		m, p := toolCall(name, args)
		return c.call(m, p)
	}

	// ── tools/call: allow ──
	m, e := tc("read_file", map[string]interface{}{"path": "/reports/q3.pdf"})
	s.expectAllow("tools/call read_file /reports/q3.pdf -> ALLOW (allowedValues *)", m, e)

	m, e = tc("read_any_report", map[string]interface{}{"path": "/reports/2025/q4.pdf"})
	s.expectAllow("tools/call read_any_report /reports/2025/q4.pdf -> ALLOW (** crosses /)", m, e)

	m, e = tc("query_db", map[string]interface{}{"query": "SELECT * FROM t"})
	s.expectAllow("tools/call query_db SELECT -> ALLOW (allowedOperations)", m, e)

	m, e = tc("query_db", map[string]interface{}{"query": "  select 1"})
	s.expectAllow("tools/call query_db lowercase+whitespace 'select' -> ALLOW (trim/case-insensitive)", m, e)

	// ── tools/call: deny ──
	m, e = tc("read_file", map[string]interface{}{"path": "/reports/2025/q4.pdf"})
	s.expectDeny("tools/call read_file /reports/2025/q4.pdf -> DENY (single * does not cross /)", "VALUE_NOT_PERMITTED", "allowedValues", m, e)

	m, e = tc("read_file", map[string]interface{}{"path": "/etc/shadow"})
	s.expectDeny("tools/call read_file /etc/shadow -> DENY (allowedValues)", "VALUE_NOT_PERMITTED", "allowedValues", m, e)

	m, e = tc("write_file", map[string]interface{}{"path": "/x", "content": "y"})
	s.expectDeny("tools/call write_file -> DENY (absent from manifest)", "AUTHORIZATION_FAILED", "", m, e)

	m, e = tc("secret_tool", map[string]interface{}{"x": "1"})
	s.expectDeny("tools/call secret_tool -> DENY (absent from manifest)", "AUTHORIZATION_FAILED", "", m, e)

	m, e = tc("query_db", map[string]interface{}{"query": "DELETE FROM t"})
	s.expectDeny("tools/call query_db DELETE -> DENY (allowedOperations)", "OPERATION_NOT_PERMITTED", "allowedOperations", m, e)

	m, e = tc("read_doc", map[string]interface{}{"path": "/a/b.exe"})
	s.expectDeny("tools/call read_doc .exe -> DENY (allowedExtensions)", "CONDITION_FAILED", "allowedExtensions", m, e)

	m, e = tc("read_doc", map[string]interface{}{"path": "/a/b.csv"})
	s.expectAllow("tools/call read_doc .csv -> ALLOW (allowedExtensions)", m, e)

	m, e = tc("send_email", map[string]interface{}{"to": "a@example.com", "subject": "s", "body": "b"})
	s.expectAllow("tools/call send_email @example.com -> ALLOW (recipientDomain)", m, e)

	m, e = tc("send_email", map[string]interface{}{"to": "a@evil.com", "subject": "s", "body": "b"})
	s.expectDeny("tools/call send_email @evil.com -> DENY (recipientDomain)", "CONDITION_FAILED", "recipientDomain", m, e)

	m, e = tc("time_gated", map[string]interface{}{"x": "1"})
	s.expectDeny("tools/call time_gated -> DENY (timeWindow notAfter past)", "CONDITION_FAILED", "timeWindow", m, e)

	// ── edge: missing / wrong-type argument fails closed ──
	m, e = tc("read_file", map[string]interface{}{})
	s.expectDeny("tools/call read_file missing 'path' -> DENY (fail closed)", "MISSING_CONTEXT", "allowedValues", m, e)

	m, e = tc("read_file", map[string]interface{}{"path": 123})
	s.expectDeny("tools/call read_file numeric 'path' -> DENY (value not in allowedValues set)", "VALUE_NOT_PERMITTED", "allowedValues", m, e)

	// ── stateful: maxCalls (synchronous, so deterministic) ──
	m, e = tc("rate_limited", map[string]interface{}{"n": "1"})
	s.expectAllow("tools/call rate_limited #1 -> ALLOW (maxCalls 2)", m, e)
	m, e = tc("rate_limited", map[string]interface{}{"n": "2"})
	s.expectAllow("tools/call rate_limited #2 -> ALLOW (maxCalls 2)", m, e)
	m, e = tc("rate_limited", map[string]interface{}{"n": "3"})
	s.expectDeny("tools/call rate_limited #3 -> DENY (RATE_LIMITED)", "RATE_LIMITED", "maxCalls", m, e)

	// ── stateful: sequenceBlock (read_credentials arms it within this session) ──
	m, e = tc("read_credentials", map[string]interface{}{"name": "db"})
	s.expectAllow("tools/call read_credentials -> ALLOW (arms sequenceBlock)", m, e)
	m, e = tc("write_external", map[string]interface{}{"url": "https://x", "data": "d"})
	s.expectDeny("tools/call write_external after read_credentials -> DENY (sequenceBlock)", "CONDITION_FAILED", "sequenceBlock", m, e)

	// ── redactFields directive ──
	m, e = tc("get_secret_record", map[string]interface{}{"id": "1"})
	checkRedaction(s, m, e)

	// get_malformed returns invalid JSON; redactFields only acts on cleanly-parseable
	// JSON, so this passes through unredacted — accepted residual (docs/threat-model-mcp.md § 6.3).
	m, e = tc("get_malformed", map[string]interface{}{"id": "1"})
	if e == nil && m.Error == nil && strings.Contains(toolText(m), `"secret"`) {
		s.ok("tools/call get_malformed -> ALLOW (malformed JSON passes through unredacted; accepted residual, redact upstream)")
	} else {
		s.bad("tools/call get_malformed -> ALLOW (malformed JSON unchanged)", fmt.Sprintf("err=%v msg=%v text=%q", e, m.Error, toolText(m)))
	}

	m, e = tc("get_plaintext", map[string]interface{}{"id": "1"})
	if e == nil && m.Error == nil && strings.Contains(toolText(m), "Revenue") {
		s.ok("tools/call get_plaintext -> ALLOW (free-form text passes redaction unchanged)")
	} else {
		s.bad("tools/call get_plaintext -> ALLOW (free-form text unchanged)", fmt.Sprintf("err=%v msg=%v text=%q", e, m.Error, toolText(m)))
	}

	// ── tools/list filtering ──
	m, e = c.call("tools/list", map[string]interface{}{})
	gotTools := listNames(m, "tools", "name")
	wantTools := []string{"big_response", "get_malformed", "get_plaintext", "get_secret_record", "query_db", "rate_limited",
		"read_any_report", "read_credentials", "read_doc", "read_file", "send_email", "time_gated", "trigger_sampling", "write_external"}
	sort.Strings(wantTools)
	if e == nil && slicesEqual(gotTools, wantTools) {
		s.ok("tools/list -> filtered to call-permitted tools (write_file, secret_tool absent)")
	} else {
		s.bad("tools/list filtering", fmt.Sprintf("err=%v\n      got:  %v\n      want: %v", e, gotTools, wantTools))
	}

	// ── resources ──
	m, e = c.call("resources/read", map[string]interface{}{"uri": "file:///data/reports/q3.pdf"})
	s.expectAllow("resources/read file:///data/reports/q3.pdf -> ALLOW", m, e)
	m, e = c.call("resources/read", map[string]interface{}{"uri": "file:///data/reports/2025/q4.pdf"})
	s.expectDeny("resources/read file:///data/reports/2025/q4.pdf -> DENY (single * URI glob)", "AUTHORIZATION_FAILED", "", m, e)
	m, e = c.call("resources/read", map[string]interface{}{"uri": "file:///data/secret.txt"})
	s.expectDeny("resources/read file:///data/secret.txt -> DENY (absent)", "AUTHORIZATION_FAILED", "", m, e)
	m, e = c.call("resources/subscribe", map[string]interface{}{"uri": "file:///data/live/metrics"})
	s.expectAllow("resources/subscribe file:///data/live/metrics -> ALLOW (read covers subscribe)", m, e)
	m, e = c.call("resources/subscribe", map[string]interface{}{"uri": "db://warehouse/secret"})
	s.expectDeny("resources/subscribe db://warehouse/secret -> DENY (absent)", "AUTHORIZATION_FAILED", "", m, e)

	m, e = c.call("resources/list", map[string]interface{}{})
	gotRes := listNames(m, "resources", "uri")
	wantRes := []string{"db://warehouse/orders", "file:///data/live/metrics", "file:///data/reports/q3.pdf", "file:///data/reports/q4.pdf"}
	sort.Strings(wantRes)
	if e == nil && slicesEqual(gotRes, wantRes) {
		s.ok("resources/list -> filtered to read-permitted URIs (secret.txt, warehouse/secret absent)")
	} else {
		s.bad("resources/list filtering", fmt.Sprintf("err=%v\n      got:  %v\n      want: %v", e, gotRes, wantRes))
	}

	// resources/templates/list is not an enforced/forwarded method -> denied by default.
	m, e = c.call("resources/templates/list", map[string]interface{}{})
	s.expectDeny("resources/templates/list -> DENY (unmapped method, fail closed)", "AUTHORIZATION_FAILED", "", m, e)

	// ── prompts ──
	m, e = c.call("prompts/get", map[string]interface{}{"name": "code_review"})
	s.expectAllow("prompts/get code_review -> ALLOW (exact)", m, e)
	m, e = c.call("prompts/get", map[string]interface{}{"name": "summarize_doc"})
	s.expectAllow("prompts/get summarize_doc -> ALLOW (summarize_* glob)", m, e)
	m, e = c.call("prompts/get", map[string]interface{}{"name": "internal_secret_prompt"})
	s.expectDeny("prompts/get internal_secret_prompt -> DENY (absent)", "AUTHORIZATION_FAILED", "", m, e)

	m, e = c.call("prompts/list", map[string]interface{}{})
	gotPrompts := listNames(m, "prompts", "name")
	wantPrompts := []string{"code_review", "summarize_doc", "summarize_pr"}
	sort.Strings(wantPrompts)
	if e == nil && slicesEqual(gotPrompts, wantPrompts) {
		s.ok("prompts/list -> filtered to get-permitted prompts (internal_secret_prompt absent)")
	} else {
		s.bad("prompts/list filtering", fmt.Sprintf("err=%v\n      got:  %v\n      want: %v", e, gotPrompts, wantPrompts))
	}

	// ── ping is answered locally, NOT denied ──
	// It carries no target for a manifest to authorize; denying it broke the liveness
	// probe every MCP host is entitled to send. Still passes the shared kill gate.
	m, e = c.call("ping", map[string]interface{}{})
	s.expectAllow("ping -> ALLOW (answered locally by the proxy)", m, e)

	// ── unmapped / pass-through methods are denied by default ──
	m, e = c.call("completion/complete", map[string]interface{}{"ref": map[string]interface{}{}})
	s.expectDeny("completion/complete -> DENY (unmapped method)", "AUTHORIZATION_FAILED", "", m, e)
	m, e = c.call("foo/bar", map[string]interface{}{})
	s.expectDeny("foo/bar -> DENY (unknown method)", "AUTHORIZATION_FAILED", "", m, e)

	// ── id-type preservation ──
	m, e = c.callRawID(`"abc-123"`, "tools/call", map[string]interface{}{"name": "read_file", "arguments": map[string]interface{}{"path": "/reports/q3.pdf"}})
	if e == nil && m.ID != nil && string(*m.ID) == `"abc-123"` {
		s.ok(`id preservation: string id "abc-123" echoed unchanged`)
	} else {
		s.bad("id preservation (string)", fmt.Sprintf("err=%v id=%v", e, idStr(m.ID)))
	}
	// 2^53+1 is not exactly representable as float64, so a proxy that decoded ids
	// through a float would corrupt it; a sub-2^53 value can't exercise that path.
	const bigID = `9007199254740993`
	m, e = c.callRawID(bigID, "tools/call", map[string]interface{}{"name": "read_file", "arguments": map[string]interface{}{"path": "/reports/q3.pdf"}})
	if e == nil && m.ID != nil && string(*m.ID) == bigID {
		s.ok("id preservation: 2^53+1 numeric id echoed unchanged (no float64 rounding)")
	} else {
		s.bad("id preservation (numeric > 2^53)", fmt.Sprintf("err=%v id=%v", e, idStr(m.ID)))
	}

	// ── sampling: server-initiated, opted-in -> ALLOWED ──
	m, e = tc("trigger_sampling", map[string]interface{}{"prompt": "hello"})
	if e == nil && m.Error == nil && strings.Contains(toolText(m), "sampling:allowed") {
		s.ok("sampling/createMessage (opted in) -> ALLOW (round-trip reached host)")
	} else {
		s.bad("sampling allow", fmt.Sprintf("err=%v msg=%v text=%q", e, m.Error, toolText(m)))
	}

	// ── large + unicode REQUEST argument passes through ──
	big := strings.Repeat("A", 256*1024)
	m, e = tc("read_file", map[string]interface{}{"path": "/reports/q3.pdf", "note": big, "emoji": "héllo-世界"})
	s.expectAllow("tools/call with 256KiB + unicode request argument -> ALLOW (large request forwarded)", m, e)

	// ── large RESPONSE is forwarded intact (not truncated by the proxy or by
	//    audit-detail capping) ──
	m, e = tc("big_response", map[string]interface{}{"x": "1"})
	if e == nil && m.Error == nil && len(toolText(m)) == 2*1024*1024 {
		s.ok("tools/call big_response -> ALLOW (2 MiB response forwarded intact, no truncation)")
	} else {
		s.bad("big_response not forwarded intact", fmt.Sprintf("err=%v errobj=%v len=%d want=%d", e, m.Error, len(toolText(m)), 2*1024*1024))
	}
}

func checkRedaction(s *suite, m rpcMsg, e error) { //nolint:gocritic // hugeParam.
	if e != nil || m.Error != nil {
		s.bad("redactFields get_secret_record", fmt.Sprintf("want ALLOW, err=%v errobj=%v", e, m.Error))
		return
	}
	body := firstContentJSON(m)
	sc := structuredContent(m)
	problems := []string{}
	if body["ssn"] != "[redacted]" {
		problems = append(problems, "text.ssn should be masked to [redacted]")
	}
	if subObject(body, "nested")["token"] != "[redacted]" {
		problems = append(problems, "text.nested.token should be masked to [redacted]")
	}
	if sc["api_key"] != "[redacted]" {
		problems = append(problems, "structuredContent.api_key should be masked to [redacted]")
	}
	// Belt-and-suspenders: none of the distinctive raw secrets may survive anywhere
	// in the forwarded result envelope, not only at the named keys.
	for _, secret := range []string{"123-45-6789", "tok_abc123", "sk-live-9999"} {
		if strings.Contains(string(m.Result), secret) {
			problems = append(problems, "raw secret "+secret+" leaked into the forwarded result")
		}
	}
	if !has(body, "name") || !has(body, "email") {
		problems = append(problems, "text.name/email must be preserved")
	}
	if !has(subObject(body, "nested"), "keep") {
		problems = append(problems, "text.nested.keep must be preserved")
	}
	if !has(sc, "public") {
		problems = append(problems, "structuredContent.public must be preserved")
	}
	if len(problems) == 0 {
		s.ok("redactFields get_secret_record -> ssn/nested.token/api_key masked to [redacted], rest preserved (text + structuredContent)")
	} else {
		s.bad("redactFields get_secret_record", strings.Join(problems, "; "))
	}
}

func idStr(id *json.RawMessage) string {
	if id == nil {
		return "<nil>"
	}
	return string(*id)
}

func runStdioSamplingDeny(c *stdioConn, s *suite) {
	m, p := toolCall("trigger_sampling", map[string]interface{}{"prompt": "hello"})
	resp, e := c.call(m, p)
	if e == nil && resp.Error == nil && strings.Contains(toolText(resp), "sampling:denied") {
		s.ok("sampling/createMessage (NOT opted in) -> DENY (upstream got JSON-RPC error, host never invoked)")
	} else {
		s.bad("sampling deny", fmt.Sprintf("err=%v errobj=%v text=%q", e, resp.Error, toolText(resp)))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP connection
// ─────────────────────────────────────────────────────────────────────────────

type httpConn struct {
	base    string
	route   string
	session string
	client  *http.Client
	nextID  int // monotonically increasing per-request id, pre-incremented before use (first id is 1)
}

// validateRPCEnvelope rejects a stale/wrong-id or version-less HTTP reply so the
// suite can't pass just because result/error happens to match the expected shape.
func validateRPCEnvelope(m rpcMsg, code, wantID int) error { //nolint:gocritic // hugeParam.
	if code < 200 || code >= 300 {
		return fmt.Errorf("non-2xx status %d for a JSON-RPC request response", code)
	}
	if m.JSONRPC != "2.0" {
		return fmt.Errorf("response jsonrpc = %q, want \"2.0\"", m.JSONRPC)
	}
	got := "null"
	if m.ID != nil {
		got = string(*m.ID)
	}
	if got != fmt.Sprintf("%d", wantID) {
		return fmt.Errorf("response id = %s, want %d (wrong-id or stale response)", got, wantID)
	}
	if (m.Result != nil) == (m.Error != nil) {
		return fmt.Errorf("response must carry exactly one of result/error (result present=%v, error present=%v)", m.Result != nil, m.Error != nil)
	}
	return nil
}

func newHTTPConn(base, route string) *httpConn {
	return &httpConn{base: base, route: route, client: &http.Client{Timeout: 15 * time.Second}}
}

func (h *httpConn) endpoint() string { return h.base + "/mcp/" + h.route }

// post sends one JSON-RPC message and returns the parsed response plus HTTP
// status. A 2xx with an empty body (notification/ack) yields a zero rpcMsg.
func (h *httpConn) post(body string) (rpcMsg, int, error) {
	req, err := http.NewRequest(http.MethodPost, h.endpoint(), strings.NewReader(body)) //nolint:noctx // short-lived test client.
	if err != nil {
		return rpcMsg{}, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if h.session != "" {
		req.Header.Set("Mcp-Session-Id", h.session)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return rpcMsg{}, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		// A truncated/aborted body is a framing failure to surface, not a clean ack.
		return rpcMsg{}, resp.StatusCode, fmt.Errorf("reading response body: %w", err)
	}
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		h.session = sid
	}
	var m rpcMsg
	if len(bytes.TrimSpace(raw)) > 0 {
		decErr := json.Unmarshal(raw, &m)
		// A 2xx must decode as JSON-RPC; a malformed body there is a framing
		// regression. Non-2xx bodies may legitimately be plain text (decode
		// failure there is expected — the caller checks the status code instead).
		if decErr != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return rpcMsg{}, resp.StatusCode, fmt.Errorf("2xx response body is not valid JSON-RPC: %w (body %q)", decErr, truncateBody(raw))
		}
	}
	return m, resp.StatusCode, nil
}

// truncateBody bounds a malformed body for an error message so a large garbage
// response does not flood the test log.
func truncateBody(b []byte) string {
	const maxLen = 256
	if len(b) > maxLen {
		return string(b[:maxLen]) + "...(truncated)"
	}
	return string(b)
}

func (h *httpConn) initialize() error {
	h.nextID++
	id := h.nextID
	m, code, err := h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}`, id))
	if err != nil {
		return err
	}
	// Same envelope validation as call(): a wrong-id / version-less initialize reply
	// must fail the handshake rather than pass on a non-empty result alone.
	if err := validateRPCEnvelope(m, code, id); err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	if h.session == "" || m.Error != nil {
		return fmt.Errorf("initialize failed: code=%d session=%q err=%v", code, h.session, m.Error)
	}
	// The notification's status must be checked too: post() returns nil for non-2xx
	// text bodies, so skipping it would hide a gateway that rejects the notification.
	_, notifCode, err := h.post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if err != nil {
		return fmt.Errorf("notifications/initialized failed: %w", err)
	}
	if notifCode < 200 || notifCode >= 300 {
		return fmt.Errorf("notifications/initialized rejected: code=%d (handshake not completed)", notifCode)
	}
	return nil
}

func (h *httpConn) call(method string, params interface{}) (rpcMsg, error) {
	pb, _ := json.Marshal(params)
	h.nextID++
	id := h.nextID
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":%s}`, id, method, string(pb))
	m, code, err := h.post(body)
	if err != nil {
		return m, err
	}
	// A fresh id + envelope check surfaces a stale/wrong-id or version-less reply as
	// a framing error, rather than accepting it whenever result/error happens to match.
	if err := validateRPCEnvelope(m, code, id); err != nil {
		return rpcMsg{}, err
	}
	return m, nil
}

func httpToolCall(h *httpConn, name string, args map[string]interface{}) (rpcMsg, error) {
	return h.call("tools/call", map[string]interface{}{"name": name, "arguments": args})
}

func runHTTPSuite(base string, s *suite) {
	main := newHTTPConn(base, "main")
	if err := main.initialize(); err != nil {
		s.bad("http initialize /mcp/main", err.Error())
		return
	}
	s.ok("http initialize /mcp/main -> session established")

	m, e := httpToolCall(main, "read_file", map[string]interface{}{"path": "/reports/q3.pdf"})
	s.expectAllow("http tools/call read_file /reports/q3.pdf -> ALLOW", m, e)
	m, e = httpToolCall(main, "read_file", map[string]interface{}{"path": "/etc/shadow"})
	s.expectDeny("http tools/call read_file /etc/shadow -> DENY", "VALUE_NOT_PERMITTED", "allowedValues", m, e)
	m, e = httpToolCall(main, "write_file", map[string]interface{}{"path": "/x", "content": "y"})
	s.expectDeny("http tools/call write_file -> DENY (absent)", "AUTHORIZATION_FAILED", "", m, e)

	// tools/list filtering over HTTP
	m, e = main.call("tools/list", map[string]interface{}{})
	got := listNames(m, "tools", "name")
	visible := map[string]bool{}
	for _, n := range got {
		visible[n] = true
	}
	if e == nil && len(got) > 0 && !visible["write_file"] && !visible["secret_tool"] && visible["read_file"] {
		s.ok("http tools/list -> filtered (write_file, secret_tool absent; read_file present)")
	} else {
		s.bad("http tools/list filtering", fmt.Sprintf("err=%v got=%v", e, got))
	}

	// resources + prompts list filtering over HTTP
	m, e = main.call("resources/list", map[string]interface{}{})
	gotRes := listNames(m, "resources", "uri")
	if e == nil && !contains(gotRes, "file:///data/secret.txt") && contains(gotRes, "db://warehouse/orders") {
		s.ok("http resources/list -> filtered (secret.txt absent)")
	} else {
		s.bad("http resources/list filtering", fmt.Sprintf("err=%v got=%v", e, gotRes))
	}

	// ── per-route policy isolation: read_file on /mcp/db (db-policy lacks it) ──
	db := newHTTPConn(base, "db")
	if err := db.initialize(); err != nil {
		s.bad("http initialize /mcp/db", err.Error())
	} else {
		s.ok("http initialize /mcp/db -> session established")
		m, e = httpToolCall(db, "query_db", map[string]interface{}{"query": "SELECT 1"})
		s.expectAllow("http /mcp/db query_db SELECT -> ALLOW", m, e)
		m, e = httpToolCall(db, "read_file", map[string]interface{}{"path": "/reports/q3.pdf"})
		s.expectDeny("http /mcp/db read_file -> DENY (read_file not in db-policy; per-route isolation)", "AUTHORIZATION_FAILED", "", m, e)
	}

	// ── session isolation: sequenceBlock armed in one session must not affect
	//    another (independent sessions, no shared state) ──
	runHTTPSessionIsolation(base, s)

	// ── malformed body robustness: a bad request must not break the session ──
	bad := newHTTPConn(base, "main")
	if err := bad.initialize(); err == nil {
		_, code, _ := bad.post("this is not json {")
		if code >= 400 {
			s.ok(fmt.Sprintf("http malformed body -> HTTP %d (rejected, session survives)", code))
		} else {
			s.bad("http malformed body", fmt.Sprintf("expected 4xx, got %d", code))
		}
		m, e = httpToolCall(bad, "read_file", map[string]interface{}{"path": "/reports/q3.pdf"})
		s.expectAllow("http session still usable after malformed body -> ALLOW", m, e)
	} else {
		s.bad("http initialize (malformed-robustness session)", err.Error())
	}

	// ── unknown route -> 404 ──
	bogus := newHTTPConn(base, "bogus")
	_, code, err := bogus.post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if err == nil && code == http.StatusNotFound {
		s.ok("http POST /mcp/bogus -> HTTP 404 (no such route)")
	} else {
		s.bad("http unknown route", fmt.Sprintf("expected 404, got %d err=%v", code, err))
	}

	// ── missing session id -> rejected ──
	noSess := newHTTPConn(base, "main")
	_, code, _ = noSess.post(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if code >= 400 {
		s.ok(fmt.Sprintf("http tools/list without session id -> HTTP %d (rejected)", code))
	} else {
		s.bad("http missing session id", fmt.Sprintf("expected 4xx, got %d", code))
	}

	// ── kill switch via loopback /control/kill ──
	runHTTPKillSwitch(base, s)
}

// runHTTPSessionIsolation proves that arming sequenceBlock in session A does not
// deny the same call in an independent session B.
func runHTTPSessionIsolation(base string, s *suite) {
	a := newHTTPConn(base, "main")
	b := newHTTPConn(base, "main")
	if err := a.initialize(); err != nil {
		s.bad("http session A init", err.Error())
		return
	}
	if err := b.initialize(); err != nil {
		s.bad("http session B init", err.Error())
		return
	}
	// Arm sequenceBlock in A only.
	if _, err := httpToolCall(a, "read_credentials", map[string]interface{}{"name": "db"}); err != nil {
		s.bad("http session A read_credentials", err.Error())
		return
	}
	mA, eA := httpToolCall(a, "write_external", map[string]interface{}{"url": "https://x", "data": "d"})
	s.expectDeny("http session A write_external after creds -> DENY (sequenceBlock)", "CONDITION_FAILED", "sequenceBlock", mA, eA)
	mB, eB := httpToolCall(b, "write_external", map[string]interface{}{"url": "https://x", "data": "d"})
	s.expectAllow("http session B write_external (creds never read here) -> ALLOW (session isolation)", mB, eB)
}

// httpControlTokenPath is the path the proxy wrote its /control/kill control
// token to (set from --control-token-path in main); empty in stdio/audit modes.
var httpControlTokenPath string

// readControlToken returns the control token the proxy wrote, or "" if no path
// was configured or the file cannot be read.
func readControlToken() string {
	if httpControlTokenPath == "" {
		return ""
	}
	data, err := os.ReadFile(httpControlTokenPath) //nolint:gosec // G304: test-controlled path from --control-token-path
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// runHTTPKillSwitch kills a session via the loopback control endpoint and
// asserts the next call is denied with KILL_SWITCH.
func runHTTPKillSwitch(base string, s *suite) {
	k := newHTTPConn(base, "main")
	if err := k.initialize(); err != nil {
		s.bad("http kill-switch session init", err.Error())
		return
	}
	m, e := httpToolCall(k, "read_file", map[string]interface{}{"path": "/reports/q3.pdf"})
	s.expectAllow("http kill-switch: pre-kill read_file -> ALLOW", m, e)

	body := fmt.Sprintf(`{"sessionId":%q}`, k.session)

	// /control/kill requires the proxy's control token (SEC-07); prove that first
	// with a tokenless request (401, rejected before the body is read, session intact).
	noTok, _ := http.NewRequest(http.MethodPost, base+"/control/kill", strings.NewReader(body)) //nolint:noctx // test client.
	noTok.Header.Set("Content-Type", "application/json")
	if resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(noTok); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			s.ok("http /control/kill without control token -> 401 (SEC-07)")
		} else {
			s.bad("http /control/kill without control token", fmt.Sprintf("expected 401, got %d", resp.StatusCode))
		}
	} else {
		s.bad("http /control/kill without control token", err.Error())
	}

	// Now issue the real kill with the control token the proxy wrote at startup.
	req, _ := http.NewRequest(http.MethodPost, base+"/control/kill", strings.NewReader(body)) //nolint:noctx // test client.
	req.Header.Set("Content-Type", "application/json")
	if tok := readControlToken(); tok != "" {
		req.Header.Set("X-Eunox-Control-Token", tok)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		s.bad("http /control/kill", err.Error())
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		s.bad("http /control/kill", fmt.Sprintf("status %d", resp.StatusCode))
		return
	}
	s.ok("http /control/kill (loopback + control token) -> accepted")

	m, e = httpToolCall(k, "read_file", map[string]interface{}{"path": "/reports/q3.pdf"})
	s.expectDeny("http kill-switch: post-kill read_file -> DENY (KILL_SWITCH)", "KILL_SWITCH", "", m, e)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit-log assertions
// ─────────────────────────────────────────────────────────────────────────────

type auditRecord struct {
	Decision      string   `json:"decision"`
	DenialCode    string   `json:"denial_code"`
	ConditionType string   `json:"condition_type"`
	TargetType    string   `json:"target_type"`
	Target        string   `json:"target"`
	Method        string   `json:"method"`
	Obligations   []string `json:"obligations"`
}

func runAuditCheck(path string, s *suite) {
	f, err := os.Open(path) //nolint:gosec // G304: audit path is a test-controlled flag.
	if err != nil {
		s.bad("audit log open", err.Error())
		return
	}
	defer func() { _ = f.Close() }()

	var recs []auditRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r auditRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			s.bad("audit record parse", err.Error())
			return
		}
		recs = append(recs, r)
	}
	if len(recs) == 0 {
		s.bad("audit log", "no records found")
		return
	}
	s.ok(fmt.Sprintf("audit log parsed (%d records)", len(recs)))

	// Every record must carry an explicit allow/deny decision.
	for i, r := range recs {
		if r.Decision != "allow" && r.Decision != "deny" {
			s.bad("audit decision field", fmt.Sprintf("record %d has decision=%q", i, r.Decision))
			return
		}
	}
	s.ok("audit: every record carries an explicit allow/deny decision")

	want := []struct {
		desc string
		pred func(auditRecord) bool
	}{
		{"audit: an allow recording the redacted paths (redactFields:ssn/nested.token/api_key) (get_secret_record)", func(r auditRecord) bool {
			return r.Decision == "allow" && r.Target == "get_secret_record" &&
				contains(r.Obligations, "redactFields:ssn") &&
				contains(r.Obligations, "redactFields:nested.token") &&
				contains(r.Obligations, "redactFields:api_key")
		}},
		{"audit: a deny with denial_code=AUTHORIZATION_FAILED (write_file)", func(r auditRecord) bool {
			return r.Decision == "deny" && r.DenialCode == "AUTHORIZATION_FAILED" && r.Target == "write_file"
		}},
		{"audit: a deny with condition_type=allowedValues", func(r auditRecord) bool {
			return r.Decision == "deny" && r.ConditionType == "allowedValues"
		}},
		{"audit: a deny with denial_code=RATE_LIMITED", func(r auditRecord) bool {
			return r.Decision == "deny" && r.DenialCode == "RATE_LIMITED"
		}},
		{"audit: target_type=resource recorded", func(r auditRecord) bool { return r.TargetType == "resource" }},
		{"audit: target_type=prompt recorded", func(r auditRecord) bool { return r.TargetType == "prompt" }},
		{"audit: a sampling/createMessage decision recorded", func(r auditRecord) bool {
			return r.Method == "sampling/createMessage"
		}},
	}
	for _, w := range want {
		found := false
		for _, r := range recs {
			if w.pred(r) {
				found = true
				break
			}
		}
		if found {
			s.ok(w.desc)
		} else {
			s.bad(w.desc, "no matching audit record")
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	mode := flag.String("mode", "stdio", "mode: stdio | http | audit")
	suiteName := flag.String("suite", "full", "stdio suite: full | sampling-deny")
	proxyBin := flag.String("proxy-bin", "", "path to the eunox binary (stdio mode)")
	config := flag.String("config", "", "path to the eunox stdio config (stdio mode)")
	url := flag.String("url", "http://127.0.0.1:3100", "proxy base URL (http mode)")
	auditLog := flag.String("audit-log", "", "audit JSONL path (audit mode)")
	controlTokenPath := flag.String("control-token-path", "", "path to the proxy's /control/kill control token file (http mode)")
	flag.Parse()
	httpControlTokenPath = *controlTokenPath

	s := &suite{}
	header := func(title string) { fmt.Printf("\n==> %s\n\n", title) }

	switch *mode {
	case "stdio":
		c, err := newStdioConn(*proxyBin, *config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "spawn proxy: %v\n", err)
			os.Exit(1)
		}
		if err := c.initialize(); err != nil {
			fmt.Fprintf(os.Stderr, "initialize: %v\n", err)
			c.close()
			os.Exit(1)
		}
		if *suiteName == "sampling-deny" {
			header("e2e [stdio] sampling DENY")
			runStdioSamplingDeny(c, s)
		} else {
			header("e2e [stdio] full enforcement matrix")
			runStdioFull(c, s)
		}
		c.close()

	case "http":
		header("e2e [http] transport, sessions, kill-switch, per-route")
		runHTTPSuite(*url, s)

	case "audit":
		header("e2e [audit] record assertions")
		runAuditCheck(*auditLog, s)

	default:
		fmt.Fprintf(os.Stderr, "unknown --mode %q\n", *mode)
		os.Exit(2)
	}

	fmt.Printf("\nResults: %d passed, %d failed\n", s.pass, s.fail)
	if s.fail > 0 {
		os.Exit(1)
	}
}
