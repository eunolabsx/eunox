// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// mock-server is the upstream MCP server for the eunox end-to-end test suite.
// Unlike the minimal demo mocks (three tools, one transport), it implements the
// full enforced MCP surface so the e2e host can drive every policy path, and
// speaks both stdio and HTTP so one binary serves both legs of the suite.
// Responses are deterministic; it is not wired to any real storage.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

const (
	sessionHeader      = "Mcp-Session-Id"
	mcpProtocolVersion = "2025-11-25"
	serverName         = "e2e-mock-server"
	serverVersion      = "1.0.0"

	// samplingReqID is the JSON-RPC id of the server-initiated sampling/createMessage
	// request trigger_sampling emits; the reply (or proxy denial) is matched against it.
	samplingReqID = "e2e-sampling-1"

	// bigResponseSize: 2 MiB, comfortably larger than the 1 MiB audit-detail bound
	// (proves forwarding isn't truncated by audit capping) yet under the proxy's 4 MiB cap.
	bigResponseSize = 2 << 20
)

// rpcMsg is a JSON-RPC 2.0 envelope. id is kept as RawMessage so the original
// JSON type (number, string, null) round-trips unchanged.
type rpcMsg struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *rpcError        `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (m *rpcMsg) isRequest() bool      { return m.ID != nil && m.Method != "" }
func (m *rpcMsg) isNotification() bool { return m.ID == nil && m.Method != "" }

// ─────────────────────────────────────────────────────────────────────────────
// Catalog: tools, resources, prompts, resource templates.
//
// Deliberately includes entries the e2e policy does NOT permit (write_file,
// secret_tool, file:///data/secret.txt, internal_secret_prompt) so the host
// can assert the proxy's */list filtering excludes them.
// ─────────────────────────────────────────────────────────────────────────────

type toolDef struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

func strSchema(props ...string) map[string]interface{} {
	properties := map[string]interface{}{}
	for _, p := range props {
		properties[p] = map[string]interface{}{"type": "string"}
	}
	return map[string]interface{}{
		"type":       "object",
		"properties": properties,
		"required":   props,
	}
}

var toolList = []toolDef{
	{Name: "read_file", Description: "Read a file (allowedValues /reports/*).", InputSchema: strSchema("path")},
	{Name: "read_any_report", Description: "Read a report at any depth (allowedValues /reports/**).", InputSchema: strSchema("path")},
	{Name: "write_file", Description: "Write a file — absent from policy, denied by default.", InputSchema: strSchema("path", "content")},
	{Name: "query_db", Description: "Run SQL (allowedOperations SELECT).", InputSchema: strSchema("query")},
	{Name: "read_doc", Description: "Read a document (allowedExtensions .csv/.txt).", InputSchema: strSchema("path")},
	{Name: "send_email", Description: "Send email (recipientDomain example.com).", InputSchema: strSchema("to", "subject", "body")},
	{Name: "read_credentials", Description: "Read a credential — arms the sequenceBlock.", InputSchema: strSchema("name")},
	{Name: "write_external", Description: "Write to an external sink (sequenceBlock after read_credentials).", InputSchema: strSchema("url", "data")},
	{Name: "rate_limited", Description: "Rate-limited tool (maxCalls 2/window).", InputSchema: strSchema("n")},
	{Name: "time_gated", Description: "Time-gated tool (timeWindow notAfter in the past).", InputSchema: strSchema("x")},
	{Name: "get_secret_record", Description: "Return a record with sensitive fields (redactFields).", InputSchema: strSchema("id")},
	{Name: "get_malformed", Description: "Return JSON-looking but invalid text (redactFields passes it through; residual).", InputSchema: strSchema("id")},
	{Name: "get_plaintext", Description: "Return free-form text under a redactFields directive.", InputSchema: strSchema("id")},
	{Name: "trigger_sampling", Description: "Ask the host to sample (server-initiated sampling/createMessage).", InputSchema: strSchema("prompt")},
	{Name: "big_response", Description: "Return a multi-megabyte text payload (stresses the response path).", InputSchema: strSchema("x")},
	{Name: "secret_tool", Description: "Absent from policy — must be filtered from tools/list.", InputSchema: strSchema("x")},
}

type resourceDef struct {
	URI      string `json:"uri"`
	Name     string `json:"name"`
	MIMEType string `json:"mimeType,omitempty"`
}

var resourceList = []resourceDef{
	{URI: "file:///data/reports/q3.pdf", Name: "Q3 report", MIMEType: "application/pdf"},
	{URI: "file:///data/reports/q4.pdf", Name: "Q4 report", MIMEType: "application/pdf"},
	{URI: "file:///data/live/metrics", Name: "Live metrics", MIMEType: "text/plain"},
	{URI: "db://warehouse/orders", Name: "Orders table", MIMEType: "application/json"},
	{URI: "file:///data/secret.txt", Name: "Secret file — must be filtered", MIMEType: "text/plain"},
	{URI: "db://warehouse/secret", Name: "Secret table — must be filtered", MIMEType: "application/json"},
}

type templateDef struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name"`
}

var templateList = []templateDef{
	{URITemplate: "file:///data/reports/{name}", Name: "Report by name"},
}

type promptDef struct {
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	Arguments   []map[string]interface{} `json:"arguments,omitempty"`
}

var promptList = []promptDef{
	{Name: "code_review", Description: "Review a code change."},
	{Name: "summarize_doc", Description: "Summarize a document."},
	{Name: "summarize_pr", Description: "Summarize a pull request."},
	{Name: "internal_secret_prompt", Description: "Privileged prompt — must be filtered from prompts/list."},
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool dispatch — returns a tools/call result map, or an rpcError for an
// unknown tool. conn is non-nil only on stdio, needed for trigger_sampling's
// server-initiated round-trip (unsupported on HTTP, which reports "skipped-http").
// ─────────────────────────────────────────────────────────────────────────────

func textResult(text string) map[string]interface{} {
	return map[string]interface{}{
		"content": []map[string]interface{}{{"type": "text", "text": text}},
		"isError": false,
	}
}

func toolCallResult(name string, args map[string]interface{}, conn *stdioConn) (map[string]interface{}, *rpcError) {
	switch name {
	case "read_file", "read_any_report":
		path, _ := args["path"].(string)
		return textResult(fmt.Sprintf("[mock] Contents of %s:\nRevenue: $12,400,000\n(end of %s)", path, path)), nil

	case "write_file":
		path, _ := args["path"].(string)
		content, _ := args["content"].(string)
		return textResult(fmt.Sprintf("[mock] Wrote %d bytes to %s", len(content), path)), nil

	case "query_db":
		query, _ := args["query"].(string)
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(query)), "SELECT") {
			return textResult("[mock] id | name | value\n 1 | revenue_q3 | 12400000\n(1 row)"), nil
		}
		return textResult(fmt.Sprintf("[mock] Executed: %s (1 row affected)", query)), nil

	case "read_doc":
		path, _ := args["path"].(string)
		return textResult(fmt.Sprintf("[mock] document %s\ncol_a,col_b\n1,2", path)), nil

	case "send_email":
		to, _ := args["to"].(string)
		return textResult(fmt.Sprintf("[mock] queued email to %s", to)), nil

	case "read_credentials":
		nm, _ := args["name"].(string)
		return textResult(fmt.Sprintf("[mock] credential %q = (redacted by upstream)", nm)), nil

	case "write_external":
		url, _ := args["url"].(string)
		return textResult(fmt.Sprintf("[mock] posted data to %s", url)), nil

	case "rate_limited":
		n, _ := args["n"].(string)
		return textResult("[mock] rate_limited ok n=" + n), nil

	case "time_gated":
		return textResult("[mock] time_gated ok"), nil

	case "get_secret_record":
		// Sensitive fields live in BOTH the text-content JSON and structuredContent
		// so the host can assert redactFields applies to both surfaces.
		payload := `{"name":"alice","email":"alice@example.com","ssn":"123-45-6789","nested":{"token":"tok_abc123","keep":"yes"}}`
		return map[string]interface{}{
			"content":           []map[string]interface{}{{"type": "text", "text": payload}},
			"structuredContent": map[string]interface{}{"api_key": "sk-live-9999", "public": "ok"},
			"isError":           false,
		}, nil

	case "get_malformed":
		// Looks like JSON (leading '{') but is truncated/invalid. redactFields only
		// acts on cleanly-parseable JSON, so this passes through unredacted (accepted residual).
		return textResult(`{"secret":"x", "oops"`), nil

	case "get_plaintext":
		// Free-form text under a redactFields directive: no JSON keys to redact.
		return textResult("Revenue: $12,400,000 (plain text, secret=hunter2)"), nil

	case "trigger_sampling":
		return triggerSampling(conn), nil

	case "big_response":
		// Forwarded intact so the host can assert the proxy doesn't truncate big
		// payloads and that audit-detail capping is independent of the forwarded body.
		return textResult(strings.Repeat("A", bigResponseSize)), nil

	case "secret_tool":
		return textResult("[mock] secret_tool ran"), nil

	default:
		return nil, &rpcError{Code: -32602, Message: "unknown tool: " + name}
	}
}

// triggerSampling emits a server-initiated sampling/createMessage request and
// blocks for the proxy's verdict, returning a deterministic marker
// ("sampling:allowed"/"sampling:denied") so the async decision is assertable
// without timing races.
func triggerSampling(conn *stdioConn) map[string]interface{} {
	if conn == nil {
		// HTTP: full sampling round-trip is unsupported upstream (documented limitation).
		return textResult("sampling:skipped-http")
	}

	id := json.RawMessage(`"` + samplingReqID + `"`)
	conn.writeMsg(rpcMsg{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "sampling/createMessage",
		Params: json.RawMessage(`{"messages":[{"role":"user","content":{"type":"text","text":"e2e ping"}}],` +
			`"maxTokens":16,"systemPrompt":"e2e"}`),
	})

	// Guard on the id rather than classifying the first line unconditionally, so a
	// stray notification or out-of-band line can't be mistaken for our verdict.
	want := `"` + samplingReqID + `"`
	for {
		line, ok := conn.readLine()
		if !ok {
			return textResult("sampling:no-response")
		}
		var reply rpcMsg
		if err := json.Unmarshal(line, &reply); err != nil {
			continue // skip anything unparseable
		}
		if reply.ID == nil || string(*reply.ID) != want {
			continue // not the verdict for our request
		}
		if reply.Error != nil {
			return textResult("sampling:denied")
		}
		return textResult("sampling:allowed")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Method handling shared by both transports. conn is non-nil only on stdio.
// ─────────────────────────────────────────────────────────────────────────────

func initializeResult() map[string]interface{} {
	return map[string]interface{}{
		"protocolVersion": mcpProtocolVersion,
		"capabilities": map[string]interface{}{
			"tools":     map[string]interface{}{"listChanged": true},
			"resources": map[string]interface{}{"subscribe": true, "listChanged": true},
			"prompts":   map[string]interface{}{"listChanged": true},
			"sampling":  map[string]interface{}{},
			"logging":   map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{"name": serverName, "version": serverVersion},
	}
}

// dispatch returns (result, rpcError) for a request, exactly one non-nil;
// never called for notifications.
//
// The two revision gates run BEFORE the method switch so no handler can serve a request the
// running revision should have refused: a declaring leg needs the per-request declaration,
// and each revision has its own method set (see revision.go).
func dispatch(msg *rpcMsg, conn *stdioConn) (interface{}, *rpcError) {
	if e := checkDeclaration(msg); e != nil {
		return nil, e
	}
	if e := checkMethodExists(msg.Method); e != nil {
		return nil, e
	}
	result, e := dispatchMethod(msg, conn)
	if e != nil {
		return nil, e
	}
	return stampResultShape(msg.Method, result), nil
}

func dispatchMethod(msg *rpcMsg, conn *stdioConn) (interface{}, *rpcError) {
	switch msg.Method {
	case "initialize":
		return initializeResult(), nil

	case "server/discover":
		return discoverResult(), nil

	case "tools/list":
		return map[string]interface{}{"tools": toolList}, nil

	case "tools/call":
		var p struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(msg.Params, &p); err != nil {
			return nil, &rpcError{Code: -32602, Message: "invalid tools/call params"}
		}
		if p.Arguments == nil {
			p.Arguments = map[string]interface{}{}
		}
		return toolCallResult(p.Name, p.Arguments, conn)

	case "resources/list":
		return map[string]interface{}{"resources": resourceList}, nil

	case "resources/templates/list":
		return map[string]interface{}{"resourceTemplates": templateList}, nil

	case "resources/read":
		var p struct {
			URI string `json:"uri"`
		}
		_ = json.Unmarshal(msg.Params, &p)
		return map[string]interface{}{
			"contents": []map[string]interface{}{
				{"uri": p.URI, "mimeType": "text/plain", "text": "[mock] contents of " + p.URI},
			},
		}, nil

	case "resources/subscribe":
		return map[string]interface{}{}, nil

	case "prompts/list":
		return map[string]interface{}{"prompts": promptList}, nil

	case "prompts/get":
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(msg.Params, &p)
		return map[string]interface{}{
			"description": "prompt " + p.Name,
			"messages": []map[string]interface{}{
				{"role": "user", "content": map[string]interface{}{"type": "text", "text": "[mock] prompt " + p.Name}},
			},
		}, nil

	case "ping":
		return map[string]interface{}{}, nil

	case "completion/complete":
		return map[string]interface{}{
			"completion": map[string]interface{}{"values": []string{"alpha", "beta"}, "total": 2},
		}, nil

	default:
		return nil, &rpcError{Code: -32601, Message: "method not found: " + msg.Method}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// stdio transport
// ─────────────────────────────────────────────────────────────────────────────

type stdioConn struct {
	scanner *bufio.Scanner
	mu      sync.Mutex
	out     *bufio.Writer
}

func newStdioConn() *stdioConn {
	return newStdioConnIO(os.Stdin, os.Stdout)
}

func newStdioConnIO(r io.Reader, w io.Writer) *stdioConn {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	return &stdioConn{scanner: sc, out: bufio.NewWriter(w)}
}

func (c *stdioConn) writeMsg(msg rpcMsg) { //nolint:gocritic // hugeParam: rpcMsg passed by value to mirror cmd/eunox convention.
	c.mu.Lock()
	defer c.mu.Unlock()
	data, _ := json.Marshal(msg)
	_, _ = c.out.Write(data)
	_ = c.out.WriteByte('\n')
	_ = c.out.Flush()
}

// readLine returns the next raw JSON-RPC line from stdin, or ok=false at EOF.
func (c *stdioConn) readLine() ([]byte, bool) {
	for c.scanner.Scan() {
		line := c.scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		// Copy: scanner reuses its buffer on the next Scan.
		out := make([]byte, len(line))
		copy(out, line)
		return out, true
	}
	return nil, false
}

func runStdio() {
	runStdioLoop(newStdioConn())
}

func runStdioLoop(conn *stdioConn) {
	for {
		line, ok := conn.readLine()
		if !ok {
			return
		}
		var msg rpcMsg
		if err := json.Unmarshal(line, &msg); err != nil {
			continue
		}
		if msg.isNotification() {
			continue // notifications get no response
		}
		if !msg.isRequest() {
			continue // a response to our sampling request, already consumed inline
		}
		result, rerr := dispatch(&msg, conn)
		if rerr != nil {
			conn.writeMsg(rpcMsg{JSONRPC: "2.0", ID: msg.ID, Error: rerr})
			continue
		}
		raw, _ := json.Marshal(result)
		conn.writeMsg(rpcMsg{JSONRPC: "2.0", ID: msg.ID, Result: raw})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP transport (MCP Streamable HTTP) — mirrors demo/mock-mcp-server.
// ─────────────────────────────────────────────────────────────────────────────

type httpServer struct {
	mu       sync.RWMutex
	sessions map[string]struct{}
}

func newHTTPServer() *httpServer { return &httpServer{sessions: make(map[string]struct{})} }

func newSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func (s *httpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/mcp" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPost:
		s.handlePost(w, r)
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
	case http.MethodDelete:
		if sid := r.Header.Get(sessionHeader); sid != "" {
			s.mu.Lock()
			delete(s.sessions, sid)
			s.mu.Unlock()
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *httpServer) handlePost(w http.ResponseWriter, r *http.Request) {
	var msg rpcMsg
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&msg); err != nil {
		http.Error(w, "invalid JSON-RPC body", http.StatusBadRequest)
		return
	}
	// A POST body is exactly one JSON value; decoding a second and requiring io.EOF
	// catches trailing garbage before we dispatch or allocate a session off it.
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		http.Error(w, "invalid JSON-RPC body: trailing data after JSON-RPC message", http.StatusBadRequest)
		return
	}

	// Only an initialize REQUEST (with an id) creates a session; an id-less
	// initialize is a notification and per JSON-RPC/MCP must not mutate state,
	// so it falls through to the session check below instead.
	if msg.Method == "initialize" && msg.isRequest() {
		sid := newSessionID()
		s.mu.Lock()
		s.sessions[sid] = struct{}{}
		s.mu.Unlock()
		w.Header().Set(sessionHeader, sid)
		writeHTTPResult(w, msg.ID, initializeResult())
		return
	}

	// Validating the session before the notification fast path means a proxy that
	// drops the upstream session header on a forwarded notification gets caught.
	sid := r.Header.Get(sessionHeader)
	if sid == "" {
		http.Error(w, "Mcp-Session-Id header required", http.StatusBadRequest)
		return
	}
	s.mu.RLock()
	_, ok := s.sessions[sid]
	s.mu.RUnlock()
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	// A notification (or any non-request) carries no id and expects no response.
	if msg.isNotification() || !msg.isRequest() {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	result, rerr := dispatch(&msg, nil)
	if rerr != nil {
		writeHTTPError(w, msg.ID, rerr.Code, rerr.Message)
		return
	}
	writeHTTPResult(w, msg.ID, result)
}

func writeHTTPResult(w http.ResponseWriter, id *json.RawMessage, result interface{}) {
	res, _ := json.Marshal(result)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rpcMsg{JSONRPC: "2.0", ID: id, Result: res})
}

func writeHTTPError(w http.ResponseWriter, id *json.RawMessage, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rpcMsg{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}})
}

func main() {
	transport := flag.String("transport", "stdio", `transport: "stdio" or "http"`)
	port := flag.String("port", "8090", "listen port (http transport)")
	revision := flag.String("protocol-version", revisionHandshake,
		`MCP revision to speak: "2025-11-25" or "2026-07-28"`)
	flag.Parse()

	// Fail closed on an unknown revision rather than falling through to a default: a matrix
	// cell that silently ran the wrong revision would report a pass for the pair it did not
	// exercise, which is the one failure this harness cannot detect from its own output.
	if *revision != revisionHandshake && *revision != revisionDeclaring {
		fmt.Fprintf(os.Stderr, "unknown --protocol-version %q (want %s|%s)\n",
			*revision, revisionHandshake, revisionDeclaring)
		os.Exit(2)
	}
	serverRevision = *revision

	switch *transport {
	case "stdio":
		runStdio()
	case "http":
		log.Printf("e2e mock-server (http) listening on :%s", *port)            //nolint:gosec // G706: port is a local flag used only for logging.
		if err := http.ListenAndServe(":"+*port, newHTTPServer()); err != nil { //nolint:gosec // G114: demo server; per-request timeouts not required.
			log.Fatalf("mock-server: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown --transport %q (want stdio|http)\n", *transport)
		os.Exit(2)
	}
}
