// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// mock-mcp-server-stdio is the stdio-transport twin of mock-mcp-server: same
// three tools and deterministic responses, but newline-delimited JSON-RPC over
// stdin/stdout, so it can run as a local subprocess upstream for eunox.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

const (
	serverName    = "mock-mcp-server-stdio"
	serverVersion = "0.1.0"
)

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

func writeMsg(msg rpcMsg) { //nolint:gocritic // hugeParam: rpcMsg passed by value intentionally (mirrors cmd/eunox convention)
	data, _ := json.Marshal(msg)
	_, _ = fmt.Fprintf(os.Stdout, "%s\n", data)
}

func writeResult(id *json.RawMessage, result interface{}) {
	raw, _ := json.Marshal(result)
	writeMsg(rpcMsg{JSONRPC: "2.0", ID: id, Result: raw})
}

func writeError(id *json.RawMessage, code int, message string) {
	writeMsg(rpcMsg{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: message},
	})
}

type toolDef struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

var toolList = []toolDef{
	{
		Name:        "read_file",
		Description: "Read the contents of a file at the given path.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Absolute file path, e.g. /reports/q3.pdf",
				},
			},
			"required": []string{"path"},
		},
	},
	{
		Name:        "write_file",
		Description: "Write content to a file at the given path.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Absolute file path to write.",
				},
				"content": map[string]interface{}{
					"type":        "string",
					"description": "Content to write.",
				},
			},
			"required": []string{"path", "content"},
		},
	},
	{
		Name:        "query_db",
		Description: "Execute a SQL query against the demo database.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type":        "string",
					"description": "SQL statement to execute.",
				},
			},
			"required": []string{"query"},
		},
	},
}

// requiredStringArgs is checked because dispatchTool substitutes empty strings
// on a failed type assertion, which would otherwise let the mock silently
// violate its own advertised required-argument schema.
var requiredStringArgs = map[string][]string{
	"read_file":  {"path"},
	"write_file": {"path", "content"},
	"query_db":   {"query"},
}

// validateToolArgs returns a non-empty message when args doesn't satisfy name's
// advertised required string arguments; an unknown tool validates clean here
// and is reported separately by handle.
func validateToolArgs(name string, args map[string]interface{}) string {
	for _, field := range requiredStringArgs[name] {
		v, ok := args[field]
		if !ok || v == nil {
			return fmt.Sprintf("invalid params: missing required argument %q", field)
		}
		if _, ok := v.(string); !ok {
			return fmt.Sprintf("invalid params: argument %q must be a string", field)
		}
	}
	return ""
}

func dispatchTool(name string, args map[string]interface{}) string {
	switch name {
	case "read_file":
		path, _ := args["path"].(string)
		return fmt.Sprintf(
			"[mock] Contents of %s:\n\n"+
				"Q3 Financial Summary\n"+
				"Revenue:  $12,400,000\n"+
				"Expenses: $ 8,900,000\n"+
				"EBITDA:   $ 3,500,000\n"+
				"(end of mock file %s)", path, path)
	case "write_file":
		path, _ := args["path"].(string)
		content, _ := args["content"].(string)
		return fmt.Sprintf("[mock] Wrote %d bytes to %s", len(content), path)
	case "query_db":
		query, _ := args["query"].(string)
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(query)), "SELECT") {
			return "[mock] Query result:\n\n" +
				"id | name        | value\n" +
				"---|-------------|----------\n" +
				" 1 | revenue_q3  | 12400000\n" +
				" 2 | revenue_q4  | 15800000\n" +
				" 3 | expenses_q3 |  8900000\n" +
				"\n(3 rows)"
		}
		return fmt.Sprintf("[mock] Executed: %s  (1 row affected)", query)
	default:
		return ""
	}
}

func handle(msg rpcMsg) { //nolint:gocritic // hugeParam: rpcMsg passed by value intentionally (mirrors cmd/eunox convention)
	switch {
	case msg.isNotification():
		// Must precede the method branches: an id-less "initialize" is a notification
		// and gets no response (JSON-RPC servers must never reply to notifications).
	case msg.Method == openerMethod():
		// The opener is exempt from the declaration check on the handshake revision only,
		// where it IS the negotiation. On the declaring revision it is an ordinary request
		// and carries its declaration like any other, so the check runs below.
		if errMsg := checkDeclaration(msg.Params); errMsg != "" {
			writeError(msg.ID, -32600, errMsg)
			return
		}
		writeResult(msg.ID, openerResult())
	case msg.Method == "tools/list":
		if errMsg := checkDeclaration(msg.Params); errMsg != "" {
			writeError(msg.ID, -32600, errMsg)
			return
		}
		writeResult(msg.ID, withListCaching(map[string]interface{}{"tools": toolList}))
	case msg.Method == "tools/call":
		if errMsg := checkDeclaration(msg.Params); errMsg != "" {
			writeError(msg.ID, -32600, errMsg)
			return
		}
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			writeError(msg.ID, -32602, "invalid tools/call params")
			return
		}
		if params.Arguments == nil {
			params.Arguments = map[string]interface{}{}
		}
		if errMsg := validateToolArgs(params.Name, params.Arguments); errMsg != "" {
			writeError(msg.ID, -32602, errMsg)
			return
		}
		text := dispatchTool(params.Name, params.Arguments)
		if text == "" {
			writeError(msg.ID, -32602, "unknown tool: "+params.Name)
			return
		}
		writeResult(msg.ID, withResultShape(map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": text},
			},
			"isError": false,
		}))
	default:
		if msg.isRequest() {
			writeError(msg.ID, -32601, "method not found: "+msg.Method)
		}
	}
}

func main() {
	revision := flag.String("protocol-version", revisionHandshake,
		"MCP protocol revision to serve ("+revisionHandshake+" or "+revisionDeclaring+")")
	flag.Parse()
	parsed, err := parseProtocolRevision(*revision)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", serverName, err)
		os.Exit(2)
	}
	protocolRevision = parsed

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4<<20), 4<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var msg rpcMsg
		if err := json.Unmarshal(line, &msg); err != nil {
			continue
		}
		handle(msg)
	}
}
