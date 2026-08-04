// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package main is the MCP tool server for the OPA-comparison demo, exposing
// all tools across scenarios 1-3 so both eunox and the OPA sidecar can be
// exercised against the same upstream.
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	sessionHeader      = "Mcp-Session-Id"
	mcpProtocolVersion = "2025-11-25"
	serverName         = "opa-comparison-server"
)

// rpcMsg is the minimal JSON-RPC 2.0 envelope used for both requests and responses.
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

type server struct {
	mu       sync.RWMutex
	sessions map[string]struct{}
}

func newServer() *server {
	return &server{sessions: make(map[string]struct{})}
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/mcp" {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodPost:
		s.handlePost(w, r)
	case http.MethodDelete:
		s.handleDelete(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handlePost(w http.ResponseWriter, r *http.Request) {
	var msg rpcMsg
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&msg); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// A POST body is exactly one JSON value; decoding a second and requiring io.EOF
	// catches trailing garbage before we dispatch or allocate a session off it.
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		http.Error(w, "bad request: trailing data after JSON-RPC message", http.StatusBadRequest)
		return
	}

	// Notifications (no id) — require an established session before
	// acknowledging, same as tools/list and tools/call.
	if msg.ID == nil {
		if !s.requireSession(w, r) {
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch msg.Method {
	case "initialize":
		s.handleInitialize(w, msg)
	case "tools/list":
		if !s.requireSession(w, r) {
			return
		}
		handleToolsList(w, msg)
	case "tools/call":
		if !s.requireSession(w, r) {
			return
		}
		handleToolsCall(w, msg)
	default:
		writeMsg(w, rpcMsg{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Error:   &rpcError{Code: -32601, Message: fmt.Sprintf("method not found: %s", msg.Method)},
		})
	}
}

func (s *server) handleInitialize(w http.ResponseWriter, msg rpcMsg) { //nolint:gocritic // hugeParam: rpcMsg passed by value intentionally
	sid := newSessionID()
	s.mu.Lock()
	s.sessions[sid] = struct{}{}
	s.mu.Unlock()

	w.Header().Set(sessionHeader, sid)
	writeMsg(w, rpcMsg{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result: mustMarshal(map[string]interface{}{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]interface{}{},
			"serverInfo":      map[string]interface{}{"name": serverName, "version": "0.1.0"},
		}),
	})
}

func (s *server) handleDelete(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get(sessionHeader)
	if sid == "" {
		http.Error(w, "missing session", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	delete(s.sessions, sid)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) requireSession(w http.ResponseWriter, r *http.Request) bool {
	sid := r.Header.Get(sessionHeader)
	if sid == "" {
		http.Error(w, "missing session", http.StatusBadRequest)
		return false
	}
	s.mu.RLock()
	_, ok := s.sessions[sid]
	s.mu.RUnlock()
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return false
	}
	return true
}

type toolDef struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

func allTools() []toolDef {
	str := func(desc string) map[string]interface{} {
		return map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{"type": "string", "description": desc},
			},
			"required": []string{"path"},
		}
	}
	return []toolDef{
		// Scenario 1 — credential exfiltration / externalwrite
		{
			Name:        "read_credentials",
			Description: "Read credentials for a named service from the secrets vault.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"service": map[string]interface{}{"type": "string", "description": "Service name"},
				},
				"required": []string{"service"},
			},
		},
		{
			Name:        "write_external",
			Description: "POST a payload to an external URL.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url":     map[string]interface{}{"type": "string"},
					"payload": map[string]interface{}{"type": "string"},
				},
				"required": []string{"url", "payload"},
			},
		},
		// Scenario 2 — 10 path-gated file/secret tools
		{Name: "read_file", Description: "Read a file.", InputSchema: str("File path")},
		{Name: "write_file", Description: "Write a file.", InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path":    map[string]interface{}{"type": "string"},
				"content": map[string]interface{}{"type": "string"},
			},
			"required": []string{"path", "content"},
		}},
		{Name: "read_config", Description: "Read a config file.", InputSchema: str("Config path")},
		{Name: "update_config", Description: "Update a config value.", InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path":  map[string]interface{}{"type": "string"},
				"key":   map[string]interface{}{"type": "string"},
				"value": map[string]interface{}{"type": "string"},
			},
			"required": []string{"path", "key", "value"},
		}},
		{Name: "read_log", Description: "Read a log file.", InputSchema: str("Log path")},
		{Name: "delete_file", Description: "Delete a file.", InputSchema: str("File path")},
		{Name: "stat_file", Description: "Stat a file.", InputSchema: str("File path")},
		{Name: "read_secret", Description: "Read a secret.", InputSchema: str("Secret path")},
		{Name: "write_secret", Description: "Write a secret.", InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path":  map[string]interface{}{"type": "string"},
				"value": map[string]interface{}{"type": "string"},
			},
			"required": []string{"path", "value"},
		}},
		{Name: "read_backup", Description: "Read a backup archive.", InputSchema: str("Backup path")},
		// Scenario 3 — short-lived cloud tokens
		{
			Name:        "get_aws_token",
			Description: "Assume an AWS IAM role and return temporary credentials.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"role": map[string]interface{}{"type": "string", "description": "IAM role ARN"},
				},
				"required": []string{"role"},
			},
		},
		{
			Name:        "get_github_token",
			Description: "Generate a GitHub App installation token.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"scope": map[string]interface{}{"type": "string", "description": "Permission scope"},
				},
				"required": []string{"scope"},
			},
		},
	}
}

func handleToolsList(w http.ResponseWriter, msg rpcMsg) { //nolint:gocritic // hugeParam: rpcMsg passed by value intentionally
	writeMsg(w, rpcMsg{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result:  mustMarshal(map[string]interface{}{"tools": allTools()}),
	})
}

func handleToolsCall(w http.ResponseWriter, msg rpcMsg) { //nolint:gocritic // hugeParam: rpcMsg passed by value intentionally
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		writeMsg(w, rpcMsg{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Error:   &rpcError{Code: -32602, Message: "invalid params"},
		})
		return
	}

	text := dispatchTool(params.Name, params.Arguments)
	if text == "" {
		writeMsg(w, rpcMsg{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Error:   &rpcError{Code: -32601, Message: fmt.Sprintf("unknown tool: %s", params.Name)},
		})
		return
	}

	writeMsg(w, rpcMsg{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result: mustMarshal(map[string]interface{}{
			"content": []map[string]interface{}{{"type": "text", "text": text}},
			"isError": false,
		}),
	})
}

// dispatchTool executes the named tool and returns a text result, or "" if unknown.
func dispatchTool(name string, args map[string]interface{}) string {
	str := func(key string) string {
		if v, ok := args[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}

	switch name {
	// Scenario 1
	case "read_credentials":
		svc := str("service")
		return fmt.Sprintf(
			`{"service":%q,"access_key_id":"AKIA_FAKE_KEY_FOR_%s","secret_access_key":"FAKE_SECRET_DO_NOT_USE","session_token":"FAKE_TOKEN"}`,
			svc, strings.ToUpper(svc),
		)
	case "write_external":
		return fmt.Sprintf("POST to %q accepted; payload forwarded (%d bytes)",
			str("url"), len(str("payload")))

	// Scenario 2 — path-gated tools
	case "read_file":
		return fmt.Sprintf("[read_file] contents of %q (1024 bytes, simulated)", str("path"))
	case "write_file":
		return fmt.Sprintf("[write_file] wrote %d bytes to %q", len(str("content")), str("path"))
	case "read_config":
		return fmt.Sprintf("[read_config] config at %q: {\"key\":\"value\"}", str("path"))
	case "update_config":
		return fmt.Sprintf("[update_config] set %q=%q in %q", str("key"), str("value"), str("path"))
	case "read_log":
		return fmt.Sprintf("[read_log] last 100 lines of %q (simulated)", str("path"))
	case "delete_file":
		return fmt.Sprintf("[delete_file] deleted %q", str("path"))
	case "stat_file":
		return fmt.Sprintf("[stat_file] %q: size=4096 mode=0644 mtime=2026-01-01T00:00:00Z", str("path"))
	case "read_secret":
		return fmt.Sprintf("[read_secret] secret at %q: FAKE_SECRET_VALUE_DO_NOT_USE", str("path"))
	case "write_secret":
		return fmt.Sprintf("[write_secret] stored secret at %q", str("path"))
	case "read_backup":
		return fmt.Sprintf("[read_backup] backup archive at %q: 512 MiB (simulated)", str("path"))

	// Scenario 3 — short-lived tokens
	case "get_aws_token":
		return fmt.Sprintf(
			`{"role":%q,"access_key_id":"ASIA_FAKE_STS_KEY","secret_access_key":"FAKE_STS_SECRET","session_token":"FAKE_STS_TOKEN","expires_in":900}`,
			str("role"),
		)
	case "get_github_token":
		return fmt.Sprintf(
			`{"scope":%q,"token":"ghs_FAKE_GITHUB_TOKEN_DO_NOT_USE","expires_in":600}`,
			str("scope"),
		)
	}
	return ""
}

// ── helpers ──────────────────────────────────────────────────────────────────

func writeMsg(w http.ResponseWriter, msg rpcMsg) { //nolint:gocritic // hugeParam: rpcMsg passed by value intentionally
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(msg); err != nil {
		log.Printf("writeMsg: encode error: %v", err)
	}
}

func mustMarshal(v interface{}) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("mustMarshal: %v", err))
	}
	return b
}

// newSessionID must be unguessable: the session header gates access to a
// client's server-side session, so a predictable counter would let a peer
// address another client's live session. Matches demo/mock-mcp-server.
func newSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9090"
	}
	addr := ":" + port
	log.Printf("opa-comparison-server listening on %s", addr) //nolint:gosec // G706: port from env, used only for logging
	httpSrv := &http.Server{
		Addr:         addr,
		Handler:      newServer(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
