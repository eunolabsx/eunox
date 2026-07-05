// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Wiring smoke test for the gateway entrypoint (serveHTTPGateway). The unit
// tests cover the subcommand helpers and error paths in isolation; this boots
// the real HTTP gateway in-process against an in-process HTTP mock upstream and
// drives one allowed and one denied tools/call end to end — config load ->
// BuildRoutes -> ManifestPDP -> HTTPProxy -> upstream client -> audit sink. Its
// job is to catch a regression in that assembly (a mis-wired PDP, a route that
// forwards without enforcing, a broken session handshake) that the per-function
// tests cannot see.
//
// The upstream is an httptest server rather than a re-exec'd stdio subprocess on
// purpose: a subprocess test binary writes the framework's "PASS"/"ok" footer to
// its stdout, which is the same stream that carries the stdio MCP protocol, so a
// persistent gateway session reading that stdout ingests the footer as a
// corrupt JSON-RPC frame. An in-process HTTP upstream has no such stream to
// pollute and is fully hermetic.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/internal/transport"
	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// smokeManifestYAML allows tool:read_file (default enforce posture) and, by
// omitting write_file, denies it by default — the fail-closed stance the proxy
// exists to enforce. serverVersion is left unpinned so the upstream's version
// does not trip a drift warning.
const smokeManifestYAML = `schemaVersion: "0.1"
name: smoke
version: "1.0.0"
capabilities:
  - target: "tool:read_file"
    actions: ["call"]
`

// TestServeHTTPGateway_SmokeAllowAndDeny boots serveHTTPGateway against an
// in-process HTTP upstream and asserts that an allowed call is forwarded and a
// denied call is failed closed with a structured JSON-RPC error before it ever
// reaches the upstream.
func TestServeHTTPGateway_SmokeAllowAndDeny(t *testing.T) {
	dir := t.TempDir()
	manifestPath := mustWriteFile(t, dir, "policy.yaml", smokeManifestYAML)

	// In-process MCP upstream: answers initialize, tools/list (read_file +
	// write_file, so the drift probe is clean), and tools/call. It records every
	// request, so we can prove the denied call was blocked before forwarding.
	upstream := newFakeUpstreamWithTools([]mcp.ToolEntry{{Name: "read_file"}, {Name: "write_file"}})
	usrv := httptest.NewServer(upstream)
	t.Cleanup(usrv.Close)

	port := reserveLoopbackPort(t)
	cfgYAML := fmt.Sprintf(`schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: %d
upstreams:
  - name: integ
    transport: http
    upstreamUrl: %q
    policy: [%q]
`, port, usrv.URL, manifestPath)
	cfgPath := mustWriteFile(t, dir, "eunox.yaml", cfgYAML)

	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadGatewayConfig: %v", err)
	}

	// A real sink so the allow/deny records exercise the audit-write wiring too;
	// its contents are the audit package's concern, so we only require it opens.
	sink, err := audit.Open(
		filepath.Join(dir, "audit.jsonl"),
		filepath.Join(dir, "audit.key"),
		0, 0,
		audit.WithIdentity(pdp.AuditIdentityFromContext),
	)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	defer func() { _ = sink.Close() }()

	pf := proxyFlags{
		shutdownMs:        2000,
		upstreamTimeoutMs: 5000,
		sessionID:         "smoke",
		configPath:        cfgPath,
		controlTokenPath:  filepath.Join(dir, "control.token"),
	}

	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- serveHTTPGateway(ctx, cfg, sink, callcounter.NewInMemory(), killswitch.NewInMemory(), pf)
	}()
	// Tear the gateway down even if an assertion below fails early, and confirm a
	// graceful return (Serve returns nil once its context is cancelled).
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("serveHTTPGateway returned %v, want nil on context cancel", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("serveHTTPGateway did not return within 10s of context cancel")
		}
	})

	endpoint := fmt.Sprintf("http://127.0.0.1:%d/mcp/integ", port)
	client := &http.Client{Timeout: 15 * time.Second}
	reqCtx := context.Background()

	// Initialize, retrying until the listener (bound in the goroutine just
	// launched) is accepting. The gateway answers initialize itself and returns
	// the session id in the response header.
	var sessID string
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, hdr, err := transport.DoMCPHTTP(reqCtx, client, endpoint, mcpRequest(1, "initialize", map[string]interface{}{
			"protocolVersion": transport.MCPProtocolVersion,
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "smoke", "version": "1.0.0"},
		}), "", "")
		if err == nil && resp.Error == nil {
			sessID = hdr.Get(transport.SessionHeader)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway did not become ready within 15s: err=%v rpcErr=%+v", err, resp.Error)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if sessID == "" {
		t.Fatal("initialize returned an empty session id")
	}

	// Allowed: read_file is in the manifest, so the call is forwarded and the
	// upstream's result comes back with no JSON-RPC error.
	allowResp, _, err := transport.DoMCPHTTP(reqCtx, client, endpoint, mcpRequest(2, "tools/call", map[string]interface{}{
		"name":      "read_file",
		"arguments": map[string]interface{}{},
	}), sessID, "")
	if err != nil {
		t.Fatalf("allowed tools/call: transport error: %v", err)
	}
	if allowResp.Error != nil {
		t.Fatalf("read_file should be allowed, got JSON-RPC error: %+v", allowResp.Error)
	}
	if len(allowResp.Result) == 0 {
		t.Fatal("allowed tools/call returned an empty result")
	}

	// Denied: write_file is absent from the manifest, so the proxy fails closed
	// with a structured JSON-RPC error and never forwards to the upstream.
	denyResp, _, err := transport.DoMCPHTTP(reqCtx, client, endpoint, mcpRequest(3, "tools/call", map[string]interface{}{
		"name":      "write_file",
		"arguments": map[string]interface{}{},
	}), sessID, "")
	if err != nil {
		t.Fatalf("denied tools/call: transport error: %v", err)
	}
	if denyResp.Error == nil {
		t.Fatalf("write_file should be denied, got result: %s", string(denyResp.Result))
	}

	// Enforcement actually happened upstream of the wire: exactly one tools/call
	// (the allowed read_file) reached the upstream; the denied write_file was
	// blocked before forwarding, so the upstream never saw a second one.
	if got := upstream.CountByMethod("tools/call"); got != 1 {
		t.Fatalf("upstream tools/call count = %d, want 1 (only the allowed call should be forwarded)", got)
	}
}

// reserveLoopbackPort grabs a free loopback TCP port and releases it for the
// caller to bind. The close->rebind window is theoretically racy but is the
// standard ephemeral-port pattern used elsewhere in the suite, and serveHTTPGateway
// binds an explicit port from config rather than exposing its chosen one.
func reserveLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved port: %v", err)
	}
	return port
}

// mcpRequest builds a JSON-RPC request RPCMsg carrying an integer id.
func mcpRequest(id int, method string, params interface{}) mcp.RPCMsg {
	raw, _ := json.Marshal(params)
	idRaw := json.RawMessage(strconv.Itoa(id))
	return mcp.RPCMsg{JSONRPC: "2.0", ID: &idRaw, Method: method, Params: raw}
}
