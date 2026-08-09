// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/mcp/mcptest"

	"github.com/alicebob/miniredis/v2"
	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	goredis "github.com/redis/go-redis/v9"

	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// build50RuleManifest returns a slice of 50 Constraints for tools named
// tool_00 … tool_49.  Used for worst-case linear-scan benchmarks.
func build50RuleManifest() []capability.Constraint {
	caps := make([]capability.Constraint, 50)
	for i := range caps {
		caps[i] = capability.Constraint{
			Target:  fmt.Sprintf("tool:tool_%02d", i),
			Actions: []string{"call"},
		}
	}
	return caps
}

// benchPDPOnly builds a ManifestPDP with an in-memory kill switch and no
// enforcement engine counters — pure condition evaluation, no I/O.
func benchPDPOnly(b *testing.B, caps ...capability.Constraint) *pdp.ManifestPDP {
	b.Helper()
	manifest := &config.LocalManifest{Name: "bench", Version: "1.0.0", Capabilities: caps}
	engine := enforcement.New()
	ks := killswitch.NewInMemory()
	return pdp.NewManifestPDP(manifest.Capabilities, engine, ks)
}

// newBenchUpstream starts a minimal MCP HTTP server optimized for benchmarks.
// Unlike fakeUpstream, it does not record received requests (no allocation
// growth over time) and always drains request bodies so the HTTP keep-alive
// connection pool is fully utilized.
func newBenchUpstream(b *testing.B) *httptest.Server {
	b.Helper()

	toolResultBytes, _ := json.Marshal(mcptest.ToolCallResult{
		Content: []mcptest.Content{{Type: "text", Text: `{"ok":true}`}},
	})
	toolRespBytes, _ := json.Marshal(mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON("2"),
		Result:  toolResultBytes,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		var msg mcp.RPCMsg
		if err := json.Unmarshal(body, &msg); err != nil {
			http.Error(w, "bad JSON", http.StatusBadRequest)
			return
		}

		switch msg.Method {
		case "initialize":
			initResult, _ := json.Marshal(mcp.InitResult{
				ProtocolVersion: capability.Revision20251125.String(),
				Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
				ServerInfo:      map[string]interface{}{"name": "bench-upstream", "version": "0.1"},
			})
			resp, _ := json.Marshal(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: initResult})
			w.Header().Set(SessionHeader, "bench-upstream-sess")
			w.Header().Set("Content-Type", CTJSON)
			_, _ = w.Write(resp)

		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)

		case "tools/call":
			w.Header().Set("Content-Type", CTJSON)
			_, _ = w.Write(toolRespBytes)

		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	b.Cleanup(srv.Close)
	return srv
}

// benchAuditSink creates a temporary audit sink that writes to a throwaway file
// in b.TempDir() so I/O noise is contained and the dir is cleaned up after.
func benchAuditSink(b *testing.B) *audit.Sink {
	b.Helper()
	dir := b.TempDir()
	s, err := audit.Open(dir+"/bench-audit.jsonl", dir+"/bench-audit.key", 100<<20, 0)
	if err != nil {
		b.Fatalf("open bench audit sink: %v", err)
	}
	b.Cleanup(func() { _ = s.Close() })
	return s
}

// benchJWTPDPContext builds a JWTPDP backed by an in-process JWKS server,
// pre-validates a token to warm the JWKS cache, and returns both the PDP and
// a context carrying valid JWT claims.  The JWKS server is stopped via
// b.Cleanup so callers need not manage its lifecycle.
func benchJWTPDPContext(b *testing.B, inner pdp.PolicyDecisionPoint) (*pdp.JWTPDP, context.Context, string) {
	b.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("generate ECDSA key: %v", err)
	}
	const kid = "bench-k1"

	jwksSet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: priv.Public(), KeyID: kid, Use: "sig"},
	}}
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksSet)
	}))
	b.Cleanup(jwksSrv.Close)

	dp := pdp.NewJWTPDP(pdp.JWTPDPOptions{
		JWKSURI:                  jwksSrv.URL + "/",
		Issuer:                   "https://idp.bench",
		Audience:                 "eunox",
		Inner:                    inner,
		CacheTTL:                 5 * time.Minute,
		ExperimentalCapabilities: true,
	})

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		b.Fatalf("new signer: %v", err)
	}
	stdClaims := josejwt.Claims{
		Issuer:   "https://idp.bench",
		Subject:  "bench-agent",
		Audience: josejwt.Audience{"eunox"},
		IssuedAt: josejwt.NewNumericDate(time.Now()),
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	benchCaps := []string{"tool:read_file?path=/reports/*", "tool:query_db?op=SELECT"}
	payload := idpJWTPayloadForTest{
		MCP: mcpClaimSetForTest{
			Version:      mcpClaimVersionForTest,
			Capabilities: &benchCaps,
			AgentID:      "bench-agent",
			TaskID:       "bench-task",
		},
	}
	token, err := josejwt.Signed(sig).Claims(stdClaims).Claims(payload).Serialize()
	if err != nil {
		b.Fatalf("sign bench token: %v", err)
	}

	ctx, err := dp.ValidateToken(context.Background(), "Bearer "+token)
	if err != nil {
		b.Fatalf("ValidateToken warmup: %v", err)
	}

	return dp, ctx, "Bearer " + token
}

// benchProxySession creates an HTTPProxy wired to a fake remote upstream, calls
// initialize to establish one session, and returns the proxy, the session ID,
// and a cleanup function.  The caller must call b.ResetTimer() after this.
func benchProxySession(b *testing.B, opts httpProxyOptions) (*HTTPProxy, string) { //nolint:gocritic // unnamedResult: multiple returns; names add no clarity here
	b.Helper()

	if opts.UpstreamURL == "" {
		upSrv := newBenchUpstream(b)
		opts.UpstreamURL = upSrv.URL
	}
	if opts.PDP == nil {
		opts.PDP = pdp.AlwaysAllowPDP{}
	}
	proxy := newHTTPProxy(opts)

	initBody := mustMarshal(b, mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON("1"),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"bench","version":"1.0"}}`),
	})
	initReq := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(initBody))
	initReq.Header.Set("Content-Type", CTJSON)
	initW := httptest.NewRecorder()
	proxy.handleMCP(initW, initReq)

	sid := initW.Header().Get(SessionHeader)
	if sid == "" {
		b.Fatalf("no session ID after initialize (status %d)", initW.Code)
	}
	return proxy, sid
}

// benchProxySessionWithJWT creates a proxy backed by a JWTPDP (+ optional inner
// manifest PDP), initializes a session with a pre-issued JWT, and returns
// everything needed for the hot loop.
func benchProxySessionWithJWT(b *testing.B, inner pdp.PolicyDecisionPoint) (*HTTPProxy, string, string) { //nolint:gocritic // unnamedResult: multiple returns; names add no clarity here
	b.Helper()

	jwtPDP, _, bearerToken := benchJWTPDPContext(b, inner)

	upSrv := newBenchUpstream(b)

	proxy := newHTTPProxy(httpProxyOptions{
		UpstreamURL: upSrv.URL,
		PDP:         jwtPDP,
		JWTPDP:      jwtPDP,
	})

	initBody := mustMarshal(b, mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON("1"),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"bench-jwt","version":"1.0"}}`),
	})
	initReq := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(initBody))
	initReq.Header.Set("Content-Type", CTJSON)
	initReq.Header.Set("Authorization", bearerToken)
	initW := httptest.NewRecorder()
	proxy.handleMCP(initW, initReq)

	sid := initW.Header().Get(SessionHeader)
	if sid == "" {
		b.Fatalf("no session ID after JWT initialize (status %d; body: %s)",
			initW.Code, initW.Body.String())
	}
	return proxy, sid, bearerToken
}

// mustMarshal marshals v to JSON or fatals the benchmark.
func mustMarshal(b *testing.B, v interface{}) []byte {
	b.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		b.Fatalf("json.Marshal: %v", err)
	}
	return out
}

// prebuiltToolCall returns pre-serialized JSON for a tools/call request.
func prebuiltToolCall(tool string, args map[string]interface{}) []byte {
	params, _ := json.Marshal(mcp.ToolCallParams{Name: tool, Arguments: args})
	msg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON("2"),
		Method:  "tools/call",
		Params:  params,
	}
	out, _ := json.Marshal(msg)
	return out
}

// BenchmarkManifestPDP measures the PDP decision latency in isolation.
// There is no network, no file I/O, and no syscalls in the hot path.
// These numbers represent the raw CPU cost of the policy evaluation loop.
//
// Target: p99 < 1 ms for any rule count.
func BenchmarkManifestPDP(b *testing.B) {
	allowArgs := map[string]interface{}{"path": "/reports/q3.pdf"}
	ctx := context.Background()

	b.Run("Decide_Allow_SimpleRule", func(b *testing.B) {
		dp := benchPDPOnly(b,
			capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = dp.Decide(ctx, "sess-bench", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "read_file"}, allowArgs, "127.0.0.1")
		}
	})

	b.Run("Decide_Deny_AbsentTool", func(b *testing.B) {
		dp := benchPDPOnly(b,
			capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		)
		denyArgs := map[string]interface{}{"path": "/etc/passwd", "content": "x"}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = dp.Decide(ctx, "sess-bench", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "write_file"}, denyArgs, "127.0.0.1")
		}
	})

	b.Run("Decide_Allow_WithGlobCondition", func(b *testing.B) {
		dp := benchPDPOnly(b,
			capability.Constraint{
				Target:  "tool:read_file",
				Actions: []string{"call"},
				Conditions: []capability.Condition{
					&capability.AllowedValuesCondition{
						Argument: "path",
						Values:   []interface{}{"/reports/*"},
					},
				},
			},
		)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = dp.Decide(ctx, "sess-bench", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "read_file"}, allowArgs, "127.0.0.1")
		}
	})

	b.Run("Decide_Allow_50Rules", func(b *testing.B) {

		rules := build50RuleManifest()
		dp := benchPDPOnly(b, rules...)
		lastTool := fmt.Sprintf("tool_%02d", len(rules)-1)
		args := map[string]interface{}{}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = dp.Decide(ctx, "sess-bench", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: lastTool}, args, "127.0.0.1")
		}
	})

	b.Run("Decide_Deny_50Rules", func(b *testing.B) {

		rules := build50RuleManifest()
		dp := benchPDPOnly(b, rules...)
		args := map[string]interface{}{}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = dp.Decide(ctx, "sess-bench", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "tool_unknown"}, args, "127.0.0.1")
		}
	})

	b.Run("Decide_Allow_WithAllowedOperations", func(b *testing.B) {
		dp := benchPDPOnly(b,
			capability.Constraint{
				Target:  "tool:query_db",
				Actions: []string{"call"},
				Conditions: []capability.Condition{
					capability.AllowedOperationsCondition{
						Operations: []string{"SELECT"},
					},
				},
			},
		)
		dbArgs := map[string]interface{}{"query": "SELECT * FROM reports"}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = dp.Decide(ctx, "sess-bench", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "query_db"}, dbArgs, "127.0.0.1")
		}
	})

	b.Run("Decide_Allow_WithArgumentSchema", func(b *testing.B) {

		falseBool := false
		dp := benchPDPOnly(b,
			capability.Constraint{
				Target:  "tool:read_file",
				Actions: []string{"call"},
				ArgumentSchema: &capability.ArgumentSchema{
					Properties: map[string]*capability.ArgumentSchema{
						"path": {MinLength: intPtr(1)},
					},
					Required:             []string{"path"},
					AdditionalProperties: &falseBool,
				},
			},
		)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = dp.Decide(ctx, "sess-bench", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "read_file"}, allowArgs, "127.0.0.1")
		}
	})

	b.Run("Decide_Deny_FailsArgumentSchema", func(b *testing.B) {

		falseBool := false
		minLen := 100
		dp := benchPDPOnly(b,
			capability.Constraint{
				Target:  "tool:read_file",
				Actions: []string{"call"},
				ArgumentSchema: &capability.ArgumentSchema{
					Properties: map[string]*capability.ArgumentSchema{
						"path": {MinLength: &minLen},
					},
					Required:             []string{"path"},
					AdditionalProperties: &falseBool,
				},
			},
		)
		shortArgs := map[string]interface{}{"path": "/x"}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = dp.Decide(ctx, "sess-bench", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "read_file"}, shortArgs, "127.0.0.1")
		}
	})
}

// BenchmarkHTTPProxy measures the added latency of the eunox proxy over a
// direct upstream call.  The fake upstream is an in-process httptest.Server
// that returns a static response; its baseline latency is subtracted via the
// companion BenchmarkUpstream_Baseline sub-benchmark.
//
// Architecture under test:
//
//	b.Loop ──► proxy.handleMCP ──► ManifestPDP.Decide ──► upstream httptest
//
// Targets:
//   - Stateless mode (no audit): p99 < 2 ms overhead
//   - With audit log: overhead varies by storage (tmpfs: +~50 µs; SSD: +~200 µs)
func BenchmarkHTTPProxy(b *testing.B) {
	allowBody := prebuiltToolCall("read_file", map[string]interface{}{"path": "/reports/q3.pdf"})
	denyBody := prebuiltToolCall("write_file", map[string]interface{}{"path": "/etc/passwd", "content": "x"})

	b.Run("Baseline_DirectUpstream", func(b *testing.B) {

		upSrv := newBenchUpstream(b)

		client := &http.Client{}

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req, _ := http.NewRequestWithContext(context.Background(),
				http.MethodPost, upSrv.URL+"/mcp", bytes.NewReader(allowBody))
			req.Header.Set("Content-Type", CTJSON)
			resp, err := client.Do(req)
			if err != nil {
				b.Fatalf("upstream request: %v", err)
			}

			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	})

	b.Run("ManifestPDP_Allow", func(b *testing.B) {
		dp := benchPDPOnly(b,
			capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
			capability.Constraint{Target: "tool:query_db", Actions: []string{"call"}},
		)
		proxy, sid := benchProxySession(b, httpProxyOptions{PDP: dp})
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(allowBody))
			req.Header.Set("Content-Type", CTJSON)
			req.Header.Set(SessionHeader, sid)
			w := httptest.NewRecorder()
			proxy.handleMCP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
			}
		}
	})

	b.Run("ManifestPDP_Deny", func(b *testing.B) {
		dp := benchPDPOnly(b,
			capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		)
		proxy, sid := benchProxySession(b, httpProxyOptions{PDP: dp})
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(denyBody))
			req.Header.Set("Content-Type", CTJSON)
			req.Header.Set(SessionHeader, sid)
			w := httptest.NewRecorder()
			proxy.handleMCP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status %d", w.Code)
			}
		}
	})

	b.Run("ManifestPDP_Allow_WithAudit", func(b *testing.B) {

		dp := benchPDPOnly(b,
			capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		)
		sink := benchAuditSink(b)
		proxy, sid := benchProxySession(b, httpProxyOptions{PDP: dp, Sink: sink})
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(allowBody))
			req.Header.Set("Content-Type", CTJSON)
			req.Header.Set(SessionHeader, sid)
			w := httptest.NewRecorder()
			proxy.handleMCP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status %d", w.Code)
			}
		}
	})

	b.Run("ManifestPDP_50Rules_Allow", func(b *testing.B) {

		rules := build50RuleManifest()
		lastBody := prebuiltToolCall(
			fmt.Sprintf("tool_%02d", len(rules)-1),
			map[string]interface{}{},
		)
		dp := benchPDPOnly(b, rules...)
		proxy, sid := benchProxySession(b, httpProxyOptions{PDP: dp})
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(lastBody))
			req.Header.Set("Content-Type", CTJSON)
			req.Header.Set(SessionHeader, sid)
			w := httptest.NewRecorder()
			proxy.handleMCP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status %d", w.Code)
			}
		}
	})

	b.Run("ManifestPDP_Allow_WithRedact", func(b *testing.B) {

		redactBody := prebuiltToolCall("get_user", map[string]interface{}{"id": "u1"})

		userPayload := `{"name":"Alice","ssn":"123-45-6789","score":99}`
		toolResult, _ := json.Marshal(mcptest.ToolCallResult{
			Content: []mcptest.Content{{Type: "text", Text: userPayload}},
		})
		upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var msg mcp.RPCMsg
			if err := json.Unmarshal(body, &msg); err != nil {
				http.Error(w, "bad JSON", http.StatusBadRequest)
				return
			}
			switch msg.Method {
			case "initialize":
				initResult, _ := json.Marshal(mcp.InitResult{
					ProtocolVersion: capability.Revision20251125.String(),
					Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
					ServerInfo:      map[string]interface{}{"name": "bench-redact-upstream", "version": "0.1"},
				})
				resp, _ := json.Marshal(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: initResult})
				w.Header().Set(SessionHeader, "bench-redact-sess")
				w.Header().Set("Content-Type", CTJSON)
				_, _ = w.Write(resp)
			case "notifications/initialized":
				w.WriteHeader(http.StatusAccepted)
			case "tools/call":
				resp, _ := json.Marshal(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("2"), Result: toolResult})
				w.Header().Set("Content-Type", CTJSON)
				_, _ = w.Write(resp)
			default:
				w.WriteHeader(http.StatusAccepted)
			}
		}))
		b.Cleanup(upSrv.Close)

		dp := benchPDPOnly(b,
			capability.Constraint{
				Target:  "tool:get_user",
				Actions: []string{"call"},
				Directives: []capability.Directive{
					&capability.RedactFieldsDirective{Fields: []string{"ssn"}},
				},
			},
		)
		proxy, sid := benchProxySession(b, httpProxyOptions{PDP: dp, UpstreamURL: upSrv.URL})
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(redactBody))
			req.Header.Set("Content-Type", CTJSON)
			req.Header.Set(SessionHeader, sid)
			w := httptest.NewRecorder()
			proxy.handleMCP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status %d", w.Code)
			}
		}
	})
}

// BenchmarkHTTPProxy_JWTPDP measures the overhead when --jwks-uri is set.
// Every handleMCP call validates the Bearer JWT (ECDSA P-256 signature
// verification) before routing to the PDP.  The JWKS is fetched once and
// cached for the duration of the benchmark run.
//
// Target: p99 < 3 ms added overhead (JWT PDP, JWKS cached).
func BenchmarkHTTPProxy_JWTPDP(b *testing.B) {
	allowBody := prebuiltToolCall("read_file", map[string]interface{}{"path": "/reports/q3.pdf"})
	denyBody := prebuiltToolCall("write_file", map[string]interface{}{"path": "/etc/passwd", "content": "x"})

	b.Run("Allow_JWTOnly", func(b *testing.B) {

		proxy, sid, token := benchProxySessionWithJWT(b, nil)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(allowBody))
			req.Header.Set("Content-Type", CTJSON)
			req.Header.Set(SessionHeader, sid)
			req.Header.Set("Authorization", token)
			w := httptest.NewRecorder()
			proxy.handleMCP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
			}
		}
	})

	b.Run("Allow_JWTAndManifest", func(b *testing.B) {

		inner := benchPDPOnly(b,
			capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
			capability.Constraint{Target: "tool:query_db", Actions: []string{"call"}},
		)
		proxy, sid, token := benchProxySessionWithJWT(b, inner)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(allowBody))
			req.Header.Set("Content-Type", CTJSON)
			req.Header.Set(SessionHeader, sid)
			req.Header.Set("Authorization", token)
			w := httptest.NewRecorder()
			proxy.handleMCP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
			}
		}
	})

	b.Run("Deny_AbsentFromJWT", func(b *testing.B) {
		proxy, sid, token := benchProxySessionWithJWT(b, nil)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(denyBody))
			req.Header.Set("Content-Type", CTJSON)
			req.Header.Set(SessionHeader, sid)
			req.Header.Set("Authorization", token)
			w := httptest.NewRecorder()
			proxy.handleMCP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status %d", w.Code)
			}
		}
	})
}

// BenchmarkHTTPProxy_RedisKS measures the overhead introduced by wiring the
// proxy to a Redis-backed kill switch (via miniredis, in-process).
//
// Note: the Redis kill switch caches state in-memory and refreshes via pub/sub.
// ShouldBlock() is therefore a mutex + map lookup on the hot path, not a
// Redis round-trip.  The p99 overhead over the in-memory baseline is expected
// to be < 1 µs.  A real Redis deployment adds network RTT only on state
// changes (kill/revive), not on every request.
//
// Target: p99 < 5 ms overhead (Redis session state, includes Redis RTT on
// state changes; hot-path reads are in-memory).
func BenchmarkHTTPProxy_RedisKS(b *testing.B) {
	allowBody := prebuiltToolCall("read_file", map[string]interface{}{"path": "/reports/q3.pdf"})

	b.Run("ManifestPDP_Allow_RedisKS", func(b *testing.B) {
		mr := miniredis.RunT(b)
		redisClient := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
		b.Cleanup(func() { _ = redisClient.Close() })

		ctx, cancel := context.WithCancel(context.Background())
		ks := killswitch.NewRedis(redisClient)
		ks.Start(ctx)
		b.Cleanup(func() { cancel(); ks.Stop() })

		manifest := &config.LocalManifest{
			Name:    "bench",
			Version: "1.0.0",
			Capabilities: []capability.Constraint{
				{Target: "tool:read_file", Actions: []string{"call"}},
			},
		}
		dp := pdp.NewManifestPDP(manifest.Capabilities, enforcement.New(), ks)

		upSrv := newBenchUpstream(b)

		proxy := newHTTPProxy(httpProxyOptions{
			UpstreamURL: upSrv.URL,
			PDP:         dp,
			KS:          ks,
		})

		initBody := mustMarshal(b, mcp.RPCMsg{
			JSONRPC: "2.0",
			ID:      mcp.RawJSON("1"),
			Method:  "initialize",
			Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"bench-redis","version":"1.0"}}`),
		})
		initReq := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(initBody))
		initReq.Header.Set("Content-Type", CTJSON)
		initW := httptest.NewRecorder()
		proxy.handleMCP(initW, initReq)
		sid := initW.Header().Get(SessionHeader)
		if sid == "" {
			b.Fatalf("no session ID after initialize (status %d)", initW.Code)
		}

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(allowBody))
			req.Header.Set("Content-Type", CTJSON)
			req.Header.Set(SessionHeader, sid)
			w := httptest.NewRecorder()
			proxy.handleMCP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status %d", w.Code)
			}
		}
	})
}

// benchStdioProxy creates a StdioProxy backed by an in-process upstream goroutine
// (two io.Pipe pairs replacing the subprocess).  handleHostRequest can be called
// directly in hot loops; responses are discarded via io.Discard.
func benchStdioProxy(b *testing.B, dp pdp.PolicyDecisionPoint) *StdioProxy {
	b.Helper()

	upR, upW := io.Pipe()

	downR, downW := io.Pipe()

	result, _ := json.Marshal(mcptest.ToolCallResult{
		Content: []mcptest.Content{{Type: "text", Text: `{"ok":true}`}},
	})

	go func() {
		defer func() { _ = downW.Close() }()
		r := mcp.NewMsgReader(upR)
		w := mcp.NewMsgWriter(downW)
		for {
			msg, err := r.Read()
			if err != nil {
				return
			}
			_ = w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: result})
		}
	}()

	proxy := &StdioProxy{
		pdp:          dp,
		sessionID:    "bench-stdio",
		hostWriter:   mcp.NewMsgWriter(io.Discard),
		upWriter:     mcp.NewMsgWriter(upW),
		upReader:     mcp.NewMsgReader(downR),
		upstreamDone: make(chan struct{}),
	}

	go func() {
		defer close(proxy.upstreamDone)
		proxy.readUpstream(context.Background())
	}()

	b.Cleanup(func() { _ = upW.Close() })

	return proxy
}

// BenchmarkStdioProxy measures the overhead of the stdio transport (used in
// IDE integrations and agent runtimes).  The upstream is an in-process goroutine
// communicating via io.Pipe, so the baseline captures JSON-RPC framing overhead
// only (no TCP).  The proxy overhead column is analogous to BenchmarkHTTPProxy.
//
// Architecture under test:
//
//	b.Loop ──► proxy.handleHostRequest ──► ManifestPDP.Decide ──► upstream goroutine (pipe)
//
// Target: p99 < 2 ms overhead (stateless mode, pipe transport).
func BenchmarkStdioProxy(b *testing.B) {
	allowParams, _ := json.Marshal(mcp.ToolCallParams{
		Name:      "read_file",
		Arguments: map[string]interface{}{"path": "/reports/q3.pdf"},
	})
	allowMsg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`"2"`),
		Method:  "tools/call",
		Params:  allowParams,
	}
	denyParams, _ := json.Marshal(mcp.ToolCallParams{
		Name:      "write_file",
		Arguments: map[string]interface{}{"path": "/etc/passwd", "content": "x"},
	})
	denyMsg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`"2"`),
		Method:  "tools/call",
		Params:  denyParams,
	}
	ctx := context.Background()

	b.Run("Baseline_DirectPipe", func(b *testing.B) {

		upR, upW := io.Pipe()
		downR, downW := io.Pipe()
		result, _ := json.Marshal(mcptest.ToolCallResult{
			Content: []mcptest.Content{{Type: "text", Text: `{"ok":true}`}},
		})
		go func() {
			defer func() { _ = downW.Close() }()
			r := mcp.NewMsgReader(upR)
			w := mcp.NewMsgWriter(downW)
			for {
				msg, err := r.Read()
				if err != nil {
					return
				}
				_ = w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: result})
			}
		}()
		writer := mcp.NewMsgWriter(upW)
		reader := mcp.NewMsgReader(downR)
		b.Cleanup(func() { _ = upW.Close() })
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = writer.Write(allowMsg)
			_, _ = reader.Read()
		}
	})

	b.Run("ManifestPDP_Allow", func(b *testing.B) {
		dp := benchPDPOnly(b,
			capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
			capability.Constraint{Target: "tool:query_db", Actions: []string{"call"}},
		)
		proxy := benchStdioProxy(b, dp)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			proxy.handleHostRequest(ctx, allowMsg)
		}
	})

	b.Run("ManifestPDP_Deny", func(b *testing.B) {

		dp := benchPDPOnly(b,
			capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		)
		proxy := benchStdioProxy(b, dp)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			proxy.handleHostRequest(ctx, denyMsg)
		}
	})
}

// BenchmarkAuditRecord measures the synchronous cost of audit.Sink.Record, which
// must stay non-blocking: it does only struct initialization and a channel send,
// with all marshalling/HMAC/disk-I/O happening in the drainer goroutine. The
// benchmark writes to a temp log so the drainer makes real progress.
func BenchmarkAuditRecord(b *testing.B) {
	dir := b.TempDir()

	sink, err := audit.Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0)
	if err != nil {
		b.Fatalf("openAuditSink: %v", err)
	}
	b.Cleanup(func() { _ = sink.Close() })

	b.Run("Allow_NoDetails", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sink.RecordAllow(context.Background(), "sess-bench", "read_file", "tools/call", nil, nil, false, nil, nil)
		}
	})

	b.Run("Deny_WithDenialCode", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sink.RecordDeny(context.Background(), "sess-bench", "write_file", "tools/call", capability.ErrCodeAuthorizationFailed, "", nil, false)
		}
	})

	b.Run("Allow_WithDetails", func(b *testing.B) {
		details := map[string]interface{}{"path": "/reports/q3.pdf", "op": "read"}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sink.RecordAllow(context.Background(), "sess-bench", "read_file", "tools/call", details, []string{"redactFields"}, false, nil, nil)
		}
	})
}

// BenchmarkDecisionTurn_Pinned measures what a serialized route pays per enforced request when
// the turn is UNCONTENDED — distinct sessions, so no two goroutines want the same anchor — and
// the request resolves the anchor its session pinned at registration. That covers every request
// on a session-anchored route and every request of a task-anchored session that stays on one
// task, and it touches no map and no shared lock at all.
//
// Run them together; each pair below is meant to be read against its own control, never across
// workloads (a task-anchored request resolves its anchor from claims and a session-anchored one
// does not, so the two workloads are not comparable per-op):
//
//	go test -run XXX -bench 'BenchmarkDecisionTurn' -count=6 -cpu=8 ./internal/transport/
func BenchmarkDecisionTurn_Pinned(b *testing.B) {
	benchmarkDecisionTurn(b, turnPinned)
}

// BenchmarkDecisionTurn_Registry is the always-correct path both faster tiers sit in front of,
// on the session-anchored workload: a route-wide mutex, a map insert and a map delete per
// request, since the refcount falls to zero the instant a non-overlapping request finishes. It
// is the control for BenchmarkDecisionTurn_Pinned.
func BenchmarkDecisionTurn_Registry(b *testing.B) {
	benchmarkDecisionTurn(b, turnRegistry)
}

// BenchmarkDecisionTurn_SpanCached is the shape this cache exists for: a session that has MOVED
// off the anchor it pinned — an agent runtime multiplexing task-2 … task-n over one long-lived
// connection — with its live anchors inside the cap. Its control is
// BenchmarkDecisionTurn_SpanUncached, which is the same workload with the cache off, i.e. what
// such a session paid on EVERY call before this existed.
func BenchmarkDecisionTurn_SpanCached(b *testing.B) {
	benchmarkDecisionTurn(b, turnSpanCached)
}

// BenchmarkDecisionTurn_SpanThrashing is the cache's WORST case, on the same workload as its
// control: a session cycling one more live anchor than the cap, so every request misses, files
// an entry and immediately sheds the one the next request wants. Read against
// BenchmarkDecisionTurn_SpanUncached it says what the cache costs a session it cannot help — a
// cache that is slower than the thing it fronts, on a reachable shape, is a cost with no
// benefit, and the answer would be to stop admitting past the cap rather than to raise it.
func BenchmarkDecisionTurn_SpanThrashing(b *testing.B) {
	benchmarkDecisionTurn(b, turnSpanThrashing)
}

// BenchmarkDecisionTurn_SpanUncached is the control for the two spanning tiers: the same
// task-anchored, off-pin workload with the cache closed, so every request resolves through the
// route registry.
func BenchmarkDecisionTurn_SpanUncached(b *testing.B) {
	benchmarkDecisionTurn(b, turnSpanUncached)
}

// Which tier of httpSession.beginTurn the benchmark below exercises.
type turnTier int

const (
	turnPinned turnTier = iota
	turnRegistry
	turnSpanCached
	turnSpanThrashing
	turnSpanUncached
)

// spans reports whether this tier drives requests OFF the session's pinned anchor, onto a
// task-anchored route.
func (t turnTier) spans() bool {
	return t == turnSpanCached || t == turnSpanThrashing || t == turnSpanUncached
}

// caches reports whether this tier leaves the session's span cache open.
func (t turnTier) caches() bool {
	return t == turnSpanCached || t == turnSpanThrashing
}

// liveAnchors is how many distinct off-pin anchors this tier cycles a session through.
func (t turnTier) liveAnchors() int {
	if t == turnSpanThrashing {
		return maxCachedSessionGates + 1 // one more than the cache can hold: every request misses
	}
	return 1
}

func benchmarkDecisionTurn(b *testing.B, tier turnTier) {
	b.Helper()
	rt := &UpstreamRoute{decideGates: newAnchorGates(), taskAnchored: tier.spans()}
	var seq atomic.Uint64
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		n := seq.Add(1)
		sess := &httpSession{id: fmt.Sprintf("sess-%d", n), route: rt}
		if tier != turnRegistry {
			// The pin every registered session takes. On a spanning tier the requests below
			// resolve a task the pin does not name, so they go past it.
			sess.holdDecisionGate()
			defer sess.dropDecideGate()
		}
		if tier.caches() {
			defer sess.decideCache.close()
		} else {
			// Closed up front so nothing is cached. On turnPinned that changes nothing (every
			// request resolves the pinned anchor and never reaches the cache); on the two
			// uncached tiers it is what sends every request through the route registry.
			sess.decideCache.close()
		}

		// One context per live anchor, cycled round-robin. A non-spanning tier gets a single
		// context on the session's own anchor.
		spread := make([]context.Context, tier.liveAnchors())
		for i := range spread {
			spread[i] = context.Background()
			if tier.spans() {
				spread[i] = taskCtx(fmt.Sprintf("task-%d-%d", n, i))
			}
		}
		i := 0
		for pb.Next() {
			sess.beginDecisionTurn(spread[i])()
			i++
			if i == len(spread) {
				i = 0
			}
		}
	})
}

// BenchmarkRefusalRecorders_ForCategory is the number behind forCategory's map probe, which is on
// every refusal record's recorder resolution and was worth measuring rather than removing: the
// disposition is read from refusalDeclarations at resolution time, and a pre-resolved per-leg table
// would be a second copy of the answer this package exists to have one of.
//
// The metered arm holds its bucket FULL by advancing an injected clock each iteration. Sharing one
// bucket across the run measured the opposite of the intended path: perCategoryDenyBurst is 5, so
// after five iterations admit() refuses and forCategory returns nil for the rest — reporting the
// drained path's cost and never once allocating the rolledUpRecorder the admitted path boxes when
// something was suppressed. The three arms are the probe alone, the admitted path, and the admitted
// path carrying a rollup.
func BenchmarkRefusalRecorders_ForCategory(b *testing.B) {
	b.Run("exempt", func(b *testing.B) {
		recs := refusalLimits{records: newRefusalRecordLimiter()}.recorders(&fwdRecorder{})
		b.ReportAllocs()
		for b.Loop() {
			_ = recs.forCategory(catUnroutable)
		}
	})
	b.Run("metered", func(b *testing.B) {
		lim := newRefusalRecordLimiter()
		now := time.Now()
		lim.setNow(func() time.Time { return now })
		recs := refusalLimits{records: lim}.recorders(&fwdRecorder{})
		b.ReportAllocs()
		for b.Loop() {
			// A second of refill per iteration keeps the bucket admitting, so this measures the
			// path that actually resolves a recorder rather than the one that returns nil.
			now = now.Add(time.Second)
			if got := recs.forCategory(catKill); got == nil {
				b.Fatal("the bucket refused; this arm must measure the ADMITTED path")
			}
		}
	})
	b.Run("metered with rollup", func(b *testing.B) {
		lim := newRefusalRecordLimiter()
		recs := refusalLimits{records: lim}.recorders(&fwdRecorder{})
		b.ReportAllocs()
		for b.Loop() {
			// Drained, then refilled: the admitted record carries a suppressed count, which is the
			// one shape that boxes a rolledUpRecorder.
			lim.bucket(catKill).suppress()
			_ = recs.forCategory(catKill)
		}
	})
}

// benchSink escapes the resolved writer so the "with writer" arm below measures the production
// shape. Discarding the result instead let escape analysis stack-allocate the bound method value,
// which reported 0 allocs for a call that heap-allocates one at every real wiring site.
var benchSink func(mcp.RPCMsg) error

// BenchmarkServerRequestUnblocker_Build is the per-request wiring cost on the server-initiated leg.
//
// The leg is not hot — a server-initiated request implies a human-facing round trip (an LLM
// completion, a roots prompt) — so the numbers are here to be read rather than defended. What this
// pins is the shape: an unblocker is built by every site that wants the TRACKER (once per forwarded
// request) and by every site that wants to ANSWER, and the writer it hands out is a method value
// bound through initiatorWriter's reflection. Resolving that writer lazily is what keeps the
// tracker-only holders — the common case, since a healthy session displaces nothing — from paying
// for a writer nothing calls, which is the ratio between these two arms.
func BenchmarkServerRequestUnblocker_Build(b *testing.B) {
	p := &StdioProxy{upWriter: mcp.NewMsgWriter(io.Discard)}
	b.Run("tracker only", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = p.unblocker().reqs
		}
	})
	b.Run("with writer", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			benchSink = p.unblocker().writeUpstream()
		}
	})
}
