// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// TestHTTPSession_ReinitializeAfterKillBlocked is the regression guard for the
// HTTP existing-session re-initialize echo bypassing the kill switch. A session
// that has been terminated — per-session or via the global emergency stop — must
// not be able to re-send initialize and receive the upstream's captured
// capability set back. Before the fix the re-initialize branch answered locally
// from buildInitResponse with no kill check, the one session action not gated by
// a kill check; every other action (enforced calls, */list, notifications,
// opening an SSE stream) already was.
func TestHTTPSession_ReinitializeAfterKillBlocked(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewServer(fake)
	defer upSrv.Close()

	ks := killswitch.NewInMemory()
	routes := map[string]*UpstreamRoute{
		"a": {
			name: "a", transport: "http", upstreamURL: upSrv.URL,
			pdp: pdp.NewManifestPDP(
				[]capability.Constraint{{Target: "tool:read_file", Actions: []string{"call"}}},
				enforcement.New(), ks),
			sink: &routeSink{},
		},
	}
	srv := newGatewayTestServer(t, routes)

	reinit := map[string]interface{}{"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": map[string]interface{}{}}

	// reinitErr returns true if the re-initialize response is a JSON-RPC error and,
	// when it is, the symbolic code carried in error.data.code.
	reinitErr := func(sid string) (bool, string) {
		resp := postGateway(t, srv, "a", reinit, sid)
		defer func() { _ = resp.Body.Close() }()
		var m mcp.RPCMsg
		_ = json.NewDecoder(resp.Body).Decode(&m)
		if m.Error == nil {
			return false, ""
		}
		var data map[string]string
		_ = json.Unmarshal(m.Error.Data, &data)
		return true, data["code"]
	}

	// --- per-session kill ---
	sid1 := initGatewaySession(t, srv, "a")
	// Before any kill the re-initialize echo succeeds (caps returned, no error).
	if isErr, _ := reinitErr(sid1); isErr {
		t.Fatal("pre-kill re-initialize must succeed and echo the captured capabilities")
	}
	if err := ks.KillSession(context.Background(), sid1); err != nil {
		t.Fatalf("KillSession: %v", err)
	}
	// After the kill the re-initialize must be a KILL_SWITCH denial, not the caps.
	if isErr, code := reinitErr(sid1); !isErr {
		t.Error("re-initialize on a per-session-killed session must be denied, not echo the capability set")
	} else if code != capability.ErrCodeKillSwitch {
		t.Errorf("re-initialize denial code = %q, want %q", code, capability.ErrCodeKillSwitch)
	}

	// --- global emergency stop ---
	sid2 := initGatewaySession(t, srv, "a")
	if isErr, _ := reinitErr(sid2); isErr {
		t.Fatal("pre-global-kill re-initialize on a fresh session must succeed")
	}
	if err := ks.ActivateGlobal(context.Background()); err != nil {
		t.Fatalf("ActivateGlobal: %v", err)
	}
	if isErr, code := reinitErr(sid2); !isErr {
		t.Error("re-initialize while a global emergency stop is active must be denied")
	} else if code != capability.ErrCodeKillSwitch {
		t.Errorf("global-kill re-initialize denial code = %q, want %q", code, capability.ErrCodeKillSwitch)
	}
}

// TestGateway_DeleteAudienceAndOwnerBinding is the regression guard for
// handleMCPDelete omitting the per-route audience pin (and, for parity with the
// GET stream-open path, the session-owner binding). In gateway mode the shared
// union validator accepts a token minted for ANY route's audience, so without
// these gates a sibling-audience token — or a same-audience but different
// identity that learned the victim's Mcp-Session-Id — could tear down another
// client's session (cross-audience teardown / tenant DoS). The two refused
// DELETEs must not delete the session; the legitimate owner's DELETE then
// succeeds (its 204 proves the session survived the refusals).
func TestGateway_DeleteAudienceAndOwnerBinding(t *testing.T) {
	key := newTestKey(t, "k1")
	jwks := makeJWKSServer(t, key)
	defer jwks.Close()
	const iss = "https://idp.test"

	fakeA := newFakeUpstream()
	srvA := httptest.NewServer(fakeA)
	defer srvA.Close()

	mkPDP := func() pdp.PolicyDecisionPoint {
		return pdp.NewManifestPDP(
			[]capability.Constraint{{Target: "tool:read_file", Actions: []string{"call"}}},
			enforcement.New(), killswitch.NewInMemory())
	}
	// Two routes so the shared validator's union accepts BOTH svc-a and svc-b.
	routes := map[string]*UpstreamRoute{
		"a": {name: "a", transport: "http", upstreamURL: srvA.URL, pdp: mkPDP(), manifest: &config.LocalManifest{Audience: "svc-a"}, sink: &routeSink{}},
		"b": {name: "b", transport: "http", upstreamURL: srvA.URL, pdp: mkPDP(), manifest: &config.LocalManifest{Audience: "svc-b"}, sink: &routeSink{}},
	}
	validator := mustWrapRoutesWithJWT(t, routes, pdp.JWTPDPOptions{
		JWKSURI: jwks.URL + "/", Issuer: iss, Audience: "svc-a", KillSwitch: killswitch.NewInMemory(),
		ExperimentalCapabilities: true,
	})
	proxy := NewHTTPProxyGateway(HTTPGatewayOptions{Routes: routes, JWTPDP: validator})
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp/{upstream}", proxy.handleMCP)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Three tokens accepted by the union: the owner (svc-a, agent-1), a sibling
	// audience (svc-b, agent-1), and a same-audience different identity (svc-a, agent-2).
	tokenOwner := makeIDPToken(t, key, []string{"tool:read_file"}, iss, "svc-a", "agent-1", time.Now().Add(time.Hour))
	tokenSiblingAud := makeIDPToken(t, key, []string{"tool:read_file"}, iss, "svc-b", "agent-1", time.Now().Add(time.Hour))
	tokenOtherSub := makeIDPToken(t, key, []string{"tool:read_file"}, iss, "svc-a", "agent-2", time.Now().Add(time.Hour))

	initBody := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "t", "version": "0"}},
	}
	// Establish a session on route A with the owner token.
	b, _ := json.Marshal(initBody)
	ri, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp/a", strings.NewReader(string(b)))
	if err != nil {
		t.Fatalf("new init request: %v", err)
	}
	ri.Header.Set("Content-Type", "application/json")
	ri.Header.Set("Authorization", "Bearer "+tokenOwner)
	riResp, err := http.DefaultClient.Do(ri)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	sid := riResp.Header.Get(SessionHeader)
	_ = riResp.Body.Close()
	if riResp.StatusCode != http.StatusOK || sid == "" {
		t.Fatalf("expected a session on route A for the owner token, status=%d sid=%q", riResp.StatusCode, sid)
	}

	del := func(token string) int {
		req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/mcp/a", http.NoBody)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set(SessionHeader, sid)
		resp, derr := http.DefaultClient.Do(req)
		if derr != nil {
			t.Fatalf("delete: %v", derr)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	// A sibling-audience (svc-b) token must not tear down route A's session.
	if got := del(tokenSiblingAud); got != http.StatusForbidden {
		t.Errorf("cross-audience DELETE must be refused 403, got %d", got)
	}
	// A same-audience but different identity (svc-a, agent-2) must not either.
	if got := del(tokenOtherSub); got != http.StatusForbidden {
		t.Errorf("foreign-sub DELETE must be refused 403, got %d", got)
	}
	// The legitimate owner's DELETE succeeds — its 204 proves the session survived
	// the two refusals above (a wrongly-applied refusal would have deleted it,
	// turning this into a 404).
	if got := del(tokenOwner); got != http.StatusNoContent {
		t.Errorf("owner DELETE must succeed 204, got %d", got)
	}
	// And now the session is gone.
	if got := del(tokenOwner); got != http.StatusNotFound {
		t.Errorf("DELETE of an already-removed session must be 404, got %d", got)
	}
}

// TestRemoteUpstream_InitializeErrorInDoMCPHTTPLeaksNoSession is the regression
// guard for initRemoteUpstream leaking the upstream session when initialize fails
// INSIDE DoMCPHTTP (a non-2xx status here; the same applies to a 202, an empty
// 200 body, or an unmatched SSE stream). DoMCPHTTP returns the response header
// alongside the error on those paths, and a lenient upstream may already have
// ALLOCATED a session, so close()'s teardown DELETE must still fire. Before the
// fix the session-id capture sat after the doRemoteHTTP error guard, so it never
// ran on this path and the session leaked. Sibling of
// TestRemoteUpstream_UncorrelatableInitializeLeaksNoSession (which covers the
// post-DoMCPHTTP correlation gate).
func TestRemoteUpstream_InitializeErrorInDoMCPHTTPLeaksNoSession(t *testing.T) {
	var mu sync.Mutex
	var deletedSess string
	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			mu.Lock()
			deletedSess = r.Header.Get(SessionHeader)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var in mcp.RPCMsg
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Method == "initialize" {
			// Allocate a session, then fail the initialize at the transport layer with a
			// non-2xx status — DoMCPHTTP returns this as an error WITH the response header.
			w.Header().Set(SessionHeader, "upstream-sess-doerr")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("upstream boom"))
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, httpProxyOptions{PDP: pdp.AlwaysAllowPDP{}})

	initMsg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`1`),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{}}`),
	}
	resp := postMCP(t, proxySrv, initMsg, "")
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK && resp.Header.Get(SessionHeader) != "" {
		t.Fatalf("proxy created a session despite the failed initialize (status %d, session %q)",
			resp.StatusCode, resp.Header.Get(SessionHeader))
	}

	// close()'s teardown DELETE runs on a detached background context, so poll briefly.
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		got := deletedSess
		mu.Unlock()
		if got == "upstream-sess-doerr" {
			return // teardown DELETE fired with the allocated upstream session id
		}
		if time.Now().After(deadline) {
			t.Fatalf("teardown DELETE did not fire with the allocated upstream session id (got %q); the session leaked when initialize failed inside DoMCPHTTP", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
