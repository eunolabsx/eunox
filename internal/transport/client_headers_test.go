// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// The smuggling test: a header a host sends that no operator granted must never reach the
// upstream.
//
// This is the whole posture in one assertion. 2026-07-28 blesses custom client headers as a
// passthrough, and through a proxy that is a channel to an upstream eunox does not police —
// carrying whatever the host chooses past a boundary whose entire purpose is that nothing
// crosses unexamined. Driven end to end through the real host handler and the real sender, so
// it fails if any layer between them ever starts copying host headers.
func TestForwardClientHeaders_UnlistedHeadersNeverReachTheUpstream(t *testing.T) {
	t.Parallel()
	srv, proxy, lastHeaders := forwardingProxy(t, []string{"X-Tenant-Id"})

	sid := initSession(t, srv)
	require.NotNil(t, proxy.getSession(sid))

	callWithHeaders(t, srv, sid, map[string]string{
		"X-Tenant-Id":     "acme",           // granted
		"X-Mcp-Smuggled":  "payload",        // not granted
		"X-Debug":         "1",              // not granted
		"Authorization":   "Bearer stolen",  // reserved: the upstream credential is the operator's
		"Cookie":          "session=hijack", // reserved: ambient authority
		"Mcp-Name":        "other_tool",     // reserved: eunox derives it from the body
		"Mcp-Method":      "tools/list",     // reserved: eunox derives it from the body
		"X-Forwarded-For": "10.0.0.1",       // not granted
	})

	got := lastHeaders(capability.MethodToolsCall)
	require.NotNil(t, got, "the upstream was never called; the test proves nothing")

	assert.Equal(t, "acme", got.Get("X-Tenant-Id"), "the granted header did not reach the upstream")
	// The routing headers are in this list on purpose: this leg is 2025-11-25, which defines
	// neither, so eunox sets neither — and a host's copy crossing would put a header on the
	// wire that only the HOST authored, describing a body eunox may have rewritten.
	for _, smuggled := range []string{
		"X-Mcp-Smuggled", "X-Debug", "X-Forwarded-For", "Cookie", RoutingHeaderMethod, RoutingHeaderName,
	} {
		assert.Empty(t, got.Get(smuggled), "an unlisted host header reached the upstream: %s", smuggled)
	}
	assert.NotEqual(t, "Bearer stolen", got.Get("Authorization"),
		"the host's credential replaced the one the operator configured for this upstream")
}

// On a leg that DOES define the routing headers, eunox's derived value wins over anything
// carried for the host — the routing header must describe the body eunox is sending, and it is
// the ordering in the sender that guarantees it rather than the config check that refuses the
// grant. Driven through the carrier directly, since config makes the grant unreachable.
func TestForwardClientHeaders_EunoxsDerivedRoutingHeadersWinOnADeclaringLeg(t *testing.T) {
	t.Parallel()
	upSrv, lastHeaders := capturingUpstream(t)

	granted := http.Header{
		RoutingHeaderMethod: []string{capability.MethodToolsList},
		RoutingHeaderName:   []string{"some_other_tool"},
	}
	msg := declaringPOST(t, capability.MethodToolsCall, map[string]interface{}{"name": "read_file"})
	ctx := withForwardedHeaders(context.Background(), granted)
	_, _, err := DoMCPHTTP(ctx, upSrv.Client(), upSrv.URL, msg, "", "", capability.Revision20260728)
	require.NoError(t, err)

	got := lastHeaders()
	assert.Equal(t, capability.MethodToolsCall, got.Get(RoutingHeaderMethod),
		"a forwarded Mcp-Method displaced the one eunox derives from the body it is sending")
	assert.Equal(t, "read_file", got.Get(RoutingHeaderName),
		"a forwarded Mcp-Name displaced the one eunox derives from the body it is sending")
}

// With no allowlist at all — the default, and what every existing deployment has — the upstream
// sees only what eunox itself sets.
//
// Asserted against the RESERVED table rather than against a hand-written list of names: that
// table is what config validation refuses an operator, so this is what keeps it covering
// reality. A header eunox starts sending on the upstream leg and forgets to reserve would be
// grantable, and the grant would silently override eunox's own value.
func TestForwardClientHeaders_DefaultForwardsNothingAndEveryHeaderEunoxSendsIsReserved(t *testing.T) {
	t.Parallel()
	srv, proxy, lastHeaders := forwardingProxy(t, nil)

	sid := initSession(t, srv)
	require.NotNil(t, proxy.getSession(sid))
	callWithHeaders(t, srv, sid, map[string]string{"X-Tenant-Id": "acme", "X-Debug": "1"})

	got := lastHeaders(capability.MethodToolsCall)
	require.NotNil(t, got)
	assert.Empty(t, got.Get("X-Tenant-Id"), "a host header crossed with no allowlist configured")
	assert.Empty(t, got.Get("X-Debug"), "a host header crossed with no allowlist configured")

	var unreserved []string
	for name := range got {
		if _, ok := config.ReservedUpstreamHeaders[name]; !ok {
			unreserved = append(unreserved, name)
		}
	}
	sort.Strings(unreserved)
	assert.Empty(t, unreserved,
		"eunox sends %v on the upstream leg without reserving them; an operator could grant one and override eunox's own value", unreserved)
}

// A granted header rides a forward made on behalf of a host request, and nothing else.
//
// eunox's own upstream requests — the opener, the drift probe, the terminating DELETE — are not
// made for a host, so they carry no host header. Asserted on the carrier rather than through a
// live call, because what makes it true is that the ctx is stamped on the host leg alone: a
// call built from any other context has nothing to apply.
func TestForwardClientHeaders_ARequestWithNoGrantCarriesNothing(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodPost, "http://upstream.invalid/mcp", http.NoBody)
	require.NoError(t, applyForwardedHeaders(context.Background(), req))
	assert.Empty(t, req.Header, "a context carrying no grant put headers on an upstream request")
}

// The runtime backstop: a reserved name that somehow reached the carrier is dropped rather than
// applied.
//
// Config refuses it at startup, which is where an operator sees the error. This is the code's
// own answer for the names eunox does NOT set itself — the hop-by-hop set — where the
// apply-first ordering would otherwise leave a forwarded value standing.
func TestForwardClientHeaders_ReservedNamesAreDroppedAtRequestTimeToo(t *testing.T) {
	t.Parallel()
	granted := http.Header{
		"Connection":    []string{"upgrade"},
		"Authorization": []string{"Bearer stolen"},
		"X-Tenant-Id":   []string{"acme"},
	}
	req := httptest.NewRequest(http.MethodPost, "http://upstream.invalid/mcp", http.NoBody)
	require.NoError(t, applyForwardedHeaders(withForwardedHeaders(context.Background(), granted), req))

	assert.Equal(t, "acme", req.Header.Get("X-Tenant-Id"))
	assert.Empty(t, req.Header.Get("Connection"), "a hop-by-hop header eunox never sets survived to the upstream request")
	assert.Empty(t, req.Header.Get("Authorization"))
}

// selectForwardableHeaders reads the operator's names out of the host's headers, and copies
// rather than aliases: the selection outlives the handler, and net/http reuses a request's own
// header storage.
func TestForwardClientHeaders_SelectionIsByNameAndCopies(t *testing.T) {
	t.Parallel()
	src := http.Header{"X-Tenant-Id": []string{"acme", "second"}, "X-Other": []string{"no"}}
	got := selectForwardableHeaders([]string{"X-Tenant-Id", "X-Absent"}, src)

	require.Equal(t, http.Header{"X-Tenant-Id": []string{"acme", "second"}}, got,
		"multi-valued headers must survive intact; a granted header the host did not send must not be invented")

	src["X-Tenant-Id"][0] = "mutated"
	assert.Equal(t, "acme", got.Get("X-Tenant-Id"), "the selection aliased the host request's storage")

	assert.Nil(t, selectForwardableHeaders(nil, src), "no grant must allocate nothing")
}

// forwardingProxy stands up a proxy over a header-capturing upstream with the given allowlist,
// and returns the host-facing server, the proxy, and a reader for the headers of the last POST
// carrying a given JSON-RPC method.
//
// Keyed by method because the handshake and the drift probe reach the upstream too: a
// last-request reader would answer about whichever of them happened to run last, and the
// question here is what rode the ENFORCED call.
func forwardingProxy(t *testing.T, allow []string) (*httptest.Server, *HTTPProxy, func(string) http.Header) {
	t.Helper()
	var mu sync.Mutex
	seen := map[string]http.Header{}
	fake := newFakeUpstream()
	capture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var msg mcp.RPCMsg
		_ = json.Unmarshal(body, &msg)
		mu.Lock()
		seen[msg.Method] = r.Header.Clone()
		mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		fake.ServeHTTP(w, r)
	})
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", capture))
	t.Cleanup(upSrv.Close)

	sink, _ := newTempAuditSink(t)
	proxy := newHTTPProxy(httpProxyOptions{
		UpstreamURL: upSrv.URL,
		PDP:         newTestManifestPDP(capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}}),
		Sink:        sink,
	})
	for _, route := range proxy.routes {
		route.forwardClientHeaders = config.CanonicalForwardClientHeaders(allow)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", proxy.handleMCP)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv, proxy, func(method string) http.Header {
		mu.Lock()
		defer mu.Unlock()
		return seen[method]
	}
}

// callWithHeaders makes one enforced tools/call on an established session, carrying extra
// headers a host chose to send.
func callWithHeaders(t *testing.T, srv *httptest.Server, sid string, headers map[string]string) {
	t.Helper()
	body, err := json.Marshal(mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: capability.MethodToolsCall,
		Params: json.RawMessage(`{"name":"read_file","arguments":{"path":"/tmp/x"}}`),
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", CTJSON)
	req.Header.Set(SessionHeader, sid)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
}
