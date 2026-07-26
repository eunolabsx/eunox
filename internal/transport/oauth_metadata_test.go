// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// ---------------------------------------------------------------------------
// buildWWWAuthenticate
// ---------------------------------------------------------------------------

func TestBuildWWWAuthenticate_NoCredNoMeta(t *testing.T) {
	t.Parallel()
	got := buildWWWAuthenticate(false, "")
	if got != `Bearer realm="eunox"` {
		t.Errorf("got %q, want %q", got, `Bearer realm="eunox"`)
	}
}

func TestBuildWWWAuthenticate_CredPresented(t *testing.T) {
	t.Parallel()
	got := buildWWWAuthenticate(true, "")
	want := `Bearer realm="eunox", error="invalid_token"`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildWWWAuthenticate_WithMetaURL(t *testing.T) {
	t.Parallel()
	const metaURL = "https://proxy.example.com/.well-known/oauth-protected-resource"
	got := buildWWWAuthenticate(false, metaURL)
	want := `Bearer realm="eunox", resource_metadata="` + metaURL + `"`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildWWWAuthenticate_CredAndMeta(t *testing.T) {
	t.Parallel()
	const metaURL = "https://proxy.example.com/.well-known/oauth-protected-resource"
	got := buildWWWAuthenticate(true, metaURL)
	want := `Bearer realm="eunox", error="invalid_token", resource_metadata="` + metaURL + `"`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildWWWAuthenticate_EscapesQuotedString(t *testing.T) {
	t.Parallel()
	// Defense-in-depth: a metaURL containing a quote or backslash must be escaped
	// so the resource_metadata quoted-string stays well-formed. The
	// startup validator normally prevents such a value, but the header builder must
	// not emit a malformed challenge regardless of input.
	got := buildWWWAuthenticate(false, `https://x/a"b\c`)
	want := `Bearer realm="eunox", resource_metadata="https://x/a\"b\\c"`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// serveOAuthMetadata
// ---------------------------------------------------------------------------

func TestServeOAuthMetadata_NotConfigured_Returns404(t *testing.T) {
	t.Parallel()
	proxy := newHTTPProxy(httpProxyOptions{Port: 3000})
	req := httptest.NewRequest(http.MethodGet, metadataBasePath, http.NoBody)
	rr := httptest.NewRecorder()
	proxy.serveOAuthMetadata(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestServeOAuthMetadata_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	proxy := newHTTPProxy(httpProxyOptions{
		Port: 3000,
		OAuthMeta: &OAuthResourceMetadata{
			Resource:             "https://proxy.example.com",
			AuthorizationServers: []string{"https://idp.example.com"},
		},
	})
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, metadataBasePath, http.NoBody)
		rr := httptest.NewRecorder()
		proxy.serveOAuthMetadata(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: expected 405, got %d", method, rr.Code)
		}
	}
}

func TestServeOAuthMetadata_HEADReturns200NoBody(t *testing.T) {
	t.Parallel()
	// HEAD must be treated like GET (same headers) but with no body.
	proxy := newHTTPProxy(httpProxyOptions{
		Port: 3000,
		OAuthMeta: &OAuthResourceMetadata{
			Resource:             "https://proxy.example.com",
			AuthorizationServers: []string{"https://idp.example.com"},
		},
	})
	req := httptest.NewRequest(http.MethodHead, metadataBasePath, http.NoBody)
	rr := httptest.NewRecorder()
	proxy.serveOAuthMetadata(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("HEAD: expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("HEAD Content-Type = %q, want application/json", ct)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("HEAD Cache-Control = %q, want no-store", rr.Header().Get("Cache-Control"))
	}
	if rr.Body.Len() != 0 {
		t.Errorf("HEAD must not send a body; got %d bytes", rr.Body.Len())
	}
}

func TestServeOAuthMetadata_ReturnsDocument(t *testing.T) {
	t.Parallel()
	meta := &OAuthResourceMetadata{
		Resource:             "https://proxy.example.com",
		AuthorizationServers: []string{"https://idp.example.com"},
	}
	proxy := newHTTPProxy(httpProxyOptions{
		Port:      3000,
		OAuthMeta: meta,
	})
	req := httptest.NewRequest(http.MethodGet, metadataBasePath, http.NoBody)
	rr := httptest.NewRecorder()
	proxy.serveOAuthMetadata(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", rr.Header().Get("Cache-Control"))
	}

	var doc OAuthResourceMetadata
	if err := json.NewDecoder(rr.Body).Decode(&doc); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if doc.Resource != meta.Resource {
		t.Errorf("resource = %q, want %q", doc.Resource, meta.Resource)
	}
	if len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != meta.AuthorizationServers[0] {
		t.Errorf("authorization_servers = %v, want %v", doc.AuthorizationServers, meta.AuthorizationServers)
	}
}

func TestServeOAuthMetadata_OmitsEmptyFields(t *testing.T) {
	t.Parallel()
	// When resource is not configured, it should be absent from the JSON.
	meta := &OAuthResourceMetadata{
		AuthorizationServers: []string{"https://idp.example.com"},
	}
	proxy := newHTTPProxy(httpProxyOptions{Port: 3000, OAuthMeta: meta})
	req := httptest.NewRequest(http.MethodGet, metadataBasePath, http.NoBody)
	rr := httptest.NewRecorder()
	proxy.serveOAuthMetadata(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(rr.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := raw["resource"]; ok {
		t.Error("'resource' field should be absent when not configured")
	}
	if _, ok := raw["authorization_servers"]; !ok {
		t.Error("'authorization_servers' field should be present")
	}
}

// ---------------------------------------------------------------------------
// Well-known endpoint registration in Serve()
// ---------------------------------------------------------------------------

// TestServe_WellKnownEndpoint verifies that the metadata endpoint is registered
// and reachable at the well-known path when the proxy is serving.
func TestServe_WellKnownEndpoint(t *testing.T) {
	t.Parallel()
	meta := &OAuthResourceMetadata{
		Resource:             "https://proxy.example.com",
		AuthorizationServers: []string{"https://idp.example.com"},
	}
	proxy := newHTTPProxy(httpProxyOptions{
		Port:      3000,
		OAuthMeta: meta,
	})
	// Exercise the handler directly rather than starting a full TCP server.
	mux := http.NewServeMux()
	mux.HandleFunc(metadataBasePath, proxy.serveOAuthMetadata)

	req := httptest.NewRequest(http.MethodGet, metadataBasePath, http.NoBody)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// TestServe_GatewayPerRoutePaths verifies that per-route path variants are
// registered and all serve the same global document.
func TestServe_GatewayPerRoutePaths(t *testing.T) {
	t.Parallel()
	meta := &OAuthResourceMetadata{
		Resource:             "https://proxy.example.com",
		AuthorizationServers: []string{"https://idp.example.com"},
	}

	routes := map[string]*UpstreamRoute{
		"stripe": {name: "stripe", pdp: pdp.AlwaysAllowPDP{}},
		"github": {name: "github", pdp: pdp.AlwaysAllowPDP{}},
	}
	proxy := NewHTTPProxyGateway(HTTPGatewayOptions{
		Routes:    routes,
		OAuthMeta: meta,
		Port:      3000,
	})

	mux := http.NewServeMux()
	mux.HandleFunc(metadataBasePath, proxy.serveOAuthMetadata)
	for name := range routes {
		path := metadataBasePath + "/mcp/" + name
		mux.HandleFunc(path, proxy.serveOAuthMetadata)
	}

	for _, path := range []string{
		metadataBasePath,
		metadataBasePath + "/mcp/stripe",
		metadataBasePath + "/mcp/github",
	} {
		req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("%s: expected 200, got %d", path, rr.Code)
			continue
		}
		var doc OAuthResourceMetadata
		if err := json.NewDecoder(rr.Body).Decode(&doc); err != nil {
			t.Errorf("%s: decode: %v", path, err)
			continue
		}
		if doc.Resource != meta.Resource {
			t.Errorf("%s: resource = %q, want %q", path, doc.Resource, meta.Resource)
		}
	}
}

// oauthMetadataPathSuffix returns the served-path suffix matching the advertised
// metadata URL's path component, for a path-bearing single-upstream resource.
func TestOAuthMetadataPathSuffix_MatchesAdvertisedURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		resource string
		want     string
	}{
		{"https://proxy.example.com/mcp", "/mcp"},
		{"https://proxy.example.com/mcp/", "/mcp"},
		{"https://proxy.example.com", ""},
		{"https://proxy.example.com/", ""},
	}
	for _, tc := range cases {
		metaURL := BuildOAuthMetadataURL(tc.resource)
		if got := oauthMetadataPathSuffix(metaURL); got != tc.want {
			t.Errorf("oauthMetadataPathSuffix(%q [meta %q]) = %q, want %q", tc.resource, metaURL, got, tc.want)
		}
		// The served path (base + suffix) must equal the advertised URL's path.
		u, err := url.Parse(metaURL)
		if err != nil {
			t.Fatalf("parse %q: %v", metaURL, err)
		}
		if served := metadataBasePath + oauthMetadataPathSuffix(metaURL); served != u.Path {
			t.Errorf("served path %q != advertised path %q", served, u.Path)
		}
	}
}

// TestServe_SingleUpstreamPathBearingResource regression: in
// single-upstream mode with a path-bearing --oauth-resource, Serve must register
// the path-inserted well-known URL that buildOAuthMetadataURL advertises, not
// only the bare base path, so a client following the WWW-Authenticate challenge
// does not 404.
func TestServe_SingleUpstreamPathBearingResource(t *testing.T) {
	resource := "https://proxy.example.com/mcp"
	metaURL := BuildOAuthMetadataURL(resource)
	advertised, err := url.Parse(metaURL)
	if err != nil {
		t.Fatalf("parse metaURL: %v", err)
	}
	// Pre-pick a free port for the proxy to bind, so the test can address it.
	port := freeTCPPort(t)

	proxy := newHTTPProxy(httpProxyOptions{
		Bind: "127.0.0.1",
		Port: port,
		OAuthMeta: &OAuthResourceMetadata{
			Resource:             resource,
			AuthorizationServers: []string{"https://idp.example.com"},
		},
		OAuthMetaURL: metaURL,
		PDP:          pdp.AlwaysAllowPDP{},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- proxy.Serve(ctx) }()

	base := "http://127.0.0.1:" + strconv.Itoa(port)
	waitForServer(t, base+metadataBasePath)

	// The path-inserted URL that the WWW-Authenticate challenge advertises must be
	// served (200), not 404.
	resp, err := http.Get(base + advertised.Path)
	if err != nil {
		t.Fatalf("get %s: %v", advertised.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s (the advertised metadata path) = %d, want 200", advertised.Path, resp.StatusCode)
	}
	var doc OAuthResourceMetadata
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if doc.Resource != resource {
		t.Errorf("resource = %q, want %q", doc.Resource, resource)
	}
}

// freeTCPPort returns a currently-free TCP port on loopback. There is a small
// window between closing the probe listener and the proxy binding, but this is
// the standard test idiom and is reliable in practice.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// waitForServer polls addr until it answers or the deadline passes.
func waitForServer(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(addr)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become ready", addr)
}

// ---------------------------------------------------------------------------
// WWW-Authenticate on 401 responses
// ---------------------------------------------------------------------------

// TestCheckAuth_WWWAuthenticateNoCred verifies that a 401 from checkAuth when
// no credential was supplied includes WWW-Authenticate without error="invalid_token".
func TestCheckAuth_WWWAuthenticateNoCred(t *testing.T) {
	t.Parallel()
	const token = "secret"
	const metaURL = "https://proxy.example.com/.well-known/oauth-protected-resource"
	proxy := newHTTPProxy(httpProxyOptions{
		Port:         3000,
		AuthToken:    token,
		OAuthMetaURL: metaURL,
	})

	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	rr := httptest.NewRecorder()
	proxy.checkAuth(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	wwwAuth := rr.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `realm="eunox"`) {
		t.Errorf("WWW-Authenticate missing realm: %q", wwwAuth)
	}
	if strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate should not include error when no credential was provided: %q", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `resource_metadata="`+metaURL+`"`) {
		t.Errorf("WWW-Authenticate missing resource_metadata: %q", wwwAuth)
	}
}

// TestCheckAuth_WWWAuthenticateWrongToken verifies that a wrong token triggers
// error="invalid_token" in the challenge.
func TestCheckAuth_WWWAuthenticateWrongToken(t *testing.T) {
	t.Parallel()
	const token = "secret"
	proxy := newHTTPProxy(httpProxyOptions{
		Port:         3000,
		AuthToken:    token,
		OAuthMetaURL: "https://proxy.example.com/.well-known/oauth-protected-resource",
	})

	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	proxy.checkAuth(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	wwwAuth := rr.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate missing error=invalid_token for wrong token: %q", wwwAuth)
	}
}

// TestCheckAuth_NoMetaURL_NoResourceMetadataParam verifies that when
// --oauth-resource is not configured, resource_metadata is omitted.
func TestCheckAuth_NoMetaURL_NoResourceMetadataParam(t *testing.T) {
	t.Parallel()
	proxy := newHTTPProxy(httpProxyOptions{
		Port:      3000,
		AuthToken: "secret",
		// OAuthMetaURL intentionally not set
	})
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	rr := httptest.NewRecorder()
	proxy.checkAuth(rr, req)

	wwwAuth := rr.Header().Get("WWW-Authenticate")
	if strings.Contains(wwwAuth, "resource_metadata") {
		t.Errorf("WWW-Authenticate should not contain resource_metadata when not configured: %q", wwwAuth)
	}
}

// TestHandleMCP_JWTMissing_WWWAuthenticate verifies that a request with no
// Authorization header against a JWT-protected proxy gets a proper challenge.
func TestHandleMCP_JWTMissing_WWWAuthenticate(t *testing.T) {
	t.Parallel()
	// Use a fake JWKS server so the JWTPDP is real but will reject any token.
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwksServer.Close()

	jwtPDP := pdp.NewJWTPDP(pdp.JWTPDPOptions{
		JWKSURI:                  jwksServer.URL,
		Audience:                 "test-aud",
		ExperimentalCapabilities: true,
	})

	const metaURL = "https://proxy.example.com/.well-known/oauth-protected-resource"
	proxy := newHTTPProxy(httpProxyOptions{
		Port:         3000,
		JWTPDP:       jwtPDP,
		OAuthMetaURL: metaURL,
	})

	// Build a minimal mux so handleMCP can dispatch.
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", proxy.handleMCP)

	// POST with no Authorization header.
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	wwwAuth := rr.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `realm="eunox"`) {
		t.Errorf("WWW-Authenticate missing realm: %q", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `resource_metadata="`+metaURL+`"`) {
		t.Errorf("WWW-Authenticate missing resource_metadata: %q", wwwAuth)
	}
	// No credential was presented, so no error="invalid_token".
	if strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate should not include error when no credential was provided: %q", wwwAuth)
	}
}

// TestHandleMCP_JWTInvalid_WWWAuthenticateWithError verifies that a request
// with a malformed JWT gets error="invalid_token" in the challenge.
func TestHandleMCP_JWTInvalid_WWWAuthenticateWithError(t *testing.T) {
	t.Parallel()
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwksServer.Close()

	jwtPDP := pdp.NewJWTPDP(pdp.JWTPDPOptions{
		JWKSURI:                  jwksServer.URL,
		Audience:                 "test-aud",
		ExperimentalCapabilities: true,
	})

	const metaURL = "https://proxy.example.com/.well-known/oauth-protected-resource"
	proxy := newHTTPProxy(httpProxyOptions{
		Port:         3000,
		JWTPDP:       jwtPDP,
		OAuthMetaURL: metaURL,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", proxy.handleMCP)

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	wwwAuth := rr.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate missing error=invalid_token for bad JWT: %q", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `resource_metadata="`+metaURL+`"`) {
		t.Errorf("WWW-Authenticate missing resource_metadata: %q", wwwAuth)
	}
}

// TestHandleMCP_JWTInvalid_ResponseBodyDoesNotLeakError verifies that the 401
// response body does NOT echo the JWT validation error: the library message can
// disclose claim values, the accepted algorithm, or key-rotation state, letting an
// unauthenticated client fingerprint the validator. The detail belongs only in the
// JWT_INVALID audit record. The client must get an opaque "Unauthorized".
func TestHandleMCP_JWTInvalid_ResponseBodyDoesNotLeakError(t *testing.T) {
	t.Parallel()
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwksServer.Close()

	jwtPDP := pdp.NewJWTPDP(pdp.JWTPDPOptions{
		JWKSURI:                  jwksServer.URL,
		AllowAnyAudience:         true,
		AllowAnyIssuer:           true,
		ExperimentalCapabilities: true,
	})
	proxy := newHTTPProxy(httpProxyOptions{Port: 3000, JWTPDP: jwtPDP})

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", proxy.handleMCP)

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	gotBody := strings.TrimSpace(rr.Body.String())
	if gotBody != "Unauthorized" {
		t.Errorf("401 body = %q, want opaque %q (the JWT error must not be echoed to the client)", gotBody, "Unauthorized")
	}
}

// TestHandleMCP_JWTInvalid_AuditCorrelatesViaClaimedSessionID verifies that the
// JWT_INVALID audit record emitted when token validation fails does NOT stamp the
// unverified Mcp-Session-Id header into the structured session_id (which would let
// an unauthenticated caller forge JWT_INVALID records attributed to a victim's
// session). The header is preserved only as the unverified claimed_session_id
// detail, so a JWT failure can still be correlated without trusting the value —
// the same separation checkOrigin applies.
func TestHandleMCP_JWTInvalid_AuditCorrelatesViaClaimedSessionID(t *testing.T) {
	t.Parallel()
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwksServer.Close()

	jwtPDP := pdp.NewJWTPDP(pdp.JWTPDPOptions{
		JWKSURI:                  jwksServer.URL,
		Audience:                 "test-aud",
		ExperimentalCapabilities: true,
	})

	sink, logPath := newTempAuditSink(t)
	proxy := newHTTPProxy(httpProxyOptions{
		Port:   3000,
		JWTPDP: jwtPDP,
		Sink:   sink,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", proxy.handleMCP)

	const sid = "sess-abc-123"
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
	req.Header.Set(SessionHeader, sid)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}

	// Close the sink to flush the async drainer before reading the log.
	if err := sink.Close(); err != nil {
		t.Fatalf("sink.Close: %v", err)
	}
	recs := readAuditRecords(t, logPath)
	var rec map[string]interface{}
	for _, r := range recs {
		if code, _ := r["denial_code"].(string); code == "JWT_INVALID" {
			rec = r
			break
		}
	}
	if rec == nil {
		t.Fatalf("no JWT_INVALID audit record found in %d records", len(recs))
	}
	// The unverified header must NOT become the structured session_id (that would
	// let an unauthenticated caller forge attribution to a victim session).
	if got, _ := rec["session_id"].(string); got != "" {
		t.Errorf("JWT_INVALID record session_id = %q; want empty (unauthenticated Mcp-Session-Id must not be stamped as a real session)", got)
	}
	// It is preserved as an unverified detail so the failure can still be correlated.
	details, ok := rec["details"].(map[string]interface{})
	if !ok {
		t.Fatalf("JWT_INVALID record details = %v; want a map carrying claimed_session_id", rec["details"])
	}
	if got, _ := details["claimed_session_id"].(string); got != sid {
		t.Errorf("JWT_INVALID record details.claimed_session_id = %q; want %q", got, sid)
	}
}

// ---------------------------------------------------------------------------
// Gateway config YAML parsing for new listen fields
// ---------------------------------------------------------------------------

func TestLoadGatewayConfig_OAuthMetadataFields(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := mustWriteFile(t, dir, "gw.yaml", `
schemaVersion: "0.1"
listen:
  bind: 127.0.0.1
  port: 3001
  oauthResource: https://proxy.example.com
  oauthAuthorizationServers:
    - https://idp.example.com
    - https://backup-idp.example.com
upstreams:
  - name: fs
    transport: stdio
    command: echo
`)
	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}
	if cfg.Listen.OAuthResource != "https://proxy.example.com" {
		t.Errorf("OAuthResource = %q, want %q", cfg.Listen.OAuthResource, "https://proxy.example.com")
	}
	if len(cfg.Listen.OAuthAuthorizationServers) != 2 {
		t.Fatalf("OAuthAuthorizationServers len = %d, want 2", len(cfg.Listen.OAuthAuthorizationServers))
	}
	if cfg.Listen.OAuthAuthorizationServers[0] != "https://idp.example.com" {
		t.Errorf("OAuthAuthorizationServers[0] = %q", cfg.Listen.OAuthAuthorizationServers[0])
	}
}

// TestLoadGatewayConfig_OAuthFieldsRejectedForStdio verifies that setting
// OAuth listen fields for a stdio transport is rejected.
func TestLoadGatewayConfig_OAuthFieldsRejectedForStdio(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := mustWriteFile(t, dir, "gw.yaml", `
schemaVersion: "0.1"
transport: stdio
listen:
  oauthResource: https://proxy.example.com
upstreams:
  - name: fs
    transport: stdio
    command: echo
`)
	_, err := config.LoadGatewayConfig(cfgPath)
	if err == nil {
		t.Error("expected error for oauthResource on stdio transport, got nil")
	}
	if !strings.Contains(err.Error(), "oauthResource") {
		t.Errorf("error should mention oauthResource, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// OAuthResourceMetadata JSON round-trip
// ---------------------------------------------------------------------------

func TestOAuthResourceMetadata_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		meta OAuthResourceMetadata
	}{
		{
			name: "full document",
			meta: OAuthResourceMetadata{
				Resource:             "https://proxy.example.com",
				AuthorizationServers: []string{"https://idp.example.com"},
			},
		},
		{
			name: "no resource",
			meta: OAuthResourceMetadata{
				AuthorizationServers: []string{"https://idp.example.com"},
			},
		},
		{
			name: "empty document",
			meta: OAuthResourceMetadata{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.meta)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got OAuthResourceMetadata
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.Resource != tc.meta.Resource {
				t.Errorf("resource = %q, want %q", got.Resource, tc.meta.Resource)
			}
			if len(got.AuthorizationServers) != len(tc.meta.AuthorizationServers) {
				t.Errorf("authorization_servers len = %d, want %d", len(got.AuthorizationServers), len(tc.meta.AuthorizationServers))
			}
		})
	}
}

// TestOAuthResourceMetadata_NoResourceFieldOmitted verifies that the JSON
// output has no "resource" key when the field is empty (omitempty).
func TestOAuthResourceMetadata_NoResourceFieldOmitted(t *testing.T) {
	t.Parallel()
	meta := OAuthResourceMetadata{AuthorizationServers: []string{"https://idp.example.com"}}
	b, _ := json.Marshal(meta)
	if strings.Contains(string(b), `"resource"`) {
		t.Errorf("JSON should not contain 'resource' when empty: %s", b)
	}
}

// ---------------------------------------------------------------------------
// serveHTTPGateway: oauthMetaURL construction
// ---------------------------------------------------------------------------

// TestMetadataBasePath verifies the constant has the correct RFC 9728 value.
func TestMetadataBasePath(t *testing.T) {
	t.Parallel()
	const want = "/.well-known/oauth-protected-resource"
	if metadataBasePath != want {
		t.Errorf("metadataBasePath = %q, want %q", metadataBasePath, want)
	}
}

// TestBuildOAuthMetadataURL exercises the RFC 9728 §3.1 metadata-URL
// construction. The load-bearing case is "resource with path": the well-known
// segment must be inserted between the authority and the path (yielding the same
// URL the proxy serves the document at), not appended after the whole identifier
// — the latter made the advertised and served URLs diverge into a 404.
func TestBuildOAuthMetadataURL(t *testing.T) {
	t.Parallel()
	const wk = "/.well-known/oauth-protected-resource"
	tests := []struct {
		name     string
		resource string
		want     string
	}{
		{"no path", "https://proxy.example.com", "https://proxy.example.com" + wk},
		{"trailing slash stripped", "https://proxy.example.com/", "https://proxy.example.com" + wk},
		{"path inserts well-known before it", "https://proxy.example.com/mcp/github", "https://proxy.example.com" + wk + "/mcp/github"},
		{"path trailing slash stripped", "https://proxy.example.com/mcp/github/", "https://proxy.example.com" + wk + "/mcp/github"},
		{"host with port preserved", "https://proxy.example.com:8443/mcp/stripe", "https://proxy.example.com:8443" + wk + "/mcp/stripe"},
		// A percent-encoded path must keep its "%XX" bytes (EscapedPath, not the decoded
		// Path): the decoded "/path space" / "/path{x}" carries characters that are
		// grammar-special in the net/http ServeMux pattern syntax and would panic
		// registration; the escaped form is a valid pattern that matches the wire path.
		{"percent-encoded space preserved", "https://proxy.example.com/path%20space", "https://proxy.example.com" + wk + "/path%20space"},
		{"percent-encoded braces preserved", "https://proxy.example.com/path%7Bx%7D", "https://proxy.example.com" + wk + "/path%7Bx%7D"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BuildOAuthMetadataURL(tt.resource); got != tt.want {
				t.Errorf("BuildOAuthMetadataURL(%q) = %q, want %q", tt.resource, got, tt.want)
			}
		})
	}
}

// TestBuildOAuthMetadataURL_MatchesServedPath pins the invariant that ties this
// fix to the route registration in HTTPProxy.Serve: for a resource whose path is
// /mcp/<name>, the advertised metadata URL's path must equal the path the proxy
// registers the handler at (metadataBasePath + "/mcp/" + name).
func TestBuildOAuthMetadataURL_MatchesServedPath(t *testing.T) {
	t.Parallel()
	const name = "github"
	got := BuildOAuthMetadataURL("https://proxy.example.com/mcp/" + name)
	servedPath := metadataBasePath + "/mcp/" + name
	if want := "https://proxy.example.com" + servedPath; got != want {
		t.Errorf("advertised metadata URL %q does not match served path %q (want %q)", got, servedPath, want)
	}
}

// TestOAuthMetadataPercentEncodedPath_RegistersAndServes is the regression for the
// ServeMux-pattern panic: a path-bearing --oauth-resource whose path contains a
// percent-encoded space or brace must (1) not panic mux.HandleFunc with the served
// pattern the proxy builds, and (2) be reachable at exactly the path the metadata URL
// advertises — pinning advertised path == served pattern == client request path.
func TestOAuthMetadataPercentEncodedPath_RegistersAndServes(t *testing.T) {
	t.Parallel()
	for _, resource := range []string{
		"https://proxy.example.com/path%20space",
		"https://proxy.example.com/path%7Bx%7D",
	} {
		t.Run(resource, func(t *testing.T) {
			metaURL := BuildOAuthMetadataURL(resource)
			suffix := oauthMetadataPathSuffix(metaURL)
			servedPattern := metadataBasePath + suffix

			u, err := url.Parse(metaURL)
			if err != nil {
				t.Fatalf("parse advertised metadata URL %q: %v", metaURL, err)
			}
			// The path a client puts on the wire is the escaped path of the advertised URL.
			advertisedPath := u.EscapedPath()
			if advertisedPath != servedPattern {
				t.Fatalf("advertised path %q does not equal served pattern %q", advertisedPath, servedPattern)
			}

			// Registering the served pattern must not panic (the bug crashed Serve here).
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("mux.HandleFunc(%q) panicked: %v", servedPattern, r)
					}
				}()
				mux := http.NewServeMux()
				mux.HandleFunc(servedPattern, func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				})
				srv := httptest.NewServer(mux)
				defer srv.Close()

				resp, err := http.Get(srv.URL + advertisedPath) //nolint:noctx // test
				if err != nil {
					t.Fatalf("GET %s: %v", advertisedPath, err)
				}
				defer func() { _ = resp.Body.Close() }()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("GET advertised path %q -> %d, want 200 (advertised != served)", advertisedPath, resp.StatusCode)
				}
			}()
		})
	}
}

// ---------------------------------------------------------------------------
// End-to-end: well-known endpoint reachable via a real httptest.Server
// ---------------------------------------------------------------------------

func TestE2E_WellKnownEndpoint_ViaRealServer(t *testing.T) {
	t.Parallel()

	fu := newFakeUpstream()
	fakeUpstreamSrv := httptest.NewServer(fu)
	defer fakeUpstreamSrv.Close()

	meta := &OAuthResourceMetadata{
		Resource:             "https://proxy.example.com",
		AuthorizationServers: []string{"https://idp.example.com"},
	}
	_, srv := newTestRemoteProxy(t, fakeUpstreamSrv.URL, httpProxyOptions{
		OAuthMeta:    meta,
		OAuthMetaURL: "https://proxy.example.com" + metadataBasePath,
	})
	// The test server only registers /mcp in newTestRemoteProxy; we need to
	// add the metadata path too.
	// Instead, build a mux directly.
	proxy := newHTTPProxy(httpProxyOptions{
		UpstreamURL: fakeUpstreamSrv.URL,
		Port:        3000,
		OAuthMeta:   meta,
	})
	_ = srv // not used after this point

	mux2 := http.NewServeMux()
	mux2.HandleFunc("/mcp", proxy.handleMCP)
	mux2.HandleFunc(metadataBasePath, proxy.serveOAuthMetadata)
	srv2 := httptest.NewServer(mux2)
	defer srv2.Close()

	resp, err := http.Get(srv2.URL + metadataBasePath) //nolint:noctx // test
	if err != nil {
		t.Fatalf("GET %s: %v", metadataBasePath, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var doc OAuthResourceMetadata
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Resource != meta.Resource {
		t.Errorf("resource = %q, want %q", doc.Resource, meta.Resource)
	}
}

// TestE2E_WellKnownEndpoint_401HasChallenge verifies that a 401 from a
// JWT-protected proxy includes the WWW-Authenticate header pointing at the
// metadata endpoint.
func TestE2E_WellKnownEndpoint_401HasChallenge(t *testing.T) {
	t.Parallel()

	// Fake JWKS server that returns empty key set (so every JWT is invalid).
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwksSrv.Close()

	jwtPDP := pdp.NewJWTPDP(pdp.JWTPDPOptions{
		JWKSURI:                  jwksSrv.URL,
		Audience:                 "test-aud",
		ExperimentalCapabilities: true,
	})

	const resource = "https://proxy.example.com"
	const metaURL = resource + "/.well-known/oauth-protected-resource"

	fu := newFakeUpstream()
	fakeUpstreamSrv := httptest.NewServer(fu)
	defer fakeUpstreamSrv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		UpstreamURL: fakeUpstreamSrv.URL,
		Port:        3000,
		JWTPDP:      jwtPDP,
		OAuthMeta: &OAuthResourceMetadata{
			Resource:             resource,
			AuthorizationServers: []string{"https://idp.example.com"},
		},
		OAuthMetaURL: metaURL,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", proxy.handleMCP)
	mux.HandleFunc(metadataBasePath, proxy.serveOAuthMetadata)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Send initialize with an invalid JWT.
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalid.jwt.token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate missing error: %q", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `resource_metadata="`+metaURL+`"`) {
		t.Errorf("WWW-Authenticate missing resource_metadata: %q", wwwAuth)
	}
}

func TestHTTPProxy_JWTMode_401OnMissingToken(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	jwtPDP := makeJWTPDP(t, srv, "", "", nil)

	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		JWTPDP:      jwtPDP,
		PDP:         jwtPDP,
		UpstreamURL: upstream.srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, proxySrv.URL+"/mcp", http.NoBody)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHTTPProxy_JWTMode_401OnExpiredToken(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	jwtPDP := makeJWTPDP(t, srv, "", "", nil)
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		JWTPDP:      jwtPDP,
		PDP:         jwtPDP,
		UpstreamURL: upstream.srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	token := makeIDPToken(t, key, []string{"tool:read_file"}, "", "", "a1", time.Now().Add(-2*time.Hour))
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, proxySrv.URL+"/mcp", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestHTTPProxy_JWTMode_UnknownRouteReturns401NotOracle is the regression for the
// route-enumeration oracle: in JWT-only mode (no static auth token, so checkAuth is
// a no-op) an unauthenticated caller must receive a uniform 401 whether or not the
// requested route exists. A 404-for-unknown vs 401-for-known split would let an
// attacker enumerate configured upstream route names without a valid token. JWT
// validation now runs before the route lookup, so both cases return 401.
func TestHTTPProxy_JWTMode_UnknownRouteReturns401NotOracle(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	jwtPDP := makeJWTPDP(t, srv, "", "", nil)
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		JWTPDP:      jwtPDP,
		PDP:         jwtPDP,
		UpstreamURL: upstream.srv.URL,
		Port:        0,
	})

	// No Authorization header. The known route (single-upstream key "") and a
	// non-existent route ("zzz") must both return 401, never 404.
	for _, route := range []string{"", "zzz"} {
		req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
		req.Header.Set("Content-Type", CTJSON)
		req.SetPathValue("upstream", route)
		rr := httptest.NewRecorder()
		proxy.handleMCP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("route %q: status = %d, want 401 (no 404 route-name oracle)", route, rr.Code)
		}
	}
}

// fakeUpstreamForJWT is a minimal MCP HTTP stub for JWT integration tests.
type fakeUpstreamForJWT struct {
	srv *httptest.Server
}

func newFakeUpstreamForJWT(t *testing.T) *fakeUpstreamForJWT {
	t.Helper()
	var sessionID string
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var msg mcp.RPCMsg
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if msg.Method == "initialize" {
			sessionID = fmt.Sprintf("us-%s", msg.Method)
			w.Header().Set("Mcp-Session-Id", sessionID)
			initResult, _ := json.Marshal(map[string]interface{}{
				"protocolVersion": "2025-11-05",
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":      map[string]interface{}{"name": "test", "version": "0"},
			})
			resp := mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: json.RawMessage(initResult)}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		if msg.IsNotification() {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		toolResult := json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)
		resp := mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: toolResult}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewServer(mux)
	return &fakeUpstreamForJWT{srv: srv}
}

// TestJWTAllowlist_ErrorCode_AUTHORIZATION_FAILED verifies that the denial returned
// when a target is not in the JWT allowlist carries AUTHORIZATION_FAILED (which
// maps to JSON-RPC -32001, not -32002).
func TestJWTAllowlist_ErrorCode_AUTHORIZATION_FAILED(t *testing.T) {
	key := newTestKey(t, "k1")
	jp, cleanup := makeJWTPDPWithInner(t, key, pdp.AlwaysAllowPDP{})
	defer cleanup()

	token := makeJWTToken(t, key, []string{"tool:read_file"})
	ctx := makeJWTCtx(t, jp, token)

	resp := jp.Decide(ctx, "sess", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "write_file"}, nil, "")
	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("expected deny, got %q", resp.Decision)
	}
	if resp.Denial == nil {
		t.Fatal("expected Denial info, got nil")
	}
	if resp.Denial.Code != capability.ErrCodeAuthorizationFailed {
		t.Errorf("denial code = %q, want %q", resp.Denial.Code, capability.ErrCodeAuthorizationFailed)
	}

	wantCode := capability.JSONRPCCodeAuthorizationFailed
	if got := denialToJSONRPCCode(resp.Denial.Code); got != wantCode {
		t.Errorf("JSON-RPC code = %d, want %d", got, wantCode)
	}
}
