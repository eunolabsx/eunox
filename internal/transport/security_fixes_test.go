// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
)

// TestLoopbackOnly_DNSRebindingHostRejected pins the DNS-rebinding guard on the
// loopback-only endpoints: a loopback SOURCE (which a rebound victim's own browser
// satisfies) is no longer sufficient — the request Host must also be a trusted name.
// A rebound request carries the attacker's Host and is rejected; a real loopback scrape
// (localhost / 127.0.0.1) passes. The source-IP check still rejects an off-host caller.
func TestLoopbackOnly_DNSRebindingHostRejected(t *testing.T) {
	t.Parallel()
	p := &HTTPProxy{allowedOriginHosts: buildAllowedOriginHosts("")}
	check := func(remoteAddr, host string) bool {
		r := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
		r.RemoteAddr = remoteAddr
		r.Host = host
		return p.loopbackOnly(httptest.NewRecorder(), r)
	}
	if check("127.0.0.1:5555", "attacker.com:3000") {
		t.Error("a rebound foreign Host with a loopback source must be rejected (DNS-rebinding guard)")
	}
	if check("127.0.0.1:5555", "attacker.com") {
		t.Error("a rebound foreign Host (no port) must be rejected")
	}
	if !check("127.0.0.1:5555", "127.0.0.1:3000") {
		t.Error("a loopback source with a 127.0.0.1 Host must pass")
	}
	if !check("127.0.0.1:5555", "localhost") {
		t.Error("a localhost Host must pass")
	}
	if !check("[::1]:5555", "[::1]:3000") {
		t.Error("an IPv6 loopback source + Host must pass")
	}
	if check("8.8.8.8:5555", "127.0.0.1") {
		t.Error("a non-loopback source must be rejected regardless of Host")
	}
}

// TestUpstreamEnv_FiltersEunoxSecrets pins that UpstreamEnv strips the eunox-owned
// secrets an upstream subprocess must never inherit, while leaving every other variable
// (including benign EUNOX_* config) intact.
func TestUpstreamEnv_FiltersEunoxSecrets(t *testing.T) {
	t.Setenv("EUNOX_CONTROL_TOKEN", "secret-token")
	t.Setenv("EUNOX_REDIS_PASSWORD", "secret-pass")
	t.Setenv("EUNOX_AUDIT_LOG", "/var/log/eunox/audit.jsonl") // benign eunox var: must survive
	t.Setenv("SUBPROCESS_ENV_MARKER", "keepme")

	env := UpstreamEnv()
	for _, kv := range env {
		if strings.HasPrefix(kv, "EUNOX_CONTROL_TOKEN=") || strings.HasPrefix(kv, "EUNOX_REDIS_PASSWORD=") {
			t.Fatalf("UpstreamEnv leaked an eunox-owned secret into the child env: %q", kv)
		}
	}
	has := func(want string) bool {
		for _, kv := range env {
			if kv == want {
				return true
			}
		}
		return false
	}
	if !has("SUBPROCESS_ENV_MARKER=keepme") {
		t.Error("UpstreamEnv dropped a benign non-eunox variable")
	}
	if !has("EUNOX_AUDIT_LOG=/var/log/eunox/audit.jsonl") {
		t.Error("UpstreamEnv dropped a benign EUNOX_* variable that is not a secret")
	}
}

// TestSourceIP_WalksPastTrustedProxyChain pins that sourceIP resolves the real client
// behind a CHAIN of trusted proxies by walking X-Forwarded-For right-to-left and
// skipping trusted-proxy hops, rather than blindly taking the right-most entry (which is
// the inner proxy's own address when two or more trusted proxies are chained).
func TestSourceIP_WalksPastTrustedProxyChain(t *testing.T) {
	t.Parallel()
	_, trusted, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	p := &HTTPProxy{trustFwdFor: true, trustedProxyNets: []*net.IPNet{trusted}}
	mk := func(remoteAddr string, xff ...string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
		r.RemoteAddr = remoteAddr
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		return r
	}
	cases := []struct {
		name   string
		remote string
		xff    []string
		want   string
	}{
		{"untrusted peer ignores XFF entirely", "203.0.113.9:5", []string{"1.2.3.4"}, "203.0.113.9"},
		{"single trusted hop -> right-most is the client", "10.0.0.1:5", []string{"1.2.3.4"}, "1.2.3.4"},
		{"two trusted hops -> skip the inner proxy", "10.0.0.2:5", []string{"1.2.3.4, 10.0.0.1"}, "1.2.3.4"},
		{"three trusted hops", "10.0.0.3:5", []string{"1.2.3.4, 10.0.0.1, 10.0.0.2"}, "1.2.3.4"},
		{"multiple XFF lines are flattened", "10.0.0.2:5", []string{"1.2.3.4", "10.0.0.1"}, "1.2.3.4"},
		{"all entries trusted -> fall through to RemoteAddr", "10.0.0.2:5", []string{"10.0.0.1"}, "10.0.0.2"},
		{"forged left-most hop is ignored", "10.0.0.1:5", []string{"9.9.9.9, 1.2.3.4"}, "1.2.3.4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := p.sourceIP(mk(tc.remote, tc.xff...)); got != tc.want {
				t.Fatalf("sourceIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestHandleMCPPost_ShutdownReturns503 pins that a session-creating initialize refused
// because the proxy is draining for graceful shutdown surfaces a retryable 503, not the
// generic 500 (whose "failed to start upstream" log also misattributes the cause). The
// upstream handshake succeeds against the fake server; registerSession then refuses under
// the shutdown latch.
func TestHandleMCPPost_ShutdownReturns503(t *testing.T) {
	fu := newFakeUpstream()
	fakeServer := httptest.NewServer(fu)
	defer fakeServer.Close()

	proxy, srv := newTestRemoteProxy(t, fakeServer.URL, httpProxyOptions{})
	proxy.mu.Lock()
	proxy.shuttingDown = true
	proxy.mu.Unlock()

	resp := postMCP(t, srv, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "initialize"}, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("initialize during shutdown = %d, want 503 (retryable), not 500", resp.StatusCode)
	}
}
