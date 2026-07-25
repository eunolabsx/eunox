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

// TestLoopbackOnly_AdmitsLocalNonAllowlistedHosts pins that the DNS-rebinding Host pin
// does not 403 legitimate local callers whose Host is not one of the seeded allowlist
// names. A rebind necessarily presents a NAME the attacker controls, so admitting
// loopback literals and an absent Host costs nothing: fetching a literal directly is
// cross-origin and requireValidOrigin rejects it before the handler, and browsers always
// send Host. Without this, an HTTP/1.0 probe or a scrape via an alternate loopback
// address regressed from 200 to 403.
func TestLoopbackOnly_AdmitsLocalNonAllowlistedHosts(t *testing.T) {
	t.Parallel()
	// Wildcard bind: the allowlist is exactly {localhost, 127.0.0.1, ::1}, so every
	// Host below is genuinely outside it.
	p := &HTTPProxy{allowedOriginHosts: buildAllowedOriginHosts("0.0.0.0")}
	check := func(remoteAddr, host string) bool {
		r := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
		r.RemoteAddr = remoteAddr
		r.Host = host
		return p.loopbackOnly(httptest.NewRecorder(), r)
	}
	allow := []struct{ name, remote, host string }{
		{"alternate loopback literal", "127.0.0.2:5555", "127.0.0.2:3000"},
		{"alternate loopback literal, no port", "127.0.0.2:5555", "127.0.0.2"},
		{"another loopback literal", "127.1.2.3:5555", "127.1.2.3:3000"},
		{"absent Host (HTTP/1.0 probe)", "127.0.0.1:5555", ""},
		{"localhost with trailing FQDN dot", "127.0.0.1:5555", "localhost."},
		{"uppercase localhost", "127.0.0.1:5555", "LOCALHOST:3000"},
	}
	for _, tc := range allow {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !check(tc.remote, tc.host) {
				t.Errorf("loopbackOnly(remote=%q, Host=%q) = false, want true (legitimate local caller)", tc.remote, tc.host)
			}
		})
	}
	// The guard must still hold: a foreign NAME is what a rebind presents.
	deny := []struct{ name, remote, host string }{
		{"rebound attacker name", "127.0.0.1:5555", "attacker.com"},
		{"rebound attacker name with port", "127.0.0.1:5555", "attacker.com:3000"},
		{"non-loopback literal Host", "127.0.0.1:5555", "8.8.8.8"},
		{"name resolving nowhere", "127.0.0.1:5555", "internal.corp.example"},
	}
	for _, tc := range deny {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if check(tc.remote, tc.host) {
				t.Errorf("loopbackOnly(remote=%q, Host=%q) = true, want false (rebinding guard)", tc.remote, tc.host)
			}
		})
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

// TestSourceIP_CountsDeclaredProxyHops pins that sourceIP resolves the client behind a
// CHAIN of trusted proxies by counting declared hops (listen.trustedProxyHops) rather
// than by testing entries against trustedProxyCIDRs.
//
// Counting is what makes the resolution unspoofable. Inferring hops from CIDR membership
// cannot distinguish a proxy's appended entry from a client whose OWN address falls in
// the trusted range, so it would skip the client's real entry and return a forged one to
// its left — see the "client inside the trusted CIDR" cases, which are the regression
// this test exists to hold.
func TestSourceIP_CountsDeclaredProxyHops(t *testing.T) {
	t.Parallel()
	_, trusted, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
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
		hops   int
		remote string
		xff    []string
		want   string
	}{
		{"untrusted peer ignores XFF entirely", 1, "203.0.113.9:5", []string{"1.2.3.4"}, "203.0.113.9"},
		{"unset hop count defaults to the single-proxy right-most read", 0, "10.0.0.1:5", []string{"1.2.3.4"}, "1.2.3.4"},
		{"single hop -> right-most is the client", 1, "10.0.0.1:5", []string{"1.2.3.4"}, "1.2.3.4"},
		{"two hops -> second from the right", 2, "10.0.0.2:5", []string{"1.2.3.4, 10.0.0.1"}, "1.2.3.4"},
		{"three hops -> third from the right", 3, "10.0.0.3:5", []string{"1.2.3.4, 10.0.0.1, 10.0.0.2"}, "1.2.3.4"},
		{"multiple XFF lines are flattened before counting", 2, "10.0.0.2:5", []string{"1.2.3.4", "10.0.0.1"}, "1.2.3.4"},
		{"forged left-most hop is ignored", 1, "10.0.0.1:5", []string{"9.9.9.9, 1.2.3.4"}, "1.2.3.4"},
		{"forged hops cannot lengthen the chain", 2, "10.0.0.2:5", []string{"9.9.9.9, 8.8.8.8, 1.2.3.4, 10.0.0.1"}, "1.2.3.4"},

		// The regression: the client's own address is inside trustedProxyCIDRs, so a
		// membership test would mistake its proxy-appended entry for a hop, skip it, and
		// hand back the attacker-chosen 192.168.1.5. Counting reads the real entry.
		{"client inside the trusted CIDR is not skipped", 1, "10.0.0.1:5", []string{"192.168.1.5, 10.5.5.5"}, "10.5.5.5"},
		{"client inside the trusted CIDR behind two hops", 2, "10.0.0.2:5", []string{"192.168.1.5, 10.5.5.5, 10.0.0.1"}, "10.5.5.5"},

		// Chain shorter than declared: nothing is provably proxy-written, so fall back to
		// the immediate peer instead of trusting a client-supplied entry.
		{"chain shorter than declared hops falls back to RemoteAddr", 3, "10.0.0.2:5", []string{"1.2.3.4, 10.0.0.1"}, "10.0.0.2"},
		{"single entry with two declared hops falls back", 2, "10.0.0.2:5", []string{"1.2.3.4"}, "10.0.0.2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := &HTTPProxy{
				trustFwdFor:      true,
				trustedProxyNets: []*net.IPNet{trusted},
				trustedProxyHops: tc.hops,
			}
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
