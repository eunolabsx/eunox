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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
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

// TestHandleMCPGet_EndsStreamAtTokenExpiry pins the transport-layer half of the SSE
// expiry bound: a stream opened with a Bearer token must END when that token's lifetime
// elapses, so a client validated once at open cannot keep receiving server->client
// traffic indefinitely. The PDP-side test only asserts that ValidateToken captures exp
// into JWTClaims; without this, removing the tokenExpiry select arm entirely would leave
// the suite green while the threat model still promises the stream is bounded.
func TestHandleMCPGet_EndsStreamAtTokenExpiry(t *testing.T) {
	fu := newFakeUpstream()
	fakeServer := httptest.NewServer(fu)
	defer fakeServer.Close()

	proxy, srv := newTestRemoteProxy(t, fakeServer.URL, httpProxyOptions{})
	sessID := proxyInitSession(t, proxy, srv)
	sess := proxy.getSession(sessID)
	if sess == nil {
		t.Fatal("session not found after initialize")
	}

	// Drive handleMCPGet directly with claims already in the context: handleMCP injects
	// them via WithJWTClaims after validating the Bearer, so this is the same shape the
	// handler sees in JWT mode, without standing up a JWKS server.
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, sessID)
	req = req.WithContext(pdp.WithJWTClaims(req.Context(), &pdp.JWTClaims{
		Subject:   "user-1",
		Issuer:    "https://idp.example",
		ExpiresAt: time.Now().Add(150 * time.Millisecond),
	}))

	done := make(chan struct{})
	go func() {
		defer close(done)
		proxy.handleMCPGet(httptest.NewRecorder(), req, proxy.routes[""])
	}()

	select {
	case <-done:
		// Returned on its own once the token lifetime elapsed.
	case <-time.After(10 * time.Second):
		t.Fatal("SSE stream outlived its token: handleMCPGet did not return after exp")
	}
}

// TestHandleMCPGet_AlreadyExpiredTokenEndsImmediately pins the fail-closed edge: the JWT
// leeway lets a token that is already past exp validate, so the stream must end at once
// rather than arming a negative timer that never fires.
func TestHandleMCPGet_AlreadyExpiredTokenEndsImmediately(t *testing.T) {
	fu := newFakeUpstream()
	fakeServer := httptest.NewServer(fu)
	defer fakeServer.Close()

	proxy, srv := newTestRemoteProxy(t, fakeServer.URL, httpProxyOptions{})
	sessID := proxyInitSession(t, proxy, srv)

	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, sessID)
	req = req.WithContext(pdp.WithJWTClaims(req.Context(), &pdp.JWTClaims{
		Subject:   "user-1",
		ExpiresAt: time.Now().Add(-time.Hour),
	}))

	done := make(chan struct{})
	go func() {
		defer close(done)
		proxy.handleMCPGet(httptest.NewRecorder(), req, proxy.routes[""])
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("stream with an already-expired token did not end immediately")
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

	env := upstreamEnv()
	for _, kv := range env {
		if strings.HasPrefix(strings.ToUpper(kv), "EUNOX_CONTROL_TOKEN=") ||
			strings.HasPrefix(strings.ToUpper(kv), "EUNOX_REDIS_PASSWORD=") {
			t.Fatalf("upstreamEnv leaked an eunox-owned secret into the child env: %q", kv)
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
		t.Error("upstreamEnv dropped a benign EUNOX_* variable that is not a secret")
	}
}

// TestIsSensitiveUpstreamEnv_CaseAndPrefix pins the two ways the entry match must not be
// naive. Windows is a release target and folds environment-variable case, so a secret set
// as "Eunox_Control_Token" is the credential the proxy actually resolves via os.Getenv
// while os.Environ() reports the operator's casing — a case-sensitive match would hand it
// to the upstream. Conversely, matching a bare prefix would strip an unrelated longer
// variable that merely begins with a secret's name.
func TestIsSensitiveUpstreamEnv_CaseAndPrefix(t *testing.T) {
	t.Parallel()
	strip := []string{
		"EUNOX_CONTROL_TOKEN=abc",
		"EUNOX_REDIS_PASSWORD=abc",
		"Eunox_Control_Token=abc",
		"eunox_redis_password=abc",
		"EuNoX_CoNtRoL_ToKeN=abc",
		"EUNOX_CONTROL_TOKEN=", // empty value is still the secret's slot
	}
	for _, kv := range strip {
		if !isSensitiveUpstreamEnv(kv) {
			t.Errorf("isSensitiveUpstreamEnv(%q) = false, want true (secret must not reach the child)", kv)
		}
	}
	keep := []string{
		"EUNOX_CONTROL_TOKEN_PATH=/etc/eunox/tok", // a different variable
		"EUNOX_REDIS_PASSWORD_FILE=/run/secret",
		"EUNOX_AUDIT_LOG=/var/log/eunox/audit.jsonl",
		"MY_EUNOX_CONTROL_TOKEN=abc",
		"PATH=/usr/bin",
		"NOT_A_PAIR", // no "=", nothing to match
	}
	for _, kv := range keep {
		if isSensitiveUpstreamEnv(kv) {
			t.Errorf("isSensitiveUpstreamEnv(%q) = true, want false (benign variable was stripped)", kv)
		}
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

		// Chain shorter than declared: nothing is provably proxy-written. Falling back to
		// RemoteAddr would be a fail-OPEN, because the peer is a trusted proxy and so sits
		// inside trustedProxyCIDRs — an ipRange allowing that supernet would then match
		// every request. An empty source IP denies with MISSING_CONTEXT instead.
		{"chain shorter than declared hops fails closed", 3, "10.0.0.2:5", []string{"1.2.3.4, 10.0.0.1"}, ""},
		{"single entry with two declared hops fails closed", 2, "10.0.0.2:5", []string{"1.2.3.4"}, ""},
		// A header carrying no usable entries is just "no XFF" -> the peer address.
		{"blank XFF header falls back to RemoteAddr", 1, "10.0.0.2:5", []string{"   "}, "10.0.0.2"},
		{"comma-only XFF header falls back to RemoteAddr", 1, "10.0.0.2:5", []string{" , "}, "10.0.0.2"},
		// A selected entry that normalizes to nothing must still fail closed downstream,
		// not resolve to the trusted peer's own address.
		{"port-only entry stays unparseable", 1, "10.0.0.2:5", []string{":8080"}, ":8080"},
		{"empty brackets entry stays unparseable", 1, "10.0.0.2:5", []string{"[]"}, "[]"},
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

// gatedSSEWriter runs gate exactly once, on the handler's first write, and then behaves as a
// plain recorder. The SSE loop's first write is the open keepalive, which happens after the
// subscriber channel is registered and before the select — the one instant at which a test can
// make an arm ready without racing the handler.
type gatedSSEWriter struct {
	*httptest.ResponseRecorder
	gate func()
	once sync.Once
}

func (w *gatedSSEWriter) Write(p []byte) (int, error) {
	w.once.Do(w.gate)
	return w.ResponseRecorder.Write(p)
}

// TestHandleMCPGet_ExpiredTokenDeliversNoData is the regression for the message arm's missing
// wall-clock re-anchor. expTimer runs on the MONOTONIC clock, which does not advance while the
// host is suspended, so on resume the timer has not fired although exp has passed in wall-clock
// terms. The keepalive arm re-checked for that; the arm that moves DATA did not, and kept
// delivering to an expired token for up to sseKeepaliveInterval past exp.
//
// The suspend itself needs a clock seam this package does not have, so the pin is its
// consequence with both arms READY: the token is already expired (tokenExpiry fires at once) and
// the gate delivers a server-initiated request into the subscriber buffer just before the
// select. Go picks between ready arms at random, so pre-fix the ch arm wrote a data frame on
// about half of these rounds and post-fix on none of them.
//
// A server-initiated REQUEST rather than a notification, because it pins the OTHER half of the
// change: the message is already consumed from the buffer when the check fires, so
// removeSubAndDrain will not recover it and the arm must fail it back to the upstream itself.
// With an id-less notification `unblock` short-circuits and deleting that call would still pass.
func TestHandleMCPGet_ExpiredTokenDeliversNoData(t *testing.T) {
	fu := newFakeUpstream()
	fakeServer := httptest.NewServer(fu)
	defer fakeServer.Close()

	proxy, srv := newTestRemoteProxy(t, fakeServer.URL, httpProxyOptions{})
	sessID := proxyInitSession(t, proxy, srv)
	sess := proxy.getSession(sessID)
	if sess == nil {
		t.Fatal("session not found after initialize")
	}
	// The unblocker answers the blocked initiator through the session's upstream sink; a remote
	// session has none, so give it a capturing one to read the disposition back off.
	uw := &mockUpstreamWriter{}
	sess.upWriter = mcp.NewMsgWriter(&writerAdapter{uw})

	const rounds = 40
	expiredWhileDelivering := 0
	for round := 0; round < rounds; round++ {
		req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
		req.Header.Set(SessionHeader, sessID)
		req = req.WithContext(pdp.WithJWTClaims(req.Context(), &pdp.JWTClaims{
			Subject:   "user-1",
			ExpiresAt: time.Now().Add(-time.Hour),
		}))

		id := json.RawMessage(fmt.Sprintf(`"srv-%d"`, round))
		rec := &gatedSSEWriter{ResponseRecorder: httptest.NewRecorder(), gate: func() {
			sess.broadcastServerRequest(context.Background(), mcp.RPCMsg{
				JSONRPC: "2.0", ID: &id, Method: capability.MethodSamplingCreateMessage,
			})
		}}
		proxy.handleMCPGet(rec, req, proxy.routes[""])

		if strings.Contains(rec.Body.String(), "data:") {
			t.Fatalf("round %d: SSE stream delivered data to an expired token: %q", round, rec.Body.String())
		}
	}

	// Whichever arm won each round, the upstream must never be left blocked: the expiry check
	// answers a request it consumed, removeSubAndDrain answers one still buffered.
	if len(uw.messages) != rounds {
		t.Fatalf("blocked initiators answered = %d, want %d: a server-initiated request was left hanging", len(uw.messages), rounds)
	}
	for _, m := range uw.messages {
		if m.Error == nil {
			t.Fatalf("an unblocking reply carried no error: %+v", m)
		}
		if strings.Contains(m.Error.Message, "token expired") {
			expiredWhileDelivering++
		}
	}
	// Pre-fix the ch arm delivered instead of failing back, so this counter stayed at zero while
	// every round was answered by the drain. Its being non-zero is what proves the arm's own
	// fail-back runs; over 40 rounds a fair select misses it with probability 2^-40.
	if expiredWhileDelivering == 0 {
		t.Errorf("no round failed a consumed server-initiated request back with the expiry reason; the message arm's fail-back never ran")
	}
}
