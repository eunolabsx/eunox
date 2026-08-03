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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// TestWrapRoutesWithJWT_EmptyEffectiveAudienceFailsClosed pins that a route with no
// effective audience (no manifest 'audience', no global Audience fallback) is rejected
// when audience pinning is active, rather than silently widening the shared validator
// and disabling per-route narrowing. AllowAnyAudience is the only way to opt out.
func TestWrapRoutesWithJWT_EmptyEffectiveAudienceFailsClosed(t *testing.T) {
	mkPDP := func() pdp.PolicyDecisionPoint {
		return pdp.NewManifestPDP(nil, enforcement.New(), killswitch.NewInMemory())
	}
	routes := map[string]*UpstreamRoute{
		"a": {name: "a", pdp: mkPDP(), manifest: &config.LocalManifest{Audience: "svc-a"}, sink: &routeSink{}},
		"b": {name: "b", pdp: mkPDP(), manifest: &config.LocalManifest{}, sink: &routeSink{}},
	}
	// opts.Audience "" + route "b" pins nothing + pinning active ⟹ error.
	if _, err := WrapRoutesWithJWT(routes, pdp.JWTPDPOptions{Issuer: "iss"}); err == nil {
		t.Fatal("WrapRoutesWithJWT accepted a route with no effective audience while pinning was active; want a fail-closed error")
	}
	// The same shape is fine once audience pinning is disabled.
	if _, err := WrapRoutesWithJWT(routes, pdp.JWTPDPOptions{Issuer: "iss", AllowAnyAudience: true}); err != nil {
		t.Fatalf("WrapRoutesWithJWT rejected a valid AllowAnyAudience config: %v", err)
	}
}

// mustWrapRoutesWithJWT calls WrapRoutesWithJWT and fails the test on error, so
// callers that pass a valid audience configuration keep reading as one expression.
func mustWrapRoutesWithJWT(t *testing.T, routes map[string]*UpstreamRoute, opts pdp.JWTPDPOptions) *pdp.JWTPDP {
	t.Helper()
	v, err := WrapRoutesWithJWT(routes, opts)
	if err != nil {
		t.Fatalf("WrapRoutesWithJWT: %v", err)
	}
	return v
}

// mustWriteFile writes content to dir/name (controlling the extension, which
// config.LoadManifest uses to choose YAML vs JSON parsing) and returns the path.
func mustWriteFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// captureStderr redirects os.Stderr for the duration of fn and returns everything
// written to it. A goroutine drains the pipe concurrently so a large write cannot
// deadlock on a full pipe buffer, and both pipe ends are closed before returning.
// os.Stderr is process-global, so callers must not run with t.Parallel().
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

func TestBuildRoutes_VersionAndPDP(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifest := mustWriteFile(t, dir, "m.yaml", "schemaVersion: \"0.1\"\nname: test\nversion: \"1.2.3\"\ncapabilities:\n  - target: tool:read_file\n    actions: [call]\n")
	cfg := &config.GatewayConfig{Upstreams: []config.UpstreamConfig{{
		Name: "fs", Transport: "stdio", Command: "echo",
		Policy: []string{manifest}, ExpectVersion: "1.2.3",
	}}}
	sink, err := audit.Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	routes, err := BuildRoutes(cfg, sink, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), false, func(*config.LocalManifest, bool) drift.CheckFunc { return nil })
	if err != nil {
		t.Fatalf("BuildRoutes: %v", err)
	}
	r := routes["fs"]
	if r == nil {
		t.Fatal("route fs missing")
	}
	if _, ok := r.pdp.(*pdp.ManifestPDP); !ok {
		t.Errorf("want *ManifestPDP, got %T", r.pdp)
	}
	if r.sink == nil {
		t.Fatal("routeSink not built")
	}
	if r.sink.policyVersion != "1.2.3" {
		t.Errorf("policyVersion=%q, want 1.2.3", r.sink.policyVersion)
	}
	if !strings.HasPrefix(r.sink.policySHA256, "sha256:") || len(r.sink.policySHA256) < 20 {
		t.Errorf("policySHA256=%q, want sha256:<hex>", r.sink.policySHA256)
	}
	if r.sink.upstream != "fs" {
		t.Errorf("routeSink not stamped: %+v", r.sink)
	}
}

// TestBuildRoutes_NilSinkLeavesRouteSinkNil pins the typed-nil rule: with no audit
// sink configured, a route must be left with a nil r.sink so asRecorder(route.sink)
// yields a genuine nil INTERFACE at every call site. Wrapping nil in a &routeSink{}
// would satisfy every `rec != nil` guard in the shared core and silently defeat its
// "no sink configured" fast paths — dispatchList would decode and count every */list
// catalog it has nowhere to record.
func TestBuildRoutes_NilSinkLeavesRouteSinkNil(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifest := mustWriteFile(t, dir, "m.yaml", "schemaVersion: \"0.1\"\nname: test\nversion: \"1.2.3\"\ncapabilities:\n  - target: tool:read_file\n    actions: [call]\n")
	cfg := &config.GatewayConfig{Upstreams: []config.UpstreamConfig{{
		Name: "fs", Transport: "stdio", Command: "echo", Policy: []string{manifest},
	}}}
	routes, err := BuildRoutes(cfg, nil, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), false, func(*config.LocalManifest, bool) drift.CheckFunc { return nil })
	if err != nil {
		t.Fatalf("BuildRoutes: %v", err)
	}
	r := routes["fs"]
	if r == nil {
		t.Fatal("route fs missing")
	}
	if r.sink != nil {
		t.Fatalf("r.sink = %+v, want nil for a sink-less route", r.sink)
	}
	// The interface conversion every call site performs must be a true nil, not a
	// non-nil interface holding a nil pointer.
	if rec := asRecorder(r.sink); rec != nil {
		t.Fatalf("asRecorder(r.sink) = %#v, want a nil interface", rec)
	}
}
func TestBuildRoutes_NoPolicyInheritsAudit(t *testing.T) {
	t.Parallel()
	cfg := &config.GatewayConfig{Upstreams: []config.UpstreamConfig{{Name: "fs", Transport: "stdio", Command: "echo"}}}
	cfg.Defaults.Enforcement = capability.EnforcementAudit
	routes, err := BuildRoutes(cfg, nil, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), false, func(*config.LocalManifest, bool) drift.CheckFunc { return nil })
	if err != nil {
		t.Fatalf("BuildRoutes: %v", err)
	}
	r := routes["fs"]
	if _, ok := r.pdp.(pdp.AlwaysAllowPDP); !ok {
		t.Errorf("want alwaysAllowPDP for no-policy route, got %T", r.pdp)
	}
	if !r.audit {
		t.Error("enforcement: audit should be inherited from defaults")
	}
	// No audit sink was passed, so no routeSink is built at all (see
	// TestBuildRoutes_NilSinkLeavesRouteSinkNil).
	if r.sink != nil {
		t.Errorf("r.sink should be nil when BuildRoutes got no sink, got %+v", r.sink)
	}

	// With a real sink the route does get a routeSink, and a policyless route stamps
	// an empty policy version/digest on it (nothing is in force to name).
	dir := t.TempDir()
	sink, err := audit.Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	routes, err = BuildRoutes(cfg, sink, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), false, func(*config.LocalManifest, bool) drift.CheckFunc { return nil })
	if err != nil {
		t.Fatalf("BuildRoutes with sink: %v", err)
	}
	if s := routes["fs"].sink; s == nil || s.policyVersion != "" || s.policySHA256 != "" {
		t.Errorf("policy provenance should be empty for a no-policy route, got %+v", s)
	}
}

// TestBuildRoutes_ManifestWithRouteAuditEmitsBanner pins: a route with a
// REAL manifest (all entries normal) AND route-level enforcement: audit downgrades
// every downgradable deny to a forwarded observe (kill-switch and other HardDeny
// denials still hard-block), but AuditOnlyCount() == 0 so the per-entry
// NOTICE never fires. BuildRoutes must still emit a loud AUDIT MODE banner, matching
// the stdio host, so a globally-observed policy is not silently un-enforced.
func TestBuildRoutes_ManifestWithRouteAuditEmitsBanner(t *testing.T) {
	dir := t.TempDir()
	manifest := mustWriteFile(t, dir, "m.yaml", "schemaVersion: \"0.1\"\nname: test\nversion: \"1.0.0\"\ncapabilities:\n  - target: tool:read_file\n    actions: [call]\n")
	cfg := &config.GatewayConfig{Upstreams: []config.UpstreamConfig{{
		Name: "fs", Transport: "stdio", Command: "echo",
		Policy: []string{manifest}, Enforcement: capability.EnforcementAudit,
	}}}

	var buildErr error
	out := captureStderr(t, func() {
		_, buildErr = BuildRoutes(cfg, nil, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), false, func(*config.LocalManifest, bool) drift.CheckFunc { return nil })
	})
	if buildErr != nil {
		t.Fatalf("BuildRoutes: %v", buildErr)
	}
	if !strings.Contains(out, "AUDIT MODE") {
		t.Errorf("expected a loud AUDIT MODE banner for a manifest + route-level audit route, got:\n%s", out)
	}
}

// TestBuildRoutes_RemoteUpstreamServerInitiatedNotice pins that a remote HTTP
// upstream emits a startup NOTICE that server-initiated requests are not serviced,
// so an operator is warned at runtime instead of debugging a silent hang; a stdio
// upstream must NOT emit it.
func TestBuildRoutes_RemoteUpstreamServerInitiatedNotice(t *testing.T) {
	dir := t.TempDir()
	manifest := mustWriteFile(t, dir, "m.yaml", "schemaVersion: \"0.1\"\nname: test\nversion: \"1.0.0\"\ncapabilities:\n  - target: tool:read_file\n    actions: [call]\n")
	cfg := &config.GatewayConfig{Upstreams: []config.UpstreamConfig{
		{Name: "remote", Transport: "http", UpstreamURL: "https://mcp.example.com", Policy: []string{manifest}},
		{Name: "local", Transport: "stdio", Command: "echo", Policy: []string{manifest}},
	}}

	var buildErr error
	s := captureStderr(t, func() {
		_, buildErr = BuildRoutes(cfg, nil, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), false, func(*config.LocalManifest, bool) drift.CheckFunc { return nil })
	})
	if buildErr != nil {
		t.Fatalf("BuildRoutes: %v", buildErr)
	}
	if !strings.Contains(s, "remote HTTP upstream") || !strings.Contains(s, "server-initiated requests") {
		t.Errorf("expected a server-initiated-not-serviced NOTICE for the remote upstream, got:\n%s", s)
	}
	// Exactly one such NOTICE must fire — a count proves the stdio route stayed
	// silent, which a bare !Contains("local") check would not (it only proves the
	// literal string is absent). The single NOTICE must name the remote http route.
	if got := strings.Count(s, "is a remote HTTP upstream"); got != 1 {
		t.Errorf("expected exactly one remote-HTTP-upstream NOTICE (only the http route), got %d:\n%s", got, s)
	}
	if !strings.Contains(s, `"remote"`) {
		t.Errorf("the NOTICE must name the remote http upstream, got:\n%s", s)
	}
	if strings.Contains(s, `"local"`) {
		t.Errorf("the stdio upstream must not appear in any server-initiated NOTICE, got:\n%s", s)
	}
}

// TestBuildRoutes_NoPolicyPerRouteAudit confirms the wiretap escape hatch: a
// route that sets 'enforcement: audit' directly (not via defaults) with no
// policy builds successfully as an allow-all/observe route.
func TestBuildRoutes_NoPolicyPerRouteAudit(t *testing.T) {
	t.Parallel()
	cfg := &config.GatewayConfig{Upstreams: []config.UpstreamConfig{{
		Name: "fs", Transport: "stdio", Command: "echo", Enforcement: capability.EnforcementAudit,
	}}}
	routes, err := BuildRoutes(cfg, nil, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), false, func(*config.LocalManifest, bool) drift.CheckFunc { return nil })
	if err != nil {
		t.Fatalf("BuildRoutes: %v", err)
	}
	r := routes["fs"]
	if _, ok := r.pdp.(pdp.AlwaysAllowPDP); !ok {
		t.Errorf("want alwaysAllowPDP for no-policy audit route, got %T", r.pdp)
	}
	if !r.audit {
		t.Errorf("per-route enforcement: audit should set observe mode: %+v", r)
	}
}

// TestServeOAuthMetadata_NoResource_Returns404 verifies the fix:
// --jwks-uri without --oauth-resource is a valid configuration (JWT validation
// does not require advertising an OAuth discovery document), and the proxy must
// never serve a non-conforming RFC 9728 document missing the REQUIRED `resource`
// field — when no resource URI is configured, oauthMeta is nil and the metadata
// endpoint returns 404 rather than a broken document. (The not-published path is
// exercised here at the handler level; the end-to-end JWT-without-resource demo
// in demo/scripts/ci-test-jwt.sh guards the startup path.)
func TestServeOAuthMetadata_NoResource_Returns404(t *testing.T) {
	t.Parallel()
	// oauthMeta nil mirrors what serveHTTPGateway builds when oauthResource is "".
	proxy := newHTTPProxy(httpProxyOptions{Port: 3000})
	req := httptest.NewRequest(http.MethodGet, metadataBasePath, http.NoBody)
	rr := httptest.NewRecorder()
	proxy.serveOAuthMetadata(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when no resource URI is configured, got %d", rr.Code)
	}
}

// TestBuildRoutes_GlobalStrictDrift verifies that the --strict-drift flag is
// folded into each route's strict-drift setting at construction: it promotes
// every policed route — including one with an explicit strictDrift: false —
// while a policyless route is never promoted (it has nothing to drift-check).
func TestBuildRoutes_GlobalStrictDrift(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifest := mustWriteFile(t, dir, "m.yaml", "schemaVersion: \"0.1\"\nname: test\nversion: \"1.0.0\"\ncapabilities: []\n")
	optOut := false
	newCfg := func() *config.GatewayConfig {
		return &config.GatewayConfig{Upstreams: []config.UpstreamConfig{
			{Name: "policed", Transport: "stdio", Command: "echo", Policy: []string{manifest}},
			{Name: "optedOut", Transport: "stdio", Command: "echo", Policy: []string{manifest}, StrictDrift: &optOut},
			// A policyless route is only legal in audit mode (SEC-05 fail-closed);
			// it still has no manifest, so strict-drift must never promote it.
			{Name: "unpoliced", Transport: "stdio", Command: "echo", Enforcement: capability.EnforcementAudit},
		}}
	}

	// strictDrift is no longer a route field (it is a BuildRoutes local, used only to
	// build the drift hook), so observe the resolved value through driftCheckFor, which
	// receives (manifest, strict) per route. A non-nil manifest marks a policed route.
	type driftArg struct{ policed, strict bool }
	captureDrift := func(rec *[]driftArg) func(*config.LocalManifest, bool) drift.CheckFunc {
		return func(m *config.LocalManifest, strict bool) drift.CheckFunc {
			*rec = append(*rec, driftArg{policed: m != nil, strict: strict})
			return nil
		}
	}

	t.Run("flag off honors per-route config", func(t *testing.T) {
		var calls []driftArg
		if _, err := BuildRoutes(newCfg(), nil, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), false, captureDrift(&calls)); err != nil {
			t.Fatalf("BuildRoutes: %v", err)
		}
		for _, c := range calls {
			if c.strict {
				t.Errorf("flag off: got strict=true (policed=%v), want false", c.policed)
			}
		}
	})

	t.Run("flag on promotes policed routes only", func(t *testing.T) {
		var calls []driftArg
		if _, err := BuildRoutes(newCfg(), nil, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), true, captureDrift(&calls)); err != nil {
			t.Fatalf("BuildRoutes: %v", err)
		}
		// Two policed routes (policed + optedOut — the latter's strictDrift:false is
		// overridden by the global flag) must be promoted to strict; the one policyless
		// route has nothing to check and must never become fatal.
		policedStrict, policedTotal, policylessStrict := 0, 0, 0
		for _, c := range calls {
			switch {
			case c.policed:
				policedTotal++
				if c.strict {
					policedStrict++
				}
			case c.strict:
				policylessStrict++
			}
		}
		if policedTotal != 2 || policedStrict != 2 {
			t.Errorf("flag on: want both policed routes promoted to strict, got %d/%d", policedStrict, policedTotal)
		}
		if policylessStrict != 0 {
			t.Error("policyless route must not be promoted to strict")
		}
	})

	t.Run("flag on with no policed route builds without error", func(t *testing.T) {
		cfg := &config.GatewayConfig{Upstreams: []config.UpstreamConfig{
			{Name: "a", Transport: "stdio", Command: "echo", Enforcement: capability.EnforcementAudit},
		}}
		var calls []driftArg
		if _, err := BuildRoutes(cfg, nil, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), true, captureDrift(&calls)); err != nil {
			t.Fatalf("BuildRoutes: %v (flag must warn, not fail, on policyless config)", err)
		}
		for _, c := range calls {
			if c.strict {
				t.Error("policyless route must not be promoted to strict")
			}
		}
	})
}
func TestRouteSink_StampsAuditRecordAndVerifies(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)
	rs := &routeSink{sink: sink, upstream: "stripe", policyVersion: "2.1.0", policySHA256: "sha256:deadbeef"}
	rs.RecordAllow(context.Background(), "sess-1", "create_charge", "tools/call", map[string]interface{}{"amount": 100}, nil, true, nil, nil)
	_ = sink.Close()

	recs := readAuditRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r["upstream"] != "stripe" {
		t.Errorf("upstream=%v, want stripe", r["upstream"])
	}
	if r["policy_version"] != "2.1.0" {
		t.Errorf("policy_version=%v, want 2.1.0", r["policy_version"])
	}
	if r["policy_sha256"] != "sha256:deadbeef" {
		t.Errorf("policy_sha256=%v", r["policy_sha256"])
	}

	// audit-verify: the HMAC must still verify with the new fields present.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		ok, err := sink.VerifyRecord([]byte(line))
		if err != nil || !ok {
			t.Errorf("HMAC verify failed (ok=%v err=%v) for line: %s", ok, err, line)
		}
	}
}

// nilUpstreamRoute (empty upstream/version) must produce records identical in
// shape to the legacy single-upstream path (fields omitted).
func TestRouteSink_EmptyUpstreamOmitsFields(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)
	rs := &routeSink{sink: sink} // upstream/version/hash all empty
	rs.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	_ = sink.Close()

	recs := readAuditRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	for _, k := range []string{"upstream", "policy_version", "policy_sha256"} {
		if _, present := recs[0][k]; present {
			t.Errorf("%q should be omitted when empty, but record has it: %v", k, recs[0])
		}
	}
}
func newGatewayTestServer(t *testing.T, routes map[string]*UpstreamRoute) *httptest.Server {
	t.Helper()
	proxy := NewHTTPProxyGateway(HTTPGatewayOptions{Routes: routes})
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp/{upstream}", proxy.handleMCP)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}
func postGateway(t *testing.T, srv *httptest.Server, route string, body interface{}, sid string) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp/"+route, strings.NewReader(string(b)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if sid != "" {
		req.Header.Set(SessionHeader, sid)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post /mcp/%s: %v", route, err)
	}
	return resp
}
func initGatewaySession(t *testing.T, srv *httptest.Server, route string) string {
	t.Helper()
	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "t", "version": "0"},
		},
	}
	resp := postGateway(t, srv, route, body, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("init route %q: status %d", route, resp.StatusCode)
	}
	sid := resp.Header.Get(SessionHeader)
	if sid == "" {
		t.Fatalf("init route %q: no session id returned", route)
	}
	return sid
}
func TestGateway_RoutesIndependently(t *testing.T) {
	fakeA := newFakeUpstream()
	srvA := httptest.NewServer(fakeA)
	defer srvA.Close()
	fakeB := newFakeUpstream()
	srvB := httptest.NewServer(fakeB)
	defer srvB.Close()

	routes := map[string]*UpstreamRoute{
		"a": {name: "a", transport: "http", upstreamURL: srvA.URL, pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{}},
		"b": {name: "b", transport: "http", upstreamURL: srvB.URL, pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{}},
	}
	srv := newGatewayTestServer(t, routes)

	sidA := initGatewaySession(t, srv, "a")

	callBody := map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{"name": "read_file", "arguments": map[string]interface{}{"path": "/x"}},
	}
	resp := postGateway(t, srv, "a", callBody, sidA)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("tools/call on route a: status %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	if got := fakeA.CountByMethod("tools/call"); got != 1 {
		t.Errorf("fakeA tools/call count = %d, want 1", got)
	}
	if got := fakeB.CountByMethod("tools/call"); got != 0 {
		t.Errorf("fakeB tools/call count = %d, want 0 (route isolation broken)", got)
	}
}
func TestGateway_UnknownRoute404(t *testing.T) {
	routes := map[string]*UpstreamRoute{
		"a": {name: "a", transport: "http", upstreamURL: "http://unused.example", pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{}},
	}
	srv := newGatewayTestServer(t, routes)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "t", "version": "0"}},
	}
	resp := postGateway(t, srv, "bogus", body, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown route: status %d, want 404", resp.StatusCode)
	}
}
func TestGateway_CrossRouteSession409(t *testing.T) {
	fakeA := newFakeUpstream()
	srvA := httptest.NewServer(fakeA)
	defer srvA.Close()
	fakeB := newFakeUpstream()
	srvB := httptest.NewServer(fakeB)
	defer srvB.Close()

	routes := map[string]*UpstreamRoute{
		"a": {name: "a", transport: "http", upstreamURL: srvA.URL, pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{}},
		"b": {name: "b", transport: "http", upstreamURL: srvB.URL, pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{}},
	}
	srv := newGatewayTestServer(t, routes)

	// Open a session on route a, then try to use it on route b.
	sidA := initGatewaySession(t, srv, "a")
	callBody := map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{"name": "read_file", "arguments": map[string]interface{}{}},
	}
	resp := postGateway(t, srv, "b", callBody, sidA)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("cross-route session: status %d, want 409", resp.StatusCode)
	}
}

// TestGateway_CrossRouteGetDelete409 verifies that GET (SSE) and DELETE honor
// the same route binding as POST: a session opened on one route cannot be
// streamed or torn down via another route's path, while the correct route still
// works.
func TestGateway_CrossRouteGetDelete409(t *testing.T) {
	fakeA := newFakeUpstream()
	srvA := httptest.NewServer(fakeA)
	defer srvA.Close()
	fakeB := newFakeUpstream()
	srvB := httptest.NewServer(fakeB)
	defer srvB.Close()

	routes := map[string]*UpstreamRoute{
		"a": {name: "a", transport: "http", upstreamURL: srvA.URL, pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{}},
		"b": {name: "b", transport: "http", upstreamURL: srvB.URL, pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{}},
	}
	srv := newGatewayTestServer(t, routes)

	sidA := initGatewaySession(t, srv, "a")

	do := func(method, route, sid string) int {
		req, err := http.NewRequest(method, srv.URL+"/mcp/"+route, http.NoBody)
		if err != nil {
			t.Fatalf("new %s request: %v", method, err)
		}
		if sid != "" {
			req.Header.Set(SessionHeader, sid)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s /mcp/%s: %v", method, route, err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	// Route a's session addressed at route b → 409 for both verbs.
	if code := do(http.MethodGet, "b", sidA); code != http.StatusConflict {
		t.Errorf("cross-route GET: status %d, want 409", code)
	}
	if code := do(http.MethodDelete, "b", sidA); code != http.StatusConflict {
		t.Errorf("cross-route DELETE: status %d, want 409", code)
	}
	// DELETE on the correct route still closes the session.
	if code := do(http.MethodDelete, "a", sidA); code != http.StatusNoContent {
		t.Errorf("same-route DELETE: status %d, want 204", code)
	}
}

// TestGateway_PerRouteJWTIntersection verifies that a single bearer token is
// intersected against each route's own manifest: a capability the token grants
// is still denied on a route whose manifest doesn't allow it, and a tool the
// token doesn't grant is denied even where the manifest would allow it.
func TestGateway_PerRouteJWTIntersection(t *testing.T) {
	key := newTestKey(t, "k1")
	jwks := makeJWKSServer(t, key)
	defer jwks.Close()
	const iss, aud = "https://idp.test", "eunox"

	fakeA := newFakeUpstream()
	srvA := httptest.NewServer(fakeA)
	defer srvA.Close()
	fakeB := newFakeUpstream()
	srvB := httptest.NewServer(fakeB)
	defer srvB.Close()

	mkPDP := func(tool string) pdp.PolicyDecisionPoint {
		return pdp.NewManifestPDP(
			[]capability.Constraint{{Target: "tool:" + tool, Actions: []string{"call"}}},
			enforcement.New(), killswitch.NewInMemory())
	}
	routes := map[string]*UpstreamRoute{
		"a": {name: "a", transport: "http", upstreamURL: srvA.URL, pdp: mkPDP("read_file"), sink: &routeSink{}},
		"b": {name: "b", transport: "http", upstreamURL: srvB.URL, pdp: mkPDP("write_file"), sink: &routeSink{}},
	}
	validator := mustWrapRoutesWithJWT(t, routes, pdp.JWTPDPOptions{
		JWKSURI: jwks.URL + "/", Issuer: iss, Audience: aud, KillSwitch: killswitch.NewInMemory(),
		ExperimentalCapabilities: true,
	})
	proxy := NewHTTPProxyGateway(HTTPGatewayOptions{Routes: routes, JWTPDP: validator})
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp/{upstream}", proxy.handleMCP)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Token grants ONLY tool:read_file.
	token := makeIDPToken(t, key, []string{"tool:read_file"}, iss, aud, "agent-1", time.Now().Add(time.Hour))

	post := func(route, sid string, body map[string]interface{}) *http.Response {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp/"+route, strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		if sid != "" {
			req.Header.Set(SessionHeader, sid)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post /mcp/%s: %v", route, err)
		}
		return resp
	}
	initBody := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "t", "version": "0"}},
	}
	call := func(tool string) map[string]interface{} {
		return map[string]interface{}{
			"jsonrpc": "2.0", "id": 2, "method": "tools/call",
			"params": map[string]interface{}{"name": tool, "arguments": map[string]interface{}{}},
		}
	}
	isErr := func(resp *http.Response) bool {
		defer func() { _ = resp.Body.Close() }()
		var m mcp.RPCMsg
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return m.Error != nil
	}
	initSID := func(route string) string {
		resp := post(route, "", initBody)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("init route %s: status %d", route, resp.StatusCode)
		}
		return resp.Header.Get(SessionHeader)
	}

	sidA := initSID("a")
	// read_file on a: JWT grants ∩ manifestA allows → ALLOW.
	if isErr(post("a", sidA, call("read_file"))) {
		t.Error("route a read_file: expected allow (JWT ∩ manifestA), got error")
	}
	// write_file on a: JWT does not grant it → DENY (JWT side).
	if !isErr(post("a", sidA, call("write_file"))) {
		t.Error("route a write_file: expected JWT denial, got allow")
	}

	sidB := initSID("b")
	// read_file on b: token grants read_file, but manifestB only allows write_file
	// → DENY. Proves the token is intersected against *route b's own* manifest.
	if !isErr(post("b", sidB, call("read_file"))) {
		t.Error("route b read_file: expected per-route manifestB denial, got allow")
	}

	// Missing token → 401 even for initialize.
	noAuth, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp/a", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	noAuth.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(noAuth)
	if err != nil {
		t.Fatalf("no-auth request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("missing token: status %d, want 401", resp.StatusCode)
	}
}

// TestBuildRoutes_WiretapPDPWiredToKillSwitch is the end-to-end guard for the
// wiretap kill fix: a policyless 'enforcement: audit' route is built with a
// kill-switch-bearing AlwaysAllowPDP, so a global kill denies its calls instead of
// the route forwarding forever.
func TestBuildRoutes_WiretapPDPWiredToKillSwitch(t *testing.T) {
	ks := killswitch.NewInMemory()
	rt := &UpstreamRoute{name: "wt"}
	// A policyless upstream (no policy, no expectVersion) yields the wiretap PDP.
	dp, _, _, _, err := LoadUpstreamPDP(&config.UpstreamConfig{Name: "wt"}, config.HostTransportStdio, "", nil, nil, ks, false)
	if err != nil {
		t.Fatalf("LoadUpstreamPDP: %v", err)
	}
	rt.pdp = dp

	ctx := context.Background()
	// Before any kill the wiretap route allows.
	if dec := rt.pdp.Decide(ctx, "sess-1", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "read_file"}, nil, ""); dec.Decision != capability.DecisionAllow {
		t.Fatalf("pre-kill: want allow, got %v", dec.Decision)
	}
	// After a global kill the wiretap route hard-blocks.
	if err := ks.ActivateGlobal(ctx); err != nil {
		t.Fatalf("ActivateGlobal: %v", err)
	}
	dec := rt.pdp.Decide(ctx, "sess-1", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "read_file"}, nil, "")
	if dec.Decision != capability.DecisionDeny {
		t.Fatalf("post-kill: want deny, got %v", dec.Decision)
	}
	if dec.Denial == nil || dec.Denial.Code != capability.ErrCodeKillSwitch {
		t.Fatalf("post-kill: want KILL_SWITCH denial, got %+v", dec.Denial)
	}
	if blk := rt.pdp.CheckKill(ctx, "sess-1"); blk == nil {
		t.Fatal("post-kill: CheckKill must block */list enumeration on a wiretap route")
	}
}

// TestBuildRoutes_RelativePolicyResolvedAgainstConfigDir verifies that a relative
// 'policy:' path resolves against the gateway config file's directory (cfg.BaseDir),
// not the process working directory, so a config launched from any cwd still finds
// its manifests. The negative control confirms that with no BaseDir the same relative
// path is cwd-relative and (from a different cwd) misses.
//
// cwd is process-global, so this test must not run with t.Parallel().
func TestBuildRoutes_RelativePolicyResolvedAgainstConfigDir(t *testing.T) {
	configDir := t.TempDir()
	mustWriteFile(t, configDir, "policy.yaml", "schemaVersion: \"0.1\"\nname: test\nversion: \"1.0.0\"\ncapabilities:\n  - target: tool:read_file\n    actions: [call]\n")

	// Run from a different directory so a cwd-relative resolution cannot accidentally
	// find configDir/policy.yaml.
	otherDir := t.TempDir()
	saved, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(otherDir); err != nil {
		t.Fatalf("chdir otherDir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(saved) })

	driftFor := func(*config.LocalManifest, bool) drift.CheckFunc { return nil }

	// BaseDir set: the relative policy path resolves against it.
	cfg := &config.GatewayConfig{
		BaseDir: configDir,
		Upstreams: []config.UpstreamConfig{{
			Name: "fs", Transport: "stdio", Command: "echo", Policy: []string{"policy.yaml"},
		}},
	}
	routes, err := BuildRoutes(cfg, nil, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), false, driftFor)
	if err != nil {
		t.Fatalf("BuildRoutes with BaseDir: %v", err)
	}
	if routes["fs"] == nil || routes["fs"].manifest == nil {
		t.Fatalf("route fs manifest not loaded from BaseDir-relative policy path")
	}

	// Negative control: no BaseDir, same relative path, run from otherDir — the
	// cwd-relative lookup misses and BuildRoutes fails.
	cwdCfg := &config.GatewayConfig{
		Upstreams: []config.UpstreamConfig{{
			Name: "fs", Transport: "stdio", Command: "echo", Policy: []string{"policy.yaml"},
		}},
	}
	if _, err := BuildRoutes(cwdCfg, nil, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), false, driftFor); err == nil {
		t.Error("BuildRoutes with empty BaseDir from a different cwd should fail to find the relative policy, but succeeded")
	}
}

// TestGateway_PerRouteAudience is the end-to-end per-route-audience acceptance: two routes whose
// manifests declare audience svc-a and svc-b accept only the matching audience. A token
// minted for svc-a is allowed on the svc-a route and denied on the svc-b route (audience
// mismatch), and its */list enumeration on the wrong route is empty. The shared
// validator accepts the union {svc-a, svc-b}, so the token clears validation on both
// routes; the per-route wrapper is what narrows.
func TestGateway_PerRouteAudience(t *testing.T) {
	key := newTestKey(t, "k1")
	jwks := makeJWKSServer(t, key)
	defer jwks.Close()
	const iss = "https://idp.test"

	fakeA := newFakeUpstream()
	srvA := httptest.NewServer(fakeA)
	defer srvA.Close()
	fakeB := newFakeUpstream()
	srvB := httptest.NewServer(fakeB)
	defer srvB.Close()

	mkPDP := func() pdp.PolicyDecisionPoint {
		return pdp.NewManifestPDP(
			[]capability.Constraint{{Target: "tool:read_file", Actions: []string{"call"}}},
			enforcement.New(), killswitch.NewInMemory())
	}
	routes := map[string]*UpstreamRoute{
		"a": {name: "a", transport: "http", upstreamURL: srvA.URL, pdp: mkPDP(), manifest: &config.LocalManifest{Audience: "svc-a"}, sink: &routeSink{}},
		"b": {name: "b", transport: "http", upstreamURL: srvB.URL, pdp: mkPDP(), manifest: &config.LocalManifest{Audience: "svc-b"}, sink: &routeSink{}},
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

	// Token minted for svc-a, granting tool:read_file.
	token := makeIDPToken(t, key, []string{"tool:read_file"}, iss, "svc-a", "agent-1", time.Now().Add(time.Hour))

	post := func(route, sid string, body map[string]interface{}) *http.Response {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp/"+route, strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		if sid != "" {
			req.Header.Set(SessionHeader, sid)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post /mcp/%s: %v", route, err)
		}
		return resp
	}
	initBody := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "t", "version": "0"}},
	}
	call := map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{"name": "read_file", "arguments": map[string]interface{}{}},
	}
	isErr := func(resp *http.Response) bool {
		defer func() { _ = resp.Body.Close() }()
		var m mcp.RPCMsg
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return m.Error != nil
	}
	initSID := func(route string) string {
		resp := post(route, "", initBody)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("init route %s: status %d", route, resp.StatusCode)
		}
		return resp.Header.Get(SessionHeader)
	}

	sidA := initSID("a")
	// svc-a token on the svc-a route: audience matches → ALLOW.
	if isErr(post("a", sidA, call)) {
		t.Error("route svc-a must allow a svc-a token's permitted call")
	}

	// svc-a token on the svc-b route: the session-creating initialize is denied BEFORE
	// any upstream is spawned/contacted, so no Mcp-Session-Id is returned and the body is
	// a JSON-RPC error. This is the completed per-route audience guarantee — a wrong-audience token
	// gets nothing on route B, not even a session (route B's upstream is never reached).
	respB := post("b", "", initBody)
	gotSID := respB.Header.Get(SessionHeader)
	deniedB := isErr(respB) // reads and closes the body
	if gotSID != "" {
		t.Errorf("route svc-b must not create a session for a svc-a token, got session id %q", gotSID)
	}
	if !deniedB {
		t.Error("route svc-b initialize must be denied for a svc-a token (audience mismatch)")
	}
}

// TestGateway_PerRouteAudience_ExistingSessionRevalidated covers the per-route audience
// pin on host-initiated traffic over an ALREADY-established session: the per-request
// bearer is re-validated against the shared union, so a token minted for a sibling
// route's audience plus a stolen session id must still be refused on every path
// (enforced calls, the re-initialize echo, notifications), not just session creation.
func TestGateway_PerRouteAudience_ExistingSessionRevalidated(t *testing.T) {
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

	tokenA := makeIDPToken(t, key, []string{"tool:read_file"}, iss, "svc-a", "agent-1", time.Now().Add(time.Hour))
	tokenB := makeIDPToken(t, key, []string{"tool:read_file"}, iss, "svc-b", "agent-1", time.Now().Add(time.Hour))

	post := func(sid, token string, body map[string]interface{}) *http.Response {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp/a", strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		if sid != "" {
			req.Header.Set(SessionHeader, sid)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		return resp
	}
	initBody := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "t", "version": "0"}},
	}
	call := map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{"name": "read_file", "arguments": map[string]interface{}{}},
	}
	reinit := map[string]interface{}{"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": map[string]interface{}{}}
	isErr := func(resp *http.Response) bool {
		defer func() { _ = resp.Body.Close() }()
		var m mcp.RPCMsg
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return m.Error != nil
	}

	// Establish a legit session on route A with a svc-a token.
	ri := post("", tokenA, initBody)
	sidA := ri.Header.Get(SessionHeader)
	if ri.StatusCode != http.StatusOK || sidA == "" {
		t.Fatalf("expected a session on route A for the svc-a token, status=%d sid=%q", ri.StatusCode, sidA)
	}
	_ = ri.Body.Close()

	// A svc-b token (accepted by the union) presented on route A's session is refused on
	// the enforced call path...
	if !isErr(post(sidA, tokenB, call)) {
		t.Error("a cross-audience (svc-b) token on route A's session must be denied on tools/call")
	}
	// ...and on the re-initialize echo (which would otherwise leak the upstream's caps).
	if !isErr(post(sidA, tokenB, reinit)) {
		t.Error("a cross-audience (svc-b) re-initialize on route A's session must be denied")
	}
	// ...and on the SSE stream open (GET), which would otherwise deliver route A's
	// server->client traffic to the svc-b token. The refusal is an immediate 403.
	gReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/mcp/a", http.NoBody)
	gReq.Header.Set("Authorization", "Bearer "+tokenB)
	gReq.Header.Set(SessionHeader, sidA)
	gResp, gErr := http.DefaultClient.Do(gReq)
	if gErr != nil {
		t.Fatalf("get: %v", gErr)
	}
	_ = gResp.Body.Close()
	if gResp.StatusCode != http.StatusForbidden {
		t.Errorf("a cross-audience (svc-b) SSE GET on route A's session must be refused 403, got %d", gResp.StatusCode)
	}
	// The legitimate svc-a token still works on its own session.
	if isErr(post(sidA, tokenA, call)) {
		t.Error("the svc-a token must still be allowed on its own session")
	}
}

// TestGateway_SessionOwnerBinding_DifferentSubRefused covers the session-ownership
// check: a re-initialize echoes the upstream capabilities captured when the session was
// created, so a SECOND identity authenticated to the SAME route (same audience pin,
// different sub) that learns the session id must not reinitialize it and read the first
// client's captured state. The audience pin alone does not catch this — both subs share
// the audience — so the owner binding (issuer+sub) is the load-bearing check.
func TestGateway_SessionOwnerBinding_DifferentSubRefused(t *testing.T) {
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
	routes := map[string]*UpstreamRoute{
		"a": {name: "a", transport: "http", upstreamURL: srvA.URL, pdp: mkPDP(), manifest: &config.LocalManifest{Audience: "svc-a"}, sink: &routeSink{}},
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

	// Two tokens for the SAME audience (svc-a) but DIFFERENT subjects.
	tokenSub1 := makeIDPToken(t, key, []string{"tool:read_file"}, iss, "svc-a", "agent-1", time.Now().Add(time.Hour))
	tokenSub2 := makeIDPToken(t, key, []string{"tool:read_file"}, iss, "svc-a", "agent-2", time.Now().Add(time.Hour))

	post := func(sid, token string, body map[string]interface{}) *http.Response {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp/a", strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		if sid != "" {
			req.Header.Set(SessionHeader, sid)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		return resp
	}
	initBody := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "t", "version": "0"}},
	}
	reinit := map[string]interface{}{"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": map[string]interface{}{}}
	isErr := func(resp *http.Response) bool {
		defer func() { _ = resp.Body.Close() }()
		var m mcp.RPCMsg
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return m.Error != nil
	}

	// agent-1 establishes a session.
	ri := post("", tokenSub1, initBody)
	sid := ri.Header.Get(SessionHeader)
	if ri.StatusCode != http.StatusOK || sid == "" {
		t.Fatalf("expected a session for agent-1, status=%d sid=%q", ri.StatusCode, sid)
	}
	_ = ri.Body.Close()

	// agent-2 (same audience svc-a, different sub) must NOT reinitialize agent-1's
	// session and read its captured capabilities.
	if !isErr(post(sid, tokenSub2, reinit)) {
		t.Error("a re-initialize from a different sub on the same audience must be refused (session-owner mismatch)")
	}
	// The session owner (agent-1) must still be able to re-initialize its own session.
	if isErr(post(sid, tokenSub1, reinit)) {
		t.Error("the session owner (agent-1) must still re-initialize its own session")
	}

	// The SSE stream (GET) is owner-bound too: a different sub on the same audience must
	// not open the victim's stream and read its server->client traffic. A refusal is an
	// immediate 403 (no stream opens), so the request returns without blocking.
	getStatus := func(token string) int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/mcp/a", http.NoBody)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set(SessionHeader, sid)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if got := getStatus(tokenSub2); got != http.StatusForbidden {
		t.Errorf("a foreign-sub SSE GET on the victim's session must be refused 403, got %d", got)
	}

	// The enforced data plane (tools/call) is owner-bound too: a different sub on the same
	// audience must not drive the victim's upstream session, even though its OWN policy
	// permits the tool. Before the owner check covered enforced POSTs (it was scoped to
	// initialize), this reached agent-1's upstream — the cross-identity session hijack.
	toolCall := map[string]interface{}{
		"jsonrpc": "2.0", "id": 5, "method": "tools/call",
		"params": map[string]interface{}{"name": "read_file", "arguments": map[string]interface{}{}},
	}
	if !isErr(post(sid, tokenSub2, toolCall)) {
		t.Error("a tools/call from a different sub on the same audience must be refused (session-owner mismatch on the enforced POST path)")
	}
	// The session owner (agent-1) must still call tools on its own session.
	if isErr(post(sid, tokenSub1, toolCall)) {
		t.Error("the session owner (agent-1) must still call tools on its own session")
	}
}

// TestWrapRoutesWithJWT_RefusesAnUnenforceableOperationsOverride pins the startup half of the
// allowedOperations divergence. The capability-claim path's `op=` shorthand names no operation
// argument, so its arm scans every argument and cannot dispatch through an embedder's
// replacement handler — enforcing the replacement on the manifest path and the shipped
// predicate on the token path for the same call, silently. The wiring is refused where an
// operator can act on it, and only where the claim path is reachable at all.
func TestWrapRoutesWithJWT_RefusesAnUnenforceableOperationsOverride(t *testing.T) {
	overridden := enforcement.New(enforcement.WithConditionHandler(
		capability.ConditionTypeAllowedOperations,
		enforcement.ConditionHandlerFunc(func(_ context.Context, _ capability.Condition, _ *capability.EnforceRequest) *enforcement.ConditionError {
			return nil
		})))
	newRoutes := func(engine *enforcement.Engine) map[string]*UpstreamRoute {
		return map[string]*UpstreamRoute{
			"a": {name: "a", pdp: pdp.NewManifestPDP(nil, engine, killswitch.NewInMemory()), sink: &routeSink{}},
		}
	}
	opts := pdp.JWTPDPOptions{Issuer: "iss", AllowAnyAudience: true, ExperimentalCapabilities: true}

	if _, err := WrapRoutesWithJWT(newRoutes(overridden), opts); err == nil {
		t.Fatal("WrapRoutesWithJWT accepted a route whose engine redefines allowedOperations while the capability-claim path is enabled; want a fail-closed startup error")
	} else if !strings.Contains(err.Error(), capability.ConditionTypeAllowedOperations) {
		t.Fatalf("the error must name the condition type an operator has to act on: %v", err)
	}

	// Without the experimental claim schema the arm is unreachable (a token carrying
	// mcp.capabilities is rejected at validation), so there is no divergence to refuse over.
	noClaims := opts
	noClaims.ExperimentalCapabilities = false
	if _, err := WrapRoutesWithJWT(newRoutes(overridden), noClaims); err != nil {
		t.Fatalf("the override must not block startup when the capability-claim path is disabled: %v", err)
	}

	// And an engine carrying only the built-ins is unaffected either way.
	if _, err := WrapRoutesWithJWT(newRoutes(enforcement.New()), opts); err != nil {
		t.Fatalf("an un-overridden engine must wrap cleanly: %v", err)
	}
}
