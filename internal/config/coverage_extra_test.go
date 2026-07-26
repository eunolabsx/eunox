// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// coverage_extra_test.go raises statement coverage for the config + manifest
// loading layer by exercising the under-covered rejection and resolution
// branches: GatewayConfig.Validate's cross-field guards, the audit-mode and
// no-policy-startup-rejection resolvers, LocalManifest's policy properties
// (Digest / AuditOnlyCount), ResolveBool, and the manifest validators'
// fail-closed paths (descriptionHash, redactFields, directives/argumentSchema
// on non-tool targets, opaque-URI wildcards, unknown keys).
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// ── resolve.go: ResolveBool ──────────────────────────────────────────────────

// ResolveBool returns the override when set (true or false) and the default when
// the override is nil.
func TestResolveBool_OverrideAndDefault(t *testing.T) {
	tr, fa := true, false
	cases := []struct {
		name     string
		override *bool
		def      bool
		want     bool
	}{
		{"nil override falls back to true default", nil, true, true},
		{"nil override falls back to false default", nil, false, false},
		{"true override beats false default", &tr, false, true},
		{"false override beats true default", &fa, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveBool(tc.override, tc.def); got != tc.want {
				t.Errorf("ResolveBool(%v, %v) = %v, want %v", tc.override, tc.def, got, tc.want)
			}
		})
	}
}

// ── manifest_policy.go: Digest ───────────────────────────────────────────────

// Digest returns a stable "sha256:<hex>" over the manifest's canonical JSON, the
// same digest for equal content and a different one when content changes.
func TestDigest_StableAndContentSensitive(t *testing.T) {
	m1 := &LocalManifest{
		SchemaVersion: "0.1",
		Name:          "p",
		Version:       "1.0.0",
		Capabilities: []capability.Constraint{
			{Target: "tool:read_file", Actions: []string{"call"}},
		},
	}
	// A second, independently-built manifest with identical content.
	m2 := &LocalManifest{
		SchemaVersion: "0.1",
		Name:          "p",
		Version:       "1.0.0",
		Capabilities: []capability.Constraint{
			{Target: "tool:read_file", Actions: []string{"call"}},
		},
	}
	d1, err := m1.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if !strings.HasPrefix(d1, "sha256:") {
		t.Errorf("digest %q must start with sha256:", d1)
	}
	if len(d1) != len("sha256:")+64 {
		t.Errorf("digest %q has unexpected length %d", d1, len(d1))
	}
	d2, err := m2.Digest()
	if err != nil {
		t.Fatalf("Digest (m2): %v", err)
	}
	if d1 != d2 {
		t.Errorf("equal-content manifests produced different digests: %q vs %q", d1, d2)
	}

	// Changing content changes the digest.
	m2.Version = "2.0.0"
	d3, err := m2.Digest()
	if err != nil {
		t.Fatalf("Digest (m2 modified): %v", err)
	}
	if d1 == d3 {
		t.Errorf("digest did not change after content change: still %q", d1)
	}
}

// Digest over a nil *LocalManifest marshals JSON null and still returns a
// well-formed digest without panicking (json.Marshal(nil pointer) = "null").
func TestDigest_NilManifest(t *testing.T) {
	var m *LocalManifest
	d, err := m.Digest()
	if err != nil {
		t.Fatalf("Digest(nil): %v", err)
	}
	if !strings.HasPrefix(d, "sha256:") {
		t.Errorf("digest %q must start with sha256:", d)
	}
}

// ── manifest_policy.go: AuditOnlyCount ───────────────────────────────────────

// AuditOnlyCount counts only the capability entries in audit (observe) mode,
// ignoring enforce-mode and default (empty enforcement) entries.
func TestAuditOnlyCount_CountsObserveEntries(t *testing.T) {
	m := &LocalManifest{
		Capabilities: []capability.Constraint{
			{Target: "tool:a", Actions: []string{"call"}, Enforcement: capability.EnforcementAudit},
			{Target: "tool:b", Actions: []string{"call"}, Enforcement: capability.EnforcementEnforce},
			{Target: "tool:c", Actions: []string{"call"}}, // default enforce
			{Target: "tool:d", Actions: []string{"call"}, Enforcement: capability.EnforcementAudit},
		},
	}
	if got := m.AuditOnlyCount(); got != 2 {
		t.Errorf("AuditOnlyCount() = %d, want 2", got)
	}

	none := &LocalManifest{
		Capabilities: []capability.Constraint{
			{Target: "tool:a", Actions: []string{"call"}},
		},
	}
	if got := none.AuditOnlyCount(); got != 0 {
		t.Errorf("AuditOnlyCount() = %d, want 0 for a manifest with no audit entries", got)
	}
}

// ── gateway_config.go: HostTransport ─────────────────────────────────────────

// HostTransport defaults an empty Transport to http and returns an explicit
// value (stdio) unchanged.
func TestHostTransport_DefaultAndExplicit(t *testing.T) {
	cases := []struct {
		name, transport, want string
	}{
		{"empty defaults to http", "", HostTransportHTTP},
		{"explicit http", HostTransportHTTP, HostTransportHTTP},
		{"explicit stdio", HostTransportStdio, HostTransportStdio},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &GatewayConfig{Transport: tc.transport}
			if got := cfg.HostTransport(); got != tc.want {
				t.Errorf("HostTransport() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ── gateway_config.go: AuditModeFor ──────────────────────────────────────────

// AuditModeFor resolves per-route enforcement, with a per-route value overriding
// the defaults and an empty per-route value inheriting them.
func TestAuditModeFor_PerRouteOverridesDefaults(t *testing.T) {
	cases := []struct {
		name          string
		defaultEnf    string
		routeEnf      string
		wantAuditMode bool
	}{
		{"inherits audit default", capability.EnforcementAudit, "", true},
		{"inherits enforce default", capability.EnforcementEnforce, "", false},
		{"inherits empty default (enforce)", "", "", false},
		{"route audit overrides enforce default", capability.EnforcementEnforce, capability.EnforcementAudit, true},
		{"route enforce overrides audit default", capability.EnforcementAudit, capability.EnforcementEnforce, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &GatewayConfig{Defaults: RouteDefaults{Enforcement: tc.defaultEnf}}
			u := &UpstreamConfig{Enforcement: tc.routeEnf}
			if got := cfg.AuditModeFor(u); got != tc.wantAuditMode {
				t.Errorf("AuditModeFor() = %v, want %v", got, tc.wantAuditMode)
			}
		})
	}
}

// ── gateway_config.go: NoPolicyStartupRejection ──────────────────────────────

// NoPolicyStartupRejection classifies a policyless route exactly as the proxy
// would: every branch of the ordered switch is exercised, plus the clean-boot
// case (audit mode, no strictDrift, no expectVersion → "").
func TestNoPolicyStartupRejection_AllBranches(t *testing.T) {
	tr := true
	cases := []struct {
		name       string
		defaults   RouteDefaults
		upstream   UpstreamConfig
		wantSubstr string // "" ⟹ expect a clean boot ("")
	}{
		{
			name:       "audit policyless route boots clean",
			defaults:   RouteDefaults{Enforcement: capability.EnforcementAudit},
			upstream:   UpstreamConfig{},
			wantSubstr: "",
		},
		{
			name:       "strictDrift with audit names the single fix",
			defaults:   RouteDefaults{Enforcement: capability.EnforcementAudit},
			upstream:   UpstreamConfig{StrictDrift: &tr},
			wantSubstr: "strictDrift requires a policy",
		},
		{
			name:       "strictDrift with enforce names both barriers",
			defaults:   RouteDefaults{Enforcement: capability.EnforcementEnforce},
			upstream:   UpstreamConfig{StrictDrift: &tr},
			wantSubstr: `enforcement is not "audit"`,
		},
		{
			name:       "non-audit policyless route fails closed (SEC-05)",
			defaults:   RouteDefaults{Enforcement: capability.EnforcementEnforce},
			upstream:   UpstreamConfig{},
			wantSubstr: `no policy and enforcement is not "audit"`,
		},
		{
			name:       "expectVersion with no policy is rejected",
			defaults:   RouteDefaults{Enforcement: capability.EnforcementAudit},
			upstream:   UpstreamConfig{ExpectVersion: "1.0.0"},
			wantSubstr: "expectVersion requires a policy",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &GatewayConfig{Defaults: tc.defaults}
			got := cfg.NoPolicyStartupRejection(&tc.upstream)
			if tc.wantSubstr == "" {
				if got != "" {
					t.Errorf("NoPolicyStartupRejection() = %q, want \"\" (clean boot)", got)
				}
				return
			}
			if !strings.Contains(got, tc.wantSubstr) {
				t.Errorf("NoPolicyStartupRejection() = %q, want it to contain %q", got, tc.wantSubstr)
			}
		})
	}
}

// ── gateway_config.go: Validate (cross-field rejection branches) ─────────────

// TestGatewayConfig_ValidateRejections drives Validate's structural guards
// directly (a programmatically-built config, so presentKeys is nil and the
// value-based fallbacks are exercised). Each case asserts the first guard that
// would fire by a substring of its message.
func TestGatewayConfig_ValidateRejections(t *testing.T) {
	neg := -1
	bigSessions := int(MaxDurationMs) + 1 // wider than the idle timer can hold
	cases := []struct {
		name       string
		cfg        GatewayConfig
		wantSubstr string
	}{
		{
			name:       "unknown schemaVersion is refused first",
			cfg:        GatewayConfig{SchemaVersion: "9.9"},
			wantSubstr: "unsupported gateway config schemaVersion",
		},
		{
			name:       "no upstreams",
			cfg:        GatewayConfig{SchemaVersion: "0.1"},
			wantSubstr: "at least one upstream is required",
		},
		{
			name: "invalid host transport",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Transport:     "websocket",
				Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo"}},
			},
			wantSubstr: `transport must be`,
		},
		{
			name: "stdio host with a listen block",
			cfg: func() GatewayConfig {
				c := GatewayConfig{
					SchemaVersion: "0.1",
					Transport:     HostTransportStdio,
					Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo"}},
				}
				c.Listen.Port = 3000
				return c
			}(),
			wantSubstr: "transport: stdio has no network listener",
		},
		{
			name: "stdio host with listen.trustedProxyCIDRs",
			cfg: func() GatewayConfig {
				c := GatewayConfig{
					SchemaVersion: "0.1",
					Transport:     HostTransportStdio,
					Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo"}},
				}
				c.Listen.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
				return c
			}(),
			wantSubstr: "transport: stdio has no network listener",
		},
		{
			name: "malformed listen.trustedProxyCIDRs entry",
			cfg: func() GatewayConfig {
				c := GatewayConfig{
					SchemaVersion: "0.1",
					Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo"}},
				}
				c.Listen.TrustedProxyCIDRs = []string{"not-a-cidr"}
				return c
			}(),
			wantSubstr: "invalid CIDR",
		},
		{
			name: "stdio host with listen.trustedProxyHops",
			cfg: func() GatewayConfig {
				c := GatewayConfig{
					SchemaVersion: "0.1",
					Transport:     HostTransportStdio,
					Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo"}},
				}
				hops := 2
				c.Listen.TrustedProxyHops = &hops
				return c
			}(),
			wantSubstr: "transport: stdio has no network listener",
		},
		{
			// 0 is not a usable "off" switch: with no proxy-written entry to read there is
			// nothing to resolve, so it is rejected rather than silently read as the default.
			name: "listen.trustedProxyHops of zero",
			cfg: func() GatewayConfig {
				c := GatewayConfig{
					SchemaVersion: "0.1",
					Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo"}},
				}
				hops := 0
				c.Listen.TrustedProxyHops = &hops
				return c
			}(),
			wantSubstr: "listen.trustedProxyHops must be at least 1",
		},
		{
			name: "negative listen.trustedProxyHops",
			cfg: func() GatewayConfig {
				c := GatewayConfig{
					SchemaVersion: "0.1",
					Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo"}},
				}
				hops := -1
				c.Listen.TrustedProxyHops = &hops
				return c
			}(),
			wantSubstr: "listen.trustedProxyHops must be at least 1",
		},
		{
			name: "stdio host with more than one upstream",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Transport:     HostTransportStdio,
				Upstreams: []UpstreamConfig{
					{Name: "a", Transport: "stdio", Command: "echo"},
					{Name: "b", Transport: "stdio", Command: "echo"},
				},
			},
			wantSubstr: "fronts exactly one upstream",
		},
		{
			name: "http listen port out of range",
			cfg: func() GatewayConfig {
				c := GatewayConfig{
					SchemaVersion: "0.1",
					Transport:     HostTransportHTTP,
					Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo"}},
				}
				c.Listen.Port = 70000
				return c
			}(),
			wantSubstr: "out of range",
		},
		{
			name: "negative maxSessions",
			cfg: func() GatewayConfig {
				c := GatewayConfig{
					SchemaVersion: "0.1",
					Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo"}},
				}
				c.Listen.MaxSessions = &neg
				return c
			}(),
			wantSubstr: "maxSessions",
		},
		{
			name: "negative sessionIdleTimeoutMs",
			cfg: func() GatewayConfig {
				c := GatewayConfig{
					SchemaVersion: "0.1",
					Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo"}},
				}
				c.Listen.SessionIdleTimeoutMs = &neg
				return c
			}(),
			wantSubstr: "must not be negative",
		},
		{
			name: "overflowing sessionIdleTimeoutMs",
			cfg: func() GatewayConfig {
				c := GatewayConfig{
					SchemaVersion: "0.1",
					Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo"}},
				}
				c.Listen.SessionIdleTimeoutMs = &bigSessions
				return c
			}(),
			wantSubstr: "exceeds the maximum",
		},
		{
			name: "negative audit.retainRotated",
			cfg: func() GatewayConfig {
				c := GatewayConfig{
					SchemaVersion: "0.1",
					Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo"}},
				}
				c.Audit.RetainRotated = &neg
				return c
			}(),
			wantSubstr: "retainRotated",
		},
		{
			name: "negative audit.rotateSizeBytes",
			cfg: func() GatewayConfig {
				c := GatewayConfig{
					SchemaVersion: "0.1",
					Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo"}},
				}
				c.Audit.RotateSizeBytes = -1
				return c
			}(),
			wantSubstr: "rotateSizeBytes",
		},
		{
			name: "negative defaults.upstreamTimeoutMs",
			cfg: func() GatewayConfig {
				c := GatewayConfig{
					SchemaVersion: "0.1",
					Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo"}},
				}
				c.Defaults.UpstreamTimeoutMs = -5
				return c
			}(),
			wantSubstr: "upstreamTimeoutMs",
		},
		{
			name: "invalid defaults enforcement",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Defaults:      RouteDefaults{Enforcement: "observe"},
				Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo"}},
			},
			wantSubstr: "invalid enforcement",
		},
		{
			name: "overflowing defaults.upstreamTimeoutMs",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Defaults:      RouteDefaults{UpstreamTimeoutMs: int(MaxDurationMs) + 1},
				Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo"}},
			},
			wantSubstr: "exceeds the maximum",
		},
		{
			name: "empty upstream name",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Upstreams:     []UpstreamConfig{{Transport: "stdio", Command: "echo"}},
			},
			wantSubstr: "'name' is required",
		},
		{
			name: "bad upstream name (path metacharacter)",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Upstreams:     []UpstreamConfig{{Name: "a/b", Transport: "stdio", Command: "echo"}},
			},
			wantSubstr: "name must match",
		},
		{
			name: "duplicate upstream name",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Transport:     HostTransportHTTP,
				Upstreams: []UpstreamConfig{
					{Name: "dup", Transport: "stdio", Command: "echo"},
					{Name: "dup", Transport: "stdio", Command: "echo"},
				},
			},
			wantSubstr: "duplicate upstream name",
		},
		{
			name: "invalid per-route enforcement",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo", Enforcement: "watch"}},
			},
			wantSubstr: "invalid enforcement",
		},
		{
			name: "stdio transport missing command",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio"}},
			},
			wantSubstr: "requires 'command'",
		},
		{
			name: "stdio transport with upstreamUrl",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo", UpstreamURL: "https://x"}},
			},
			wantSubstr: "'upstreamUrl' is not allowed with stdio",
		},
		{
			name: "stdio transport with upstreamAuthHeader",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo", UpstreamAuthHeader: "Authorization: Bearer x"}},
			},
			wantSubstr: "'upstreamAuthHeader' is not allowed with stdio",
		},
		{
			name: "stdio transport with upstreamTlsSkipVerify",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Upstreams:     []UpstreamConfig{{Name: "a", Transport: "stdio", Command: "echo", UpstreamTLSSkipVerify: true}},
			},
			wantSubstr: "'upstreamTlsSkipVerify' is not allowed with stdio",
		},
		{
			name: "http transport missing upstreamUrl",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Transport:     HostTransportHTTP,
				Upstreams:     []UpstreamConfig{{Name: "a", Transport: "http"}},
			},
			wantSubstr: "http transport requires 'upstreamUrl'",
		},
		{
			name: "http transport with non-http(s) scheme",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Transport:     HostTransportHTTP,
				Upstreams:     []UpstreamConfig{{Name: "a", Transport: "http", UpstreamURL: "file:///etc/passwd"}},
			},
			wantSubstr: "must be an http or https URL",
		},
		{
			name: "http transport with scheme-only url (no host)",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Transport:     HostTransportHTTP,
				Upstreams:     []UpstreamConfig{{Name: "a", Transport: "http", UpstreamURL: "http://"}},
			},
			wantSubstr: "has no host",
		},
		{
			name: "http transport with command",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Transport:     HostTransportHTTP,
				Upstreams:     []UpstreamConfig{{Name: "a", Transport: "http", UpstreamURL: "https://x", Command: "echo"}},
			},
			wantSubstr: "'command' is not allowed with http",
		},
		{
			name: "http transport with args",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Transport:     HostTransportHTTP,
				Upstreams:     []UpstreamConfig{{Name: "a", Transport: "http", UpstreamURL: "https://x", Args: []string{"x"}}},
			},
			wantSubstr: "'args' is not allowed with http",
		},
		{
			name: "missing transport",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Upstreams:     []UpstreamConfig{{Name: "a", Command: "echo"}},
			},
			wantSubstr: "'transport' is required",
		},
		{
			name: "unknown transport value",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Upstreams:     []UpstreamConfig{{Name: "a", Transport: "grpc"}},
			},
			wantSubstr: `transport must be "stdio" or "http"`,
		},
		{
			name: "expectVersion ambiguous with multiple policy files",
			cfg: GatewayConfig{
				SchemaVersion: "0.1",
				Upstreams: []UpstreamConfig{{
					Name: "a", Transport: "stdio", Command: "echo",
					ExpectVersion: "1.0.0",
					Policy:        []string{"a.yaml", "b.yaml"},
				}},
			},
			wantSubstr: "only supported with a single policy file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate(nil)
			if err == nil {
				t.Fatalf("Validate accepted an invalid config, want rejection (%s)", tc.wantSubstr)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("Validate error = %q, want it to contain %q", err.Error(), tc.wantSubstr)
			}
		})
	}
}

// A fully-formed http gateway config with two routes (stdio + http) validates,
// covering the success path through both transport arms and the valid listen
// fields (port, maxSessions, idle timeout) that the rejection cases negate.
func TestGatewayConfig_ValidateAcceptsWellFormedHTTP(t *testing.T) {
	zero := 0
	cfg := GatewayConfig{
		SchemaVersion: "0.1",
		Transport:     HostTransportHTTP,
		Defaults:      RouteDefaults{Enforcement: capability.EnforcementAudit, UpstreamTimeoutMs: 5000},
		Upstreams: []UpstreamConfig{
			{Name: "fs", Transport: "stdio", Command: "echo", Args: []string{"hi"}, Policy: []string{"fs.yaml"}},
			{Name: "remote", Transport: "http", UpstreamURL: "https://mcp.example.com", Policy: []string{"r.yaml"}},
		},
	}
	cfg.Listen.Port = 3000
	cfg.Listen.MaxSessions = &zero // explicit unlimited (valid)
	idle := 30000
	cfg.Listen.SessionIdleTimeoutMs = &idle
	cfg.Listen.TrustedProxyCIDRs = []string{"10.0.0.0/8", "192.168.1.1/32"}
	retain := 5
	cfg.Audit.RetainRotated = &retain
	if err := cfg.Validate(nil); err != nil {
		t.Fatalf("Validate rejected a well-formed http config: %v", err)
	}
}

// ── gateway_config.go: LoadGatewayConfig (http transport + env expansion) ────

// LoadGatewayConfig parses an http gateway config end to end and expands env
// references in string-typed fields (auth token and upstream auth header),
// leaving an unset reference intact. This exercises the env-expansion walk over
// the decoded tree and the http transport branch through the file loader.
func TestLoadGatewayConfig_HTTPTransportWithEnvExpansion(t *testing.T) {
	t.Setenv("EUNOX_TEST_GW_TOKEN", "tok-123")
	t.Setenv("EUNOX_TEST_STRIPE_KEY", "sk-live")
	t.Setenv("EUNOX_TEST_GW_CMD", "/usr/bin/srv")

	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
  authToken: ${EUNOX_TEST_GW_TOKEN}
upstreams:
  - name: stripe
    transport: http
    upstreamUrl: https://mcp.stripe.com
    upstreamAuthHeader: "Authorization: Bearer ${EUNOX_TEST_STRIPE_KEY}"
    policy: ["stripe.yaml"]
  - name: fs
    transport: stdio
    command: ${EUNOX_TEST_GW_CMD}
    args: ["-y", "srv"]
    policy: ["fs.yaml"]
`))
	if err != nil {
		t.Fatalf("LoadGatewayConfig: %v", err)
	}
	if cfg.Listen.AuthToken != "tok-123" {
		t.Errorf("authToken = %q, want expanded tok-123", cfg.Listen.AuthToken)
	}
	if got := cfg.Upstreams[0].UpstreamAuthHeader; got != "Authorization: Bearer sk-live" {
		t.Errorf("upstreamAuthHeader = %q, want the key expanded", got)
	}
	if got := cfg.Upstreams[1].Command; got != "/usr/bin/srv" {
		t.Errorf("command = %q, want the reference expanded", got)
	}
}

// TestLoadGatewayConfig_UnsetEnvRefInCommandAndArgs pins that an unset ${VAR} in a stdio
// upstream's command or args is a STARTUP failure, like every sibling expanded field.
// An unset reference survives expansion as literal text, so without this guard the route
// booted cleanly and failed at exec time on the first session — the operator learns of a
// plain config typo from a client's failed handshake instead of from `proxy` refusing to
// start.
func TestLoadGatewayConfig_UnsetEnvRefInCommandAndArgs(t *testing.T) {
	for _, tc := range []struct{ name, upstream, wantIn string }{
		{
			name: "command",
			upstream: `    command: ${EUNOX_TEST_GW_UNSET}
    args: ["-y", "srv"]`,
			wantIn: `upstream "fs" command references environment variable "EUNOX_TEST_GW_UNSET"`,
		},
		{
			name: "args",
			upstream: `    command: /usr/bin/srv
    args: ["-y", "${EUNOX_TEST_GW_UNSET}"]`,
			wantIn: `upstream "fs" args[1] references environment variable "EUNOX_TEST_GW_UNSET"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
upstreams:
  - name: fs
    transport: stdio
`+tc.upstream+`
    policy: ["fs.yaml"]
`))
			if err == nil {
				t.Fatal("LoadGatewayConfig accepted an unset env reference; want a startup failure")
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error = %q, want it to name %q", err, tc.wantIn)
			}
		})
	}
}

// TestLoadGatewayConfig_BareDollarInCommandArgsIsLiteral pins that the unset-env-ref
// guard on command/args accepts a bare "$word".
//
// These two fields are arbitrary subprocess argv, not a URL: a bare "$word" is ordinary
// literal text there — an OData "?$filter=", a regex "$anchor", a jq expression, or
// anything the child interpolates itself. Applying the broader bare-$ rule the
// upstreamUrl guard uses would refuse to START a config that works today, blaming a
// variable the operator never wrote. Only the unambiguous "${VAR}" fails closed.
func TestLoadGatewayConfig_BareDollarInCommandArgsIsLiteral(t *testing.T) {
	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
upstreams:
  - name: fs
    transport: stdio
    command: /usr/bin/srv
    args: ["--query", "?$filter=name eq 'x'", "s/$anchor/x/"]
    policy: ["fs.yaml"]
`))
	if err != nil {
		t.Fatalf("LoadGatewayConfig rejected literal $ text in argv: %v", err)
	}
	if got := cfg.Upstreams[0].Args[1]; got != "?$filter=name eq 'x'" {
		t.Errorf("args[1] = %q, want the literal text preserved verbatim", got)
	}
	if got := cfg.Upstreams[0].Args[2]; got != "s/$anchor/x/" {
		t.Errorf("args[2] = %q, want the literal text preserved verbatim", got)
	}
}

// LoadGatewayConfig surfaces a read error for a path that does not exist.
func TestLoadGatewayConfig_MissingFile(t *testing.T) {
	_, err := LoadGatewayConfig(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected an error for a missing config file")
	}
	if !strings.Contains(err.Error(), "reading gateway config") {
		t.Errorf("error = %q, want a 'reading gateway config' wrap", err)
	}
}

// LoadGatewayConfig rejects a config whose key presence is forbidden for the
// declared transport even when the value is an explicit zero — args: [] on an
// http upstream — driving the presentKeys path of Validate (vs. the value-based
// fallback the programmatic tests use).
func TestLoadGatewayConfig_RejectsExplicitZeroForbiddenKey(t *testing.T) {
	_, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: http
upstreams:
  - name: remote
    transport: http
    upstreamUrl: https://mcp.example.com
    args: []
    policy: ["r.yaml"]
`))
	if err == nil {
		t.Fatal("expected rejection of args: [] on an http upstream")
	}
	if !strings.Contains(err.Error(), "'args' is not allowed with http") {
		t.Errorf("error = %q, want the args-not-allowed message", err)
	}
}

// LoadGatewayConfig validates an empty document (io.EOF on decode) through the
// loader and reports the missing upstreams via Validate rather than a bare EOF.
func TestLoadGatewayConfig_EmptyDocument(t *testing.T) {
	_, err := LoadGatewayConfig(writeConfig(t, ""))
	if err == nil {
		t.Fatal("expected an error for an empty config document")
	}
	// An empty doc has schemaVersion "" → the schema-version gate fires first.
	if !strings.Contains(err.Error(), "schemaVersion") {
		t.Errorf("error = %q, want it to mention the missing schemaVersion", err)
	}
}

// writeBinary writes raw bytes to a temp file with the given basename and
// returns its path — for the "pointed --config at a binary" guards below.
func writeBinary(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

// A ZIP/.mcpb bundle handed to --config (the common Desktop Extension install
// mistake — selecting the downloaded .mcpb instead of an eunox.yaml) is rejected
// with an actionable message naming the bundle, not yaml.v3's opaque "control
// characters are not allowed".
func TestLoadGatewayConfig_RejectsMCPBBundle(t *testing.T) {
	// "PK\x03\x04" — the ZIP local-file-header signature every .mcpb begins with.
	bundle := append([]byte{'P', 'K', 0x03, 0x04}, []byte("\x14\x00\x00\x00binary junk")...)
	_, err := LoadGatewayConfig(writeBinary(t, "eunox_0.1.0_darwin_arm64.mcpb", bundle))
	if err == nil {
		t.Fatal("expected rejection of a .mcpb bundle passed as --config")
	}
	for _, want := range []string{"ZIP archive", ".mcpb", "eunox init"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}
}

// A binary file with NUL bytes (no ZIP signature) is also rejected before the
// YAML parser sees it, via the NUL-byte branch.
func TestLoadGatewayConfig_RejectsBinaryWithNUL(t *testing.T) {
	_, err := LoadGatewayConfig(writeBinary(t, "blob.yaml", []byte("schemaVersion: \x00\x01\x02")))
	if err == nil {
		t.Fatal("expected rejection of a binary file passed as --config")
	}
	if !strings.Contains(err.Error(), "NUL") {
		t.Errorf("error = %q, want it to mention NUL bytes", err)
	}
}

// LoadManifest gets the same binary-file guard as the gateway loader.
func TestLoadManifest_RejectsMCPBBundle(t *testing.T) {
	bundle := append([]byte{'P', 'K', 0x03, 0x04}, []byte("\x14\x00\x00\x00binary junk")...)
	_, err := LoadManifest(writeBinary(t, "manifest.mcpb", bundle))
	if err == nil {
		t.Fatal("expected rejection of a .mcpb bundle passed as a manifest")
	}
	if !strings.Contains(err.Error(), "ZIP archive") {
		t.Errorf("error = %q, want the ZIP-archive guard message", err)
	}
}

// ── manifest.go: LoadManifest + validators (rejection paths) ─────────────────

// TestLoadManifest_DescriptionHashValidation drives the descriptionHash
// branches of validateLocalManifest: accepted on an exact tool target, and
// rejected on a non-tool target, a glob tool target, and a malformed hash.
func TestLoadManifest_DescriptionHashValidation(t *testing.T) {
	const goodHash = "sha256:" + // 64 lowercase hex chars
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		name, yaml, wantErr string
	}{
		{
			name: "exact tool target with valid hash accepted",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    descriptionHash: "` + goodHash + `"
`,
		},
		{
			name: "descriptionHash on resource target rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "resource:file:///data/x"
    actions: [read]
    descriptionHash: "` + goodHash + `"
`,
			wantErr: "descriptionHash is only supported on tool: targets",
		},
		{
			name: "descriptionHash on glob tool target rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_*"
    actions: [call]
    descriptionHash: "` + goodHash + `"
`,
			wantErr: "cannot be set on glob target",
		},
		{
			name: "malformed descriptionHash rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    descriptionHash: "sha256:nothex"
`,
			wantErr: "hex part must be exactly 64 characters",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifestFile(t, tc.yaml)
			_, err := LoadManifest(path)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("LoadManifest rejected valid manifest: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// argumentSchema and directives are tool-only; both must be rejected on a
// non-tool target (the proxy validates tool-call arguments / redacts tools/call
// results, never resource/prompt/system responses).
func TestLoadManifest_ToolOnlyFeaturesRejectedOnNonToolTargets(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{
			name: "argumentSchema on resource target rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "resource:file:///data/x"
    actions: [read]
    argumentSchema:
      type: object
      properties:
        uri:
          type: string
`,
			wantErr: "applies only to tool: targets",
		},
		{
			name: "directives on prompt target rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "prompt:code_review"
    actions: [get]
    directives:
      - type: redactFields
        fields: ["ssn"]
`,
			wantErr: "apply only to tool: targets",
		},
		{
			name: "directives on system target rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "system:sampling/createMessage"
    actions: [allow]
    directives:
      - type: redactFields
        fields: ["ssn"]
`,
			wantErr: "apply only to tool: targets",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifestFile(t, tc.yaml)
			_, err := LoadManifest(path)
			if err == nil {
				t.Fatalf("LoadManifest accepted %s, want rejection", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestLoadManifest_RedactFieldsValidation drives validateRedactFields: a valid
// dot path is accepted; array-index notation, an empty field, the "$." root
// marker over an empty path, and an empty-segment path are each rejected.
func TestLoadManifest_RedactFieldsValidation(t *testing.T) {
	cases := []struct {
		name, fields, wantErr string
	}{
		{"valid dot path accepted", `["user.ssn", "$.result.secret"]`, ""},
		{"array index notation rejected", `["users[0].ssn"]`, "array-index notation"},
		{"empty field rejected", `[""]`, "is empty"},
		{"whitespace-only field rejected", `["   "]`, "is empty"},
		{"root marker over empty path rejected", `["$."]`, "is empty"},
		// A "$"-prefix that is neither "$." nor a lone "$" (a likely "$.users.ssn" typo)
		// silently redacts nothing at runtime while the audit log reports it applied — a
		// fail-open leak, so it must be rejected at load time.
		{"dollar-prefix without dot rejected", `["$users.ssn"]`, "begins with '$'"},
		{"dollar-prefix single segment rejected", `["$ref"]`, "begins with '$'"},
		{"leading dot empty segment rejected", `[".ssn"]`, "empty path segment"},
		{"trailing dot empty segment rejected", `["users."]`, "empty path segment"},
		{"doubled dot empty segment rejected", `["a..b"]`, "empty path segment"},
		// Whitespace-bearing segments redact nothing at runtime (the redactor matches
		// keys literally) but the audit log reports redaction applied — a fail-open of
		// the declared control, so each must be rejected at load time.
		{"trailing-space segment rejected", `["users .ssn"]`, "whitespace"},
		{"leading-space segment rejected", `["users. ssn"]`, "whitespace"},
		{"leading-space whole path rejected", `["  users.ssn"]`, "whitespace"},
		{"space-displaced root marker rejected", `[" $.users.ssn"]`, "whitespace"},
		{"whitespace-only segment rejected", `["users. .ssn"]`, "whitespace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yaml := `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_record"
    actions: [call]
    directives:
      - type: redactFields
        fields: ` + tc.fields + `
`
			path := writeManifestFile(t, yaml)
			_, err := LoadManifest(path)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("LoadManifest rejected valid redactFields: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// A "$" lone-root redactFields path strips to an empty path and is rejected,
// confirming the field == "$" branch of validateRedactFields.
func TestLoadManifest_RedactFieldsLoneRootRejected(t *testing.T) {
	yaml := `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_record"
    actions: [call]
    directives:
      - type: redactFields
        fields: ["$"]
`
	path := writeManifestFile(t, yaml)
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("want a lone '$' redactFields path rejected as empty, got %v", err)
	}
}

// resourceOpaqueURIWildcard's no-scheme branch: a bare resource pattern with no
// colon is not an opaque URI, so an authority/path glob on a scheme-bearing URI
// is the rejection path while a no-colon target is handled elsewhere. Drive the
// urn:/mailto: opaque-wildcard rejection plus a hierarchical scheme that is
// accepted (the rest-has-"/" early return).
func TestLoadManifest_ResourceOpaqueURIWildcard(t *testing.T) {
	cases := []struct {
		name, target, wantErr string
	}{
		{"urn opaque wildcard rejected", "resource:urn:isbn:*", "opaque"},
		{"mailto opaque wildcard rejected", "resource:mailto:*@x.com", "opaque"},
		{"hierarchical path glob accepted", "resource:file:///data/*", ""},
		{"opaque exact (no glob) accepted", "resource:urn:isbn:12345", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yaml := `name: p
version: "0.1.0"
capabilities:
  - target: "` + tc.target + `"
    actions: [read]
`
			path := writeManifestFile(t, yaml)
			_, err := LoadManifest(path)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("LoadManifest rejected %q: %v", tc.target, err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want %q rejected with %q, got %v", tc.target, tc.wantErr, err)
			}
		})
	}
}

// TestLoadManifest_UnknownKeysAtEveryLevel drives checkManifestKeys / the
// per-condition and per-directive key checks: an unknown key at the manifest
// root, inside a capability, inside a condition, and inside a directive are each
// rejected with a path-qualified message.
func TestLoadManifest_UnknownKeysAtEveryLevel(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{
			name: "unknown top-level key",
			yaml: `name: p
version: "0.1.0"
capabilities: []
bogus: true
`,
			wantErr: "unknown field",
		},
		{
			name: "unknown capability key",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    bogusCap: 1
`,
			wantErr: "unknown field",
		},
		{
			name: "unknown condition key",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 5
        windowSeconds: 60
        bogusCond: true
`,
			wantErr: "unknown field",
		},
		{
			name: "unknown directive key",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_record"
    actions: [call]
    directives:
      - type: redactFields
        fields: ["ssn"]
        bogusDir: 1
`,
			wantErr: "unknown field",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifestFile(t, tc.yaml)
			_, err := LoadManifest(path)
			if err == nil {
				t.Fatalf("LoadManifest accepted an unknown key (%s), want rejection", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// An unknown condition `type` is left to the typed decode rather than the
// key-presence check (conditionKeysFor returns known=false), so checkManifestKeys
// skips it. The typed decode rejects the unknown discriminator, so the manifest
// still fails to load — this drives the `!known` continue arm of conditionKeysFor
// via checkManifestKeys.
func TestLoadManifest_UnknownConditionTypeSkipsKeyCheck(t *testing.T) {
	yaml := `name: p
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: notARealCondition
        someKey: 1
`
	path := writeManifestFile(t, yaml)
	if _, err := LoadManifest(path); err == nil {
		t.Fatal("expected the unknown condition type to be rejected by the typed decode")
	}
}

// A condition `type` this build does model (timeWindow) with all-valid keys
// loads cleanly, exercising the `known=true` arm of conditionKeysFor and a key
// set that passes checkObjectKeys.
func TestLoadManifest_KnownConditionTypeKeyCheckPasses(t *testing.T) {
	yaml := `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: timeWindow
        notBefore: "2026-01-01T00:00:00Z"
        notAfter: "2026-12-31T23:59:59Z"
`
	path := writeManifestFile(t, yaml)
	if _, err := LoadManifest(path); err != nil {
		t.Fatalf("LoadManifest rejected a valid timeWindow condition: %v", err)
	}
}

// An unknown directive `type` is skipped by directiveKeysFor (known=false) and
// left to the typed decode, which rejects it — driving the `!known` arm.
func TestLoadManifest_UnknownDirectiveTypeRejected(t *testing.T) {
	yaml := `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_record"
    actions: [call]
    directives:
      - type: notARealDirective
        whatever: 1
`
	path := writeManifestFile(t, yaml)
	if _, err := LoadManifest(path); err == nil {
		t.Fatal("expected the unknown directive type to be rejected")
	}
}

// LoadManifest reports a read error for a path that does not exist (the os.ReadFile
// error arm).
func TestLoadManifest_MissingFile(t *testing.T) {
	_, err := LoadManifest(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected an error for a missing manifest file")
	}
	if !strings.Contains(err.Error(), "reading manifest") {
		t.Errorf("error = %q, want a 'reading manifest' wrap", err)
	}
}

// LoadManifest rejects a YAML file that does not parse (the YAML decode error
// arm of the .yaml branch).
func TestLoadManifest_MalformedYAML(t *testing.T) {
	yaml := "name: p\nversion: \"0.1.0\"\ncapabilities: [unterminated\n"
	path := writeManifestFile(t, yaml)
	if _, err := LoadManifest(path); err == nil {
		t.Fatal("expected a parse error for malformed YAML")
	}
}

// An empty YAML manifest (zero node, raw stays nil) decodes to a manifest with
// no name and is rejected by validateLocalManifest — driving forceTimestampsToStrings
// over a nil/zero node and the Kind==0 branch of LoadManifest.
func TestLoadManifest_EmptyYAMLDocumentRejected(t *testing.T) {
	// writeManifestFile injects a schemaVersion line, so the document is not truly
	// empty; write it raw with only whitespace to hit the zero-node path.
	path := writeRawManifest(t, "\n")
	_, err := LoadManifest(path)
	if err == nil {
		t.Fatal("expected an empty manifest to be rejected (missing schemaVersion/name)")
	}
}

// MergeManifests with multiple valid manifests unions their capabilities and
// re-validates the merged result (the len > 1 branch + the defense-in-depth
// validate), and the single-manifest fast path returns the input unchanged.
func TestMergeManifests_UnionsAndRevalidates(t *testing.T) {
	a := &LocalManifest{
		SchemaVersion: "0.1", Name: "a", Version: "1.0.0",
		Capabilities: []capability.Constraint{{Target: "tool:read_file", Actions: []string{"call"}}},
	}
	b := &LocalManifest{
		SchemaVersion: "0.1", Name: "b", Version: "2.0.0",
		Capabilities: []capability.Constraint{{Target: "tool:write_file", Actions: []string{"call"}}},
	}
	merged, err := MergeManifests([]*LocalManifest{a, b})
	if err != nil {
		t.Fatalf("MergeManifests: %v", err)
	}
	if len(merged.Capabilities) != 2 {
		t.Errorf("merged capabilities = %d, want 2", len(merged.Capabilities))
	}
	if merged.Name != "a" || merged.Version != "1.0.0" {
		t.Errorf("merged metadata = (%q,%q), want (a,1.0.0) from the first manifest", merged.Name, merged.Version)
	}

	// Single-manifest fast path returns the same pointer.
	if got, _ := MergeManifests([]*LocalManifest{a}); got != a {
		t.Errorf("MergeManifests single-element returned a copy, want the input pointer")
	}
}

// TestValidateLocalManifest_ValueTypedConditions calls validateLocalManifest
// directly with value-typed conditions (the JWT path builds these; the YAML
// loader always builds pointer-typed ones), so the value arms of the per-condition
// type switch are exercised. Every condition is well-formed, so the manifest is
// valid; the goal is branch coverage of the value cases, not a rejection.
func TestValidateLocalManifest_ValueTypedConditions(t *testing.T) {
	m := &LocalManifest{
		SchemaVersion: "0.1",
		Name:          "value-conds",
		Version:       "1.0.0",
		Capabilities: []capability.Constraint{
			{
				Target:  "tool:query_db",
				Actions: []string{"call"},
				Conditions: []capability.Condition{
					capability.AllowedOperationsCondition{Argument: "sql", Operations: []string{"SELECT"}},
					capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".csv"}},
					capability.AllowedTablesCondition{Argument: "table", Tables: []string{"sales"}},
					capability.RecipientDomainCondition{Argument: "to", Domains: []string{"example.com"}},
					capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/data/*"}},
					capability.MaxCallsCondition{Count: 5, WindowSeconds: 60},
					capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
					capability.TimeWindowCondition{NotBefore: "2026-01-01T00:00:00Z"},
					capability.SequenceBlockCondition{AfterTools: []string{"read_credentials"}},
				},
			},
		},
	}
	if err := validateLocalManifest(m); err != nil {
		t.Fatalf("validateLocalManifest rejected well-formed value-typed conditions: %v", err)
	}
}

// validateLocalManifest rejects an empty target and empty actions when called
// with a hand-built constraint (the YAML loader's required-field checks would
// otherwise mask which branch fires).
func TestValidateLocalManifest_EmptyTargetAndActions(t *testing.T) {
	cases := []struct {
		name       string
		constraint capability.Constraint
		wantSubstr string
	}{
		{
			name:       "empty target",
			constraint: capability.Constraint{Target: "   ", Actions: []string{"call"}},
			wantSubstr: "'target' must not be empty",
		},
		{
			name:       "empty actions",
			constraint: capability.Constraint{Target: "tool:read_file", Actions: nil},
			wantSubstr: "'actions' must not be empty",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &LocalManifest{Name: "p", Version: "1.0.0", Capabilities: []capability.Constraint{tc.constraint}}
			err := validateLocalManifest(m)
			if err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("validateLocalManifest error = %v, want it to contain %q", err, tc.wantSubstr)
			}
		})
	}
}

// A maxCalls condition whose window is non-positive is skipped by
// validateMaxCallsWindowsDistinct (left to the per-condition validateMaxCalls),
// and a non-maxCalls condition alongside it drives the default/skip arm of the
// distinct-windows scan. The per-condition validator then reports the missing
// window.
func TestLoadManifest_MaxCallsWindowlessSkippedByDistinctScan(t *testing.T) {
	yaml := `name: p
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: allowedValues
        argument: path
        values: ["/data/*"]
      - type: maxCalls
        count: 5
`
	path := writeManifestFile(t, yaml)
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "maxCalls requires 'windowSeconds' >= 1") {
		t.Fatalf("want the windowless maxCalls reported by the per-condition validator, got %v", err)
	}
}

// policy and custom conditions are modeled by conditionKeysFor (the
// ConditionTypePolicy / ConditionTypeCustom arms) but are not in the per-condition
// validation switch, so a well-formed one loads cleanly — exercising both arms.
func TestLoadManifest_PolicyAndCustomConditionsLoad(t *testing.T) {
	cases := []struct{ name, yaml string }{
		{
			name: "policy condition",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: policy
        backend: opa
        config: {url: "http://localhost"}
`,
		},
		{
			name: "custom condition",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: custom
        name: mything
        config: {foo: bar}
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifestFile(t, tc.yaml)
			if _, err := LoadManifest(path); err != nil {
				t.Fatalf("LoadManifest rejected a valid %s: %v", tc.name, err)
			}
		})
	}
}

// An unsatisfiable subschema nested under `items` is caught by
// validateArgumentSchemaConsistency's items recursion (the sibling test covers
// the properties recursion).
func TestLoadManifest_RejectsUnsatisfiableItemsArgumentSchema(t *testing.T) {
	yaml := `name: p
version: "0.1.0"
capabilities:
  - target: "tool:bulk_write"
    actions: [call]
    argumentSchema:
      type: object
      properties:
        records:
          type: array
          items:
            type: object
            required: [mode]
            properties: {}
            additionalProperties: false
`
	path := writeManifestFile(t, yaml)
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "unsatisfiable") {
		t.Fatalf("want the unsatisfiable items subschema rejected, got %v", err)
	}
}

// directiveKeysFor returns (nil,false) for a type it does not model. Drive it
// directly so the unknown-directive arm is covered without depending on the
// typed decode's rejection ordering.
func TestDirectiveKeysFor_UnknownTypeNotKnown(t *testing.T) {
	if _, known := directiveKeysFor("notARealDirective"); known {
		t.Error("directiveKeysFor(unknown) reported known=true, want false")
	}
	if keys, known := directiveKeysFor(capability.DirectiveTypeRedactFields); !known || !keys["fields"] || !keys["type"] {
		t.Errorf("directiveKeysFor(redactFields) = (%v, %v), want the fields+type key set", keys, known)
	}
}

// writeRawManifest writes content verbatim (no schemaVersion injection) to a
// .yaml temp file and returns its path.
func writeRawManifest(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "raw.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write raw manifest: %v", err)
	}
	return p
}
