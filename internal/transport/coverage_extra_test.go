// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// ---------------------------------------------------------------------------
// ResolveMaxSessions (http.go) — pure flag/config precedence helper.
// ---------------------------------------------------------------------------

func TestResolveMaxSessions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		flagVal int
		cfgVal  *int
		want    int
	}{
		{"absent config keeps flag default", 200, nil, 200},
		{"present config overrides flag", 200, intPtr(50), 50},
		{"present config of 0 (unlimited) wins over flag", 200, intPtr(0), 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ResolveMaxSessions(tc.flagVal, tc.cfgVal); got != tc.want {
				t.Errorf("ResolveMaxSessions(%d, %v) = %d, want %d", tc.flagVal, tc.cfgVal, got, tc.want)
			}
		})
	}
}

// TestResolveSessionIdleTimeout pins the same flag/config precedence as
// ResolveMaxSessions: a present config value wins INCLUDING an explicit 0, so config
// can disable a non-zero --session-idle-timeout flag (the zero-override contract).
func TestResolveSessionIdleTimeout(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		flagVal int
		cfgVal  *int
		want    int
	}{
		{"absent config keeps flag value", 60000, nil, 60000},
		{"present config overrides flag", 60000, intPtr(30000), 30000},
		{"present config of 0 (no idle reaping) wins over non-zero flag", 60000, intPtr(0), 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ResolveSessionIdleTimeout(tc.flagVal, tc.cfgVal); got != tc.want {
				t.Errorf("ResolveSessionIdleTimeout(%d, %v) = %d, want %d", tc.flagVal, tc.cfgVal, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SetProxyVersion (stdio.go) — flows the build version into the proxy's
// initialize response. It is package-global, so restore it after the test.
// ---------------------------------------------------------------------------

func TestSetProxyVersion(t *testing.T) {
	// Not parallel: mutates the package-global proxyVersion.
	prev := proxyVersion
	t.Cleanup(func() { proxyVersion = prev })

	SetProxyVersion("1.2.3-test")
	if proxyVersion != "1.2.3-test" {
		t.Fatalf("proxyVersion = %q, want 1.2.3-test", proxyVersion)
	}

	// The version flows into the initialize response the proxy builds for the host.
	sess := newTestSession(&httpSession{})
	resp := sess.buildInitResponse(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("1"), Method: "initialize"})
	var result mcp.InitResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal init result: %v", err)
	}
	if got, _ := result.ServerInfo["version"].(string); got != "1.2.3-test" {
		t.Errorf("serverInfo.version = %q, want 1.2.3-test", got)
	}
}

// ---------------------------------------------------------------------------
// buildInitResponse (http_session.go) — default-capabilities branch and the
// upstream-supplied caps + instructions branch.
// ---------------------------------------------------------------------------

func TestBuildInitResponse_DefaultsWhenNoUpstreamCaps(t *testing.T) {
	t.Parallel()
	sess := newTestSession(&httpSession{}) // upstreamCaps nil
	resp := sess.buildInitResponse(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("7"), Method: "initialize"})
	if resp.Error != nil {
		t.Fatalf("unexpected error response: %+v", resp.Error)
	}
	var result mcp.InitResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.ProtocolVersion != MCPProtocolVersion {
		t.Errorf("protocolVersion = %q, want %q", result.ProtocolVersion, MCPProtocolVersion)
	}
	// Default capabilities synthesize a tools object when the upstream supplied none.
	if _, ok := result.Capabilities["tools"]; !ok {
		t.Errorf("default capabilities should carry a tools object, got %v", result.Capabilities)
	}
}

func TestBuildInitResponse_UsesUpstreamCapsAndInstructions(t *testing.T) {
	t.Parallel()
	sess := newTestSession(&httpSession{
		upstreamCaps:         map[string]interface{}{"resources": map[string]interface{}{}},
		upstreamInstructions: "be careful",
	})
	resp := sess.buildInitResponse(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("8"), Method: "initialize"})
	var result mcp.InitResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := result.Capabilities["resources"]; !ok {
		t.Errorf("upstream-supplied capabilities should be preserved, got %v", result.Capabilities)
	}
	if result.Instructions != "be careful" {
		t.Errorf("instructions = %q, want %q", result.Instructions, "be careful")
	}
}

// ---------------------------------------------------------------------------
// ApplyInitializeResult (jsonrpc.go) — exported wrapper. The existing suite
// drives the unexported applyInitializeResult; this exercises the exported
// seam the CLI probe consumes (one happy + one fail-closed case).
// ---------------------------------------------------------------------------

func TestApplyInitializeResult_ExportedWrapper(t *testing.T) {
	t.Parallel()

	result := mcp.InitResult{
		ProtocolVersion: MCPProtocolVersion,
		Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
		ServerInfo:      map[string]interface{}{"name": "up", "version": "4.5.6"},
		Instructions:    "exported path",
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	caps, ver, instructions, err := ApplyInitializeResult(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("1"), Result: json.RawMessage(raw)})
	if err != nil {
		t.Fatalf("ApplyInitializeResult rejected a valid result: %v", err)
	}
	if ver != "4.5.6" || instructions != "exported path" || caps == nil {
		t.Errorf("got caps=%v ver=%q instructions=%q", caps, ver, instructions)
	}

	// Fail-closed: an error response surfaces as an error from the exported form too.
	_, _, _, err = ApplyInitializeResult(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("1"), Error: &mcp.RPCError{Code: -32600, Message: "nope"}})
	if err == nil {
		t.Fatal("ApplyInitializeResult must fail closed on an error response")
	}

	// A result missing the required serverInfo object must also fail closed
	// (exercises validateInitializeResultFields' serverInfo branch).
	noServerInfo := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON("1"),
		Result:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{}}`),
	}
	if _, _, _, err := ApplyInitializeResult(noServerInfo); err == nil {
		t.Fatal("a result missing serverInfo must fail closed")
	} else if !strings.Contains(err.Error(), "serverInfo") {
		t.Errorf("error = %q, want it to mention serverInfo", err.Error())
	}
}

// ---------------------------------------------------------------------------
// denialArgument (jsonrpc.go) — the uncovered branches: nil DenialInfo, a
// present string argument, and a present-but-non-string argument detail.
// ---------------------------------------------------------------------------

func TestDenialArgument(t *testing.T) {
	t.Parallel()

	if got := denialArgument(nil); got != "" {
		t.Errorf("nil DenialInfo must yield empty argument, got %q", got)
	}

	d := &capability.DenialInfo{Details: map[string]interface{}{"argument": "path"}}
	if got := denialArgument(d); got != "path" {
		t.Errorf("got %q, want path", got)
	}

	// A non-string argument detail (or a missing key) must yield "" — only the
	// argument name is ever surfaced, never a value of another type.
	nonString := &capability.DenialInfo{Details: map[string]interface{}{"argument": 42}}
	if got := denialArgument(nonString); got != "" {
		t.Errorf("non-string argument detail must yield empty, got %q", got)
	}
	noKey := &capability.DenialInfo{Details: map[string]interface{}{"other": "x"}}
	if got := denialArgument(noKey); got != "" {
		t.Errorf("missing argument key must yield empty, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// BuildOAuthMetadataURL / oauthMetadataPathSuffix (oauth_metadata.go) — the
// defensive parse-failure branches the existing suite does not reach.
// ---------------------------------------------------------------------------

func TestBuildOAuthMetadataURL_DefensiveFallback(t *testing.T) {
	t.Parallel()

	// A host-less / unparseable resource hits the defensive fallback: trim a
	// trailing slash and append the well-known base path.
	if got := BuildOAuthMetadataURL("not-a-url/"); got != "not-a-url"+metadataBasePath {
		t.Errorf("host-less resource = %q, want %q", got, "not-a-url"+metadataBasePath)
	}
	if got := BuildOAuthMetadataURL(""); got != metadataBasePath {
		t.Errorf("empty resource = %q, want %q", got, metadataBasePath)
	}
}

func TestOAuthMetadataPathSuffix_UnparseableReturnsEmpty(t *testing.T) {
	t.Parallel()

	// A control character makes url.Parse fail, exercising the error branch that
	// returns "" so the bare metadataBasePath registration still covers it.
	if got := oauthMetadataPathSuffix("http://exa\x7fmple/x"); got != "" {
		t.Errorf("unparseable metaURL must yield empty suffix, got %q", got)
	}
	// A metaURL that is exactly the base path has no suffix.
	if got := oauthMetadataPathSuffix(metadataBasePath); got != "" {
		t.Errorf("base-path-only metaURL must yield empty suffix, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// LocalManifest.HasSamplingGrant / AnyRouteHasMaxCalls — pure manifest
// inspection helpers. HasSamplingGrant is single-sourced in internal/config so
// the startup HTTP-upstream sampling guard and DecideSampling cannot drift; it is
// action-aware, matching DecideSampling's containsAction(...,"allow") rule.
// ---------------------------------------------------------------------------

func TestManifestHasSamplingGrant(t *testing.T) {
	t.Parallel()

	if (*config.LocalManifest)(nil).HasSamplingGrant() {
		t.Error("nil manifest must report no sampling grant")
	}

	withSampling := &config.LocalManifest{
		Capabilities: []capability.Constraint{
			{Target: "system:sampling/createMessage", Actions: []string{"allow"}},
		},
	}
	if !withSampling.HasSamplingGrant() {
		t.Error("a system:sampling/createMessage target with an allow action is a grant")
	}

	// Action-aware: a system:sampling entry whose actions do NOT permit it is not a
	// grant. The prior presence-only check ignored actions and would have (wrongly)
	// reported a grant here, drifting from DecideSampling.
	notAllowed := &config.LocalManifest{
		Capabilities: []capability.Constraint{
			{Target: "system:sampling/createMessage", Actions: []string{"deny"}},
		},
	}
	if notAllowed.HasSamplingGrant() {
		t.Error("a system:sampling entry without an allow/* action must not count as a grant")
	}

	// A system: wildcard whose glob covers sampling/createMessage also grants sampling
	// — the engine matches target names by glob (MatchesResource) at runtime, so these
	// must be caught too.
	for _, pat := range []string{"system:*", "system:sampling/*"} {
		m := &config.LocalManifest{Capabilities: []capability.Constraint{{Target: pat, Actions: []string{"*"}}}}
		if !m.HasSamplingGrant() {
			t.Errorf("%q covers sampling/createMessage by glob and must count as a grant", pat)
		}
	}

	// system: patterns that do NOT cover sampling/createMessage are not grants. A
	// single '*' does not cross '/', so "system:sampl*" matches "sampling" but not
	// "sampling/createMessage"; "system:roots/*" matches a different namespace.
	for _, pat := range []string{"system:sampl*", "system:roots/*"} {
		m := &config.LocalManifest{Capabilities: []capability.Constraint{{Target: pat, Actions: []string{"*"}}}}
		if m.HasSamplingGrant() {
			t.Errorf("%q does not cover sampling/createMessage and must not count as a grant", pat)
		}
	}

	// A tool target (and an unparseable target) is not a sampling grant.
	withoutSampling := &config.LocalManifest{
		Capabilities: []capability.Constraint{
			{Target: "tool:read_file", Actions: []string{"call"}},
			{Target: "not a valid target"},
		},
	}
	if withoutSampling.HasSamplingGrant() {
		t.Error("no system:sampling target ⟹ no grant")
	}
}

func TestAnyRouteHasMaxCalls(t *testing.T) {
	t.Parallel()

	maxCallsCap := capability.Constraint{
		Target:  "tool:read_file",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 5},
		},
	}
	plainCap := capability.Constraint{Target: "tool:write_file", Actions: []string{"call"}}

	withMax := map[string]*UpstreamRoute{
		"a": {manifest: &config.LocalManifest{Capabilities: []capability.Constraint{plainCap}}},
		"b": {manifest: &config.LocalManifest{Capabilities: []capability.Constraint{maxCallsCap}}},
	}
	if !AnyRouteHasMaxCalls(withMax) {
		t.Error("a route whose manifest uses maxCalls must be detected")
	}

	// A nil-manifest (wiretap) route plus a maxCalls-free route ⟹ false; the nil
	// guard must not panic.
	withoutMax := map[string]*UpstreamRoute{
		"wiretap": {manifest: nil},
		"plain":   {manifest: &config.LocalManifest{Capabilities: []capability.Constraint{plainCap}}},
	}
	if AnyRouteHasMaxCalls(withoutMax) {
		t.Error("no route uses maxCalls ⟹ false")
	}
}

// TestFirstRouteAudiencePin verifies detection of a manifest `audience` pin so the CLI
// can fail closed when a route pins an audience but no --jwks-uri is set (the pin would
// otherwise be dead config and the route would serve every request unauthenticated).
func TestFirstRouteAudiencePin(t *testing.T) {
	t.Parallel()

	// A route whose manifest declares an audience is detected (by name).
	withPin := map[string]*UpstreamRoute{
		"open":   {manifest: &config.LocalManifest{}},
		"tenant": {manifest: &config.LocalManifest{Audience: "team-a"}},
	}
	name, pinned := FirstRouteAudiencePin(withPin)
	if !pinned || name != "tenant" {
		t.Errorf("FirstRouteAudiencePin = (%q, %v), want (\"tenant\", true)", name, pinned)
	}

	// A nil-manifest (wiretap) route plus an audience-free route ⟹ (_, false); the nil
	// guard must not panic.
	withoutPin := map[string]*UpstreamRoute{
		"wiretap": {manifest: nil},
		"plain":   {manifest: &config.LocalManifest{}},
	}
	if _, pinned := FirstRouteAudiencePin(withoutPin); pinned {
		t.Error("no route pins an audience ⟹ false")
	}
}

// TestAnyRouteHasSequenceBlock mirrors TestAnyRouteHasMaxCalls: the multi-instance
// advisory must fire for a sequenceBlock-only policy too, since sequenceBlock reads
// per-session history out of the same per-process counter that maxCalls uses.
func TestAnyRouteHasSequenceBlock(t *testing.T) {
	t.Parallel()

	seqCap := capability.Constraint{
		Target:  "tool:deploy",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.SequenceBlockCondition{AfterTools: []string{"tool:read_secret"}},
		},
	}
	plainCap := capability.Constraint{Target: "tool:write_file", Actions: []string{"call"}}

	withSeq := map[string]*UpstreamRoute{
		"a": {manifest: &config.LocalManifest{Capabilities: []capability.Constraint{plainCap}}},
		"b": {manifest: &config.LocalManifest{Capabilities: []capability.Constraint{seqCap}}},
	}
	if !AnyRouteHasSequenceBlock(withSeq) {
		t.Error("a route whose manifest uses sequenceBlock must be detected")
	}

	// A nil-manifest (wiretap) route plus a sequenceBlock-free route ⟹ false; the nil
	// guard must not panic.
	withoutSeq := map[string]*UpstreamRoute{
		"wiretap": {manifest: nil},
		"plain":   {manifest: &config.LocalManifest{Capabilities: []capability.Constraint{plainCap}}},
	}
	if AnyRouteHasSequenceBlock(withoutSeq) {
		t.Error("no route uses sequenceBlock ⟹ false")
	}
}

// ---------------------------------------------------------------------------
// routeSink.AuditDegraded (route.go) — delegation to the shared sink plus the
// nil-receiver healthy report.
// ---------------------------------------------------------------------------

func TestRouteSink_AuditDegraded(t *testing.T) {
	t.Parallel()

	// A nil routeSink reports healthy (a strict proxy with a failed sink is refused
	// at startup, so the runtime gate never sees one).
	var nilSink *routeSink
	if degraded, reason, detail := nilSink.AuditDegraded(); degraded || reason != "" || detail != nil {
		t.Errorf("nil routeSink: got (%v, %q, %v), want (false, \"\", nil)", degraded, reason, detail)
	}

	// A fresh sink (no drops, no write failures) is healthy and delegates through
	// the wrapper.
	sink, _ := newTempAuditSink(t)
	rs := &routeSink{sink: sink, upstream: "fs"}
	if degraded, reason, detail := rs.AuditDegraded(); degraded || reason != "" || detail != nil {
		t.Errorf("fresh sink: got (%v, %q, %v), want (false, \"\", nil)", degraded, reason, detail)
	}
}

// ---------------------------------------------------------------------------
// GenerateControlToken / WriteControlTokenFile (control_token.go) — the
// default-path ("" -> default) and current-directory ("." dir) branches not
// exercised by the existing round-trip tests.
// ---------------------------------------------------------------------------

func TestGenerateControlToken_DistinctEachCall(t *testing.T) {
	t.Parallel()
	a, err := GenerateControlToken()
	if err != nil {
		t.Fatalf("GenerateControlToken: %v", err)
	}
	b, err := GenerateControlToken()
	if err != nil {
		t.Fatalf("GenerateControlToken: %v", err)
	}
	if len(a) != 64 || len(b) != 64 {
		t.Fatalf("token lengths = %d, %d, want 64", len(a), len(b))
	}
	if a == b {
		t.Error("two GenerateControlToken calls must not collide")
	}
}

func TestWriteControlTokenFile_BareFilenameUsesCurrentDir(t *testing.T) {
	// Not parallel: t.Chdir mutates the process working directory so a bare
	// relative filename (dir ".") exercises the "do not MkdirAll/Chmod ." branch.
	// t.Chdir restores the prior directory automatically at test end.
	dir := t.TempDir()
	t.Chdir(dir)

	written, err := WriteControlTokenFile("relative.token", "tok-bare")
	if err != nil {
		t.Fatalf("WriteControlTokenFile: %v", err)
	}
	if written != "relative.token" {
		t.Errorf("written path = %q, want relative.token", written)
	}
	// Confirm the secret landed at the bare path with the documented 0600 mode.
	info, err := os.Stat("relative.token")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 0600", perm)
	}
	got, err := ResolveControlToken("", written)
	if err != nil {
		t.Fatalf("ResolveControlToken: %v", err)
	}
	if got != "tok-bare" {
		t.Errorf("token = %q, want tok-bare", got)
	}
}

// ---------------------------------------------------------------------------
// LoadUpstreamPDP (route.go) — the uncovered fail-closed branches: expectVersion
// without a policy, expectVersion across multiple policy files, and a
// sampling-opt-in manifest on an http upstream.
// ---------------------------------------------------------------------------

func TestLoadUpstreamPDP_ExpectVersionWithoutPolicy(t *testing.T) {
	t.Parallel()
	u := &config.UpstreamConfig{Name: "fs", Transport: "stdio", ExpectVersion: "1.0.0"}
	_, _, _, _, err := LoadUpstreamPDP(u, config.HostTransportStdio, "", callcounter.NewInMemory(), nil, killswitch.NewInMemory())
	if err == nil {
		t.Fatal("expectVersion without a policy must fail closed")
	}
	if !strings.Contains(err.Error(), "expectVersion") {
		t.Errorf("error = %q, want it to mention expectVersion", err.Error())
	}
}

func TestLoadUpstreamPDP_ExpectVersionMultiplePolicies(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m1 := mustWriteFile(t, dir, "a.yaml", "schemaVersion: \"0.1\"\nname: a\nversion: \"1.0.0\"\ncapabilities:\n  - target: tool:read_file\n    actions: [call]\n")
	m2 := mustWriteFile(t, dir, "b.yaml", "schemaVersion: \"0.1\"\nname: b\nversion: \"1.0.0\"\ncapabilities:\n  - target: tool:write_file\n    actions: [call]\n")
	u := &config.UpstreamConfig{Name: "fs", Transport: "stdio", ExpectVersion: "1.0.0", Policy: []string{m1, m2}}
	_, _, _, _, err := LoadUpstreamPDP(u, config.HostTransportStdio, "", callcounter.NewInMemory(), nil, killswitch.NewInMemory())
	if err == nil {
		t.Fatal("expectVersion with multiple policy files must be rejected")
	}
	if !strings.Contains(err.Error(), "expectVersion") {
		t.Errorf("error = %q, want it to mention expectVersion", err.Error())
	}
}

func TestLoadUpstreamPDP_SamplingOptInOnHTTPUpstreamRejected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m := mustWriteFile(t, dir, "sampling.yaml",
		"schemaVersion: \"0.1\"\nname: s\nversion: \"1.0.0\"\ncapabilities:\n  - target: system:sampling/createMessage\n    actions: [allow]\n")
	u := &config.UpstreamConfig{Name: "remote", Transport: config.HostTransportHTTP, Policy: []string{m}}
	_, _, _, _, err := LoadUpstreamPDP(u, config.HostTransportHTTP, "", callcounter.NewInMemory(), nil, killswitch.NewInMemory())
	if err == nil {
		t.Fatal("a sampling opt-in on an http upstream must fail closed (it cannot be enforced)")
	}
	if !strings.Contains(err.Error(), "sampling") {
		t.Errorf("error = %q, want it to mention sampling", err.Error())
	}
}

// TestStartupFatalManifestCheck_DirectlyAgainstAlreadyMergedManifest is a
// regression for the doctor/validate reuse seam: a caller that already loaded and
// merged a route's manifests (as doctor's writeDoctorManifests and validate's
// validateConfigRoutes now do) must be able to call StartupFatalManifestCheck
// directly against that merged result — without re-parsing/re-merging the
// manifest files a second time via LoadUpstreamPDP — and get the identical
// startup-fatal verdict LoadUpstreamPDP would compute inline.
func TestStartupFatalManifestCheck_DirectlyAgainstAlreadyMergedManifest(t *testing.T) {
	t.Parallel()

	t.Run("expectVersion mismatch", func(t *testing.T) {
		t.Parallel()
		u := &config.UpstreamConfig{Name: "fs", Transport: "stdio", ExpectVersion: "2.0.0"}
		merged := &config.LocalManifest{Version: "1.0.0"}
		err := StartupFatalManifestCheck(u, config.HostTransportStdio, merged)
		if err == nil {
			t.Fatal("expectVersion mismatch must fail closed")
		}
		if !strings.Contains(err.Error(), "expectVersion") {
			t.Errorf("error = %q, want it to mention expectVersion", err.Error())
		}
	})

	t.Run("expectVersion match passes", func(t *testing.T) {
		t.Parallel()
		u := &config.UpstreamConfig{Name: "fs", Transport: "stdio", ExpectVersion: "1.0.0"}
		merged := &config.LocalManifest{Version: "1.0.0"}
		if err := StartupFatalManifestCheck(u, config.HostTransportStdio, merged); err != nil {
			t.Errorf("expectVersion match should pass, got: %v", err)
		}
	})

	t.Run("sampling opt-in on http upstream", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		m := mustWriteFile(t, dir, "sampling.yaml",
			"schemaVersion: \"0.1\"\nname: s\nversion: \"1.0.0\"\ncapabilities:\n  - target: system:sampling/createMessage\n    actions: [allow]\n")
		loaded, err := config.LoadManifest(m)
		if err != nil {
			t.Fatalf("LoadManifest: %v", err)
		}
		u := &config.UpstreamConfig{Name: "remote", Transport: config.HostTransportHTTP}
		if err := StartupFatalManifestCheck(u, config.HostTransportHTTP, loaded); err == nil {
			t.Fatal("a sampling opt-in on an http upstream must fail closed")
		} else if !strings.Contains(err.Error(), "sampling") {
			t.Errorf("error = %q, want it to mention sampling", err.Error())
		}
	})

	t.Run("no findings passes", func(t *testing.T) {
		t.Parallel()
		u := &config.UpstreamConfig{Name: "fs", Transport: "stdio"}
		merged := &config.LocalManifest{Version: "1.0.0"}
		if err := StartupFatalManifestCheck(u, config.HostTransportStdio, merged); err != nil {
			t.Errorf("clean manifest/upstream pair should pass, got: %v", err)
		}
	})

	t.Run("audience pin on stdio host", func(t *testing.T) {
		t.Parallel()
		u := &config.UpstreamConfig{Name: "fs", Transport: "stdio"}
		merged := &config.LocalManifest{Version: "1.0.0", Audience: "some-aud"}
		err := StartupFatalManifestCheck(u, config.HostTransportStdio, merged)
		if err == nil {
			t.Fatal("an audience pin on a stdio host must fail closed")
		}
		if !strings.Contains(err.Error(), "audience") {
			t.Errorf("error = %q, want it to mention audience", err.Error())
		}
	})

	t.Run("audience pin on http host passes", func(t *testing.T) {
		t.Parallel()
		u := &config.UpstreamConfig{Name: "fs", Transport: "stdio"}
		merged := &config.LocalManifest{Version: "1.0.0", Audience: "some-aud"}
		if err := StartupFatalManifestCheck(u, config.HostTransportHTTP, merged); err != nil {
			t.Errorf("an audience pin on an http gateway host should pass, got: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// sseResponseForID (http_remote.go) — the interleaved-notification skip and
// the no-match terminal error, neither of which the happy-path tests reach.
// ---------------------------------------------------------------------------

func TestSseResponseForID_SkipsInterleavedAndMatches(t *testing.T) {
	t.Parallel()
	// A notification (no id), then a non-matching response, then the matching one.
	stream := strings.Join([]string{
		`data: {"jsonrpc":"2.0","method":"notifications/progress"}`,
		``,
		`data: {"jsonrpc":"2.0","id":99,"result":{"other":true}}`,
		``,
		`data: {"jsonrpc":"2.0","id":7,"result":{"ok":true}}`,
		``,
	}, "\n")
	out, err := sseResponseForID(strings.NewReader(stream), mcp.RawJSON("7"))
	if err != nil {
		t.Fatalf("sseResponseForID: %v", err)
	}
	if mcp.MsgKey(out.ID) != mcp.MsgKey(mcp.RawJSON("7")) {
		t.Errorf("matched id = %s, want 7", out.ID)
	}
}

func TestSseResponseForID_MultiLineDataMatches(t *testing.T) {
	t.Parallel()
	// An event whose JSON payload is split across two data: lines (joined by a
	// newline) must still decode to the matching response.
	stream := "data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":3,\"result\":{\"v\":1}}\n\n"
	out, err := sseResponseForID(strings.NewReader(stream), mcp.RawJSON("3"))
	if err != nil {
		t.Fatalf("sseResponseForID multi-line: %v", err)
	}
	if mcp.MsgKey(out.ID) != mcp.MsgKey(mcp.RawJSON("3")) {
		t.Errorf("matched id = %s, want 3", out.ID)
	}
}

func TestSseResponseForID_NoMatchReturnsError(t *testing.T) {
	t.Parallel()
	// A stream that never carries the wanted id (and ends without a trailing blank
	// line) exercises the terminal decode + no-match error.
	stream := `data: {"jsonrpc":"2.0","id":1,"result":{}}`
	_, err := sseResponseForID(strings.NewReader(stream), mcp.RawJSON("42"))
	if err == nil {
		t.Fatal("a stream with no matching id must return an error")
	}
	if !strings.Contains(err.Error(), "no SSE event matched") {
		t.Errorf("error = %q, want it to report the unmatched id", err.Error())
	}
}

// ---------------------------------------------------------------------------
// handleMCPGet (http_routing.go) — the early-return error paths (missing
// session header, unknown session, wrong route) that the SSE happy path skips.
// ---------------------------------------------------------------------------

func TestHandleMCPGet_MissingSessionHeader(t *testing.T) {
	t.Parallel()
	proxy := newHTTPProxy(httpProxyOptions{PDP: pdp.AlwaysAllowPDP{}})
	route := proxy.routes[""]
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	rr := httptest.NewRecorder()
	proxy.handleMCPGet(rr, req, route)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing session header: got %d, want 400", rr.Code)
	}
}

func TestHandleMCPGet_UnknownSession(t *testing.T) {
	t.Parallel()
	proxy := newHTTPProxy(httpProxyOptions{PDP: pdp.AlwaysAllowPDP{}})
	route := proxy.routes[""]
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "does-not-exist")
	rr := httptest.NewRecorder()
	proxy.handleMCPGet(rr, req, route)
	if rr.Code != http.StatusNotFound {
		t.Errorf("unknown session: got %d, want 404", rr.Code)
	}
}

func TestHandleMCPGet_WrongRoute(t *testing.T) {
	t.Parallel()
	proxy := newHTTPProxy(httpProxyOptions{PDP: pdp.AlwaysAllowPDP{}})
	ownRoute := proxy.routes[""]
	// Register a session bound to ownRoute, then GET it as if for a different route.
	sess := newTestSession(&httpSession{
		id:    "sess-1",
		proxy: proxy,
		route: ownRoute,
		done:  make(chan struct{}),
	})
	proxy.mu.Lock()
	proxy.sessions["sess-1"] = sess
	proxy.mu.Unlock()

	otherRoute := &UpstreamRoute{name: "other", pdp: pdp.AlwaysAllowPDP{}}
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "sess-1")
	rr := httptest.NewRecorder()
	proxy.handleMCPGet(rr, req, otherRoute)
	if rr.Code != http.StatusConflict {
		t.Errorf("cross-route GET: got %d, want 409", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// reapIdleSessions (http_session.go) — the run loop. Drive one tick (which
// calls reapOnce) then cancel ctx and confirm the loop returns. Deterministic:
// a short idle window yields a sub-second ticker, and the cancel is observed by
// the select's ctx.Done arm.
// ---------------------------------------------------------------------------

func TestReapIdleSessions_TicksThenStopsOnCancel(t *testing.T) {
	proxy, srv := newCappedProxy(t, 0, 1) // 1ms idle ⟹ ticker clamps to 1s minimum
	sid := initSession(t, srv)
	sess := proxy.getSession(sid)
	if sess == nil {
		t.Fatal("session not found")
	}
	// Drive the session well past the (clamped) idle horizon so the first tick reaps it.
	sess.lastActive.Store(time.Now().Add(-time.Hour).UnixNano())
	sess.lastRequest.Store(time.Now().Add(-time.Hour).UnixNano())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		proxy.reapIdleSessions(ctx)
		close(done)
	}()

	// The reaper's first tick (at the 1s clamped interval) closes the stale session.
	waitForSessions(t, proxy, 0)

	// Cancelling ctx must make the loop return promptly via its ctx.Done arm.
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("reapIdleSessions did not return after context cancel")
	}
}

// ---------------------------------------------------------------------------
// warnStrictAuditOnce (forward.go) — the one-shot stderr warning. The nil-guard
// branch (test callers) is covered elsewhere; here we cover the real
// CompareAndSwap path: it fires once and not again.
// ---------------------------------------------------------------------------

func TestWarnStrictAuditOnce_FiresOnce(t *testing.T) {
	t.Parallel()
	var warned atomic.Bool
	// First call swaps false->true.
	warnStrictAuditOnce(&warned, "test reason")
	if !warned.Load() {
		t.Fatal("warnStrictAuditOnce must set the warned flag on first call")
	}
	// Second call is a no-op (CompareAndSwap fails); the flag stays set and nothing
	// panics.
	warnStrictAuditOnce(&warned, "test reason")
	if !warned.Load() {
		t.Fatal("warned flag must remain set after the second call")
	}
}

// ---------------------------------------------------------------------------
// handleHealth (health.go) — the loopback-guard rejection and the
// method-not-allowed branch the happy-path scrape skips.
// ---------------------------------------------------------------------------

func TestHandleHealth_NonLoopbackRejected(t *testing.T) {
	t.Parallel()
	proxy := newHTTPProxy(httpProxyOptions{PDP: pdp.AlwaysAllowPDP{}})
	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	req.RemoteAddr = "203.0.113.7:9999" // off-host
	rr := httptest.NewRecorder()
	proxy.handleHealth(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("off-host /healthz: got %d, want 403", rr.Code)
	}
}

func TestHandleHealth_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	proxy := newHTTPProxy(httpProxyOptions{PDP: pdp.AlwaysAllowPDP{}})
	req := httptest.NewRequest(http.MethodPost, "/healthz", http.NoBody)
	req.RemoteAddr = "127.0.0.1:9999" // loopback: passes the guard, fails the method check
	req.Host = "127.0.0.1:9999"       // loopback Host so loopbackOnly's DNS-rebinding guard passes
	rr := httptest.NewRecorder()
	proxy.handleHealth(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /healthz: got %d, want 405", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// handleMetrics (health.go) — the loopback-guard rejection branch.
// ---------------------------------------------------------------------------

func TestHandleMetrics_NonLoopbackRejected(t *testing.T) {
	t.Parallel()
	proxy := newHTTPProxy(httpProxyOptions{PDP: pdp.AlwaysAllowPDP{}})
	req := httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody)
	req.RemoteAddr = "203.0.113.9:9999"
	rr := httptest.NewRecorder()
	proxy.handleMetrics(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("off-host /metrics: got %d, want 403", rr.Code)
	}
}

func TestHandleMetrics_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	proxy := newHTTPProxy(httpProxyOptions{PDP: pdp.AlwaysAllowPDP{}})
	req := httptest.NewRequest(http.MethodPost, "/metrics", http.NoBody)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Host = "127.0.0.1:9999" // loopback Host so loopbackOnly's DNS-rebinding guard passes
	rr := httptest.NewRecorder()
	proxy.handleMetrics(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /metrics: got %d, want 405", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// splitHeaderLine (stdio_http_upstream.go) — pure "Name: Value" parser.
// ---------------------------------------------------------------------------

func TestSplitHeaderLine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		line              string
		wantName, wantVal string
		wantOK            bool
	}{
		{"Authorization: Bearer abc", "Authorization", "Bearer abc", true},
		{"X-Api-Key:value-no-space", "X-Api-Key", "value-no-space", true},
		{"  Spaced  :  trimmed  ", "Spaced", "trimmed", true},
		{"", "", "", false},
		{"no-colon-here", "", "", false},
	}
	for _, tc := range cases {
		name, val, ok := splitHeaderLine(tc.line)
		if ok != tc.wantOK || name != tc.wantName || val != tc.wantVal {
			t.Errorf("splitHeaderLine(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.line, name, val, ok, tc.wantName, tc.wantVal, tc.wantOK)
		}
	}
}

// ---------------------------------------------------------------------------
// BuildUpstreamClient (http_remote.go) — the tlsSkipVerify branch and the
// secure default. Both refuse to follow redirects.
// ---------------------------------------------------------------------------

func TestBuildUpstreamClient_TLSSkipVerifyAndRedirectPolicy(t *testing.T) {
	t.Parallel()

	secure := BuildUpstreamClient(false, 0)
	if tr, ok := secure.Transport.(*http.Transport); ok {
		if tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
			t.Error("default client must verify TLS certificates")
		}
	}
	insecure := BuildUpstreamClient(true, 0)
	tr, ok := insecure.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", insecure.Transport)
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("tlsSkipVerify=true must set InsecureSkipVerify")
	}
	// Both clients must refuse to follow redirects so a custom auth header is never
	// replayed to a redirect target.
	if secure.CheckRedirect == nil || insecure.CheckRedirect == nil {
		t.Fatal("CheckRedirect must be set to refuse redirects")
	}
	if err := secure.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect = %v, want ErrUseLastResponse", err)
	}
}

// ---------------------------------------------------------------------------
// DoMCPHTTP (http_remote.go) — the response-handling branches not covered by
// the proxy-level happy path: a non-2xx upstream, a 202 Accepted notification,
// and an SSE-bodied 200 OK that must be parsed via sseResponseForID.
// ---------------------------------------------------------------------------

func TestDoMCPHTTP_NonOKReturnsError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream is unhappy", http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)

	req := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("1"), Method: "tools/list"}
	_, _, err := DoMCPHTTP(context.Background(), srv.Client(), srv.URL, req, "", "")
	if err == nil {
		t.Fatal("a non-2xx upstream response must return an error")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error = %q, want it to report the 502 status", err.Error())
	}
}

func TestDoMCPHTTP_AcceptedReturnsEmpty(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	// A notification (no id) answered with 202 returns an empty message and no error.
	notif, _ := mcp.NotificationMsg(mcp.MethodNotificationsInitialized, nil)
	out, _, err := DoMCPHTTP(context.Background(), srv.Client(), srv.URL, notif, "sess", "Authorization: Bearer x")
	if err != nil {
		t.Fatalf("202 Accepted must not error: %v", err)
	}
	if out.Method != "" || out.Result != nil || out.Error != nil {
		t.Errorf("202 must yield an empty message, got %+v", out)
	}
}

func TestDoMCPHTTP_SSEBodyDecoded(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ctSSE)
		w.WriteHeader(http.StatusOK)
		// A leading notification then the matching response on the same stream.
		_, _ = w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"))
		_, _ = w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"ok\":true}}\n\n"))
	}))
	t.Cleanup(srv.Close)

	req := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("5"), Method: "tools/call"}
	out, _, err := DoMCPHTTP(context.Background(), srv.Client(), srv.URL, req, "", "")
	if err != nil {
		t.Fatalf("SSE 200 response must decode: %v", err)
	}
	if mcp.MsgKey(out.ID) != mcp.MsgKey(mcp.RawJSON("5")) {
		t.Errorf("decoded id = %s, want 5", out.ID)
	}
}

func TestDoMCPHTTP_MalformedJSONBodyErrors(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", CTJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{ this is not valid json"))
	}))
	t.Cleanup(srv.Close)

	req := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("1"), Method: "tools/list"}
	_, _, err := DoMCPHTTP(context.Background(), srv.Client(), srv.URL, req, "", "")
	if err == nil {
		t.Fatal("a malformed JSON body must surface a decode error")
	}
	if !strings.Contains(err.Error(), "decoding upstream response") {
		t.Errorf("error = %q, want it to report a JSON decode failure", err.Error())
	}
}

func TestDoMCPHTTP_SSENoMatchErrors(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ctSSE)
		w.WriteHeader(http.StatusOK)
		// The stream carries an event for a different id, so no match is found.
		_, _ = w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"))
	}))
	t.Cleanup(srv.Close)

	req := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("99"), Method: "tools/call"}
	_, _, err := DoMCPHTTP(context.Background(), srv.Client(), srv.URL, req, "", "")
	if err == nil {
		t.Fatal("an SSE stream with no matching id must surface a decode error")
	}
	if !strings.Contains(err.Error(), "decoding upstream SSE response") {
		t.Errorf("error = %q, want it to report an SSE decode failure", err.Error())
	}
}

// ---------------------------------------------------------------------------
// DeleteMCPHTTPSession (http_remote.go) — the no-op guards (blank sessID, nil
// client) and the success path with an auth header set.
// ---------------------------------------------------------------------------

func TestDeleteMCPHTTPSession_NoOpGuards(t *testing.T) {
	t.Parallel()
	// A blank session ID is a no-op: nothing was initialized to terminate. A nil
	// client is likewise a no-op. Neither must panic or make a request.
	DeleteMCPHTTPSession(http.DefaultClient, "http://127.0.0.1:0/mcp", "", "")
	DeleteMCPHTTPSession(nil, "http://127.0.0.1:0/mcp", "sess", "")
}

func TestDeleteMCPHTTPSession_SendsDeleteWithAuthHeader(t *testing.T) {
	t.Parallel()
	type seen struct {
		method, sess, auth string
	}
	got := make(chan seen, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- seen{method: r.Method, sess: r.Header.Get(SessionHeader), auth: r.Header.Get("Authorization")}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	DeleteMCPHTTPSession(srv.Client(), srv.URL+"/mcp", "up-sess-1", "Authorization: Bearer tok")
	select {
	case s := <-got:
		if s.method != http.MethodDelete {
			t.Errorf("method = %q, want DELETE", s.method)
		}
		if s.sess != "up-sess-1" {
			t.Errorf("session header = %q, want up-sess-1", s.sess)
		}
		if s.auth != "Bearer tok" {
			t.Errorf("auth header = %q, want Bearer tok", s.auth)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DeleteMCPHTTPSession did not send a request")
	}
}
