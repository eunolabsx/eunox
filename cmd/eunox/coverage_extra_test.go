// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Additional subcommand coverage. These tests target the under-covered error
// and success branches of the CLI subcommands and their pure helpers, driving
// the exported-by-package-main functions directly (validateConfigRoutes,
// killViaRedis, the doctor section writers, the suggest/init pure helpers) and
// the os.Args-wired subcommands through their return-without-os.Exit paths.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/internal/transport"
	"github.com/eunolabs/eunox/pkg/capability"
)

// newClosedPipe returns a reader/writer pair from an io.Pipe whose writer is
// already closed, so the first Write returns io.ErrClosedPipe — used to drive
// the write-error branches without a subprocess.
func newClosedPipe(t *testing.T) (*io.PipeReader, *io.PipeWriter) {
	t.Helper()
	pr, pw := io.Pipe()
	_ = pw.Close()
	t.Cleanup(func() { _ = pr.Close() })
	return pr, pw
}

// ───────────────────────── auditRequirement.String ─────────────────────────

// TestAuditRequirementString covers every branch of (*auditRequirement).String,
// which the flag package calls to render the default in -help.
func TestAuditRequirementString(t *testing.T) {
	cases := []struct {
		val  auditRequirement
		want string
	}{
		{auditRequireOff, "off"},
		{auditRequireOn, "on"},
		{auditRequireStrict, "strict"},
		{auditRequirement(99), "off"}, // unknown → default branch
	}
	for _, tc := range cases {
		v := tc.val
		if got := v.String(); got != tc.want {
			t.Errorf("auditRequirement(%d).String() = %q, want %q", int(tc.val), got, tc.want)
		}
	}
}

// ───────────────────────── validateConfigRoutes (live) ─────────────────────

// singleUpstreamConfig returns a minimal GatewayConfig holding a single
// upstream route, bypassing the YAML loader so a test can point a route at an
// httptest server (HTTP transport) or an in-process fake (stdio transport)
// directly.
func singleUpstreamConfig(transportKind string, defaults config.RouteDefaults, u config.UpstreamConfig) *config.GatewayConfig {
	return &config.GatewayConfig{
		Transport: transportKind,
		Defaults:  defaults,
		Upstreams: []config.UpstreamConfig{u},
	}
}

// newConfigForRoute returns a minimal HTTP-transport GatewayConfig holding a
// single upstream route, bypassing the YAML loader so a test can point a
// route at an httptest server URL directly.
func newConfigForRoute(u config.UpstreamConfig) *config.GatewayConfig {
	return singleUpstreamConfig(config.HostTransportHTTP, config.RouteDefaults{}, u)
}

// TestValidateConfigRoutes_LiveHTTPRouteWithDrift drives the --live path of
// validateConfigRoutes against a real HTTP upstream whose live tool list drifts
// from the route's manifest (a glob match → FM-1), exercising the per-route
// connect → merge → runValidateLive branch and the worst-code bump.
func TestValidateConfigRoutes_LiveHTTPRouteWithDrift(t *testing.T) {
	orig := liveUpstreamTimeout
	liveUpstreamTimeout = 5 * time.Second
	t.Cleanup(func() { liveUpstreamTimeout = orig })

	fake := newFakeUpstreamWithTools([]mcp.ToolEntry{
		{Name: "read_file"},
		{Name: "get_customer"}, // matched by get_* glob → FM-1
	})
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	manifestPath := mustWriteFile(t, dir, "policy.yaml", `
schemaVersion: "0.1"
name: drift-policy
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: ["call"]
  - target: "tool:get_*"
    actions: ["call"]
`)
	cfg := newConfigForRoute(config.UpstreamConfig{
		Name:        "r1",
		Transport:   config.HostTransportHTTP,
		UpstreamURL: srv.URL,
		Policy:      []string{manifestPath},
	})

	var buf bytes.Buffer
	code := validateConfigRoutes(context.Background(), cfg, true /* live */, &buf)
	if code != 1 {
		t.Errorf("exit code: want 1 (glob match), got %d\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "Connecting to upstream...  ok") {
		t.Errorf("expected a successful connect line:\n%s", out)
	}
	if !strings.Contains(out, "get_customer") {
		t.Errorf("expected FM-1 glob match for get_customer:\n%s", out)
	}
}

// TestValidateConfigRoutes_LiveConnectFailure exercises the connect-FAILED
// branch: the route points at a dead address, so fetchRouteLive errors and the
// worst code is bumped to 2.
func TestValidateConfigRoutes_LiveConnectFailure(t *testing.T) {
	orig := liveUpstreamTimeout
	liveUpstreamTimeout = 1 * time.Second
	t.Cleanup(func() { liveUpstreamTimeout = orig })

	dir := t.TempDir()
	manifestPath := mustWriteFile(t, dir, "policy.yaml", validManifestYAML)
	cfg := newConfigForRoute(config.UpstreamConfig{
		Name:        "dead",
		Transport:   config.HostTransportHTTP,
		UpstreamURL: "http://127.0.0.1:1", // nothing listening
		Policy:      []string{manifestPath},
	})

	var buf bytes.Buffer
	code := validateConfigRoutes(context.Background(), cfg, true, &buf)
	if code != 2 {
		t.Errorf("exit code: want 2 (connect failure), got %d\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "FAILED") {
		t.Errorf("expected a FAILED connect line:\n%s", buf.String())
	}
}

// TestValidateConfigRoutes_LiveAllowAllRouteNoManifest covers the policyless
// (allow-all) route under --live: it has no manifest, so after connecting the
// "no manifest to compare against" branch runs and the exit code stays 0.
func TestValidateConfigRoutes_LiveAllowAllRouteNoManifest(t *testing.T) {
	orig := liveUpstreamTimeout
	liveUpstreamTimeout = 5 * time.Second
	t.Cleanup(func() { liveUpstreamTimeout = orig })

	fake := newFakeUpstreamWithTools([]mcp.ToolEntry{{Name: "tool_a"}})
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	cfg := &config.GatewayConfig{
		Transport: config.HostTransportHTTP,
		Defaults:  config.RouteDefaults{Enforcement: "audit"},
		Upstreams: []config.UpstreamConfig{{
			Name:        "open",
			Transport:   config.HostTransportHTTP,
			UpstreamURL: srv.URL,
			// no Policy → allow-all/wiretap route
		}},
	}

	var buf bytes.Buffer
	code := validateConfigRoutes(context.Background(), cfg, true, &buf)
	if code != 0 {
		t.Errorf("allow-all live route should stay exit 0; got %d\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "no manifest to compare against") {
		t.Errorf("expected the no-manifest live note:\n%s", out)
	}
}

// ───────────────────────── killViaRedis (error paths) ──────────────────────

// TestKillViaRedis_PingFailure covers the ping-failure return: the Redis client
// is built, but the address is unreachable so pingRedis errors out before any
// kill-switch write.
func TestKillViaRedis_PingFailure(t *testing.T) {
	// 127.0.0.1:1 is reserved/unbound; the dial fails fast.
	err := killViaRedis("127.0.0.1:1", "", false, "sess-x")
	if err == nil {
		t.Fatal("expected an error pinging an unreachable redis, got nil")
	}
}

// TestKillViaRedis_EmptyAddr covers the buildRedisClient error wrapping branch.
func TestKillViaRedis_EmptyAddr(t *testing.T) {
	err := killViaRedis("", "", false, "all")
	if err == nil {
		t.Fatal("expected an error for an empty redis addr, got nil")
	}
	if !strings.Contains(err.Error(), "redis client") {
		t.Errorf("error should be wrapped with 'redis client'; got %v", err)
	}
}

// TestKillViaRedis_AllAndSessionSucceed re-covers the success branches through
// the function under test (the cmdKill redis tests go via os.Args; this exercises
// killViaRedis directly so the "all" and per-session legs are both hit).
func TestKillViaRedis_AllAndSessionSucceed(t *testing.T) {
	mr := miniredis.RunT(t)

	if err := killViaRedis(mr.Addr(), "", false, "all"); err != nil {
		t.Fatalf("killViaRedis all: %v", err)
	}
	if got, err := mr.Get("killswitch:global"); err != nil || got != "1" {
		t.Errorf("global kill not set: got %q err=%v", got, err)
	}

	if err := killViaRedis(mr.Addr(), "", false, "sess-direct"); err != nil {
		t.Fatalf("killViaRedis session: %v", err)
	}
	if got, err := mr.Get("killswitch:session:sess-direct"); err != nil || got != "1" {
		t.Errorf("session kill not set: got %q err=%v", got, err)
	}
}

// ───────────────────────── cmdStats / cmdAuditVerify (--config) ─────────────

// TestCmdStats_ConfigProvidesAuditLog drives cmdStats with --config so the
// configured audit.log becomes the default --audit-log; the command then reads
// the (empty) log and returns normally.
func TestCmdStats_ConfigProvidesAuditLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	doctorWriteFile(t, logPath, "")
	cfgPath := mustWriteFile(t, dir, "eunox.yaml", `
schemaVersion: "0.1"
transport: stdio
audit:
  log: `+logPath+`
upstreams:
  - name: u1
    transport: stdio
    command: echo
`)
	withArgs([]string{"eunox", "stats", "--config", cfgPath}, func() {
		cmdStats()
	})
}

// TestCmdAuditVerify_ConfigProvidesDefaults drives cmdAuditVerify with --config
// so the configured audit.log and audit.keyPath supply the defaults, then
// verifies a small signed log written through the same key.
func TestCmdAuditVerify_ConfigProvidesDefaults(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := audit.Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cfgPath := mustWriteFile(t, dir, "eunox.yaml", `
schemaVersion: "0.1"
transport: stdio
audit:
  log: `+logPath+`
  keyPath: `+keyPath+`
upstreams:
  - name: u1
    transport: stdio
    command: echo
`)
	withArgs([]string{"eunox", "audit-verify", "--config", cfgPath}, func() {
		cmdAuditVerify()
	})
}

// ───────────────────────── cmdSuggest (output paths) ───────────────────────

// auditAllowToolLine returns a JSONL audit record for an allowed tools/call with
// the given arguments captured in details.
func auditAllowToolLine(t *testing.T, tool string, args map[string]interface{}) string {
	t.Helper()
	rec := map[string]interface{}{
		"decision":    "allow",
		"target_type": "tool",
		"target":      tool,
		"method":      "tools/call",
		"session_id":  "sess-1",
		"details":     args,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal audit rec: %v", err)
	}
	return string(b) + "\n"
}

// TestCmdSuggest_WithRecordsToStdout drives cmdSuggest over a populated tape on
// the stdout path (no --output), exercising the read → render → print branch.
func TestCmdSuggest_WithRecordsToStdout(t *testing.T) {
	content := auditAllowToolLine(t, "read_file", map[string]interface{}{"path": "/tmp/a"}) +
		auditAllowToolLine(t, "read_file", map[string]interface{}{"path": "/tmp/b"})
	logPath := writeTempFile(t, content)

	withArgs([]string{"eunox", "suggest", "--audit-log", logPath}, func() {
		cmdSuggest()
	})
}

// TestCmdSuggest_WithOutputAndMaxValues exercises the --output write branch and
// the --max-values flag together.
func TestCmdSuggest_WithOutputAndMaxValues(t *testing.T) {
	content := auditAllowToolLine(t, "read_file", map[string]interface{}{"path": "/tmp/a"})
	logPath := writeTempFile(t, content)
	outPath := filepath.Join(t.TempDir(), "suggested.yaml")

	withArgs([]string{
		"eunox", "suggest",
		"--audit-log", logPath,
		"--output", outPath,
		"--max-values", "5",
		"--name", "drafted",
	}, func() {
		cmdSuggest()
	})

	got := doctorReadFile(t, outPath)
	// yamlScalar emits a plain unquoted scalar for a simple name (it only quotes / uses
	// !!binary when round-trip safety requires it).
	if !strings.Contains(got, "name: drafted") {
		t.Errorf("output manifest missing the custom name:\n%s", got)
	}
	if !strings.Contains(got, "tool:read_file") {
		t.Errorf("output manifest missing the observed target:\n%s", got)
	}
	// The written draft must be loadable by the manifest loader.
	if _, err := config.LoadManifest(outPath); err != nil {
		t.Errorf("suggested manifest does not load: %v\n%s", err, got)
	}
}

// ───────────────────────── cmdInit (--config-output) ───────────────────────

// TestCmdInit_ConfigOutputHTTP exercises the --config-output branch for an HTTP
// upstream: both the manifest and a runnable config are written.
func TestCmdInit_ConfigOutputHTTP(t *testing.T) {
	srv := httptest.NewServer(newFakeUpstream())
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.yaml")
	configPath := filepath.Join(dir, "eunox.yaml")

	withArgs([]string{
		"eunox", "init",
		"--upstream-url", srv.URL,
		"--output", manifestPath,
		"--config-output", configPath,
	}, func() {
		cmdInit()
	})

	if _, err := os.Stat(manifestPath); err != nil {
		t.Errorf("manifest not written: %v", err)
	}
	// Assert on the PARSED config, not a raw-bytes substring: the upstream URL is
	// a YAML scalar whose quoting/spacing is an emitter detail (a colon-bearing
	// URL may be emitted quoted), so a byte-level match is brittle. Loading the
	// config also subsumes the "must validate" check.
	cfgBytes := doctorReadFile(t, configPath)
	cfg, err := config.LoadGatewayConfig(configPath)
	if err != nil {
		t.Fatalf("generated config does not load: %v\n%s", err, cfgBytes)
	}
	if len(cfg.Upstreams) != 1 {
		t.Fatalf("generated config: got %d upstream(s), want 1\n%s", len(cfg.Upstreams), cfgBytes)
	}
	if got := cfg.Upstreams[0].UpstreamURL; got != srv.URL {
		t.Errorf("generated config upstream URL = %q, want %q\n%s", got, srv.URL, cfgBytes)
	}
}

// TestGenerateInitConfigYAML_HostileScalarsRoundTrip locks that the operator-supplied
// scalars init scaffolds into the runnable config — command, args, upstreamUrl,
// upstreamAuthHeader, and the policy path — round-trip through the gateway-config
// loader even when they carry YAML flow delimiters, quotes, colons, or a trailing
// comment marker. They previously used raw %q, which is unsafe for the same reasons
// the manifest scaffold routes its scalars through yamlScalar.
func TestGenerateInitConfigYAML_HostileScalarsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "weird #manifest.yaml")
	if err := os.WriteFile(manifestPath, []byte("schemaVersion: \"0.1\"\nname: m\nversion: \"0.1.0\"\ncapabilities: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		spec initUpstreamSpec
	}{
		{
			name: "stdio command and args with flow delimiters and quotes",
			spec: initUpstreamSpec{
				Transport: config.HostTransportStdio,
				Command:   "/opt/my server",
				Args:      []string{"-y", `{weird, "arg"}`, "key: value # not a comment"},
			},
		},
		{
			name: "http url and auth header with colon and quote",
			spec: initUpstreamSpec{
				Transport:  config.HostTransportHTTP,
				URL:        "https://mcp.example.com:8443/path?x=1",
				AuthHeader: `Authorization: Bearer "tok#en"`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yamlStr := generateInitConfigYAML(tc.spec, manifestPath)
			cfgPath := filepath.Join(dir, "cfg.yaml")
			if err := os.WriteFile(cfgPath, []byte(yamlStr), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.LoadGatewayConfig(cfgPath)
			if err != nil {
				t.Fatalf("generated config does not load: %v\n%s", err, yamlStr)
			}
			if len(cfg.Upstreams) != 1 {
				t.Fatalf("got %d upstream(s), want 1\n%s", len(cfg.Upstreams), yamlStr)
			}
			up := cfg.Upstreams[0]
			switch tc.spec.Transport {
			case config.HostTransportStdio:
				if up.Command != tc.spec.Command {
					t.Errorf("command round-trip: got %q want %q", up.Command, tc.spec.Command)
				}
				if len(up.Args) != len(tc.spec.Args) {
					t.Fatalf("args round-trip: got %q want %q", up.Args, tc.spec.Args)
				}
				for i := range tc.spec.Args {
					if up.Args[i] != tc.spec.Args[i] {
						t.Errorf("args[%d] round-trip: got %q want %q", i, up.Args[i], tc.spec.Args[i])
					}
				}
			default:
				if up.UpstreamURL != tc.spec.URL {
					t.Errorf("upstreamUrl round-trip: got %q want %q", up.UpstreamURL, tc.spec.URL)
				}
				if up.UpstreamAuthHeader != tc.spec.AuthHeader {
					t.Errorf("upstreamAuthHeader round-trip: got %q want %q", up.UpstreamAuthHeader, tc.spec.AuthHeader)
				}
			}
			if len(up.Policy) != 1 || up.Policy[0] != manifestPath {
				t.Errorf("policy round-trip: got %q want [%q]", up.Policy, manifestPath)
			}
		})
	}
}

// ───────────────────────── doctor section writers ──────────────────────────

// TestWriteDoctorBinary_EmitsIdentity covers writeDoctorBinary, which is only
// reachable through the full bundle otherwise.
func TestWriteDoctorBinary_EmitsIdentity(t *testing.T) {
	var buf bytes.Buffer
	writeDoctorBinary(&buf)
	out := buf.String()
	for _, marker := range []string{"version:", "go:", "os/arch:", "vcs:"} {
		if !strings.Contains(out, marker) {
			t.Errorf("binary section missing %q:\n%s", marker, out)
		}
	}
}

// TestWriteDoctorConfig_ReadError covers the read-failure branch: the path does
// not exist.
func TestWriteDoctorConfig_ReadError(t *testing.T) {
	var buf bytes.Buffer
	writeDoctorConfig(&buf, filepath.Join(t.TempDir(), "nope.yaml"))
	if !strings.Contains(buf.String(), "could not read:") {
		t.Errorf("expected a read-error line:\n%s", buf.String())
	}
}

// TestWriteDoctorConfig_ParseError covers the YAML-parse-failure branch.
func TestWriteDoctorConfig_ParseError(t *testing.T) {
	dir := t.TempDir()
	bad := mustWriteFile(t, dir, "bad.yaml", "this: : not: valid: yaml:\n")
	var buf bytes.Buffer
	writeDoctorConfig(&buf, bad)
	if !strings.Contains(buf.String(), "could not parse YAML:") {
		t.Errorf("expected a parse-error line:\n%s", buf.String())
	}
}

// TestWriteDoctorConfig_RedactsAndEmits covers the happy path of writeDoctorConfig
// (parse → redact → re-emit), including the per-line indent loop.
func TestWriteDoctorConfig_RedactsAndEmits(t *testing.T) {
	dir := t.TempDir()
	cfg := mustWriteFile(t, dir, "ok.yaml", `
schemaVersion: "0.1"
listen:
  bind: 127.0.0.1
  authToken: SENTINEL-TOKEN
upstreams:
  - name: u1
    transport: http
    upstreamUrl: https://host/x
`)
	var buf bytes.Buffer
	writeDoctorConfig(&buf, cfg)
	out := buf.String()
	if strings.Contains(out, "SENTINEL-TOKEN") {
		t.Errorf("authToken should be redacted:\n%s", out)
	}
	if !strings.Contains(out, "127.0.0.1") {
		t.Errorf("non-sensitive bind should survive:\n%s", out)
	}
}

// TestWriteDoctorAudit_MissingLogAndKey covers the audit section against a log
// path that resolves but does not exist, and a key path that resolves but is
// absent — the "log file: <err>" and "key path: ... (<err>)" branches.
func TestWriteDoctorAudit_MissingLogAndKey(t *testing.T) {
	dir := t.TempDir()
	missingLog := filepath.Join(dir, "absent.jsonl")
	missingKey := filepath.Join(dir, "absent.key")

	var buf bytes.Buffer
	writeDoctorAudit(&buf, missingLog, missingKey, 10)
	out := buf.String()
	if !strings.Contains(out, "log path:") {
		t.Errorf("expected a log path line:\n%s", out)
	}
	if !strings.Contains(out, "log file:") {
		t.Errorf("expected a 'log file:' stat-error line for a missing log:\n%s", out)
	}
}

// TestWriteDoctorAudit_WithKeyPresentAndTail covers the key-present branch, the
// aggregate-stats branch, and the record-tail branch (tail > 0) against a real
// signed log.
func TestWriteDoctorAudit_WithKeyPresentAndTail(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := audit.Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	sink.RecordDeny(context.Background(), "sess-1", "write_file", "tools/call", "CAPABILITY_DENIED", "", nil, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var buf bytes.Buffer
	writeDoctorAudit(&buf, logPath, keyPath, 50)
	out := buf.String()
	if !strings.Contains(out, "(present)") {
		t.Errorf("expected the key-present marker:\n%s", out)
	}
	if !strings.Contains(out, "records=2") {
		t.Errorf("expected aggregate totals records=2:\n%s", out)
	}
	if !strings.Contains(out, "Last 2 record(s)") {
		t.Errorf("expected a 2-record tail header:\n%s", out)
	}
}

// TestWriteDoctorAudit_TailSkipped covers the tail<=0 branch.
func TestWriteDoctorAudit_TailSkipped(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	sink, err := audit.Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var buf bytes.Buffer
	writeDoctorAudit(&buf, logPath, keyPath, 0)
	if !strings.Contains(buf.String(), "record tail skipped") {
		t.Errorf("expected the tail-skipped note:\n%s", buf.String())
	}
}

// ───────────────────────── doctor pure helpers ─────────────────────────────

// TestRedactString_NonStringAndEmpty covers the non-string and empty branches.
func TestRedactString_NonStringAndEmpty(t *testing.T) {
	if got := redactString(42); got != "<redacted non-string>" {
		t.Errorf("non-string: got %q", got)
	}
	if got := redactString(""); got != "" {
		t.Errorf("empty: got %q, want empty", got)
	}
	if got := redactString("abc"); got != "<redacted len=3>" {
		t.Errorf("present: got %q", got)
	}
}

// TestTailAuditLines_RingEvictsOldest exercises the ring-buffer eviction branch
// (more lines than n) which the existing tests' small inputs do not all hit.
func TestTailAuditLines_RingEvictsOldest(t *testing.T) {
	got, err := tailAuditLines(strings.NewReader("1\n2\n3\n4\n5\n6\n"), 2)
	if err != nil {
		t.Fatalf("tailAuditLines: %v", err)
	}
	if !equalStringSlice(got, []string{"5", "6"}) {
		t.Errorf("got %v, want [5 6]", got)
	}
}

// TestIndentWriter_NoTrailingNewline covers the mid-line Write branch where the
// chunk has no newline, so the function returns from the nl<0 path.
func TestIndentWriter_NoTrailingNewline(t *testing.T) {
	var buf bytes.Buffer
	iw := &indentWriter{w: &buf, prefix: []byte("> "), atLineStart: true}
	if _, err := iw.Write([]byte("partial")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := iw.Write([]byte(" line\nnext\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "> partial line") {
		t.Errorf("first logical line should be indented once:\n%q", out)
	}
	if !strings.Contains(out, "> next") {
		t.Errorf("second line should be indented:\n%q", out)
	}
}

// ───────────────────────── suggest / init pure helpers ─────────────────────

// TestActionForNamespace covers every namespace branch.
func TestActionForNamespace(t *testing.T) {
	cases := map[string]string{
		"resource": "read",
		"prompt":   "get",
		"system":   "allow",
		"tool":     "call",
		"unknown":  "call", // default branch
	}
	for ns, want := range cases {
		if got := actionForNamespace(ns); got != want {
			t.Errorf("actionForNamespace(%q) = %q, want %q", ns, got, want)
		}
	}
}

// TestCommonPrefixGlob_EdgeCases covers the <2-values short-circuit and the
// no-shared-directory branch in addition to a successful prefix.
func TestCommonPrefixGlob_EdgeCases(t *testing.T) {
	if got := commonPrefixGlob([]string{"only"}); got != "" {
		t.Errorf("single value: want empty, got %q", got)
	}
	if got := commonPrefixGlob([]string{"alpha", "beta"}); got != "" {
		t.Errorf("no shared dir prefix: want empty, got %q", got)
	}
	if got := commonPrefixGlob([]string{"/srv/a.txt", "/srv/b.txt"}); got != "/srv/*" {
		t.Errorf("shared dir prefix: want /srv/*, got %q", got)
	}
}

// ───────────────────────── runValidateLive (FM5 next-steps) ────────────────

// TestRunValidateLive_FM5DescriptionHashMismatch covers the FM-5 rendering and
// the FM-5 "Next steps" branch in runValidateLive: a manifest pins a tool's
// description hash, but the live description differs.
func TestRunValidateLive_FM5DescriptionHashMismatch(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{
			Target:          "tool:read_file",
			Actions:         []string{"call"},
			DescriptionHash: capability.ComputeToolHash("the ORIGINAL vetted description", nil),
		},
	)
	tools := []drift.UpstreamTool{
		{Name: "read_file", Description: "a DIFFERENT, possibly poisoned description"},
	}

	var buf bytes.Buffer
	code := runValidateLive(manifest, tools, "", &buf)
	if code != 1 {
		t.Errorf("exit code: want 1 (FM-5), got %d", code)
	}
	out := buf.String()
	if !strings.Contains(out, "description hash mismatch") {
		t.Errorf("expected the FM-5 warning line:\n%s", out)
	}
	if !strings.Contains(out, "Description hash mismatch:") {
		t.Errorf("expected the FM-5 next-steps guidance:\n%s", out)
	}
	if !strings.Contains(out, "1 description hash mismatch") {
		t.Errorf("expected the singular FM-5 result summary:\n%s", out)
	}
}

// ───────────────────────── fetchLiveTools (error paths) ─────────────────────

// initOKHandler returns an http.Handler that answers initialize successfully
// (session header + InitResult) and notifications/initialized with 202 — the
// only two methods fetchLiveTools sends before tools/list — delegating
// tools/list to toolsList so callers can drive fetchLiveTools' post-handshake
// error branches without repeating the handshake boilerplate.
func initOKHandler(t *testing.T, toolsList func(w http.ResponseWriter, msg mcp.RPCMsg)) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg mcp.RPCMsg
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		switch msg.Method {
		case "initialize":
			w.Header().Set(transport.SessionHeader, "sess-1")
			w.Header().Set("Content-Type", transport.CTJSON)
			result := mcp.InitResult{
				ProtocolVersion: transport.MCPProtocolVersion,
				Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
				ServerInfo:      map[string]interface{}{"name": "x", "version": "1.0.0"},
			}
			resp, _ := mcp.SuccessResponse(msg.ID, result)
			_ = json.NewEncoder(w).Encode(resp)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			toolsList(w, msg)
		}
	})
}

// TestFetchLiveTools_ToolsListRPCError covers the tools/list server-error branch
// in fetchLiveTools: initialize and the notification succeed, but tools/list
// returns a JSON-RPC error.
func TestFetchLiveTools_ToolsListRPCError(t *testing.T) {
	srv := httptest.NewServer(initOKHandler(t, func(w http.ResponseWriter, msg mcp.RPCMsg) {
		w.Header().Set("Content-Type", transport.CTJSON)
		resp := mcp.RPCMsg{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Error:   &mcp.RPCError{Code: -32000, Message: "tools unavailable"},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)

	_, err := fetchLiveTools(context.Background(), srv.URL, "", false)
	if err == nil {
		t.Fatal("expected an error from the tools/list RPC error, got nil")
	}
	if !strings.Contains(err.Error(), "tools/list") {
		t.Errorf("error should surface tools/list; got %v", err)
	}
}

// ───────────────────────── readResponseWithID (ctx canceled) ───────────────

// TestReadResponseWithID_ContextCanceled covers the ctx.Err() guard at the top
// of the read loop: a pre-canceled context returns immediately without reading.
func TestReadResponseWithID_ContextCanceled(t *testing.T) {
	srv := newStdioMockServer(func(r *mcp.MsgReader, _ *mcp.MsgWriter) {
		// Drain so the writer side never blocks; never reply.
		for {
			if _, err := r.Read(); err != nil {
				return
			}
		}
	})
	t.Cleanup(srv.close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := readResponseWithID(ctx, srv.clientW, srv.clientR, `"_init"`)
	if err == nil {
		t.Fatal("expected a context error, got nil")
	}
}

// TestReadResponseWithID_StreamEOF covers the non-context read-error branch: the
// server closes its side before responding, so the reader sees EOF while the
// context is still live.
func TestReadResponseWithID_StreamEOF(t *testing.T) {
	// readResponseWithID only reads; drive it with a pipe whose write end is
	// closed so the pending Read returns EOF (no context cancellation involved).
	pr, pw := io.Pipe()
	_ = pw.Close()
	r := mcp.NewMsgReader(pr)
	w := mcp.NewMsgWriter(io.Discard)

	_, err := readResponseWithID(context.Background(), w, r, `"_init"`)
	if err == nil {
		t.Fatal("expected an EOF read error, got nil")
	}
}

// ───────────────────────── fetchLiveTools (more error paths) ────────────────

// TestFetchLiveTools_NotificationPostFails covers the notifications/initialized
// error branch: the server accepts initialize but rejects the notification POST
// with a 500.
func TestFetchLiveTools_NotificationPostFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg mcp.RPCMsg
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		switch msg.Method {
		case "initialize":
			w.Header().Set(transport.SessionHeader, "sess-1")
			w.Header().Set("Content-Type", transport.CTJSON)
			result := mcp.InitResult{
				ProtocolVersion: transport.MCPProtocolVersion,
				Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
				ServerInfo:      map[string]interface{}{"name": "x", "version": "1.0.0"},
			}
			resp, _ := mcp.SuccessResponse(msg.ID, result)
			_ = json.NewEncoder(w).Encode(resp)
		case "notifications/initialized":
			http.Error(w, "boom", http.StatusInternalServerError)
		default:
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)

	_, err := fetchLiveTools(context.Background(), srv.URL, "", false)
	if err == nil {
		t.Fatal("expected an error from the failed notification POST, got nil")
	}
	if !strings.Contains(err.Error(), "notifications/initialized") {
		t.Errorf("error should surface notifications/initialized; got %v", err)
	}
}

// TestFetchLiveTools_MalformedToolsResult covers the ParseToolsListResult error
// branch: tools/list returns 200 with a result whose "tools" field is not an
// array.
func TestFetchLiveTools_MalformedToolsResult(t *testing.T) {
	srv := httptest.NewServer(initOKHandler(t, func(w http.ResponseWriter, msg mcp.RPCMsg) {
		w.Header().Set("Content-Type", transport.CTJSON)
		resp := mcp.RPCMsg{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Result:  json.RawMessage(`{"tools": "not-an-array"}`),
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)

	_, err := fetchLiveTools(context.Background(), srv.URL, "", false)
	if err == nil {
		t.Fatal("expected a parse error from a malformed tools/list result, got nil")
	}
}

// ───────────────────────── runStdioHandshake (more error paths) ─────────────

// TestRunStdioHandshake_InitWriteError covers the initialize-write failure: the
// writer wraps an already-closed pipe so the very first Write errors.
func TestRunStdioHandshake_InitWriteError(t *testing.T) {
	pr, pw := newClosedPipe(t)
	w := mcp.NewMsgWriter(pw)
	r := mcp.NewMsgReader(pr)

	_, err := runStdioHandshake(context.Background(), w, r)
	if err == nil {
		t.Fatal("expected an initialize write error against a closed pipe, got nil")
	}
	if !strings.Contains(err.Error(), "initialize") {
		t.Errorf("error should surface the initialize write failure; got %v", err)
	}
}

// TestRunStdioHandshake_ToolsListWriteError covers the tools/list write-error
// branch: initialize succeeds, then the server closes the client→server
// direction so the subsequent tools/list write fails.
func TestRunStdioHandshake_ToolsListWriteError(t *testing.T) {
	var srv *stdioMockServer
	srv = newStdioMockServer(func(r *mcp.MsgReader, w *mcp.MsgWriter) {
		// initialize ok
		msg, err := r.Read()
		if err != nil {
			return
		}
		initResult, _ := json.Marshal(mcp.InitResult{
			ProtocolVersion: transport.MCPProtocolVersion,
			Capabilities:    map[string]interface{}{},
			ServerInfo:      map[string]interface{}{"version": "0.0.1"},
		})
		_ = w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: initResult})
		// drain notifications/initialized, then close the client→server reader so
		// the next client write (tools/list) errors.
		_, _ = r.Read()
		_ = srv.cToS_w.Close()
	})

	_, err := runStdioHandshake(context.Background(), srv.clientW, srv.clientR)
	srv.close()
	if err == nil {
		t.Fatal("expected a tools/list write error after the reader side closed, got nil")
	}
}

// ───────────────────────── cmdInit stdio dispatch ──────────────────────────

// TestCmdInit_StdioToStdout drives cmdInit over the stdio transport against the
// re-exec helper upstream, returning to stdout (no --output) so the function
// returns normally and the stdio dispatch branch is exercised.
func TestCmdInit_StdioToStdout(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the test binary as a stdio upstream; skipped in -short")
	}
	orig := liveUpstreamTimeout
	liveUpstreamTimeout = 10 * time.Second
	t.Cleanup(func() { liveUpstreamTimeout = orig })

	cmd, args := helperUpstreamArgs()
	argv := append([]string{"eunox", "init", "--transport", "stdio", "--", cmd}, args...)
	withArgs(argv, func() {
		cmdInit()
	})
}

// ───────────────────────── runValidateLive (plural summaries) ───────────────

// TestRunValidateLive_PluralFM5AndFM3 covers the plural-count summary branches
// for FM-5 (>1 description hash mismatch) and FM-3 (>1 argument drift), which the
// single-finding tests do not reach.
func TestRunValidateLive_PluralFM5AndFM3(t *testing.T) {
	manifest := manifestWith(
		// Two pinned tools whose descriptions will mismatch → 2× FM-5.
		capability.Constraint{
			Target:          "tool:read_file",
			Actions:         []string{"call"},
			DescriptionHash: capability.ComputeToolHash("orig read", nil),
		},
		capability.Constraint{
			Target:          "tool:write_file",
			Actions:         []string{"call"},
			DescriptionHash: capability.ComputeToolHash("orig write", nil),
		},
		// Two tools with a condition argument absent from the live schema → 2× FM-3.
		capability.Constraint{
			Target:  "tool:search",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				capability.AllowedValuesCondition{Argument: "ghost", Values: []interface{}{"x"}},
			},
		},
		capability.Constraint{
			Target:  "tool:lookup",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				capability.AllowedValuesCondition{Argument: "phantom", Values: []interface{}{"y"}},
			},
		},
	)
	// A non-empty live schema whose single property is NOT the pinned argument, so
	// the FM-3 "argument not in live inputSchema" check fires for both tools.
	otherPropSchema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"other": map[string]interface{}{"type": "string"},
		},
	}
	tools := []drift.UpstreamTool{
		{Name: "read_file", Description: "CHANGED read"},
		{Name: "write_file", Description: "CHANGED write"},
		{Name: "search", InputSchema: otherPropSchema},
		{Name: "lookup", InputSchema: otherPropSchema},
	}

	var buf bytes.Buffer
	code := runValidateLive(manifest, tools, "", &buf)
	if code != 1 {
		t.Errorf("exit code: want 1, got %d\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "description hash mismatches") {
		t.Errorf("expected the plural FM-5 summary:\n%s", out)
	}
	if !strings.Contains(out, "argument drift warnings") {
		t.Errorf("expected the plural FM-3 summary:\n%s", out)
	}
}

// ───────────────────────── cmdDoctor (--output auto) ───────────────────────

// TestCmdDoctor_OutputAuto drives cmdDoctor with --output auto, covering the
// auto-name branch and the file-open success path. t.Chdir keeps the timestamped
// file inside a temp directory.
func TestCmdDoctor_OutputAuto(t *testing.T) {
	t.Chdir(t.TempDir())
	withArgs([]string{
		"eunox", "doctor",
		"--output", "auto",
		"--audit-log", filepath.Join(t.TempDir(), "absent.jsonl"),
		"--audit-tail", "0",
	}, func() {
		cmdDoctor()
	})
	matches, _ := filepath.Glob("eunox-doctor-*.txt")
	if len(matches) != 1 {
		t.Fatalf("expected exactly one auto-named bundle file, got %v", matches)
	}
	got := doctorReadFile(t, matches[0])
	if !strings.Contains(got, "eunox doctor — support bundle") {
		t.Errorf("auto bundle missing header:\n%s", got)
	}
}

// TestWriteDoctorBundle_LiveAgainstHelperUpstream drives the full bundle with
// --live and --config against the re-exec helper upstream, covering the
// writeDoctorLive bundle branch (section 5 default case).
func TestWriteDoctorBundle_LiveAgainstHelperUpstream(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the test binary as a stdio upstream; skipped in -short")
	}
	orig := liveUpstreamTimeout
	liveUpstreamTimeout = 10 * time.Second
	t.Cleanup(func() { liveUpstreamTimeout = orig })

	dir := t.TempDir()
	manifestPath := mustWriteFile(t, dir, "policy.yaml", cleanManifestYAML)
	cfgPath := mustWriteFile(t, dir, "eunox.yaml", `schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: integ
    transport: stdio
    command: `+os.Args[0]+`
    args: `+helperUpstreamYAMLArgs()+`
    policy: [`+manifestPath+`]
`)

	var buf bytes.Buffer
	writeDoctorBundle(&buf, withLoadedConfig(doctorOptions{
		configPath:   cfgPath,
		auditLogPath: filepath.Join(dir, "absent.jsonl"),
		auditTail:    0,
		live:         true,
	}))
	out := buf.String()
	if !strings.Contains(out, "validate exit code:") {
		t.Errorf("expected the live section to render a validate exit code:\n%s", out)
	}
}

// ───────────────────────── tools/list pagination ───────────────────────────

// pagingToolsHandler returns an http.Handler that answers initialize +
// notifications/initialized and pages tools/list: the first call (no cursor)
// returns one tool plus a nextCursor; the second call (with the cursor) returns
// a second tool and no cursor. This exercises the "if cursor != \"\"" branch.
func pagingToolsHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg mcp.RPCMsg
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", transport.CTJSON)
		switch msg.Method {
		case "initialize":
			w.Header().Set(transport.SessionHeader, "sess-1")
			result := mcp.InitResult{
				ProtocolVersion: transport.MCPProtocolVersion,
				Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
				ServerInfo:      map[string]interface{}{"name": "x", "version": "1.0.0"},
			}
			resp, _ := mcp.SuccessResponse(msg.ID, result)
			_ = json.NewEncoder(w).Encode(resp)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			var params struct {
				Cursor string `json:"cursor"`
			}
			_ = json.Unmarshal(msg.Params, &params)
			var raw json.RawMessage
			if params.Cursor == "" {
				raw = json.RawMessage(`{"tools":[{"name":"page1_tool"}],"nextCursor":"c1"}`)
			} else {
				raw = json.RawMessage(`{"tools":[{"name":"page2_tool"}]}`)
			}
			resp := mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: raw}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			resp, _ := mcp.SuccessResponse(msg.ID, map[string]interface{}{})
			_ = json.NewEncoder(w).Encode(resp)
		}
	})
}

// TestFetchLiveTools_PaginatesToExhaustion covers the cursor branch in
// fetchLiveTools by paging through a two-page tools/list.
func TestFetchLiveTools_PaginatesToExhaustion(t *testing.T) {
	srv := httptest.NewServer(http.StripPrefix("/mcp", pagingToolsHandler(t)))
	t.Cleanup(srv.Close)

	info, err := fetchLiveTools(context.Background(), srv.URL, "", false)
	if err != nil {
		t.Fatalf("fetchLiveTools: %v", err)
	}
	if len(info.Tools) != 2 {
		t.Fatalf("expected 2 paged tools, got %d (%v)", len(info.Tools), info.Tools)
	}
}

// TestRunStdioHandshake_PaginatesToExhaustion covers the cursor branch in
// runStdioHandshake (the stdio peer of the HTTP pagination).
func TestRunStdioHandshake_PaginatesToExhaustion(t *testing.T) {
	srv := newStdioMockServer(func(r *mcp.MsgReader, w *mcp.MsgWriter) {
		// initialize
		msg, err := r.Read()
		if err != nil {
			return
		}
		initResult, _ := json.Marshal(mcp.InitResult{
			ProtocolVersion: transport.MCPProtocolVersion,
			Capabilities:    map[string]interface{}{},
			ServerInfo:      map[string]interface{}{"version": "1.0.0"},
		})
		_ = w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: initResult})
		// notifications/initialized
		if _, err := r.Read(); err != nil {
			return
		}
		// tools/list page 1
		p1, err := r.Read()
		if err != nil {
			return
		}
		_ = w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: p1.ID,
			Result: json.RawMessage(`{"tools":[{"name":"page1"}],"nextCursor":"c1"}`)})
		// tools/list page 2 (carries the cursor)
		p2, err := r.Read()
		if err != nil {
			return
		}
		_ = w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: p2.ID,
			Result: json.RawMessage(`{"tools":[{"name":"page2"}]}`)})
	})

	info, err := runStdioHandshake(context.Background(), srv.clientW, srv.clientR)
	srv.close()
	if err != nil {
		t.Fatalf("runStdioHandshake: %v", err)
	}
	if len(info.Tools) != 2 {
		t.Fatalf("expected 2 paged tools, got %d", len(info.Tools))
	}
}

// ───────────────────────── validateConfigRoutes (empty version) ────────────

// TestValidateConfigRoutes_LiveEmptyServerVersion covers the
// versionLabel=="unknown" branch: the upstream reports no server version.
func TestValidateConfigRoutes_LiveEmptyServerVersion(t *testing.T) {
	orig := liveUpstreamTimeout
	liveUpstreamTimeout = 5 * time.Second
	t.Cleanup(func() { liveUpstreamTimeout = orig })

	// An upstream whose initialize serverInfo omits "version".
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg mcp.RPCMsg
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", transport.CTJSON)
		switch msg.Method {
		case "initialize":
			w.Header().Set(transport.SessionHeader, "sess-1")
			result := mcp.InitResult{
				ProtocolVersion: transport.MCPProtocolVersion,
				Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
				ServerInfo:      map[string]interface{}{"name": "noversion"},
			}
			resp, _ := mcp.SuccessResponse(msg.ID, result)
			_ = json.NewEncoder(w).Encode(resp)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			resp := mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: json.RawMessage(`{"tools":[{"name":"read_file"}]}`)}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			resp, _ := mcp.SuccessResponse(msg.ID, map[string]interface{}{})
			_ = json.NewEncoder(w).Encode(resp)
		}
	})
	srv := httptest.NewServer(http.StripPrefix("/mcp", handler))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	manifestPath := mustWriteFile(t, dir, "policy.yaml", `
schemaVersion: "0.1"
name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: ["call"]
`)
	cfg := newConfigForRoute(config.UpstreamConfig{
		Name:        "r1",
		Transport:   config.HostTransportHTTP,
		UpstreamURL: srv.URL,
		Policy:      []string{manifestPath},
	})

	var buf bytes.Buffer
	code := validateConfigRoutes(context.Background(), cfg, true, &buf)
	if code != 0 {
		t.Errorf("clean manifest should exit 0; got %d\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "server version: unknown") {
		t.Errorf("expected 'server version: unknown' for a versionless upstream:\n%s", buf.String())
	}
}

// ───────────────────────── computeAuditStats (unknown decision) ─────────────

// TestComputeAuditStats_UnknownDecisionGoesToOther covers the default branch in
// the decision switch (a record whose decision is neither allow nor deny lands
// in the "other" bucket).
func TestComputeAuditStats_UnknownDecisionGoesToOther(t *testing.T) {
	content := `{"decision":"allow","target_type":"tool","target":"a","method":"tools/call"}` + "\n" +
		`{"decision":"sideways","target_type":"tool","target":"b","method":"tools/call"}` + "\n"
	summary, err := computeAuditStats(strings.NewReader(content))
	if err != nil {
		t.Fatalf("computeAuditStats: %v", err)
	}
	if summary.other != 1 {
		t.Errorf("unknown decision should bump other; got other=%d", summary.other)
	}
	if summary.allowed != 1 {
		t.Errorf("allowed should be 1; got %d", summary.allowed)
	}
}

// ───────────────────────── suggest helpers (more branches) ──────────────────

// TestComputeSuggestions_SkipsUnknownTarget covers the bare=="" skip: a record
// whose target_type is not a known namespace and whose method is empty resolves
// to no target and is skipped.
func TestComputeSuggestions_SkipsUnknownTarget(t *testing.T) {
	rec := map[string]interface{}{
		"decision":    "allow",
		"target_type": "mystery", // not a known namespace
		"target":      "whatever",
		"method":      "", // empty so the infra-denial skip does not apply
	}
	b, _ := json.Marshal(rec)
	s, err := computeSuggestions(strings.NewReader(string(b)+"\n"), suggestMaxValuesDefault)
	if err != nil {
		t.Fatalf("computeSuggestions: %v", err)
	}
	if len(s.targets) != 0 {
		t.Errorf("unknown-namespace record should yield no targets; got %d", len(s.targets))
	}
}

// TestRenderSuggestedManifest_MaxValuesDefaultAndDenyOnlySort covers the
// maxValues<=0 normalization and the deny-only sort path (more than one
// deny-only target so sort.Slice does real work).
func TestRenderSuggestedManifest_MaxValuesDefaultAndDenyOnlySort(t *testing.T) {
	s := suggestionSet{
		targets: map[string]*observedTarget{
			"tool:zeta":  {namespace: "tool", name: "zeta", deny: 2, args: map[string]*observedArg{}},
			"tool:alpha": {namespace: "tool", name: "alpha", deny: 1, args: map[string]*observedArg{}},
		},
		records: 3,
		deny:    3,
	}
	out := renderSuggestedManifest(s, "draft", 0 /* maxValues<=0 → default */)
	if !strings.Contains(out, "Seen only as denials") {
		t.Errorf("expected the deny-only section:\n%s", out)
	}
	// Deny-only entries are sorted by name, so alpha precedes zeta.
	ai := strings.Index(out, "tool:alpha")
	zi := strings.Index(out, "tool:zeta")
	if ai < 0 || zi < 0 || ai > zi {
		t.Errorf("deny-only targets should be sorted alpha before zeta:\n%s", out)
	}
}

// TestWriteTargetEntry_NonStringOnlyArgument covers the
// "a.nonString && len(vals)==0" review-note branch: a tool argument observed
// only with a non-string value.
func TestWriteTargetEntry_NonStringOnlyArgument(t *testing.T) {
	content := auditAllowToolLine(t, "set_limit", map[string]interface{}{"max": 42})
	s, err := computeSuggestions(strings.NewReader(content), 20)
	if err != nil {
		t.Fatalf("computeSuggestions: %v", err)
	}
	out := renderSuggestedManifest(s, "draft", 20)
	if !strings.Contains(out, "non-string values observed") {
		t.Errorf("expected the non-string review note for the 'max' argument:\n%s", out)
	}
}

// ───────────────────────── writeDoctorAudit (other>0) ──────────────────────

// TestWriteDoctorAudit_OtherBucketRendered covers the "summary.other > 0" branch
// of the audit totals line: a record with an unrecognized decision lands in the
// other bucket and the totals line appends "other=N".
func TestWriteDoctorAudit_OtherBucketRendered(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	// One allow record and one with an unknown decision (other), plus a bogus key
	// path that resolves but does not exist (covered by the absent branch above).
	doctorWriteFile(t, logPath,
		`{"decision":"allow","target_type":"tool","target":"a","method":"tools/call"}`+"\n"+
			`{"decision":"weird","target_type":"tool","target":"b","method":"tools/call"}`+"\n")

	var buf bytes.Buffer
	writeDoctorAudit(&buf, logPath, filepath.Join(dir, "k.key"), 0)
	if !strings.Contains(buf.String(), "other=1") {
		t.Errorf("expected other=1 in the totals line:\n%s", buf.String())
	}
}

// ───────────────────────── indentWriter (error propagation) ────────────────

// errWriter fails every Write after the first `okWrites` succeed, returning a
// short count and a sentinel error so indentWriter's error branches are hit.
type errWriter struct {
	okWrites int
	n        int
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.n >= e.okWrites {
		return 0, io.ErrShortWrite
	}
	e.n++
	return len(p), nil
}

// TestIndentWriter_PrefixWriteError covers the prefix-write error branch: writing
// the indent prefix fails on the first Write.
func TestIndentWriter_PrefixWriteError(t *testing.T) {
	iw := &indentWriter{w: &errWriter{okWrites: 0}, prefix: []byte("  "), atLineStart: true}
	if _, err := iw.Write([]byte("hello\n")); err == nil {
		t.Fatal("expected the prefix-write error to propagate, got nil")
	}
}

// TestIndentWriter_BodyWriteError covers the line-body write error branch: the
// prefix write succeeds, the body write fails.
func TestIndentWriter_BodyWriteError(t *testing.T) {
	iw := &indentWriter{w: &errWriter{okWrites: 1}, prefix: []byte("  "), atLineStart: true}
	if _, err := iw.Write([]byte("hello\nworld\n")); err == nil {
		t.Fatal("expected the body-write error to propagate, got nil")
	}
}

// ───────────────────────── writeDenialTable (tie-break tail) ────────────────

// TestWriteDenialTable_TieBreakByCode covers the final comparator branch
// (rows[i].code < rows[j].code): two rows with equal count AND equal tool but
// different codes force the code-level tiebreak.
func TestWriteDenialTable_TieBreakByCode(t *testing.T) {
	denials := map[denialKey]int{
		{tool: "write_file", code: "B_CODE"}: 3,
		{tool: "write_file", code: "A_CODE"}: 3,
	}
	var buf bytes.Buffer
	writeDenialTable(&buf, denials)
	out := buf.String()
	ai := strings.Index(out, "A_CODE")
	bi := strings.Index(out, "B_CODE")
	if ai < 0 || bi < 0 || ai > bi {
		t.Errorf("equal-count equal-tool rows should tiebreak by code (A before B):\n%s", out)
	}
}

// ───────────────────────── fetchLiveTools (tools/list HTTP error) ───────────

// TestFetchLiveTools_ToolsListHTTPError covers the tools/list transport-error
// branch: initialize + the notification succeed, but the tools/list POST returns
// HTTP 500 (a transport-level error, distinct from a JSON-RPC error result).
func TestFetchLiveTools_ToolsListHTTPError(t *testing.T) {
	srv := httptest.NewServer(initOKHandler(t, func(w http.ResponseWriter, _ mcp.RPCMsg) {
		http.Error(w, "kaboom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	_, err := fetchLiveTools(context.Background(), srv.URL, "", false)
	if err == nil {
		t.Fatal("expected a transport error from the tools/list HTTP 500, got nil")
	}
	if !strings.Contains(err.Error(), "tools/list") {
		t.Errorf("error should surface tools/list; got %v", err)
	}
}

// ───────────────────────── runStdioHandshake (tools/list RPC error read) ────

// TestRunStdioHandshake_ToolsListServerErrorAfterRead covers the path where the
// tools/list write succeeds, the response is read, and it carries a JSON-RPC
// error (the read-then-error branch rather than the write-error branch).
func TestRunStdioHandshake_ToolsListServerErrorAfterRead(t *testing.T) {
	srv := newStdioMockServer(func(r *mcp.MsgReader, w *mcp.MsgWriter) {
		msg, err := r.Read()
		if err != nil {
			return
		}
		initResult, _ := json.Marshal(mcp.InitResult{
			ProtocolVersion: transport.MCPProtocolVersion,
			Capabilities:    map[string]interface{}{},
			ServerInfo:      map[string]interface{}{"version": "1.0.0"},
		})
		_ = w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: initResult})
		if _, err := r.Read(); err != nil { // notifications/initialized
			return
		}
		listMsg, err := r.Read()
		if err != nil {
			return
		}
		_ = w.Write(mcp.RPCMsg{
			JSONRPC: "2.0",
			ID:      listMsg.ID,
			Error:   &mcp.RPCError{Code: -32000, Message: "tools temporarily unavailable"},
		})
	})

	_, err := runStdioHandshake(context.Background(), srv.clientW, srv.clientR)
	srv.close()
	if err == nil {
		t.Fatal("expected an error from the tools/list JSON-RPC error, got nil")
	}
	if !strings.Contains(err.Error(), "tools/list") {
		t.Errorf("error should surface tools/list; got %v", err)
	}
}

// ───────────────────────── runStdioHandshake (malformed tools result) ───────

// TestRunStdioHandshake_MalformedToolsResult covers the ParseToolsListResult
// error branch in the stdio path: tools/list returns a result whose "tools"
// field is not an array.
func TestRunStdioHandshake_MalformedToolsResult(t *testing.T) {
	srv := newStdioMockServer(func(r *mcp.MsgReader, w *mcp.MsgWriter) {
		msg, err := r.Read()
		if err != nil {
			return
		}
		initResult, _ := json.Marshal(mcp.InitResult{
			ProtocolVersion: transport.MCPProtocolVersion,
			Capabilities:    map[string]interface{}{},
			ServerInfo:      map[string]interface{}{"version": "1.0.0"},
		})
		_ = w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: initResult})
		if _, err := r.Read(); err != nil {
			return
		}
		listMsg, err := r.Read()
		if err != nil {
			return
		}
		_ = w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: listMsg.ID,
			Result: json.RawMessage(`{"tools": 123}`)})
	})

	_, err := runStdioHandshake(context.Background(), srv.clientW, srv.clientR)
	srv.close()
	if err == nil {
		t.Fatal("expected a parse error from a malformed stdio tools/list result, got nil")
	}
}

// ───────────────────────── run dispatch (suggest / doctor) ──────────────────

// TestRun_DispatchesSuggestAndDoctor covers the run() dispatch cases for the
// subcommands that return without os.Exit on success. run reads args[1] but the
// subcommands read os.Args, so both must be set in lockstep via withArgs.
func TestRun_DispatchesSuggestAndDoctor(t *testing.T) {
	logPath := writeTempFile(t, auditAllowToolLine(t, "read_file", map[string]interface{}{"path": "/x"}))
	suggestArgs := []string{"eunox", "suggest", "--audit-log", logPath}
	withArgs(suggestArgs, func() {
		if code := run(suggestArgs); code != 0 {
			t.Errorf("run suggest: exit %d, want 0", code)
		}
	})

	t.Chdir(t.TempDir())
	doctorArgs := []string{"eunox", "doctor", "--audit-tail", "0", "--audit-log", filepath.Join(t.TempDir(), "absent.jsonl")}
	withArgs(doctorArgs, func() {
		if code := run(doctorArgs); code != 0 {
			t.Errorf("run doctor: exit %d, want 0", code)
		}
	})
}

// ───────────────────────── scanner errors (line too long) ──────────────────

// hugeLineReader yields a single line longer than the audit scan buffer (4 MiB)
// with no newline, forcing the bufio.Scanner used by computeAuditStats and
// computeSuggestions to return bufio.ErrTooLong from Err().
func hugeLineReader() io.Reader {
	const oversize = (4 << 20) + 16
	return strings.NewReader(strings.Repeat("a", oversize))
}

// TestComputeAuditStats_ScannerError covers the scanner.Err() return in
// computeAuditStats: a line exceeding the 4 MiB buffer surfaces as an error.
func TestComputeAuditStats_ScannerError(t *testing.T) {
	_, err := computeAuditStats(hugeLineReader())
	if err == nil {
		t.Fatal("expected a scanner error for an over-long line, got nil")
	}
}

// TestComputeSuggestions_ScannerError covers the scanner.Err() return in
// computeSuggestions for the same over-long-line condition.
func TestComputeSuggestions_ScannerError(t *testing.T) {
	_, err := computeSuggestions(hugeLineReader(), suggestMaxValuesDefault)
	if err == nil {
		t.Fatal("expected a scanner error for an over-long line, got nil")
	}
}

// ───────────────────────── runStdioHandshake (notif write error) ────────────

// TestRunStdioHandshake_NotificationWriteError covers the
// notifications/initialized write-error branch: the server answers initialize,
// then closes the client→server reader so the subsequent notification write
// fails before tools/list is ever attempted.
func TestRunStdioHandshake_NotificationWriteError(t *testing.T) {
	var srv *stdioMockServer
	srv = newStdioMockServer(func(r *mcp.MsgReader, w *mcp.MsgWriter) {
		msg, err := r.Read()
		if err != nil {
			return
		}
		initResult, _ := json.Marshal(mcp.InitResult{
			ProtocolVersion: transport.MCPProtocolVersion,
			Capabilities:    map[string]interface{}{},
			ServerInfo:      map[string]interface{}{"version": "1.0.0"},
		})
		_ = w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: initResult})
		// Close the client→server direction so the client's notification write fails.
		_ = srv.cToS_w.Close()
	})

	_, err := runStdioHandshake(context.Background(), srv.clientW, srv.clientR)
	srv.close()
	if err == nil {
		t.Fatal("expected a notifications/initialized write error, got nil")
	}
}

// ───────────────────────── printProxyUsage ──────────────────────────────────

func TestPrintProxyUsage(t *testing.T) {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.String("config", "", "config path")

	out := captureStderr(t, func() { printProxyUsage(fs) })
	if !strings.Contains(out, "Usage:") {
		t.Errorf("expected usage banner, got %q", out)
	}
	if !strings.Contains(out, "-config") {
		t.Errorf("expected flag defaults to be printed, got %q", out)
	}
}

// ───────────────────────── buildCallCounterAndKillSwitch ───────────────────

func TestBuildCallCounterAndKillSwitch_InMemory(t *testing.T) {
	counter, _, ks, ksRedis := buildCallCounterAndKillSwitch("", "", false, false, 0, 0)
	if counter == nil || ks == nil {
		t.Fatal("want non-nil in-memory counter and kill-switch")
	}
	if ksRedis != nil {
		t.Error("want nil Redis kill-switch when redisAddr is empty")
	}
}

// TestBuildCallCounterAndKillSwitch_Redis exercises the Redis success path —
// fail-open and a positive reconcile interval, so both warning branches run —
// without hitting the os.Exit(1) error branches (a real miniredis instance
// answers PING, so buildRedisClient/pingRedis succeed).
func TestBuildCallCounterAndKillSwitch_Redis(t *testing.T) {
	mr := miniredis.RunT(t)

	counter, _, ks, ksRedis := buildCallCounterAndKillSwitch(mr.Addr(), "", false, true, 5*time.Second, 0)
	if counter == nil || ks == nil {
		t.Fatal("want non-nil counter and kill-switch")
	}
	if ksRedis == nil {
		t.Fatal("want non-nil Redis kill-switch when redisAddr is set")
	}
}

// TestBuildCallCounterAndKillSwitch_RedisFailClosed covers the fail-closed
// (default) warning branch, distinct from the fail-open branch above.
func TestBuildCallCounterAndKillSwitch_RedisFailClosed(t *testing.T) {
	mr := miniredis.RunT(t)

	counter, _, ks, ksRedis := buildCallCounterAndKillSwitch(mr.Addr(), "", false, false, 0, 0)
	if counter == nil || ks == nil || ksRedis == nil {
		t.Fatal("want non-nil counter, kill-switch, and Redis kill-switch")
	}
}

// ───────────────────────── openConfiguredAuditSink ──────────────────────────

func TestOpenConfiguredAuditSink_ConfigOverridesFlags(t *testing.T) {
	dir := t.TempDir()
	cfgLogPath := filepath.Join(dir, "config-audit.jsonl")
	cfgKeyPath := filepath.Join(dir, "config-audit.key")

	cfg := &config.GatewayConfig{}
	cfg.Audit.Log = cfgLogPath
	cfg.Audit.KeyPath = cfgKeyPath
	cfg.Audit.RotateSizeBytes = 1 << 20
	retain := 3
	cfg.Audit.RetainRotated = &retain

	var sink *audit.Sink
	stderr := captureStderr(t, func() {
		sink = openConfiguredAuditSink("/flag-log.jsonl", "/flag-key", 1, 1, cfg, false)
	})
	if sink == nil {
		t.Fatal("expected a non-nil sink")
	}
	t.Cleanup(func() { _ = sink.Close() })

	if _, err := os.Stat(cfgLogPath); err != nil {
		t.Errorf("expected the config-supplied log path to be used: %v", err)
	}
	// Regression: an explicitly-set --audit-log/--audit-key-path silently
	// overridden by the config's audit block must warn, so an operator who passed
	// the flag expecting it to be honored has a signal for why it wasn't.
	if !strings.Contains(stderr, "/flag-log.jsonl") || !strings.Contains(stderr, cfgLogPath) {
		t.Errorf("expected a WARNING naming both the overridden --audit-log flag and the config's audit.log, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "/flag-key") || !strings.Contains(stderr, cfgKeyPath) {
		t.Errorf("expected a WARNING naming both the overridden --audit-key-path flag and the config's audit.keyPath, got:\n%s", stderr)
	}
}

// TestOpenConfiguredAuditSink_NoWarningWhenFlagUnset confirms the WARNING added
// above fires only when the flag was explicitly set to a DIFFERENT value than the
// config: the common case (no --audit-log flag, config supplies the path) must
// stay silent.
func TestOpenConfiguredAuditSink_NoWarningWhenFlagUnset(t *testing.T) {
	dir := t.TempDir()
	cfgLogPath := filepath.Join(dir, "config-audit.jsonl")
	cfg := &config.GatewayConfig{}
	cfg.Audit.Log = cfgLogPath

	var sink *audit.Sink
	stderr := captureStderr(t, func() {
		sink = openConfiguredAuditSink("", "", 0, 0, cfg, false)
	})
	if sink == nil {
		t.Fatal("expected a non-nil sink")
	}
	t.Cleanup(func() { _ = sink.Close() })
	if strings.Contains(stderr, "WARNING") {
		t.Errorf("no --audit-log flag was set; expected no override warning, got:\n%s", stderr)
	}
}

func TestOpenConfiguredAuditSink_Success(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink := openConfiguredAuditSink(logPath, keyPath, 0, 0, &config.GatewayConfig{}, true)
	if sink == nil {
		t.Fatal("expected a non-nil sink")
	}
	_ = sink.Close()
}

func TestOpenConfiguredAuditSink_NonFatalFailure(t *testing.T) {
	dir := t.TempDir()
	// A regular file occupying a path component MkdirAll must traverse as a
	// directory makes audit.Open's directory creation fail.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	logPath := filepath.Join(blocker, "subdir", "audit.jsonl")

	sink := openConfiguredAuditSink(logPath, "", 0, 0, &config.GatewayConfig{}, false)
	if sink != nil {
		t.Error("expected a nil sink on a non-fatal open failure")
		_ = sink.Close()
	}
}

// ───────────────────────── buildAuditWiretapConfig ──────────────────────────

func TestBuildAuditWiretapConfig_BothSourcesError(t *testing.T) {
	_, err := buildAuditWiretapConfig([]string{"echo"}, "http://example.com", "", false)
	if err == nil {
		t.Fatal("expected an error when both positional and --upstream-url are set")
	}
}

func TestBuildAuditWiretapConfig_NeitherSourceError(t *testing.T) {
	_, err := buildAuditWiretapConfig(nil, "", "", false)
	if err == nil {
		t.Fatal("expected an error when neither positional nor --upstream-url is set")
	}
}

func TestBuildAuditWiretapConfig_Positional(t *testing.T) {
	cfg, err := buildAuditWiretapConfig([]string{"echo", "hi"}, "", "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Upstreams[0].Command != "echo" || len(cfg.Upstreams[0].Args) != 1 {
		t.Errorf("want command echo with one arg, got %+v", cfg.Upstreams[0])
	}
}

func TestBuildAuditWiretapConfig_UpstreamURL(t *testing.T) {
	cfg, err := buildAuditWiretapConfig(nil, "http://example.com/mcp", "Authorization: Bearer x", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	u := cfg.Upstreams[0]
	if u.UpstreamURL != "http://example.com/mcp" || !u.UpstreamTLSSkipVerify {
		t.Errorf("want upstream url config, got %+v", u)
	}
}

// ───────────────────────── jwtExperimentalCapsWarning ───────────────────────

func TestJwtExperimentalCapsWarning_Enabled(t *testing.T) {
	got := jwtExperimentalCapsWarning(true)
	if !strings.Contains(got, "EXPERIMENTAL") {
		t.Errorf("want an EXPERIMENTAL warning, got %q", got)
	}
}

// ───────────────────────── validateJWKSURIScheme ────────────────────────────

func TestValidateJWKSURIScheme_InvalidURL(t *testing.T) {
	err := validateJWKSURIScheme("http://x%zz", false)
	if err == nil {
		t.Fatal("expected a URL parse error")
	}
}

// ───────────────────────── validateOAuthAuthzServerURI ──────────────────────

func TestValidateOAuthAuthzServerURI_EnvRef(t *testing.T) {
	err := validateOAuthURI("oauth authorization server", "${ISSUER}", false)
	if err == nil || !strings.Contains(err.Error(), "unexpanded") {
		t.Fatalf("want an unexpanded-env-ref error, got %v", err)
	}
}

func TestValidateOAuthAuthzServerURI_ControlChar(t *testing.T) {
	err := validateOAuthURI("oauth authorization server", "https://idp.example.com/\x01", false)
	if err == nil {
		t.Fatal("expected a control-character error")
	}
}

// ───────────────────────── newJWKSHTTPClient ────────────────────────────────

func TestNewJWKSHTTPClient_TooManyRedirects(t *testing.T) {
	client := newJWKSHTTPClient(true)
	via := make([]*http.Request, 10)
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", http.NoBody)
	for i := range via {
		via[i] = req
	}
	err := client.CheckRedirect(req, via)
	if err == nil || !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("want too-many-redirects error, got %v", err)
	}
}

// ───────────────────────── serveHTTPGateway ─────────────────────────────────

func auditUpstreamHTTPConfig(t *testing.T, srvURL string) *config.GatewayConfig {
	t.Helper()
	return &config.GatewayConfig{
		Transport: config.HostTransportHTTP,
		Defaults:  config.RouteDefaults{Enforcement: "audit"},
		Upstreams: []config.UpstreamConfig{{
			Name:        "u1",
			Transport:   config.HostTransportHTTP,
			UpstreamURL: srvURL,
		}},
	}
}

func TestServeHTTPGateway_BuildRoutesError(t *testing.T) {
	cfg := &config.GatewayConfig{
		Transport: config.HostTransportHTTP,
		Upstreams: []config.UpstreamConfig{{
			Name:      "u1",
			Transport: config.HostTransportStdio,
			Command:   "echo",
			// no Policy and enforcement is not audit -> BuildRoutes fails fail-closed.
		}},
	}
	err := serveHTTPGateway(context.Background(), cfg, nil, nil, nil, nil, proxyFlags{})
	if err == nil {
		t.Fatal("expected a BuildRoutes error for a policyless enforce-mode route")
	}
}

func TestServeHTTPGateway_BindAllRejected(t *testing.T) {
	fake := newFakeUpstreamWithTools([]mcp.ToolEntry{{Name: "t"}})
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	cfg := auditUpstreamHTTPConfig(t, srv.URL)
	cfg.Listen.Bind = "0.0.0.0"

	err := serveHTTPGateway(context.Background(), cfg, nil, nil, nil, nil, proxyFlags{})
	if err == nil || !strings.Contains(err.Error(), "--unsafe-bind-all") {
		t.Fatalf("want a bind-all-rejected error, got %v", err)
	}
}

func TestServeHTTPGateway_JWTAudienceError(t *testing.T) {
	fake := newFakeUpstreamWithTools([]mcp.ToolEntry{{Name: "t"}})
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	cfg := auditUpstreamHTTPConfig(t, srv.URL)
	pf := proxyFlags{jwksURI: "https://idp.example.com/jwks.json"}

	err := serveHTTPGateway(context.Background(), cfg, nil, nil, nil, nil, pf)
	if err == nil || !strings.Contains(err.Error(), "--jwt-audience") {
		t.Fatalf("want a jwt-audience error, got %v", err)
	}
}

func TestServeHTTPGateway_JWTIssuerError(t *testing.T) {
	fake := newFakeUpstreamWithTools([]mcp.ToolEntry{{Name: "t"}})
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	cfg := auditUpstreamHTTPConfig(t, srv.URL)
	pf := proxyFlags{
		jwksURI:     "https://idp.example.com/jwks.json",
		jwtAudience: "eunox",
	}

	err := serveHTTPGateway(context.Background(), cfg, nil, nil, nil, nil, pf)
	if err == nil || !strings.Contains(err.Error(), "--jwt-issuer") {
		t.Fatalf("want a jwt-issuer error, got %v", err)
	}
}

func TestServeHTTPGateway_JWKSSchemeError(t *testing.T) {
	fake := newFakeUpstreamWithTools([]mcp.ToolEntry{{Name: "t"}})
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	cfg := auditUpstreamHTTPConfig(t, srv.URL)
	pf := proxyFlags{
		jwksURI:     "ftp://idp.example.com/jwks.json",
		jwtAudience: "eunox",
		jwtIssuer:   "https://idp.example.com",
	}

	err := serveHTTPGateway(context.Background(), cfg, nil, nil, nil, nil, pf)
	if err == nil || !strings.Contains(err.Error(), "http or https") {
		t.Fatalf("want a JWKS scheme error, got %v", err)
	}
}

func TestServeHTTPGateway_AuthTokenJWTConflict(t *testing.T) {
	jwks := makeJWKSServer(t)
	fake := newFakeUpstreamWithTools([]mcp.ToolEntry{{Name: "t"}})
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	cfg := auditUpstreamHTTPConfig(t, srv.URL)
	cfg.Listen.AuthToken = "static-token"
	pf := proxyFlags{
		jwksURI:             jwks.URL,
		jwtAudience:         "eunox",
		jwtIssuer:           "https://idp.example.com",
		jwtExperimentalCaps: true,
	}

	err := serveHTTPGateway(context.Background(), cfg, nil, nil, nil, nil, pf)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("want an authToken/jwks-uri conflict error, got %v", err)
	}
}

func TestServeHTTPGateway_OAuthResourceError(t *testing.T) {
	fake := newFakeUpstreamWithTools([]mcp.ToolEntry{{Name: "t"}})
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	cfg := auditUpstreamHTTPConfig(t, srv.URL)
	pf := proxyFlags{oauthResource: "not-a-url"}

	err := serveHTTPGateway(context.Background(), cfg, nil, nil, nil, nil, pf)
	if err == nil || !strings.Contains(err.Error(), "--oauth-resource") {
		t.Fatalf("want an oauth-resource error, got %v", err)
	}
}

func TestServeHTTPGateway_OAuthResourceError_ConfigSourced(t *testing.T) {
	// A resource URI sourced from listen.oauthResource (not the --oauth-resource
	// flag) must be labeled with the config key it actually came from, not the flag
	// name the operator never passed.
	fake := newFakeUpstreamWithTools([]mcp.ToolEntry{{Name: "t"}})
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	cfg := auditUpstreamHTTPConfig(t, srv.URL)
	cfg.Listen.OAuthResource = "not-a-url"
	pf := proxyFlags{}

	err := serveHTTPGateway(context.Background(), cfg, nil, nil, nil, nil, pf)
	if err == nil || !strings.Contains(err.Error(), "listen.oauthResource") {
		t.Fatalf("want an error labeled listen.oauthResource, got %v", err)
	}
	if strings.Contains(err.Error(), "--oauth-resource") {
		t.Errorf("error should not reference the --oauth-resource flag the operator never passed: %v", err)
	}
}

func TestServeHTTPGateway_OAuthAuthzServerError(t *testing.T) {
	fake := newFakeUpstreamWithTools([]mcp.ToolEntry{{Name: "t"}})
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	cfg := auditUpstreamHTTPConfig(t, srv.URL)
	cfg.Listen.OAuthAuthorizationServers = []string{"${ISSUER}"}
	pf := proxyFlags{}

	err := serveHTTPGateway(context.Background(), cfg, nil, nil, nil, nil, pf)
	if err == nil || !strings.Contains(err.Error(), "unexpanded") {
		t.Fatalf("want an unexpanded-env-ref authz-server error, got %v", err)
	}
}

func TestServeHTTPGateway_ControlTokenWriteError(t *testing.T) {
	fake := newFakeUpstreamWithTools([]mcp.ToolEntry{{Name: "t"}})
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	// A file occupying what must be a directory component breaks MkdirAll.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	cfg := auditUpstreamHTTPConfig(t, srv.URL)
	pf := proxyFlags{controlTokenPath: filepath.Join(blocker, "subdir", "token")}

	err := serveHTTPGateway(context.Background(), cfg, nil, nil, nil, nil, pf)
	if err == nil || !strings.Contains(err.Error(), "kill control endpoint") {
		t.Fatalf("want a control-token write error, got %v", err)
	}
}

// TestServeHTTPGateway_FullSuccess drives serveHTTPGateway all the way to
// proxy.Serve: a JWT PDP, an OAuth resource, and an authz server are all
// configured (no listen.authToken, so no conflict), the proxy binds on an
// ephemeral loopback port, and the context is canceled to make Serve return.
func TestServeHTTPGateway_FullSuccess(t *testing.T) {
	jwks := makeJWKSServer(t)
	fake := newFakeUpstreamWithTools([]mcp.ToolEntry{{Name: "t"}})
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	cfg := auditUpstreamHTTPConfig(t, srv.URL)
	cfg.Listen.Bind = "127.0.0.1"
	cfg.Listen.Port = reserveLoopbackPort(t)
	cfg.Listen.OAuthResource = "https://proxy.example.com"

	pf := proxyFlags{
		jwksURI:             jwks.URL,
		jwtAudience:         "eunox",
		jwtIssuer:           "https://idp.example.com",
		jwtAllowAnyAudience: true,
		jwtAllowAnyIssuer:   true,
		jwtExperimentalCaps: true,
		oauthAuthzServer:    "https://idp.example.com",
		controlTokenPath:    filepath.Join(t.TempDir(), "control-token"),
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- serveHTTPGateway(ctx, cfg, nil, nil, nil, nil, pf) }()

	// Poll for the listener instead of a fixed sleep, so this doesn't flake
	// under a loaded CI runner: cancel() must not fire until Serve has bound,
	// or serveHTTPGateway returns a context-canceled error from net.Listen
	// rather than the clean shutdown this test is verifying.
	addr := net.JoinHostPort(cfg.Listen.Bind, strconv.Itoa(cfg.Listen.Port))
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway did not start listening on %s in time: %v", addr, dialErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("unexpected error from serveHTTPGateway: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveHTTPGateway did not return after context cancel")
	}
}

// ───────────────────────── serveStdioHost ───────────────────────────────────

func stdioHostConfig(u config.UpstreamConfig) *config.GatewayConfig {
	return singleUpstreamConfig(config.HostTransportStdio, config.RouteDefaults{Enforcement: "audit"}, u)
}

func TestServeStdioHost_JWKSURIRejected(t *testing.T) {
	cfg := stdioHostConfig(config.UpstreamConfig{Name: "u1"})
	err := serveStdioHost(context.Background(), cfg, nil, nil, nil, nil, proxyFlags{jwksURI: "https://idp.example.com/jwks.json"})
	if err == nil || !strings.Contains(err.Error(), "transport: http") {
		t.Fatalf("want a transport-http-required error, got %v", err)
	}
}

func TestServeStdioHost_OAuthResourceRejected(t *testing.T) {
	cfg := stdioHostConfig(config.UpstreamConfig{Name: "u1"})
	err := serveStdioHost(context.Background(), cfg, nil, nil, nil, nil, proxyFlags{oauthResource: "https://proxy.example.com"})
	if err == nil || !strings.Contains(err.Error(), "transport: http") {
		t.Fatalf("want a transport-http-required error, got %v", err)
	}
}

// TestServeStdioHost_HTTPOnlyFlagsRejected is a regression: before
// httpOnlyFlagsSetOnStdio existed, --control-token-path, --session-idle-timeout,
// --max-sessions, --unsafe-bind-all, and --trust-forwarded-for were silently
// accepted (and ignored) on a stdio host instead of being rejected like
// --jwks-uri/--oauth-resource/--oauth-authorization-server above.
func TestServeStdioHost_HTTPOnlyFlagsRejected(t *testing.T) {
	cases := []struct {
		name string
		pf   proxyFlags
	}{
		{"control-token-path", proxyFlags{httpOnlyFlagsSet: []string{"--control-token-path"}}},
		{"session-idle-timeout", proxyFlags{httpOnlyFlagsSet: []string{"--session-idle-timeout"}}},
		{"max-sessions", proxyFlags{httpOnlyFlagsSet: []string{"--max-sessions"}}},
		{"unsafe-bind-all", proxyFlags{httpOnlyFlagsSet: []string{"--unsafe-bind-all"}}},
		{"trust-forwarded-for", proxyFlags{httpOnlyFlagsSet: []string{"--trust-forwarded-for"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := stdioHostConfig(config.UpstreamConfig{Name: "u1"})
			err := serveStdioHost(context.Background(), cfg, nil, nil, nil, nil, tc.pf)
			if err == nil || !strings.Contains(err.Error(), "transport: http") {
				t.Fatalf("want a transport-http-required error, got %v", err)
			}
		})
	}
}

// TestHTTPOnlyFlagsSetOnStdio_DetectsEachFlag is the FlagSet-level regression:
// each httpOnlyProxyFlags entry must be detected as active when the operator
// actually passes it (including --max-sessions, whose non-zero default requires
// explicit-set detection rather than value detection), and none should fire on
// an untouched FlagSet.
func TestHTTPOnlyFlagsSetOnStdio_DetectsEachFlag(t *testing.T) {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	f := registerProxyFlags(fs)
	if err := fs.Parse([]string{
		"--control-token-path", "/tmp/token",
		"--session-idle-timeout", "1000",
		"--max-sessions", "5",
		"--unsafe-bind-all",
		"--trust-forwarded-for",
	}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	_ = f
	got := httpOnlyFlagsSetOnStdio(fs)
	want := []string{"--control-token-path", "--session-idle-timeout", "--max-sessions", "--unsafe-bind-all", "--trust-forwarded-for"}
	if len(got) != len(want) {
		t.Fatalf("httpOnlyFlagsSetOnStdio = %v, want %v", got, want)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
			}
		}
		if !found {
			t.Errorf("missing %q in %v", w, got)
		}
	}
}

func TestHTTPOnlyFlagsSetOnStdio_EmptyWhenUnset(t *testing.T) {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	registerProxyFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := httpOnlyFlagsSetOnStdio(fs); len(got) != 0 {
		t.Errorf("httpOnlyFlagsSetOnStdio with no flags set = %v, want empty", got)
	}
}

// TestServeHTTPGateway_SessionIDRejected is a regression: --session-id is a
// stdio-only concept (a gateway mints its own Mcp-Session-Id per client session),
// so it must be rejected on an http-transport config rather than silently
// ignored.
func TestServeHTTPGateway_SessionIDRejected(t *testing.T) {
	cfg := singleUpstreamConfig(config.HostTransportHTTP, config.RouteDefaults{Enforcement: "audit"}, config.UpstreamConfig{Name: "u1", UpstreamURL: "http://example.invalid"})
	err := serveHTTPGateway(context.Background(), cfg, nil, nil, nil, nil, proxyFlags{sessionIDSet: true})
	if err == nil || !strings.Contains(err.Error(), "transport: stdio") {
		t.Fatalf("want a transport-stdio-required error, got %v", err)
	}
}

func TestServeStdioHost_StrictDriftRequiresPolicy(t *testing.T) {
	strict := true
	cfg := stdioHostConfig(config.UpstreamConfig{Name: "u1", StrictDrift: &strict})
	err := serveStdioHost(context.Background(), cfg, nil, nil, nil, nil, proxyFlags{})
	if err == nil || !strings.Contains(err.Error(), "strictDrift requires a policy") {
		t.Fatalf("want a strictDrift-requires-policy error, got %v", err)
	}
}

func TestServeStdioHost_NoPolicyNotAuditRejected(t *testing.T) {
	cfg := &config.GatewayConfig{
		Transport: config.HostTransportStdio,
		Upstreams: []config.UpstreamConfig{{Name: "u1"}},
	}
	err := serveStdioHost(context.Background(), cfg, nil, nil, nil, nil, proxyFlags{})
	if err == nil || !strings.Contains(err.Error(), "no policy configured") {
		t.Fatalf("want a no-policy-configured error, got %v", err)
	}
}

// TestServeStdioHost_AuditModeStartsAndFailsFast drives serveStdioHost past
// every guard into transport.NewStdioProxy/proxy.Start: the upstream command
// does not exist, so Start returns a spawn error quickly instead of blocking.
func TestServeStdioHost_AuditModeStartsAndFailsFast(t *testing.T) {
	cfg := stdioHostConfig(config.UpstreamConfig{
		Name:      "u1",
		Transport: config.HostTransportStdio,
		Command:   "/no/such/eunox-test-binary-xyz",
	})
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	sink, err := audit.Open(logPath, keyPath, 0, 0, audit.WithIdentity(pdp.AuditIdentityFromContext))
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serveErr := serveStdioHost(ctx, cfg, sink, nil, nil, nil, proxyFlags{})
	if serveErr == nil {
		t.Fatal("expected a spawn error for a non-existent upstream command")
	}
}

// ───────────────────────── cmdValidate error branches ───────────────────────

func TestCmdValidate_NoFiles(t *testing.T) {
	var code int
	withArgs([]string{"eunox", "validate"}, func() { code = cmdValidate() })
	if code != 2 {
		t.Errorf("expected exit code 2 (usage: no manifest files), got %d", code)
	}
}

func TestCmdValidate_ConfigAndPositional(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "eunox.yaml")
	mfPath := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(cfgPath, []byte("transport: stdio\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	withArgs([]string{"eunox", "validate", "--config", cfgPath, mfPath}, func() { code = cmdValidate() })
	if code != 2 {
		t.Errorf("expected exit code 2 (usage: --config+positional conflict), got %d", code)
	}
}

func TestCmdValidate_ConfigAndUpstreamURL(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "eunox.yaml")
	if err := os.WriteFile(cfgPath, []byte("transport: stdio\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	withArgs([]string{"eunox", "validate", "--config", cfgPath, "--upstream-url", "http://x"}, func() {
		code = cmdValidate()
	})
	if code != 2 {
		t.Errorf("expected exit code 2 (usage: --config+--upstream-url conflict), got %d", code)
	}
}

func TestCmdValidate_ConfigLoadError(t *testing.T) {
	var code int
	withArgs([]string{"eunox", "validate", "--config", "/no/such/eunox.yaml"}, func() {
		code = cmdValidate()
	})
	if code != 2 {
		t.Errorf("expected exit code 2 (config load error), got %d", code)
	}
}

func TestCmdValidate_TransportSetWithoutLive(t *testing.T) {
	dir := t.TempDir()
	mfPath := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(mfPath, []byte(`schemaVersion: "0.1"
name: test
version: "1.0.0"
capabilities: []
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	withArgs([]string{"eunox", "validate", "--upstream-url", "http://x", mfPath}, func() {
		code = cmdValidate()
	})
	if code != 2 {
		t.Errorf("expected exit code 2 (usage: transport flags without --live), got %d", code)
	}
}

func TestCmdValidate_ManifestLoadError(t *testing.T) {
	var code int
	withArgs([]string{"eunox", "validate", "/no/such/manifest.yaml"}, func() {
		code = cmdValidate()
	})
	if code != 2 {
		t.Errorf("expected exit code 2 (parse error, matching the documented codes and --config mode), got %d", code)
	}
}

// TestCmdValidate_PositionalFilesConflictWithoutLive is a regression: `validate
// a.yaml b.yaml` with no --live (and no --config) must run config.MergeManifests
// and catch a cross-file conflict — before MergeManifests was hoisted above the
// syntax-only early return, two positional manifests with a genuine merge
// conflict (an audit-mode observer in one file, a restrictive condition on the
// same target in the other) passed with exit 0, even though `proxy` (and
// `validate --config`, which always merges) would refuse to boot on the same
// conflict.
func TestCmdValidate_PositionalFilesConflictWithoutLive(t *testing.T) {
	dir := t.TempDir()
	aPath := filepath.Join(dir, "a.yaml")
	if err := os.WriteFile(aPath, []byte(`schemaVersion: "0.1"
name: a
version: "1.0.0"
capabilities:
  - target: "tool:read_file"
    actions: ["call"]
    enforcement: audit
`), 0o600); err != nil {
		t.Fatal(err)
	}
	bPath := filepath.Join(dir, "b.yaml")
	if err := os.WriteFile(bPath, []byte(`schemaVersion: "0.1"
name: b
version: "1.0.0"
capabilities:
  - target: "tool:read_file"
    actions: ["call"]
    conditions:
      - type: allowedValues
        argument: path
        values: ["/reports/*"]
`), 0o600); err != nil {
		t.Fatal(err)
	}

	var code int
	stderr := captureStderr(t, func() {
		withArgs([]string{"eunox", "validate", aPath, bPath}, func() {
			code = cmdValidate()
		})
	})
	if code != 2 {
		t.Errorf("expected exit code 2 (merge conflict) for conflicting positional manifests without --live, got %d\nstderr:\n%s", code, stderr)
	}
}

func TestCmdValidate_LiveMissingUpstreamURL(t *testing.T) {
	dir := t.TempDir()
	mfPath := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(mfPath, []byte(`schemaVersion: "0.1"
name: test
version: "1.0.0"
capabilities: []
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	withArgs([]string{"eunox", "validate", "--live", mfPath}, func() {
		code = cmdValidate()
	})
	if code != 2 {
		t.Errorf("expected exit code 2 (connection error: --live without --upstream-url), got %d", code)
	}
}

func TestCmdValidate_LiveConnectError(t *testing.T) {
	dir := t.TempDir()
	mfPath := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(mfPath, []byte(`schemaVersion: "0.1"
name: test
version: "1.0.0"
capabilities: []
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	withArgs([]string{"eunox", "validate", "--live", "--upstream-url", "http://127.0.0.1:1", mfPath}, func() {
		code = cmdValidate()
	})
	if code != 2 {
		t.Errorf("expected exit code 2 (connect failure), got %d", code)
	}
}

// ───────────────────────── cmdInit error branches ───────────────────────────

func TestCmdInit_MissingUpstreamURL(t *testing.T) {
	var code int
	withArgs([]string{"eunox", "init"}, func() { code = cmdInit() })
	if code != 1 {
		t.Errorf("expected exit code 1 (missing --upstream-url), got %d", code)
	}
}

func TestCmdInit_ConnectError(t *testing.T) {
	var code int
	withArgs([]string{"eunox", "init", "--upstream-url", "http://127.0.0.1:1"}, func() {
		code = cmdInit()
	})
	if code != 2 {
		t.Errorf("expected exit code 2 (connect failure), got %d", code)
	}
}

func TestCmdInit_ConfigOutputWithoutOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"t"}}}`))
	}))
	defer srv.Close()

	var code int
	withArgs([]string{"eunox", "init", "--upstream-url", srv.URL, "--config-output", "/tmp/cfg.yaml"}, func() {
		code = cmdInit()
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (--config-output without --output), got %d", code)
	}
}

// ───────────────────────── cmdKill error branches ───────────────────────────

func TestCmdKill_NoTarget(t *testing.T) {
	var code int
	withArgs([]string{"eunox", "kill"}, func() { code = cmdKill() })
	if code != 1 {
		t.Errorf("expected exit code 1 (no target arg), got %d", code)
	}
}

func TestCmdKill_NoControlToken(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "no-such-token")
	var code int
	withArgs([]string{"eunox", "kill", "--port", "3001", "--control-token-path", tokenPath, "all"}, func() {
		code = cmdKill()
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (no control token), got %d", code)
	}
}

func TestCmdKill_ProxyReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	tok := "test-token-xyz"
	tokenPath := filepath.Join(t.TempDir(), "control.token")
	if err := os.WriteFile(tokenPath, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	addr := srv.Listener.Addr().String()
	portStr := addr[strings.LastIndex(addr, ":")+1:]
	var code int
	withArgs([]string{"eunox", "kill", "--port", portStr, "--control-token", tok, "all"}, func() {
		code = cmdKill()
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (proxy returned 403), got %d", code)
	}
}

// ───────────────────────── cmdAuditVerify error branches ────────────────────

func TestCmdAuditVerify_NoAuditLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	var code int
	withArgs([]string{"eunox", "audit-verify", "--audit-log", logPath}, func() {
		code = cmdAuditVerify()
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (no audit log), got %d", code)
	}
}

func TestCmdAuditVerify_InvalidSince(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	sink, err := audit.Open(logPath, keyPath, 0, 0, audit.WithIdentity(pdp.AuditIdentityFromContext))
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "s", "c", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var code int
	withArgs([]string{"eunox", "audit-verify", "--audit-log", logPath, "--audit-key-path", keyPath, "--since", "not-a-timestamp"}, func() {
		code = cmdAuditVerify()
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (invalid --since), got %d", code)
	}
}

func TestCmdAuditVerify_ConfigLoadError(t *testing.T) {
	var code int
	withArgs([]string{"eunox", "audit-verify", "--config", "/no/such/config.yaml"}, func() {
		code = cmdAuditVerify()
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (config load error), got %d", code)
	}
}

// ───────────────────────── cmdStats error branches ──────────────────────────

func TestCmdStats_NoAuditLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	var code int
	withArgs([]string{"eunox", "stats", "--audit-log", logPath}, func() {
		code = cmdStats()
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (no audit log), got %d", code)
	}
}

func TestCmdStats_ConfigLoadError(t *testing.T) {
	var code int
	withArgs([]string{"eunox", "stats", "--config", "/no/such/config.yaml"}, func() {
		code = cmdStats()
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (config load error), got %d", code)
	}
}

// ───────────────────────── cmdSuggest error branches ────────────────────────

func TestCmdSuggest_NoAuditLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	var code int
	withArgs([]string{"eunox", "suggest", "--audit-log", logPath}, func() {
		code = cmdSuggest()
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (no audit log), got %d", code)
	}
}

// ───────────────────────── openAuditChain discovery error ───────────────────

func TestOpenAuditChain_DiscoveryError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(blocker, "audit.jsonl")

	_, _, err := openAuditChain("stats", logPath)
	if err == nil {
		t.Fatal("expected an error when the log directory is a regular file")
	}
}

// ───────────────────────── validate_live.go FM-2Pinned + FM-6 ───────────────

// TestRunValidateLive_FM2PinnedAndFM6_Singular covers the FM-2Pinned path
// (a descriptionHash-pinned tool absent from the live tools/list) and the FM-6
// path (structural schema drift: live tool has a property not declared in the
// manifest's closed argumentSchema). A single finding of each covers the
// singular summary messages and all next-steps blocks.
func TestRunValidateLive_FM2PinnedAndFM6_Singular(t *testing.T) {
	falseVal := false
	manifest := manifestWith(
		// pinned_absent_tool is absent from the upstream → FM-2Pinned
		capability.Constraint{
			Target:          "tool:pinned_absent_tool",
			Actions:         []string{"call"},
			DescriptionHash: capability.ComputeToolHash("vetted description", nil),
		},
		// schema_tool is present but has an extra live parameter → FM-6
		capability.Constraint{
			Target:  "tool:schema_tool",
			Actions: []string{"call"},
			ArgumentSchema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"known_param": {},
				},
				AdditionalProperties: &falseVal,
			},
		},
	)
	tools := []drift.UpstreamTool{
		{
			Name: "schema_tool",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"known_param":  map[string]interface{}{"type": "string"},
					"secret_param": map[string]interface{}{"type": "string"},
				},
			},
		},
		// pinned_absent_tool is intentionally absent.
	}

	var buf bytes.Buffer
	code := runValidateLive(manifest, tools, "", &buf)
	if code != 1 {
		t.Errorf("exit code: want 1 (FM-2Pinned + FM-6), got %d\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "DESCRIPTION-PINNED tool absent upstream") {
		t.Errorf("expected FM-2Pinned warning line:\n%s", out)
	}
	if !strings.Contains(out, "structural schema drift") {
		t.Errorf("expected FM-6 next-steps guidance:\n%s", out)
	}
	if !strings.Contains(out, "1 description-pinned tool missing") {
		t.Errorf("expected singular FM-2Pinned result summary:\n%s", out)
	}
	if !strings.Contains(out, "1 structural schema drift warning") {
		t.Errorf("expected singular FM-6 result summary:\n%s", out)
	}
}

// TestRunValidateLive_FM2PinnedAndFM6_Plural covers the plural-count branches
// in the result summary: "N description-pinned tools missing" and
// "N structural schema drift warnings".
func TestRunValidateLive_FM2PinnedAndFM6_Plural(t *testing.T) {
	falseVal := false
	manifest := manifestWith(
		capability.Constraint{
			Target:          "tool:pinned_absent_1",
			Actions:         []string{"call"},
			DescriptionHash: capability.ComputeToolHash("vetted description A", nil),
		},
		capability.Constraint{
			Target:          "tool:pinned_absent_2",
			Actions:         []string{"call"},
			DescriptionHash: capability.ComputeToolHash("vetted description B", nil),
		},
		capability.Constraint{
			Target:  "tool:schema_tool_a",
			Actions: []string{"call"},
			ArgumentSchema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"known": {},
				},
				AdditionalProperties: &falseVal,
			},
		},
		capability.Constraint{
			Target:  "tool:schema_tool_b",
			Actions: []string{"call"},
			ArgumentSchema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"known": {},
				},
				AdditionalProperties: &falseVal,
			},
		},
	)
	tools := []drift.UpstreamTool{
		{
			Name: "schema_tool_a",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"known": map[string]interface{}{"type": "string"},
					"extra": map[string]interface{}{"type": "string"},
				},
			},
		},
		{
			Name: "schema_tool_b",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"known": map[string]interface{}{"type": "string"},
					"extra": map[string]interface{}{"type": "string"},
				},
			},
		},
	}

	var buf bytes.Buffer
	code := runValidateLive(manifest, tools, "", &buf)
	if code != 1 {
		t.Errorf("exit code: want 1, got %d\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "description-pinned tools missing") {
		t.Errorf("expected plural FM-2Pinned summary:\n%s", out)
	}
	if !strings.Contains(out, "structural schema drift warnings") {
		t.Errorf("expected plural FM-6 summary:\n%s", out)
	}
}

// ───────────────────────── cmdKill additional error branches ─────────────────

// TestCmdKill_RedisKillError covers the cmdKill branch where --redis-addr is
// provided but the kill fails (unreachable Redis → ping refused).
func TestCmdKill_RedisKillError(t *testing.T) {
	var code int
	withArgs([]string{"eunox", "kill", "--redis-addr", "127.0.0.1:1", "sess-x"}, func() {
		code = cmdKill()
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (redis kill failed), got %d", code)
	}
}

// TestCmdKill_HttpDoFails covers the http.DefaultClient.Do error branch in
// cmdKill: the server is started, port captured, then closed so the POST fails
// with connection refused.
func TestCmdKill_HttpDoFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := srv.Listener.Addr().String()
	portStr := addr[strings.LastIndex(addr, ":")+1:]
	srv.Close() // close before the kill request so Do fails

	tok := "tok-" + t.Name()
	tokenPath := filepath.Join(t.TempDir(), "control.token")
	if err := os.WriteFile(tokenPath, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var code int
	withArgs([]string{"eunox", "kill", "--port", portStr, "--control-token", tok, "all"}, func() {
		code = cmdKill()
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (http.Do connection refused), got %d", code)
	}
}

// ───────────────────── cmdAuditVerify additional error branches ──────────────

// TestCmdAuditVerify_LoadOrCreateKeysError covers the LoadOrCreateKeys error
// path: a regular file sits where the key directory must be created, so
// os.MkdirAll fails with ENOTDIR.
func TestCmdAuditVerify_LoadOrCreateKeysError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "key-blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "audit.jsonl")
	badKeyPath := filepath.Join(blocker, "subdir", "audit.key")

	var code int
	withArgs([]string{"eunox", "audit-verify", "--audit-log", logPath, "--audit-key-path", badKeyPath}, func() {
		code = cmdAuditVerify()
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (LoadOrCreateKeys failed), got %d", code)
	}
}

// TestCmdAuditVerify_LogChainFilesError covers the LogChainFiles error path:
// the key loads successfully (a fresh key is created at a valid path), but the
// log directory is a regular file so os.ReadDir fails with ENOTDIR.
func TestCmdAuditVerify_LogChainFilesError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "log-blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(blocker, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	var code int
	withArgs([]string{"eunox", "audit-verify", "--audit-log", logPath, "--audit-key-path", keyPath}, func() {
		code = cmdAuditVerify()
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (LogChainFiles failed), got %d", code)
	}
}

// TestCmdAuditVerify_UnknownKeyID covers the res.UnknownKey > 0 notice and
// the !res.OK() return: records are signed with key A but verification uses key
// B (a freshly generated key at a different path), so every record's key_id is
// absent from the ring and the verdict fails with UNKNOWN_KEY_ID.
func TestCmdAuditVerify_UnknownKeyID(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPathA := filepath.Join(dir, "keyA.key")
	keyPathB := filepath.Join(dir, "keyB.key")

	sink, err := audit.Open(logPath, keyPathA, 0, 0, audit.WithIdentity(pdp.AuditIdentityFromContext))
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "s", "c", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("sink.Close: %v", err)
	}

	// Verify with a completely different key (keyB is freshly generated).
	var code int
	withArgs([]string{"eunox", "audit-verify", "--audit-log", logPath, "--audit-key-path", keyPathB}, func() {
		code = cmdAuditVerify()
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (UNKNOWN_KEY_ID), got %d", code)
	}
}

// ───────────────────────── cmdSuggest WriteFile error ───────────────────────

// TestCmdSuggest_WriteFileError covers the os.WriteFile error path in
// cmdSuggest: a regular file sits where the output directory must be, so
// WriteFile fails with ENOTDIR.
func TestCmdSuggest_WriteFileError(t *testing.T) {
	content := auditAllowToolLine(t, "read_file", map[string]interface{}{"path": "/tmp/a"})
	logPath := writeTempFile(t, content)

	dir := t.TempDir()
	blocker := filepath.Join(dir, "output-blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	badOutput := filepath.Join(blocker, "manifest.yaml")

	var code int
	withArgs([]string{
		"eunox", "suggest",
		"--audit-log", logPath,
		"--output", badOutput,
	}, func() {
		code = cmdSuggest()
	})
	if code != 2 {
		t.Errorf("expected exit code 2 (WriteFile failed), got %d", code)
	}
}

// ───────────────────────── --help across refactored subcommands ────────────

// TestSubcommands_HelpReturnsZero covers the flag.ErrHelp branch added when
// each subcommand's FlagSet moved from flag.ExitOnError to
// flag.ContinueOnError: --help must print usage and return 0, not fall
// through to the generic parse-error return 1.
func TestSubcommands_HelpReturnsZero(t *testing.T) {
	cases := []struct {
		name string
		run  func() int
	}{
		{"validate", cmdValidate},
		{"init", cmdInit},
		{"suggest", cmdSuggest},
		{"kill", cmdKill},
		{"audit-verify", cmdAuditVerify},
		{"stats", cmdStats},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var code int
			out := captureStderr(t, func() {
				withArgs([]string{"eunox", tc.name, "--help"}, func() { code = tc.run() })
			})
			if code != 0 {
				t.Errorf("%s --help: want exit code 0, got %d", tc.name, code)
			}
			if !strings.Contains(out, "Usage") {
				t.Errorf("%s --help: expected usage text, got %q", tc.name, out)
			}
		})
	}
}

// TestValidateJWTFlagsRequireJWKS verifies the fail-closed guard for JWT-authentication
// flags supplied without --jwks-uri: without it those flags are silently ignored and the
// gateway serves every request unauthenticated, so startup must reject the mismatch.
func TestValidateJWTFlagsRequireJWKS(t *testing.T) {
	// --jwks-uri present: any JWT flags are honored, no error.
	if err := validateJWTFlagsRequireJWKS(proxyFlags{jwksURI: "https://idp/jwks", jwtAudience: "api", jwtLeeway: pdp.DefaultJWTLeeway}); err != nil {
		t.Errorf("jwks set: want nil, got %v", err)
	}
	// No --jwks-uri and no JWT flags: nothing to enforce, no error.
	if err := validateJWTFlagsRequireJWKS(proxyFlags{jwtLeeway: pdp.DefaultJWTLeeway}); err != nil {
		t.Errorf("no jwt flags: want nil, got %v", err)
	}
	// No --jwks-uri but at least one gated flag activated: fail closed with a message
	// naming --jwks-uri. The guard now reads only the precomputed gatedJWTFlagsSet
	// (populated by gatedFlagsSetWithoutJWKS over the FlagSet); the detection of WHICH
	// flags populate it is covered by TestGatedFlagsSetWithoutJWKS below.
	for _, name := range []string{"--jwt-audience", "--jwt-issuer", "--jwt-allow-any-audience", "--jwt-experimental-capabilities", "--jwt-leeway"} {
		t.Run(name, func(t *testing.T) {
			err := validateJWTFlagsRequireJWKS(proxyFlags{gatedJWTFlagsSet: []string{name}, jwtLeeway: pdp.DefaultJWTLeeway})
			if err == nil {
				t.Fatal("a gated JWT flag without --jwks-uri must fail closed")
			}
			if !strings.Contains(err.Error(), "--jwks-uri") || !strings.Contains(err.Error(), name) {
				t.Errorf("error %q should mention --jwks-uri and %s", err, name)
			}
		})
	}
}

// TestGatedFlagsSetWithoutJWKS pins the unified detection that drives BOTH halves of the
// require-jwks guard off the single jwksGatedFlags list: value detection for zero-default
// flags and explicit-set for non-zero-default ones (today just --jwt-leeway). It drives
// the REAL proxy FlagSet so a drift between the list and the flags is caught.
func TestGatedFlagsSetWithoutJWKS(t *testing.T) {
	t.Run("no gated flags set -> empty", func(t *testing.T) {
		fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
		_ = registerProxyFlags(fs)
		if err := fs.Parse(nil); err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got := gatedFlagsSetWithoutJWKS(fs); len(got) != 0 {
			t.Errorf("got %v, want none", got)
		}
	})

	t.Run("zero-default gated flag set to a non-zero value is reported (value detection)", func(t *testing.T) {
		fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
		_ = registerProxyFlags(fs)
		if err := fs.Parse([]string{"--jwt-audience=api"}); err != nil {
			t.Fatalf("parse: %v", err)
		}
		got := gatedFlagsSetWithoutJWKS(fs)
		if len(got) != 1 || got[0] != "--jwt-audience" {
			t.Errorf("got %v, want [--jwt-audience]", got)
		}
	})

	t.Run("explicit --jwt-leeway at its default is reported (explicit-set)", func(t *testing.T) {
		fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
		_ = registerProxyFlags(fs)
		// Set it to the DEFAULT value: value detection would miss this non-zero-default flag,
		// explicit-set must not.
		if err := fs.Parse([]string{"--jwt-leeway", pdp.DefaultJWTLeeway.String()}); err != nil {
			t.Fatalf("parse: %v", err)
		}
		got := gatedFlagsSetWithoutJWKS(fs)
		if len(got) != 1 || got[0] != "--jwt-leeway" {
			t.Errorf("got %v, want [--jwt-leeway]", got)
		}
	})

	t.Run("explicit zero-default gated flag =false is NOT reported (value detection owns it)", func(t *testing.T) {
		fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
		_ = registerProxyFlags(fs)
		// --jwt-allow-any-audience=false carries no JWT intent; value detection spares it.
		if err := fs.Parse([]string{"--jwt-allow-any-audience=false"}); err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got := gatedFlagsSetWithoutJWKS(fs); len(got) != 0 {
			t.Errorf("got %v, want none (zero-default flags are value-detected)", got)
		}
	})
}

// TestFlagDefaultIsZero_ClassifiesTypes confirms flagDefaultIsZero classifies the
// stdlib zero renderings for every flag type the gated-flags list uses —
// string/bool/int/duration — as zero, and their non-zero defaults as non-zero.
func TestFlagDefaultIsZero_ClassifiesTypes(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.String("s", "", "")           // zero default
	fs.String("s-nonzero", "x", "")  // non-zero default
	fs.Bool("b", false, "")          // zero default
	fs.Int("i", 0, "")               // zero default
	fs.Int("i-nonzero", 5, "")       // non-zero default
	fs.Duration("d", 0, "")          // zero default
	fs.Duration("d-nonzero", 30, "") // non-zero default (30ns)
	cases := map[string]bool{
		"s": true, "s-nonzero": false,
		"b": true,
		"i": true, "i-nonzero": false,
		"d": true, "d-nonzero": false,
	}
	for name, want := range cases {
		if got := flagDefaultIsZero(fs.Lookup(name)); got != want {
			t.Errorf("flagDefaultIsZero(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestValidateConfigRoutes_NonLiveMirrorsStartupChecks verifies that `validate --config`
// (no --live) FAILs on configs the proxy would refuse to boot — previously it exited 0
// on these, green-lighting an unbootable config. Each mirrors a LoadUpstreamPDP
// startup-fatal check.
func TestValidateConfigRoutes_NonLiveMirrorsStartupChecks(t *testing.T) {
	dir := t.TempDir()
	pinManifest := mustWriteFile(t, dir, "pin.yaml", `
schemaVersion: "0.1"
name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: ["call"]
`)
	samplingManifest := mustWriteFile(t, dir, "sampling.yaml", `
schemaVersion: "0.1"
name: s
version: "0.1.0"
capabilities:
  - target: "system:sampling/createMessage"
    actions: ["*"]
`)
	cases := []struct {
		name string
		u    config.UpstreamConfig
	}{
		{"expectVersion mismatch", config.UpstreamConfig{
			Name: "pin", Transport: config.HostTransportHTTP, UpstreamURL: "http://x",
			Policy: []string{pinManifest}, ExpectVersion: "9.9.9",
		}},
		{"sampling on http upstream", config.UpstreamConfig{
			Name: "samp", Transport: config.HostTransportHTTP, UpstreamURL: "http://x",
			Policy: []string{samplingManifest},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newConfigForRoute(tc.u)
			var buf bytes.Buffer
			// live=false: the non-live path must now catch these (it did not before).
			code := validateConfigRoutes(context.Background(), cfg, false, &buf)
			if code != 2 {
				t.Errorf("exit code = %d, want 2 (validate must FAIL a config proxy would reject)\n%s", code, buf.String())
			}
			if !strings.Contains(buf.String(), "FAIL") {
				t.Errorf("expected a FAIL line:\n%s", buf.String())
			}
		})
	}
}

// TestValidateConfigRoutes_StdioHostAudiencePinFails and
// TestWriteDoctorManifests_StdioHostAudiencePinFails are regressions: a manifest
// `audience` pin can never be enforced on a stdio-HOST config (the host-facing
// transport, distinct from an individual upstream's own subprocess-vs-remote-HTTP
// transport) because a stdio host cannot stand up a JWT PDP — `proxy` refuses to
// boot on it (serveStdioHost, via transport.startupFatalManifestCheck's
// audience-pin guard). Before that guard existed, neither `validate --config` nor
// `doctor` reproduced this refusal, so both would report a config OK that `proxy`
// would reject.
func TestValidateConfigRoutes_StdioHostAudiencePinFails(t *testing.T) {
	dir := t.TempDir()
	manifestPath := mustWriteFile(t, dir, "audience.yaml", `
schemaVersion: "0.1"
name: a
version: "0.1.0"
audience: "some-service"
capabilities:
  - target: "tool:read_file"
    actions: ["call"]
`)
	cfgPath := mustWriteFile(t, dir, "eunox.yaml", `
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: aud
    transport: stdio
    command: echo
    policy: ["`+manifestPath+`"]
`)
	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}

	var buf bytes.Buffer
	code := validateConfigRoutes(context.Background(), cfg, false, &buf)
	if code != 2 {
		t.Errorf("exit code = %d, want 2 (validate must FAIL a stdio-host config declaring a dead audience pin)\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "FAIL") || !strings.Contains(buf.String(), "audience pin") {
		t.Errorf("expected a FAIL line naming the audience pin:\n%s", buf.String())
	}
}

func TestWriteDoctorManifests_StdioHostAudiencePinFails(t *testing.T) {
	dir := t.TempDir()
	manifestPath := mustWriteFile(t, dir, "audience.yaml", `
schemaVersion: "0.1"
name: a
version: "0.1.0"
audience: "some-service"
capabilities:
  - target: "tool:read_file"
    actions: ["call"]
`)
	cfgPath := mustWriteFile(t, dir, "eunox.yaml", `
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: aud
    transport: stdio
    command: echo
    policy: ["`+manifestPath+`"]
`)
	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}

	var buf bytes.Buffer
	writeDoctorManifests(&buf, cfg, nil)
	if !strings.Contains(buf.String(), "WOULD FAIL CLOSED") || !strings.Contains(buf.String(), "audience pin") {
		t.Errorf("expected a WOULD FAIL CLOSED line naming the audience pin:\n%s", buf.String())
	}
}
