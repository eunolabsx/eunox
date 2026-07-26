// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Tests for CLI-level functions that can be exercised by manipulating os.Args
// and providing temporary files.  These tests are NOT parallel because they
// modify package-level state (os.Args).

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/internal/transport"
	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/killswitch"

	"github.com/alicebob/miniredis/v2"
)

// withArgs temporarily replaces os.Args for the duration of fn, then restores.
// Must not be called from parallel tests.
func withArgs(args []string, fn func()) {
	orig := os.Args
	os.Args = args
	defer func() { os.Args = orig }()
	fn()
}

// writeTempFile writes content to a temp file and returns its path.
func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "test-*.jsonl")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write: %v", err)
	}
	return f.Name()
}

// ── run (top-level dispatch) ────────────────────────────────────────────────

// TestRun_ExitCodes pins the process exit code of the dispatch-level paths that
// do not themselves call os.Exit. The bare-invocation case is load-bearing for
// package validation: winget's automatic validation launches the installed
// executable with no arguments and reports any non-zero exit as a failure, so a
// bare `eunox` must exit 0 (regression guard for the winget "returned exit
// code: 1" validation failure).
func TestRun_ExitCodes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"bare invocation", []string{"eunox"}, 0},
		{"help long", []string{"eunox", "--help"}, 0},
		{"help short", []string{"eunox", "-h"}, 0},
		{"help word", []string{"eunox", "help"}, 0},
		{"version", []string{"eunox", "version"}, 0},
		{"version flag", []string{"eunox", "--version"}, 0},
		{"unknown subcommand", []string{"eunox", "bogus"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(tc.args); got != tc.want {
				t.Errorf("run(%v): exit code = %d, want %d", tc.args[1:], got, tc.want)
			}
		})
	}
}

// ── cmdStats ──────────────────────────────────────────────────────────────

func TestCmdStats_EmptyLog(t *testing.T) {
	path := writeTempFile(t, "")
	withArgs([]string{"eunox", "stats", "--audit-log", path}, func() {
		cmdStats()
	})
}

func TestCmdStats_AllowedAndDenied(t *testing.T) {
	type rec struct {
		Decision   string `json:"decision"`
		TargetType string `json:"target_type"`
		Target     string `json:"target"`
		Method     string `json:"method"`
		DenialCode string `json:"denial_code"`
	}
	makeRec := func(r rec) string {
		b, _ := json.Marshal(r)
		return string(b) + "\n"
	}
	content := "" +
		makeRec(rec{Decision: "allow", TargetType: "tool", Target: "read_file", Method: "tools/call"}) +
		makeRec(rec{Decision: "deny", TargetType: "tool", Target: "write_file", Method: "tools/call", DenialCode: "CAPABILITY_DENIED"}) +
		makeRec(rec{Decision: "deny", TargetType: "tool", Target: "write_file", Method: "tools/call", DenialCode: "CAPABILITY_DENIED"}) +
		"\n" + // empty line → skipped
		"not-json\n" + // invalid JSON → skipped
		makeRec(rec{Decision: "allow", TargetType: "tool", Target: "read_file", Method: "tools/call"})

	path := writeTempFile(t, content)
	withArgs([]string{"eunox", "stats", "--audit-log", path}, func() {
		cmdStats()
	})
}

// TestCmdStats_WithMultipleDenials exercises the sort / print path.
func TestCmdStats_WithMultipleDenials(t *testing.T) {
	type rec struct {
		Decision   string `json:"decision"`
		TargetType string `json:"target_type"`
		Target     string `json:"target"`
		Method     string `json:"method"`
		DenialCode string `json:"denial_code"`
	}
	makeRec := func(r rec) string {
		b, _ := json.Marshal(r)
		return string(b) + "\n"
	}
	content := "" +
		makeRec(rec{Decision: "deny", TargetType: "tool", Target: "tool_a", Method: "tools/call", DenialCode: "CODE_1"}) +
		makeRec(rec{Decision: "deny", TargetType: "tool", Target: "tool_b", Method: "tools/call", DenialCode: "CODE_2"}) +
		makeRec(rec{Decision: "deny", TargetType: "tool", Target: "tool_a", Method: "tools/call", DenialCode: "CODE_1"}) +
		makeRec(rec{Decision: "deny", TargetType: "tool", Target: "tool_c", Method: "tools/call", DenialCode: "CODE_1"})

	path := writeTempFile(t, content)
	withArgs([]string{"eunox", "stats", "--audit-log", path}, func() {
		cmdStats()
	})
}

// ── audit-log empty-state hint ─────────────────────────────────────────────

// TestAuditLogMissingHint_GuidesFirstRun verifies the first-run hint names the
// command, the missing log path, and the proxy --audit capture step — rather
// than echoing a raw OS "no such file or directory" error.
func TestAuditLogMissingHint_GuidesFirstRun(t *testing.T) {
	for _, cmd := range []string{"stats", "suggest", "audit-verify"} {
		hint := auditLogMissingHint(cmd, "~/.eunox/audit.jsonl")
		if !strings.Contains(hint, cmd) {
			t.Errorf("hint for %q must name the command; got: %q", cmd, hint)
		}
		if !strings.Contains(hint, "~/.eunox/audit.jsonl") {
			t.Errorf("hint must name the missing log path; got: %q", hint)
		}
		if !strings.Contains(hint, "proxy --audit") {
			t.Errorf("hint must point at the capture command; got: %q", hint)
		}
		if strings.Contains(hint, "no such file") {
			t.Errorf("hint must not echo the raw OS error; got: %q", hint)
		}
	}
}

// TestOpenAuditChainOrExit_ConcatenatesInOrder confirms the reporting commands
// read the full rotated history (rotated siblings then active base) in order, via
// the lazy audit.OpenLogChain reader, rather than only the active segment.
func TestOpenAuditChainOrExit_ConcatenatesInOrder(t *testing.T) {
	r := audit.OpenLogChain([]string{
		writeTempFile(t, "rotated-1\n"),
		writeTempFile(t, "active-2\n"),
	})
	defer func() { _ = r.Close() }()
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	// Files are newline-joined; the blank separator line is skipped by line scanners
	// (computeAuditStats/computeSuggestions/tailAuditLines).
	if want := "rotated-1\n\nactive-2\n"; string(got) != want {
		t.Errorf("chain reader = %q, want %q (rotated siblings then active base)", got, want)
	}
}

// ── cmdValidate ───────────────────────────────────────────────────────────

func TestCmdValidate_ValidManifest(t *testing.T) {
	manifest := `
schemaVersion: "0.1"
name: test-manifest
version: "1.0.0"
capabilities:
  - target: "tool:read_file"
    actions: ["call"]
`
	path := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	withArgs([]string{"eunox", "validate", path}, func() {
		cmdValidate()
	})
}

// TestParseFlagsAndPositionals pins the interspersed-argument behavior that lets
// "validate <manifest> --live ..." (the order the usage text advertises) work as
// well as "--live ... <manifest>". A plain flag.Parse stops at the first
// positional, so without this the trailing flags get mis-read as filenames.
// TestAuditRequirementFlag covers the three-state --require-audit flag: the
// strict (default) / on / off spellings, the bare-flag bool ergonomics
// (IsBoolFlag → "strict"), and a fail-closed parse error on a typo. It also pins
// the required()/strict() predicates the proxy wiring reads.
func TestAuditRequirementFlag(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		want         auditRequirement
		wantParseErr bool
	}{
		{"default (absent) is strict", nil, auditRequireStrict, false},
		{"bare flag means strict", []string{"--require-audit"}, auditRequireStrict, false},
		{"explicit on", []string{"--require-audit=on"}, auditRequireOn, false},
		{"true alias means strict", []string{"--require-audit=true"}, auditRequireStrict, false},
		{"explicit off", []string{"--require-audit=off"}, auditRequireOff, false},
		{"false alias", []string{"--require-audit=false"}, auditRequireOff, false},
		{"strict", []string{"--require-audit=strict"}, auditRequireStrict, false},
		{"case-insensitive strict", []string{"--require-audit=STRICT"}, auditRequireStrict, false},
		{"typo fails closed", []string{"--require-audit=strikt"}, auditRequireStrict, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			f := registerProxyFlags(fs)
			err := fs.Parse(tc.args)
			if tc.wantParseErr {
				if err == nil {
					t.Fatal("expected a parse error for an invalid --require-audit value")
				}
				// A rejected value must leave the requirement at the strict
				// default, never silently weaken it (fail closed at parse time).
				if !f.requireAudit.strict() {
					t.Errorf("after a rejected value the requirement weakened to %v, want strict", *f.requireAudit)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}
			if *f.requireAudit != tc.want {
				t.Errorf("requireAudit = %v, want %v", *f.requireAudit, tc.want)
			}
			wantRequired := tc.want != auditRequireOff
			if f.requireAudit.required() != wantRequired {
				t.Errorf("required() = %v, want %v", f.requireAudit.required(), wantRequired)
			}
			wantStrict := tc.want == auditRequireStrict
			if f.requireAudit.strict() != wantStrict {
				t.Errorf("strict() = %v, want %v", f.requireAudit.strict(), wantStrict)
			}
		})
	}
}

// TestJWTExperimentalCapabilitiesFlag pins the security-critical default of the
// experimental mcp.capabilities gate: it must be OFF unless explicitly enabled, so
// the feature can never be silently re-enabled by a regression. Also confirms the
// flag parses on explicitly.
func TestJWTExperimentalCapabilitiesFlag(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"default (absent) is off", nil, false},
		{"explicit on", []string{"--jwt-experimental-capabilities"}, true},
		{"explicit true", []string{"--jwt-experimental-capabilities=true"}, true},
		{"explicit false", []string{"--jwt-experimental-capabilities=false"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			f := registerProxyFlags(fs)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}
			if *f.jwtExperimentalCaps != tc.want {
				t.Errorf("jwtExperimentalCaps = %v, want %v", *f.jwtExperimentalCaps, tc.want)
			}
		})
	}
}

// The --jwt-experimental-capabilities "requires --jwks-uri" contract is now enforced by the
// single validateJWTFlagsRequireJWKS guard (see TestValidateJWTFlagsRequireJWKS), which lists
// every jwks-gated flag once so the set cannot drift.

func TestParseFlagsAndPositionals(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantLive bool
		wantURL  string
		wantPos  []string
	}{
		{"flags then positional", []string{"--live", "--upstream-url", "u", "a.yaml"}, true, "u", []string{"a.yaml"}},
		{"positional then flags", []string{"a.yaml", "--live", "--upstream-url", "u"}, true, "u", []string{"a.yaml"}},
		{"interspersed", []string{"--live", "a.yaml", "--upstream-url", "u"}, true, "u", []string{"a.yaml"}},
		{"multiple positionals around flags", []string{"a.yaml", "--live", "b.yaml"}, true, "", []string{"a.yaml", "b.yaml"}},
		{"positionals only", []string{"a.yaml", "b.yaml"}, false, "", []string{"a.yaml", "b.yaml"}},
		{"flags only", []string{"--live"}, true, "", nil},
		{"empty", nil, false, "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("validate", flag.ContinueOnError)
			live := fs.Bool("live", false, "")
			url := fs.String("upstream-url", "", "")
			pos, err := parseFlagsAndPositionals(fs, tc.args)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if *live != tc.wantLive {
				t.Errorf("live = %v, want %v", *live, tc.wantLive)
			}
			if *url != tc.wantURL {
				t.Errorf("upstream-url = %q, want %q", *url, tc.wantURL)
			}
			if strings.Join(pos, ",") != strings.Join(tc.wantPos, ",") {
				t.Errorf("positionals = %v, want %v", pos, tc.wantPos)
			}
		})
	}
}

// TestParseFlagsAndPositionals_BadFlag confirms an unknown flag surfaces as an
// error (with ContinueOnError) rather than being silently treated as positional.
func TestParseFlagsAndPositionals_BadFlag(t *testing.T) {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(&strings.Builder{}) // suppress usage noise
	fs.Bool("live", false, "")
	if _, err := parseFlagsAndPositionals(fs, []string{"a.yaml", "--nope"}); err == nil {
		t.Fatal("expected error for unknown flag --nope, got nil")
	}
}

// ── cmdKill ───────────────────────────────────────────────────────────────

// TestKillControlURL is the regression for the IPv6 authority bug: an IPv6
// literal host must be bracketed so the resulting authority is parseable by
// net.SplitHostPort and the emergency control endpoint stays reachable.
func TestKillControlURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		host string
		port int
		want string
	}{
		{"ipv4", "127.0.0.1", 3000, "http://127.0.0.1:3000/control/kill"},
		{"hostname", "localhost", 8080, "http://localhost:8080/control/kill"},
		{"ipv6 loopback", "::1", 3000, "http://[::1]:3000/control/kill"},
		{"ipv6 full", "2001:db8::1", 443, "http://[2001:db8::1]:443/control/kill"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := killControlURL(tt.host, tt.port)
			if got != tt.want {
				t.Fatalf("killControlURL(%q, %d) = %q, want %q", tt.host, tt.port, got, tt.want)
			}
			// The authority must be re-parseable by net.SplitHostPort — exactly what
			// the HTTP client does before dialing, and what the unbracketed IPv6
			// authority (::1:3000) failed.
			authority := strings.TrimSuffix(strings.TrimPrefix(got, "http://"), "/control/kill")
			if _, _, err := net.SplitHostPort(authority); err != nil {
				t.Errorf("net.SplitHostPort(%q): %v (unparseable authority)", authority, err)
			}
		})
	}
}

func TestCmdKill_KillSession_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"killed":"sess-1"}`))
	}))
	defer srv.Close()

	// Parse port from server URL (format: http://127.0.0.1:PORT)
	addr := srv.Listener.Addr().String()
	// addr is host:port
	var host, port string
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			host = addr[:i]
			port = addr[i+1:]
			break
		}
	}

	withArgs([]string{"eunox", "kill", "--port", port, "--host", host, "--control-token", "kill-test-token", "sess-1"}, func() {
		cmdKill()
	})
}

func TestCmdKill_KillAll_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"killed":"all"}`))
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	var host, port string
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			host = addr[:i]
			port = addr[i+1:]
			break
		}
	}

	withArgs([]string{"eunox", "kill", "--port", port, "--host", host, "--control-token", "kill-test-token", "all"}, func() {
		cmdKill()
	})
}

// TestCmdKill_Redis_KillSession verifies the --redis-addr transport writes the
// session kill directly to the shared Redis state — the revocation path for a
// stdio proxy, which has no HTTP control endpoint.
func TestCmdKill_Redis_KillSession(t *testing.T) {
	mr := miniredis.RunT(t)

	withArgs([]string{"eunox", "kill", "--redis-addr", mr.Addr(), "sess-redis"}, func() {
		cmdKill()
	})

	if got, err := mr.Get("killswitch:session:sess-redis"); err != nil || got != "1" {
		t.Errorf("expected session kill key set to \"1\" in redis; got %q err=%v (keys=%v)", got, err, mr.Keys())
	}
}

// TestCmdKill_Redis_KillAll verifies that the "all" target activates the global
// kill switch in shared Redis state.
func TestCmdKill_Redis_KillAll(t *testing.T) {
	mr := miniredis.RunT(t)

	withArgs([]string{"eunox", "kill", "--redis-addr", mr.Addr(), "all"}, func() {
		cmdKill()
	})

	if got, err := mr.Get("killswitch:global"); err != nil || got != "1" {
		t.Errorf("expected global kill key set to \"1\" in redis; got %q err=%v (keys=%v)", got, err, mr.Keys())
	}
}

// ── cmdAuditVerify ────────────────────────────────────────────────────────

func TestCmdAuditVerify_EmptyLog(t *testing.T) {
	logPath := writeTempFile(t, "")
	keyPath := filepath.Join(t.TempDir(), "audit.key")

	withArgs([]string{"eunox", "audit-verify",
		"--audit-log", logPath,
		"--audit-key-path", keyPath,
	}, func() {
		cmdAuditVerify()
	})
}

// TestCmdAuditVerify_WithRecords exercises the scanner loop in cmdAuditVerify
// by providing a log file containing signed audit records.
func TestCmdAuditVerify_WithRecords(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/audit.jsonl"
	keyPath := dir + "/audit.key"

	// Create a real audit sink to produce signed records.
	sink, err := audit.Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	sink.RecordDeny(context.Background(), "sess-1", "write_file", "tools/call", "CAPABILITY_DENIED", "", nil, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	withArgs([]string{"eunox", "audit-verify",
		"--audit-log", logPath,
		"--audit-key-path", keyPath,
	}, func() {
		cmdAuditVerify()
	})
}

// TestCmdAuditVerify_VerifiesRotatedSet locks in the multi-file fix at the CLI
// boundary: audit-verify must gather the rotated siblings plus the current base
// and verify them as ONE chain, not just the base file (verifying the base alone
// could not detect deletion of an entire interior rotated file). A clean
// two-file rotated set must verify clean and report both files and every record.
func TestCmdAuditVerify_VerifiesRotatedSet(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// Segment 1 -> rotated sibling.
	sink, err := audit.Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess", "a", "tools/call", nil, nil, false, nil, nil)
	sink.RecordAllow(context.Background(), "sess", "b", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := os.Rename(logPath, logPath+".20260601T000000.000000000Z"); err != nil {
		t.Fatalf("rename to rotated sibling: %v", err)
	}
	// Segment 2 -> current base; reopen resumes the chain from the sibling tail.
	sink, err = audit.Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess", "c", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close (segment 2): %v", err)
	}

	var code int
	out := captureStdout(t, func() {
		withArgs([]string{"eunox", "audit-verify",
			"--audit-log", logPath,
			"--audit-key-path", keyPath,
		}, func() { code = cmdAuditVerify() })
	})

	if code != 0 {
		t.Errorf("expected exit code 0 for a clean rotated chain, got %d", code)
	}
	if !strings.Contains(out, "Verifying 2 audit log files") {
		t.Errorf("expected the multi-file chain notice (the base file alone would not mention it); got:\n%s", out)
	}
	// All 3 records across BOTH files must be verified, with the cross-file link clean.
	if !strings.Contains(out, "3 valid") || !strings.Contains(out, "0 chain break") {
		t.Errorf("expected 3 valid records and 0 chain breaks across the rotated set; got:\n%s", out)
	}
}

// captureStdout redirects os.Stdout for the duration of fn and returns what was
// written. Used by the CLI tests that assert on a subcommand's printed summary.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	defer func() {
		os.Stdout = orig
		_ = r.Close()
	}()
	fn()
	_ = w.Close()
	return <-done
}

// captureStderr redirects os.Stderr for the duration of fn and returns what
// was written. Mirrors captureStdout for CLI paths (like flag-parse usage
// output) that print to stderr instead.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	defer func() {
		os.Stderr = orig
		_ = r.Close()
	}()
	fn()
	_ = w.Close()
	return <-done
}

// TestCmdAuditVerify_WithRequestIDFilter exercises the --request-id filter.
func TestCmdAuditVerify_WithRequestIDFilter(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/audit.jsonl"
	keyPath := dir + "/audit.key"

	sink, err := audit.Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	withArgs([]string{"eunox", "audit-verify",
		"--audit-log", logPath,
		"--audit-key-path", keyPath,
		"--request-id", "nonexistent-id", // no records match → all skipped
	}, func() {
		cmdAuditVerify()
	})
}

// TestCmdInit_WithFakeUpstream exercises cmdInit with a fake upstream that
// returns an empty tools list.
func TestCmdInit_WithFakeUpstream(t *testing.T) {
	srv := httptest.NewServer(newFakeUpstream())
	defer srv.Close()

	withArgs([]string{"eunox", "init", "--upstream-url", srv.URL}, func() {
		cmdInit()
	})
}

// TestCmdInit_WithOutputFile exercises the --output flag path of cmdInit.
func TestCmdInit_WithOutputFile(t *testing.T) {
	srv := httptest.NewServer(newFakeUpstream())
	defer srv.Close()

	outputPath := filepath.Join(t.TempDir(), "manifest.yaml")
	withArgs([]string{"eunox", "init", "--upstream-url", srv.URL, "--output", outputPath}, func() {
		cmdInit()
	})

	if _, err := os.Stat(outputPath); err != nil {
		t.Errorf("expected output file to exist: %v", err)
	}
}

// TestCmdAuditVerify_SinceFilter exercises the --since timestamp filter.
func TestCmdAuditVerify_SinceFilter(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/audit.jsonl"
	keyPath := dir + "/audit.key"

	sink, err := audit.Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Use a far-future timestamp so all records are before it → all skipped
	withArgs([]string{"eunox", "audit-verify",
		"--audit-log", logPath,
		"--audit-key-path", keyPath,
		"--since", "2099-01-01T00:00:00Z",
	}, func() {
		cmdAuditVerify()
	})
}

// ── run() safe branches ────────────────────────────────────────────────────
// These exercise dispatch branches whose subcommand returns without os.Exit, so
// they call run() directly (main() always calls os.Exit and would kill the test
// binary). Dispatch exit codes are pinned in TestRun_ExitCodes.

// TestMain_VersionBranch exercises the "version" branch which dispatches to
// cmdVersion() and returns without os.Exit.
func TestMain_VersionBranch(t *testing.T) {
	withArgs([]string{"eunox", "version"}, func() {
		run(os.Args)
	})
}

func TestMain_DashDashVersionBranch(t *testing.T) {
	withArgs([]string{"eunox", "--version"}, func() {
		run(os.Args)
	})
}

func TestMain_HelpBranch(t *testing.T) {
	withArgs([]string{"eunox", "--help"}, func() {
		run(os.Args)
	})
}

func TestMain_HelpShortBranch(t *testing.T) {
	withArgs([]string{"eunox", "-h"}, func() {
		run(os.Args)
	})
}

func TestMain_HelpWordBranch(t *testing.T) {
	withArgs([]string{"eunox", "help"}, func() {
		run(os.Args)
	})
}

func TestMain_StatsBranch(t *testing.T) {
	path := writeTempFile(t, "")
	withArgs([]string{"eunox", "stats", "--audit-log", path}, func() {
		run(os.Args)
	})
}

func TestMain_ValidateBranch(t *testing.T) {
	manifest := `
schemaVersion: "0.1"
name: test
version: "1.0.0"
capabilities:
  - target: "tool:read_file"
    actions: ["call"]
`
	path := filepath.Join(t.TempDir(), "m.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	withArgs([]string{"eunox", "validate", path}, func() {
		run(os.Args)
	})
}

func TestMain_KillBranch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	var host, port string
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			host = addr[:i]
			port = addr[i+1:]
			break
		}
	}
	withArgs([]string{"eunox", "kill", "--port", port, "--host", host, "--control-token", "kill-test-token", "all"}, func() {
		run(os.Args)
	})
}

func TestMain_AuditVerifyBranch(t *testing.T) {
	logPath := writeTempFile(t, "")
	keyPath := filepath.Join(t.TempDir(), "audit.key")
	withArgs([]string{"eunox", "audit-verify",
		"--audit-log", logPath,
		"--audit-key-path", keyPath,
	}, func() {
		run(os.Args)
	})
}

func TestMain_InitBranch(t *testing.T) {
	srv := httptest.NewServer(newFakeUpstream())
	defer srv.Close()
	withArgs([]string{"eunox", "init", "--upstream-url", srv.URL}, func() {
		run(os.Args)
	})
}

// ── expandHome ────────────────────────────────────────────────────────────

// ── defaultAuditLog / expandHome edge cases ──────────────────────────────

// TestWriteDoctorAudit_LogPathUnresolvable_NoSpuriousStat is the regression:
// when the audit-log path cannot be resolved (e.g. a "~" path with no home dir),
// writeDoctorAudit must not fall through to os.Stat(""), which would print a
// second, confusing "log file:  stat : no such file or directory" line with an
// empty filename on top of the "cannot resolve" line. The key-path diagnostics
// (which precede the log-file stat) must still be emitted.
func TestWriteDoctorAudit_LogPathUnresolvable_NoSpuriousStat(t *testing.T) {
	t.Setenv("HOME", "")
	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("os.UserHomeDir still resolves with HOME unset on this platform; cannot exercise the failure path")
	}
	var buf bytes.Buffer
	// Absolute key path so the key-path block does not also fail to resolve,
	// proving the log-path failure does not suppress the diagnostics after it.
	writeDoctorAudit(&buf, "~/.eunox/audit.jsonl", "/nonexistent/eunox/key", 0)
	out := buf.String()
	if !strings.Contains(out, "cannot resolve") {
		t.Errorf("expected 'cannot resolve' for unresolvable log path; got:\n%s", out)
	}
	if !strings.Contains(out, "key path:") {
		t.Errorf("key-path diagnostics were suppressed by the log-path failure; got:\n%s", out)
	}
	if strings.Contains(out, "log file:") {
		t.Errorf("os.Stat(\"\") produced a spurious 'log file:' line; got:\n%s", out)
	}
}

// ─── validateConfigRoutes (no --live) ─────────────────────────────────────────
//
// Without --live, validateConfigRoutes just exercises the per-route syntax
// path and the exit-code aggregation — no upstream is contacted. These tests
// cover:
//
//   - happy path: every route's manifest loads, exit 0
//   - allow-all (audit) route: no policy + enforcement: audit → notice, no bump
//   - gateway policyless non-audit route: fails closed at startup → exit 2
//   - malformed manifest: per-route FAIL, exit 2 (aggregation picks the worst)
//   - exit-code aggregation: clean route + broken route → exit 2

// validManifestYAML is a minimal syntactically valid manifest, with one
// capability so the OK line includes capabilities=1 for a meaningful assertion.
const validManifestYAML = `
schemaVersion: "0.1"
name: ok-manifest
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: ["call"]
`

func TestValidateConfigRoutes_HappyPath(t *testing.T) {
	dir := t.TempDir()
	manifestPath := mustWriteFile(t, dir, "ok.yaml", validManifestYAML)
	cfgPath := mustWriteFile(t, dir, "eunox.yaml", `
schemaVersion: "0.1"
upstreams:
  - name: fs
    transport: stdio
    command: echo
    policy:
      - `+manifestPath+`
`)
	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}

	var buf bytes.Buffer
	code := validateConfigRoutes(context.Background(), cfg, false /* live */, &buf)
	if code != 0 {
		t.Errorf("exit code: want 0, got %d\noutput:\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, `route "fs"`) {
		t.Errorf("output missing route header for %q:\n%s", "fs", out)
	}
	if !strings.Contains(out, "OK") || !strings.Contains(out, "capabilities=1") {
		t.Errorf("output missing OK line with capability count:\n%s", out)
	}
}

// TestValidateConfigRoutes_RelativePolicyResolvedAgainstBaseDir pins the fix for
// validate --config resolving a relative policy path against the process CWD instead
// of the config file's directory. A config that proxy --config loads cleanly from any
// working directory must also validate cleanly from any working directory; before the
// fix this returned exit 2 with "open ok.yaml: no such file or directory".
func TestValidateConfigRoutes_RelativePolicyResolvedAgainstBaseDir(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, dir, "ok.yaml", validManifestYAML)
	cfgPath := mustWriteFile(t, dir, "eunox.yaml", `
schemaVersion: "0.1"
upstreams:
  - name: fs
    transport: stdio
    command: echo
    policy:
      - ok.yaml
`)
	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}

	// Run from an unrelated working directory: the relative policy must still resolve
	// against the config file's directory (cfg.BaseDir), not the CWD.
	t.Chdir(t.TempDir())

	var buf bytes.Buffer
	code := validateConfigRoutes(context.Background(), cfg, false /* live */, &buf)
	if code != 0 {
		t.Fatalf("relative policy must resolve against the config dir; got exit %d\noutput:\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "OK") {
		t.Errorf("expected an OK line for the resolved manifest:\n%s", buf.String())
	}
}

// TestValidateConfigRoutes_DemoLocalGateway pins demo/eunox.local.gateway.yaml as
// a runnable fixture: it is the documented host-run debug config, and its policy
// paths are resolved against the config file's directory (demo/), not the repo
// root, so they must read as "policies/..." rather than "demo/policies/...".
func TestValidateConfigRoutes_DemoLocalGateway(t *testing.T) {
	cfg, err := config.LoadGatewayConfig("../../demo/eunox.local.gateway.yaml")
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}

	var buf bytes.Buffer
	code := validateConfigRoutes(context.Background(), cfg, false /* live */, &buf)
	if code != 0 {
		t.Fatalf("demo/eunox.local.gateway.yaml must validate cleanly; got exit %d\noutput:\n%s", code, buf.String())
	}
}

func TestValidateConfigRoutes_AllowAllRouteNoExitBump(t *testing.T) {
	dir := t.TempDir()
	cfgPath := mustWriteFile(t, dir, "eunox.yaml", `
schemaVersion: "0.1"
defaults:
  enforcement: audit
upstreams:
  - name: open
    transport: stdio
    command: echo
`)
	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}

	var buf bytes.Buffer
	code := validateConfigRoutes(context.Background(), cfg, false, &buf)
	if code != 0 {
		t.Errorf("allow-all route should not bump exit code; got %d\noutput:\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "no policy configured") {
		t.Errorf("output should call out the allow-all route:\n%s", buf.String())
	}
}

// TestValidateConfigRoutes_GatewayPolicylessNonAuditFails locks the SEC-05
// consistency rule: validate must FAIL (exit 2) a gateway route that has no
// policy and is not in audit mode, because the proxy now fails closed on it at
// startup. Green-lighting such a config would defeat validate's pre-flight role.
func TestValidateConfigRoutes_GatewayPolicylessNonAuditFails(t *testing.T) {
	dir := t.TempDir()
	cfgPath := mustWriteFile(t, dir, "eunox.yaml", `
schemaVersion: "0.1"
transport: http
upstreams:
  - name: open
    transport: stdio
    command: echo
`)
	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}

	var buf bytes.Buffer
	code := validateConfigRoutes(context.Background(), cfg, false, &buf)
	if code != 2 {
		t.Errorf("policyless non-audit gateway route should exit 2; got %d\noutput:\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "FAIL") || !strings.Contains(buf.String(), "fails closed") {
		t.Errorf("output should flag the fail-closed misconfiguration:\n%s", buf.String())
	}
}

// TestValidateConfigRoutes_StdioHostPolicylessNonAuditFails locks the
// SEC-05 fix: a stdio-host route with no policy and not in audit mode must FAIL
// (exit 2) in validate, because serveStdioHost now refuses to start it — it
// previously booted allow-all, and validate/doctor green-lit it. Mirrors the
// gateway-host check so both transports are flagged identically.
func TestValidateConfigRoutes_StdioHostPolicylessNonAuditFails(t *testing.T) {
	dir := t.TempDir()
	cfgPath := mustWriteFile(t, dir, "eunox.yaml", `
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: open
    transport: stdio
    command: echo
`)
	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}

	var buf bytes.Buffer
	code := validateConfigRoutes(context.Background(), cfg, false, &buf)
	if code != 2 {
		t.Errorf("policyless non-audit stdio-host route should exit 2; got %d\noutput:\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "FAIL") || !strings.Contains(buf.String(), "fails closed") {
		t.Errorf("output should flag the fail-closed misconfiguration:\n%s", buf.String())
	}
}

// TestValidateConfigRoutes_NoPolicyExpectVersionFails locks that a no-policy
// route which declares expectVersion is reported FAIL (exit 2) even though it is
// in audit mode: loadUpstreamPDP rejects a version pin with no policy to pin, so
// the proxy would refuse to start. An audit posture alone must not mask that.
func TestValidateConfigRoutes_NoPolicyExpectVersionFails(t *testing.T) {
	dir := t.TempDir()
	cfgPath := mustWriteFile(t, dir, "eunox.yaml", `
schemaVersion: "0.1"
transport: http
upstreams:
  - name: tap
    transport: stdio
    command: echo
    enforcement: audit
    expectVersion: "1.0.0"
`)
	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}

	var buf bytes.Buffer
	code := validateConfigRoutes(context.Background(), cfg, false, &buf)
	if code != 2 {
		t.Errorf("no-policy expectVersion route should exit 2; got %d\noutput:\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "fails closed") || !strings.Contains(out, "expectVersion") {
		t.Errorf("output should flag the expectVersion-without-policy misconfiguration:\n%s", out)
	}
}

// TestValidateConfigRoutes_InvalidNoPolicyRouteNotIntrospected is the --live
// counterpart: a no-policy route the proxy would refuse to start (here, an audit
// route with strictDrift, which requires a policy) must be reported FAIL and
// skipped — validate must not spawn or connect to the upstream for a route that
// would never serve traffic. We assert the introspection banner is absent.
func TestValidateConfigRoutes_InvalidNoPolicyRouteNotIntrospected(t *testing.T) {
	dir := t.TempDir()
	cfgPath := mustWriteFile(t, dir, "eunox.yaml", `
schemaVersion: "0.1"
transport: http
upstreams:
  - name: tap
    transport: stdio
    command: echo
    enforcement: audit
    strictDrift: true
`)
	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}

	var buf bytes.Buffer
	code := validateConfigRoutes(context.Background(), cfg, true /* live */, &buf)
	if code != 2 {
		t.Errorf("invalid no-policy route should exit 2 under --live; got %d\noutput:\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "strictDrift") {
		t.Errorf("output should flag the strictDrift-without-policy misconfiguration:\n%s", out)
	}
	// The upstream must not have been contacted: the live-introspection banner
	// is the proof that fetchRouteLive ran. It must be absent.
	if strings.Contains(out, "Connecting to upstream") {
		t.Errorf("invalid no-policy route must not be introspected under --live:\n%s", out)
	}
}

func TestValidateConfigRoutes_MalformedManifestExits2(t *testing.T) {
	dir := t.TempDir()
	badPath := mustWriteFile(t, dir, "bad.yaml", "schemaVersion: \"0.1\"\nname: bad\nversion: \"0.1.0\"\ncapabilities:\n  - this is not a real entry\n")
	cfgPath := mustWriteFile(t, dir, "eunox.yaml", `
schemaVersion: "0.1"
upstreams:
  - name: broken
    transport: stdio
    command: echo
    policy:
      - `+badPath+`
`)
	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}

	var buf bytes.Buffer
	code := validateConfigRoutes(context.Background(), cfg, false, &buf)
	if code != 2 {
		t.Errorf("malformed manifest should exit 2 (parse error); got %d\noutput:\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "FAIL") {
		t.Errorf("output should mark the bad manifest FAIL:\n%s", buf.String())
	}
}

func TestValidateConfigRoutes_AggregatesWorstAcrossRoutes(t *testing.T) {
	// One clean route + one broken route → overall exit 2, but the clean route
	// still reports OK. Locks the "max across routes" rule.
	dir := t.TempDir()
	goodPath := mustWriteFile(t, dir, "ok.yaml", validManifestYAML)
	badPath := mustWriteFile(t, dir, "bad.yaml", "schemaVersion: \"0.1\"\nname: bad\nversion: \"0.1.0\"\ncapabilities:\n  - not a capability\n")
	cfgPath := mustWriteFile(t, dir, "eunox.yaml", `
schemaVersion: "0.1"
upstreams:
  - name: good
    transport: stdio
    command: echo
    policy:
      - `+goodPath+`
  - name: broken
    transport: stdio
    command: echo
    policy:
      - `+badPath+`
`)
	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}

	var buf bytes.Buffer
	code := validateConfigRoutes(context.Background(), cfg, false, &buf)
	if code != 2 {
		t.Errorf("aggregate exit code: want 2 (worst of routes), got %d\noutput:\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, `route "good"`) || !strings.Contains(out, `route "broken"`) {
		t.Errorf("output should include both route headers:\n%s", out)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("output should still report OK for the good route:\n%s", out)
	}
	if !strings.Contains(out, "FAIL") {
		t.Errorf("output should report FAIL for the broken route:\n%s", out)
	}
}

// ─── fetchRouteLive transport dispatch ────────────────────────────────────────

// fetchRouteLive's transport switch is small but worth pinning: an unknown
// transport must surface a clear per-route error rather than silently picking a
// default. The hostTransport stdio/http cases are exercised end-to-end by the
// existing live-upstream tests.
func TestFetchRouteLive_UnknownTransportErrors(t *testing.T) {
	u := &config.UpstreamConfig{Name: "weird", Transport: "grpc"}
	_, err := fetchRouteLive(context.Background(), u)
	if err == nil {
		t.Fatal("want error for unknown transport, got nil")
	}
	if !strings.Contains(err.Error(), "unknown transport") || !strings.Contains(err.Error(), "weird") {
		t.Errorf("error should name the bad transport and the route: %v", err)
	}
}

// ─── computeAuditStats + printAuditStats ──────────────────────────────────────
//
// The whole point of splitting the histogram is that a denial recorded under
// audit_only=true was forwarded, not blocked. A pre-split `stats` reporting
// "write_file denied 50×" while running in audit mode misled the operator at
// exactly the moment they needed accurate visibility (staging an allowlist
// before flipping to enforce). These tests pin the bucketing rule.

// statsLine is a one-record audit-line builder for fixture readability. The
// JSON shape mirrors the subset of audit.go's auditRecord that cmdStats reads:
// a tools/call decision carrying the structured target_type/target fields.
func statsLine(decision, tool, code string, auditOnly bool) string {
	ao := ""
	if auditOnly {
		ao = `, "audit_only": true`
	}
	return `{"decision": "` + decision + `", "target_type": "tool", "target": "` + tool + `", "method": "tools/call", "denial_code": "` + code + `"` + ao + "}\n"
}

func TestComputeAuditStats_BucketsByAuditOnly(t *testing.T) {
	// Mixed log: 1 allow, 2 enforced denies (blocked), 3 audit-mode denies
	// (observed). The blocked and observed buckets must NOT collide on the
	// same (target, code) key — that was the pre-split bug.
	log := "" +
		statsLine("allow", "read_file", "", false) +
		statsLine("deny", "write_file", "deny-by-policy", false) +
		statsLine("deny", "write_file", "deny-by-policy", false) +
		statsLine("deny", "write_file", "deny-by-policy", true) +
		statsLine("deny", "write_file", "deny-by-policy", true) +
		statsLine("deny", "delete_file", "no-rule-matched", true)

	got, err := computeAuditStats(strings.NewReader(log))
	if err != nil {
		t.Fatalf("computeAuditStats: %v", err)
	}
	if got.total != 6 || got.allowed != 1 || got.blocked != 2 || got.observed != 3 {
		t.Errorf("totals: got total=%d allowed=%d blocked=%d observed=%d; want 6/1/2/3",
			got.total, got.allowed, got.blocked, got.observed)
	}

	wantBlocked := map[denialKey]int{
		{tool: "tool:write_file", code: "deny-by-policy"}: 2,
	}
	wantObserved := map[denialKey]int{
		{tool: "tool:write_file", code: "deny-by-policy"}:   2,
		{tool: "tool:delete_file", code: "no-rule-matched"}: 1,
	}
	if !equalDenialMap(got.blockedDenials, wantBlocked) {
		t.Errorf("blockedDenials: got %v, want %v", got.blockedDenials, wantBlocked)
	}
	if !equalDenialMap(got.observedDenials, wantObserved) {
		t.Errorf("observedDenials: got %v, want %v", got.observedDenials, wantObserved)
	}
}

func TestComputeAuditStats_SkipsBlankAndMalformed(t *testing.T) {
	log := statsLine("allow", "t", "", false) +
		"\n" + // blank line
		"this is not json\n" +
		statsLine("deny", "t", "c", false)

	got, err := computeAuditStats(strings.NewReader(log))
	if err != nil {
		t.Fatalf("computeAuditStats: %v", err)
	}
	// total counts every non-blank line (including malformed); allowed/denied
	// count only successfully-parsed records.
	if got.total != 3 {
		t.Errorf("total: got %d, want 3 (blank skipped; malformed counted)", got.total)
	}
	if got.allowed != 1 || got.blocked != 1 || got.observed != 0 {
		t.Errorf("counts: got allowed=%d blocked=%d observed=%d; want 1/1/0",
			got.allowed, got.blocked, got.observed)
	}
}

func TestPrintAuditStats_AuditModeIsNotMistakenForBlock(t *testing.T) {
	// All denials are audit-mode. The OBSERVED table must be present; the
	// BLOCKED table must NOT be — otherwise the operator can read "50× denied"
	// and assume the calls were rejected.
	s := auditStatsSummary{
		total:          50,
		allowed:        0,
		blocked:        0,
		observed:       50,
		blockedDenials: map[denialKey]int{},
		observedDenials: map[denialKey]int{
			{tool: "write_file", code: "deny-by-policy"}: 50,
		},
	}
	var buf bytes.Buffer
	printAuditStats(&buf, s)
	out := buf.String()

	if !strings.Contains(out, "OBSERVED DENIALS") {
		t.Errorf("output missing OBSERVED DENIALS header:\n%s", out)
	}
	if strings.Contains(out, "BLOCKED DENIALS") {
		t.Errorf("output should NOT include BLOCKED DENIALS when no enforced denials exist:\n%s", out)
	}
	if !strings.Contains(out, "audit-mode denials") {
		t.Errorf("output should explain that observed denials were forwarded, not blocked:\n%s", out)
	}
	// Summary line must distinguish blocked from observed.
	if !strings.Contains(out, "blocked: 0") || !strings.Contains(out, "observed: 50") {
		t.Errorf("summary line should split blocked vs observed:\n%s", out)
	}
}

func TestPrintAuditStats_MixedBucketsBothTablesAppear(t *testing.T) {
	s := auditStatsSummary{
		total: 3, allowed: 0, blocked: 1, observed: 1,
		blockedDenials:  map[denialKey]int{{tool: "x", code: "c"}: 1},
		observedDenials: map[denialKey]int{{tool: "y", code: "d"}: 1},
	}
	var buf bytes.Buffer
	printAuditStats(&buf, s)
	out := buf.String()
	if !strings.Contains(out, "BLOCKED DENIALS") || !strings.Contains(out, "OBSERVED DENIALS") {
		t.Errorf("output should include both tables when both buckets are non-empty:\n%s", out)
	}
	// Ordering: BLOCKED before OBSERVED so the enforced state is the headline.
	if strings.Index(out, "BLOCKED DENIALS") > strings.Index(out, "OBSERVED DENIALS") {
		t.Errorf("BLOCKED table should appear before OBSERVED:\n%s", out)
	}
}

func TestPrintAuditStats_NoDenials(t *testing.T) {
	s := auditStatsSummary{
		total: 5, allowed: 5,
		blockedDenials:  map[denialKey]int{},
		observedDenials: map[denialKey]int{},
	}
	var buf bytes.Buffer
	printAuditStats(&buf, s)
	out := buf.String()
	if !strings.Contains(out, "No denials recorded.") {
		t.Errorf("output should say no denials recorded:\n%s", out)
	}
}

// TestStatsTarget_LabelPrecedence pins how statsTarget labels a histogram row:
// a typed target_type+target combine into a "type:name" label; when either is
// missing the record's method is used as the label instead.
func TestStatsTarget_LabelPrecedence(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                       string
		targetType, target, method string
		want                       string
	}{
		{"typed tool target", "tool", "write_file", "tools/call", "tool:write_file"},
		{"typed resource target", "resource", "file:///etc", "resources/read", "resource:file:///etc"},
		{"bare target, no type, falls back to method", "", "write_file", "tools/call", "tools/call"},
		{"type without target falls back to method", "tool", "", "tools/call", "tools/call"},
		{"neither set falls back to method", "", "", "prompts/get", "prompts/get"},
		{"all empty", "", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := statsTarget(tc.targetType, tc.target, tc.method); got != tc.want {
				t.Errorf("statsTarget(%q,%q,%q) = %q, want %q",
					tc.targetType, tc.target, tc.method, got, tc.want)
			}
		})
	}
}

func equalDenialMap(a, b map[denialKey]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// ===== merged from audit_envelope_bound_test.go =====

// TestRecordOversizedAgentTaskIDBounded covers AgentID and TaskID: both are
// IdP-supplied JWT claims whose length is not validated, so a misconfigured or
// compromised IdP could stamp a multi-megabyte value and push a single record
// past the 4 MiB audit-verify scanner buffer, breaking HMAC-chain verification.
// They must be bounded like SessionID/Target/Method.
//
// This test stays in package main (not internal/audit) because it exercises the
// real JWT->audit identity wiring (withJWTClaims + auditIdentityFromContext),
// which lives in the binary's JWT layer and cannot be imported by the audit
// package without a cycle. It is a wiring smoke check: a huge claim must surface
// truncated and the record must stay small and verify. The exact per-field
// auditEnvelopeFieldCap bound is asserted against the real constant in the
// internal/audit white-box test (TestRecordBoundsAgentTaskID).
func TestRecordOversizedAgentTaskIDBounded(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := audit.Open(logPath, keyPath, 0, 0, audit.WithIdentity(pdp.AuditIdentityFromContext))
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}

	huge := strings.Repeat("A", 5<<20) // ~5 MiB attacker-controlled JWT claim
	ctx := pdp.WithJWTClaims(context.Background(), &pdp.JWTClaims{AgentID: huge, TaskID: huge})
	sink.RecordAllow(ctx, "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	line := lastNonBlankLine(t, logPath)
	if line == "" {
		t.Fatal("no record written (or the oversized line overflowed the tail window)")
	}
	if len(line) > 1<<20 {
		t.Fatalf("serialized record is %d bytes; AgentID/TaskID were not bounded", len(line))
	}

	// Read the record back through the public JSONL surface and assert the wiring
	// produced a bounded, truncated envelope. The exact cap value is checked against
	// the real constant in the internal/audit white-box test.
	var rec struct {
		AgentID string `json:"agent_id"`
		TaskID  string `json:"task_id"`
	}
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("written record does not parse: %v", err)
	}
	if !strings.Contains(rec.AgentID, "truncated") {
		t.Errorf("expected a truncation marker in AgentID, got %d-byte value", len(rec.AgentID))
	}
	if !strings.Contains(rec.TaskID, "truncated") {
		t.Errorf("expected a truncation marker in TaskID, got %d-byte value", len(rec.TaskID))
	}

	// The record must verify against its own chain HMAC after bounding.
	if ok, err := sink.VerifyRecord([]byte(line)); err != nil || !ok {
		t.Fatalf("oversized-agent/task-id record failed HMAC verification: ok=%v err=%v", ok, err)
	}
}

// lastNonBlankLine returns the last non-blank line of the file at path. It is a
// small package-main reader for the one audit test that stays here; the white-box
// equivalent (mustReadLastAuditLine, exercising the bounded-tail readLastAuditLine)
// lives in internal/audit.
func lastNonBlankLine(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: test-controlled temp dir
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		if len(bytes.TrimSpace(lines[i])) > 0 {
			return string(bytes.TrimSpace(lines[i]))
		}
	}
	return ""
}

// ===== merged from version_usage_test.go =====

func TestCmdVersion_DoesNotPanic(t *testing.T) {
	// cmdVersion writes to os.Stdout; just verify it doesn't panic.
	cmdVersion()
}

func TestPrintUsage_DoesNotPanic(t *testing.T) {
	// printUsage writes to the supplied writer; just verify it doesn't panic.
	printUsage(io.Discard)
}

// ===== merged from operational_resolve_test.go =====

func TestResolveMaxSessions(t *testing.T) {
	tests := []struct {
		name string
		flag int
		cfg  *int
		want int
	}{
		{"no config → flag backstop default", defaultMaxSessions, nil, defaultMaxSessions},
		{"no config → explicit flag", 0, nil, 0},
		{"config overrides flag", defaultMaxSessions, intPtr(50), 50},
		{"config 0 means unlimited, overriding the non-zero flag default", defaultMaxSessions, intPtr(0), 0},
		{"config value wins over an explicit flag too", 100, intPtr(50), 50},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := transport.ResolveMaxSessions(tc.flag, tc.cfg); got != tc.want {
				t.Errorf("ResolveMaxSessions(%d, %v) = %d, want %d", tc.flag, tc.cfg, got, tc.want)
			}
		})
	}
}

// ===== merged from operational_hardening_test.go =====

// -----------------------------------------------------------------
// resolveUpstreamTimeout
// -----------------------------------------------------------------

// -----------------------------------------------------------------
// resolveMaxSessions
// -----------------------------------------------------------------

// -----------------------------------------------------------------
// Config validation for the new listen / audit fields
// -----------------------------------------------------------------

func TestConfigValidation_OperationalFields(t *testing.T) {
	stdioWith := func(mutate func(c *config.GatewayConfig)) *config.GatewayConfig {
		c := &config.GatewayConfig{SchemaVersion: "0.1", Transport: config.HostTransportStdio}
		c.Upstreams = []config.UpstreamConfig{{Name: "u", Transport: config.HostTransportStdio, Command: "true"}}
		mutate(c)
		return c
	}
	httpWith := func(mutate func(c *config.GatewayConfig)) *config.GatewayConfig {
		c := &config.GatewayConfig{SchemaVersion: "0.1", Transport: config.HostTransportHTTP}
		c.Upstreams = []config.UpstreamConfig{{Name: "u", Transport: config.HostTransportHTTP, UpstreamURL: "http://127.0.0.1:1"}}
		mutate(c)
		return c
	}

	tests := []struct {
		name    string
		cfg     *config.GatewayConfig
		wantErr string
	}{
		{"maxSessions rejected under stdio", stdioWith(func(c *config.GatewayConfig) { c.Listen.MaxSessions = intPtr(5) }), "no network listener"},
		{"maxSessions: 0 also rejected under stdio (present key, not 'unlimited')", stdioWith(func(c *config.GatewayConfig) { c.Listen.MaxSessions = intPtr(0) }), "no network listener"},
		{"sessionIdleTimeoutMs rejected under stdio", stdioWith(func(c *config.GatewayConfig) { c.Listen.SessionIdleTimeoutMs = intPtr(5) }), "no network listener"},
		{"sessionIdleTimeoutMs: 0 also rejected under stdio (present key)", stdioWith(func(c *config.GatewayConfig) { c.Listen.SessionIdleTimeoutMs = intPtr(0) }), "no network listener"},
		{"negative maxSessions rejected", httpWith(func(c *config.GatewayConfig) { c.Listen.MaxSessions = intPtr(-1) }), "maxSessions"},
		{"maxSessions: 0 accepted under http (unlimited)", httpWith(func(c *config.GatewayConfig) { c.Listen.MaxSessions = intPtr(0) }), ""},
		{"negative sessionIdleTimeoutMs rejected", httpWith(func(c *config.GatewayConfig) { c.Listen.SessionIdleTimeoutMs = intPtr(-1) }), "sessionIdleTimeoutMs"},
		{"sessionIdleTimeoutMs: 0 accepted under http (no idle reaping)", httpWith(func(c *config.GatewayConfig) { c.Listen.SessionIdleTimeoutMs = intPtr(0) }), ""},
		{"negative retainRotated rejected", httpWith(func(c *config.GatewayConfig) { c.Audit.RetainRotated = intPtr(-1) }), "retainRotated"},
		{"retainRotated: 0 accepted under http (keep all)", httpWith(func(c *config.GatewayConfig) { c.Audit.RetainRotated = intPtr(0) }), ""},
		{"valid http config accepted", httpWith(func(c *config.GatewayConfig) {
			c.Listen.MaxSessions = intPtr(10)
			c.Listen.SessionIdleTimeoutMs = intPtr(60000)
			c.Audit.RetainRotated = intPtr(5)
		}), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate(nil)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestLoadConfig_OperationalKeys verifies the new YAML keys decode through the
// strict loader (KnownFields(true) would reject a mistyped yaml tag) and land on
// the expected fields.
func TestLoadConfig_OperationalKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eunox.yaml")
	doc := `schemaVersion: "0.1"
transport: http
listen:
  port: 3000
  maxSessions: 25
  sessionIdleTimeoutMs: 90000
audit:
  retainRotated: 7
upstreams:
  - name: api
    transport: http
    upstreamUrl: http://127.0.0.1:9000
    enforcement: audit
`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadGatewayConfig(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Listen.MaxSessions == nil || *cfg.Listen.MaxSessions != 25 {
		t.Errorf("maxSessions = %v, want 25", cfg.Listen.MaxSessions)
	}
	if cfg.Listen.SessionIdleTimeoutMs == nil || *cfg.Listen.SessionIdleTimeoutMs != 90000 {
		t.Errorf("sessionIdleTimeoutMs = %v, want 90000", cfg.Listen.SessionIdleTimeoutMs)
	}
	if cfg.Audit.RetainRotated == nil || *cfg.Audit.RetainRotated != 7 {
		t.Errorf("retainRotated = %v, want 7", cfg.Audit.RetainRotated)
	}
}

// -----------------------------------------------------------------
// Audit-log retention
// -----------------------------------------------------------------

// -----------------------------------------------------------------
// /healthz and /metrics
// -----------------------------------------------------------------

// ===== merged from pdp_jwt_mainbound_test.go =====

func TestJWTLeewayOption(t *testing.T) {
	// The flag→Options.Leeway bridge has two legs: jwtLeewayOption maps the flag's
	// "0 = disable" to a negative sentinel (asserted here), and pdp.effectiveLeeway
	// maps that negative to a zero grace (asserted directly by TestEffectiveLeeway in
	// internal/pdp, where effectiveLeeway lives). Together they cover the end-to-end
	// "flag 0 disables the grace" contract without this package reaching into the
	// pdp internal.
	if got := jwtLeewayOption(0); got >= 0 {
		t.Errorf("jwtLeewayOption(0) = %v, want a negative (disabled) value", got)
	}
	if got := jwtLeewayOption(30 * time.Second); got != 30*time.Second {
		t.Errorf("jwtLeewayOption(30s) = %v, want 30s", got)
	}
}

// TestValidateJWTAudienceConfig pins the fail-closed audience requirement for
// --jwks-uri mode: an unpinned aud is refused unless the operator explicitly
// opts out with --jwt-allow-any-audience.
func TestValidateJWTAudienceConfig(t *testing.T) {
	tests := []struct {
		name             string
		jwksURI          string
		audience         string
		allowAnyAudience bool
		wantErr          bool
	}{
		{"jwt mode off is unconstrained", "", "", false, false},
		{"jwt mode off ignores opt-out", "", "", true, false},
		{"jwks with audience is allowed", "https://idp.example/jwks", "eunox", false, false},
		{"jwks without audience fails closed", "https://idp.example/jwks", "", false, true},
		{"jwks without audience but explicit opt-out is allowed", "https://idp.example/jwks", "", true, false},
		{"jwks with audience and opt-out is allowed", "https://idp.example/jwks", "eunox", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateJWTAudienceConfig(tt.jwksURI, tt.audience, tt.allowAnyAudience)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateJWTAudienceConfig(%q, %q, %v) error = %v, wantErr %v",
					tt.jwksURI, tt.audience, tt.allowAnyAudience, err, tt.wantErr)
			}
		})
	}
}

// TestJWTAudienceBypassWarning pins that the audience-bypass warning is keyed on
// the --jwt-allow-any-audience flag, not on whether --jwt-audience is empty. The
// critical regression: with both flags set, the old `jwtAudience == ""`
// condition suppressed the warning even though JWTPDP ignores the configured
// audience and accepts any aud.
func TestJWTAudienceBypassWarning(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		allowAnyAudience bool
		audience         string
		wantWarn         bool
		wantContains     string
	}{
		{"pinning active, no audience", false, "", false, ""},
		{"pinning active, audience set", false, "eunox", false, ""},
		{"bypass with empty audience warns", true, "", true, "disabling cross-service replay protection"},
		{"bypass with audience set still warns and notes pin is ignored", true, "eunox", true, `--jwt-audience "eunox" is ignored`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := jwtAudienceBypassWarning(tt.allowAnyAudience, tt.audience)
			if tt.wantWarn {
				if got == "" {
					t.Fatalf("jwtAudienceBypassWarning(%v, %q) = \"\", want a warning", tt.allowAnyAudience, tt.audience)
				}
				if !strings.Contains(got, tt.wantContains) {
					t.Errorf("warning %q does not contain %q", got, tt.wantContains)
				}
			} else if got != "" {
				t.Errorf("jwtAudienceBypassWarning(%v, %q) = %q, want no warning", tt.allowAnyAudience, tt.audience, got)
			}
		})
	}
}

// TestValidateJWTIssuerConfig pins the fail-closed issuer requirement for
// --jwks-uri mode: an unpinned iss is refused unless the operator explicitly opts
// out with --jwt-allow-any-issuer, so a token from another issuer sharing the JWKS
// endpoint cannot be replayed against eunox.
func TestValidateJWTIssuerConfig(t *testing.T) {
	tests := []struct {
		name           string
		jwksURI        string
		issuer         string
		allowAnyIssuer bool
		wantErr        bool
	}{
		{"jwt mode off is unconstrained", "", "", false, false},
		{"jwt mode off ignores opt-out", "", "", true, false},
		{"jwks with issuer is allowed", "https://idp.example/jwks", "https://idp.example", false, false},
		{"jwks without issuer fails closed", "https://idp.example/jwks", "", false, true},
		{"jwks without issuer but explicit opt-out is allowed", "https://idp.example/jwks", "", true, false},
		{"jwks with issuer and opt-out is allowed", "https://idp.example/jwks", "https://idp.example", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateJWTIssuerConfig(tt.jwksURI, tt.issuer, tt.allowAnyIssuer)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateJWTIssuerConfig(%q, %q, %v) error = %v, wantErr %v",
					tt.jwksURI, tt.issuer, tt.allowAnyIssuer, err, tt.wantErr)
			}
		})
	}
}

// TestJWTIssuerBypassWarning pins that the issuer-bypass warning is keyed on the
// --jwt-allow-any-issuer flag, not on whether --jwt-issuer is empty: with both set,
// JWTPDP ignores the configured issuer and accepts any iss, so the warning must
// still fire and note the configured issuer is ignored.
func TestJWTIssuerBypassWarning(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		allowAnyIssuer bool
		issuer         string
		wantWarn       bool
		wantContains   string
	}{
		{"pinning active, no issuer", false, "", false, ""},
		{"pinning active, issuer set", false, "https://idp.example", false, ""},
		{"bypass with empty issuer warns", true, "", true, "disabling issuer pinning"},
		{"bypass with issuer set still warns and notes pin is ignored", true, "https://idp.example", true, `--jwt-issuer "https://idp.example" is ignored`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := jwtIssuerBypassWarning(tt.allowAnyIssuer, tt.issuer)
			if tt.wantWarn {
				if got == "" {
					t.Fatalf("jwtIssuerBypassWarning(%v, %q) = \"\", want a warning", tt.allowAnyIssuer, tt.issuer)
				}
				if !strings.Contains(got, tt.wantContains) {
					t.Errorf("warning %q does not contain %q", got, tt.wantContains)
				}
			} else if got != "" {
				t.Errorf("jwtIssuerBypassWarning(%v, %q) = %q, want no warning", tt.allowAnyIssuer, tt.issuer, got)
			}
		})
	}
}

// TestValidateJWKSURIScheme pins the fail-closed transport requirement for the
// JWKS endpoint: https is always fine, http is fine only to loopback (no MITM
// surface) unless the operator opts into insecure remote http. A plaintext fetch
// to a remote host would let an attacker swap the key set and forge tokens.
func TestValidateJWKSURIScheme(t *testing.T) {
	tests := []struct {
		name          string
		jwksURI       string
		allowInsecure bool
		wantErr       bool
	}{
		{"jwt mode off is unconstrained", "", false, false},
		{"https is allowed", "https://idp.example/jwks", false, false},
		{"http to localhost is allowed", "http://localhost:8080/jwks", false, false},
		{"http to uppercase LOCALHOST is allowed (host names are case-insensitive)", "http://LOCALHOST:8080/jwks", false, false},
		{"http to mixed-case Localhost is allowed", "http://Localhost/jwks", false, false},
		{"http to localhost with trailing FQDN dot is allowed", "http://localhost./jwks", false, false},
		{"http to 127.0.0.1 is allowed", "http://127.0.0.1:8080/jwks", false, false},
		{"http to ipv6 loopback is allowed", "http://[::1]:8080/jwks", false, false},
		{"http to remote host fails closed", "http://idp.example/jwks", false, true},
		{"http to remote host with opt-in is allowed", "http://idp.example/jwks", true, false},
		{"non-http scheme is rejected", "file:///etc/jwks.json", false, true},
		{"opt-in does not rescue a bad scheme", "ftp://idp.example/jwks", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateJWKSURIScheme(tt.jwksURI, tt.allowInsecure)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateJWKSURIScheme(%q, %v) error = %v, wantErr %v",
					tt.jwksURI, tt.allowInsecure, err, tt.wantErr)
			}
		})
	}
}

func TestValidateOAuthResourceURI(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		wantErr  bool
	}{
		{"empty is allowed (endpoint simply unpublished)", "", false},
		{"valid https URI", "https://proxy.example.com", false},
		{"valid https URI with path", "https://proxy.example.com/mcp", false},
		{"relative URI rejected", "/mcp", true},
		{"scheme-only rejected", "https://", true},
		{"unparseable URI rejected", "https://exa mple.com", true},
		{"embedded double-quote rejected", `https://example.com/"bad`, true},
		{"embedded backslash rejected", `https://example.com/\bad`, true},
		{"plaintext http rejected", "http://proxy.example.com", true},
		{"non-http scheme rejected", "ftp://proxy.example.com", true},
		{"uppercase https accepted", "HTTPS://proxy.example.com", false},
		{"fragment rejected", "https://proxy.example.com/mcp#section", true},
		{"empty trailing fragment rejected", "https://proxy.example.com#", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOAuthURI("--oauth-resource", tt.resource, true)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateOAuthResourceURI(%q) error = %v, wantErr %v", tt.resource, err, tt.wantErr)
			}
		})
	}
}

// TestValidateOAuthAuthzServerURI mirrors TestValidateOAuthResourceURI for the
// authorization-server URI guard. Beyond the absolute-https/host/no-fragment
// checks it additionally rejects a residual ${VAR}/$VAR reference left by an
// unset environment variable, so a literal "${ISSUER}" is never advertised as
// an authorization server in the OAuth metadata document (fail closed).
func TestValidateOAuthAuthzServerURI(t *testing.T) {
	tests := []struct {
		name    string
		server  string
		wantErr bool
	}{
		{"valid https URI", "https://idp.example.com", false},
		{"valid https URI with path", "https://idp.example.com/realms/x", false},
		{"uppercase https accepted", "HTTPS://idp.example.com", false},
		{"residual brace env ref rejected", "${ISSUER}", true},
		{"residual bare env ref rejected", "$ISSUER", true},
		{"plaintext http rejected", "http://idp.example.com", true},
		{"non-http scheme rejected", "ftp://idp.example.com", true},
		{"relative URI rejected", "/realms/x", true},
		{"scheme-only rejected", "https://", true},
		{"fragment rejected", "https://idp.example.com#frag", true},
		// An empty authorization-server URI is NOT allowed (allowEmpty=false): unlike the
		// resource URI, an empty entry would be published as "" in the RFC 9728
		// authorization_servers array, so it must fail closed at startup.
		{"empty rejected", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOAuthURI("oauth authorization server", tt.server, false)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateOAuthAuthzServerURI(%q) error = %v, wantErr %v", tt.server, err, tt.wantErr)
			}
		})
	}
}

// TestContainsEnvRef_DetectsResidualRef pins the residual-env-ref predicate the
// authz-server guard relies on: a literal "${X}" is a residual reference (an
// unset variable left unexpanded), while a fully-expanded https URI is not.
func TestContainsEnvRef_DetectsResidualRef(t *testing.T) {
	if !config.ContainsEnvRef("${X}") {
		t.Errorf("config.ContainsEnvRef(%q) = false, want true (residual env ref)", "${X}")
	}
	if config.ContainsEnvRef("https://idp.example.com") {
		t.Errorf("config.ContainsEnvRef(%q) = true, want false (no env ref)", "https://idp.example.com")
	}
}

// TestJWKSClient_BlocksHTTPSToHTTPRedirect is the regression for the redirect
// hole: validating only the configured JWKS URI is not enough, because a valid
// https endpoint can answer with a 302 to a plaintext remote http URL and the
// key fetch would then happen over a tamperable channel. The JWKS client must
// re-apply the scheme policy to redirect targets and refuse a remote-http hop.
func TestJWKSClient_BlocksHTTPSToHTTPRedirect(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://idp.example.com/jwks", http.StatusFound)
	}))
	defer srv.Close()

	client := newJWKSHTTPClient(false)
	resp, err := client.Get(srv.URL)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected redirect to remote http to be blocked, got nil error")
	}
	if !strings.Contains(err.Error(), "redirect blocked") {
		t.Errorf("error = %v, want it to mention 'redirect blocked'", err)
	}
}

// TestJWKSClient_AllowsLoopbackRedirect confirms the redirect policy is not a
// blanket no-redirect ban: a redirect whose target satisfies the scheme policy
// (here, loopback http) is still followed, so legitimate IdP redirects work.
func TestJWKSClient_AllowsLoopbackRedirect(t *testing.T) {
	t.Parallel()
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwks.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, jwks.URL, http.StatusFound)
	}))
	defer redir.Close()

	client := newJWKSHTTPClient(false)
	resp, err := client.Get(redir.URL)
	if err != nil {
		t.Fatalf("loopback-http redirect should be followed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestJWKSClient_BlocksCrossHostRedirect is the regression for the cross-host redirect
// hole: the scheme check alone passes an https->https hop, so a valid IdP endpoint that
// 30x's the key fetch to an ATTACKER host (an open-redirect or a compromised redirector)
// would substitute the key set and forge capability claims. The client must refuse a
// redirect that leaves the configured host, while still allowing a path/port change on
// the same host.
func TestJWKSClient_BlocksCrossHostRedirect(t *testing.T) {
	t.Parallel()
	client := newJWKSHTTPClient(false)
	orig, _ := http.NewRequest(http.MethodGet, "https://idp.example.com/jwks", http.NoBody)
	via := []*http.Request{orig}

	// Same scheme (https), DIFFERENT host: must be blocked.
	target, _ := http.NewRequest(http.MethodGet, "https://attacker.example.com/jwks", http.NoBody)
	if err := client.CheckRedirect(target, via); err == nil {
		t.Fatal("a same-scheme redirect to a different host must be blocked")
	} else if !strings.Contains(err.Error(), "redirect blocked") {
		t.Errorf("error = %v, want it to mention 'redirect blocked'", err)
	}

	// Same host, different port + path (an IdP relocating its key set): still allowed.
	sameHost, _ := http.NewRequest(http.MethodGet, "https://idp.example.com:8443/keys", http.NoBody)
	if err := client.CheckRedirect(sameHost, via); err != nil {
		t.Fatalf("a same-host redirect (port/path change) must be allowed, got %v", err)
	}

	// Case-insensitive host match.
	caseHost, _ := http.NewRequest(http.MethodGet, "https://IDP.EXAMPLE.COM/jwks", http.NoBody)
	if err := client.CheckRedirect(caseHost, via); err != nil {
		t.Fatalf("a same-host redirect differing only in case must be allowed, got %v", err)
	}

	// A loopback->loopback hop that changes only the host spelling (localhost <->
	// 127.0.0.1) has no on-path attacker surface, so it is allowed even though the
	// hostname string differs — the loopback dev flow depends on it. Loopback http passes
	// the scheme check regardless of --jwks-allow-insecure-http.
	loopbackOrig, _ := http.NewRequest(http.MethodGet, "http://localhost:8080/jwks", http.NoBody)
	loopbackVia := []*http.Request{loopbackOrig}
	loopbackAlias, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:9090/jwks", http.NoBody)
	if err := client.CheckRedirect(loopbackAlias, loopbackVia); err != nil {
		t.Fatalf("a loopback->loopback redirect (localhost->127.0.0.1) must be allowed, got %v", err)
	}
	// The reverse spelling is equally allowed.
	revOrig, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/jwks", http.NoBody)
	rev, _ := http.NewRequest(http.MethodGet, "http://localhost:9090/jwks", http.NoBody)
	if err := client.CheckRedirect(rev, []*http.Request{revOrig}); err != nil {
		t.Fatalf("a loopback->loopback redirect (127.0.0.1->localhost) must be allowed, got %v", err)
	}
	// But a loopback origin redirecting OFF the machine is still blocked: the target host
	// is not loopback, so it leaves the machine and must be refused.
	offMachine, _ := http.NewRequest(http.MethodGet, "https://attacker.example.com/jwks", http.NoBody)
	if err := client.CheckRedirect(offMachine, loopbackVia); err == nil {
		t.Fatal("a loopback->remote redirect must be blocked (it leaves the machine)")
	}
}

// ===== merged from gateway_test.go =====

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
func TestLoadGatewayConfig_ValidAndEnvExpand(t *testing.T) {
	t.Setenv("EUNOX_TEST_TOKEN", "s3kret")
	dir := t.TempDir()
	cfgPath := mustWriteFile(t, dir, "gw.yaml", `
schemaVersion: "0.1"
listen:
  bind: 127.0.0.1
  port: 3100
  authToken: ${EUNOX_TEST_TOKEN}
audit:
  log: /tmp/eunox-test.jsonl
defaults:
  enforcement: audit
  upstreamTimeoutMs: 1234
upstreams:
  - name: fs
    transport: stdio
    command: echo
    args: ["hi"]
  - name: stripe
    transport: http
    upstreamUrl: https://mcp.stripe.com
    upstreamAuthHeader: "Authorization: Bearer x"
    expectVersion: "1.0.0"
`)
	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}
	if cfg.Listen.AuthToken != "s3kret" {
		t.Errorf("env not expanded: authToken=%q", cfg.Listen.AuthToken)
	}
	if cfg.Listen.Port != 3100 {
		t.Errorf("port=%d, want 3100", cfg.Listen.Port)
	}
	if cfg.Defaults.Enforcement != capability.EnforcementAudit || cfg.Defaults.UpstreamTimeoutMs != 1234 {
		t.Errorf("defaults not parsed: %+v", cfg.Defaults)
	}
	if len(cfg.Upstreams) != 2 {
		t.Fatalf("want 2 upstreams, got %d", len(cfg.Upstreams))
	}
	if cfg.Upstreams[0].Name != "fs" || cfg.Upstreams[0].Transport != "stdio" || cfg.Upstreams[0].Command != "echo" {
		t.Errorf("upstream[0] wrong: %+v", cfg.Upstreams[0])
	}
	if cfg.Upstreams[1].ExpectVersion != "1.0.0" || cfg.Upstreams[1].UpstreamURL != "https://mcp.stripe.com" {
		t.Errorf("upstream[1] wrong: %+v", cfg.Upstreams[1])
	}
}

// TestLoadGatewayConfig_EnvExpandPreservesLiteralDollar verifies that env
// expansion substitutes ${VAR}/$VAR when set, but leaves a literal '$' that is not
// an env reference (e.g. "$$", "$5") untouched — os.ExpandEnv would corrupt these,
// silently mangling secrets that contain '$'. (An UNSET reference in
// upstreamAuthHeader is now rejected fail-closed, like listen.authToken — see
// TestLoadGatewayConfig_RejectsUnresolvedUpstreamAuthHeader — so this test uses only
// set references and non-reference literal dollars.)
func TestLoadGatewayConfig_EnvExpandPreservesLiteralDollar(t *testing.T) {
	t.Setenv("EUNOX_TEST_TOKEN", "s3kret")
	dir := t.TempDir()
	cfgPath := mustWriteFile(t, dir, "gw.yaml", `
schemaVersion: "0.1"
listen:
  authToken: ${EUNOX_TEST_TOKEN}
upstreams:
  - name: api
    transport: http
    upstreamUrl: https://api.example
    upstreamAuthHeader: "Authorization: Bearer $EUNOX_TEST_TOKEN-$5-pa$$"
`)
	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}
	if cfg.Listen.AuthToken != "s3kret" {
		t.Errorf("braced ${VAR} not expanded: %q", cfg.Listen.AuthToken)
	}
	// Bare set var expands; "$5" (digit, not an identifier start) survives untouched;
	// and the trailing "$$" is the literal-dollar ESCAPE, so it collapses to one '$'.
	want := "Authorization: Bearer s3kret-$5-pa$"
	if got := cfg.Upstreams[0].UpstreamAuthHeader; got != want {
		t.Errorf("env expansion corrupted value:\n got  %q\n want %q", got, want)
	}
}

// TestLoadGatewayConfig_EnvExpandDollarEscape pins the escape contract: "$$" is a
// literal '$' and consumes both characters, so an identifier following it is NOT a
// reference.
//
// Without the escape a literal '$' was inexpressible, and "pa$$word" — an ordinary
// generated password — silently expanded its second "$word" the moment an unrelated
// environment variable named "word" happened to be set, substituting a value the
// operator never intended into a credential. A bare "$word" still expands; escaping is
// what makes the two distinguishable.
func TestLoadGatewayConfig_EnvExpandDollarEscape(t *testing.T) {
	t.Setenv("word", "EXPANDED")
	dir := t.TempDir()
	cfgPath := mustWriteFile(t, dir, "gw.yaml", `
schemaVersion: "0.1"
listen:
  authToken: "pa$$word"
upstreams:
  - name: api
    transport: http
    upstreamUrl: https://api.example
`)
	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}
	want := "pa$word"
	if got := cfg.Listen.AuthToken; got != want {
		t.Errorf("'$$' must escape to a literal '$' and stop the following identifier from expanding:\n got  %q\n want %q", got, want)
	}
}

// TestLoadGatewayConfig_EnvExpandBareRefStillExpands is the negative control: escaping
// must not have disabled ordinary expansion of an unescaped reference.
func TestLoadGatewayConfig_EnvExpandBareRefStillExpands(t *testing.T) {
	t.Setenv("word", "EXPANDED")
	dir := t.TempDir()
	cfgPath := mustWriteFile(t, dir, "gw.yaml", `
schemaVersion: "0.1"
listen:
  authToken: "pa-$word"
upstreams:
  - name: api
    transport: http
    upstreamUrl: https://api.example
`)
	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}
	if got, want := cfg.Listen.AuthToken, "pa-EXPANDED"; got != want {
		t.Errorf("an unescaped reference must still expand:\n got  %q\n want %q", got, want)
	}
}

// TestLoadGatewayConfig_EnvValueIsLiteralNotYAML pins the high-severity fix: an
// environment value is substituted into the PARSED string field and is never
// re-parsed as YAML. Expanding the raw file text before parsing let a value
// carrying a YAML metacharacter alter the parse — most dangerously "#secret",
// which YAML read as a trailing comment, silently blanking authToken and
// disabling listener auth.
func TestLoadGatewayConfig_EnvValueIsLiteralNotYAML(t *testing.T) {
	cases := []struct {
		name, value string
	}{
		{"leading hash reads as comment", "#secret"},
		{"embedded colon reads as mapping", "a: b"},
		{"leading asterisk reads as alias", "*notanchor"},
		{"trailing spaces get stripped", "tok   "},
		{"flow brace reads as mapping", "{nope}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv forbids t.Parallel(), so these run serially.
			t.Setenv("EUNOX_LITERAL_TOKEN", tc.value)
			cfgPath := mustWriteFile(t, t.TempDir(), "gw.yaml", `
schemaVersion: "0.1"
listen:
  authToken: ${EUNOX_LITERAL_TOKEN}
upstreams:
  - name: api
    transport: http
    upstreamUrl: https://api.example
`)
			cfg, err := config.LoadGatewayConfig(cfgPath)
			if err != nil {
				t.Fatalf("config.LoadGatewayConfig: %v", err)
			}
			if cfg.Listen.AuthToken != tc.value {
				t.Fatalf("authToken = %q, want %q verbatim — an env value must not be re-interpreted as YAML; a blanked token silently disables listener auth", cfg.Listen.AuthToken, tc.value)
			}
		})
	}
}

func TestLoadGatewayConfig_Errors(t *testing.T) {
	cases := []struct {
		name    string
		cfg     string
		wantErr string
	}{
		{"no upstreams", "upstreams: []\n", "at least one upstream"},
		{"empty name", "upstreams:\n  - {transport: stdio, command: x}\n", "'name' is required"},
		{"bad name", "upstreams:\n  - {name: 'a/b', transport: stdio, command: x}\n", "must match"},
		{"dup name", "upstreams:\n  - {name: a, transport: stdio, command: x}\n  - {name: a, transport: stdio, command: y}\n", "duplicate"},
		{"stdio no command", "upstreams:\n  - {name: a, transport: stdio}\n", "requires 'command'"},
		{"stdio with url", "upstreams:\n  - {name: a, transport: stdio, command: x, upstreamUrl: 'http://y'}\n", "not allowed with stdio"},
		{"stdio with auth header", "upstreams:\n  - {name: a, transport: stdio, command: x, upstreamAuthHeader: 'Authorization: Bearer y'}\n", "not allowed with stdio"},
		{"stdio with tls skip", "upstreams:\n  - {name: a, transport: stdio, command: x, upstreamTlsSkipVerify: true}\n", "not allowed with stdio"},
		// Present-but-zero forbidden fields: the schema rejects the *key*, so the
		// loader must too even when the value decodes to a Go zero.
		{"stdio with empty url", "upstreams:\n  - {name: a, transport: stdio, command: x, upstreamUrl: \"\"}\n", "not allowed with stdio"},
		{"stdio with empty auth header", "upstreams:\n  - {name: a, transport: stdio, command: x, upstreamAuthHeader: \"\"}\n", "not allowed with stdio"},
		{"stdio with tls skip false", "upstreams:\n  - {name: a, transport: stdio, command: x, upstreamTlsSkipVerify: false}\n", "not allowed with stdio"},
		{"http no url", "upstreams:\n  - {name: a, transport: http}\n", "requires 'upstreamUrl'"},
		{"http with command", "upstreams:\n  - {name: a, transport: http, upstreamUrl: 'http://y', command: x}\n", "not allowed with http"},
		{"http with args", "upstreams:\n  - {name: a, transport: http, upstreamUrl: 'http://y', args: ['x']}\n", "'args' is not allowed with http"},
		{"http with empty command", "upstreams:\n  - {name: a, transport: http, upstreamUrl: 'http://y', command: \"\"}\n", "'command' is not allowed with http"},
		{"http with empty args", "upstreams:\n  - {name: a, transport: http, upstreamUrl: 'http://y', args: []}\n", "'args' is not allowed with http"},
		{"missing transport", "upstreams:\n  - {name: a, command: x}\n", "'transport' is required"},
		{"bad transport", "upstreams:\n  - {name: a, transport: ftp, command: x}\n", "must be"},
		// Millisecond settings so large they would overflow time.Duration (int64 ns)
		// once scaled by time.Millisecond are refused; config.MaxDurationMs is 9223372036854.
		{"idle timeout overflow", "listen:\n  sessionIdleTimeoutMs: 9223372036855\nupstreams:\n  - {name: a, transport: stdio, command: x}\n", "exceeds the maximum"},
		{"upstream timeout overflow", "defaults:\n  upstreamTimeoutMs: 9223372036855\nupstreams:\n  - {name: a, transport: stdio, command: x}\n", "exceeds the maximum"},
		// A trailing "---" document must be rejected, not silently ignored.
		{"multiple documents", "upstreams:\n  - {name: a, transport: stdio, command: x}\n---\nupstreams: []\n", "multiple YAML documents"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Inject a valid schemaVersion so each case reaches its intended
			// structural error; the schemaVersion gate is covered separately by
			// TestLoadGatewayConfig_SchemaVersion.
			p := mustWriteFile(t, t.TempDir(), "gw.yaml", "schemaVersion: \"0.1\"\n"+tc.cfg)
			_, err := config.LoadGatewayConfig(p)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestLoadGatewayConfig_PresentZeroAllowedFields guards that presence-based
// rejection of cross-transport fields does not over-reach: an empty
// but present `args: []` is legal on a stdio route (args belongs to stdio), and a
// stdio route that simply omits the HTTP-only fields still loads.
func TestLoadGatewayConfig_PresentZeroAllowedFields(t *testing.T) {
	t.Parallel()
	p := mustWriteFile(t, t.TempDir(), "gw.yaml",
		"schemaVersion: \"0.1\"\nupstreams:\n  - {name: a, transport: stdio, command: echo, args: []}\n")
	cfg, err := config.LoadGatewayConfig(p)
	if err != nil {
		t.Fatalf("stdio with empty args should load, got %v", err)
	}
	if cfg.Upstreams[0].Args == nil || len(cfg.Upstreams[0].Args) != 0 {
		t.Errorf("args should decode to a present empty slice, got %#v", cfg.Upstreams[0].Args)
	}
}
func TestLoadGatewayConfig_SchemaVersion(t *testing.T) {
	base := "upstreams:\n  - {name: a, transport: stdio, command: echo}\n"
	cases := []struct {
		name, prefix, wantErr string
	}{
		{"valid 0.1", "schemaVersion: \"0.1\"\n", ""},
		{"absent", "", "'schemaVersion' is required"},
		{"unsupported", "schemaVersion: \"9.9\"\n", "unsupported gateway config schemaVersion"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := mustWriteFile(t, t.TempDir(), "gw.yaml", tc.prefix+base)
			_, err := config.LoadGatewayConfig(p)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want load to succeed, got %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
func TestBuildRoutes_ExpectVersionMismatchIsFatal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifest := mustWriteFile(t, dir, "m.yaml", "schemaVersion: \"0.1\"\nname: test\nversion: \"1.2.3\"\ncapabilities: []\n")
	cfg := &config.GatewayConfig{Upstreams: []config.UpstreamConfig{{
		Name: "fs", Transport: "stdio", Command: "echo",
		Policy: []string{manifest}, ExpectVersion: "9.9.9",
	}}}
	_, err := transport.BuildRoutes(cfg, nil, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), false, drift.MakeDriftCheck)
	if err == nil || !strings.Contains(err.Error(), "does not match pinned expectVersion") {
		t.Errorf("want version-mismatch error, got %v", err)
	}
}
func TestBuildRoutes_ExpectVersionWithoutPolicy(t *testing.T) {
	t.Parallel()
	// Audit mode clears the SEC-05 fail-closed guard so the route reaches the
	// expectVersion validation in loadUpstreamPDP — an expectVersion pin with no
	// manifest to pin against is its own error, independent of enforcement mode.
	cfg := &config.GatewayConfig{Upstreams: []config.UpstreamConfig{{
		Name: "fs", Transport: "stdio", Command: "echo",
		Enforcement: capability.EnforcementAudit, ExpectVersion: "1.0.0",
	}}}
	_, err := transport.BuildRoutes(cfg, nil, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), false, drift.MakeDriftCheck)
	if err == nil || !strings.Contains(err.Error(), "expectVersion") {
		t.Errorf("want expectVersion-without-policy error, got %v", err)
	}
}

// TestNoPolicyStartupRejection_StrictDriftMessageDependsOnAuditMode is a
// regression: when a policyless route has strictDrift AND enforcement is not
// audit, removing strictDrift alone would not let the gateway boot (the no-policy
// non-audit guard still fires), so the message must name both barriers rather than
// suggesting "remove strictDrift" as a standalone fix.
func TestNoPolicyStartupRejection_StrictDriftMessageDependsOnAuditMode(t *testing.T) {
	t.Parallel()
	strict := true

	// strictDrift + enforce (default): both barriers named.
	enforceCfg := &config.GatewayConfig{}
	uEnforce := &config.UpstreamConfig{Name: "fs", Transport: "stdio", Command: "echo", StrictDrift: &strict}
	msg := enforceCfg.NoPolicyStartupRejection(uEnforce)
	if !strings.Contains(msg, "strictDrift") || !strings.Contains(msg, `enforcement is not "audit"`) {
		t.Errorf("with enforce mode the message must name both barriers, got %q", msg)
	}

	// strictDrift + audit: removing strictDrift would suffice, so the original
	// single-fix suggestion stands.
	auditCfg := &config.GatewayConfig{Defaults: config.RouteDefaults{Enforcement: capability.EnforcementAudit}}
	uAudit := &config.UpstreamConfig{Name: "fs", Transport: "stdio", Command: "echo", StrictDrift: &strict}
	msg = auditCfg.NoPolicyStartupRejection(uAudit)
	if !strings.Contains(msg, "remove 'strictDrift'") || strings.Contains(msg, `enforcement is not "audit"`) {
		t.Errorf("with audit mode the message should offer the standalone strictDrift fix, got %q", msg)
	}
}

// TestValidate_ExpectVersionMultiPolicyRejected is a regression: the
// config-validation layer (which backs the `validate` and `doctor` subcommands)
// must reject expectVersion alongside multiple policy files, matching the guard
// loadUpstreamPDP already applies at real startup. Otherwise `validate` green-lights
// a config the proxy would refuse to start, and the operator's version pin silently
// tracks only the first file's version.
func TestValidate_ExpectVersionMultiPolicyRejected(t *testing.T) {
	t.Parallel()
	cfg := &config.GatewayConfig{SchemaVersion: "0.1", Upstreams: []config.UpstreamConfig{{
		Name: "stripe", Transport: "http", UpstreamURL: "https://mcp.stripe.com",
		Policy: []string{"a.yaml", "b.yaml"}, ExpectVersion: "1.0.0",
	}}}
	err := cfg.Validate(nil)
	if err == nil || !strings.Contains(err.Error(), "single policy file") {
		t.Errorf("want single-policy-file rejection from Validate, got %v", err)
	}

	// A single policy file with expectVersion is the supported case and must pass
	// config validation (the version match itself is checked later, at load time).
	cfgOK := &config.GatewayConfig{SchemaVersion: "0.1", Upstreams: []config.UpstreamConfig{{
		Name: "stripe", Transport: "http", UpstreamURL: "https://mcp.stripe.com",
		Policy: []string{"a.yaml"}, ExpectVersion: "1.0.0",
	}}}
	if err := cfgOK.Validate(nil); err != nil {
		t.Errorf("single-file expectVersion must pass Validate, got %v", err)
	}
}

// TestBuildRoutes_ExpectVersionMultiPolicyRejected: a version pin over multiple
// merged policy files is ambiguous (merged.Version is only the first file's), so
// the combination is rejected rather than giving false assurance.
func TestBuildRoutes_ExpectVersionMultiPolicyRejected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m1 := mustWriteFile(t, dir, "m1.yaml", "schemaVersion: \"0.1\"\nname: a\nversion: \"1.2.3\"\ncapabilities: []\n")
	m2 := mustWriteFile(t, dir, "m2.yaml", "schemaVersion: \"0.1\"\nname: b\nversion: \"1.2.3\"\ncapabilities: []\n")
	cfg := &config.GatewayConfig{Upstreams: []config.UpstreamConfig{{
		Name: "fs", Transport: "stdio", Command: "echo",
		Policy: []string{m1, m2}, ExpectVersion: "1.2.3",
	}}}
	_, err := transport.BuildRoutes(cfg, nil, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), false, drift.MakeDriftCheck)
	if err == nil || !strings.Contains(err.Error(), "multiple policy files") {
		t.Errorf("want multiple-policy-files rejection, got %v", err)
	}
}

// TestBuildRoutes_NoPolicyEnforce_FailsClosed verifies the SEC-05 fail-closed
// guard: a route with no 'policy:' and no 'enforcement: audit' is a
// misconfiguration, so BuildRoutes refuses to start rather than silently
// allowing every call unenforced.
func TestBuildRoutes_NoPolicyEnforce_FailsClosed(t *testing.T) {
	t.Parallel()
	cfg := &config.GatewayConfig{Upstreams: []config.UpstreamConfig{{Name: "fs", Transport: "stdio", Command: "echo"}}}
	routes, err := transport.BuildRoutes(cfg, nil, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), false, drift.MakeDriftCheck)
	if err == nil {
		t.Fatalf("want startup error for policyless non-audit route, got routes=%v", routes)
	}
	if !strings.Contains(err.Error(), "no policy configured") || !strings.Contains(err.Error(), "fs") {
		t.Errorf("error should name the route and the missing policy, got: %v", err)
	}
}

// TestBuildRoutes_SamplingOptInOnHTTPUpstreamRejected: a system:sampling/createMessage
// opt-in cannot be enforced for a remote HTTP upstream (eunox never reads its
// server-initiated requests), so loading one fails closed rather than shipping a
// silently inert grant.
func TestBuildRoutes_SamplingOptInOnHTTPUpstreamRejected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m := mustWriteFile(t, dir, "m.yaml",
		"schemaVersion: \"0.1\"\nname: s\nversion: \"1.0.0\"\ncapabilities:\n  - target: \"system:sampling/createMessage\"\n    actions: [\"allow\"]\n")
	cfg := &config.GatewayConfig{Upstreams: []config.UpstreamConfig{{
		Name: "remote", Transport: "http", UpstreamURL: "https://example.test",
		Policy: []string{m},
	}}}
	_, err := transport.BuildRoutes(cfg, nil, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), false, drift.MakeDriftCheck)
	if err == nil || !strings.Contains(err.Error(), "sampling") {
		t.Fatalf("want sampling-unenforceable rejection for an http upstream, got %v", err)
	}
	if !strings.Contains(err.Error(), "remote") {
		t.Errorf("error should name the upstream, got %v", err)
	}
}

// TestBuildRoutes_SamplingOptInOnStdioUpstreamAllowed: the same opt-in builds
// fine for a stdio upstream, where server-initiated sampling IS enforced.
func TestBuildRoutes_SamplingOptInOnStdioUpstreamAllowed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m := mustWriteFile(t, dir, "m.yaml",
		"schemaVersion: \"0.1\"\nname: s\nversion: \"1.0.0\"\ncapabilities:\n  - target: \"system:sampling/createMessage\"\n    actions: [\"allow\"]\n")
	cfg := &config.GatewayConfig{Upstreams: []config.UpstreamConfig{{
		Name: "local", Transport: "stdio", Command: "echo",
		Policy: []string{m},
	}}}
	if _, err := transport.BuildRoutes(cfg, nil, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), false, drift.MakeDriftCheck); err != nil {
		t.Fatalf("stdio upstream with a sampling opt-in should build, got %v", err)
	}
}

// TestServeHTTPGateway_AuthTokenAndJWKSMutuallyExclusive verifies that
// configuring both listen.authToken and --jwks-uri fails closed at startup,
// since the static token check would otherwise reject every IdP JWT.
func TestServeHTTPGateway_AuthTokenAndJWKSMutuallyExclusive(t *testing.T) {
	t.Parallel()
	cfg := &config.GatewayConfig{
		Upstreams: []config.UpstreamConfig{{Name: "fs", Transport: "stdio", Command: "echo", Enforcement: capability.EnforcementAudit}},
	}
	cfg.Listen.AuthToken = "static-secret"
	cfg.Listen.OAuthResource = "https://proxy.example.com"
	pf := proxyFlags{jwksURI: "https://idp.example/jwks", jwtAllowAnyAudience: true, jwtAllowAnyIssuer: true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := serveHTTPGateway(ctx, cfg, nil, callcounter.NewInMemory(), nil, killswitch.NewInMemory(), pf)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusivity error for authToken + jwks-uri, got %v", err)
	}
}

var schemaPath = filepath.Join("..", "..", "schemas", "eunox-gateway-config.schema.json")

func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema %s: %v", schemaPath, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	return doc
}
func TestGatewaySchema_WellFormed(t *testing.T) {
	t.Parallel()
	doc := loadSchema(t)
	for _, key := range []string{"$schema", "$id", "title", "type", "properties"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("schema missing top-level %q", key)
		}
	}
	if doc["type"] != "object" {
		t.Errorf(`schema "type" = %v, want "object"`, doc["type"])
	}
	if doc["additionalProperties"] != false {
		t.Errorf(`schema "additionalProperties" = %v, want false`, doc["additionalProperties"])
	}
}

// TestGatewaySchema_ExpectVersionPattern asserts the value-level behavior of the
// `expectVersion` regex the schema publishes: a well-formed three-part semver core
// matches, and anything else (pre-release/build suffix, missing/extra component, v
// prefix, leading zero, surrounding whitespace) is rejected at author time. The
// loader itself does not run JSON-Schema validation, so this compiles the pattern
// the schema declares and exercises it directly rather than pulling in a
// json-schema dependency. The accepted form mirrors the strict semverRe the
// manifest loader enforces on `version`, so an author-time pin and the runtime it
// pins against agree on what a valid version string looks like.
func TestGatewaySchema_ExpectVersionPattern(t *testing.T) {
	t.Parallel()
	doc := loadSchema(t)
	node := schemaObjectAt(t, doc, "$defs", "upstream", "properties", "expectVersion")
	pat, ok := node["pattern"].(string)
	if !ok {
		t.Fatal("expectVersion has no string \"pattern\"")
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		t.Fatalf("expectVersion pattern is not a valid regexp: %v", err)
	}
	valid := []string{"0.0.0", "0.1.0", "1.2.3", "10.20.30", "1.0.0"}
	invalid := []string{
		"1.2.3-rc",    // pre-release suffix
		"1.2.3+build", // build metadata
		"1.2",         // missing patch
		"1.2.3.4",     // extra component
		"v1.2.3",      // v prefix
		"01.2.3",      // leading zero (major)
		"1.02.3",      // leading zero (minor)
		"1.2.03",      // leading zero (patch)
		"1.2.3 ",      // trailing whitespace
		" 1.2.3",      // leading whitespace
		"1.2.x",       // non-numeric component
		"",            // empty
	}
	for _, v := range valid {
		if !re.MatchString(v) {
			t.Errorf("expectVersion pattern rejected valid version %q", v)
		}
	}
	for _, v := range invalid {
		if re.MatchString(v) {
			t.Errorf("expectVersion pattern accepted invalid version %q", v)
		}
	}
}

// TestGatewaySchema_MatchesStructs guards against drift between the Go config
// structs (the source of truth the loader actually parses) and the published
// JSON Schema (what editors and CI validate against).
//
// The earlier version of this test flattened every yaml tag and every schema
// property into two GLOBAL name sets and diffed names only. That is blind to the
// the drift issue was about: a field can sit on the wrong PARENT object, or a
// property's type/enum/required can diverge — and a flat name-set comparison sees
// none of it (a name present anywhere matches a name present anywhere). This
// version asserts the per-object, PARENT-QUALIFIED property set for each object
// node, so a field on the wrong parent is caught. The companion
// TestGatewaySchema_EveryObjectForbidsAdditionalProperties covers the
// additionalProperties:false invariant the old flat check also missed.
func TestGatewaySchema_MatchesStructs(t *testing.T) {
	t.Parallel()
	doc := loadSchema(t)

	// Parent-qualified property sets the loader actually parses, keyed by a path
	// that mirrors the schema's object tree. defaults and each upstream resolve
	// through a $ref, so they get their own qualified node.
	wantByObject := map[string]map[string]bool{
		"root":         yamlTagSet(reflect.TypeOf(config.GatewayConfig{})),
		"listen":       yamlTagSet(fieldType(t, config.GatewayConfig{}, "Listen")),
		"audit":        yamlTagSet(fieldType(t, config.GatewayConfig{}, "Audit")),
		"defaults":     yamlTagSet(reflect.TypeOf(config.RouteDefaults{})),
		"upstreams[*]": yamlTagSet(reflect.TypeOf(config.UpstreamConfig{})),
	}

	// Parent-qualified property sets the schema declares, navigated with $ref
	// resolution so defaults/upstream items map to the same logical objects.
	gotByObject := map[string]map[string]bool{
		"root":         schemaPropSet(t, doc, doc),
		"listen":       schemaPropSet(t, doc, schemaObjectAt(t, doc, "properties", "listen")),
		"audit":        schemaPropSet(t, doc, schemaObjectAt(t, doc, "properties", "audit")),
		"defaults":     schemaPropSet(t, doc, schemaObjectAt(t, doc, "properties", "defaults")),
		"upstreams[*]": schemaPropSet(t, doc, schemaObjectAt(t, doc, "properties", "upstreams", "items")),
	}

	for _, obj := range []string{"root", "listen", "audit", "defaults", "upstreams[*]"} {
		want, got := wantByObject[obj], gotByObject[obj]
		if missing := diffKeys(want, got); len(missing) > 0 {
			t.Errorf("object %q: struct fields missing from schema (add them under the right parent in schemas/eunox-gateway-config.schema.json): %v", obj, missing)
		}
		if extra := diffKeys(got, want); len(extra) > 0 {
			t.Errorf("object %q: schema properties with no matching struct field on this object (stale, typo'd, or on the wrong parent): %v", obj, extra)
		}
	}
}

// TestGatewaySchema_EnumsRequiredAndPatterns deepens the name-only struct/schema
// drift guard (TestGatewaySchema_MatchesStructs) by pinning the schema's
// value-level constraints — the enum sets, required arrays, and string patterns —
// that the loader also enforces. A name-only check is blind to an enum gaining or
// losing a member, a required field being dropped, or a pattern being loosened.
// Where the accepted values are exported constants the loader/validator actually
// uses (the host/upstream transport and the per-constraint enforcement mode), the
// schema enum is cross-checked against those constants, so the schema and the code
// cannot drift apart. The remaining literals (the grammar version, the required
// arrays, and the name/semver patterns) are pinned here and pinned independently
// by the loader tests, so a one-sided change to either side trips a test.
func TestGatewaySchema_EnumsRequiredAndPatterns(t *testing.T) {
	t.Parallel()
	doc := loadSchema(t)
	upstream := resolveRef(t, doc, schemaObjectAt(t, doc, "properties", "upstreams", "items"))
	defaults := resolveRef(t, doc, schemaObjectAt(t, doc, "properties", "defaults"))

	// Required arrays. Source of truth: the loader's GatewayConfig.Validate
	// (top-level schemaVersion + non-empty upstreams) and per-upstream checks.
	assertSchemaStringSet(t, "root.required", schemaStringList(t, doc, "required"),
		[]string{"schemaVersion", "upstreams"})
	assertSchemaStringSet(t, "upstream.required", schemaStringList(t, upstream, "required"),
		[]string{"name", "transport"})

	// Grammar version. Source of truth:
	// internal/config/schema_version.go supportedGatewaySchemaVersions.
	assertSchemaStringSet(t, "schemaVersion.enum",
		schemaStringList(t, schemaObjectAt(t, doc, "properties", "schemaVersion"), "enum"),
		[]string{"0.1"})

	// transport enums cross-checked against the exported host-transport constants.
	assertSchemaStringSet(t, "root.transport.enum",
		schemaStringList(t, schemaObjectAt(t, doc, "properties", "transport"), "enum"),
		[]string{"", config.HostTransportStdio, config.HostTransportHTTP})
	assertSchemaStringSet(t, "upstream.transport.enum",
		schemaStringList(t, schemaObjectAt(t, upstream, "properties", "transport"), "enum"),
		[]string{config.HostTransportStdio, config.HostTransportHTTP})

	// enforcement enums cross-checked against the exported enforcement-mode
	// constants ("" defaults to enforce).
	wantEnforce := []string{"", capability.EnforcementEnforce, capability.EnforcementAudit}
	assertSchemaStringSet(t, "defaults.enforcement.enum",
		schemaStringList(t, schemaObjectAt(t, defaults, "properties", "enforcement"), "enum"),
		wantEnforce)
	assertSchemaStringSet(t, "upstream.enforcement.enum",
		schemaStringList(t, schemaObjectAt(t, upstream, "properties", "enforcement"), "enum"),
		wantEnforce)

	// Patterns: the route-name grammar and the upstream version pin, enforced by
	// the loader (routeNameRe / expectVersion validation).
	assertSchemaPattern(t, "upstream.name.pattern",
		schemaObjectAt(t, upstream, "properties", "name"), `^[a-zA-Z0-9_-]+$`)
	assertSchemaPattern(t, "upstream.expectVersion.pattern",
		schemaObjectAt(t, upstream, "properties", "expectVersion"),
		`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$`)
}

// schemaStringList reads a string array (an enum or required block) under key from
// a schema node, failing the test if it is absent or holds a non-string element.
func schemaStringList(t *testing.T, node map[string]any, key string) []string {
	t.Helper()
	raw, ok := node[key].([]any)
	if !ok {
		t.Fatalf("schema node is missing string-array %q (got %T)", key, node[key])
	}
	out := make([]string, 0, len(raw))
	for i, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("schema %q[%d] is %T, want string", key, i, v)
		}
		out = append(out, s)
	}
	return out
}

// assertSchemaStringSet fails when got and want differ as sets (order-independent),
// reporting the label so a drifted enum/required block names itself.
func assertSchemaStringSet(t *testing.T, label string, got, want []string) {
	t.Helper()
	gset, wset := map[string]bool{}, map[string]bool{}
	for _, s := range got {
		gset[s] = true
	}
	for _, s := range want {
		wset[s] = true
	}
	if !reflect.DeepEqual(gset, wset) {
		t.Errorf("%s = %v, want %v (schema and loader/constants drifted)", label, got, want)
	}
}

// assertSchemaPattern fails when node's "pattern" string differs from want.
func assertSchemaPattern(t *testing.T, label string, node map[string]any, want string) {
	t.Helper()
	got, ok := node["pattern"].(string)
	if !ok {
		t.Fatalf("%s: schema node has no string \"pattern\"", label)
	}
	if got != want {
		t.Errorf("%s = %q, want %q", label, got, want)
	}
}

// TestGatewaySchema_EveryObjectForbidsAdditionalProperties asserts that every
// object node in the schema that declares "properties" also sets
// "additionalProperties": false. The loader decodes with yaml.KnownFields(true),
// so an unknown key at ANY level is a hard error; a "properties" block that
// forgot "additionalProperties": false would silently accept keys the loader
// rejects. The old flat name-set parity check could never have caught this.
func TestGatewaySchema_EveryObjectForbidsAdditionalProperties(t *testing.T) {
	t.Parallel()
	var offenders []string
	var walk func(path string, node map[string]any)
	walk = func(path string, node map[string]any) {
		if props, ok := node["properties"].(map[string]any); ok {
			// Only a genuine object DEFINITION (type: object) must seal itself with
			// additionalProperties:false. An if/then/else (or anyOf/oneOf) fragment
			// also carries a "properties" block, but it is a PARTIAL constraint
			// layered onto a base object — sealing it would forbid every property the
			// base defines but the branch does not restate, breaking validation. Such
			// fragments declare no "type": "object", which is exactly how we tell them
			// apart from the real object nodes (root, listen, audit, $defs entries).
			if node["type"] == "object" && node["additionalProperties"] != false {
				offenders = append(offenders, path)
			}
			keys := make([]string, 0, len(props))
			for k := range props {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if child, ok := props[k].(map[string]any); ok {
					walk(path+"."+k, child)
				}
			}
		}
		// Descend through schema combinators and $defs so nested object nodes
		// (items, then-branches, $defs entries) are also checked.
		for _, key := range []string{"$defs", "items", "if", "then", "else", "not"} {
			if child, ok := node[key].(map[string]any); ok {
				walk(path+"."+key, child)
			}
		}
		for _, key := range []string{"allOf", "anyOf", "oneOf"} {
			if arr, ok := node[key].([]any); ok {
				for i, raw := range arr {
					if child, ok := raw.(map[string]any); ok {
						walk(fmt.Sprintf("%s.%s[%d]", path, key, i), child)
					}
				}
			}
		}
	}
	walk("root", loadSchema(t))
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("every object node with a \"properties\" block must set \"additionalProperties\": false "+
			"(the loader rejects unknown keys at every level); missing on: %v", offenders)
	}
}

// yamlTagSet returns the set of first-segment yaml tag names declared directly on
// ty (no recursion into nested structs — each object is validated as its own
// node, so a nested struct's fields belong to that node, not this one).
func yamlTagSet(ty reflect.Type) map[string]bool {
	for ty.Kind() == reflect.Pointer || ty.Kind() == reflect.Slice || ty.Kind() == reflect.Array {
		ty = ty.Elem()
	}
	out := map[string]bool{}
	if ty.Kind() != reflect.Struct {
		return out
	}
	for i := 0; i < ty.NumField(); i++ {
		tag := ty.Field(i).Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		if name := strings.Split(tag, ",")[0]; name != "" {
			out[name] = true
		}
	}
	return out
}

// fieldType returns the type of the named struct field on v (used for the inline
// anonymous-struct fields Listen and Audit, which have no named type).
func fieldType(t *testing.T, v any, field string) reflect.Type {
	t.Helper()
	f, ok := reflect.TypeOf(v).FieldByName(field)
	if !ok {
		t.Fatalf("struct %T has no field %q", v, field)
	}
	return f.Type
}

// schemaObjectAt navigates node by successive object keys and returns the
// map[string]any at the leaf, failing the test if any segment is absent or not an
// object.
func schemaObjectAt(t *testing.T, node map[string]any, path ...string) map[string]any {
	t.Helper()
	cur := node
	for _, k := range path {
		next, ok := cur[k].(map[string]any)
		if !ok {
			t.Fatalf("schema path %v: %q is absent or not an object", path, k)
		}
		cur = next
	}
	return cur
}

// resolveRef follows a "$ref" of the form "#/$defs/<name>" to the referenced
// object, or returns node unchanged when it carries no "$ref".
func resolveRef(t *testing.T, root, node map[string]any) map[string]any {
	t.Helper()
	ref, ok := node["$ref"].(string)
	if !ok {
		return node
	}
	const prefix = "#/$defs/"
	if !strings.HasPrefix(ref, prefix) {
		t.Fatalf("unsupported $ref %q (only #/$defs/<name> is handled)", ref)
	}
	return schemaObjectAt(t, root, "$defs", strings.TrimPrefix(ref, prefix))
}

// schemaPropSet returns the property-name set declared under node's "properties"
// block ($ref resolved first), plus the transport-specific properties contributed
// by node's allOf then/else branches. A "<field>": false entry FORBIDS the
// property on that branch (the cross-transport guard) and is therefore not counted
// as a declared property.
func schemaPropSet(t *testing.T, root, node map[string]any) map[string]bool {
	t.Helper()
	node = resolveRef(t, root, node)
	out := map[string]bool{}
	addProps := func(n map[string]any) {
		props, ok := n["properties"].(map[string]any)
		if !ok {
			return
		}
		for k, v := range props {
			if v == false {
				continue // forbidden-on-this-branch, not a real property
			}
			out[k] = true
		}
	}
	addProps(node)
	if allOf, ok := node["allOf"].([]any); ok {
		for _, raw := range allOf {
			branch, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			for _, key := range []string{"then", "else"} {
				if sub, ok := branch[key].(map[string]any); ok {
					addProps(sub)
				}
			}
		}
	}
	return out
}

// TestGatewaySchema_DurationBoundsMatchLoader pins the schema's millisecond
// duration bounds to the loader's validation. The upper `maximum` must match
// config.MaxDurationMs — the two are independent literals (the schema hard-codes
// 9223372036854; the loader derives int64(math.MaxInt64)/int64(time.Millisecond))
// — and the lower `minimum` must be 0, matching the loader's up-front rejection of a
// negative value for each field (e.g. "defaults.upstreamTimeoutMs -1 must not be
// negative"). Without a schema-side minimum, editor/CI schema validation would
// accept a config the loader rejects at runtime. TestGatewaySchema_MatchesStructs
// checks only field-name parity, so without this test a bound drifting out of
// lockstep with the Go validation (in either direction) would go unnoticed.
func TestGatewaySchema_DurationBoundsMatchLoader(t *testing.T) {
	t.Parallel()
	doc := loadSchema(t)
	cases := []struct {
		name    string
		maxPath []string
		minPath []string
	}{
		{
			"listen.sessionIdleTimeoutMs",
			[]string{"properties", "listen", "properties", "sessionIdleTimeoutMs", "maximum"},
			[]string{"properties", "listen", "properties", "sessionIdleTimeoutMs", "minimum"},
		},
		// defaults is a $ref to #/$defs/routeDefaults, so the field lives under $defs.
		{
			"defaults.upstreamTimeoutMs",
			[]string{"$defs", "routeDefaults", "properties", "upstreamTimeoutMs", "maximum"},
			[]string{"$defs", "routeDefaults", "properties", "upstreamTimeoutMs", "minimum"},
		},
	}
	for _, tc := range cases {
		if got, ok := schemaNumberAt(doc, tc.maxPath); !ok {
			t.Errorf("%s: no numeric %q at %v", tc.name, "maximum", tc.maxPath)
		} else if int64(got) != config.MaxDurationMs {
			t.Errorf("%s maximum = %d, want config.MaxDurationMs (%d) — schema and loader have drifted", tc.name, int64(got), config.MaxDurationMs)
		}
		if got, ok := schemaNumberAt(doc, tc.minPath); !ok {
			t.Errorf("%s: no numeric %q at %v — the loader rejects a negative value here, so the schema must assert minimum: 0 too", tc.name, "minimum", tc.minPath)
		} else if got != 0 {
			t.Errorf("%s minimum = %g, want 0 — the loader rejects a negative value", tc.name, got)
		}
	}
}

// schemaNumberAt navigates a decoded JSON Schema by successive object keys and
// returns the float64 at the leaf (JSON numbers decode as float64), or false if
// the path is absent or the leaf is not a number.
func schemaNumberAt(doc map[string]any, path []string) (float64, bool) {
	var cur any = doc
	for _, k := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return 0, false
		}
		if cur, ok = m[k]; !ok {
			return 0, false
		}
	}
	f, ok := cur.(float64)
	return f, ok
}

// TestLoadGatewayConfig_RejectsUnknownFields verifies the loader is strict, so
// the schema's "additionalProperties": false is also enforced at runtime — a
// typo'd key fails loudly instead of being silently dropped.
func TestLoadGatewayConfig_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	// Each fixture declares a SUPPORTED schemaVersion so the unknown-field error is
	// what surfaces. The loader gates the declared grammar version first (mirroring the
	// manifest loader), so a config omitting schemaVersion would be rejected for that
	// instead — correctly, but it would stop this test from covering strictness.
	cases := map[string]string{
		"unknown top-level key": "schemaVersion: \"0.1\"\nbogusTopLevel: 1\nupstreams:\n  - {name: a, transport: stdio, command: echo}\n",
		"unknown upstream key":  "schemaVersion: \"0.1\"\nupstreams:\n  - {name: a, transport: stdio, command: echo, comand: echo}\n",
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := mustWriteFile(t, t.TempDir(), "gw.yaml", cfg)
			_, err := config.LoadGatewayConfig(p)
			if err == nil || !strings.Contains(err.Error(), "not found") {
				t.Errorf("want unknown-field error, got %v", err)
			}
		})
	}
}

// TestGatewaySchema_TransportSpecificFields guards that the JSON Schema forbids
// the same cross-transport fields the runtime loader rejects (see
// TestLoadGatewayConfig_Errors): a stdio route must not carry HTTP-only options,
// and an http route must not carry stdio-only command/args. Without this the
// schema can pass a config the loader rejects (or vice versa) — the inconsistency
// tracked here. Keeps the schema in lockstep with config.GatewayConfig.validate.
func TestGatewaySchema_TransportSpecificFields(t *testing.T) {
	t.Parallel()
	defs, ok := loadSchema(t)["$defs"].(map[string]any)
	if !ok {
		t.Fatal("schema missing $defs")
	}
	upstream, ok := defs["upstream"].(map[string]any)
	if !ok {
		t.Fatal("schema missing $defs.upstream")
	}
	allOf, ok := upstream["allOf"].([]any)
	if !ok {
		t.Fatal("schema $defs.upstream missing allOf")
	}

	// forbiddenForTransport returns the set of properties the schema disallows
	// (sets to the JSON Schema `false`) in the then-branch guarded by
	// transport == want.
	forbiddenForTransport := func(want string) map[string]bool {
		for _, raw := range allOf {
			branch, _ := raw.(map[string]any)
			ifProps, _ := branch["if"].(map[string]any)["properties"].(map[string]any)
			transport, _ := ifProps["transport"].(map[string]any)
			if transport["const"] != want {
				continue
			}
			then, _ := branch["then"].(map[string]any)
			thenProps, _ := then["properties"].(map[string]any)
			forbidden := map[string]bool{}
			for k, v := range thenProps {
				if v == false {
					forbidden[k] = true
				}
			}
			return forbidden
		}
		t.Fatalf("schema has no upstream allOf branch guarded by transport == %q", want)
		return nil
	}

	cases := []struct {
		transport string
		forbidden []string // fields the other transport owns, rejected here
	}{
		{"stdio", []string{"upstreamUrl", "upstreamAuthHeader", "upstreamTlsSkipVerify"}},
		{"http", []string{"command", "args"}},
	}
	for _, tc := range cases {
		got := forbiddenForTransport(tc.transport)
		for _, field := range tc.forbidden {
			if !got[field] {
				t.Errorf("schema %s branch must forbid %q (it belongs to the other transport)", tc.transport, field)
			}
		}
	}
}

// diffKeys returns the sorted keys present in a but not in b.
func diffKeys(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// TestHostTransport_DefaultsToHTTP verifies an absent top-level transport
// resolves to http, so existing gateway configs are unchanged.
func TestHostTransport_DefaultsToHTTP(t *testing.T) {
	t.Parallel()
	cfg := &config.GatewayConfig{}
	if got := cfg.HostTransport(); got != config.HostTransportHTTP {
		t.Errorf("hostTransport() = %q, want %q", got, config.HostTransportHTTP)
	}
}
func TestLoadConfig_InvalidTransportRejected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := mustWriteFile(t, dir, "gw.yaml", `
schemaVersion: "0.1"
transport: grpc
upstreams:
  - name: fs
    transport: stdio
    command: echo
`)
	_, err := config.LoadGatewayConfig(path)
	if err == nil || !strings.Contains(err.Error(), "transport must be") {
		t.Fatalf("want invalid-transport error, got %v", err)
	}
}

// TestLoadConfig_StdioHost_SubprocessUpstream: a stdio host fronting a single
// stdio (subprocess) upstream is the simplest stdio config and must validate.
func TestLoadConfig_StdioHost_SubprocessUpstream(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := mustWriteFile(t, dir, "gw.yaml", `
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: fs
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
`)
	cfg, err := config.LoadGatewayConfig(path)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}
	if cfg.HostTransport() != config.HostTransportStdio {
		t.Errorf("hostTransport() = %q, want stdio", cfg.HostTransport())
	}
}

// TestLoadConfig_StdioHost_HTTPUpstream: the newly-expressible combination — a
// stdio host fronting a remote HTTP upstream — must validate.
func TestLoadConfig_StdioHost_HTTPUpstream(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := mustWriteFile(t, dir, "gw.yaml", `
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: remote
    transport: http
    upstreamUrl: https://mcp.example.com
`)
	cfg, err := config.LoadGatewayConfig(path)
	if err != nil {
		t.Fatalf("config.LoadGatewayConfig: %v", err)
	}
	if cfg.Upstreams[0].UpstreamURL != "https://mcp.example.com" {
		t.Errorf("upstreamUrl not parsed: %+v", cfg.Upstreams[0])
	}
}
func TestLoadConfig_StdioHost_RejectsListen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := mustWriteFile(t, dir, "gw.yaml", `
schemaVersion: "0.1"
transport: stdio
listen:
  port: 3000
upstreams:
  - name: fs
    transport: stdio
    command: echo
`)
	_, err := config.LoadGatewayConfig(path)
	if err == nil || !strings.Contains(err.Error(), "no network listener") {
		t.Fatalf("want listen-rejected error for stdio host, got %v", err)
	}
}
func TestLoadConfig_StdioHost_RejectsMultipleUpstreams(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := mustWriteFile(t, dir, "gw.yaml", `
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: a
    transport: stdio
    command: echo
  - name: b
    transport: stdio
    command: echo
`)
	_, err := config.LoadGatewayConfig(path)
	if err == nil || !strings.Contains(err.Error(), "exactly one upstream") {
		t.Fatalf("want single-upstream error for stdio host, got %v", err)
	}
}

// TestInitConfig_Validates verifies the config scaffolded by `eunox init`
// loads and validates (the quickstart: init → proxy --config).
func TestInitConfig_Validates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifestPath := mustWriteFile(t, dir, "manifest.yaml", "schemaVersion: \"0.1\"\nname: m\nversion: \"0.1.0\"\ncapabilities: []\n")

	cfgYAML := generateInitConfigYAML(initUpstreamSpec{
		Transport:  config.HostTransportHTTP,
		URL:        "https://mcp.stripe.com",
		AuthHeader: "Authorization: Bearer x",
	}, manifestPath)
	cfgPath := mustWriteFile(t, dir, "eunox.yaml", cfgYAML)

	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("init-scaffolded config failed to validate: %v\n---\n%s", err, cfgYAML)
	}
	if cfg.HostTransport() != config.HostTransportHTTP {
		t.Errorf("init config host transport = %q, want http", cfg.HostTransport())
	}
	if len(cfg.Upstreams) != 1 || cfg.Upstreams[0].Transport != "http" || cfg.Upstreams[0].UpstreamURL != "https://mcp.stripe.com" {
		t.Errorf("init config upstream wrong: %+v", cfg.Upstreams)
	}
	if cfg.Upstreams[0].UpstreamAuthHeader != "Authorization: Bearer x" {
		t.Errorf("init config auth header not emitted: %q", cfg.Upstreams[0].UpstreamAuthHeader)
	}
	if len(cfg.Upstreams[0].Policy) != 1 || cfg.Upstreams[0].Policy[0] != manifestPath {
		t.Errorf("init config policy ref wrong: %+v", cfg.Upstreams[0].Policy)
	}
}

// TestInitConfig_UpstreamURLRoundTrips is the regression for the scaffolded
// upstreamUrl field: it must be emitted through yamlScalar so an operator-supplied
// URL carrying a YAML-significant character round-trips verbatim through the loader
// instead of failing to parse or silently changing. yamlScalar emits the minimal
// valid form (a plain URL stays unquoted; one carrying a flow/comment sequence is
// quoted), so the test asserts the round-trip, not a particular quoting style.
func TestInitConfig_UpstreamURLRoundTrips(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifestPath := mustWriteFile(t, dir, "manifest.yaml", "schemaVersion: \"0.1\"\nname: m\nversion: \"0.1.0\"\ncapabilities: []\n")

	// A plain URL and one carrying a YAML-significant sequence (" #" starts a comment
	// in a plain scalar) must both round-trip verbatim through the scaffolded config.
	for _, url := range []string{"https://mcp.example.com", "https://h/p?x=1 #frag"} {
		cfgYAML := generateInitConfigYAML(initUpstreamSpec{
			Transport: config.HostTransportHTTP,
			URL:       url,
		}, manifestPath)
		cfgPath := mustWriteFile(t, dir, "eunox.yaml", cfgYAML)
		cfg, err := config.LoadGatewayConfig(cfgPath)
		if err != nil {
			t.Fatalf("scaffolded config with URL %q failed to load: %v\n---\n%s", url, err, cfgYAML)
		}
		if len(cfg.Upstreams) != 1 || cfg.Upstreams[0].UpstreamURL != url {
			t.Errorf("upstreamUrl did not round-trip verbatim: got %+v, want %q", cfg.Upstreams, url)
		}
	}
}

// TestInitConfig_TLSSkipVerify_RoundTrips is the regression for the dropped
// --upstream-tls-skip-verify: when init introspects a self-signed upstream with
// the flag set, the scaffolded config must carry upstreamTlsSkipVerify so the
// generated `proxy --config` can reconnect to that same upstream instead of
// failing TLS verification on the first connect.
func TestInitConfig_TLSSkipVerify_RoundTrips(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifestPath := mustWriteFile(t, dir, "manifest.yaml", "schemaVersion: \"0.1\"\nname: m\nversion: \"0.1.0\"\ncapabilities: []\n")

	cfgYAML := generateInitConfigYAML(initUpstreamSpec{
		Transport:     config.HostTransportHTTP,
		URL:           "https://self-signed.example.com",
		TLSSkipVerify: true,
	}, manifestPath)
	if !strings.Contains(cfgYAML, "upstreamTlsSkipVerify: true") {
		t.Fatalf("expected upstreamTlsSkipVerify: true in scaffolded config, got:\n%s", cfgYAML)
	}

	cfgPath := mustWriteFile(t, dir, "eunox.yaml", cfgYAML)
	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("tls-skip-verify init config failed to validate: %v\n---\n%s", err, cfgYAML)
	}
	if len(cfg.Upstreams) != 1 || !cfg.Upstreams[0].UpstreamTLSSkipVerify {
		t.Errorf("init config did not round-trip upstreamTlsSkipVerify: %+v", cfg.Upstreams)
	}
}

// TestInitConfig_NoTLSSkipVerify_Omitted verifies the flag is omitted entirely
// (no commented placeholder, no false value) when init was not given it.
func TestInitConfig_NoTLSSkipVerify_Omitted(t *testing.T) {
	t.Parallel()
	got := generateInitConfigYAML(initUpstreamSpec{
		Transport: config.HostTransportHTTP,
		URL:       "https://mcp.example.com",
	}, "m.yaml")
	if strings.Contains(got, "upstreamTlsSkipVerify") {
		t.Errorf("expected no upstreamTlsSkipVerify line when the flag is unset, got:\n%s", got)
	}
}

// TestInitConfig_NoAuthHeader_CommentsItOut verifies the auth header is left as a
// commented-out placeholder when none is supplied.
func TestInitConfig_NoAuthHeader_CommentsItOut(t *testing.T) {
	t.Parallel()
	got := generateInitConfigYAML(initUpstreamSpec{
		Transport: config.HostTransportHTTP,
		URL:       "https://mcp.example.com",
	}, "m.yaml")
	if strings.Contains(got, "\n    upstreamAuthHeader:") {
		t.Errorf("expected no active upstreamAuthHeader line, got:\n%s", got)
	}
	if !strings.Contains(got, "# upstreamAuthHeader:") {
		t.Errorf("expected a commented-out upstreamAuthHeader placeholder, got:\n%s", got)
	}
}

// TestInitConfig_AuthHeader_CarriesSecurityComment is a regression: when
// --upstream-auth-header is supplied, the generated config persists the literal
// credential (needed so the config is runnable out of the box), but must carry a
// SECURITY comment flagging it as cleartext — before this, the header was written
// with no warning at all, indistinguishable from any other non-secret field.
func TestInitConfig_AuthHeader_CarriesSecurityComment(t *testing.T) {
	t.Parallel()
	got := generateInitConfigYAML(initUpstreamSpec{
		Transport:  config.HostTransportHTTP,
		URL:        "https://mcp.example.com",
		AuthHeader: "Authorization: Bearer sk-live-secret",
	}, "m.yaml")
	if !strings.Contains(got, "SECURITY") || !strings.Contains(got, "cleartext credential") {
		t.Errorf("expected a SECURITY comment flagging the cleartext credential, got:\n%s", got)
	}
	if !strings.Contains(got, "Authorization: Bearer sk-live-secret") {
		t.Errorf("expected the literal auth header to still be emitted (config must be runnable as-is), got:\n%s", got)
	}
}

// TestCmdInit_AuthHeader_WarnsOnStderr is the CLI-surface regression for
// TestInitConfig_AuthHeader_CarriesSecurityComment: `init --upstream-auth-header
// ... --config-output` must also warn on stderr, so the cleartext-credential
// signal reaches the operator even if they never open the generated file.
func TestCmdInit_AuthHeader_WarnsOnStderr(t *testing.T) {
	dir := t.TempDir()
	manifestOut := filepath.Join(dir, "manifest.yaml")
	cfgOut := filepath.Join(dir, "eunox.yaml")
	srv := httptest.NewServer(newFakeUpstream())
	defer srv.Close()

	var code int
	stderr := captureStderr(t, func() {
		withArgs([]string{
			"eunox", "init",
			"--upstream-url", srv.URL,
			"--upstream-auth-header", "Authorization: Bearer sk-live-secret",
			"--output", manifestOut,
			"--config-output", cfgOut,
		}, func() {
			code = cmdInit()
		})
	})
	if code != 0 {
		t.Fatalf("cmdInit exit code = %d, want 0\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "SECURITY") || !strings.Contains(stderr, cfgOut) {
		t.Errorf("expected a SECURITY warning naming %q on stderr, got:\n%s", cfgOut, stderr)
	}
}

// TestInitConfig_Stdio_Validates covers the stdio peer of TestInitConfig_Validates:
// `init --transport stdio -- npx -y ...` scaffolds a stdio-host config with a
// stdio upstream, and that config loads and validates.
func TestInitConfig_Stdio_Validates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifestPath := mustWriteFile(t, dir, "manifest.yaml", "schemaVersion: \"0.1\"\nname: m\nversion: \"0.1.0\"\ncapabilities: []\n")

	cfgYAML := generateInitConfigYAML(initUpstreamSpec{
		Transport: config.HostTransportStdio,
		Command:   "npx",
		Args:      []string{"-y", "@modelcontextprotocol/server-filesystem", "/data"},
	}, manifestPath)
	cfgPath := mustWriteFile(t, dir, "eunox.yaml", cfgYAML)

	cfg, err := config.LoadGatewayConfig(cfgPath)
	if err != nil {
		t.Fatalf("stdio init-scaffolded config failed to validate: %v\n---\n%s", err, cfgYAML)
	}
	if cfg.HostTransport() != config.HostTransportStdio {
		t.Errorf("init config host transport = %q, want stdio", cfg.HostTransport())
	}
	if len(cfg.Upstreams) != 1 {
		t.Fatalf("want exactly one upstream, got %d", len(cfg.Upstreams))
	}
	u := cfg.Upstreams[0]
	if u.Transport != "stdio" {
		t.Errorf("upstream transport = %q, want stdio", u.Transport)
	}
	if u.Command != "npx" {
		t.Errorf("upstream command = %q, want npx", u.Command)
	}
	if got, want := u.Args, []string{"-y", "@modelcontextprotocol/server-filesystem", "/data"}; !equalStrings(got, want) {
		t.Errorf("upstream args = %v, want %v", got, want)
	}
	if u.UpstreamURL != "" {
		t.Errorf("stdio upstream must not carry upstreamUrl, got %q", u.UpstreamURL)
	}
	// Stdio host must not carry a listen block (validate() rejects it).
	if cfg.Listen.Port != 0 || cfg.Listen.Bind != "" {
		t.Errorf("stdio init config must not emit a listen block, got %+v", cfg.Listen)
	}
}
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ===== merged from drift_test.go =====

func TestResolveStrictDrift(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                            string
		configured, globalFlag, policed bool
		want                            bool
	}{
		{"nothing set", false, false, false, false},
		{"per-route true wins", true, false, true, true},
		{"per-route true on policyless still honored", true, false, false, true},
		{"flag promotes policed (even over explicit false)", false, true, true, true},
		{"flag no-ops on policyless", false, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := transport.ResolveStrictDrift(tc.configured, tc.globalFlag, tc.policed); got != tc.want {
				t.Errorf("resolveStrictDrift(%v,%v,%v)=%v, want %v",
					tc.configured, tc.globalFlag, tc.policed, got, tc.want)
			}
		})
	}
}

func TestLoadManifest_DescriptionHashValid(t *testing.T) {
	hash := capability.ComputeToolHash("Reads a file from the filesystem.", nil)
	yaml := `
name: "test-policy"
version: "1.0.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    descriptionHash: "` + hash + `"
`
	path := writeManifestFile(t, yaml)
	m, err := config.LoadManifest(path)
	if err != nil {
		t.Fatalf("valid descriptionHash must load without error: %v", err)
	}
	if m.Capabilities[0].DescriptionHash != hash {
		t.Errorf("DescriptionHash round-trip: want %q, got %q", hash, m.Capabilities[0].DescriptionHash)
	}
}

func TestLoadManifest_DescriptionHashInvalidFormat(t *testing.T) {
	cases := []struct {
		name    string
		hash    string
		wantErr string
	}{
		{"wrong prefix", "md5:abc123", `must start with "sha256:"`},
		{"too short", "sha256:abc123", "exactly 64"},
		{"uppercase hex", "sha256:" + strings.Repeat("A", 64), "lowercase"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yaml := `
name: "test-policy"
version: "1.0.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    descriptionHash: "` + tc.hash + `"
`
			path := writeManifestFile(t, yaml)
			_, err := config.LoadManifest(path)
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestLoadManifest_DescriptionHashUnknownKey(t *testing.T) {

	hash := capability.ComputeToolHash("some tool description", nil)
	yaml := `
name: "test-policy"
version: "1.0.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    descriptionHash: "` + hash + `"
`
	path := writeManifestFile(t, yaml)
	if _, err := config.LoadManifest(path); err != nil {
		t.Errorf("descriptionHash must not be rejected as unknown key: %v", err)
	}
}

func TestLoadManifest_DescriptionHashOnResourceRejected(t *testing.T) {
	hash := capability.ComputeToolHash("The canonical reports directory.", nil)
	yaml := `
name: "test-policy"
version: "1.0.0"
capabilities:
  - target: "resource:file:///data/reports/"
    actions: [read]
    descriptionHash: "` + hash + `"
`
	path := writeManifestFile(t, yaml)
	_, err := config.LoadManifest(path)
	if err == nil {
		t.Fatal("descriptionHash on resource: target must be rejected at manifest load")
	}
	if !strings.Contains(err.Error(), "only supported on tool: targets") {
		t.Errorf("error must explain the tool:-only scope, got: %v", err)
	}
}

func TestLoadManifest_DescriptionHashOnPromptRejected(t *testing.T) {
	hash := capability.ComputeToolHash("Summarize the given text.", nil)
	yaml := `
name: "test-policy"
version: "1.0.0"
capabilities:
  - target: "prompt:summarize"
    actions: [get]
    descriptionHash: "` + hash + `"
`
	path := writeManifestFile(t, yaml)
	_, err := config.LoadManifest(path)
	if err == nil {
		t.Fatal("descriptionHash on prompt: target must be rejected at manifest load")
	}
	if !strings.Contains(err.Error(), "only supported on tool: targets") {
		t.Errorf("error must explain the tool:-only scope, got: %v", err)
	}
}

func TestLoadManifest_DescriptionHashOnGlobToolRejected(t *testing.T) {
	hash := capability.ComputeToolHash("some description", nil)
	yaml := `
name: "test-policy"
version: "1.0.0"
capabilities:
  - target: "tool:read_*"
    actions: [call]
    descriptionHash: "` + hash + `"
`
	path := writeManifestFile(t, yaml)
	_, err := config.LoadManifest(path)
	if err == nil {
		t.Fatal("descriptionHash on glob tool: target must be rejected at manifest load")
	}
	if !strings.Contains(err.Error(), "glob") {
		t.Errorf("error must mention glob, got: %v", err)
	}
}

// ===== merged from security_test.go =====

// TestAuditRecord_SignVerifyRoundTrip exercises the full Record→VerifyRecord
// path to ensure the signing and verification byte sequences always match.
// This is the regression test for the map-vs-struct marshaling bug where
// VerifyRecord re-marshaled through map[string]interface{} (alphabetical key
// order) while Record signed through the auditRecord struct (declaration order).
func TestAuditRecord_SignVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()

	sink, err := audit.Open(
		dir+"/test.jsonl",
		dir+"/test.key",
		0,
		0,
	)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	cases := []struct {
		session    string
		tool       string
		decision   string
		denialCode string
	}{
		{"sess-1", "read_file", "allow", ""},
		{"sess-1", "write_file", "deny", "AUTHORIZATION_FAILED"},
		{"sess-2", "query_db", "deny", "CONDITION_FAILED"},
	}
	for _, c := range cases {
		if c.decision == "deny" {
			sink.RecordDeny(context.Background(), c.session, c.tool, "tools/call", c.denialCode, "", nil, false)
		} else {
			sink.RecordAllow(context.Background(), c.session, c.tool, "tools/call", nil, nil, false, nil, nil)
		}
	}
	// Record enqueues to a background drainer goroutine; Close flushes it.
	if err := sink.Close(); err != nil {
		t.Fatalf("closing audit sink: %v", err)
	}

	data, err := os.ReadFile(dir + "/test.jsonl")
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	if len(lines) != len(cases) {
		t.Fatalf("expected %d lines, got %d", len(cases), len(lines))
	}
	for i, line := range lines {
		ok, err := sink.VerifyRecord(line)
		if err != nil {
			t.Fatalf("line %d: VerifyRecord error: %v", i, err)
		}
		if !ok {
			t.Errorf("line %d: expected VALID signature, got INVALID", i)
		}
	}
}

// ===== merged from low_severity_fixes_test.go =====

// TestAuditSink_AsyncWrite verifies that Record returns without blocking on
// disk I/O: it enqueues onto a buffered channel and the drainer goroutine does
// the serialization, signing, and writes. It also checks that the records
// eventually appear on disk after Close.
//
// Single-call timing is too noisy on CI under -race to distinguish an
// async-channel-send (sub-µs) from "fast disk + scheduler hiccup" (a few ms),
// which flaked the previous 5 ms threshold. Amortizing over many records
// back-to-back turns that into a stable throughput check: enqueueing is sub-µs
// per call, so even a heavily loaded -race runner clears the ceiling by orders
// of magnitude, while a regression that put real blocking disk I/O back on the
// call path — a synchronous write, and far more so an fsync — would overrun it.
// The drainer batches writes and only fsyncs on Close, so this ceiling is a
// throughput guard, not proof of decoupling; that proof lives in
// TestAuditSink_RecordDoesNotBlockOnSlowWriter, which stalls the writer
// directly.
// TestAuditSink_ConcurrentRecord verifies that multiple goroutines can call
// Record concurrently without a data race.  Run with -race to catch issues.
func TestAuditSink_ConcurrentRecord(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := audit.Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	var wg sync.WaitGroup
	const goroutines = 50
	const perGoroutine = 20
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				sink.RecordAllow(context.Background(), "sess-c", "list_files", "tools/call", nil, nil, false, nil, nil)
			}
		}()
	}
	wg.Wait()

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestAuditSink_CloseFlushesQueuedRecords verifies that records enqueued just
// before Close are all flushed to disk (not silently dropped on shutdown).
func TestAuditSink_CloseFlushesQueuedRecords(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := audit.Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	const n = 100
	for i := 0; i < n; i++ {
		sink.RecordAllow(context.Background(), "sess-flush", "read_file", "tools/call", nil, nil, false, nil, nil)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	lines := strings.Count(string(data), "\n")
	if lines < n-int(sink.DroppedRecords()) {
		t.Errorf("regression: expected at least %d lines (minus dropped=%d), got %d",
			n, sink.DroppedRecords(), lines)
	}
}

// TestAuditSink_RotateKeepsWriting verifies that after a rotation the
// audit sink keeps writing records.
func TestAuditSink_RotateKeepsWriting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	const threshold = 256
	sink, err := audit.Open(logPath, filepath.Join(dir, "audit.key"), threshold, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	sink.RecordAllow(context.Background(), "sess-before", "tool_before_rotate", "tools/call", nil, nil, false, nil, nil)
	sink.RecordAllow(context.Background(), "sess-after", "tool_after_rotate", "tools/call", nil, nil, false, nil, nil)

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if dropped := sink.DroppedRecords(); dropped != 0 {
		t.Errorf("regression: %d records dropped (s.f was nil after rotation)", dropped)
	}

	entries, err := filepath.Glob(logPath + "*")
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	allFiles := make(map[string]bool, len(entries)+1)
	for _, e := range entries {
		allFiles[e] = true
	}
	allFiles[logPath] = true

	var found bool
	for f := range allFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "tool_after_rotate") {
			found = true
			break
		}
	}
	if !found {
		t.Error("regression: record written after rotation is missing — audit sink stopped writing")
	}
}

func TestAuditSink_NormalWrite_StillWorks(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := audit.Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess-ok", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "read_file") {
		t.Errorf("expected read_file in audit log; got %q", string(data))
	}
}

// TestBindExposesAllInterfaces pins that every spelling the RESOLVER accepts for the
// unspecified address trips the --unsafe-bind-all guard.
//
// The guard used to test net.ParseIP alone, which is a narrower grammar than
// getaddrinfo: "0" and hex/octal shorthands are not Go IP literals, so ParseIP returned
// nil, the guard was skipped entirely, and on a cgo-resolver build the listener bound
// every interface with no opt-in and no warning.
func TestBindExposesAllInterfaces(t *testing.T) {
	exposed := []string{
		"0.0.0.0", "::", "::0", "0:0:0:0:0:0:0:0", // IP literals ParseIP already caught
		"0", "00", "0x0", "0X0", "0o0", // inet_aton-style integer forms it did not
		"", // empty host in "host:port" means all interfaces
	}
	for _, h := range exposed {
		if !bindExposesAllInterfaces(h) {
			t.Errorf("bind host %q resolves to the unspecified address and must require --unsafe-bind-all", h)
		}
	}
	confined := []string{
		"127.0.0.1", "::1", "localhost", "192.168.1.10", "example.com",
		"0.0.0.1", // numerically nonzero
		"1",       // inet_aton 0.0.0.1, not unspecified
		"0abc",    // a name, not an integer
	}
	for _, h := range confined {
		if bindExposesAllInterfaces(h) {
			t.Errorf("bind host %q is not the unspecified address and must not trip the guard", h)
		}
	}
}
