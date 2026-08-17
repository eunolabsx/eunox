// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
)

// auditSinkConfig returns a GatewayConfig whose audit tape lands in a temp dir, so a test
// opening a real sink never touches the operator's default ~/.eunox log.
func auditSinkConfig(t *testing.T) *config.GatewayConfig {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.GatewayConfig{}
	cfg.Audit.Log = filepath.Join(dir, "audit.jsonl")
	cfg.Audit.KeyPath = filepath.Join(dir, "audit.key")
	return cfg
}

// The enforcement-point name follows the same precedence the rest of the audit block does —
// the config wins so every route of one process shares one tape identity — and says so, since
// an operator who passed the flag would otherwise find their fleet stamping a name they did
// not choose.
func TestOpenConfiguredAuditSink_ConfigPEPOverridesFlag(t *testing.T) {
	cfg := auditSinkConfig(t)
	cfg.Audit.PEP = "edge-config"

	var sink *audit.Sink
	var openErr error
	stderr := captureStderr(t, func() {
		sink, openErr = openConfiguredAuditSink("", "", "edge-flag", 0, 0, false, cfg, false)
	})
	if openErr != nil {
		t.Fatalf("unexpected error: %v", openErr)
	}
	t.Cleanup(func() { _ = sink.Close() })

	if !strings.Contains(stderr, "--audit-pep") || !strings.Contains(stderr, "edge-config") {
		t.Errorf("expected a WARNING naming both the overridden --audit-pep and the config's audit.pep, got:\n%s", stderr)
	}

	sink.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	tape, err := os.ReadFile(cfg.Audit.Log)
	if err != nil {
		t.Fatalf("read tape: %v", err)
	}
	if !strings.Contains(string(tape), `"pep":"mcp:edge-config"`) {
		t.Errorf("the tape must carry the config's name, got:\n%s", tape)
	}
}

// An unusable --audit-pep fails startup outright rather than being folded into the
// --require-audit stance: that stance decides what to do about a tape that cannot be OPENED,
// where this is an operator typo with a one-line fix, and repairing it silently would put a
// name on the signed tape that matches nothing the operator configured elsewhere.
func TestOpenConfiguredAuditSink_RefusesAnUnusablePEPRegardlessOfRequireAudit(t *testing.T) {
	for _, requireAudit := range []bool{false, true} {
		cfg := auditSinkConfig(t)
		var sink *audit.Sink
		var openErr error
		_ = captureStderr(t, func() {
			sink, openErr = openConfiguredAuditSink("", "", "edge 1", 0, 0, false, cfg, requireAudit)
		})
		if sink != nil {
			_ = sink.Close()
			t.Fatalf("requireAudit=%v: a sink must not be opened under an unusable enforcement-point name", requireAudit)
		}
		if openErr == nil || !strings.Contains(openErr.Error(), "enforcement-point name") {
			t.Errorf("requireAudit=%v: error = %v, want a refusal naming the enforcement-point name", requireAudit, openErr)
		}
	}
}

// TestResolveAuditPEP is the precedence the sink opener and both serve paths' advisory all
// read, so a proxy cannot stamp one name while advising about another.
func TestResolveAuditPEP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		flag, cfg string
		want      string
	}{
		{name: "neither", want: ""},
		{name: "flag only", flag: "edge-flag", want: "edge-flag"},
		{name: "config only", cfg: "edge-config", want: "edge-config"},
		{name: "config wins", flag: "edge-flag", cfg: "edge-config", want: "edge-config"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.GatewayConfig{}
			cfg.Audit.PEP = tc.cfg
			if got := resolveAuditPEP(tc.flag, cfg); got != tc.want {
				t.Errorf("resolveAuditPEP(%q, audit.pep=%q) = %q, want %q", tc.flag, tc.cfg, got, tc.want)
			}
		})
	}
}

// Task anchoring is the one configurable statement that an operator INTENDS a task to cross
// enforcement points, so it is where an unnamed instance is worth a line: the tapes it
// crosses would be attributable only by which file they came out of, which does not survive
// being merged.
func TestWarnTaskAnchoringWithoutPEP(t *testing.T) {
	tests := []struct {
		name                        string
		pepConfigured, taskAnchored bool
		wantNotice                  bool
	}{
		{name: "anchored and unnamed warns", taskAnchored: true, wantNotice: true},
		{name: "anchored and named is silent", pepConfigured: true, taskAnchored: true},
		{name: "unanchored and unnamed is silent"},
		{name: "unanchored and named is silent", pepConfigured: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStderr(t, func() {
				warnTaskAnchoringWithoutPEP(tc.pepConfigured, tc.taskAnchored)
			})
			if got := strings.Contains(out, "enforcement-point name"); got != tc.wantNotice {
				t.Errorf("notice emitted = %v, want %v; got:\n%s", got, tc.wantNotice, out)
			}
		})
	}
}
