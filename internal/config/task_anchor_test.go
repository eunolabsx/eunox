// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolvedTaskAnchoredState pins the defaults-plus-override precedence: a per-route
// pointer wins over the default INCLUDING when it is an explicit false, so a gateway that
// anchors most routes on the task can still pin one route to session keying.
func TestResolvedTaskAnchoredState(t *testing.T) {
	tr := func(b bool) *bool { return &b }
	for name, tc := range map[string]struct {
		def   bool
		route *bool
		want  bool
	}{
		"off by default":              {false, nil, false},
		"inherits the default":        {true, nil, true},
		"route opts in":               {false, tr(true), true},
		"route opts out of a default": {true, tr(false), false},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &GatewayConfig{}
			cfg.Defaults.TaskAnchoredState = tc.def
			u := &UpstreamConfig{Name: "u", TaskAnchoredState: tc.route}
			if got := cfg.ResolvedTaskAnchoredState(u); got != tc.want {
				t.Errorf("ResolvedTaskAnchoredState = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestGatewayConfig_ParsesTaskAnchoredState is the round-trip through YAML: an unknown key is
// rejected by the loader, so a key that does not parse would fail LOUDLY rather than silently
// leaving the anchor at its default — this pins that the key is actually wired.
func TestGatewayConfig_ParsesTaskAnchoredState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eunox.yaml")
	if err := os.WriteFile(path, []byte(`
schemaVersion: "0.1"
transport: stdio
defaults:
  taskAnchoredState: true
upstreams:
  - name: alpha
    transport: stdio
    command: /bin/true
    taskAnchoredState: false
`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := LoadGatewayConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Defaults.TaskAnchoredState {
		t.Error("defaults.taskAnchoredState did not parse")
	}
	if got := cfg.ResolvedTaskAnchoredState(&cfg.Upstreams[0]); got {
		t.Error("the per-route explicit false must win over the default true")
	}
}
