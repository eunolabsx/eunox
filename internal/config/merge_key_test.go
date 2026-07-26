// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// TestGatewayConfig_MergeKeyKeysCountAsPresent pins that a field an upstream inherits
// through a YAML merge key (`<<: *base`) is seen by the forbidden-field check exactly as
// a literally-written one is.
//
// The check is presence-based on purpose: the strict typed decode cannot tell an explicit
// zero (command: "") from an absent key, so validate() consults a second parse
// (upstreamKeyPresence) that records which keys the YAML actually wrote. If that second
// parse did not resolve merge keys while the typed decode did, an anchor could smuggle a
// transport-forbidden field past the guard — the config would carry the field with
// nothing rejecting it. It does resolve them; this test is what keeps that true.
func TestGatewayConfig_MergeKeyKeysCountAsPresent(t *testing.T) {
	t.Parallel()

	// `command` is forbidden on an http upstream. Here it arrives only via the merge.
	_, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
upstreams:
  - &base
    name: local
    transport: stdio
    command: /usr/bin/srv
    policy: ["p.yaml"]
  - name: remote
    <<: *base
    transport: http
    upstreamUrl: https://mcp.example.com
    policy: ["p.yaml"]
`))
	if err == nil {
		t.Fatal("a merge-key-inherited `command` on an http upstream was accepted; the forbidden-field check must see merged keys as present")
	}
	if !strings.Contains(err.Error(), "command") {
		t.Errorf("error = %q, want it to name the forbidden `command` field", err)
	}
}

// TestGatewayConfig_MergeKeyExplicitZeroCountsAsPresent is the harder half: a merged
// field whose value is an explicit ZERO. Only the presence parse can catch this — the
// typed decode sees "" and cannot distinguish it from an absent key — so it fails if the
// presence parse ever stops resolving merges, even though the case above might still pass
// through a value-based fallback.
func TestGatewayConfig_MergeKeyExplicitZeroCountsAsPresent(t *testing.T) {
	t.Parallel()

	_, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
upstreams:
  - &base
    name: local
    transport: stdio
    command: ""
    args: ["srv"]
    policy: ["p.yaml"]
  - name: remote
    <<: *base
    transport: http
    upstreamUrl: https://mcp.example.com
    policy: ["p.yaml"]
`))
	if err == nil {
		t.Fatal("a merge-key-inherited explicit-zero `command` was accepted; presence, not value, is what the forbidden-field check must test")
	}
	if !strings.Contains(err.Error(), "command") {
		t.Errorf("error = %q, want it to name the forbidden `command` field", err)
	}
}

// TestGatewayConfig_MergeKeyKeepsUpstreamsAligned pins the count/index invariant the
// presence slice rests on: merges must not add or drop upstream entries, or one
// upstream's forbidden fields would be checked against another's key set.
func TestGatewayConfig_MergeKeyKeepsUpstreamsAligned(t *testing.T) {
	t.Parallel()

	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
upstreams:
  - &base
    name: a
    transport: stdio
    command: /usr/bin/srv
    policy: ["a.yaml"]
  - <<: *base
    name: b
    policy: ["b.yaml"]
`))
	if err != nil {
		t.Fatalf("LoadGatewayConfig: %v", err)
	}
	if len(cfg.Upstreams) != 2 {
		t.Fatalf("upstreams = %d, want 2", len(cfg.Upstreams))
	}
	for i, u := range cfg.Upstreams {
		if u.Command != "/usr/bin/srv" {
			t.Errorf("upstream[%d].Command = %q, want the merged value", i, u.Command)
		}
		if u.Transport != HostTransportStdio {
			t.Errorf("upstream[%d].Transport = %q, want the merged value", i, u.Transport)
		}
	}
}
