// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// TestLoadGatewayConfig_ProtocolVersionRoundTrip is the load→resolve round-trip for the
// per-upstream protocol pin: every accepted spelling parses to the value the transport
// reads, and `auto` (or an omitted key) resolves to "probe it" rather than to a revision.
func TestLoadGatewayConfig_ProtocolVersionRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		yamlLine string
		want     string
	}{
		{name: "omitted", yamlLine: "", want: ""},
		{name: "explicit auto", yamlLine: `    protocolVersion: auto`, want: ""},
		{name: "pinned to the old revision", yamlLine: `    protocolVersion: "2025-11-25"`, want: "2025-11-25"},
		{name: "pinned to the new revision", yamlLine: `    protocolVersion: "2026-07-28"`, want: "2026-07-28"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := LoadGatewayConfig(writeConfig(t, fmt.Sprintf(`
schemaVersion: "0.1"
defaults:
  enforcement: audit
upstreams:
  - name: mock
    transport: stdio
    command: echo
%s
`, tc.yamlLine)))
			if err != nil {
				t.Fatalf("LoadGatewayConfig: %v", err)
			}
			if got := cfg.Upstreams[0].ResolvedProtocolVersion(); got != tc.want {
				t.Errorf("ResolvedProtocolVersion() = %q, want %q", got, tc.want)
			}
			// A resolved pin must be a revision the transport can act on, never a bare
			// string the loader admitted and nothing downstream recognizes.
			if got := cfg.Upstreams[0].ResolvedProtocolVersion(); got != "" {
				if _, ok := capability.ParseRevision(got); !ok {
					t.Errorf("ResolvedProtocolVersion() = %q, which is not a revision this build speaks", got)
				}
			}
		})
	}
}

// TestLoadGatewayConfig_RejectsUnspokenProtocolVersion: the pin is refused at LOAD, not at
// the first request. Admitting an unknown value would fall back to the probe and silently
// serve the upstream under a revision the operator did not name.
func TestLoadGatewayConfig_RejectsUnspokenProtocolVersion(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"2026-07-27", "2099-01-01", "latest", "AUTO", "1.0"} {
		_, err := LoadGatewayConfig(writeConfig(t, fmt.Sprintf(`
schemaVersion: "0.1"
defaults:
  enforcement: audit
upstreams:
  - name: mock
    transport: stdio
    command: echo
    protocolVersion: %q
`, bad)))
		if err == nil {
			t.Errorf("protocolVersion %q was accepted; want a load-time refusal", bad)
			continue
		}
		if !strings.Contains(err.Error(), "protocolVersion") {
			t.Errorf("protocolVersion %q: error should name the key, got: %v", bad, err)
		}
		// The message must name the accepted set: the value is a date this build either
		// knows or does not, and guessing is unhelpful.
		if !strings.Contains(err.Error(), ProtocolVersionAuto) || !strings.Contains(err.Error(), capability.Revision20260728.String()) {
			t.Errorf("protocolVersion %q: error should list the valid values, got: %v", bad, err)
		}
	}
}

// TestValidateProtocolVersionFlag keeps the CLI flag and the config key accepting exactly
// the same set — two spellings of one pin that disagreed would be an operator trap.
func TestValidateProtocolVersionFlag(t *testing.T) {
	t.Parallel()
	for _, good := range []string{"", ProtocolVersionAuto, "2025-11-25", "2026-07-28"} {
		if err := ValidateProtocolVersionFlag(good); err != nil {
			t.Errorf("ValidateProtocolVersionFlag(%q) = %v, want nil", good, err)
		}
	}
	for _, bad := range []string{"2099-01-01", "latest", "0.1"} {
		err := ValidateProtocolVersionFlag(bad)
		if err == nil {
			t.Errorf("ValidateProtocolVersionFlag(%q) = nil, want a refusal", bad)
			continue
		}
		if !strings.Contains(err.Error(), "--upstream-protocol-version") {
			t.Errorf("ValidateProtocolVersionFlag(%q) error should name the flag, got: %v", bad, err)
		}
	}
}

// TestProtocolVersion_EveryPublishedRevisionIsAccepted derives the accepted set from
// capability.PublishedRevisions rather than restating it, so publishing a revision cannot
// leave the config loader refusing a revision the binary speaks.
func TestProtocolVersion_EveryPublishedRevisionIsAccepted(t *testing.T) {
	t.Parallel()
	for _, rev := range capability.PublishedRevisions() {
		if err := validateProtocolVersion("mock", rev.String()); err != nil {
			t.Errorf("published revision %q is refused by the config loader: %v", rev, err)
		}
	}
}
