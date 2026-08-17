// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// A configured enforcement-point name loads verbatim: it is stamped on every audit record,
// so the value the operator joins their tapes on has to be the value they wrote.
func TestLoadGatewayConfig_AcceptsAuditPEP(t *testing.T) {
	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: stdio
audit:
  pep: gw.eu-west-1
upstreams:
  - name: fs
    transport: stdio
    command: /usr/bin/server
    policy: ["fs.yaml"]
`))
	if err != nil {
		t.Fatalf("LoadGatewayConfig: %v", err)
	}
	if cfg.Audit.PEP != "gw.eu-west-1" {
		t.Errorf("audit.pep = %q, want %q", cfg.Audit.PEP, "gw.eu-west-1")
	}
}

// A per-instance name is exactly the kind of value a deployment templates from the
// environment, so the expansion walk must reach it like any other string field — a fleet
// that has to bake one config per instance is a fleet that shares one name by accident.
func TestLoadGatewayConfig_ExpandsAuditPEPFromEnv(t *testing.T) {
	t.Setenv("EUNOX_TEST_PEP", "edge-7")
	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: stdio
audit:
  pep: ${EUNOX_TEST_PEP}
upstreams:
  - name: fs
    transport: stdio
    command: /usr/bin/server
    policy: ["fs.yaml"]
`))
	if err != nil {
		t.Fatalf("LoadGatewayConfig: %v", err)
	}
	if cfg.Audit.PEP != "edge-7" {
		t.Errorf("audit.pep = %q, want the expanded %q", cfg.Audit.PEP, "edge-7")
	}
}

// And an UNSET reference is refused rather than stamped: it survives expansion as literal
// "${VAR}" text, which would put a name no enforcement point answers to onto the signed tape.
func TestLoadGatewayConfig_RejectsUnsetEnvRefInAuditPEP(t *testing.T) {
	_, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: stdio
audit:
  pep: ${EUNOX_TEST_NO_SUCH_PEP}
upstreams:
  - name: fs
    transport: stdio
    command: /usr/bin/server
    policy: ["fs.yaml"]
`))
	if err == nil {
		t.Fatal("expected a load error for an unset ${VAR} in audit.pep")
	}
	for _, want := range []string{"audit.pep", "EUNOX_TEST_NO_SUCH_PEP", "unset"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
}

// The fail-closed case the accepted-name rule cannot see: a variable that is SET but blank —
// a configMap key or EnvironmentFile line that is present and empty. It expands to "", which
// is byte-identical to the field being omitted, so nothing downstream can tell that a name
// was asked for; the proxy would write its whole signed tape unattributed with nothing said.
func TestLoadGatewayConfig_RejectsBlankEnvRefInAuditPEP(t *testing.T) {
	for _, blank := range []string{"", "   "} {
		t.Setenv("EUNOX_TEST_BLANK_PEP", blank)
		_, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: stdio
audit:
  pep: ${EUNOX_TEST_BLANK_PEP}
upstreams:
  - name: fs
    transport: stdio
    command: /usr/bin/server
    policy: ["fs.yaml"]
`))
		if err == nil {
			t.Fatalf("value %q: expected a load error for an env ref that expanded to nothing", blank)
		}
		for _, want := range []string{"audit.pep", "empty string"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("value %q: error = %q, want it to mention %q", blank, err, want)
			}
		}
	}
}

// A reference is refused only when it produces NO name. One that merely contributes part of
// a name still yields something the operator can join their tapes on, so it loads: refusing
// there would reject a perfectly usable "edge-" that the operator wrote themselves.
func TestLoadGatewayConfig_AcceptsAuditPEPWhoseRefIsBlankButLeavesAName(t *testing.T) {
	t.Setenv("EUNOX_TEST_PEP_SUFFIX", "")
	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: stdio
audit:
  pep: edge-${EUNOX_TEST_PEP_SUFFIX}
upstreams:
  - name: fs
    transport: stdio
    command: /usr/bin/server
    policy: ["fs.yaml"]
`))
	if err != nil {
		t.Fatalf("LoadGatewayConfig: %v", err)
	}
	if cfg.Audit.PEP != "edge-" {
		t.Errorf("audit.pep = %q, want %q", cfg.Audit.PEP, "edge-")
	}
}
