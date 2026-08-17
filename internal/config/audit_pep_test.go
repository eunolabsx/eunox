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
// "${VAR}" text, which would put a name no enforcement point answers to onto the signed
// tape. The accepted-name rule catches it (a '$' is outside the set), so this needs no guard
// of its own — but the load must still fail, which is what this pins.
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
	if !strings.Contains(err.Error(), "audit.pep") {
		t.Errorf("error = %q, want it to name audit.pep", err)
	}
}
