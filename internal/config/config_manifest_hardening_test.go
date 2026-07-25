// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// TestLoadGatewayConfig_RejectsOctalCoercedNumeric is a regression test: an
// unquoted leading-zero numeric field YAML reads as OCTAL (port: 0755 → 493), which the
// strict struct decode accepts silently. The loader must fail closed, and a quoted value
// (the operator disambiguated it to a string, which then fails the range check) or a
// plain decimal must load fine.
func TestLoadGatewayConfig_RejectsOctalCoercedNumeric(t *testing.T) {
	base := func(auditOrListen string) string {
		return `
schemaVersion: "0.1"
transport: http
listen:
` + auditOrListen + `
upstreams:
  - name: mock
    transport: stdio
    command: echo
    args: ["hi"]
    policy: ["manifest.yaml"]
`
	}
	// Unquoted octal port must be rejected with a clear coercion error.
	_, err := LoadGatewayConfig(writeConfig(t, base("  port: 0755\n")))
	if err == nil {
		t.Fatal("expected a fail-closed error for an octal-coerced port (0755)")
	}
	if !strings.Contains(err.Error(), "unquoted YAML number") && !strings.Contains(err.Error(), "coerced") && !strings.Contains(err.Error(), "differs from the text") {
		t.Errorf("error = %v, want it to name the numeric coercion", err)
	}

	// A plain decimal port loads (subject to the normal range check).
	if _, err := LoadGatewayConfig(writeConfig(t, base("  port: 8080\n"))); err != nil {
		t.Errorf("a plain decimal port must load, got %v", err)
	}
}

// TestLoadGatewayConfig_RejectsEmptyPolicyEntry is a regression test: a policy
// list with an empty entry (a literal [""], or a ${VAR} that expands to empty) passes the old validation and
// dies at route start with a misleading "is a directory". It must be rejected at load.
func TestLoadGatewayConfig_RejectsEmptyPolicyEntry(t *testing.T) {
	cfg := `
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: mock
    transport: stdio
    command: echo
    policy: [""]
`
	_, err := LoadGatewayConfig(writeConfig(t, cfg))
	if err == nil {
		t.Fatal("expected a fail-closed error for an empty policy entry")
	}
	if !strings.Contains(err.Error(), "empty entry") {
		t.Errorf("error = %v, want it to name the empty policy entry", err)
	}
}

// TestLoadGatewayConfig_RejectsWhitespaceAuthToken is a regression test: a literal
// whitespace-only authToken is a degenerate bearer secret that also satisfies the
// non-loopback-bind safety gate. It must be rejected like the env-ref-expands-to-blank case.
func TestLoadGatewayConfig_RejectsWhitespaceAuthToken(t *testing.T) {
	cfg := `
schemaVersion: "0.1"
transport: http
listen:
  authToken: "   "
upstreams:
  - name: mock
    transport: stdio
    command: echo
    policy: ["manifest.yaml"]
`
	_, err := LoadGatewayConfig(writeConfig(t, cfg))
	if err == nil {
		t.Fatal("expected a fail-closed error for a whitespace-only authToken")
	}
	if !strings.Contains(err.Error(), "whitespace-only") {
		t.Errorf("error = %v, want it to name the whitespace-only token", err)
	}
}

// TestLoadManifest_RejectsEmptyServerVersionComponent is a regression test: a
// serverVersion pin with an empty dot-component ("1.2.", "1..2") passes the regex but can
// never match a real version — a self-inflicted blackout under --strict-drift. Reject at load.
func TestLoadManifest_RejectsEmptyServerVersionComponent(t *testing.T) {
	for _, pin := range []string{"1.2.", "1..2", "*."} {
		body := "schemaVersion: \"0.1\"\nname: t\nversion: 1.0.0\nserverVersion: \"" + pin + "\"\ncapabilities: []\n"
		_, err := LoadManifest(writeManifestFile(t, body))
		if err == nil {
			t.Errorf("serverVersion %q must be rejected (empty dot-component)", pin)
		} else if !strings.Contains(err.Error(), "empty dot-component") {
			t.Errorf("serverVersion %q: error = %v, want it to name the empty dot-component", pin, err)
		}
	}
	// A valid whole-component wildcard pin still loads.
	ok := "schemaVersion: \"0.1\"\nname: t\nversion: 1.0.0\nserverVersion: \"1.2.*\"\ncapabilities: []\n"
	if _, err := LoadManifest(writeManifestFile(t, ok)); err != nil {
		t.Errorf("a valid serverVersion pin must load, got %v", err)
	}
}

// TestLoadManifest_UnquotedSchemaVersion is a regression test: an UNQUOTED
// schemaVersion (schemaVersion: 0.1, yaml-typed as a float) must negotiate identically to
// the quoted form and to the gateway loader, instead of failing json.Unmarshal into the
// string field with an opaque decode error.
func TestLoadManifest_UnquotedSchemaVersion(t *testing.T) {
	m, err := LoadManifest(writeManifestFile(t, "schemaVersion: 0.1\nname: t\nversion: 1.0.0\ncapabilities: []\n"))
	if err != nil {
		t.Fatalf("an unquoted schemaVersion: 0.1 must load like the quoted form, got %v", err)
	}
	if m.SchemaVersion != "0.1" {
		t.Errorf("SchemaVersion = %q, want %q (verbatim text preserved)", m.SchemaVersion, "0.1")
	}
}
