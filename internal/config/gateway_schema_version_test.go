// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// gatewayConfigWithVersion renders a minimal, otherwise-valid stdio gateway config whose
// schemaVersion is spelled exactly as given (bare number or quoted string).
func gatewayConfigWithVersion(version string) string {
	return "schemaVersion: " + version + `
transport: stdio
upstreams:
  - name: u1
    transport: stdio
    command: echo
    args: ["hi"]
    enforcement: audit
`
}

// An unquoted `schemaVersion: 0.1` is auto-typed !!float by YAML. The tolerant probe that
// used to read the version was string-typed, so it failed on exactly that spelling and the
// error was swallowed: the version gate never ran, and the strict decode reported the whole
// document with an opaque "cannot unmarshal !!float into string" — about a line the
// operator had written in the most natural way. The gate now reads the scalar's verbatim
// text regardless of tag, and says what to do.
func TestLoadGatewayConfig_BareNumberSchemaVersionIsDiagnosed(t *testing.T) {
	t.Parallel()

	_, err := LoadGatewayConfig(writeConfig(t, gatewayConfigWithVersion("0.1")))
	if err == nil {
		t.Fatal("expected an error for a bare-number schemaVersion")
	}
	if !strings.Contains(err.Error(), "must be quoted") {
		t.Errorf("the error must tell the operator to quote it, got: %v", err)
	}
	if strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("the operator must not be shown the raw yaml type error, got: %v", err)
	}
}

// The verbatim text is what gets validated: "0.10" is a different version from "0.1" and
// must not be renormalized into acceptance by a numeric read.
func TestLoadGatewayConfig_BareNumberUnsupportedVersionReportsTheVersion(t *testing.T) {
	t.Parallel()

	_, err := LoadGatewayConfig(writeConfig(t, gatewayConfigWithVersion("9.9")))
	if err == nil {
		t.Fatal("expected an error for an unsupported schemaVersion")
	}
	// The version gate must fire (unsupported version), not the quoting hint: an operator
	// on a future grammar is not helped by being told to add quotes.
	if strings.Contains(err.Error(), "must be quoted") {
		t.Errorf("an unsupported version must be reported as such, not as a quoting problem: %v", err)
	}
}

// The quoted form is unaffected.
func TestLoadGatewayConfig_QuotedSchemaVersionLoads(t *testing.T) {
	t.Parallel()

	if _, err := LoadGatewayConfig(writeConfig(t, gatewayConfigWithVersion(`"0.1"`))); err != nil {
		t.Fatalf("a quoted schemaVersion must load: %v", err)
	}
}
