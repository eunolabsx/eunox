// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// TestLoadGatewayConfig_SchemaVersionGatedBeforeStrictDecode pins the loader's error
// ORDERING: the declared grammar version is checked before the strict (KnownFields)
// decode reports an unknown key.
//
// The two run in the opposite order to the manifest loader's deliberate one
// (validateManifestSchemaVersion ahead of checkManifestKeys), so a config written for
// a FUTURE grammar — necessarily carrying keys this binary's structs do not model —
// was reported as a typo: "field flowPolicy not found in type config.GatewayConfig".
// That sends an operator hunting a spelling mistake in a correctly-spelled file when
// the real answer is "this binary does not speak that dialect; upgrade it".
func TestLoadGatewayConfig_SchemaVersionGatedBeforeStrictDecode(t *testing.T) {
	t.Parallel()

	// A future grammar version AND a key only that grammar would know.
	_, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "99.0"
someFutureGrammarKey: true
upstreams:
  - name: mock
    transport: stdio
    command: echo
`))
	if err == nil {
		t.Fatal("expected an error for an unsupported schemaVersion, got nil")
	}
	if !strings.Contains(err.Error(), "schemaVersion") {
		t.Errorf("error should name the unsupported schemaVersion, got: %v", err)
	}
	if strings.Contains(err.Error(), "someFutureGrammarKey") {
		t.Errorf("error blamed the future-grammar key instead of the unsupported grammar version: %v", err)
	}
}

// TestLoadGatewayConfig_UnknownKeyStillReportedOnSupportedVersion is the other half:
// gating the version first must not swallow the strict decode. On a SUPPORTED version
// an unknown key is still reported as an unknown key, so a plain typo keeps its
// precise message.
func TestLoadGatewayConfig_UnknownKeyStillReportedOnSupportedVersion(t *testing.T) {
	t.Parallel()

	_, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
upstreamms: true
upstreams:
  - name: mock
    transport: stdio
    command: echo
`))
	if err == nil {
		t.Fatal("expected an error for an unknown top-level key, got nil")
	}
	if !strings.Contains(err.Error(), "upstreamms") {
		t.Errorf("error should name the unknown key, got: %v", err)
	}
}

// TestLoadGatewayConfig_MalformedYAMLStillReportsSyntaxError guards the tolerant
// pre-read's failure mode: a document that will not parse as YAML at all must fall
// through to the strict decode's own path-qualified syntax error, not be silently
// treated as "no schemaVersion declared".
func TestLoadGatewayConfig_MalformedYAMLStillReportsSyntaxError(t *testing.T) {
	t.Parallel()

	_, err := LoadGatewayConfig(writeConfig(t, "schemaVersion: \"0.1\"\nupstreams: [oops\n"))
	if err == nil {
		t.Fatal("expected a parse error for malformed YAML, got nil")
	}
	if !strings.Contains(err.Error(), "parsing gateway config") {
		t.Errorf("want the strict decode's parse error, got: %v", err)
	}
}
