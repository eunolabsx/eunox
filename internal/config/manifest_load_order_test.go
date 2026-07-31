// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// A manifest declaring a grammar version this build does not model must be reported as
// an unsupported schemaVersion — not as carrying an "unknown key". Both the recursive
// key walk and the typed decode interpret content under the 0.1 grammar, so a future
// dialect's perfectly valid key looks unknown to them; surfacing that first would bury
// the one thing the operator can act on.
//
// The companion ordering — the key walk keeping ownership of the path-naming "did you
// mean" message for a typo'd condition or directive key, ahead of the blunter message
// the condition/directive decoders now produce themselves — is pinned by
// TestLoadManifest_RejectsUnknownKeys.
func TestLoadManifest_UnsupportedSchemaVersionReportedBeforeUnknownKeys(t *testing.T) {
	_, err := LoadManifest(writeManifestFile(t, `schemaVersion: "9.9"
name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    aKeyFromAFutureDialect: true
`))
	if err == nil {
		t.Fatal("expected an error for an unsupported schemaVersion")
	}
	if !strings.Contains(err.Error(), "schemaVersion") {
		t.Errorf("error = %q, want it to name the unsupported schemaVersion", err)
	}
	if strings.Contains(err.Error(), "unknown field") || strings.Contains(err.Error(), "unknown key") {
		t.Errorf("error = %q, want the version gate to fire BEFORE the unknown-key walk", err)
	}
}

// The same ordering must hold against the SCALAR-COERCION guard, which runs earlier still
// and also reads content under the current grammar. A future-dialect manifest whose
// condition values carry a scalar that guard rejects was reported as "quote it" — a
// spelling fix in a correctly-spelled file — while the actionable message (this build does
// not speak that dialect) never appeared.
func TestLoadManifest_UnsupportedSchemaVersionReportedBeforeScalarCoercion(t *testing.T) {
	_, err := LoadManifest(writeManifestFile(t, `schemaVersion: "9.9"
name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    conditions:
      - type: allowedValues
        argument: mode
        values: [010]
`))
	if err == nil {
		t.Fatal("expected an error for an unsupported schemaVersion")
	}
	if !strings.Contains(err.Error(), "schemaVersion") {
		t.Errorf("error = %q, want it to name the unsupported schemaVersion", err)
	}
	if strings.Contains(err.Error(), "quote it") {
		t.Errorf("error = %q, want the version gate to fire BEFORE the scalar-coercion guard", err)
	}
}

// The pre-decode probe must not become the authoritative check: it reads the source text
// off the parsed node, so a manifest with a SUPPORTED version still has to pass everything
// that follows, and one whose schemaVersion is not a plain scalar falls through to the
// post-decode check rather than being waved past.
func TestLoadManifest_SchemaVersionProbeIsNotAuthoritative(t *testing.T) {
	if _, err := LoadManifest(writeManifestFile(t, `schemaVersion:
  nested: "0.1"
name: p
version: "0.1.0"
capabilities: []
`)); err == nil {
		t.Fatal("expected an error: a non-scalar schemaVersion must still be rejected downstream")
	}
}

// A manifest whose top-level document is not an object must still be rejected. The key
// walk returns nil for it (there are no keys to walk), so the typed decode that now runs
// AFTER it is what fails closed — the reordering must not have opened a gap where a
// non-object document slips through unvalidated.
func TestLoadManifest_RejectsNonObjectDocument(t *testing.T) {
	if _, err := LoadManifest(writeManifestFile(t, "- not: an object\n")); err == nil {
		t.Fatal("expected an error for a non-object manifest document")
	}
}
