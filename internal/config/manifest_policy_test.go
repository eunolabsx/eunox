// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// TestHasMaxCalls_LoadedManifestPointerCondition: a
// manifest loaded through LoadManifest stores conditions as pointers
// (*capability.MaxCallsCondition), so a value-only type assertion was always
// false for real loaded manifests and the multi-instance "no --redis-addr"
// advisory never fired. HasMaxCalls must accept both the pointer and value forms.
func TestHasMaxCalls_LoadedManifestPointerCondition(t *testing.T) {
	yaml := `
name: "quota-policy"
version: "1.0.0"
capabilities:
  - target: "tool:send_email"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 5
        windowSeconds: 3600
`
	path := writeManifestFile(t, yaml)
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest rejected valid manifest: %v", err)
	}
	// Confirm the loader produced a pointer-typed condition (the shape that made
	// the value-only assertion always false).
	if len(m.Capabilities) != 1 || len(m.Capabilities[0].Conditions) != 1 {
		t.Fatalf("unexpected manifest shape: %d caps", len(m.Capabilities))
	}
	if _, ok := m.Capabilities[0].Conditions[0].(*capability.MaxCallsCondition); !ok {
		t.Fatalf("expected *capability.MaxCallsCondition, got %T", m.Capabilities[0].Conditions[0])
	}
	if !m.HasMaxCalls() {
		t.Error("HasMaxCalls() = false for a loaded manifest with a maxCalls condition; want true")
	}
}

// TestHasMaxCalls_ValueCondition covers the value-typed form (the JWT path builds
// value-typed conditions), so both arms of the type switch are exercised.
func TestHasMaxCalls_ValueCondition(t *testing.T) {
	m := &LocalManifest{
		Capabilities: []capability.Constraint{
			{
				Target:  "tool:send_email",
				Actions: []string{"call"},
				Conditions: []capability.Condition{
					capability.MaxCallsCondition{Count: 5, WindowSeconds: 3600},
				},
			},
		},
	}
	if !m.HasMaxCalls() {
		t.Error("HasMaxCalls() = false for a value-typed maxCalls condition; want true")
	}
}

// TestHasMaxCalls_None confirms a manifest with no maxCalls condition reports false.
func TestHasMaxCalls_None(t *testing.T) {
	yaml := `
name: "no-quota-policy"
version: "1.0.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
`
	path := writeManifestFile(t, yaml)
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest rejected valid manifest: %v", err)
	}
	if m.HasMaxCalls() {
		t.Error("HasMaxCalls() = true for a manifest without maxCalls; want false")
	}
	var nilManifest *LocalManifest
	if nilManifest.HasMaxCalls() {
		t.Error("HasMaxCalls() = true for a nil manifest; want false")
	}
	if nilManifest.AuditOnlyCount() != 0 {
		t.Error("AuditOnlyCount() != 0 for a nil manifest; want 0")
	}
}
