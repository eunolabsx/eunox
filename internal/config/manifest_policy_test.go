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

// TestHonorsAttributionInterface_RequiresTheFlowEffectGrammar pins the runtime staging
// gate for the attribution interface.
//
// The repo's staging discipline is that a DRAFT grammar token must be refused under the
// published grammar, and checkTokenGrammarVersion enforces that at load for every
// token that appears IN a manifest. The attribution interface cannot ride that gate: its
// token (`io.eunolabs.context-manifest`) arrives in a REQUEST's `_meta`, so there is
// nothing to reject at load and the gate has to be a runtime predicate the transport
// consults per call. Without this, a `0.1` operator got a draft feature — including its
// malformed-request rejection — that is not in the grammar they declared.
func TestHonorsAttributionInterface_RequiresTheFlowEffectGrammar(t *testing.T) {
	cases := []struct {
		name    string
		version string
		want    bool
	}{
		{"the published grammar does not contain the token", "0.1", false},
		{"a bare version string is likewise published-grammar", "0.1.0", false},
		{"an unset version cannot be an opt-in", "", false},
		{"the flow+effect grammar admits it", ManifestSchemaVersion02, true},
		{"surrounding whitespace does not defeat the gate", "  " + ManifestSchemaVersion02 + "  ", true},
		{"a future draft is not this draft", "0.3-draft", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &LocalManifest{SchemaVersion: c.version}
			if got := m.HonorsAttributionInterface(); got != c.want {
				t.Errorf("HonorsAttributionInterface() = %v, want %v for schemaVersion %q", got, c.want, c.version)
			}
		})
	}

	// A route with no policy has no schema version, so it has no draft opt-in either.
	// Nil-safe because the binary calls this on a manifest that is nil in audit/wiretap
	// mode, where a panic would take down startup.
	var nilManifest *LocalManifest
	if nilManifest.HonorsAttributionInterface() {
		t.Error("a nil manifest must not opt into a draft token")
	}
}

// TestNeedsDecisionTurn is the predicate both transports gate their decision turn on. It was
// spelled out at each of them, and a mirrored condition's failure mode is silent: a third
// state-accumulating token added to one copy leaves one transport serializing and the other
// racing the source->sink ordering the turn exists to guarantee.
func TestNeedsDecisionTurn(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		m    *LocalManifest
		want bool
	}{
		"nil manifest accumulates nothing": {nil, false},
		"no state-accumulating token": {&LocalManifest{Capabilities: []capability.Constraint{{
			Target: "tool:x", Actions: []string{"call"},
			Conditions: []capability.Condition{capability.MaxCallsCondition{Count: 1, WindowSeconds: 60}},
		}}}, false},
		"a flowLabel sink reads what a source wrote": {&LocalManifest{Capabilities: []capability.Constraint{{
			Target: "tool:x", Actions: []string{"call"},
			Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic}}},
		}}}, true},
		"a labelOutput source writes what a sink reads": {&LocalManifest{Capabilities: []capability.Constraint{{
			Target: "tool:x", Actions: []string{"call"},
			Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelPII}}},
		}}}, true},
		"a declassify directive splits its write across two phases": {&LocalManifest{Capabilities: []capability.Constraint{{
			Target: "tool:x", Actions: []string{"call"},
			Directives: []capability.Directive{capability.DeclassifyDirective{Labels: []string{capability.FlowLabelPII}}},
		}}}, true},
		"a sequenceBlock antecedent has the same shape": {&LocalManifest{Capabilities: []capability.Constraint{{
			Target: "tool:x", Actions: []string{"call"},
			Conditions: []capability.Condition{capability.SequenceBlockCondition{AfterTools: []string{"tool:y"}}},
		}}}, true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := tc.m.NeedsDecisionTurn(); got != tc.want {
				t.Errorf("NeedsDecisionTurn() = %v, want %v", got, tc.want)
			}
		})
	}
}
