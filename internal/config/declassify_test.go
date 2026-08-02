// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// declassifyManifest wraps a capabilities body in a manifest declaring version.
func declassifyManifest(version, caps string) string {
	return "schemaVersion: \"" + version + "\"\nname: p\nversion: \"0.1.0\"\ncapabilities:\n" + caps
}

// TestDeclassify_Validation is the allow/deny/malformed table the grammar's standing test
// discipline requires for a new directive.
func TestDeclassify_Validation(t *testing.T) {
	cases := []struct {
		name, caps, wantErr string
	}{
		{
			name: "a well-formed declassify loads",
			caps: "  - target: \"tool:sanitize\"\n    actions: [call]\n    directives:\n      - type: declassify\n        labels: [pii]\n",
		},
		{
			name: "several labels load",
			caps: "  - target: \"resource:file:///clean/*\"\n    actions: [read]\n    directives:\n      - type: declassify\n        labels: [pii, confidential]\n",
		},
		{
			name:    "an unknown label is a load error",
			caps:    "  - target: \"tool:sanitize\"\n    actions: [call]\n    directives:\n      - type: declassify\n        labels: [secret]\n",
			wantErr: "unknown label \"secret\"",
		},
		{
			// An empty list clears nothing while still requiring an approval, so the
			// capability could never be satisfied.
			name:    "an empty label list is a load error",
			caps:    "  - target: \"tool:sanitize\"\n    actions: [call]\n    directives:\n      - type: declassify\n        labels: []\n",
			wantErr: "requires a non-empty 'labels' list",
		},
		{
			name:    "a misspelled key is a load error",
			caps:    "  - target: \"tool:sanitize\"\n    actions: [call]\n    directives:\n      - type: declassify\n        lables: [pii]\n",
			wantErr: "unknown field",
		},
		{
			// Clearing a label at an egress launders it at exactly the point the flow
			// layer exists to gate.
			name:    "a system: target is refused",
			caps:    "  - target: \"system:sampling/createMessage\"\n    actions: [allow]\n    directives:\n      - type: declassify\n        labels: [pii]\n",
			wantErr: "valid only on tool: or resource: source targets",
		},
		{
			name:    "a prompt: target is refused",
			caps:    "  - target: \"prompt:summarize\"\n    actions: [get]\n    directives:\n      - type: declassify\n        labels: [pii]\n",
			wantErr: "valid only on tool: or resource: source targets",
		},
		{
			// The two write the same session state in opposite directions on one call.
			name:    "labelOutput and declassify on one constraint is refused",
			caps:    "  - target: \"tool:sanitize\"\n    actions: [call]\n    directives:\n      - type: labelOutput\n        labels: [internal]\n      - type: declassify\n        labels: [pii]\n",
			wantErr: "both labelOutput and declassify",
		},
		{
			name:    "two declassify directives on one constraint is refused",
			caps:    "  - target: \"tool:sanitize\"\n    actions: [call]\n    directives:\n      - type: declassify\n        labels: [pii]\n      - type: declassify\n        labels: [confidential]\n",
			wantErr: "2 declassify directives on one constraint",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadManifest(writeManifestFile(t, declassifyManifest(ManifestSchemaVersion02, tc.caps)))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestDeclassify_RequiresTheFlowEffectGrammar keeps the "0.1" grammar closed: declassify
// is a "0.2" token and a 0.1 manifest using it is refused rather than silently enabling a
// directive that revision does not define.
func TestDeclassify_RequiresTheFlowEffectGrammar(t *testing.T) {
	caps := "  - target: \"tool:sanitize\"\n    actions: [call]\n    directives:\n      - type: declassify\n        labels: [pii]\n"
	_, err := LoadManifest(writeManifestFile(t, declassifyManifest("0.1", caps)))
	if err == nil {
		t.Fatal("declassify must be refused under the 0.1 grammar")
	}
	if !strings.Contains(err.Error(), "declassify directive was introduced in schemaVersion \"0.2\"") {
		t.Fatalf("err = %v, want it to name the introducing grammar version", err)
	}
}

// TestDeclassify_CountsAsFlowForTheSharedStateAdvisory pins that a declassify-only policy
// trips the multi-instance shared-state advisory: the directive reads and writes the same
// per-session label state labelOutput/flowLabel do, so a deployment running it without a
// shared backend has the same silent split-brain.
func TestDeclassify_CountsAsFlowForTheSharedStateAdvisory(t *testing.T) {
	caps := "  - target: \"tool:sanitize\"\n    actions: [call]\n    directives:\n      - type: declassify\n        labels: [pii]\n"
	m, err := LoadManifest(writeManifestFile(t, declassifyManifest(ManifestSchemaVersion02, caps)))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !m.HasFlowLabel() {
		t.Fatal("a declassify policy is flow-relevant")
	}
}

// TestTaskVar_ManifestValidation is the allow/deny/malformed table for the ${task.*}
// surface: a recognized reference loads, and every other ${...} shape is a LOAD error
// rather than an inert literal that denies every call at runtime.
func TestTaskVar_ManifestValidation(t *testing.T) {
	body := func(value string) string {
		return "  - target: \"tool:fetch\"\n    actions: [call]\n    conditions:\n      - type: allowedValues\n        argument: task\n        values: [\"" + value + "\"]\n"
	}
	cases := []struct {
		name, value, wantErr string
	}{
		{name: "task id", value: "${task.id}"},
		{name: "agent", value: "${task.agent}"},
		{name: "principal", value: "${task.principal}"},
		{name: "an ordinary literal is untouched", value: "task-42"},
		{name: "an ordinary glob is untouched", value: "task-*"},
		{name: "misspelled variable", value: "${task.identifier}", wantErr: "unknown task-context variable"},
		{name: "wrong namespace", value: "${env.HOME}", wantErr: "unknown task-context variable"},
		{name: "interpolated", value: "job-${task.id}", wantErr: "must be the ENTIRE value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadManifest(writeManifestFile(t, declassifyManifest(ManifestSchemaVersion02, body(tc.value))))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestTaskVar_RequiresTheFlowEffectGrammar keeps "0.1" closed against the variable
// surface too — the batch's one token that is a VALUE rather than a discriminator, and so
// the one a per-type gate would have missed.
func TestTaskVar_RequiresTheFlowEffectGrammar(t *testing.T) {
	caps := "  - target: \"tool:fetch\"\n    actions: [call]\n    conditions:\n      - type: allowedValues\n        argument: task\n        values: [\"${task.id}\"]\n"
	_, err := LoadManifest(writeManifestFile(t, declassifyManifest("0.1", caps)))
	if err == nil {
		t.Fatal("a task-context variable must be refused under the 0.1 grammar")
	}
	if !strings.Contains(err.Error(), "was introduced in schemaVersion \"0.2\"") {
		t.Fatalf("err = %v, want it to name the introducing grammar version", err)
	}
}

// TestTaskVarNames_MatchTheLoaderVocabulary is the drift guard between the closed set the
// package exports and what the loader accepts: a variable added to one and not the other
// would either be undocumented or unloadable.
func TestTaskVarNames_MatchTheLoaderVocabulary(t *testing.T) {
	for _, name := range capability.TaskVarNames() {
		if err := capability.ValidateVariableRef("${" + name + "}"); err != nil {
			t.Fatalf("exported variable %q is rejected by the loader gate: %v", name, err)
		}
	}
}

// TestTaskVar_LiteralBracesStillLoadUnder01 is the compatibility guard for the revision the
// variable surface does NOT exist in.
//
// The reference check first shipped ungated, which turned any pre-existing "0.1" manifest
// whose allowlist held template-shaped text ("${HOME}/reports", "greeting-${name}") into a
// hard load failure — and a manifest that fails to load is a proxy that refuses to start.
// Under "0.1" a "${" is an ordinary character in a literal value (it is not a glob
// metacharacter), so those documents must keep loading exactly as they did.
func TestTaskVar_LiteralBracesStillLoadUnder01(t *testing.T) {
	body := func(value string) string {
		return "  - target: \"tool:fetch\"\n    actions: [call]\n    conditions:\n      - type: allowedValues\n        argument: a\n        values: [\"" + value + "\"]\n"
	}
	for _, value := range []string{"${HOME}/reports", "greeting-${name}", "${BUILD_ID}", "${env.HOME}"} {
		t.Run(value, func(t *testing.T) {
			if _, err := LoadManifest(writeManifestFile(t, declassifyManifest("0.1", body(value)))); err != nil {
				t.Fatalf("a literal %q was valid under 0.1 before the variable surface existed and must stay valid: %v", value, err)
			}
		})
	}
	// A RECOGNIZED reference is the one shape 0.1 must still refuse — it is a 0.2 token,
	// and the refusal names the revision that introduced it.
	_, err := LoadManifest(writeManifestFile(t, declassifyManifest("0.1", body("${task.id}"))))
	if err == nil || !strings.Contains(err.Error(), "was introduced in schemaVersion \"0.2\"") {
		t.Fatalf("a recognized task variable must still be refused under 0.1, got %v", err)
	}
	// Under 0.2 the closed-grammar rule applies in full: an unrecognized ${...} is a load
	// error rather than an inert literal.
	_, err = LoadManifest(writeManifestFile(t, declassifyManifest(ManifestSchemaVersion02, body("${env.HOME}"))))
	if err == nil || !strings.Contains(err.Error(), "unknown task-context variable") {
		t.Fatalf("under 0.2 an unrecognized reference must be a load error, got %v", err)
	}
}
