// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// TestFlowEffect_RequireTheFlowEffectGrammar is the closed-grammar assertion across
// revisions: the flowLabel condition and labelOutput directive are NOT part of "0.1".
// A manifest declaring 0.1 that uses one is rejected; the same manifest under the
// flow+effect grammar ("0.2") loads. A published revision does not retroactively widen
// the one before it.
func TestFlowEffect_RequireTheFlowEffectGrammar(t *testing.T) {
	flowLabelBody := `name: p
version: "0.1.0"
capabilities:
  - target: "tool:send_email"
    actions: [call]
    conditions:
      - type: flowLabel
        allow: [public, internal]
`
	labelOutputBody := `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_secret"
    actions: [call]
    directives:
      - type: labelOutput
        labels: [confidential]
`

	cases := []struct {
		name    string
		version string
		body    string
		wantErr string // "" means it must load
	}{
		{"flowLabel rejected under 0.1", "0.1", flowLabelBody, "was introduced in schemaVersion \"0.2\""},
		{"labelOutput rejected under 0.1", "0.1", labelOutputBody, "was introduced in schemaVersion \"0.2\""},
		{"flowLabel accepted under the flow+effect grammar", ManifestSchemaVersion02, flowLabelBody, ""},
		{"labelOutput accepted under the flow+effect grammar", ManifestSchemaVersion02, labelOutputBody, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yaml := "schemaVersion: \"" + tc.version + "\"\n" + tc.body
			path := writeManifestFile(t, yaml)
			_, err := LoadManifest(path)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("LoadManifest rejected a 0.2 manifest: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("LoadManifest accepted %s under schemaVersion %s, want rejection", tc.name, tc.version)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestFlowEffect_LabelVocabularyValidation drives the closed-vocabulary validation:
// an unknown label in flowLabel.allow or labelOutput.labels is a load-time error, and
// labelOutput requires a non-empty labels list. All under the draft schemaVersion so
// the staging gate is already satisfied and only the vocabulary check is exercised.
func TestFlowEffect_LabelVocabularyValidation(t *testing.T) {
	draft := "schemaVersion: \"" + ManifestSchemaVersion02 + "\"\n"
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name: "unknown flowLabel allow label",
			body: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:send_email"
    actions: [call]
    conditions:
      - type: flowLabel
        allow: [public, sekret]
`,
			wantErr: "unknown flow label \"sekret\"",
		},
		{
			name: "unknown labelOutput label",
			body: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_secret"
    actions: [call]
    directives:
      - type: labelOutput
        labels: [toppublic]
`,
			wantErr: "unknown flow label \"toppublic\"",
		},
		{
			name: "empty labelOutput labels",
			body: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_secret"
    actions: [call]
    directives:
      - type: labelOutput
        labels: []
`,
			wantErr: "non-empty 'labels'",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifestFile(t, draft+tc.body)
			_, err := LoadManifest(path)
			if err == nil {
				t.Fatalf("LoadManifest accepted %s, want rejection", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestLabelOutput_AllowedOnResourceTarget confirms the directive-target relaxation:
// labelOutput is valid on a resource: source (a sensitive read is a flow source), where
// redactFields — a response mutation — remains tool-only. An empty allow flowLabel is
// also accepted (the strictest sink), proving empty is a valid rule, not a malformed one.
func TestLabelOutput_AllowedOnResourceTarget(t *testing.T) {
	draft := "schemaVersion: \"" + ManifestSchemaVersion02 + "\"\n"

	ok := draft + `name: p
version: "0.1.0"
capabilities:
  - target: "resource:file:///secrets/*"
    actions: [read]
    directives:
      - type: labelOutput
        labels: [confidential]
  - target: "tool:send_email"
    actions: [call]
    conditions:
      - type: flowLabel
        allow: []
`
	if _, err := LoadManifest(writeManifestFile(t, ok)); err != nil {
		t.Fatalf("labelOutput on a resource: target (and empty-allow flowLabel) must load, got %v", err)
	}

	// redactFields on a resource: target is still rejected (response mutation, tool-only).
	bad := draft + `name: p
version: "0.1.0"
capabilities:
  - target: "resource:file:///secrets/*"
    actions: [read]
    directives:
      - type: redactFields
        fields: [ssn]
`
	_, err := LoadManifest(writeManifestFile(t, bad))
	if err == nil || !strings.Contains(err.Error(), "apply only to tool: targets") {
		t.Fatalf("redactFields on resource: must stay rejected, got %v", err)
	}
}

// TestFlowEffect_UnknownKeyRejected locks in the closed-grammar guarantee for the new
// tokens: an unrecognized key inside a flowLabel condition or a labelOutput directive is
// a load error (conditionKeysFor/directiveKeysFor now cover them), not silently dropped
// — so a typo like `allowed:` for `allow:` cannot silently turn a sink into deny-all.
func TestFlowEffect_UnknownKeyRejected(t *testing.T) {
	draft := "schemaVersion: \"" + ManifestSchemaVersion02 + "\"\n"
	cases := []struct{ name, body, wantErr string }{
		{
			"typo'd flowLabel key",
			`name: p
version: "0.1.0"
capabilities:
  - target: "tool:send_email"
    actions: [call]
    conditions:
      - type: flowLabel
        allowed: [public]
`,
			"unknown field \"allowed\"",
		},
		{
			"bogus labelOutput key",
			`name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_secret"
    actions: [call]
    directives:
      - type: labelOutput
        labels: [confidential]
        onlyOn: read
`,
			"unknown field \"onlyOn\"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadManifest(writeManifestFile(t, draft+tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want rejection containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestLabelOutput_RejectedOnSystemTarget confirms labelOutput is a source directive
// valid only on tool:/resource: targets; a system: target is rejected at load, so a
// sampling-leg state/tape mismatch cannot be authored.
func TestLabelOutput_RejectedOnSystemTarget(t *testing.T) {
	draft := "schemaVersion: \"" + ManifestSchemaVersion02 + "\"\n"
	body := draft + `name: p
version: "0.1.0"
capabilities:
  - target: "system:sampling/createMessage"
    actions: [allow]
    directives:
      - type: labelOutput
        labels: [confidential]
`
	_, err := LoadManifest(writeManifestFile(t, body))
	if err == nil || !strings.Contains(err.Error(), "tool: or resource:") {
		t.Fatalf("labelOutput on system: must be rejected, got %v", err)
	}
}

// TestImportedSensitivity_NamespaceClosure drives the load-time closure the imported
// sensitivity axis rests on. eunox cannot own the taxonomy's VALUES, so the namespace
// declaration is the only closure left: it is what turns a misspelled taxonomy name into a
// load error instead of a label that taints where nothing admits it and reads, much later,
// as a mysterious denial.
func TestImportedSensitivity_NamespaceClosure(t *testing.T) {
	v2 := "schemaVersion: \"" + ManifestSchemaVersion02 + "\"\n"
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name: "declared namespace loads on both halves",
			body: `name: p
version: "0.1.0"
flowLabelNamespaces: [purview, msip]
capabilities:
  - target: "tool:read_doc"
    actions: [call]
    directives:
      - type: labelOutput
        labels: [pii, "purview:highly-confidential"]
  - target: "tool:send_email"
    actions: [call]
    conditions:
      - type: flowLabel
        allow: [public, "msip:general"]
`,
		},
		{
			name: "undeclared namespace in labelOutput",
			body: `name: p
version: "0.1.0"
flowLabelNamespaces: [purview]
capabilities:
  - target: "tool:read_doc"
    actions: [call]
    directives:
      - type: labelOutput
        labels: ["msip:confidential"]
`,
			wantErr: "does not declare",
		},
		{
			// The typo this closure exists for: without the declaration it would load
			// clean and simply never match the sink that spells it correctly.
			name: "misspelled namespace is a load error",
			body: `name: p
version: "0.1.0"
flowLabelNamespaces: [purview]
capabilities:
  - target: "tool:send_email"
    actions: [call]
    conditions:
      - type: flowLabel
        allow: ["purvew:general"]
`,
			wantErr: "does not declare",
		},
		{
			name: "no declaration admits no imported label",
			body: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_doc"
    actions: [call]
    directives:
      - type: labelOutput
        labels: ["purview:confidential"]
`,
			wantErr: "does not declare",
		},
		{
			name: "malformed namespace declaration",
			body: `name: p
version: "0.1.0"
flowLabelNamespaces: ["Purview"]
capabilities: []
`,
			wantErr: "must start with a lowercase letter",
		},
		{
			name: "duplicate namespace declaration",
			body: `name: p
version: "0.1.0"
flowLabelNamespaces: [purview, purview]
capabilities: []
`,
			wantErr: "declares \"purview\" twice",
		},
		{
			name: "malformed imported label value",
			body: `name: p
version: "0.1.0"
flowLabelNamespaces: [purview]
capabilities:
  - target: "tool:read_doc"
    actions: [call]
    directives:
      - type: labelOutput
        labels: ["purview:highly confidential"]
`,
			wantErr: "printable ASCII with no spaces",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadManifest(writeManifestFile(t, v2+tc.body))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("LoadManifest rejected a valid manifest: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("LoadManifest accepted %s, want rejection", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestFlowLabelNamespaces_RefusedUnder01 pins the grammar gate. flowLabelNamespaces has no
// prototype-registry entry of its own (it is not a discriminator), so it is gated inside
// checkTokenGrammarVersion beside effectCeiling — and that gate is what keeps a later
// revision's surface from silently widening an earlier one.
func TestFlowLabelNamespaces_RefusedUnder01(t *testing.T) {
	body := "schemaVersion: \"" + ManifestSchemaVersion01 + `"
name: p
version: "0.1.0"
flowLabelNamespaces: [purview]
capabilities: []
`
	_, err := LoadManifest(writeManifestFile(t, body))
	if err == nil || !strings.Contains(err.Error(), "flowLabelNamespaces was introduced in schemaVersion") {
		t.Fatalf("flowLabelNamespaces must be refused under %q, got %v", ManifestSchemaVersion01, err)
	}
}

// TestMergeManifests_UnionsFlowLabelNamespaces pins the union fold. Two files each
// declaring the taxonomy their own capabilities use are COMPOSING, not disagreeing, so the
// conflict check Audience and effectCeiling take would make the axis unusable across a
// split policy. Nothing widens: a namespace only permits labels, and a label can only add
// taint or narrow an allow-set.
func TestMergeManifests_UnionsFlowLabelNamespaces(t *testing.T) {
	load := func(body string) *LocalManifest {
		t.Helper()
		m, err := LoadManifest(writeManifestFile(t, "schemaVersion: \""+ManifestSchemaVersion02+"\"\n"+body))
		if err != nil {
			t.Fatalf("LoadManifest: %v", err)
		}
		return m
	}
	a := load(`name: a
version: "0.1.0"
flowLabelNamespaces: [purview]
capabilities:
  - target: "tool:read_doc"
    actions: [call]
    directives:
      - type: labelOutput
        labels: ["purview:confidential"]
`)
	b := load(`name: b
version: "0.1.0"
flowLabelNamespaces: [msip, purview]
capabilities:
  - target: "tool:send_email"
    actions: [call]
    conditions:
      - type: flowLabel
        allow: ["msip:general"]
`)
	merged, err := MergeManifests([]*LocalManifest{a, b})
	if err != nil {
		t.Fatalf("MergeManifests rejected a composing pair: %v", err)
	}
	// First-seen order, deduplicated — and the merged whole re-validates, so each file's
	// imported labels still resolve against the union.
	want := []string{"purview", "msip"}
	if len(merged.FlowLabelNamespaces) != len(want) {
		t.Fatalf("merged namespaces = %v, want %v", merged.FlowLabelNamespaces, want)
	}
	for i, ns := range want {
		if merged.FlowLabelNamespaces[i] != ns {
			t.Errorf("merged namespaces = %v, want %v", merged.FlowLabelNamespaces, want)
			break
		}
	}
}
