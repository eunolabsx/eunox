// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// manifest_validation_test.go covers action–namespace pairing validation
// exercised through the full LoadManifest → validateLocalManifest path with
// real YAML files. These tests confirm that:
//   - The validation fires on every code path that loads a manifest (LoadManifest,
//     proxy startup, validate subcommand — all use LoadManifest).
//   - YAML manifests with invalid action–namespace pairings are rejected with a
//     descriptive error that names the constraint and the invalid action.
//   - Valid manifests covering all four namespace types load without error.
//   - The empty-name, missing-prefix, and wildcard-action cases are all covered.

// manifest_namespace_test.go covers manifest validation:
// namespace prefix requirement and action–namespace pairing rules.

// manifest_ipcompile_test.go verifies that LoadManifest pre-compiles ipRange
// CIDRs at load time so the per-request enforcement hot path never
// calls net.ParseCIDR. The condition the engine evaluates at runtime is the same
// *capability.IPRangeCondition the loader compiled, so asserting Networks() on
// the loaded manifest proves the wiring end to end.

// Unit tests for jsonFieldKeys, the reflective JSON-key extractor used by the
// manifest's unknown-field guard. The table covers every tag shape: named,
// named-with-options, skipped ("-"), untagged (falls back to the Go field
// name), pointer types, and promoted keys from an anonymous embedded struct.

// examples_policies_test.go guards the claim in examples/policies/README.md that
// every reference policy in that directory is "`eunox validate`-clean". Each
// file is loaded through LoadManifest — the exact path the `validate` subcommand
// uses (cmd/eunox/main.go) — so a policy that would be rejected at validate
// time (e.g. an allowedExtensions condition missing its required `argument:`
// field) fails the build instead of shipping silently. The cases are derived
// from a glob of the directory, so a newly added policy is covered automatically.

package config

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// writeManifestFile writes content to a temp file with a .yaml extension and
// returns its path. The file is removed at test cleanup.
func writeManifestFile(t *testing.T, content string) string {
	t.Helper()
	// These content-focused fixtures omit the required schemaVersion for brevity;
	// inject a supported one so each test reaches its actual assertion. The
	// schemaVersion gate itself is covered by TestLoadManifest_SchemaVersion.
	if !strings.Contains(content, "schemaVersion") {
		content = "schemaVersion: \"0.1\"\n" + content
	}
	f, err := os.CreateTemp(t.TempDir(), "manifest-*.yaml")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	_ = f.Close()
	return f.Name()
}

// TestLoadManifest_RejectsMultipleDocuments: a manifest followed by a second
// "---" YAML document must be rejected, not silently truncated to the first
// document. Otherwise an operator who appends a restrictive manifest would get a
// passing load that enforces none of the trailing content.
func TestLoadManifest_RejectsMultipleDocuments(t *testing.T) {
	content := "schemaVersion: \"0.1\"\ncapabilities: []\n---\nschemaVersion: \"0.1\"\ncapabilities:\n  - target: \"tool:evil\"\n    actions: [call]\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	if _, err := LoadManifest(path); err == nil {
		t.Fatal("expected an error loading a multi-document manifest, got nil")
	} else if !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Errorf("error = %q; want it to mention multiple YAML documents", err)
	}
}

// TestLoadManifest_ToleratesTrailingEmptyDoc: a single valid manifest followed by a
// bare "---" separator (which some editors or CI templating append) carries no
// enforceable content and must load successfully, matching the gateway-config loader
// — only a content-bearing second document is rejected.
func TestLoadManifest_ToleratesTrailingEmptyDoc(t *testing.T) {
	content := "schemaVersion: \"0.1\"\nname: \"trailing-sep\"\nversion: \"0.1.0\"\ncapabilities: []\n---\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "trailing.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	if _, err := LoadManifest(path); err != nil {
		t.Fatalf("a trailing empty document must be tolerated, got: %v", err)
	}
}

// TestLoadManifest_UnquotedDatesStayStrings: an unquoted
// date in a manifest (which yaml.v3 would otherwise infer as a timestamp and the
// YAML->JSON round-trip would rewrite to "2026-01-01T00:00:00Z") must load as its
// literal string, or an allowedValues condition silently enforces a different
// value than the operator wrote and denies calls that should be allowed.
func TestLoadManifest_UnquotedDatesStayStrings(t *testing.T) {
	yaml := `
name: "date-policy"
version: "1.0.0"
capabilities:
  - target: "tool:send_email"
    actions: [call]
    conditions:
      - type: allowedValues
        argument: scheduled_date
        values:
          - 2026-01-01
          - 2026-06-30
`
	path := writeManifestFile(t, yaml)
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest rejected valid manifest: %v", err)
	}
	if len(m.Capabilities) != 1 || len(m.Capabilities[0].Conditions) != 1 {
		t.Fatalf("unexpected manifest shape: %d caps", len(m.Capabilities))
	}
	av, ok := m.Capabilities[0].Conditions[0].(*capability.AllowedValuesCondition)
	if !ok {
		t.Fatalf("expected AllowedValuesCondition, got %T", m.Capabilities[0].Conditions[0])
	}
	want := []string{"2026-01-01", "2026-06-30"}
	if len(av.Values) != len(want) {
		t.Fatalf("expected %d values, got %v", len(want), av.Values)
	}
	for i, w := range want {
		got, isStr := av.Values[i].(string)
		if !isStr {
			t.Fatalf("value %d is %T (%v), want a string — an unquoted date must not become a timestamp", i, av.Values[i], av.Values[i])
		}
		if got != w {
			t.Errorf("value %d = %q, want %q — unquoted date silently rewritten", i, got, w)
		}
	}
}

// TestLoadManifest_RejectsCoercedNumericValues pins: an unquoted YAML scalar
// in an allowedValues values: list that auto-types away from the author's text — a
// leading-zero octal (010 -> 8) or a decimal-pointed int (1.0 -> 1) — is rejected at
// load with a clear "quote it / write the number" message, rather than silently
// enforcing a different value. A clean numeric value (200) and an explicitly quoted
// string ("010") both still load.
func TestLoadManifest_RejectsCoercedNumericValues(t *testing.T) {
	mkYAML := func(value string) string {
		return `
name: "t"
version: "1.0.0"
capabilities:
  - target: "tool:transfer"
    actions: [call]
    conditions:
      - type: allowedValues
        argument: code
        values: [` + value + `]
`
	}

	for _, bad := range []string{"010", "1.0", "+5", "0x10", "0.0"} {
		t.Run("reject_"+bad, func(t *testing.T) {
			_, err := LoadManifest(writeManifestFile(t, mkYAML(bad)))
			if err == nil {
				t.Fatalf("expected rejection of an auto-typed values entry %q, got nil", bad)
			}
			if !strings.Contains(err.Error(), "quote it") {
				t.Errorf("error should guide the author to quote/canonicalize, got: %v", err)
			}
		})
	}

	for _, ok := range []string{`"010"`, "200", "1.5", "-3", `"1.0"`} {
		t.Run("accept_"+strings.Trim(ok, `"`), func(t *testing.T) {
			if _, err := LoadManifest(writeManifestFile(t, mkYAML(ok))); err != nil {
				t.Errorf("a clean/quoted values entry %q must load, got: %v", ok, err)
			}
		})
	}

	// A YAML anchor/alias must not smuggle a coerced scalar past the guard: the
	// alias element resolves to the anchored `010` (octal 8) at decode time, so the
	// guard must follow the alias and reject it.
	aliasYAML := `
name: "t"
version: "1.0.0"
anchors:
  code: &leadingzero 010
capabilities:
  - target: "tool:transfer"
    actions: [call]
    conditions:
      - type: allowedValues
        argument: code
        values: [*leadingzero]
`
	if _, err := LoadManifest(writeManifestFile(t, aliasYAML)); err == nil {
		t.Error("expected rejection of a coerced value smuggled via a YAML alias, got nil")
	} else if !strings.Contains(err.Error(), "quote it") {
		t.Errorf("alias-bypass error should guide quoting/canonicalizing, got: %v", err)
	}

	// The same guard applies to an argumentSchema enum list.
	enumYAML := `
name: "t"
version: "1.0.0"
capabilities:
  - target: "tool:transfer"
    actions: [call]
    argumentSchema:
      type: object
      properties:
        code: { type: string, enum: [010] }
`
	if _, err := LoadManifest(writeManifestFile(t, enumYAML)); err == nil {
		t.Error("expected rejection of an auto-typed enum entry 010, got nil")
	}
}

// TestLoadManifest_SelfReferentialAliasDoesNotStackOverflow is a regression test for a
// self-referential YAML anchor in a values: list: an alias whose only content is a
// reference back to its own anchor (values: &loop [*loop]) previously recursed forever
// in checkValueScalarNotCoerced (no cycle guard), overflowing the stack with an
// uncatchable fatal error that killed the whole process. The list carries no numeric
// scalar at all, so the coercion guard itself finds nothing to reject; what matters here
// is that LoadManifest returns at all instead of crashing the test binary.
func TestLoadManifest_SelfReferentialAliasDoesNotStackOverflow(t *testing.T) {
	yaml := `
name: "t"
version: "1.0.0"
capabilities:
  - target: "tool:x"
    actions: [call]
    conditions:
      - type: allowedValues
        argument: p
        values: &loop
          - *loop
`
	_, err := LoadManifest(writeManifestFile(t, yaml))
	t.Logf("LoadManifest on a self-referential alias returned: %v", err)
}

// TestLoadManifest_CyclicAliasStillDetectsReachableCoercion pins that the cycle guard
// does not simply give up on the whole list at the first self-reference: a coercion
// reachable elsewhere in the same cyclic graph must still be caught. The list aliases
// back to itself (an infinite structure) AND carries a genuine unquoted-octal sibling
// entry; the walk must terminate on the cycle without skipping the sibling.
func TestLoadManifest_CyclicAliasStillDetectsReachableCoercion(t *testing.T) {
	yaml := `
name: "t"
version: "1.0.0"
capabilities:
  - target: "tool:x"
    actions: [call]
    conditions:
      - type: allowedValues
        argument: p
        values: &loop
          - *loop
          - 010
`
	_, err := LoadManifest(writeManifestFile(t, yaml))
	if err == nil {
		t.Fatal("expected rejection of the coerced 010 entry reachable inside the cyclic list, got nil")
	}
	if !strings.Contains(err.Error(), "quote it") {
		t.Errorf("error should guide the author to quote/canonicalize, got: %v", err)
	}
}

// ── Valid manifests load without error ───────────────────────────────────────

func TestLoadManifest_ValidV04_AllNamespaces(t *testing.T) {
	yaml := `
name: "full-v04-manifest"
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
  - target: "tool:query_db"
    actions: ["*"]
  - target: "resource:file:///data/reports/*"
    actions: [read]
  - target: "prompt:code_review"
    actions: [get]
  - target: "prompt:*"
    actions: ["*"]
  - target: "system:sampling/createMessage"
    actions: [allow]
`
	path := writeManifestFile(t, yaml)
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest rejected valid manifest: %v", err)
	}
	if len(m.Capabilities) != 6 {
		t.Errorf("expected 6 capabilities, got %d", len(m.Capabilities))
	}
}

func TestLoadManifest_ValidV04_JSON(t *testing.T) {
	// LoadManifest also accepts JSON files; validate the same pairing rules.
	json := `{
  "schemaVersion": "0.1",
  "name": "json-manifest",
  "version": "1.0.0",
  "capabilities": [
    {"target": "tool:write_file", "actions": ["call"]},
    {"target": "resource:s3://bucket/*", "actions": ["read"]},
    {"target": "system:sampling/createMessage", "actions": ["allow"]}
  ]
}`
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, []byte(json), 0o600); err != nil {
		t.Fatalf("writing JSON manifest: %v", err)
	}
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest rejected valid JSON manifest: %v", err)
	}
	if len(m.Capabilities) != 3 {
		t.Errorf("expected 3 capabilities, got %d", len(m.Capabilities))
	}
}

func TestLoadManifest_TargetPatternBreadth(t *testing.T) {
	accept := []struct {
		name, target, action string
	}{
		{"tool prefix glob", "tool:read_*", "call"},
		{"tool suffix glob", "tool:*_report", "call"},
		// A bare run of ONLY "?" is bounded (path.Match's "?" matches exactly one
		// character), so "tool:??" scopes to two-character tool names — not a
		// match-everything target — and must NOT be rejected as a bare wildcard.
		{"tool single question mark", "tool:?", "call"},
		{"tool double question mark", "tool:??", "call"},
		{"resource path glob", "resource:file:///data/reports/*", "read"},
		{"resource concrete authority glob path", "resource:db://warehouse/*", "read"},
		{"resource multi-segment path glob", "resource:api://crm/customers/**", "read"},
		{"resource opaque exact uri", "resource:mailto:ops@example.com", "read"},
		{"prompt bare wildcard", "prompt:*", "get"},
		{"prompt prefix glob", "prompt:summarize_*", "get"},
		{"system fixed identifier", "system:sampling/createMessage", "allow"},
	}
	for _, tc := range accept {
		t.Run("accept "+tc.name, func(t *testing.T) {
			yaml := `
name: "ok"
version: "0.1.0"
capabilities:
  - target: "` + tc.target + `"
    actions: [` + tc.action + `]
`
			path := writeManifestFile(t, yaml)
			if _, err := LoadManifest(path); err != nil {
				t.Fatalf("LoadManifest rejected %q: %v", tc.target, err)
			}
		})
	}

	reject := []struct {
		name, target, action, wantErr string
	}{
		{"tool bare wildcard", "tool:*", "call", "bare tool wildcard"},
		{"tool double-star wildcard", "tool:**", "call", "bare tool wildcard"},
		{"resource bare wildcard", "resource:*", "read", "bare resource wildcard"},
		{"resource double-star wildcard", "resource:**", "read", "bare resource wildcard"},
		{"resource wildcard authority", "resource:api://*", "read", "URI scheme or authority"},
		{"resource wildcard authority with path", "resource:api://*/v1/*", "read", "URI scheme or authority"},
		{"resource wildcard scheme", "resource:*://warehouse/*", "read", "URI scheme or authority"},
		{"resource opaque mailto wildcard", "resource:mailto:*", "read", "opaque"},
		{"resource opaque urn wildcard", "resource:urn:isbn:*", "read", "opaque"},
		// An opaque URI is opaque even when its scheme-specific part contains a "/"
		// (a URN namespace-specific string, a path-like opaque value): only a "//"
		// authority makes it hierarchical. A glob in such a target must still be
		// rejected — keying off any "/" let this one slip past the opaque guard.
		{"resource opaque urn wildcard with slash", "resource:urn:example:foo/bar*", "read", "opaque"},
		{"resource opaque tag wildcard with slash", "resource:tag:example.com,2026:thing/*", "read", "opaque"},
		{"system bare wildcard sampling opt-in", "system:*", "allow", "glob metacharacters"},
		{"system question glob", "system:sampling/?reateMessage", "allow", "glob metacharacters"},
		{"system character-class glob", "system:sampling/[create]Message", "allow", "glob metacharacters"},
	}
	for _, tc := range reject {
		t.Run("reject "+tc.name, func(t *testing.T) {
			yaml := `
name: "bad"
version: "0.1.0"
capabilities:
  - target: "tool:valid_tool"
    actions: [call]
  - target: "` + tc.target + `"
    actions: [` + tc.action + `]
`
			path := writeManifestFile(t, yaml)
			_, err := LoadManifest(path)
			if err == nil {
				t.Fatalf("LoadManifest accepted %q, want rejection", tc.target)
			}
			msg := err.Error()
			if !strings.Contains(msg, "capability at index 1") {
				t.Errorf("error should identify capability at index 1; got: %v", err)
			}
			if !strings.Contains(msg, tc.wantErr) {
				t.Errorf("error should contain %q; got: %v", tc.wantErr, err)
			}
		})
	}
}

// ── schemaVersion gate (fail-closed on absent/unrecognized grammar) ──────────

func TestLoadManifest_SchemaVersion(t *testing.T) {
	// Written raw (not via writeManifestFile, which injects a schemaVersion) so
	// the gate sees exactly what each case declares.
	base := "name: m\nversion: \"1.0.0\"\ncapabilities:\n  - target: tool:read_file\n    actions: [call]\n"
	cases := []struct {
		name, prefix, wantErr string
	}{
		{"valid 0.1", "schemaVersion: \"0.1\"\n", ""},
		{"absent", "", "'schemaVersion' is required"},
		{"empty", "schemaVersion: \"\"\n", "'schemaVersion' is required"},
		{"unsupported", "schemaVersion: \"0.2\"\n", "unsupported manifest schemaVersion"},
		// A quoted scalar's surrounding whitespace survives the load path; the empty
		// check and the membership lookup now both run on the trimmed value, so a
		// padded-but-valid version is accepted instead of failing with a misleading
		// "unsupported \" 0.1\"" message, and a whitespace-only value is reported as
		// required (not unsupported).
		{"leading space tolerated", "schemaVersion: \" 0.1\"\n", ""},
		{"trailing space tolerated", "schemaVersion: \"0.1 \"\n", ""},
		{"tab tolerated", "schemaVersion: \"\\t0.1\"\n", ""},
		{"whitespace only is required", "schemaVersion: \"  \"\n", "'schemaVersion' is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "m.yaml")
			if err := os.WriteFile(p, []byte(tc.prefix+base), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, err := LoadManifest(p)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want load to succeed, got %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// ── Invalid action–namespace pairings are rejected ───────────────────────────

// invalidPairingCase describes one YAML manifest that should be rejected with
// an error containing wantErr as a substring.
type invalidPairingCase struct {
	name    string
	yaml    string
	wantErr string
}

func invalidPairingCases() []invalidPairingCase {
	return []invalidPairingCase{
		{
			name: "tool with read action",
			yaml: `
name: "bad"
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [read]
`,
			wantErr: "invalid action",
		},
		{
			name: "tool with get action",
			yaml: `
name: "bad"
version: "0.1.0"
capabilities:
  - target: "tool:send_email"
    actions: [get]
`,
			wantErr: "invalid action",
		},
		{
			name: "tool with allow action",
			yaml: `
name: "bad"
version: "0.1.0"
capabilities:
  - target: "tool:sampling_proxy"
    actions: [allow]
`,
			wantErr: "invalid action",
		},
		{
			name: "resource with call action",
			yaml: `
name: "bad"
version: "0.1.0"
capabilities:
  - target: "resource:file:///data/*"
    actions: [call]
`,
			wantErr: "invalid action",
		},
		{
			name: "resource with get action",
			yaml: `
name: "bad"
version: "0.1.0"
capabilities:
  - target: "resource:db://prod/users"
    actions: [get]
`,
			wantErr: "invalid action",
		},
		{
			name: "resource with allow action",
			yaml: `
name: "bad"
version: "0.1.0"
capabilities:
  - target: "resource:file:///secrets"
    actions: [allow]
`,
			wantErr: "invalid action",
		},
		{
			name: "prompt with call action",
			yaml: `
name: "bad"
version: "0.1.0"
capabilities:
  - target: "prompt:code_review"
    actions: [call]
`,
			wantErr: "invalid action",
		},
		{
			name: "prompt with read action",
			yaml: `
name: "bad"
version: "0.1.0"
capabilities:
  - target: "prompt:summarize"
    actions: [read]
`,
			wantErr: "invalid action",
		},
		{
			name: "system with call action",
			yaml: `
name: "bad"
version: "0.1.0"
capabilities:
  - target: "system:sampling/createMessage"
    actions: [call]
`,
			wantErr: "invalid action",
		},
		{
			name: "system with read action",
			yaml: `
name: "bad"
version: "0.1.0"
capabilities:
  - target: "system:sampling/createMessage"
    actions: [read]
`,
			wantErr: "invalid action",
		},
		{
			name: "system with get action",
			yaml: `
name: "bad"
version: "0.1.0"
capabilities:
  - target: "system:sampling/createMessage"
    actions: [get]
`,
			wantErr: "invalid action",
		},
	}
}

func TestLoadManifest_RejectsInvalidActionPairing_YAML(t *testing.T) {
	for _, tc := range invalidPairingCases() {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifestFile(t, tc.yaml)
			_, err := LoadManifest(path)
			if err == nil {
				t.Errorf("LoadManifest accepted invalid manifest %q, want error", tc.name)
				return
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q should contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestLoadManifest_RejectsUnprefixedResource_YAML(t *testing.T) {
	cases := []struct {
		name     string
		resource string
	}{
		{"bare tool name", "read_file"},
		{"old prompt path", "prompts/code_review"},
		{"old sampling path", "sampling/createMessage"},
		{"bare URI (looks like resource: prefix)", "file:///data/reports"},
		{"bare wildcard", "*"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yaml := `
name: "bad"
version: "0.1.0"
capabilities:
  - target: "` + tc.resource + `"
    actions: [call]
`
			path := writeManifestFile(t, yaml)
			_, err := LoadManifest(path)
			if err == nil {
				t.Errorf("LoadManifest accepted unprefixed resource %q, want error", tc.resource)
				return
			}
			if !strings.Contains(err.Error(), "namespace prefix") {
				t.Errorf("error %q should mention 'namespace prefix'", err.Error())
			}
		})
	}
}

func TestLoadManifest_ErrorNamesConstraintIndex_YAML(t *testing.T) {
	// The error message must identify which capability is invalid when multiple
	// constraints are present.
	yaml := `
name: "mixed"
version: "0.1.0"
capabilities:
  - target: "tool:valid_tool"
    actions: [call]
  - target: "tool:another_tool"
    actions: [get]
`
	path := writeManifestFile(t, yaml)
	_, err := LoadManifest(path)
	if err == nil {
		t.Fatal("expected error for invalid constraint at index 1")
	}
	if !strings.Contains(err.Error(), "capability at index 1") {
		t.Errorf("error should identify 'capability at index 1'; got: %v", err)
	}
}

func TestLoadManifest_ErrorNamesConstraintAndAction_YAML(t *testing.T) {
	// The error message must name both the constraint resource and the invalid action.
	yaml := `
name: "clear-error"
version: "0.1.0"
capabilities:
  - target: "tool:write_file"
    actions: [read]
`
	path := writeManifestFile(t, yaml)
	_, err := LoadManifest(path)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "tool:write_file") {
		t.Errorf("error should name the constraint; got: %v", msg)
	}
	if !strings.Contains(msg, `"read"`) {
		t.Errorf("error should name the invalid action; got: %v", msg)
	}
}

// ── argumentSchema consistency validation ────────────────────────────────────

func TestLoadManifest_RejectsUnsatisfiableArgumentSchema(t *testing.T) {
	// required: [path] with properties: {} and additionalProperties: false is
	// logically unsatisfiable — `path` is required yet forbidden — so it must be
	// rejected at load rather than denying every live call with a misleading
	// "additional property" error.
	yaml := `
name: "unsat-schema"
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: object
      required: [path]
      properties: {}
      additionalProperties: false
`
	path := writeManifestFile(t, yaml)
	_, err := LoadManifest(path)
	if err == nil {
		t.Fatal("LoadManifest accepted an unsatisfiable argumentSchema, want rejection")
	}
	if !strings.Contains(err.Error(), "unsatisfiable") {
		t.Errorf("error should explain the schema is unsatisfiable; got: %v", err)
	}
}

func TestLoadManifest_RejectsUnsatisfiableNestedArgumentSchema(t *testing.T) {
	// The same defect nested under properties.<name> must also be caught.
	yaml := `
name: "unsat-nested-schema"
version: "0.1.0"
capabilities:
  - target: "tool:write_file"
    actions: [call]
    argumentSchema:
      type: object
      properties:
        opts:
          type: object
          required: [mode]
          properties: {}
          additionalProperties: false
`
	path := writeManifestFile(t, yaml)
	_, err := LoadManifest(path)
	if err == nil {
		t.Fatal("LoadManifest accepted an unsatisfiable nested argumentSchema, want rejection")
	}
	if !strings.Contains(err.Error(), "unsatisfiable") {
		t.Errorf("error should explain the nested schema is unsatisfiable; got: %v", err)
	}
}

func TestLoadManifest_AcceptsSatisfiableArgumentSchema(t *testing.T) {
	// A required field that IS listed in properties is satisfiable and must load,
	// even with additionalProperties: false.
	yaml := `
name: "sat-schema"
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: object
      required: [path]
      properties:
        path:
          type: string
      additionalProperties: false
`
	path := writeManifestFile(t, yaml)
	if _, err := LoadManifest(path); err != nil {
		t.Fatalf("LoadManifest rejected a satisfiable argumentSchema: %v", err)
	}
}

func TestLoadManifest_RejectsNullPropertySubschema(t *testing.T) {
	// `properties: {id: null}` decodes to a nil subschema that the validator treats
	// as "any", so the declared property silently accepts any value — a structural
	// footgun. It must be rejected at load (fail closed), at both the top level and
	// nested under another property.
	for _, tc := range []struct{ name, yaml string }{
		{
			name: "top level",
			yaml: `
name: "null-prop"
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: object
      properties:
        id: null
`,
		},
		{
			name: "nested",
			yaml: `
name: "null-prop-nested"
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: object
      properties:
        opts:
          type: object
          properties:
            mode: null
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifestFile(t, tc.yaml)
			_, err := LoadManifest(path)
			if err == nil {
				t.Fatal("LoadManifest accepted a null property subschema, want rejection")
			}
			if !strings.Contains(err.Error(), "null schema") {
				t.Errorf("error should flag the null property schema; got: %v", err)
			}
		})
	}
}

func TestLoadManifest_AcceptsEmptyObjectPropertySubschema(t *testing.T) {
	// `properties: {id: {}}` is the correct JSON-Schema "any": it decodes to a
	// non-nil zero-value schema and must still load — only the null form is refused.
	yaml := `
name: "any-prop"
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: object
      properties:
        id: {}
`
	path := writeManifestFile(t, yaml)
	if _, err := LoadManifest(path); err != nil {
		t.Fatalf("LoadManifest rejected an empty-object (any) property subschema: %v", err)
	}
}

func TestLoadManifest_RejectsNullItemsSubschema(t *testing.T) {
	// `items: null` is the array-element counterpart of `properties: {x: null}`: it
	// would accept any element unchecked. It must be rejected at load, including when
	// nested under a property. (The typed *ArgumentSchema can't see it — present-null
	// and absent both decode to a nil Items — so the raw key-walker catches it.)
	for _, tc := range []struct{ name, yaml string }{
		{
			name: "top level",
			yaml: `
name: "null-items"
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: array
      items: null
`,
		},
		{
			name: "nested under a property",
			yaml: `
name: "null-items-nested"
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: object
      properties:
        tags:
          type: array
          items: null
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifestFile(t, tc.yaml)
			_, err := LoadManifest(path)
			if err == nil {
				t.Fatal("LoadManifest accepted a null items subschema, want rejection")
			}
			if !strings.Contains(err.Error(), "element schema is null") {
				t.Errorf("error should flag the null items schema; got: %v", err)
			}
		})
	}
}

func TestLoadManifest_AcceptsValidItemsSubschema(t *testing.T) {
	// An absent items, an empty-object items ({} = any element), and a concrete items
	// schema must all still load — only the explicit null form is refused.
	for _, tc := range []struct{ name, yaml string }{
		{
			name: "items absent",
			yaml: `
name: "items-absent"
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: array
`,
		},
		{
			name: "items empty object (any)",
			yaml: `
name: "items-any"
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: array
      items: {}
`,
		},
		{
			name: "items concrete schema",
			yaml: `
name: "items-concrete"
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: array
      items:
        type: string
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifestFile(t, tc.yaml)
			if _, err := LoadManifest(path); err != nil {
				t.Fatalf("LoadManifest rejected a valid items subschema (%s): %v", tc.name, err)
			}
		})
	}
}

// ── sequenceBlock validation ─────────────────────────────────────────────────

func TestLoadManifest_SequenceBlock_Valid(t *testing.T) {
	// A non-empty afterTools list whose entries survive prefix-stripping loads.
	yaml := `
name: "seq-ok"
version: "0.1.0"
capabilities:
  - target: "tool:write_external"
    actions: [call]
    conditions:
      - type: sequenceBlock
        afterTools: ["read_credentials", "tool:list_secrets"]
`
	path := writeManifestFile(t, yaml)
	if _, err := LoadManifest(path); err != nil {
		t.Fatalf("LoadManifest rejected valid sequenceBlock: %v", err)
	}
}

func TestLoadManifest_SequenceBlock_RejectsEmptyAfterTools(t *testing.T) {
	yaml := `
name: "seq-empty"
version: "0.1.0"
capabilities:
  - target: "tool:write_external"
    actions: [call]
    conditions:
      - type: sequenceBlock
        afterTools: []
`
	path := writeManifestFile(t, yaml)
	_, err := LoadManifest(path)
	if err == nil {
		t.Fatal("LoadManifest accepted sequenceBlock with empty afterTools, want rejection")
	}
	if !strings.Contains(err.Error(), "afterTools") {
		t.Errorf("error should name afterTools, got: %v", err)
	}
}

// TestLoadManifest_SequenceBlock_RejectsGlobAfterTools pins that a glob in afterTools is
// rejected at load: the runtime matches afterTools LITERALLY against the concrete tool
// names recordSessionCall persisted, so a pattern like "read_*" never matches a real
// recorded name and the block silently fails open.
func TestLoadManifest_SequenceBlock_RejectsGlobAfterTools(t *testing.T) {
	for _, glob := range []string{"read_*", "tool:list_?", "read_[abc]"} {
		yaml := `
name: "seq-glob"
version: "0.1.0"
capabilities:
  - target: "tool:write_external"
    actions: [call]
    conditions:
      - type: sequenceBlock
        afterTools: ["` + glob + `"]
`
		path := writeManifestFile(t, yaml)
		_, err := LoadManifest(path)
		if err == nil {
			t.Fatalf("LoadManifest accepted a sequenceBlock afterTools glob %q, want rejection (a glob is matched literally and never fires)", glob)
		}
		if !strings.Contains(err.Error(), "glob metacharacters") {
			t.Errorf("afterTools glob %q: error should explain the glob rejection, got: %v", glob, err)
		}
	}
}

// TestLoadManifest_SequenceBlock_ResourceURIGlobMeta pins the resource:-specific rejection
// set. A resource URI legitimately contains '[' (an IPv6 literal host) and '?' (a query
// string), and those cannot make a block look armed while silently never firing — so they
// load. A '*' can: resource antecedents are matched by the same exact-key lookup as tool
// names, and resource TARGETS legitimately glob, so an author who globs a target is the
// most likely to glob an antecedent. It must still be rejected.
func TestLoadManifest_SequenceBlock_ResourceURIGlobMeta(t *testing.T) {
	manifestWith := func(entry string) string {
		return `
name: "seq-resource-uri"
version: "0.1.0"
capabilities:
  - target: "tool:write_external"
    actions: [call]
    conditions:
      - type: sequenceBlock
        afterTools: ["` + entry + `"]
`
	}
	for _, uri := range []string{"resource:file://[::1]/secret", "resource:https://h/p?a=1"} {
		if _, err := LoadManifest(writeManifestFile(t, manifestWith(uri))); err != nil {
			t.Errorf("LoadManifest rejected a valid resource: antecedent %q (matched literally at runtime): %v", uri, err)
		}
	}
	for _, uri := range []string{"resource:file:///secrets/*", "resource:file:///a/*/b"} {
		_, err := LoadManifest(writeManifestFile(t, manifestWith(uri)))
		if err == nil {
			t.Errorf("LoadManifest accepted a wildcard resource: antecedent %q; the exact-key lookup never matches it, so the block silently fails open", uri)
			continue
		}
		if !strings.Contains(err.Error(), "glob metacharacters") {
			t.Errorf("resource wildcard %q: error should explain the glob rejection, got: %v", uri, err)
		}
	}
}

func TestLoadManifest_SequenceBlock_RejectsEntryThatStripsToEmpty(t *testing.T) {
	// An entry that carries a recognized prefix but no name (e.g. "tool:"), or is
	// empty outright, strips to "" and can never match session history — an
	// authoring mistake that must be rejected at load rather than shipped as a
	// silently inert rule.
	cases := []struct {
		name      string
		afterTool string
	}{
		{"bare tool prefix", `"tool:"`},
		{"bare resource prefix", `"resource:"`},
		{"empty string", `""`},
		{"whitespace after prefix", `"tool: "`},
		{"whitespace only", `"   "`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yaml := `
name: "seq-bad"
version: "0.1.0"
capabilities:
  - target: "tool:write_external"
    actions: [call]
    conditions:
      - type: sequenceBlock
        afterTools: ["read_credentials", ` + tc.afterTool + `]
`
			path := writeManifestFile(t, yaml)
			_, err := LoadManifest(path)
			if err == nil {
				t.Fatalf("LoadManifest accepted afterTools entry %s, want rejection", tc.afterTool)
			}
			if !strings.Contains(err.Error(), "names no tool") {
				t.Errorf("error should explain the entry names no tool, got: %v", err)
			}
		})
	}
}

func TestLoadManifest_RejectsMissingName(t *testing.T) {
	yaml := `
version: "0.1.0"
capabilities: []
`
	path := writeManifestFile(t, yaml)
	_, err := LoadManifest(path)
	if err == nil {
		t.Error("LoadManifest should reject manifest with no name field")
	}
}

func TestLoadManifest_RejectsMissingVersion(t *testing.T) {
	yaml := `
name: "no-version"
capabilities: []
`
	path := writeManifestFile(t, yaml)
	_, err := LoadManifest(path)
	if err == nil {
		t.Error("LoadManifest should reject manifest with no version field")
	}
}

func TestLoadManifest_VersionSemverValidation(t *testing.T) {
	valid := []string{"0.1.0", "1.0.0", "12.34.56", "0.0.1"}
	for _, v := range valid {
		y := "name: m\nversion: \"" + v + "\"\ncapabilities: []\n"
		path := writeManifestFile(t, y)
		if _, err := LoadManifest(path); err != nil {
			t.Errorf("version %q should be accepted, got error: %v", v, err)
		}
	}

	invalid := []string{"v1", "v1.0.0", "1.0", "latest", "1", "1.0.0-alpha", "1.0.0+build", "01.2.3", "1.02.3", "1.2.03", " 1.0.0", "1.0.0 "}
	for _, v := range invalid {
		y := "name: m\nversion: \"" + v + "\"\ncapabilities: []\n"
		path := writeManifestFile(t, y)
		if _, err := LoadManifest(path); err == nil {
			t.Errorf("version %q should be rejected but was accepted", v)
		}
	}
}

func TestLoadManifest_EmptyCapabilitiesIsValid(t *testing.T) {
	yaml := `
name: "empty"
version: "0.1.0"
capabilities: []
`
	path := writeManifestFile(t, yaml)
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("empty capabilities manifest should be valid: %v", err)
	}
	if len(m.Capabilities) != 0 {
		t.Errorf("expected 0 capabilities, got %d", len(m.Capabilities))
	}
}

// TestLoadManifest_WildcardActionIsAlwaysValid verifies that "*" is accepted
// for every namespace type, as required by the pairing table.
func TestLoadManifest_WildcardActionIsAlwaysValid(t *testing.T) {
	yaml := `
name: "wildcard-actions"
version: "0.1.0"
capabilities:
  - target: "tool:any_tool"
    actions: ["*"]
  - target: "resource:file:///data/*"
    actions: ["*"]
  - target: "prompt:any_prompt"
    actions: ["*"]
  - target: "system:sampling/createMessage"
    actions: ["*"]
`
	path := writeManifestFile(t, yaml)
	if _, err := LoadManifest(path); err != nil {
		t.Errorf("wildcard action should be valid for all namespace types: %v", err)
	}
}

// TestLoadManifest_MultipleActionsAllMustBeValid verifies that when a
// constraint lists several actions, every one of them is validated.
func TestLoadManifest_MultipleActionsAllMustBeValid(t *testing.T) {
	// Both "call" and "read" in a tool: constraint — "read" is invalid.
	yaml := `
name: "multi-actions"
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call, read]
`
	path := writeManifestFile(t, yaml)
	_, err := LoadManifest(path)
	if err == nil {
		t.Error("expected error: 'read' is not valid for tool: namespace")
	}
	if err != nil && !strings.Contains(err.Error(), "invalid action") {
		t.Errorf("error should mention 'invalid action'; got: %v", err)
	}
}

// TestLoadManifest_UnrecognizedPrefix verifies that an unrecognized prefix
// (e.g. "tools:" instead of "tool:") is rejected with a clear error.
func TestLoadManifest_UnrecognizedPrefix(t *testing.T) {
	cases := []string{
		"tools:read_file",
		"resources:file:///data",
		"prompts:code_review",
		"actions:send_email",
	}
	for _, res := range cases {
		t.Run(res, func(t *testing.T) {
			yaml := `
name: "bad-prefix"
version: "0.1.0"
capabilities:
  - target: "` + res + `"
    actions: [call]
`
			path := writeManifestFile(t, yaml)
			_, err := LoadManifest(path)
			if err == nil {
				t.Errorf("LoadManifest accepted unrecognized prefix %q, want error", res)
			}
		})
	}
}

// A serverVersion pin using semver-range operators (>=, ~, ^, …) is never
// satisfiable by matchServerVersion's component-wise equality and would, under
// strictDrift, block every session. LoadManifest must reject it up front; valid
// dot/wildcard pins must still load.
func TestLoadManifest_ServerVersionPinSyntax(t *testing.T) {
	base := func(sv string) string {
		return "name: \"p\"\nversion: \"1.0.0\"\nserverVersion: \"" + sv + "\"\ncapabilities: []\n"
	}
	// A mid-component wildcard ("1.2*", "1*.0") passes the coarse token regex but is
	// never a whole-component "*", so matchServerVersion can never satisfy it — FM-4
	// would fire every session. It must be rejected up front like a range operator.
	rejected := []string{">=2.0.0", ">2.0.0", "<=1.0.0", "~1.2.0", "^1.0.0", "1.2.* || 2.0.*", "1.2*", "1*.0"}
	for _, sv := range rejected {
		path := writeManifestFile(t, base(sv))
		if _, err := LoadManifest(path); err == nil {
			t.Errorf("serverVersion %q: expected a load error, got nil", sv)
		} else if !strings.Contains(err.Error(), "serverVersion") {
			t.Errorf("serverVersion %q: error = %q, want it to mention serverVersion", sv, err)
		}
	}
	accepted := []string{"1.2.3", "1.2.*", "1.*", "*", "2.0.0-rc.1"}
	for _, sv := range accepted {
		path := writeManifestFile(t, base(sv))
		if _, err := LoadManifest(path); err != nil {
			t.Errorf("serverVersion %q: expected a clean load, got %v", sv, err)
		}
	}
}

// A serverVersion pin declared in any merged manifest must survive the merge so
// that FM-4 (server-version) drift detection is not silently disabled when
// policy is split across multiple --policy files.
func TestMergeManifests_PreservesServerVersion(t *testing.T) {
	first := &LocalManifest{Name: "a", Version: "1.0.0"} // no serverVersion pin
	second := &LocalManifest{Name: "b", Version: "1.0.0", ServerVersion: "1.2.3"}

	merged, err := MergeManifests([]*LocalManifest{first, second})
	if err != nil {
		t.Fatalf("MergeManifests: %v", err)
	}
	if merged.ServerVersion != "1.2.3" {
		t.Errorf("serverVersion = %q, want %q (pin from a later manifest must survive)", merged.ServerVersion, "1.2.3")
	}
	if merged.Name != "a" {
		t.Errorf("name = %q, want %q (inherited from the first manifest)", merged.Name, "a")
	}
}

// A padded (explicitly quoted) schemaVersion is validated by trimming a copy, but
// LoadManifest must canonicalize the stored value too — otherwise " 0.1" and "0.1"
// loaded from separate --policy files collide in MergeManifests' exact-string
// conflict check even though they name the same grammar.
func TestMergeManifests_PaddedSchemaVersionDoesNotConflict(t *testing.T) {
	padded := writeManifestFile(t, "schemaVersion: \" 0.1\"\nname: \"a\"\nversion: \"1.0.0\"\ncapabilities: []\n")
	plain := writeManifestFile(t, "schemaVersion: \"0.1\"\nname: \"b\"\nversion: \"1.0.0\"\ncapabilities: []\n")

	first, err := LoadManifest(padded)
	if err != nil {
		t.Fatalf("LoadManifest(padded): %v", err)
	}
	if first.SchemaVersion != "0.1" {
		t.Errorf("padded schemaVersion loaded as %q, want the trimmed %q", first.SchemaVersion, "0.1")
	}
	second, err := LoadManifest(plain)
	if err != nil {
		t.Fatalf("LoadManifest(plain): %v", err)
	}

	merged, err := MergeManifests([]*LocalManifest{first, second})
	if err != nil {
		t.Fatalf("MergeManifests: a padded and a plain schemaVersion that trim equal must not conflict, got %v", err)
	}
	if merged.SchemaVersion != "0.1" {
		t.Errorf("merged schemaVersion = %q, want %q", merged.SchemaVersion, "0.1")
	}
}

// A manifest 'audience' is matched verbatim against a token's 'aud' claim, so
// surrounding whitespace (or a whitespace-only value) would never match and would
// silently deny every call on the route. LoadManifest must reject it up front, like
// the other trim-sensitive fields.
func TestLoadManifest_AudienceWhitespace(t *testing.T) {
	base := func(aud string) string {
		return "name: \"p\"\nversion: \"1.0.0\"\naudience: \"" + aud + "\"\ncapabilities: []\n"
	}
	rejected := []string{" svc-a", "svc-a ", "\\tsvc-a", "   "}
	for _, aud := range rejected {
		path := writeManifestFile(t, base(aud))
		if _, err := LoadManifest(path); err == nil {
			t.Errorf("audience %q: expected a load error, got nil", aud)
		} else if !strings.Contains(err.Error(), "audience") {
			t.Errorf("audience %q: error = %q, want it to mention audience", aud, err)
		}
	}
	// A clean audience (and an omitted one) must still load.
	for _, aud := range []string{"svc-a", "https://api.example.com"} {
		path := writeManifestFile(t, base(aud))
		if _, err := LoadManifest(path); err != nil {
			t.Errorf("audience %q: expected a clean load, got %v", aud, err)
		}
	}
}

// Pure-metadata fields that only label the policy (name, version, description,
// defaultTtl, audience) are inherited from the first manifest; a later file's
// differing value for these is intentionally dropped, since none feeds enforcement
// or drift. The serverVersion pin and the audience here are declared only by the first
// file, so they survive unchanged. (Two files declaring *conflicting*
// serverVersion/schemaVersion/audience values are a separate, rejected case — see
// TestMergeManifests_RejectsConflicting* and TestMergeManifests_AudienceFoldsWithConflictCheck.)
func TestMergeManifests_InheritsFirstManifestMetadata(t *testing.T) {
	first := &LocalManifest{
		SchemaVersion: "0.1", Name: "a", Version: "1.0.0",
		ServerVersion: "2.0.0", Description: "d", DefaultTTL: 30, Audience: "team-a",
	}
	// second declares no serverVersion pin and no audience, so there is nothing to
	// conflict with for those single-value fields.
	second := &LocalManifest{
		SchemaVersion: "0.1", Name: "b", Version: "3.0.0",
		Description: "other", DefaultTTL: 99,
	}

	merged, err := MergeManifests([]*LocalManifest{first, second})
	if err != nil {
		t.Fatalf("MergeManifests: %v", err)
	}
	if merged.ServerVersion != "2.0.0" {
		t.Errorf("serverVersion = %q, want %q (the only declared pin survives)", merged.ServerVersion, "2.0.0")
	}
	if merged.Name != "a" {
		t.Errorf("name = %q, want %q (inherited from the first manifest)", merged.Name, "a")
	}
	if merged.Version != "1.0.0" {
		t.Errorf("version = %q, want %q (inherited from the first manifest)", merged.Version, "1.0.0")
	}
	if merged.Description != "d" {
		t.Errorf("description = %q, want %q (inherited from the first manifest)", merged.Description, "d")
	}
	if merged.DefaultTTL != 30 {
		t.Errorf("defaultTTL = %d, want 30 (inherited from the first manifest)", merged.DefaultTTL)
	}
	if merged.Audience != "team-a" {
		t.Errorf("audience = %q, want %q (the only declared audience survives)", merged.Audience, "team-a")
	}
}

// audience pins the per-route JWT audience in gateway mode, so on a multi-file merge it
// is folded with a conflict check like serverVersion (first non-empty wins; two
// disagreeing files are rejected) — never silently dropped, which would widen the route's
// accepted audience.
func TestMergeManifests_AudienceFoldsWithConflictCheck(t *testing.T) {
	// An audience declared only in the SECOND file survives (first non-empty wins): a
	// later file's pin must NOT be dropped, since it drives enforcement.
	none := &LocalManifest{SchemaVersion: "0.1", Name: "a", Version: "1.0.0"}
	later := &LocalManifest{SchemaVersion: "0.1", Name: "b", Version: "1.0.0", Audience: "corp-api"}
	merged, err := MergeManifests([]*LocalManifest{none, later})
	if err != nil {
		t.Fatalf("a single-sided audience must merge cleanly, got: %v", err)
	}
	if merged.Audience != "corp-api" {
		t.Errorf("audience = %q, want %q (a later file's pin survives the fold, not dropped)", merged.Audience, "corp-api")
	}

	// Two files declaring DIFFERENT non-empty audiences are rejected: silently keeping the
	// first would drop the second's pin and widen the route's accepted audience.
	first := &LocalManifest{SchemaVersion: "0.1", Name: "a", Version: "1.0.0", Audience: "team-a"}
	second := &LocalManifest{SchemaVersion: "0.1", Name: "b", Version: "1.0.0", Audience: "corp-api"}
	if _, err := MergeManifests([]*LocalManifest{first, second}); err == nil {
		t.Fatal("conflicting audiences across policy files must be rejected, not silently collapsed")
	}

	// Matching audiences merge cleanly.
	same2 := &LocalManifest{SchemaVersion: "0.1", Name: "b", Version: "1.0.0", Audience: "team-a"}
	merged, err = MergeManifests([]*LocalManifest{first, same2})
	if err != nil {
		t.Fatalf("matching audiences must merge cleanly, got: %v", err)
	}
	if merged.Audience != "team-a" {
		t.Errorf("audience = %q, want %q", merged.Audience, "team-a")
	}
}

// Two --policy files that pin *conflicting* non-empty serverVersions cannot be
// merged: silently keeping the first would disable the second file's FM-4 drift
// coverage, so MergeManifests fails closed with a clear error that names the
// field and both conflicting values.
func TestMergeManifests_RejectsConflictingServerVersion(t *testing.T) {
	first := &LocalManifest{SchemaVersion: "0.1", Name: "a", Version: "1.0.0", ServerVersion: "1.*"}
	second := &LocalManifest{SchemaVersion: "0.1", Name: "b", Version: "1.0.0", ServerVersion: "2.*"}

	if _, err := MergeManifests([]*LocalManifest{first, second}); err == nil {
		t.Fatal("expected a conflicting-serverVersion merge to be rejected, got nil error")
	} else {
		for _, want := range []string{"serverVersion", "1.*", "2.*"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
	}
}

// Two --policy files that declare the *same* non-empty serverVersion (a
// reasonable way to keep each file self-describing) are not in conflict: equal
// values merge cleanly. This locks the "or make the values match" escape hatch
// named in the conflict error so a later change can't turn it into a rejection.
func TestMergeManifests_AllowsMatchingServerVersion(t *testing.T) {
	first := &LocalManifest{SchemaVersion: "0.1", Name: "a", Version: "1.0.0", ServerVersion: "1.2.*"}
	second := &LocalManifest{SchemaVersion: "0.1", Name: "b", Version: "1.0.0", ServerVersion: "1.2.*"}

	merged, err := MergeManifests([]*LocalManifest{first, second})
	if err != nil {
		t.Fatalf("matching serverVersions must merge cleanly, got: %v", err)
	}
	if merged.ServerVersion != "1.2.*" {
		t.Errorf("serverVersion = %q, want %q (matching pins survive the merge)", merged.ServerVersion, "1.2.*")
	}
}

// Two --policy files written against different schemaVersion grammars cannot be
// merged into one document: the merged manifest can carry only a single grammar
// label, so a conflict is rejected rather than silently interpreted under the
// first file's grammar.
func TestMergeManifests_RejectsConflictingSchemaVersion(t *testing.T) {
	first := &LocalManifest{SchemaVersion: "0.1", Name: "a", Version: "1.0.0"}
	second := &LocalManifest{SchemaVersion: "0.2", Name: "b", Version: "1.0.0"}

	if _, err := MergeManifests([]*LocalManifest{first, second}); err == nil {
		t.Fatal("expected a conflicting-schemaVersion merge to be rejected, got nil error")
	} else if !strings.Contains(err.Error(), "schemaVersion") {
		t.Errorf("error %q does not mention schemaVersion", err)
	}
}

// MergeManifests must not panic on an empty slice. It returns an empty manifest
// (zero capabilities = deny everything), consistent with the fail-closed
// invariant, rather than indexing ms[0] out of range.
func TestMergeManifests_EmptyInput(t *testing.T) {
	merged, err := MergeManifests([]*LocalManifest{})
	if err != nil {
		t.Fatalf("MergeManifests(empty): %v", err)
	}
	if merged == nil {
		t.Fatal("MergeManifests(nil) returned nil, want a non-nil empty manifest")
	}
	if len(merged.Capabilities) != 0 {
		t.Errorf("empty input merged to %d capabilities, want 0", len(merged.Capabilities))
	}
}

// TestMergeManifests_RejectsCrossFileConflict covers the fail-open the merge
// guards against: two --policy files declaring the same target with overlapping
// actions and principal scopes a single request can satisfy at once tie in the
// engine's equal-specificity selection, which resolves the tie by file order.
// MergeManifests rejects the combination at load so an operator who appends a
// file to tighten policy cannot silently widen it, and so the effective policy
// cannot depend on --policy ordering.
func TestMergeManifests_RejectsCrossFileConflict(t *testing.T) {
	// The issue's repro: a.yaml observes read_file (audit: allow & log, never
	// block); b.yaml restricts it to /reports/*. Concatenated, the engine's
	// first-in-order tie-break would pick whichever file is listed first.
	audit := func() *LocalManifest {
		return &LocalManifest{
			SchemaVersion: "0.1", Name: "a", Version: "1.0.0",
			Capabilities: []capability.Constraint{{
				Target: "tool:read_file", Actions: []string{"call"},
				Enforcement: capability.EnforcementAudit,
			}},
		}
	}
	restrictive := func() *LocalManifest {
		return &LocalManifest{
			SchemaVersion: "0.1", Name: "b", Version: "1.0.0",
			Capabilities: []capability.Constraint{{
				Target: "tool:read_file", Actions: []string{"call"},
				Conditions: []capability.Condition{
					&capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/reports/*"}},
				},
			}},
		}
	}

	cases := []struct {
		name       string
		ms         []*LocalManifest
		wantTarget string
	}{
		// Both orderings must be rejected: the whole point is that the outcome
		// must not depend on which file is listed first.
		{"audit then restrictive", []*LocalManifest{audit(), restrictive()}, "tool:read_file"},
		{"restrictive then audit", []*LocalManifest{restrictive(), audit()}, "tool:read_file"},
		{
			// A wildcard action in one file overlaps the explicit verb in the other.
			name: "wildcard action overlaps explicit verb",
			ms: []*LocalManifest{
				{SchemaVersion: "0.1", Name: "a", Version: "1.0.0", Capabilities: []capability.Constraint{
					{Target: "tool:read_file", Actions: []string{"*"}},
				}},
				{SchemaVersion: "0.1", Name: "b", Version: "1.0.0", Capabilities: []capability.Constraint{
					{Target: "tool:read_file", Actions: []string{"call"}},
				}},
			},
			wantTarget: "tool:read_file",
		},
		{
			// Two entries scoped to the SAME principal also tie.
			name: "same target, same principal scope",
			ms: []*LocalManifest{
				{SchemaVersion: "0.1", Name: "a", Version: "1.0.0", Capabilities: []capability.Constraint{
					{Target: "tool:query_db", Actions: []string{"call"}, Principal: map[string][]string{"sub": {"alice"}}, Enforcement: capability.EnforcementAudit},
				}},
				{SchemaVersion: "0.1", Name: "b", Version: "1.0.0", Capabilities: []capability.Constraint{
					{Target: "tool:query_db", Actions: []string{"call"}, Principal: map[string][]string{"sub": {"alice"}}},
				}},
			},
			wantTarget: "tool:query_db",
		},
		{
			// Same principal written with its pattern list in a different order
			// must still collide — overlap is decided by value (x vs x), so
			// detection cannot depend on map/slice iteration order.
			name: "same principal, reordered patterns",
			ms: []*LocalManifest{
				{SchemaVersion: "0.1", Name: "a", Version: "1.0.0", Capabilities: []capability.Constraint{
					{Target: "tool:deploy", Actions: []string{"call"}, Principal: map[string][]string{"agent_id": {"x", "y"}}},
				}},
				{SchemaVersion: "0.1", Name: "b", Version: "1.0.0", Capabilities: []capability.Constraint{
					{Target: "tool:deploy", Actions: []string{"call"}, Principal: map[string][]string{"agent_id": {"y", "x"}}},
				}},
			},
			wantTarget: "tool:deploy",
		},
		{
			// Different claims still tie: principal matching is AND *within* an
			// entry, so a token carrying both sub and iss satisfies both scopes.
			// The engine has no principal-specificity ranking, so it breaks the
			// tie by file order — exactly the cross-file shadow this guards against.
			name: "different claims, co-satisfiable",
			ms: []*LocalManifest{
				{SchemaVersion: "0.1", Name: "a", Version: "1.0.0", Capabilities: []capability.Constraint{
					{Target: "tool:deploy", Actions: []string{"call"}, Principal: map[string][]string{"sub": {"alice"}}, Enforcement: capability.EnforcementAudit},
				}},
				{SchemaVersion: "0.1", Name: "b", Version: "1.0.0", Capabilities: []capability.Constraint{
					{Target: "tool:deploy", Actions: []string{"call"}, Principal: map[string][]string{"iss": {"https://idp.example"}}},
				}},
			},
			wantTarget: "tool:deploy",
		},
		{
			// Two globs on the same claim that can match a common value ("a*" and
			// "*e" both match "ace") are not provably disjoint, so they conflict.
			name: "overlapping globs, same claim",
			ms: []*LocalManifest{
				{SchemaVersion: "0.1", Name: "a", Version: "1.0.0", Capabilities: []capability.Constraint{
					{Target: "tool:query_db", Actions: []string{"call"}, Principal: map[string][]string{"sub": {"a*"}}},
				}},
				{SchemaVersion: "0.1", Name: "b", Version: "1.0.0", Capabilities: []capability.Constraint{
					{Target: "tool:query_db", Actions: []string{"call"}, Principal: map[string][]string{"sub": {"*e"}}},
				}},
			},
			wantTarget: "tool:query_db",
		},
		{
			// Two overlapping glob targets: tool:read_* (audit) and tool:*_file
			// (strict) both match read_file at the same specificity, so they tie and
			// the file-order winner silently shadows the other. A string-keyed check
			// bucketed them separately; targetsCanTie's semantic overlap catches it.
			name: "overlapping glob targets across files",
			ms: []*LocalManifest{
				{SchemaVersion: "0.1", Name: "a", Version: "1.0.0", Capabilities: []capability.Constraint{
					{Target: "tool:read_*", Actions: []string{"call"}, Enforcement: capability.EnforcementAudit},
				}},
				{SchemaVersion: "0.1", Name: "b", Version: "1.0.0", Capabilities: []capability.Constraint{
					{Target: "tool:*_file", Actions: []string{"call"}},
				}},
			},
			wantTarget: "tool:read_*",
		},
		{
			// Multi-claim principals whose only shared claim (sub) overlaps, while each
			// also names a claim the other omits (iss vs region). A token with sub=alice,
			// iss=acme, region=us satisfies both scopes at once, so they tie and the
			// engine breaks it by file order. The loop must not be tricked into
			// returning "disjoint" by the non-shared claims.
			name: "multi-claim principals, shared claim overlaps",
			ms: []*LocalManifest{
				{SchemaVersion: "0.1", Name: "a", Version: "1.0.0", Capabilities: []capability.Constraint{
					{Target: "tool:deploy", Actions: []string{"call"}, Principal: map[string][]string{"sub": {"alice"}, "iss": {"acme"}}, Enforcement: capability.EnforcementAudit},
				}},
				{SchemaVersion: "0.1", Name: "b", Version: "1.0.0", Capabilities: []capability.Constraint{
					{Target: "tool:deploy", Actions: []string{"call"}, Principal: map[string][]string{"sub": {"alice"}, "region": {"us"}}},
				}},
			},
			wantTarget: "tool:deploy",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := MergeManifests(tc.ms)
			if err == nil {
				t.Fatal("MergeManifests: want a conflict error, got nil (the later file would be silently shadowed)")
			}
			if !strings.Contains(err.Error(), tc.wantTarget) {
				t.Errorf("error = %q, want it to name the conflicting target %q", err, tc.wantTarget)
			}
		})
	}
}

// TestMergeManifests_AllowsNonConflicting confirms the conflict guard does not
// over-reject. Distinct targets, principal scopes no single request can satisfy
// at once (disjoint values on the same claim), and a general entry refined by a
// principal-scoped one (which the engine resolves deterministically regardless
// of order) all merge cleanly. A duplicate target WITHIN a single file is also
// left alone — that first-wins tie-break is documented behavior; only the
// cross-file merge is rejected.
func TestMergeManifests_AllowsNonConflicting(t *testing.T) {
	newCap := func(target string, principal map[string][]string) capability.Constraint {
		return capability.Constraint{Target: target, Actions: []string{"call"}, Principal: principal}
	}
	mani := func(name string, caps ...capability.Constraint) *LocalManifest {
		return &LocalManifest{SchemaVersion: "0.1", Name: name, Version: "1.0.0", Capabilities: caps}
	}
	cases := []struct {
		name string
		ms   []*LocalManifest
	}{
		{
			"distinct targets",
			[]*LocalManifest{mani("a", newCap("tool:read_file", nil)), mani("b", newCap("tool:write_file", nil))},
		},
		{
			// Same claim, disjoint literal values: no request has agent_id equal
			// to both ci-bot and release-bot, so the two can never co-match.
			"same target, distinct principals on the same claim",
			[]*LocalManifest{
				mani("a", newCap("tool:deploy", map[string][]string{"agent_id": {"ci-bot"}})),
				mani("b", newCap("tool:deploy", map[string][]string{"agent_id": {"release-bot"}})),
			},
		},
		{
			"same target, general refined by principal-scoped",
			[]*LocalManifest{
				mani("a", newCap("tool:query_db", nil)),
				mani("b", newCap("tool:query_db", map[string][]string{"sub": {"alice"}})),
			},
		},
		{
			"duplicate target within one file is not a cross-file conflict",
			[]*LocalManifest{
				mani("a", newCap("tool:read_file", nil), newCap("tool:read_file", nil)),
				mani("b", newCap("tool:write_file", nil)),
			},
		},
		{
			// Same claim, disjoint values: "alice" cannot match "bob*", so no
			// single request satisfies both scopes — no tie, merges cleanly.
			"same claim, disjoint literal and non-matching glob",
			[]*LocalManifest{
				mani("a", newCap("tool:deploy", map[string][]string{"sub": {"alice"}})),
				mani("b", newCap("tool:deploy", map[string][]string{"sub": {"bob*"}})),
			},
		},
		{
			// Two glob targets whose literal prefixes cannot both prefix one name
			// (read_* vs write_*) never match the same tool, so the cross-glob overlap
			// check must not over-reject them.
			"non-overlapping glob targets across files",
			[]*LocalManifest{
				mani("a", newCap("tool:read_*", nil)),
				mani("b", newCap("tool:write_*", nil)),
			},
		},
		{
			// A glob and a literal it does not cover (get_* vs set_value) cannot match
			// the same tool — no tie, merges cleanly.
			"glob target and non-covered literal across files",
			[]*LocalManifest{
				mani("a", newCap("tool:get_*", nil)),
				mani("b", newCap("tool:set_value", nil)),
			},
		},
		{
			// A glob and a more-specific exact target it covers do not tie: the exact
			// match scores exactMatchSpecificity and outranks the glob, so the engine
			// resolves it deterministically regardless of file order.
			"glob and a more-specific exact target it covers",
			[]*LocalManifest{
				mani("a", newCap("tool:get_*", nil)),
				mani("b", newCap("tool:get_user", nil)),
			},
		},
		{
			// Two overlapping globs of DIFFERENT specificity (list_* vs
			// list_users_*) never tie in the engine: it deterministically picks
			// the more-specific list_users_* for any matching name regardless of
			// file order, so this is not a file-order shadow.
			"overlapping globs of different specificity across files",
			[]*LocalManifest{
				mani("a", newCap("tool:list_*", nil)),
				mani("b", newCap("tool:list_users_*", nil)),
			},
		},
		{
			// Different namespaces never tie even with the same bare pattern: the
			// engine matches by target type first, so tool:* and prompt:... do not
			// shadow each other.
			"same bare pattern, different namespaces",
			[]*LocalManifest{
				mani("a", newCap("tool:export", nil)),
				mani("b", capability.Constraint{Target: "prompt:export", Actions: []string{"get"}}),
			},
		},
		{
			// Multi-claim principals where one shared claim (sub) pins to disjoint
			// values: no single token has sub equal to both alice and bob, so the
			// scopes can never co-match even though they agree on iss. Exercises
			// principalsConflict returning false on a shared-but-disjoint claim.
			"multi-claim principals, one shared claim disjoint",
			[]*LocalManifest{
				mani("a", newCap("tool:deploy", map[string][]string{"sub": {"alice"}, "iss": {"https://idp.example"}})),
				mani("b", newCap("tool:deploy", map[string][]string{"sub": {"bob"}, "iss": {"https://idp.example"}})),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := MergeManifests(tc.ms); err != nil {
				t.Errorf("MergeManifests: unexpected error: %v", err)
			}
		})
	}
}

// TestLoadManifest_Enforcement exercises the per-entry `enforcement` field:
// audit/enforce are accepted, an unknown value is rejected fail-closed, and
// audit is rejected on a system: target (the sampling opt-in is binary).
func TestLoadManifest_Enforcement(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{
			name: "audit on tool is valid",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    enforcement: audit
`,
		},
		{
			name: "explicit enforce is valid",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    enforcement: enforce
`,
		},
		{
			name: "unknown enforcement rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    enforcement: observe
`,
			wantErr: "invalid enforcement",
		},
		{
			name: "audit on system target rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "system:sampling/createMessage"
    actions: [allow]
    enforcement: audit
`,
			wantErr: "not supported on a system",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "m.yaml")
			if err := os.WriteFile(p, []byte(tc.yaml), 0o600); err != nil {
				t.Fatalf("write manifest: %v", err)
			}
			_, err := LoadManifest(p)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("LoadManifest rejected valid manifest: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestLoadManifest_ConditionArgumentValidation verifies that conditions which
// require an explicit argument field are rejected at load time when the field
// is absent, and accepted when it is present.
func TestLoadManifest_ConditionArgumentValidation(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		// allowedOperations
		{
			name: "allowedOperations without argument rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: allowedOperations
        operations: [SELECT]
`,
			wantErr: "allowedOperations requires an 'argument' field",
		},
		{
			name: "allowedOperations with argument accepted",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: allowedOperations
        argument: sql
        operations: [SELECT]
`,
		},
		{
			name: "allowedOperations empty operations rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: allowedOperations
        argument: sql
        operations: []
`,
			wantErr: "allowedOperations requires a non-empty 'operations' list",
		},
		{
			name: "allowedOperations wildcard rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: allowedOperations
        argument: sql
        operations: ["*"]
`,
			wantErr: "the wildcard is not a valid operation verb",
		},
		{
			name: "allowedOperations blank entry rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: allowedOperations
        argument: sql
        operations: ["  "]
`,
			wantErr: "allowedOperations contains an empty or whitespace-only entry",
		},
		// allowedExtensions
		{
			name: "allowedExtensions without argument rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:export_data"
    actions: [call]
    conditions:
      - type: allowedExtensions
        extensions: [".csv"]
`,
			wantErr: "allowedExtensions requires an 'argument' field",
		},
		{
			name: "allowedExtensions with argument accepted",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:export_data"
    actions: [call]
    conditions:
      - type: allowedExtensions
        argument: path
        extensions: [".csv"]
`,
		},
		{
			name: "allowedExtensions empty extensions rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:export_data"
    actions: [call]
    conditions:
      - type: allowedExtensions
        argument: path
        extensions: []
`,
			wantErr: "allowedExtensions requires a non-empty 'extensions' list",
		},
		{
			name: "allowedExtensions all-blank extensions rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:export_data"
    actions: [call]
    conditions:
      - type: allowedExtensions
        argument: path
        extensions: ["", "  "]
`,
			wantErr: "empty or whitespace-only entry",
		},
		// allowedTables
		{
			name: "allowedTables without argument rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:query_sales"
    actions: [call]
    conditions:
      - type: allowedTables
        tables: [sales]
`,
			wantErr: "allowedTables requires an 'argument' field",
		},
		{
			name: "allowedTables with argument accepted",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:query_sales"
    actions: [call]
    conditions:
      - type: allowedTables
        argument: table
        tables: [sales]
`,
		},
		{
			name: "allowedTables empty tables rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:query_sales"
    actions: [call]
    conditions:
      - type: allowedTables
        argument: table
        tables: []
`,
			wantErr: "allowedTables requires a non-empty 'tables' list",
		},
		{
			name: "allowedTables all-blank tables rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:query_sales"
    actions: [call]
    conditions:
      - type: allowedTables
        argument: table
        tables: ["", "  "]
`,
			wantErr: "empty or whitespace-only table entry",
		},
		{
			name: "allowedTables empty tables with columns still rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:query_sales"
    actions: [call]
    conditions:
      - type: allowedTables
        argument: table
        tables: []
        columns:
          users: [id]
`,
			wantErr: "allowedTables requires a non-empty 'tables' list",
		},
		{
			name: "allowedTables case-colliding columns keys rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:query_sales"
    actions: [call]
    conditions:
      - type: allowedTables
        argument: table
        tables: [users]
        columns:
          users: [id, name]
          Users: [id]
`,
			wantErr: "case-colliding keys",
		},
		{
			// An empty column allowlist for a table is a permanently
			// unfulfillable condition (every access to that table is denied), so it
			// must be rejected at validate-time rather than discovered as a confusing
			// runtime deny.
			name: "allowedTables empty column allowlist rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:query_sales"
    actions: [call]
    conditions:
      - type: allowedTables
        argument: table
        tables: [users]
        columns:
          users: []
`,
			wantErr: "empty column allowlist for table",
		},
		{
			name: "allowedTables distinct columns keys accepted",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:query_sales"
    actions: [call]
    conditions:
      - type: allowedTables
        argument: table
        tables: [users, orders]
        columns:
          users: [id, name]
          orders: [id, total]
`,
		},
		// recipientDomain
		{
			name: "recipientDomain without argument rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:send_email"
    actions: [call]
    conditions:
      - type: recipientDomain
        domains: ["example.com"]
`,
			wantErr: "recipientDomain requires an 'argument' field",
		},
		{
			name: "recipientDomain with argument accepted",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:send_email"
    actions: [call]
    conditions:
      - type: recipientDomain
        argument: to
        domains: ["example.com"]
`,
		},
		{
			name: "recipientDomain empty domains rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:send_email"
    actions: [call]
    conditions:
      - type: recipientDomain
        argument: to
        domains: []
`,
			wantErr: "recipientDomain requires a non-empty 'domains' list",
		},
		{
			name: "recipientDomain empty domain entry rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:send_email"
    actions: [call]
    conditions:
      - type: recipientDomain
        argument: to
        domains: [""]
`,
			wantErr: "empty or whitespace-only domain entry",
		},
		{
			name: "recipientDomain whitespace-only domain entry rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:send_email"
    actions: [call]
    conditions:
      - type: recipientDomain
        argument: to
        domains: ["example.com", "   "]
`,
			wantErr: "empty or whitespace-only domain entry",
		},
		{
			name: "recipientDomain at-prefixed domain entry rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:send_email"
    actions: [call]
    conditions:
      - type: recipientDomain
        argument: to
        domains: ["@example.com"]
`,
			wantErr: "must not start with '@'",
		},
		// error message names the constraint index and condition index
		{
			name: "error names condition index",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 5
        windowSeconds: 3600
      - type: allowedOperations
        operations: [SELECT]
`,
			wantErr: "capability at index 1, condition 1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "m.yaml")
			if err := os.WriteFile(p, []byte(tc.yaml), 0o600); err != nil {
				t.Fatalf("write manifest: %v", err)
			}
			_, err := LoadManifest(p)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("LoadManifest rejected valid manifest: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestLoadManifest_AllowedValuesAndMaxCallsValidation verifies that the two
// most common conditions reject the degenerate shapes that a typo or an omitted
// field produces — an allowedValues with no argument or no values (which would
// deny every call at runtime), and a maxCalls missing its count or window
// (which would silently become a never-resetting lifetime cap).
func TestLoadManifest_AllowedValuesAndMaxCallsValidation(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{
			name: "allowedValues without argument rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    conditions:
      - type: allowedValues
        values: ["/data/*"]
`,
			wantErr: "allowedValues requires an 'argument' field",
		},
		{
			name: "allowedValues with empty values rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    conditions:
      - type: allowedValues
        argument: path
        values: []
`,
			wantErr: "allowedValues requires a non-empty 'values' list",
		},
		{
			name: "allowedValues well-formed accepted",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    conditions:
      - type: allowedValues
        argument: path
        values: ["/data/*"]
`,
		},
		{
			// A malformed glob (unclosed character
			// class) returns path.ErrBadPattern at runtime, which the handler
			// silently treats as a non-match — leaving a policy quietly more
			// restrictive than intended. Reject it at load.
			name: "allowedValues malformed glob pattern rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    conditions:
      - type: allowedValues
        argument: path
        values: ["/reports/[invalid"]
`,
			wantErr: "invalid glob pattern",
		},
		{
			// A "**"-bearing pattern whose bracket class spans a "/" parses as a
			// single valid class under whole-string path.Match but, at runtime,
			// MatchValueGlob splits on "/" and the segment "[a" is path.ErrBadPattern
			// — a silently dead, deny-all policy. Validating through the same segment
			// decomposition catches it at load.
			name: "allowedValues doublestar bracket-spanning-slash rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    conditions:
      - type: allowedValues
        argument: path
        values: ["[a/b]/**"]
`,
			wantErr: "invalid glob pattern",
		},
		{
			// A non-string value (number) is matched by exact equality at
			// runtime, never fed to path.Match, so it must not trip the glob
			// validation.
			name: "allowedValues non-string value accepted",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    conditions:
      - type: allowedValues
        argument: limit
        values: [10, "/data/*"]
`,
		},
		{
			name: "maxCalls missing windowSeconds rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 5
`,
			wantErr: "maxCalls requires 'windowSeconds' >= 1",
		},
		{
			name: "maxCalls missing count rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: maxCalls
        windowSeconds: 3600
`,
			wantErr: "maxCalls requires 'count' >= 1",
		},
		{
			// An absurdly large windowSeconds overflows
			// the call-counter duration arithmetic at runtime and would silently
			// reset the quota (fail-open). Reject it at load.
			name: "maxCalls windowSeconds overflow rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 5
        windowSeconds: 99999999999999
`,
			wantErr: "exceeds the maximum",
		},
		{
			name: "maxCalls well-formed accepted",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 5
        windowSeconds: 3600
`,
		},
		{
			// Two maxCalls conditions on one capability
			// sharing a window address the same counter bucket, so each admitted
			// call is counted once per condition and the effective limit collapses
			// to the lower count over the number of conditions. Reject at load.
			name: "maxCalls duplicate windowSeconds rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:export"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 10
        windowSeconds: 60
      - type: maxCalls
        count: 20
        windowSeconds: 60
`,
			wantErr: "conditions 0 and 1 are both maxCalls with the same windowSeconds (60)",
		},
		{
			// Even an exact duplicate (same window AND count) double-counts, since
			// each condition's handler records the admitted call into the shared
			// bucket. It is pure redundancy, so reject it too.
			name: "maxCalls identical windowSeconds and count rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:export"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 10
        windowSeconds: 60
      - type: maxCalls
        count: 10
        windowSeconds: 60
`,
			wantErr: "same windowSeconds (60)",
		},
		{
			// Distinct windows are independent rate limits, each keyed to its own
			// bucket (30/minute AND 500/hour). They must be accepted.
			name: "maxCalls distinct windowSeconds accepted",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:export"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 30
        windowSeconds: 60
      - type: maxCalls
        count: 500
        windowSeconds: 3600
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifestFile(t, tc.yaml)
			_, err := LoadManifest(path)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("LoadManifest rejected valid manifest: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestLoadManifest_IPRangeAndTimeWindowValidation verifies that ipRange CIDRs
// and timeWindow timestamps are parsed at load time. Before this
// check a typo'd CIDR (e.g. "10.0.1/24") or RFC3339 timestamp (e.g.
// "2026-13-01T00:00:00Z") passed LoadManifest silently and only surfaced as a
// CONDITION_FAILED denial on the first live request, indistinguishable from a
// legitimate enforcement event. The degenerate shapes that deny every call — an
// empty cidrs list, a window with neither bound, or a notBefore at/after
// notAfter — are rejected too.
func TestLoadManifest_IPRangeAndTimeWindowValidation(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		// ── ipRange ──
		{
			name: "ipRange invalid CIDR rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: ipRange
        cidrs: ["10.0.1/24"]
`,
			wantErr: `invalid CIDR "10.0.1/24"`,
		},
		{
			name: "ipRange empty cidrs rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: ipRange
        cidrs: []
`,
			wantErr: "ipRange requires a non-empty 'cidrs' list",
		},
		{
			name: "ipRange one bad CIDR among several rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: ipRange
        cidrs: ["10.0.0.0/8", "192.168.0.0/33"]
`,
			wantErr: `invalid CIDR "192.168.0.0/33"`,
		},
		{
			name: "ipRange IPv4 CIDR with host bits rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: ipRange
        cidrs: ["10.0.0.5/8"]
`,
			wantErr: `CIDR "10.0.0.5/8" has host bits set`,
		},
		{
			name: "ipRange IPv6 CIDR with host bits rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: ipRange
        cidrs: ["2001:db8::1/32"]
`,
			wantErr: `CIDR "2001:db8::1/32" has host bits set`,
		},
		{
			name: "ipRange single host /32 accepted",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: ipRange
        cidrs: ["10.0.0.5/32"]
`,
		},
		{
			name: "ipRange valid IPv4 and IPv6 cidrs accepted",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: ipRange
        cidrs: ["10.0.0.0/8", "2001:db8::/32"]
`,
		},
		// ── timeWindow ──
		{
			name: "timeWindow invalid notBefore rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: timeWindow
        notBefore: "2026-13-01T00:00:00Z"
`,
			wantErr: `invalid notBefore "2026-13-01T00:00:00Z"`,
		},
		{
			name: "timeWindow invalid notAfter rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: timeWindow
        notAfter: "not-a-timestamp"
`,
			wantErr: `invalid notAfter "not-a-timestamp"`,
		},
		{
			name: "timeWindow with neither bound rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: timeWindow
`,
			wantErr: "timeWindow requires at least one of 'notBefore' or 'notAfter'",
		},
		{
			name: "timeWindow empty window (notBefore after notAfter) rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: timeWindow
        notBefore: "2026-12-31T23:59:59Z"
        notAfter: "2026-04-01T00:00:00Z"
`,
			wantErr: "the window is empty and denies every call",
		},
		{
			// notBefore == notAfter: a single-instant window that can never be
			// satisfied. Pins the `!notBefore.Before(notAfter)` boundary so a
			// refactor to e.g. `notAfter.Before(notBefore)` (which would silently
			// start accepting it) is caught here.
			name: "timeWindow equal bounds (single instant) rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: timeWindow
        notBefore: "2026-04-01T00:00:00Z"
        notAfter: "2026-04-01T00:00:00Z"
`,
			wantErr: "the window is empty and denies every call",
		},
		{
			name: "timeWindow notBefore only accepted",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: timeWindow
        notBefore: "2026-04-01T00:00:00Z"
`,
		},
		{
			name: "timeWindow notAfter only accepted",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: timeWindow
        notAfter: "2026-12-31T23:59:59Z"
`,
		},
		{
			name: "timeWindow valid window accepted",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: timeWindow
        notBefore: "2026-04-01T00:00:00Z"
        notAfter: "2026-12-31T23:59:59Z"
`,
		},
		// error message names both the capability index and the condition index
		{
			name: "error names capability and condition index",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 5
        windowSeconds: 3600
      - type: ipRange
        cidrs: ["bogus"]
`,
			wantErr: "capability at index 1, condition 1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifestFile(t, tc.yaml)
			_, err := LoadManifest(path)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("LoadManifest rejected valid manifest: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestLoadManifest_SequenceBlockValidation verifies that a sequenceBlock
// condition's afterTools list is checked at load time. sequenceBlock
// was the only condition type with no validateLocalManifest case, so two classes
// of authoring mistake passed `eunox validate` silently and failed OPEN at
// runtime: an empty afterTools list (caught only by the runtime guard, surfacing
// as a CONDITION_FAILED on the first live call), and an entry with an
// unrecognized namespace prefix (e.g. mcp:read_file, or a case mismatch like
// Tool:read_file) that the handler records under one key but looks up under
// another, so the count is always zero and the rule never fires. An entry that
// strips to the empty string (e.g. "" or a bare "tool:") names no tool and is
// likewise rejected. A colon-bearing entry without a recognized prefix is
// rejected as ambiguous — including a bare resource URI like file:///secrets,
// which must be written with the explicit resource: prefix. Bare names and
// recognized prefixes (tool:, resource:, prompt:, system:) are accepted.
func TestLoadManifest_SequenceBlockValidation(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{
			name: "empty afterTools rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:write_external"
    actions: [call]
    conditions:
      - type: sequenceBlock
        afterTools: []
`,
			wantErr: "sequenceBlock requires a non-empty 'afterTools' list",
		},
		{
			name: "missing afterTools rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:write_external"
    actions: [call]
    conditions:
      - type: sequenceBlock
`,
			wantErr: "sequenceBlock requires a non-empty 'afterTools' list",
		},
		{
			name: "unrecognized namespace prefix rejected as ambiguous",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:write_external"
    actions: [call]
    conditions:
      - type: sequenceBlock
        afterTools: ["mcp:read_file"]
`,
			wantErr: `entry "mcp:read_file" is ambiguous`,
		},
		{
			name: "case-mismatched prefix rejected as ambiguous",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:write_external"
    actions: [call]
    conditions:
      - type: sequenceBlock
        afterTools: ["Tool:read_file"]
`,
			wantErr: `entry "Tool:read_file" is ambiguous`,
		},
		{
			// A bare resource URI would actually fire at runtime (a resource read
			// records history under the bare URI), but at load time it is
			// indistinguishable from a prefix typo, so it is rejected as ambiguous
			// and the author must write the explicit resource: form (see the
			// "recognized prefixes accepted" case, which includes it). Locks in the
			// deliberate asymmetry flagged in review.
			name: "bare resource URI rejected as ambiguous",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:write_external"
    actions: [call]
    conditions:
      - type: sequenceBlock
        afterTools: ["file:///secrets"]
`,
			wantErr: `entry "file:///secrets" is ambiguous`,
		},
		{
			name: "one bad entry among several rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:write_external"
    actions: [call]
    conditions:
      - type: sequenceBlock
        afterTools: ["read_file", "tool:list_dir", "x:exec"]
`,
			wantErr: `entry "x:exec" is ambiguous`,
		},
		{
			name: "empty string entry rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:write_external"
    actions: [call]
    conditions:
      - type: sequenceBlock
        afterTools: [""]
`,
			wantErr: `entry "" names no tool`,
		},
		{
			name: "prefix-only entry (empty tool name) rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:write_external"
    actions: [call]
    conditions:
      - type: sequenceBlock
        afterTools: ["tool:"]
`,
			wantErr: `entry "tool:" names no tool`,
		},
		{
			name: "bare tool name accepted",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:write_external"
    actions: [call]
    conditions:
      - type: sequenceBlock
        afterTools: ["read_credentials"]
`,
		},
		{
			// resource:file:///secrets is the disambiguated form of the bare
			// file:///secrets entry rejected above — the explicit prefix strips to the
			// same history key, so it is accepted.
			name: "recognized prefixes accepted",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:write_external"
    actions: [call]
    conditions:
      - type: sequenceBlock
        afterTools: ["tool:read_file", "resource:file:///secrets", "prompt:summarize", "system:initialize"]
`,
		},
		{
			// The error must name the capability index, the condition index, and the
			// offending afterTools entry index, so an operator can locate the typo in
			// a manifest with several capabilities and conditions.
			name: "error names capability, condition, and entry index",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
  - target: "tool:write_external"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 5
        windowSeconds: 3600
      - type: sequenceBlock
        afterTools: ["read_file", "bad:entry"]
`,
			wantErr: "capability at index 1, condition 1, afterTools entry 1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifestFile(t, tc.yaml)
			_, err := LoadManifest(path)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("LoadManifest rejected valid manifest: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestLoadManifest_RejectsUnknownKeys verifies that a misspelled or unrecognized
// key anywhere in the manifest is rejected (fail-closed) rather than silently
// dropped — a typo in a security policy must never produce a quietly different
// policy. This includes argumentSchema, whose keywords are a closed JSON-Schema
// subset (SPEC § 3.2.2) checked recursively (see
// TestLoadManifest_ArgumentSchemaKeywords).
func TestLoadManifest_RejectsUnknownKeys(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{
			name: "unknown top-level key with suggestion",
			yaml: `naem: typo
version: "0.1.0"
capabilities: []
`,
			wantErr: `unknown field "naem" (did you mean "name"?)`,
		},
		{
			name: "singular 'action' key on capability",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    action: [call]
`,
			wantErr: `capabilities[0]: unknown field "action" (did you mean "actions"?)`,
		},
		{
			name: "typo'd condition field 'arguments'",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    conditions:
      - type: allowedValues
        arguments: path
        values: ["/data/*"]
`,
			wantErr: `conditions[0]: unknown field "arguments" (did you mean "argument"?)`,
		},
		{
			name: "typo'd directive field 'field'",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    directives:
      - type: redactFields
        field: ["secret"]
`,
			wantErr: `directives[0]: unknown field "field"`,
		},
		{
			name: "valid manifest with directives and argumentSchema accepted",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: object
      properties:
        path:
          type: string
      required: [path]
    conditions:
      - type: allowedValues
        argument: path
        values: ["/data/*"]
    directives:
      - type: redactFields
        fields: ["result.secret"]
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifestFile(t, tc.yaml)
			_, err := LoadManifest(path)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("LoadManifest rejected valid manifest: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestLoadManifest_ArgumentSchemaKeywords verifies that argumentSchema accepts
// only the closed JSON-Schema keyword set (SPEC § 3.2.2) and rejects everything
// else — recursively through properties and items — with a path-qualified
// error. Before this check a keyword the struct does not model (const, $ref,
// allOf, exclusiveMinimum, format, …) was silently dropped by the typed decode
// and never enforced, weakening the policy relative to author intent.
func TestLoadManifest_ArgumentSchemaKeywords(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{
			name: "accept: full supported keyword set, nested",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: object
      description: "read_file arguments"
      additionalProperties: false
      required: [path]
      properties:
        path:
          type: string
          minLength: 1
          maxLength: 4096
          pattern: "^/data/"
        mode:
          type: [string, "null"]
          enum: ["r", "rw"]
        count:
          type: integer
          minimum: 0
          maximum: 100
        tags:
          type: array
          minItems: 1
          maxItems: 8
          items:
            type: string
`,
		},
		{
			name: "reject: const at top level",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      const: "frozen"
`,
			wantErr: `capabilities[0].argumentSchema: unknown keyword "const"`,
		},
		{
			name: "reject: $ref at top level",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      $ref: "#/definitions/path"
`,
			wantErr: `capabilities[0].argumentSchema: unknown keyword "$ref"`,
		},
		{
			name: "reject: allOf applicator",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      allOf: []
`,
			wantErr: `capabilities[0].argumentSchema: unknown keyword "allOf"`,
		},
		{
			name: "reject: format annotation nested in properties",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: object
      properties:
        path:
          type: string
          format: uri
`,
			wantErr: `capabilities[0].argumentSchema.properties.path: unknown keyword "format"`,
		},
		{
			name: "reject: exclusiveMinimum nested in items",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: object
      properties:
        scores:
          type: array
          items:
            type: number
            exclusiveMinimum: 0
`,
			wantErr: `capabilities[0].argumentSchema.properties.scores.items: unknown keyword "exclusiveMinimum"`,
		},
		{
			name: "reject: arbitrary typo'd keyword suggests nearest",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: object
      proprties:
        path:
          type: string
`,
			wantErr: `capabilities[0].argumentSchema: unknown keyword "proprties" (did you mean "properties"?)`,
		},
		{
			name: "reject: strict is no longer a supported keyword",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: object
      strict: true
`,
			wantErr: `capabilities[0].argumentSchema: unknown keyword "strict"`,
		},
		{
			// The load-bearing regression case: an empty type array previously decoded
			// to SchemaType{Multiple: []string{}}, which IsZero() treats as "no type
			// declared", silently disabling the type check entirely (a numeric argument
			// would then never reach schemaValidateString, so a string-only `pattern`
			// was never enforced).
			name: "reject: empty type array nested in properties",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: object
      properties:
        path:
          type: []
          pattern: "^/safe/"
`,
			wantErr: `capabilities[0].argumentSchema.properties.path.type: type must not be an empty array`,
		},
		{
			name: "reject: empty type array at top level",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: []
`,
			wantErr: `capabilities[0].argumentSchema.type: type must not be an empty array`,
		},
		{
			name: "reject: empty string type",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: ""
`,
			wantErr: `capabilities[0].argumentSchema.type: type must not be an empty string`,
		},
		{
			name: "reject: unknown type name",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: sting
`,
			wantErr: `capabilities[0].argumentSchema.type: unknown JSON-Schema type "sting"`,
		},
		{
			name: "reject: unknown type name inside array",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: [string, boolan]
`,
			wantErr: `capabilities[0].argumentSchema.type: unknown JSON-Schema type "boolan"`,
		},
		{
			name: "reject: duplicate type name inside array",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: [string, string]
`,
			wantErr: `capabilities[0].argumentSchema.type: duplicate type "string"`,
		},
		{
			name: "accept: type omitted entirely",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      properties:
        path:
          pattern: "^/safe/"
`,
		},
		{
			name: "accept: explicit null type",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: null
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifestFile(t, tc.yaml)
			_, err := LoadManifest(path)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("LoadManifest rejected valid manifest: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestLoadManifest_ArgumentSchemaPattern verifies that an argumentSchema
// `pattern` is compiled at load: a valid regex loads, and a malformed one is
// rejected up front with a path-qualified error rather than loading silently
// and only failing on the first live request. The pattern is a recognized
// keyword, so checkArgumentSchemaKeywords accepts it — this is the
// validateLocalManifest compile step.
func TestLoadManifest_ArgumentSchemaPattern(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{
			name: "accept: valid pattern, nested in properties and items",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: object
      properties:
        path:
          type: string
          pattern: "^/data/[a-z0-9_/-]+$"
        tags:
          type: array
          items:
            type: string
            pattern: "^t-[0-9]+$"
`,
		},
		{
			name: "reject: malformed pattern in a property",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: object
      properties:
        path:
          type: string
          pattern: "[unclosed"
`,
			wantErr: `capabilities[0].argumentSchema.properties.path: invalid pattern "[unclosed"`,
		},
		{
			name: "reject: malformed pattern nested in items",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: object
      properties:
        tags:
          type: array
          items:
            type: string
            pattern: "(unbalanced"
`,
			wantErr: `capabilities[0].argumentSchema.properties.tags.items: invalid pattern "(unbalanced"`,
		},
		{
			name: "reject: malformed pattern at top level",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:read_file"
    actions: [call]
    argumentSchema:
      type: string
      pattern: "*nostart"
`,
			wantErr: `capabilities[0].argumentSchema: invalid pattern "*nostart"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifestFile(t, tc.yaml)
			_, err := LoadManifest(path)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("LoadManifest rejected valid manifest: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestLoadManifest_RejectsArgumentSchemaOnNonToolTarget verifies that an
// argumentSchema on a resource:/prompt:/system: target is rejected at load.
// argumentSchema is tool-only by design (SPEC § 3.2.2): those requests carry no
// tool-argument map for it to validate, so the proxy never evaluated it there.
// Silently accepting one was a fail-open — a declared structural guard with no
// runtime effect is equivalent to no guard — so it must fail closed
// at validate/startup time, mirroring the directives-on-non-tool rejection.
func TestLoadManifest_RejectsArgumentSchemaOnNonToolTarget(t *testing.T) {
	cases := []struct {
		name   string
		target string
		action string
	}{
		{"resource target", "resource:file:///data/reports/q3.csv", "read"},
		{"prompt target", "prompt:code_review", "get"},
		{"system sampling opt-in", "system:sampling/createMessage", "allow"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yamlContent := `
name: test-policy
version: "0.1.0"
capabilities:
  - target: "` + tc.target + `"
    actions: [` + tc.action + `]
    argumentSchema:
      type: object
      properties:
        uri:
          type: string
`
			path := writeManifestFile(t, yamlContent)
			_, err := LoadManifest(path)
			if err == nil {
				t.Fatalf("argumentSchema on %s must be rejected at load, got nil error", tc.target)
			}
			if !strings.Contains(err.Error(), "argumentSchema") || !strings.Contains(err.Error(), "tool:") {
				t.Fatalf("want error mentioning argumentSchema and tool:, got %v", err)
			}
		})
	}
}

// ── Prefix requirement ────────────────────────────────────────────────────────

func TestValidateLocalManifest_RejectsUnprefixedResource(t *testing.T) {
	cases := []struct {
		name     string
		resource string
	}{
		{"bare tool name", "read_file"},
		{"bare wildcard", "*"},
		{"old prompt format", "prompts/code_review"},
		{"old sampling format", "sampling/createMessage"},
		{"bare URI", "file:///data/reports"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &LocalManifest{
				Name:    "test",
				Version: "1.0.0",
				Capabilities: []capability.Constraint{
					{Target: tc.resource, Actions: []string{"call"}},
				},
			}
			err := validateLocalManifest(m)
			if err == nil {
				t.Errorf("validateLocalManifest accepted unprefixed resource %q, want error", tc.resource)
			}
			if err != nil && !strings.Contains(err.Error(), "namespace prefix") {
				t.Errorf("error should mention 'namespace prefix', got: %v", err)
			}
		})
	}
}

// TestValidateLocalManifest_ConflictingDescriptionHashPins pins the load-time rejection of
// an ambiguous manifest: two exact-tool entries pinning the SAME tool to DIFFERENT hashes.
// The ambiguity is a static property of the manifest text, so it is caught here (fail
// closed) instead of being carried into the PDP's enforcement path. Same-tool entries with
// the SAME hash, and different tools with different hashes, remain valid.
func TestValidateLocalManifest_ConflictingDescriptionHashPins(t *testing.T) {
	hashA := capability.ComputeToolHash("Description A.", nil)
	hashB := capability.ComputeToolHash("Description B.", nil)

	t.Run("same tool, different hashes -> rejected", func(t *testing.T) {
		m := &LocalManifest{
			Name:    "test",
			Version: "1.0.0",
			Capabilities: []capability.Constraint{
				{Target: "tool:list_dir", Actions: []string{"call"}, DescriptionHash: hashA},
				{Target: "tool:list_dir", Actions: []string{"call"}, DescriptionHash: hashB},
			},
		}
		err := validateLocalManifest(m)
		if err == nil {
			t.Fatal("two different descriptionHash pins for one tool must be rejected at load")
		}
		if !strings.Contains(err.Error(), "conflicting descriptionHash") {
			t.Errorf("error should name the conflicting pins, got: %v", err)
		}
	})

	t.Run("same tool, same hash -> accepted", func(t *testing.T) {
		m := &LocalManifest{
			Name:    "test",
			Version: "1.0.0",
			Capabilities: []capability.Constraint{
				{Target: "tool:list_dir", Actions: []string{"call"}, DescriptionHash: hashA},
				{Target: "tool:list_dir", Actions: []string{"*"}, DescriptionHash: hashA},
			},
		}
		if err := validateLocalManifest(m); err != nil {
			t.Errorf("identical pins for one tool must be accepted, got: %v", err)
		}
	})

	t.Run("different tools, different hashes -> accepted", func(t *testing.T) {
		m := &LocalManifest{
			Name:    "test",
			Version: "1.0.0",
			Capabilities: []capability.Constraint{
				{Target: "tool:list_dir", Actions: []string{"call"}, DescriptionHash: hashA},
				{Target: "tool:read_file", Actions: []string{"call"}, DescriptionHash: hashB},
			},
		}
		if err := validateLocalManifest(m); err != nil {
			t.Errorf("distinct tools with distinct pins must be accepted, got: %v", err)
		}
	})
}

func TestValidateLocalManifest_AcceptsPrefixedResources(t *testing.T) {
	cases := []struct {
		name     string
		resource string
		actions  []string
	}{
		{"tool prefix", "tool:read_file", []string{"call"}},
		{"tool glob", "tool:read_*", []string{"call"}},
		{"resource prefix", "resource:file:///data/*", []string{"read"}},
		{"prompt prefix", "prompt:code_review", []string{"get"}},
		{"prompt wildcard", "prompt:*", []string{"get"}},
		{"system prefix", "system:sampling/createMessage", []string{"allow"}},
		{"star action on tool", "tool:read_file", []string{"*"}},
		{"star action on resource", "resource:file:///data/*", []string{"*"}},
		{"star action on prompt", "prompt:code_review", []string{"*"}},
		{"star action on system", "system:sampling/createMessage", []string{"*"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &LocalManifest{
				Name:    "test",
				Version: "1.0.0",
				Capabilities: []capability.Constraint{
					{Target: tc.resource, Actions: tc.actions},
				},
			}
			if err := validateLocalManifest(m); err != nil {
				t.Errorf("validateLocalManifest rejected valid constraint %q %v: %v", tc.resource, tc.actions, err)
			}
		})
	}
}

func TestValidateLocalManifest_RejectsTooBroadTargetPatterns(t *testing.T) {
	cases := []struct {
		name, target string
		actions      []string
		wantErr      string
	}{
		{
			name:    "tool bare wildcard",
			target:  "tool:*",
			actions: []string{"call"},
			wantErr: "bare tool wildcard",
		},
		{
			name:    "tool double-star wildcard",
			target:  "tool:**",
			actions: []string{"call"},
			wantErr: "bare tool wildcard",
		},
		{
			name:    "tool star-question wildcard",
			target:  "tool:*?",
			actions: []string{"call"},
			wantErr: "bare tool wildcard",
		},
		{
			name:    "tool question-star wildcard",
			target:  "tool:?*",
			actions: []string{"call"},
			wantErr: "bare tool wildcard",
		},
		{
			name:    "resource bare wildcard",
			target:  "resource:*",
			actions: []string{"read"},
			wantErr: "bare resource wildcard",
		},
		{
			name:    "resource double-star wildcard",
			target:  "resource:**",
			actions: []string{"read"},
			wantErr: "bare resource wildcard",
		},
		{
			name:    "resource wildcard authority",
			target:  "resource:api://*",
			actions: []string{"read"},
			wantErr: "URI scheme or authority",
		},
		{
			name:    "resource opaque uri wildcard",
			target:  "resource:mailto:*",
			actions: []string{"read"},
			wantErr: "opaque",
		},
		{
			name:    "system wildcard",
			target:  "system:*",
			actions: []string{"allow"},
			wantErr: "glob metacharacters",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &LocalManifest{
				Name:    "test",
				Version: "1.0.0",
				Capabilities: []capability.Constraint{
					{Target: tc.target, Actions: tc.actions},
				},
			}
			err := validateLocalManifest(m)
			if err == nil {
				t.Fatalf("validateLocalManifest accepted %q, want error", tc.target)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error should contain %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

// ── Action–namespace pairing ──────────────────────────────────────────────────

func TestValidateLocalManifest_RejectsInvalidActionPairings(t *testing.T) {
	cases := []struct {
		name     string
		resource string
		actions  []string
		wantErr  string
	}{
		{
			name:     "tool with read action",
			resource: "tool:read_file",
			actions:  []string{"read"},
			wantErr:  "invalid action",
		},
		{
			name:     "tool with get action",
			resource: "tool:read_file",
			actions:  []string{"get"},
			wantErr:  "invalid action",
		},
		{
			name:     "tool with allow action",
			resource: "tool:read_file",
			actions:  []string{"allow"},
			wantErr:  "invalid action",
		},
		{
			name:     "resource with call action",
			resource: "resource:file:///data/*",
			actions:  []string{"call"},
			wantErr:  "invalid action",
		},
		{
			name:     "resource with get action",
			resource: "resource:file:///data/*",
			actions:  []string{"get"},
			wantErr:  "invalid action",
		},
		{
			name:     "prompt with call action",
			resource: "prompt:code_review",
			actions:  []string{"call"},
			wantErr:  "invalid action",
		},
		{
			name:     "prompt with read action",
			resource: "prompt:code_review",
			actions:  []string{"read"},
			wantErr:  "invalid action",
		},
		{
			name:     "system with call action",
			resource: "system:sampling/createMessage",
			actions:  []string{"call"},
			wantErr:  "invalid action",
		},
		{
			name:     "system with read action",
			resource: "system:sampling/createMessage",
			actions:  []string{"read"},
			wantErr:  "invalid action",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &LocalManifest{
				Name:    "test",
				Version: "1.0.0",
				Capabilities: []capability.Constraint{
					{Target: tc.resource, Actions: tc.actions},
				},
			}
			err := validateLocalManifest(m)
			if err == nil {
				t.Errorf("validateLocalManifest accepted invalid pairing %q %v, want error", tc.resource, tc.actions)
			}
			if err != nil && !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error should contain %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidateLocalManifest_ErrorMessage_IncludesConstraintIndex(t *testing.T) {
	// The error message must identify which capability is invalid.
	m := &LocalManifest{
		Name:    "test",
		Version: "1.0.0",
		Capabilities: []capability.Constraint{
			{Target: "tool:read_file", Actions: []string{"call"}}, // valid
			{Target: "no_prefix_here", Actions: []string{"call"}}, // invalid at index 1
		},
	}
	err := validateLocalManifest(m)
	if err == nil {
		t.Fatal("expected error for invalid constraint at index 1")
	}
	if !strings.Contains(err.Error(), "capability at index 1") {
		t.Errorf("error should identify 'capability at index 1', got: %v", err)
	}
}

func TestValidateLocalManifest_ErrorMessage_NamesPrefixClearly(t *testing.T) {
	m := &LocalManifest{
		Name:    "test",
		Version: "1.0.0",
		Capabilities: []capability.Constraint{
			{Target: "tool:read_file", Actions: []string{"read"}},
		},
	}
	err := validateLocalManifest(m)
	if err == nil {
		t.Fatal("expected error for tool: with read action")
	}
	msg := err.Error()
	// Error must mention the constraint and the invalid action.
	if !strings.Contains(msg, "tool:read_file") {
		t.Errorf("error should name the constraint, got: %v", msg)
	}
	if !strings.Contains(msg, `"read"`) {
		t.Errorf("error should name the invalid action, got: %v", msg)
	}
}

// ── Full manifest with multiple capabilities ──────────────────────────────────

func TestValidateLocalManifest_MixedValidCapabilities(t *testing.T) {
	m := &LocalManifest{
		Name:    "mixed-agent",
		Version: "2.0.0",
		Capabilities: []capability.Constraint{
			{Target: "tool:read_file", Actions: []string{"call"}},
			{Target: "tool:query_db", Actions: []string{"*"}},
			{Target: "resource:file:///data/reports/*", Actions: []string{"read"}},
			{Target: "prompt:code_review", Actions: []string{"get"}},
			{Target: "system:sampling/createMessage", Actions: []string{"allow"}},
		},
	}
	if err := validateLocalManifest(m); err != nil {
		t.Errorf("validateLocalManifest rejected a fully valid manifest: %v", err)
	}
}

func TestLoadManifest_PreCompilesIPRangeCIDRs(t *testing.T) {
	yaml := `name: p
version: "0.1.0"
capabilities:
  - target: "tool:get_invoice"
    actions: [call]
    conditions:
      - type: ipRange
        cidrs: ["10.0.0.0/8", "192.168.0.0/16"]
`
	path := writeManifestFile(t, yaml)
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}

	if len(m.Capabilities) != 1 || len(m.Capabilities[0].Conditions) != 1 {
		t.Fatalf("manifest shape: got %d capabilities / %d conditions, want 1 / 1",
			len(m.Capabilities), len(m.Capabilities[0].Conditions))
	}

	cond, ok := m.Capabilities[0].Conditions[0].(*capability.IPRangeCondition)
	if !ok {
		t.Fatalf("condition type: got %T, want *capability.IPRangeCondition", m.Capabilities[0].Conditions[0])
	}

	networks, compiled := cond.Networks()
	if !compiled {
		t.Fatal("Networks: condition was not compiled at load time, want compiled")
	}
	if len(networks) != 2 {
		t.Fatalf("Networks: got %d networks, want 2", len(networks))
	}
	// Sanity-check the compiled networks resolve membership correctly.
	if !networks[0].Contains(net.ParseIP("10.1.2.3")) {
		t.Error("compiled network[0] should contain 10.1.2.3")
	}
	if networks[1].Contains(net.ParseIP("10.1.2.3")) {
		t.Error("compiled network[1] (192.168.0.0/16) should not contain 10.1.2.3")
	}
}

type jfkEmbed struct {
	Inner string `json:"inner"`
}

type jfkSample struct {
	jfkEmbed        // anonymous embed → promotes "inner"
	Named    string `json:"named"`
	WithOpts int    `json:"with_opts,omitempty"`
	Skipped  string `json:"-"`
	Untagged string // no tag → falls back to the field name "Untagged"
	PtrField *jfkEmbed
}

func TestJSONFieldKeys_AllTagShapes(t *testing.T) {
	t.Parallel()
	got := jsonFieldKeys(reflect.TypeOf(jfkSample{}))

	want := map[string]bool{
		"inner":     true, // promoted from the anonymous embed
		"named":     true,
		"with_opts": true, // options after the comma are stripped
		"Untagged":  true, // untagged field falls back to its Go name
		"PtrField":  true, // named pointer field, no tag → falls back to its Go name
	}
	for k := range want {
		if !got[k] {
			t.Errorf("expected key %q to be present, got keys: %v", k, got)
		}
	}
	if got["Skipped"] || got["-"] {
		t.Errorf(`json:"-" field must be excluded, got keys: %v`, got)
	}
}

// TestJSONFieldKeys_PointerToStruct asserts the pointer is dereferenced so the
// element type's keys are returned.
func TestJSONFieldKeys_PointerToStruct(t *testing.T) {
	t.Parallel()
	got := jsonFieldKeys(reflect.TypeOf(&jfkEmbed{}))
	if !got["inner"] {
		t.Errorf("expected pointer element keys, got: %v", got)
	}
}

// examplePoliciesGlob locates the reference policies relative to this package
// directory (cmd/eunox) so the test runs under `make test` with no binary
// build and no dependence on the process working directory.
const examplePoliciesGlob = "../../examples/policies/*.yaml"

func TestExamplePoliciesValidateClean(t *testing.T) {
	paths, err := filepath.Glob(examplePoliciesGlob)
	if err != nil {
		t.Fatalf("globbing %q: %v", examplePoliciesGlob, err)
	}
	if len(paths) == 0 {
		t.Fatalf("no reference policies matched %q — wrong working directory or the examples moved", examplePoliciesGlob)
	}

	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			if _, err := LoadManifest(path); err != nil {
				t.Errorf("%s does not validate clean, but examples/policies/README.md advertises every policy as `eunox validate`-clean: %v", path, err)
			}
		})
	}
}

// The following white-box tests reach config's unexported validators
// (validateLocalManifest, validateDescriptionHashFormat). They were extracted
// from package main's drift_test.go, enforcement_gaps_test.go, and pdp_test.go
// when this package was split out; the integration tests around them stay in
// cmd/eunox on the exported API.

func TestValidateDescriptionHashFormat(t *testing.T) {
	goodHash := capability.ComputeToolHash("test description", nil)

	cases := []struct {
		input   string
		wantErr string
	}{
		{goodHash, ""},
		{"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ""},
		{"", `must start with "sha256:"`},
		{"md5:abc123", `must start with "sha256:"`},
		{"sha256:tooshort", "exactly 64"},
		{"sha256:" + strings.Repeat("g", 64), "not valid hex"},
		{"sha256:" + strings.Repeat("A", 64), "lowercase"},
	}

	for _, tc := range cases {
		err := validateDescriptionHashFormat(tc.input)
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("validateDescriptionHashFormat(%q): unexpected error: %v", tc.input, err)
			}
		} else {
			if err == nil {
				t.Errorf("validateDescriptionHashFormat(%q): want error containing %q, got nil", tc.input, tc.wantErr)
			} else if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("validateDescriptionHashFormat(%q): error %q does not contain %q", tc.input, err.Error(), tc.wantErr)
			}
		}
	}
}

func TestGap5_ManifestValidation_SamplingEntryAccepted(t *testing.T) {
	manifest := &LocalManifest{
		Name:    "agent",
		Version: "1.0.0",
		Capabilities: []capability.Constraint{
			{Target: "tool:read_file", Actions: []string{"call"}},
			{Target: "system:sampling/createMessage", Actions: []string{"allow"}},
		},
	}
	if err := validateLocalManifest(manifest); err != nil {
		t.Errorf("manifest with sampling entry should be valid, got: %v", err)
	}
}

func TestGap4_ManifestValidation_PromptEntryAccepted(t *testing.T) {
	manifest := &LocalManifest{
		Name:    "agent",
		Version: "1.0.0",
		Capabilities: []capability.Constraint{
			{Target: "tool:read_file", Actions: []string{"call"}},
			{Target: "prompt:code_review", Actions: []string{"get"}},
			{Target: "prompt:*", Actions: []string{"get"}},
		},
	}
	if err := validateLocalManifest(manifest); err != nil {
		t.Errorf("manifest with prompt entries should be valid, got: %v", err)
	}
}

func TestPrincipal_Validation(t *testing.T) {
	manifestWith := func(principal map[string][]string) *LocalManifest {
		return &LocalManifest{
			Name:    "p",
			Version: "1.0.0",
			Capabilities: []capability.Constraint{
				{Target: "tool:x", Actions: []string{"call"}, Principal: principal},
			},
		}
	}

	tests := []struct {
		name      string
		principal map[string][]string
		wantErr   string
	}{
		{"unsupported claim rejected", map[string][]string{"org": {"acme"}}, "not supported"},
		{"empty value list rejected", map[string][]string{"agent_id": {}}, "at least one"},
		{"empty value string rejected", map[string][]string{"agent_id": {""}}, "empty value"},
		{"malformed glob pattern rejected", map[string][]string{"agent_id": {"agent-["}}, "invalid pattern"},
		// A malformed glob in a principal constraint must be rejected at load,
		// not silently skipped at match time (PrincipalMatches drops an ErrBadPattern
		// pattern, which would make the whole constraint permanently unreachable). The
		// "sub" case is the issue's verbatim example; the "iss" case has a literal
		// prefix and a star before the malformed class, the form that path.Match must
		// still reject when probed with an empty name (it does — see the regression).
		{"malformed sub bracket rejected (issue example)", map[string][]string{"sub": {"service-[abc"}}, "invalid pattern"},
		{"malformed iss star-then-class rejected", map[string][]string{"iss": {"a*[bad"}}, "invalid pattern"},
		{"valid agent_id accepted", map[string][]string{"agent_id": {"admin"}}, ""},
		{"valid glob accepted", map[string][]string{"agent_id": {"batch-*"}}, ""},
		{"valid multi-claim accepted", map[string][]string{"agent_id": {"a"}, "task_id": {"t1"}}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateLocalManifest(manifestWith(tc.principal))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestLoadManifest_ConditionEntrySurroundingWhitespace verifies that the
// allowlist validators reject an entry carrying surrounding whitespace.
// Request operation verbs, table names, and recipient domains are trimmed
// before matching, so " users" or "SELECT " would never match and would
// silently deny every call — the same footgun as an all-blank entry, which is
// already rejected. These cases assert load-time rejection; a clean manifest
// with no surrounding whitespace still loads.
func TestLoadManifest_ConditionEntrySurroundingWhitespace(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{
			name: "allowedOperations entry with trailing space rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: allowedOperations
        argument: sql
        operations: ["SELECT "]
`,
			wantErr: "leading or trailing whitespace",
		},
		{
			name: "allowedTables entry with leading space rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:query_sales"
    actions: [call]
    conditions:
      - type: allowedTables
        argument: table
        tables: [" users"]
`,
			wantErr: "leading or trailing whitespace",
		},
		{
			name: "recipientDomain entry with trailing space rejected",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:send_email"
    actions: [call]
    conditions:
      - type: recipientDomain
        argument: to
        domains: ["example.com "]
`,
			wantErr: "leading or trailing whitespace",
		},
		{
			name: "clean entries without surrounding whitespace accepted",
			yaml: `schemaVersion: "0.1"
name: "p"
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: allowedOperations
        argument: sql
        operations: ["SELECT"]
  - target: "tool:query_sales"
    actions: [call]
    conditions:
      - type: allowedTables
        argument: table
        tables: ["users"]
  - target: "tool:send_email"
    actions: [call]
    conditions:
      - type: recipientDomain
        argument: to
        domains: ["example.com"]
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "m.yaml")
			if err := os.WriteFile(p, []byte(tc.yaml), 0o600); err != nil {
				t.Fatalf("write manifest: %v", err)
			}
			_, err := LoadManifest(p)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("LoadManifest rejected valid manifest: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestLoadManifest_RejectsNestedCoercedNumericValues pins the depth-uniform
// coercion guard: a coerced scalar nested one level deep inside a values:/enum:
// list element (a sequence or mapping element) is rejected with the same
// "quote it" message as the flat case, while a clean/quoted nested value loads.
// Without the recursion in checkValueScalarNotCoerced, `values: [[010]]` would
// load with 010 silently coerced to 8.
func TestLoadManifest_RejectsNestedCoercedNumericValues(t *testing.T) {
	mkValuesYAML := func(value string) string {
		return `
name: "t"
version: "1.0.0"
capabilities:
  - target: "tool:transfer"
    actions: [call]
    conditions:
      - type: allowedValues
        argument: code
        values: [` + value + `]
`
	}
	mkEnumYAML := func(value string) string {
		return `
name: "t"
version: "1.0.0"
capabilities:
  - target: "tool:transfer"
    actions: [call]
    argumentSchema:
      type: object
      properties:
        code: { type: array, enum: [` + value + `] }
`
	}

	cases := []struct {
		name  string
		yaml  string
		quote bool // true => must be rejected with the "quote it" guidance
	}{
		{name: "values_nested_seq_octal", yaml: mkValuesYAML("[010]"), quote: true},
		{name: "values_nested_seq_float", yaml: mkValuesYAML("[1.0]"), quote: true},
		{name: "values_nested_map_octal", yaml: mkValuesYAML("{k: 010}"), quote: true},
		{name: "enum_nested_seq_octal", yaml: mkEnumYAML("[010]"), quote: true},
		{name: "values_nested_seq_clean", yaml: mkValuesYAML("[200]"), quote: false},
		{name: "values_nested_seq_quoted", yaml: mkValuesYAML(`["010"]`), quote: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadManifest(writeManifestFile(t, tc.yaml))
			if tc.quote {
				if err == nil {
					t.Fatalf("expected rejection of a nested coerced value, got nil")
				}
				if !strings.Contains(err.Error(), "quote it") {
					t.Errorf("nested-coercion error should guide quoting/canonicalizing, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Errorf("a clean/quoted nested value must load, got: %v", err)
			}
		})
	}
}

// TestLoadManifest_RejectsCoercedNumericPolicyFields is the regression for a bare
// numeric policy field (not a values:/enum: list entry) whose YAML auto-typed
// value silently differs from its source text: an unquoted leading-zero
// windowSeconds/minimum is read as octal, quietly changing what the manifest
// enforces (a shortened rate-limit window, a lowered argument bound) with no
// load-time signal. Covers maxCalls' count/windowSeconds and argumentSchema's
// minimum/maximum/minLength/maxLength/minItems/maxItems.
func TestLoadManifest_RejectsCoercedNumericPolicyFields(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "maxCalls windowSeconds octal-looking literal rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 5
        windowSeconds: 0600
`,
			wantErr: true,
		},
		{
			name: "maxCalls count octal-looking literal rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 010
        windowSeconds: 60
`,
			wantErr: true,
		},
		{
			name: "argumentSchema minimum octal-looking literal rejected",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:transfer"
    actions: [call]
    argumentSchema:
      type: object
      properties:
        amount:
          type: number
          minimum: 010
`,
			wantErr: true,
		},
		{
			name: "argumentSchema maximum, minLength, maxItems clean literals accepted",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:transfer"
    actions: [call]
    argumentSchema:
      type: object
      properties:
        amount:
          type: number
          minimum: 10
          maximum: 1000
        note:
          type: string
          minLength: 1
        tags:
          type: array
          maxItems: 5
`,
			wantErr: false,
		},
		{
			name: "maxCalls windowSeconds octal-looking literal rejected when the key is a YAML alias",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 5
        enum: [&vk windowSeconds, other]
        *vk: 0600
`,
			wantErr: true,
		},
		{
			name: "maxCalls with clean literals accepted",
			yaml: `name: p
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 5
        windowSeconds: 600
`,
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadManifest(writeManifestFile(t, tc.yaml))
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected rejection of a coerced numeric policy field, got nil")
				}
				if !strings.Contains(err.Error(), "quote it") {
					t.Errorf("error should guide quoting/canonicalizing, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Errorf("clean numeric policy fields must load, got: %v", err)
			}
		})
	}
}

// TestLoadManifest_RejectsDuplicateJSONKeys pins that a .json manifest with a
// duplicated mapping key is rejected (matching the YAML posture) rather than
// silently keeping the last value. encoding/json keeps last-wins for a duplicated
// key, a fail-closed gap for a security key like enforcement; routing JSON through
// the yaml.Node decode rejects the duplicate. A valid JSON manifest still loads.
func TestLoadManifest_RejectsDuplicateJSONKeys(t *testing.T) {
	writeJSON := func(t *testing.T, content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "manifest.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("writing JSON manifest: %v", err)
		}
		return path
	}

	dupEnforcement := `{"schemaVersion":"0.1","name":"m","version":"1.0.0",
  "capabilities":[{"target":"tool:x","actions":["call"],
    "enforcement":"audit","enforcement":"enforce"}]}`
	if _, err := LoadManifest(writeJSON(t, dupEnforcement)); err == nil {
		t.Fatal("expected rejection of a JSON manifest with a duplicated enforcement key, got nil")
	}

	dupActions := `{"schemaVersion":"0.1","name":"m","version":"1.0.0",
  "capabilities":[{"target":"tool:x","actions":["call"],"actions":["read"]}]}`
	if _, err := LoadManifest(writeJSON(t, dupActions)); err == nil {
		t.Fatal("expected rejection of a JSON manifest with a duplicated actions key, got nil")
	}

	// A valid JSON manifest with no duplicate keys still loads cleanly.
	valid := `{"schemaVersion":"0.1","name":"m","version":"1.0.0",
  "capabilities":[{"target":"tool:x","actions":["call"]}]}`
	if _, err := LoadManifest(writeJSON(t, valid)); err != nil {
		t.Fatalf("a valid JSON manifest must still load, got: %v", err)
	}
}

// TestLoadManifest_JSONNumericValuesNotCoerced guards that the scalar-coercion
// guard does not over-reject valid JSON. A JSON manifest whose allowedValues
// `values` list carries non-canonical but numerically-lossless literals (1.0,
// 1.50, 1e3) must still load: JSON numbers are unambiguous, so the guard compares
// them numerically (big.Rat) and accepts a value equal to its canonical form.
func TestLoadManifest_JSONNumericValuesNotCoerced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	content := `{"schemaVersion":"0.1","name":"m","version":"1.0.0",
  "capabilities":[{"target":"tool:x","actions":["call"],
    "conditions":[{"type":"allowedValues","argument":"x","values":[1.0,1.50,1e3]}]}]}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing JSON manifest: %v", err)
	}
	if _, err := LoadManifest(path); err != nil {
		t.Fatalf("a JSON manifest with numerically-lossless values must load, got: %v", err)
	}
}

// TestLoadManifest_JSONRejectsBeyondPrecisionInteger is the regression for a JSON
// allowlist value silently widening: an integer beyond float64 precision is rounded
// by yaml.v3's node.Decode (which decodes an integer larger than uint64 to float64),
// so the manifest would admit a DIFFERENT integer that rounds to the same float64.
// The guard now rejects a numerically-lossy JSON number at load.
func TestLoadManifest_JSONRejectsBeyondPrecisionInteger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	content := `{"schemaVersion":"0.1","name":"m","version":"1.0.0",
  "capabilities":[{"target":"tool:x","actions":["call"],
    "conditions":[{"type":"allowedValues","argument":"x","values":[12345678901234567890123]}]}]}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing JSON manifest: %v", err)
	}
	_, err := LoadManifest(path)
	if err == nil {
		t.Fatal("expected rejection of a beyond-float64-precision JSON allowlist integer, got nil")
	}
	if !strings.Contains(err.Error(), "precision") {
		t.Errorf("error should name the precision loss, got: %v", err)
	}
}

// TestLoadManifest_UnrecognizedExtensionRoutesThroughHardening is the regression
// for an extensionless (or unknown-extension) manifest bypassing the yaml.Node
// hardening pipeline and falling through to a bare json.Unmarshal that keeps the
// last value for a duplicated key. Every file must now be routed through the same
// decode, so a duplicated security-critical key is rejected regardless of
// extension, while a clean file of the same kind still loads.
func TestLoadManifest_UnrecognizedExtensionRoutesThroughHardening(t *testing.T) {
	write := func(t *testing.T, content string) string {
		t.Helper()
		// No extension: previously fell through to encoding/json (last-wins on dup keys).
		path := filepath.Join(t.TempDir(), "policy")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("writing manifest: %v", err)
		}
		return path
	}

	dupEnforcement := `{"schemaVersion":"0.1","name":"m","version":"1.0.0",
  "capabilities":[{"target":"tool:read_file","actions":["call"],
    "enforcement":"enforce","enforcement":"audit"}]}`
	if _, err := LoadManifest(write(t, dupEnforcement)); err == nil {
		t.Fatal("expected rejection of an extensionless manifest with a duplicated enforcement key, got nil")
	}

	valid := `{"schemaVersion":"0.1","name":"m","version":"1.0.0",
  "capabilities":[{"target":"tool:read_file","actions":["call"]}]}`
	if _, err := LoadManifest(write(t, valid)); err != nil {
		t.Fatalf("a clean extensionless manifest must still load, got: %v", err)
	}

	// An extensionless file with JSON content is treated as JSON for the coercion
	// guard (content-detected), so a non-canonical but numerically-lossless value like
	// 1.0 loads (matching the pre-hardening bare json.Unmarshal path) rather than being
	// rejected under YAML-strict coercion.
	jsonNumbers := `{"schemaVersion":"0.1","name":"m","version":"1.0.0",
  "capabilities":[{"target":"tool:x","actions":["call"],
    "conditions":[{"type":"allowedValues","argument":"x","values":[1.0]}]}]}`
	if _, err := LoadManifest(write(t, jsonNumbers)); err != nil {
		t.Fatalf("an extensionless JSON manifest with a lossless value (1.0) must load, got: %v", err)
	}

	// ...but a numerically-lossy JSON value (beyond float64 precision) is still rejected.
	jsonLossy := `{"schemaVersion":"0.1","name":"m","version":"1.0.0",
  "capabilities":[{"target":"tool:x","actions":["call"],
    "conditions":[{"type":"allowedValues","argument":"x","values":[12345678901234567890123]}]}]}`
	if _, err := LoadManifest(write(t, jsonLossy)); err == nil {
		t.Fatal("expected rejection of a beyond-precision value in an extensionless JSON manifest, got nil")
	}
}

// TestLoadManifest_JSONExtensionRejectsNonJSON guards that a .json file is held to JSON
// syntax, not the YAML superset: routing JSON through the yaml.Node decoder (for
// duplicate-key rejection) must not silently start accepting YAML-only constructs (a
// "#" comment, an unquoted key, a bare non-object document) just because the file is
// named .json. The strict json.Valid pre-check keeps the .json extension meaning JSON.
func TestLoadManifest_JSONExtensionRejectsNonJSON(t *testing.T) {
	cases := map[string]string{
		"trailing comment": "{\n  \"schemaVersion\": \"0.1\"\n} # not JSON\n",
		"unquoted key":     "{ schemaVersion: \"0.1\" }",
		"bare yaml body":   "schemaVersion: \"0.1\"\nname: m\nversion: \"1.0.0\"\n",
	}
	for name, content := range cases {
		content := content
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := LoadManifest(path); err == nil {
				t.Errorf("a .json file containing YAML-only syntax (%s) must be rejected as not valid JSON", name)
			}
		})
	}
}

// TestLoadManifest_RejectsMalformedArgumentPath pins that a condition 'argument'
// using a malformed "$." nested path (empty body, empty segment, or trailing dot)
// is rejected at load — ArgumentPathSegments returns nil for it and ResolveArgument
// fails closed, so it would silently deny every matching call. A well-formed "$.a.b"
// path and a bare top-level key both still load. Covered across the argument-bearing
// condition types that share validateArgumentRef.
func TestLoadManifest_RejectsMalformedArgumentPath(t *testing.T) {
	mkYAML := func(condType, body, argument string) string {
		return `
name: "t"
version: "1.0.0"
capabilities:
  - target: "tool:x"
    actions: [call]
    conditions:
      - type: ` + condType + `
        argument: "` + argument + `"
` + body
	}

	bodies := map[string]string{
		"allowedValues":     "        values: [\"x\"]\n",
		"allowedOperations": "        operations: [\"SELECT\"]\n",
		"allowedExtensions": "        extensions: [\".pdf\"]\n",
		"allowedTables":     "        tables: [\"users\"]\n",
		"recipientDomain":   "        domains: [\"example.com\"]\n",
	}

	malformed := []string{"$.", "$.a..b", "$.a."}
	for condType, body := range bodies {
		for _, arg := range malformed {
			t.Run(condType+"_reject_"+arg, func(t *testing.T) {
				_, err := LoadManifest(writeManifestFile(t, mkYAML(condType, body, arg)))
				if err == nil {
					t.Fatalf("expected rejection of malformed argument path %q, got nil", arg)
				}
				if !strings.Contains(err.Error(), "malformed") {
					t.Errorf("error should name the malformed path, got: %v", err)
				}
			})
		}
		for _, arg := range []string{"$.a.b", "code"} {
			t.Run(condType+"_accept_"+strings.NewReplacer("$", "d", ".", "_").Replace(arg), func(t *testing.T) {
				if _, err := LoadManifest(writeManifestFile(t, mkYAML(condType, body, arg))); err != nil {
					t.Errorf("a well-formed argument %q must load, got: %v", arg, err)
				}
			})
		}
	}
}

// TestLoadManifest_RejectsNullCondition: a null entry in a conditions array (YAML `~`)
// decodes to a nil Condition that would panic the engine at request time
// (ConditionType() on the nil interface — a whole-proxy DoS from one route manifest), so
// it must be rejected at load, fail closed.
func TestLoadManifest_RejectsNullCondition(t *testing.T) {
	yaml := `name: p
version: "0.1.0"
capabilities:
  - target: "tool:query_db"
    actions: [call]
    conditions:
      - ~
`
	_, err := LoadManifest(writeManifestFile(t, yaml))
	if err == nil {
		t.Fatal("a null condition must be rejected at load, not accepted")
	}
	if !strings.Contains(err.Error(), "null condition") {
		t.Errorf("error = %q, want it to mention a null condition", err)
	}
}
