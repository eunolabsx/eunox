// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/pkg/capability"
)

// ─── generateInitManifestYAML ─────────────────────────────────────────────────

func TestGenerateInitManifestYAML_Header(t *testing.T) {
	got := generateInitManifestYAML(nil, "my-policy", "", false)

	if !strings.Contains(got, `schemaVersion: "0.1"`) {
		t.Errorf("header: missing schemaVersion field, got:\n%s", got)
	}
	// The name is rendered via yamlScalar (loss-free for invalid UTF-8), which emits a
	// plain unquoted scalar when no quoting is required — matching every other simple
	// scalar field in the manifest.
	if !strings.Contains(got, "name: my-policy") {
		t.Errorf("header: missing name field, got:\n%s", got)
	}
	if !strings.Contains(got, `version: "0.1.0"`) {
		t.Errorf("header: missing version field, got:\n%s", got)
	}
}

// TestGenerateInitManifestYAML_NonUTF8NameRoundTrips locks the fix that renders the
// top-level name through yamlScalar instead of %q. strconv.Quote (%q) is not a
// YAML-correct scalar for invalid UTF-8 — Go's \xNN escape is a raw byte while YAML's
// \xNN is code point U+00NN — so a non-UTF-8 --name would decode back to a different
// string. yamlScalar falls back to a !!binary scalar that round-trips any bytes.
func TestGenerateInitManifestYAML_NonUTF8NameRoundTrips(t *testing.T) {
	cases := map[string]string{
		"raw-bytes-80-81": "\x80\x81",
		"latin1-eacute":   "caf\xe9",
		"single-ff":       "\xff",
	}
	for label, name := range cases {
		t.Run(label, func(t *testing.T) {
			got := generateInitManifestYAML(nil, name, "", false)
			var doc struct {
				Name string `yaml:"name"`
			}
			if err := yaml.Unmarshal([]byte(got), &doc); err != nil {
				t.Fatalf("generated manifest does not parse: %v\nyaml:\n%s", err, got)
			}
			if doc.Name != name {
				t.Errorf("name did not round-trip: got %x, want %x\nyaml:\n%s",
					doc.Name, name, got)
			}
		})
	}
}

func TestGenerateInitManifestYAML_EmptyTools(t *testing.T) {
	got := generateInitManifestYAML(nil, "empty-manifest", "", false)

	if !strings.Contains(got, "capabilities:") {
		t.Error("should contain capabilities:")
	}
	if !strings.Contains(got, "no tools") {
		t.Errorf("should indicate no tools found, got:\n%s", got)
	}
	// Must not contain any capability entries.
	if strings.Contains(got, "- target:") {
		t.Error("empty tool list must not contain any target entries")
	}
}

func TestGenerateInitManifestYAML_ToolNoSchema(t *testing.T) {
	tools := []drift.UpstreamTool{{Name: "simple_tool"}}
	got := generateInitManifestYAML(tools, "test", "", false)

	if !strings.Contains(got, "# - target: tool:simple_tool") {
		t.Errorf("should have commented-out target entry with tool: prefix, got:\n%s", got)
	}
	if !strings.Contains(got, "#   actions: [call]") {
		t.Errorf("should have commented-out actions entry, got:\n%s", got)
	}
	// No argumentSchema when the tool has no inputSchema.
	if strings.Contains(got, "argumentSchema") {
		t.Error("should not emit argumentSchema for a tool with no inputSchema")
	}
}

func TestGenerateInitManifestYAML_ToolWithSchema(t *testing.T) {
	tools := []drift.UpstreamTool{{
		Name: "read_file",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path":     map[string]interface{}{"type": "string"},
				"encoding": map[string]interface{}{"type": "string"},
			},
			"required": []interface{}{"path"},
		},
	}}
	got := generateInitManifestYAML(tools, "test", "", false)

	for _, want := range []string{
		"# - target: tool:read_file",
		"#   argumentSchema:",
		"#     type: object",
		"#     additionalProperties: false",
		"#     properties:",
		"#       encoding: { type: string }",
		"#       path: { type: string }",
		"#     required: [path]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing expected line %q in:\n%s", want, got)
		}
	}
}

func TestGenerateInitManifestYAML_ToolSchemaUnknownType(t *testing.T) {
	// Property without an explicit "type" field should default to "string".
	tools := []drift.UpstreamTool{{
		Name: "tool_a",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"param": map[string]interface{}{}, // no "type" field
			},
		},
	}}
	got := generateInitManifestYAML(tools, "test", "", false)

	if !strings.Contains(got, "param: { type: string }") {
		t.Errorf("unknown type should default to string, got:\n%s", got)
	}
}

func TestGenerateInitManifestYAML_MultipleTools(t *testing.T) {
	tools := []drift.UpstreamTool{
		{Name: "tool_a"},
		{Name: "tool_b"},
		{Name: "tool_c"},
	}
	got := generateInitManifestYAML(tools, "test", "", false)

	for _, name := range []string{"tool_a", "tool_b", "tool_c"} {
		if !strings.Contains(got, "target: tool:"+name) {
			t.Errorf("should contain prefixed target entry for %s", name)
		}
	}

	// There should be separator comment lines between tools.
	if !strings.Contains(got, "  #\n") {
		t.Error("should have blank separator comment lines between tool entries")
	}
}

func TestGenerateInitManifestYAML_ReviewComment(t *testing.T) {
	tools := []drift.UpstreamTool{{Name: "some_tool"}}
	got := generateInitManifestYAML(tools, "test", "", false)

	if !strings.Contains(got, "REVIEW") {
		t.Error("should contain the REVIEW guidance comment")
	}
}

func TestGenerateInitManifestYAML_AllEntriesCommentedOut(t *testing.T) {
	tools := []drift.UpstreamTool{{Name: "tool_a"}, {Name: "tool_b"}}
	got := generateInitManifestYAML(tools, "test", "", false)

	// Every line in the capabilities block must be a comment or blank.
	// Scan the lines after "capabilities:".
	lines := strings.Split(got, "\n")
	inCaps := false
	for _, line := range lines {
		if line == "capabilities:" {
			inCaps = true
			continue
		}
		if !inCaps {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, "#") {
			t.Errorf("non-comment line in capabilities block: %q", line)
		}
	}
}

// TestGenerateInitManifestYAML_NewlineInToolNameStaysCommented is a regression
// for the deny-all-starter breakout: a hostile upstream tool whose name carries
// an embedded newline must not break out of the "  # " comment prefix and plant
// an ACTIVE capability. Every non-empty line of the capabilities section for
// such a tool must remain commented.
func TestGenerateInitManifestYAML_NewlineInToolNameStaysCommented(t *testing.T) {
	tools := []drift.UpstreamTool{{
		Name: "benign\n  - target: tool:exec_shell\n    actions: [call]",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"arg\n  - target: tool:exec_evil\n    actions: [call]": map[string]interface{}{"type": "string"},
			},
			"required": []interface{}{"arg\n  - target: tool:exec_required\n    actions: [call]"},
		},
	}}
	got := generateInitManifestYAML(tools, "test", "", false)

	// The injected target tokens must NOT appear as active (uncommented) YAML.
	lines := strings.Split(got, "\n")
	inCaps := false
	for _, line := range lines {
		if line == "capabilities:" {
			inCaps = true
			continue
		}
		if !inCaps {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, "#") {
			t.Errorf("active (uncommented) line in capabilities block: %q\n\nfull output:\n%s", line, got)
		}
	}

	// Belt and suspenders: no injected capability should be live. The
	// exec_shell/exec_evil/exec_required targets only ever appear inside a
	// comment, so no physical line may begin (after whitespace) with the
	// injected "- target:" payload.
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- target: tool:exec_") {
			t.Errorf("injected capability planted as active YAML: %q", line)
		}
	}
}

// TestYamlScalar_FlowContextAndBlockScalarSafe pins that yamlScalar produces a
// scalar that round-trips byte-for-byte through BOTH flow call sites the scaffold
// uses (`required: [..]` and `{ type: .. }`) for upstream names carrying flow
// delimiters (, [ ] { }) and for a value yaml.v3 renders as a block scalar (a lone
// newline). A benign name must stay unquoted so the scaffold reads cleanly.
func TestYamlScalar_FlowContextAndBlockScalarSafe(t *testing.T) {
	cases := []struct {
		name        string
		wantUnquote bool // benign names should not be escalated to quoted form
	}{
		{"path", true},
		{"simple_tool", true},
		{"a,b", false},
		{"x]y", false},
		{"p{q", false},
		{"x}y", false},
		// Flow mapping indicators yaml.Marshal leaves unquoted in block context but
		// which are structural at the `required: [..]` flow call site.
		{"?x", false},
		{":x", false},
		{"x?", false},
		{"a:b", false},
		{"-x", false},
		{"\n", false},
		{"read: report # prod", false},
		// The YAML merge key: structural only in block-key position (handled by the
		// dedicated test below); must be quoted, so not left bare.
		{"<<", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := yamlScalar(tc.name)

			// Flow sequence round-trip: one element, equal to the original.
			var seq map[string][]string
			if err := yaml.Unmarshal([]byte("required: ["+sc+"]"), &seq); err != nil {
				t.Fatalf("required: [%s] does not parse: %v", sc, err)
			}
			if got := seq["required"]; len(got) != 1 || got[0] != tc.name {
				t.Errorf("required flow round-trip = %q, want exactly [%q]", got, tc.name)
			}

			// Flow mapping round-trip: the `type:` value equals the original.
			var m map[string]map[string]string
			if err := yaml.Unmarshal([]byte("prop: { type: "+sc+" }"), &m); err != nil {
				t.Fatalf("{ type: %s } does not parse: %v", sc, err)
			}
			if got := m["prop"]["type"]; got != tc.name {
				t.Errorf("type flow round-trip = %q, want %q", got, tc.name)
			}

			if tc.wantUnquote && sc != tc.name {
				t.Errorf("benign name %q was needlessly quoted to %q", tc.name, sc)
			}
		})
	}
}

// TestYamlScalar_MergeKeyInBlockKeyPosition is the regression for the YAML merge key
// "<<": it round-trips cleanly as a scalar value and as a flow-sequence element (so the
// value and flow checks pass and yamlScalar previously returned it bare), but placed
// bare as a block-mapping KEY it is the merge key — it drops the "<<" property and
// merges its value map into the parent, yielding an internally inconsistent closed
// schema. yamlScalar must quote it so a property literally named "<<" survives in key
// position.
func TestYamlScalar_MergeKeyInBlockKeyPosition(t *testing.T) {
	sc := yamlScalar("<<")
	if sc == "<<" {
		t.Fatalf("yamlScalar(%q) = %q (bare merge key); must be quoted so it is not structural in key position", "<<", sc)
	}
	// Placed as a block-mapping key, the rendered scalar must decode to a single
	// property literally named "<<", not trigger a merge.
	var m map[string]interface{}
	doc := sc + ": { type: string }\n"
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("%q does not parse: %v", doc, err)
	}
	if _, ok := m["<<"]; !ok || len(m) != 1 {
		t.Errorf("block-key round-trip of %q produced %v, want a single key %q", sc, m, "<<")
	}
}

// TestGenerateInitManifestYAML_FlowDelimiterPropertyName is an end-to-end check
// that a property name containing a flow delimiter does not corrupt the scaffold:
// the uncommented manifest parses and the property is preserved as a single key,
// not split into two `required` entries.
func TestGenerateInitManifestYAML_FlowDelimiterPropertyName(t *testing.T) {
	tools := []drift.UpstreamTool{{
		Name: "tool_a",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"a,b": map[string]interface{}{"type": "string"}},
			"required":   []interface{}{"a,b"},
		},
	}}
	got := generateInitManifestYAML(tools, "test", "", false)
	// Uncomment the scaffold the way an operator would (matching the other
	// round-trip tests), then parse with yaml.v3.
	var b strings.Builder
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "REVIEW") {
			continue
		}
		line = strings.Replace(line, "  # ", "  ", 1)
		line = strings.Replace(line, "  #", "  ", 1)
		b.WriteString(line)
		b.WriteString("\n")
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(b.String()), &doc); err != nil {
		t.Fatalf("uncommented scaffold with a comma property name does not parse: %v\n\n%s", err, b.String())
	}
	// The "a,b" name must survive as a single required entry, not be split into a,b.
	if !strings.Contains(got, `"a,b"`) {
		t.Errorf("property name with a comma should be double-quoted in the scaffold, got:\n%s", got)
	}
}

// TestIsYAMLLineBreak verifies the comment-guard split predicate treats every
// character yaml.v3 honors as a line break (LF, CR, NEL, LS, PS) as a break, and
// ordinary characters as non-breaks.
func TestIsYAMLLineBreak(t *testing.T) {
	for _, r := range []rune{'\n', '\r', '\u0085', '\u2028', '\u2029'} {
		if !isYAMLLineBreak(r) {
			t.Errorf("isYAMLLineBreak(%U) = false, want true", r)
		}
	}
	for _, r := range []rune{'a', ' ', '\t', '-', ':', '#'} {
		if isYAMLLineBreak(r) {
			t.Errorf("isYAMLLineBreak(%U) = true, want false", r)
		}
	}
}

// TestGenerateInitManifestYAML_LineBreakInToolNameStaysCommented verifies that a
// hostile tool name carrying a non-LF YAML line break (CR, NEL, LS, PS) cannot
// break out of the "  # " comment prefix and plant an ACTIVE capability. The
// assertion parses the generated manifest with yaml.v3 (which honors all of these
// as line breaks) and requires the capabilities mapping to stay empty (deny-all).
func TestGenerateInitManifestYAML_LineBreakInToolNameStaysCommented(t *testing.T) {
	breaks := map[string]string{
		"CR":  "\r",
		"NEL": "\u0085",
		"LS":  "\u2028",
		"PS":  "\u2029",
	}
	for name, br := range breaks {
		t.Run(name, func(t *testing.T) {
			tools := []drift.UpstreamTool{{
				Name: "benign" + br + "- target: tool:exec_evil" + br + "  actions: [call]",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"arg" + br + "- target: tool:exec_prop" + br + "  actions: [call]": map[string]interface{}{"type": "string"},
					},
				},
			}}
			out := generateInitManifestYAML(tools, "test", "", false)

			// Parse with yaml.v3 — the very loader the proxy uses — and require the
			// capabilities entry to be empty. A breakout would surface as an active
			// list/map entry under capabilities (or an injected top-level key).
			var doc map[string]interface{}
			if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
				t.Fatalf("generated manifest does not parse: %v\n\n%s", err, out)
			}
			caps, present := doc["capabilities"]
			if !present {
				return // no capabilities key at all is trivially deny-all
			}
			if caps == nil {
				return
			}
			if lst, ok := caps.([]interface{}); ok {
				if len(lst) != 0 {
					t.Errorf("%s break planted an ACTIVE capability: %#v\n\n%s", name, lst, out)
				}
				return
			}
			t.Errorf("capabilities parsed to an unexpected non-empty value %#v\n\n%s", caps, out)
		})
	}
}

// TestGenerateInitManifestYAML_LoadsWhenUncommented round-trips the scaffolded
// manifest through config.LoadManifest after stripping the "  # " comment prefix from
// every entry line — the exact transform an operator performs to enable a tool.
// Regression for a bug where init emitted a "resource:" key instead of
// "target:", which left the target empty and made the loader reject the
// manifest, silently breaking the init → uncomment → `proxy --config`
// quickstart.
func TestGenerateInitManifestYAML_LoadsWhenUncommented(t *testing.T) {
	tools := []drift.UpstreamTool{
		{Name: "read_file"},
		{
			Name: "write_file",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path":    map[string]interface{}{"type": "string"},
					"content": map[string]interface{}{"type": "string"},
				},
				"required": []interface{}{"path", "content"},
			},
		},
	}
	got := generateInitManifestYAML(tools, "init-roundtrip", "", false)

	// Simulate an operator uncommenting every entry: strip the "  # " and "  #"
	// prefixes added by generateInitManifestYAML, and drop the REVIEW guidance
	// line that has no YAML meaning once uncommented.
	var b strings.Builder
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "REVIEW") {
			continue
		}
		line = strings.Replace(line, "  # ", "  ", 1)
		line = strings.Replace(line, "  #", "  ", 1)
		b.WriteString(line)
		b.WriteString("\n")
	}
	uncommented := b.String()

	path := writeManifestFile(t, uncommented)
	m, err := config.LoadManifest(path)
	if err != nil {
		t.Fatalf("init-scaffolded manifest must load after uncommenting; got: %v\n\n--- uncommented YAML ---\n%s", err, uncommented)
	}

	gotTargets := make(map[string]bool, len(m.Capabilities))
	for _, c := range m.Capabilities {
		gotTargets[c.Target] = true
	}
	for _, want := range []string{"tool:read_file", "tool:write_file"} {
		if !gotTargets[want] {
			t.Errorf("loaded manifest missing target %q; got %v", want, gotTargets)
		}
	}
}

// An upstream-controlled tool name, property name, required entry, or type string
// containing YAML-significant characters (colon-space, '#', quotes, keywords) must
// not produce invalid YAML or silently retarget an entry once the operator
// uncomments it. The scaffold quotes every upstream-derived scalar, so the
// uncommented manifest still loads and the entry keeps its intended target.
func TestGenerateInitManifestYAML_HostileNamesLoadWhenUncommented(t *testing.T) {
	tools := []drift.UpstreamTool{
		{
			Name: "read: report # prod",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"header: name": map[string]interface{}{"type": "string"},
					"true":         map[string]interface{}{"type": "string"},
				},
				"required": []interface{}{"header: name"},
			},
		},
	}
	got := generateInitManifestYAML(tools, "init-hostile", "", false)

	var b strings.Builder
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "REVIEW") {
			continue
		}
		line = strings.Replace(line, "  # ", "  ", 1)
		line = strings.Replace(line, "  #", "  ", 1)
		b.WriteString(line)
		b.WriteString("\n")
	}
	uncommented := b.String()

	path := writeManifestFile(t, uncommented)
	m, err := config.LoadManifest(path)
	if err != nil {
		t.Fatalf("init-scaffolded manifest with hostile names must load after uncommenting; got: %v\n\n--- uncommented YAML ---\n%s", err, uncommented)
	}
	found := false
	for _, c := range m.Capabilities {
		if c.Target == "tool:read: report # prod" {
			found = true
		}
	}
	if !found {
		t.Errorf("hostile tool name was lost or retargeted; loaded targets: %v", m.Capabilities)
	}
}

// ─── yamlScalar ──────────────────────────────────────────────────────────────

// TestYamlScalar_RoundTrips is a regression for two bugs. (1) The block-scalar
// body-stripping bug: yaml.v3 renders pathological values (e.g. a tool name that is
// exactly a newline) as a literal block scalar ("|4+\n"), where the value's body
// lives on the lines after the header. yamlScalar's TrimRight stripped that body,
// leaving a bodyless header ("|4+") — a different, malformed value — that the
// multiline guard missed because no newline survived; only the "\n"/"\n\n" cases
// actually drive that path (the "|leading-pipe"/">leading-gt" cases marshal to a
// quoted scalar and take the happy path, so they verify the guard does not
// over-trigger on a legitimate leading indicator). (2) The invalid-UTF-8 fallback
// bug: a long name carrying raw bytes 0x80-0xFF makes yaml line-fold a !!binary
// block, tripping the multiline guard into strconv.Quote, whose \xNN escape YAML
// decodes as code point U+00NN (a different byte sequence). Every case here must
// yaml-decode back to exactly the input string.
func TestYamlScalar_RoundTrips(t *testing.T) {
	cases := []string{
		"\n",                  // single newline -> "|4+" block scalar (drives the fix)
		"\n\n",                // multiple newlines (drives the fix)
		"line1\nline2",        // interior newline
		"trailing\n",          // trailing newline
		"plain",               // ordinary value
		"read: report # prod", // YAML-significant in flow/plain context
		"|leading-pipe",       // legitimate leading indicator -> quoted (happy path)
		">leading-gt",
		"",
		"\x80",                             // single invalid-UTF-8 byte -> single-line !!binary
		strings.Repeat("\x80", 100),        // long invalid-UTF-8 -> line-folded !!binary -> fallback
		strings.Repeat("\xff\x80\xfe", 50), // long invalid-UTF-8, varied bytes
		"prefix-" + strings.Repeat("\x90", 80) + "-suffix", // invalid UTF-8 amid ASCII
	}
	for _, in := range cases {
		got := yamlScalar(in)
		// The emitted scalar must be a single physical line (it is interpolated into
		// one scaffold line) and must decode back to the exact input.
		if strings.ContainsAny(got, "\n\r") {
			t.Errorf("yamlScalar(%q) = %q contains a line break; not a single-line scalar", in, got)
		}
		var decoded string
		if err := yaml.Unmarshal([]byte(got), &decoded); err != nil {
			t.Errorf("yamlScalar(%q) = %q does not parse as YAML: %v", in, got, err)
			continue
		}
		if decoded != in {
			t.Errorf("yamlScalar(%q) = %q decoded to %q, want %q", in, got, decoded, in)
		}
	}
}

// ─── toolEntryYAMLLines ──────────────────────────────────────────────────────

func TestToolEntryYAMLLines_NoSchema(t *testing.T) {
	lines := toolEntryYAMLLines(drift.UpstreamTool{Name: "my_tool"}, false)

	if len(lines) != 2 {
		t.Fatalf("no-schema tool: want 2 lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "- target: tool:my_tool" {
		t.Errorf("line[0]: want '- target: tool:my_tool', got %q", lines[0])
	}
	if lines[1] != "  actions: [call]" {
		t.Errorf("line[1]: want '  actions: [call]', got %q", lines[1])
	}
}

func TestToolEntryYAMLLines_WithSchema(t *testing.T) {
	tool := drift.UpstreamTool{
		Name: "read_file",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{"type": "string"},
			},
			"required": []interface{}{"path"},
		},
	}
	lines := toolEntryYAMLLines(tool, false)
	joined := strings.Join(lines, "\n")

	for _, want := range []string{
		"- target: tool:read_file",
		"  actions: [call]",
		"  argumentSchema:",
		"    type: object",
		"    additionalProperties: false",
		"    properties:",
		"      path: { type: string }",
		"    required: [path]",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("toolEntryYAMLLines: missing %q in:\n%s", want, joined)
		}
	}
}

// ─── argumentSchemaYAML ──────────────────────────────────────────────────────

func TestArgumentSchemaYAML_Nil(t *testing.T) {
	if lines := argumentSchemaYAML(nil); len(lines) != 0 {
		t.Errorf("nil schema: want no lines, got %v", lines)
	}
}

func TestArgumentSchemaYAML_EmptyProperties(t *testing.T) {
	schema := map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
	}
	if lines := argumentSchemaYAML(schema); len(lines) != 0 {
		t.Errorf("empty properties: want no lines, got %v", lines)
	}
}

func TestArgumentSchemaYAML_MultipleProperties_SortedAlphabetically(t *testing.T) {
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"z_param": map[string]interface{}{"type": "string"},
			"a_param": map[string]interface{}{"type": "integer"},
			"m_param": map[string]interface{}{"type": "boolean"},
		},
	}
	lines := argumentSchemaYAML(schema)
	joined := strings.Join(lines, "\n")

	aPos := strings.Index(joined, "a_param")
	mPos := strings.Index(joined, "m_param")
	zPos := strings.Index(joined, "z_param")
	if aPos < 0 || mPos < 0 || zPos < 0 {
		t.Fatal("all properties should appear in output")
	}
	if aPos >= mPos || mPos >= zPos {
		t.Errorf("properties should be sorted alphabetically: a < m < z, got positions a=%d m=%d z=%d", aPos, mPos, zPos)
	}
}

func TestArgumentSchemaYAML_RequiredFields(t *testing.T) {
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"a": map[string]interface{}{"type": "string"},
			"b": map[string]interface{}{"type": "string"},
		},
		"required": []interface{}{"a", "b"},
	}
	lines := argumentSchemaYAML(schema)
	joined := strings.Join(lines, "\n")

	if !strings.Contains(joined, "required: [a, b]") {
		t.Errorf("should contain required: [a, b], got:\n%s", joined)
	}
}

// TestArgumentSchemaYAML_RequiredFiltersAbsentFromProperties confirms a required
// name with no matching property schema is dropped. The scaffold always emits
// additionalProperties:false, so keeping such a name would make the uncommented
// schema unsatisfiable and config.LoadManifest would reject the whole manifest.
func TestArgumentSchemaYAML_RequiredFiltersAbsentFromProperties(t *testing.T) {
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"path": map[string]interface{}{"type": "string"},
		},
		"required": []interface{}{"path", "ghost"}, // ghost is not in properties
	}
	lines := argumentSchemaYAML(schema)
	joined := strings.Join(lines, "\n")

	if !strings.Contains(joined, "required: [path]") {
		t.Errorf("required should be filtered to [path] (ghost dropped), got:\n%s", joined)
	}
	if strings.Contains(joined, "ghost") {
		t.Errorf("ghost must not appear: it is required but absent from properties, making the schema unsatisfiable, got:\n%s", joined)
	}
}

// TestArgumentSchemaYAML_RequiredAllAbsent_OmitsRequiredLine confirms that when
// EVERY required name is absent from properties the scaffold emits no required
// line at all (rather than an empty `required: []`).
func TestArgumentSchemaYAML_RequiredAllAbsent_OmitsRequiredLine(t *testing.T) {
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"path": map[string]interface{}{"type": "string"},
		},
		"required": []interface{}{"ghost"},
	}
	for _, l := range argumentSchemaYAML(schema) {
		if strings.Contains(l, "required") {
			t.Errorf("should emit no required line when all required names are absent from properties: %q", l)
		}
	}
}

// TestGenerateInitManifest_RequiredNotInProperties_LoadsWhenUncommented is the
// quickstart regression: init must emit a manifest that loads after uncommenting,
// even when an upstream tool's required list names a field absent from its
// properties. Without filtering, the uncommented manifest fails config.LoadManifest
// with an "unsatisfiable" error and `proxy --config` refuses to start.
func TestGenerateInitManifest_RequiredNotInProperties_LoadsWhenUncommented(t *testing.T) {
	tools := []drift.UpstreamTool{
		{
			Name: "reader",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{"type": "string"},
				},
				"required": []interface{}{"path", "ghost"},
			},
		},
	}
	got := generateInitManifestYAML(tools, "init-ghost", "", false)

	var b strings.Builder
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "REVIEW") {
			continue
		}
		line = strings.Replace(line, "  # ", "  ", 1)
		line = strings.Replace(line, "  #", "  ", 1)
		b.WriteString(line)
		b.WriteString("\n")
	}
	uncommented := b.String()

	path := writeManifestFile(t, uncommented)
	if _, err := config.LoadManifest(path); err != nil {
		t.Fatalf("scaffolded manifest must load after uncommenting; got: %v\n\n--- uncommented YAML ---\n%s", err, uncommented)
	}
}

func TestArgumentSchemaYAML_NoRequiredField(t *testing.T) {
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"param": map[string]interface{}{"type": "string"},
		},
	}
	lines := argumentSchemaYAML(schema)
	for _, l := range lines {
		if strings.Contains(l, "required") {
			t.Errorf("should not emit required line when schema has no required field: %q", l)
		}
	}
}

func TestArgumentSchemaYAML_UnionType(t *testing.T) {
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"count": map[string]interface{}{"type": []interface{}{"integer", "null"}},
			"name":  map[string]interface{}{"type": []interface{}{"string", "null"}},
		},
	}
	lines := argumentSchemaYAML(schema)
	joined := strings.Join(lines, "\n")

	// A union/array type must keep its real members, not collapse to `string`,
	// otherwise an uncommented entry would deny legitimate calls of the other type.
	if !strings.Contains(joined, `count: { type: [integer, "null"] }`) {
		t.Errorf("union integer type should render as a flow sequence, got:\n%s", joined)
	}
	if !strings.Contains(joined, `name: { type: [string, "null"] }`) {
		t.Errorf("union string type should render as a flow sequence, got:\n%s", joined)
	}
}

// TestArgumentSchemaYAML_UnionType_LoadsAndEnforcesAsDeclared confirms the emitted
// flow sequence round-trips through the manifest loader into a multi-type
// SchemaType (rather than the wrong scalar that would deny valid integer calls
// once an operator uncomments the entry).
func TestArgumentSchemaYAML_UnionType_LoadsAndEnforcesAsDeclared(t *testing.T) {
	tools := []drift.UpstreamTool{
		{
			Name: "tally",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"count": map[string]interface{}{"type": []interface{}{"integer", "null"}},
				},
			},
		},
	}
	got := generateInitManifestYAML(tools, "init-union", "", false)

	// Simulate an operator uncommenting every entry, as in the other round-trip tests.
	var b strings.Builder
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "REVIEW") {
			continue
		}
		line = strings.Replace(line, "  # ", "  ", 1)
		line = strings.Replace(line, "  #", "  ", 1)
		b.WriteString(line)
		b.WriteString("\n")
	}
	uncommented := b.String()

	path := writeManifestFile(t, uncommented)
	m, err := config.LoadManifest(path)
	if err != nil {
		t.Fatalf("union-typed scaffolded manifest must load after uncommenting; got: %v\n\n--- uncommented YAML ---\n%s", err, uncommented)
	}
	if len(m.Capabilities) != 1 || m.Capabilities[0].ArgumentSchema == nil {
		t.Fatalf("expected one capability with an argumentSchema, got %+v", m.Capabilities)
	}
	gotType := m.Capabilities[0].ArgumentSchema.Properties["count"].Type
	want := capability.SchemaType{Multiple: []string{"integer", "null"}}
	if gotType.Single != want.Single || strings.Join(gotType.Multiple, ",") != strings.Join(want.Multiple, ",") {
		t.Errorf("count type = %+v, want %+v (must preserve the union, not collapse to a scalar)", gotType, want)
	}
}

// ─── server version in generated YAML ────────────────────────────────────────

func TestGenerateInitManifestYAML_ServerVersionComment(t *testing.T) {
	got := generateInitManifestYAML(nil, "test", "1.2.3", false)

	// Should include a commented-out serverVersion line with the exact version.
	// yamlScalar emits "1.2.3" as a bare (unquoted) scalar since it is an unambiguous
	// YAML string that round-trips without quoting.
	if !strings.Contains(got, `# serverVersion: 1.2.3`) {
		t.Errorf("should include commented serverVersion with exact version, got:\n%s", got)
	}
	// Should also suggest the patch-wildcard form as an "allow updates" hint, since a
	// looser-but-still-matching pin exists for a 3-component version.
	if !strings.Contains(got, `use 1.2.* to allow updates`) {
		t.Errorf("should suggest patch wildcard 1.2.* to allow updates, got:\n%s", got)
	}
}

// TestGenerateInitManifestYAML_ServerVersionComment_BareMajor locks the else branch
// of the serverVersion emission: a single-component version has no looser form the
// drift matcher accepts, so serverVersionWildcard returns it unchanged and the
// comment must offer only the exact pin — no "allow updates" hint and no wildcard
// suggestion (which, being "*", would match any upstream and defeat the pin, or
// abort startup under --strict-drift once an operator pasted it).
func TestGenerateInitManifestYAML_ServerVersionComment_BareMajor(t *testing.T) {
	got := generateInitManifestYAML(nil, "test", "2", false)

	if !strings.Contains(got, `# serverVersion: "2"  # uncomment to pin`) {
		t.Errorf("bare-major version should emit an exact-pin-only comment, got:\n%s", got)
	}
	if strings.Contains(got, "allow updates") {
		t.Errorf("bare-major version has no looser form; must not offer an allow-updates hint, got:\n%s", got)
	}
	if strings.Contains(got, `"*"`) {
		t.Errorf("bare-major version must not suggest a wildcard pin, got:\n%s", got)
	}
}

func TestGenerateInitManifestYAML_NoServerVersion(t *testing.T) {
	got := generateInitManifestYAML(nil, "test", "", false)

	if strings.Contains(got, "serverVersion") {
		t.Errorf("should not emit serverVersion when none provided, got:\n%s", got)
	}
}

// TestGenerateInitManifestYAML_ServerVersionRoundTrips locks that the
// upstream-controlled serverVersion pin round-trips through the YAML loader once the
// operator uncomments it — including a version carrying a raw byte in 0x80-0xFF. The
// value flows unsanitized from the upstream initialize result; a raw %q escape would
// decode to a different string (Go's \xNN is a byte, YAML's \xNN is U+00NN), so an
// uncommented pin would no longer match the live server and raise a self-inflicted
// FM-4 strict-drift abort against the unchanged upstream it was generated from.
func TestGenerateInitManifestYAML_ServerVersionRoundTrips(t *testing.T) {
	for _, version := range []string{"1.2.3", "2", `1.0-"weird"`, "1.0-\xff", "v\x80\x81"} {
		got := generateInitManifestYAML(nil, "test", version, false)

		// Recover the operator's uncommented line: strip only the leading "# " that
		// generateInitManifestYAML adds; the trailing "  # uncomment to pin..." is a
		// YAML comment the loader ignores once the line is active.
		var line string
		for _, l := range strings.Split(got, "\n") {
			if strings.HasPrefix(l, "# serverVersion:") {
				line = strings.TrimPrefix(l, "# ")
				break
			}
		}
		if line == "" {
			t.Fatalf("version %q: no serverVersion line emitted, got:\n%s", version, got)
		}

		var doc struct {
			ServerVersion string `yaml:"serverVersion"`
		}
		if err := yaml.Unmarshal([]byte(line), &doc); err != nil {
			t.Errorf("version %q: uncommented line %q does not parse as YAML: %v", version, line, err)
			continue
		}
		if doc.ServerVersion != version {
			t.Errorf("version %q: round-trip mismatch, decoded %q from line %q", version, doc.ServerVersion, line)
		}
	}
}

// ─── serverVersionWildcard ────────────────────────────────────────────────────

func TestServerVersionWildcard(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"1.2.3", "1.2.*"},
		// "1.2" has no patch component, so "1.2.*" (which the drift matcher requires
		// to have a 3rd component) would not match the version it came from; wildcard
		// the minor instead.
		{"1.2", "1.*"},
		// A bare major has nothing looser the matcher accepts; suggest the exact pin.
		{"1", "1"},
		// cmdInit guards on serverVersion != "", so "" never reaches this function in
		// production; the pure-function contract is empty-in -> empty-out (no bogus "*").
		{"", ""},
		{"1.2.3.4", "1.2.*"}, // only first two parts used
	}
	for _, tc := range cases {
		got := serverVersionWildcard(tc.in)
		if got != tc.want {
			t.Errorf("serverVersionWildcard(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestServerVersionWildcard_RoundTripMatchesDrift locks down the cross-package
// invariant that init's own suggestion never raises spurious FM-4 drift against
// the unchanged upstream it was derived from. It composes serverVersionWildcard
// (cmd/eunox) with the runtime matcher through the public drift API — the two
// functions live in different packages and were previously only tested in
// isolation, so the suggestion-vs-matcher contradiction went unnoticed.
func TestServerVersionWildcard_RoundTripMatchesDrift(t *testing.T) {
	for _, v := range []string{"2", "1.2", "1.0", "1.2.3", "1.2.3.4", "2024"} {
		wildcard := serverVersionWildcard(v)
		manifest := &config.LocalManifest{ServerVersion: wildcard}
		warnings := drift.CheckManifestDrift(manifest, nil, v)
		for i := range warnings {
			w := warnings[i]
			if w.Kind == drift.Fm4 {
				t.Errorf("serverVersionWildcard(%q)=%q raised spurious FM-4 against unchanged version %q (actual=%q)",
					v, wildcard, v, w.VersionActual)
			}
		}
	}
}

// ─── sortedKeys ──────────────────────────────────────────────────────────────

// ─── buildInitUpstreamSpec ────────────────────────────────────────────────────

func TestBuildInitUpstreamSpec(t *testing.T) {
	cases := []struct {
		name          string
		transport     string
		upstreamURL   string
		authHeader    string
		tlsSkipVerify bool
		positional    []string
		wantErr       string // substring; empty = expect success
		want          initUpstreamSpec
	}{
		{
			name:        "http happy path",
			transport:   "http",
			upstreamURL: "https://mcp.example.com",
			authHeader:  "Authorization: Bearer x",
			want: initUpstreamSpec{
				Transport: "http", URL: "https://mcp.example.com", AuthHeader: "Authorization: Bearer x",
			},
		},
		{
			name:          "http preserves tls skip verify",
			transport:     "http",
			upstreamURL:   "https://self-signed.example.com",
			tlsSkipVerify: true,
			want: initUpstreamSpec{
				Transport: "http", URL: "https://self-signed.example.com", TLSSkipVerify: true,
			},
		},
		{
			name:      "http missing url",
			transport: "http",
			wantErr:   "--upstream-url is required",
		},
		{
			name:        "http rejects positional",
			transport:   "http",
			upstreamURL: "https://mcp.example.com",
			positional:  []string{"npx", "-y"},
			wantErr:     "positional args are not allowed",
		},
		{
			name:       "stdio happy path",
			transport:  "stdio",
			positional: []string{"npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"},
			want: initUpstreamSpec{
				Transport: "stdio",
				Command:   "npx",
				Args:      []string{"-y", "@modelcontextprotocol/server-filesystem", "/data"},
			},
		},
		{
			name:      "stdio missing command",
			transport: "stdio",
			wantErr:   `requires a subprocess command after "--"`,
		},
		{
			name:        "stdio rejects upstream-url",
			transport:   "stdio",
			upstreamURL: "https://mcp.example.com",
			positional:  []string{"npx"},
			wantErr:     "--upstream-url is not allowed with --transport stdio",
		},
		{
			name:       "stdio rejects auth header",
			transport:  "stdio",
			authHeader: "Authorization: Bearer x",
			positional: []string{"npx"},
			wantErr:    "--upstream-auth-header is not allowed with --transport stdio",
		},
		{
			name:          "stdio rejects tls flag",
			transport:     "stdio",
			tlsSkipVerify: true,
			positional:    []string{"npx"},
			wantErr:       "--upstream-tls-skip-verify is not allowed with --transport stdio",
		},
		{
			name:      "unknown transport rejected",
			transport: "grpc",
			wantErr:   "--transport must be",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildInitUpstreamSpec(tc.transport, tc.upstreamURL, tc.authHeader, tc.tlsSkipVerify, tc.positional, "")
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got nil (spec=%+v)", tc.wantErr, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error mismatch: want substring %q, got %q", tc.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Transport != tc.want.Transport ||
				got.URL != tc.want.URL ||
				got.AuthHeader != tc.want.AuthHeader ||
				got.TLSSkipVerify != tc.want.TLSSkipVerify ||
				got.Command != tc.want.Command ||
				!equalStrSlice(got.Args, tc.want.Args) {
				t.Errorf("spec mismatch:\n got  %+v\n want %+v", got, tc.want)
			}
		})
	}
}

func equalStrSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestSortedKeys(t *testing.T) {
	m := map[string]interface{}{"z": 1, "a": 2, "m": 3}
	got := sortedKeys(m)
	want := []string{"a", "m", "z"}
	if len(got) != len(want) {
		t.Fatalf("sortedKeys: want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sortedKeys[%d]: want %q, got %q", i, want[i], got[i])
		}
	}
}

// ===== merged from drift_test.go =====

func TestGenerateInitManifestYAML_PinDescriptions(t *testing.T) {
	desc := "Reads a file from the filesystem."
	tools := []drift.UpstreamTool{{Name: "read_file", Description: desc}}
	expectedHash := capability.ComputeToolHash(desc, nil)

	out := generateInitManifestYAML(tools, "test", "", true)

	if !strings.Contains(out, expectedHash) {
		t.Errorf("pin-descriptions: expected hash %q not found in:\n%s", expectedHash, out)
	}
	if !strings.Contains(out, "descriptionHash") {
		t.Errorf("pin-descriptions: missing descriptionHash key in:\n%s", out)
	}
}

func TestGenerateInitManifestYAML_NoPinDescriptions(t *testing.T) {
	tools := []drift.UpstreamTool{{Name: "read_file", Description: "Some description."}}
	out := generateInitManifestYAML(tools, "test", "", false)

	if strings.Contains(out, "descriptionHash") {
		t.Errorf("no pin-descriptions: must not emit descriptionHash, got:\n%s", out)
	}
}

func TestGenerateInitManifestYAML_PinDescriptions_EmptyDescription(t *testing.T) {

	tools := []drift.UpstreamTool{{Name: "read_file"}}
	out := generateInitManifestYAML(tools, "test", "", true)

	// --pin-descriptions must pin EVERY tool, including one whose live description
	// is the empty string: the hash of "" is a valid, verifiable pin, and skipping
	// it leaves a tool-poisoning detection gap (an empty description silently
	// changing into a prompt-injecting one would never be caught at startup).
	emptyHash := capability.ComputeToolHash("", nil)
	if !strings.Contains(out, "descriptionHash") {
		t.Errorf("empty description + pin-descriptions: must emit descriptionHash, got:\n%s", out)
	}
	if !strings.Contains(out, emptyHash) {
		t.Errorf("empty description + pin-descriptions: must pin the hash of %q (%s), got:\n%s", "", emptyHash, out)
	}
}

func TestToolEntryYAMLLines_PinDescriptions(t *testing.T) {
	desc := "Executes a database query."
	tool := drift.UpstreamTool{Name: "query_db", Description: desc}
	lines := toolEntryYAMLLines(tool, true)
	joined := strings.Join(lines, "\n")

	expectedHash := capability.ComputeToolHash(desc, nil)
	if !strings.Contains(joined, expectedHash) {
		t.Errorf("pin-descriptions: hash %q not in lines:\n%s", expectedHash, joined)
	}
	if !strings.Contains(joined, "descriptionHash") {
		t.Errorf("pin-descriptions: missing descriptionHash in lines:\n%s", joined)
	}
}

func TestGenerateInitManifestYAML_PinDescriptions_RoundTrip(t *testing.T) {

	desc := "Reads a file from the filesystem."
	tools := []drift.UpstreamTool{{Name: "read_file", Description: desc}}
	expectedHash := capability.ComputeToolHash(desc, nil)

	raw := generateInitManifestYAML(tools, "pin-roundtrip", "", true)

	// Uncomment all capability lines (same transform as the operator performs).
	var b strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		if strings.Contains(line, "REVIEW") {
			continue
		}
		line = strings.Replace(line, "  # ", "  ", 1)
		line = strings.Replace(line, "  #", "  ", 1)
		b.WriteString(line + "\n")
	}
	uncommented := b.String()

	path := writeManifestFile(t, uncommented)
	m, err := config.LoadManifest(path)
	if err != nil {
		t.Fatalf("pinned manifest round-trip load failed: %v\n\nYAML:\n%s", err, uncommented)
	}
	if len(m.Capabilities) == 0 {
		t.Fatal("expected at least one capability after round-trip")
	}
	if got := m.Capabilities[0].DescriptionHash; got != expectedHash {
		t.Errorf("DescriptionHash round-trip: want %q, got %q", expectedHash, got)
	}
}
