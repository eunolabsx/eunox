// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// auditLine builds one audit-log JSON line carrying the structured target fields
// the proxy writes (target_type/target/method), for the suggest tests. ns is the
// enforcement namespace ("tool"|"resource"|"prompt"|"system") and target is the
// bare target name; any extra fields (session_id, details, denial_code) are
// merged in.
func auditLine(decision, ns, target string, extra map[string]any) string {
	method := map[string]string{
		"tool":     "tools/call",
		"resource": "resources/read",
		"prompt":   "prompts/get",
		"system":   "sampling/createMessage",
	}[ns]
	m := map[string]any{
		"decision":    decision,
		"target_type": ns,
		"target":      target,
		"method":      method,
	}
	for k, v := range extra {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// ─── resolveTarget (structured target fields) ────────────────────────────────

func TestResolveTarget(t *testing.T) {
	cases := []struct {
		name               string
		targetType, target string
		wantNS, wantBare   string
	}{
		// Structured fields are taken at face value — including opaque or
		// oddly-named targets that no string heuristic could place correctly.
		{"opaque resource URI", "resource", "memory:notes", "resource", "memory:notes"},
		{"tool name with ://", "tool", "weird://connector", "tool", "weird://connector"},
		{"tool name with prompts/ prefix", "tool", "prompts/run", "tool", "prompts/run"},
		{"prompt bare name", "prompt", "code_review", "prompt", "code_review"},
		{"system", "system", "sampling/createMessage", "system", "sampling/createMessage"},
		// An unrecognized target_type or an absent target yields no target.
		{"unknown target_type", "bogus", "x", "", ""},
		{"empty target", "resource", "", "", ""},
		{"no target at all", "", "", "", ""},
	}
	for _, tc := range cases {
		gotNS, gotBare := resolveTarget(tc.targetType, tc.target)
		if gotNS != tc.wantNS || gotBare != tc.wantBare {
			t.Errorf("%s: resolveTarget(%q, %q) = (%q, %q); want (%q, %q)",
				tc.name, tc.targetType, tc.target, gotNS, gotBare, tc.wantNS, tc.wantBare)
		}
	}
}

// TestComputeSuggestions_ClassifiesFromStructuredTargetFields verifies that
// targets are classified from the authoritative target_type/target fields,
// including opaque resource URIs and odd-but-valid tool names (a "://"-bearing
// tool name, or one prefixed "prompts/") that no string heuristic could place
// correctly.
func TestComputeSuggestions_ClassifiesFromStructuredTargetFields(t *testing.T) {
	log := strings.Join([]string{
		auditLine("allow", "resource", "urn:isbn:0451450523", nil),
		auditLine("allow", "resource", "mailto:ops@example.com", nil),
		auditLine("allow", "resource", "memory:session", nil),
		auditLine("allow", "tool", "weird://connector", nil),
		auditLine("allow", "tool", "prompts/run", nil),
		auditLine("allow", "prompt", "code_review", nil),
	}, "\n")

	s, err := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	if err != nil {
		t.Fatalf("computeSuggestions: %v", err)
	}

	// Each target must land in its true namespace, taken from target_type.
	for _, key := range []string{
		"resource:urn:isbn:0451450523",
		"resource:mailto:ops@example.com",
		"resource:memory:session",
		"tool:weird://connector",
		"tool:prompts/run",
		"prompt:code_review",
	} {
		if s.targets[key] == nil {
			t.Errorf("missing expected target %q (have %d targets)", key, len(s.targets))
		}
	}
}

// TestComputeSuggestions_UnmappedMethodDenialExcluded verifies that audit
// records written for novel/unmapped MCP method denials (e.g. "tools/execute")
// are not proposed as manifest entries by the suggest subcommand. These records
// carry a method but no structured target, so they have no namespace to suggest.
func TestComputeSuggestions_UnmappedMethodDenialExcluded(t *testing.T) {
	// Records produced by the unmapped-method default branch: method is set but
	// target_type/target are empty (no valid enforcement target exists).
	log := strings.Join([]string{
		`{"decision":"deny","method":"tools/execute","denial_code":"AUTHORIZATION_FAILED"}`,
		`{"decision":"deny","method":"resources/patch","denial_code":"AUTHORIZATION_FAILED"}`,
		// A genuine policy deny on a real tool must still appear.
		auditLine("deny", "tool", "write_file", map[string]any{"denial_code": "AUTHORIZATION_FAILED"}),
	}, "\n")

	s, err := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	if err != nil {
		t.Fatalf("computeSuggestions: %v", err)
	}

	for _, bad := range []string{"tool:tools/execute", "tool:resources/patch"} {
		if s.targets[bad] != nil {
			t.Errorf("bogus target %q present; unmapped-method denial should have been excluded", bad)
		}
	}
	if s.targets["tool:write_file"] == nil {
		t.Error("genuine tool:write_file deny should still appear in suggestions")
	}
}

func TestComputeSuggestions_InfraDenialExcluded(t *testing.T) {
	// Upstream-failure records carry a known target namespace (a tools/list
	// timeout reads as target_type "tool", a prompts/list timeout as "prompt")
	// but are transport noise, not policy signals. They must not surface as
	// draft targets.
	log := strings.Join([]string{
		`{"decision":"deny","target_type":"tool","target":"tools/list","method":"tools/list","denial_code":"UPSTREAM_TIMEOUT"}`,
		`{"decision":"deny","target_type":"prompt","target":"list","method":"prompts/list","denial_code":"UPSTREAM_TIMEOUT"}`,
		`{"decision":"deny","target_type":"tool","target":"read_file","method":"tools/call","denial_code":"UPSTREAM_ERROR"}`,
		// A genuine policy deny on the same tool must still appear.
		`{"decision":"deny","target_type":"tool","target":"read_file","method":"tools/call","denial_code":"AUTHORIZATION_FAILED"}`,
	}, "\n")

	s, err := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	if err != nil {
		t.Fatalf("computeSuggestions: %v", err)
	}

	if s.targets["prompt:list"] != nil {
		t.Error("prompts/list timeout misparsed as a prompt named \"list\"; infra denial should be excluded")
	}
	if s.targets["tool:tools/list"] != nil {
		t.Error("tools/list timeout surfaced as a phantom tool; infra denial should be excluded")
	}
	rf := s.targets["tool:read_file"]
	if rf == nil {
		t.Fatal("genuine policy deny on read_file should still appear")
	}
	// Only the AUTHORIZATION_FAILED record counts; the UPSTREAM_ERROR one is skipped.
	if rf.deny != 1 {
		t.Errorf("read_file deny count = %d, want 1 (infra UPSTREAM_ERROR record must not be counted)", rf.deny)
	}
}

// TestComputeSuggestions_ListEnumerationExcluded verifies that */list
// enumeration records — recorded as allows with the method name
// as their target — never become phantom capability targets. List access is
// governed by automatic list filtering, not by a per-target manifest entry, so
// a "tool:tools/list" entry would be meaningless (and was being emitted before
// this fix).
func TestComputeSuggestions_ListEnumerationExcluded(t *testing.T) {
	log := strings.Join([]string{
		`{"decision":"allow","target_type":"tool","target":"tools/list","method":"tools/list"}`,
		`{"decision":"allow","target_type":"resource","target":"resources/list","method":"resources/list"}`,
		`{"decision":"allow","target_type":"prompt","target":"prompts/list","method":"prompts/list"}`,
		// A genuine tools/call on the same session must still appear.
		auditLine("allow", "tool", "read_file", nil),
	}, "\n")

	s, err := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	if err != nil {
		t.Fatalf("computeSuggestions: %v", err)
	}

	for _, phantom := range []string{"tool:tools/list", "resource:resources/list", "prompt:prompts/list"} {
		if s.targets[phantom] != nil {
			t.Errorf("%q surfaced as a draft target; */list enumeration records must be excluded", phantom)
		}
	}
	if s.targets["tool:read_file"] == nil {
		t.Fatal("a genuine tools/call must still appear in the draft")
	}
	// The three list records must not inflate the observation counts.
	if s.records != 1 {
		t.Errorf("records = %d, want 1 (only the read_file call counts; */list records are skipped)", s.records)
	}
}

// ─── computeSuggestions ─────────────────────────────────────────────────────

func TestComputeSuggestions_AggregatesAndMinesArgs(t *testing.T) {
	log := strings.Join([]string{
		auditLine("allow", "tool", "read_file", map[string]any{"session_id": "s1", "details": map[string]any{"path": "/reports/q3.pdf"}}),
		auditLine("allow", "tool", "read_file", map[string]any{"session_id": "s1", "details": map[string]any{"path": "/reports/q4.pdf"}}),
		auditLine("allow", "tool", "read_file", map[string]any{"session_id": "s2", "details": map[string]any{"path": "/reports/q3.pdf"}}), // duplicate value
		auditLine("allow", "tool", "query_db", map[string]any{"session_id": "s2", "details": map[string]any{"sql": "SELECT 1", "limit": 10}}),
		auditLine("deny", "tool", "write_file", map[string]any{"session_id": "s1", "denial_code": "AUTHORIZATION_FAILED"}),
		"", // blank
		"not json",
	}, "\n")

	s, err := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	if err != nil {
		t.Fatalf("computeSuggestions: %v", err)
	}

	if s.records != 5 {
		t.Errorf("records = %d; want 5 (blank and malformed skipped)", s.records)
	}
	if s.allow != 4 || s.deny != 1 {
		t.Errorf("allow/deny = %d/%d; want 4/1", s.allow, s.deny)
	}
	if len(s.sessions) != 2 {
		t.Errorf("sessions = %d; want 2", len(s.sessions))
	}

	rf := s.targets["tool:read_file"]
	if rf == nil || rf.allow != 3 {
		t.Fatalf("read_file: %+v; want allow=3", rf)
	}
	if got := len(rf.args["path"].values); got != 2 {
		t.Errorf("read_file path distinct values = %d; want 2 (dedup)", got)
	}

	qdb := s.targets["tool:query_db"]
	if qdb == nil {
		t.Fatal("query_db target missing")
	}
	if !qdb.args["limit"].nonString {
		t.Error("query_db limit should be flagged nonString (numeric value)")
	}
	if len(qdb.args["sql"].values) != 1 {
		t.Errorf("query_db sql values = %d; want 1", len(qdb.args["sql"].values))
	}

	wf := s.targets["tool:write_file"]
	if wf == nil || wf.allow != 0 || wf.deny != 1 {
		t.Errorf("write_file: %+v; want allow=0 deny=1", wf)
	}
}

// TestComputeSuggestions_TypeDriftedDetailsStillCountsRecord pins the fix for a
// type-drifted `details` field (a scalar/array instead of the producer's usual
// object) no longer discarding the WHOLE record via the outer json.Unmarshal
// error. Before the fix, decoding `details` straight into a struct field typed
// map[string]interface{} made a non-object details value fail the outer decode,
// so the "continue" skip dropped an otherwise-parseable target/decision — the
// opposite of computeSuggestions' documented "a schema-drifted tape still
// yields a draft" contract.
func TestComputeSuggestions_TypeDriftedDetailsStillCountsRecord(t *testing.T) {
	log := auditLine("allow", "tool", "foo", map[string]any{"details": "redacted"}) + "\n" + // string, not object
		auditLine("allow", "tool", "bar", map[string]any{"details": []string{"x", "y"}}) // array, not object

	s, err := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	if err != nil {
		t.Fatalf("computeSuggestions: %v", err)
	}
	if s.records != 2 || s.allow != 2 {
		t.Fatalf("records/allow = %d/%d; want 2/2 (type-drifted details must not drop the record)", s.records, s.allow)
	}
	foo := s.targets["tool:foo"]
	if foo == nil || foo.allow != 1 {
		t.Errorf("foo: %+v; want allow=1", foo)
	}
	if len(foo.args) != 0 {
		t.Errorf("foo: non-object details should mine no arguments; got %+v", foo.args)
	}
	bar := s.targets["tool:bar"]
	if bar == nil || bar.allow != 1 {
		t.Errorf("bar: %+v; want allow=1", bar)
	}
}

func TestComputeSuggestions_DenyRecordsDoNotMineArgs(t *testing.T) {
	// A deny record's details carry denial metadata, not caller arguments, so
	// they must not contaminate the suggested allowedValues.
	log := auditLine("deny", "tool", "query_db", map[string]any{"details": map[string]any{"operation": "DROP", "allowedOperations": []string{"SELECT"}}})
	s, err := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	if err != nil {
		t.Fatalf("computeSuggestions: %v", err)
	}
	tgt := s.targets["tool:query_db"]
	if tgt == nil {
		t.Fatal("query_db missing")
	}
	if len(tgt.args) != 0 {
		t.Errorf("deny record mined %d args; want 0", len(tgt.args))
	}
}

// ─── renderSuggestedManifest ─────────────────────────────────────────────────

// TestRenderSuggestedManifest_RoundTripsThroughValidate is the load-bearing
// correctness test: whatever suggest emits must pass the same validation the
// proxy runs at load. A draft that `eunox validate` rejects would be a
// broken first-touch experience.
func TestRenderSuggestedManifest_RoundTripsThroughValidate(t *testing.T) {
	log := strings.Join([]string{
		auditLine("allow", "tool", "read_file", map[string]any{"session_id": "s1", "details": map[string]any{"path": "/reports/q3.pdf"}}),
		auditLine("allow", "tool", "query_db", map[string]any{"session_id": "s1", "details": map[string]any{"sql": "SELECT 1"}}),
		auditLine("allow", "prompt", "code_review", map[string]any{"session_id": "s1", "details": map[string]any{"name": "code_review"}}),
		auditLine("allow", "resource", "db://warehouse/orders", map[string]any{"session_id": "s1", "details": map[string]any{"uri": "db://warehouse/orders"}}),
		auditLine("allow", "system", "sampling/createMessage", map[string]any{"session_id": "s1"}),
		auditLine("deny", "tool", "write_file", map[string]any{"session_id": "s1", "denial_code": "AUTHORIZATION_FAILED"}),
	}, "\n")

	s, err := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	if err != nil {
		t.Fatalf("computeSuggestions: %v", err)
	}
	manifest := renderSuggestedManifest(s, "round-trip", suggestMaxValuesDefault)

	path := filepath.Join(t.TempDir(), "suggested.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	m, err := config.LoadManifest(path)
	if err != nil {
		t.Fatalf("generated manifest failed validation:\n%s\nerror: %v", manifest, err)
	}
	// 4 active entries: read_file, query_db (tool), code_review (prompt),
	// orders (resource). sampling and write_file are commented out.
	if len(m.Capabilities) != 4 {
		t.Errorf("capabilities = %d; want 4 (sampling + deny-only excluded)", len(m.Capabilities))
	}
}

// TestRenderSuggestedManifest_NonUTF8NameRoundTrips locks the fix that renders the
// top-level name through yamlScalar instead of %q. A non-UTF-8 --name passed to
// suggest would otherwise be mis-decoded by yaml.v3 (Go \xNN raw byte vs YAML \xNN
// code point); yamlScalar emits a !!binary scalar that round-trips any bytes.
func TestRenderSuggestedManifest_NonUTF8NameRoundTrips(t *testing.T) {
	cases := map[string]string{
		"raw-bytes-80-81": "\x80\x81",
		"latin1-eacute":   "caf\xe9",
	}
	for label, name := range cases {
		t.Run(label, func(t *testing.T) {
			log := auditLine("allow", "tool", "read_file", nil)
			s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
			out := renderSuggestedManifest(s, name, suggestMaxValuesDefault)
			var doc struct {
				Name string `yaml:"name"`
			}
			if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
				t.Fatalf("generated manifest does not parse: %v\nyaml:\n%s", err, out)
			}
			if doc.Name != name {
				t.Errorf("name did not round-trip: got %x, want %x\nyaml:\n%s", doc.Name, name, out)
			}
		})
	}
}

func TestRenderSuggestedManifest_StringArgBecomesAllowedValues(t *testing.T) {
	log := auditLine("allow", "tool", "read_file", map[string]any{"details": map[string]any{"path": "/reports/q3.pdf"}}) + "\n" +
		auditLine("allow", "tool", "read_file", map[string]any{"details": map[string]any{"path": "/reports/q4.pdf"}})
	s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	for _, want := range []string{
		`- target: "tool:read_file"`, // target token is emitted as a quoted scalar
		"- type: allowedValues",
		`argument: "path"`, // argument name is emitted as a quoted scalar
		`"/reports/q3.pdf"`,
		`"/reports/q4.pdf"`,
		`["/reports/*"]`, // glob generalization hint
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n---\n%s", want, out)
		}
	}
}

// TestRenderSuggestedManifest_EmptyArgumentNameNotConstrained pins that an
// observed argument with an EMPTY name ({"": "x"}, legal JSON) does not become an
// allowedValues with an empty `argument` — which both the loader and the engine
// reject, yielding an unloadable draft that denies the observed-allowed call. The
// draft must instead carry a review note, still load through validate, and still
// allow the observed call.
func TestRenderSuggestedManifest_EmptyArgumentNameNotConstrained(t *testing.T) {
	log := auditLine("allow", "tool", "read_file", map[string]any{"details": map[string]any{"": "report.pdf"}})
	s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	if strings.Contains(out, "allowedValues") {
		t.Errorf("draft must not emit an allowedValues condition for an empty argument name:\n%s", out)
	}
	if strings.Contains(out, `argument: ""`) {
		t.Errorf("draft must not emit an empty argument field:\n%s", out)
	}
	if !strings.Contains(out, "empty argument name") {
		t.Errorf("draft missing empty-argument review note:\n%s", out)
	}
	// The draft must load through validate and still allow the observed call.
	assertManifestAllows(t, out, "read_file", map[string]any{"": "report.pdf"})
}

// TestRenderSuggestedManifest_TruncationMarkerNotMined pins the case where an
// allowed call's arguments exceeded the audit detail cap, the audit layer
// replaced the whole map with the audit.TruncatedKey marker. suggest must NOT
// treat that marker as a real tool argument — an allowedValues condition on the
// phantom "_eunox_truncated" argument would deny every call to the tool. The
// draft instead carries a review note and still allows the observed call.
func TestRenderSuggestedManifest_TruncationMarkerNotMined(t *testing.T) {
	log := auditLine("allow", "tool", "bulk_export", map[string]any{
		"details": map[string]any{audit.TruncatedKey: "details omitted: 2000000-byte map exceeds the 1048576-byte audit record detail cap"},
	})
	s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	if strings.Contains(out, audit.TruncatedKey) {
		t.Errorf("draft must not mention the truncation marker %q as an argument:\n%s", audit.TruncatedKey, out)
	}
	if strings.Contains(out, "allowedValues") {
		t.Errorf("draft must not emit an allowedValues condition for a truncated-only record:\n%s", out)
	}
	if !strings.Contains(out, "truncated in the audit log") {
		t.Errorf("draft missing truncation review note:\n%s", out)
	}
	// The draft must still allow the observed call — no phantom mandatory argument.
	assertManifestAllows(t, out, "bulk_export", map[string]any{"anything": "x"})
}

// TestRenderSuggestedManifest_TruncationAlongsideRealArg pins the mixed
// case: a tool seen with both a normal minable argument and a separate truncated
// call still constrains the real argument and warns about the truncation.
func TestRenderSuggestedManifest_TruncationAlongsideRealArg(t *testing.T) {
	log := auditLine("allow", "tool", "read_file", map[string]any{"details": map[string]any{"path": "/reports/q3.pdf"}}) + "\n" +
		auditLine("allow", "tool", "read_file", map[string]any{"details": map[string]any{audit.TruncatedKey: "details omitted: huge"}})
	s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	if strings.Contains(out, audit.TruncatedKey) {
		t.Errorf("draft must not mention the truncation marker as an argument:\n%s", out)
	}
	if !strings.Contains(out, "truncated in the audit log") {
		t.Errorf("draft missing truncation review note:\n%s", out)
	}
	// Core safety invariant: a whole-map-truncated call may have carried "path"
	// with a value now hidden from the tape, so an enumerated allowedValues built
	// from only the visible "/reports/q3.pdf" would DENY that observed-allowed call.
	// The draft must therefore emit no allowedValues and admit a different path.
	if strings.Contains(out, "allowedValues") {
		t.Errorf("draft must not emit an allowedValues condition when another call to the tool was whole-map truncated:\n%s", out)
	}
	assertManifestAllows(t, out, "read_file", map[string]any{"path": "/etc/secret"})
}

// assertManifestAllows loads the rendered draft and asserts the enforcement
// engine ALLOWS the given tool call against it. It is the load-bearing check for
// the two "suggest must not reject what it observed" regressions: a draft that
// denies a call the tape recorded as allowed is broken, however valid its YAML.
func assertManifestAllows(t *testing.T, manifestYAML, tool string, args map[string]any) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "draft.yaml")
	if err := os.WriteFile(path, []byte(manifestYAML), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	m, err := config.LoadManifest(path)
	if err != nil {
		t.Fatalf("generated manifest failed to load:\n%s\nerror: %v", manifestYAML, err)
	}
	resp := enforcement.New().ValidateAction(context.Background(),
		&capability.EnforceRequest{SessionID: "s1", ToolName: tool, Arguments: args},
		m.Capabilities)
	if resp.Decision != capability.DecisionAllow {
		code := ""
		if resp.Denial != nil {
			code = resp.Denial.Code
		}
		t.Errorf("generated manifest DENIED an observed-allowed call %s(%v) [%s]; a draft must never reject a call the tape showed as allowed\n%s",
			tool, args, code, manifestYAML)
	}
}

// allowedValuesArg returns the argument named by the first allowedValues
// condition on the tool:<tool> capability of m, or "" if none is present.
func allowedValuesArg(m *config.LocalManifest, tool string) string {
	for i := range m.Capabilities {
		c := &m.Capabilities[i]
		if c.Target != "tool:"+tool {
			continue
		}
		for _, cond := range c.Conditions {
			switch v := cond.(type) {
			case *capability.AllowedValuesCondition:
				return v.Argument
			case capability.AllowedValuesCondition:
				return v.Argument
			}
		}
	}
	return ""
}

// TestRenderSuggestedManifest_YAMLSignificantArgNameRoundTrips guards the
// defect where a tool argument whose name carries a YAML-significant character
// (here a colon-space) was emitted unquoted, producing a draft that failed to
// load — or worse, parsed into a different argument name than the tape observed.
func TestRenderSuggestedManifest_YAMLSignificantArgNameRoundTrips(t *testing.T) {
	const arg = "header: name" // the ": " makes this a YAML-significant scalar
	log := auditLine("allow", "tool", "fetch", map[string]any{"details": map[string]any{arg: "X-Trace"}}) + "\n" +
		auditLine("allow", "tool", "fetch", map[string]any{"details": map[string]any{arg: "X-Request"}})
	s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	if !strings.Contains(out, `argument: "header: name"`) {
		t.Errorf("argument name with YAML-significant characters must be emitted quoted\n%s", out)
	}
	// The draft must load, and the loaded condition must name the exact argument
	// rather than a fragment left by a YAML misparse.
	path := filepath.Join(t.TempDir(), "draft.yaml")
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	m, err := config.LoadManifest(path)
	if err != nil {
		t.Fatalf("draft with a YAML-significant argument name failed to load:\n%s\nerror: %v", out, err)
	}
	if got := allowedValuesArg(m, "fetch"); got != arg {
		t.Errorf("loaded allowedValues argument = %q; want %q\n%s", got, arg, out)
	}
}

// TestRenderSuggestedManifest_OptionalArgNotConstrained guards the defect where
// an argument observed on some but not all allowed calls was emitted as a
// mandatory allowedValues condition — which, because a missing argument fails
// closed, would deny exactly the observed call that omitted it.
func TestRenderSuggestedManifest_OptionalArgNotConstrained(t *testing.T) {
	// read_file is allowed twice: once WITH path, once WITHOUT. "encoding"
	// appears on both calls; "path" on only one.
	withPath := map[string]any{"path": "/reports/q3.pdf", "encoding": "utf8"}
	noPath := map[string]any{"encoding": "utf8"}
	log := auditLine("allow", "tool", "read_file", map[string]any{"details": withPath}) + "\n" +
		auditLine("allow", "tool", "read_file", map[string]any{"details": noPath})
	s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	if strings.Contains(out, `argument: "path"`) {
		t.Errorf("optional argument \"path\" was emitted as an active condition; it must be left unconstrained\n%s", out)
	}
	if !strings.Contains(out, `# argument "path"`) {
		t.Errorf("expected a review comment for the unconstrained optional argument \"path\"\n%s", out)
	}
	if !strings.Contains(out, `argument: "encoding"`) {
		t.Errorf("the always-present argument \"encoding\" should still be constrained\n%s", out)
	}
	// Both observed calls — including the one that omitted "path" — must still be
	// admitted by the generated manifest.
	assertManifestAllows(t, out, "read_file", withPath)
	assertManifestAllows(t, out, "read_file", noPath)
}

// TestRenderSuggestedManifest_ZeroArgCallNotConstrained is the regression for the
// zero-argument denominator gap: an audit/wiretap tool allow that carried ZERO
// arguments records no details field at all (a missing map, never "{}"), so suggest
// must still count it as a denominator for the optional-argument check. Otherwise an
// argument seen on the ONLY other call satisfies a.calls == nonTruncatedAllow, is
// emitted as an allowedValues condition, and then denies the zero-argument calls the
// tape showed as allowed (MISSING_CONTEXT).
func TestRenderSuggestedManifest_ZeroArgCallNotConstrained(t *testing.T) {
	// list_files is observed twice in audit mode: once with zero arguments (no details
	// field), once with a path. The zero-arg call makes "path" optional.
	zeroArg := auditLine("allow", "tool", "list_files", map[string]any{"audit_only": true})
	withPath := auditLine("allow", "tool", "list_files", map[string]any{
		"audit_only": true,
		"details":    map[string]any{"path": "/tmp"},
	})
	log := zeroArg + "\n" + withPath
	s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	if strings.Contains(out, `argument: "path"`) {
		t.Errorf("optional argument \"path\" was emitted as an active condition; the zero-arg call makes it optional\n%s", out)
	}
	// Both observed calls — including the zero-argument one — must still be admitted by
	// the generated manifest.
	assertManifestAllows(t, out, "list_files", map[string]any{})
	assertManifestAllows(t, out, "list_files", map[string]any{"path": "/tmp"})
}

// TestRenderSuggestedManifest_MixedTypeArgNotConstrained guards the defect where
// an argument observed as BOTH a string and a non-string value was emitted as a
// string-only allowedValues condition — which would deny the observed non-string
// call, since a string allowlist is glob-matched and never matches a number.
func TestRenderSuggestedManifest_MixedTypeArgNotConstrained(t *testing.T) {
	asString := map[string]any{"value": "max"}
	asNumber := map[string]any{"value": 42}
	log := auditLine("allow", "tool", "set_limit", map[string]any{"details": asString}) + "\n" +
		auditLine("allow", "tool", "set_limit", map[string]any{"details": asNumber})
	s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	if strings.Contains(out, "- type: allowedValues") {
		t.Errorf("mixed string/non-string argument must not be emitted as an allowedValues condition\n%s", out)
	}
	if !strings.Contains(out, `# argument "value"`) {
		t.Errorf("expected a review comment for the unconstrained mixed-type argument \"value\"\n%s", out)
	}
	// Both observed forms must be admitted by the generated manifest.
	assertManifestAllows(t, out, "set_limit", asString)
	assertManifestAllows(t, out, "set_limit", asNumber)
}

// TestRenderSuggestedManifest_GlobSignificantValueNotConstrained guards the
// value-side analogue of the YAML-significant-name defect. An allowedValues
// string entry is matched ONLY as a glob, so an observed value
// carrying glob metacharacters can fail to re-admit the call it came from:
// "report[2024].pdf" is a valid pattern that does not match its own literal
// text, and "data[" is malformed (path.ErrBadPattern) and would make the whole
// draft fail to load. Either way the argument must be left unconstrained.
func TestRenderSuggestedManifest_GlobSignificantValueNotConstrained(t *testing.T) {
	valid := map[string]any{"pattern": "report[2024].pdf"} // valid glob, does not self-match
	malformed := map[string]any{"q": "data["}              // malformed pattern
	log := auditLine("allow", "tool", "search_files", map[string]any{"details": valid}) + "\n" +
		auditLine("allow", "tool", "grep_tool", map[string]any{"details": malformed})
	s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	if strings.Contains(out, "- type: allowedValues") {
		t.Errorf("glob-significant values must not be emitted as an allowedValues condition\n%s", out)
	}
	for _, arg := range []string{`# argument "pattern"`, `# argument "q"`} {
		if !strings.Contains(out, arg) {
			t.Errorf("expected a review comment %s\n%s", arg, out)
		}
	}
	// The draft must load AND admit both observed calls — including the malformed
	// pattern, which would otherwise have failed validation outright.
	assertManifestAllows(t, out, "search_files", valid)
	assertManifestAllows(t, out, "grep_tool", malformed)
}

// TestRenderSuggestedManifest_TooManyValuesDowngradesToComment deliberately collects
// with the default cap (well above the 5 values fed in, so nothing overflows during
// collection — see TestMineArgs_CapsHighCardinalityValueAccumulation for that case)
// and renders with a much smaller maxValues, to exercise the render-side "count
// exceeds THIS render's cutoff" downgrade independent of collection's cap. Production
// (cmd/eunox/main.go) always passes the identical resolved maxValues to both calls;
// this mismatch is intentional test setup, not a mirror of production usage.
func TestRenderSuggestedManifest_TooManyValuesDowngradesToComment(t *testing.T) {
	var lines []string
	for i := 0; i < 5; i++ {
		lines = append(lines, auditLine("allow", "tool", "echo", map[string]any{"details": map[string]any{"msg": "v" + string(rune('a'+i))}}))
	}
	s, _ := computeSuggestions(strings.NewReader(strings.Join(lines, "\n")), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", 3) // 5 distinct values > maxValues=3

	if strings.Contains(out, "allowedValues") {
		t.Errorf("expected no allowedValues when over threshold\n%s", out)
	}
	if !strings.Contains(out, `argument "msg": 5 distinct values observed`) {
		t.Errorf("expected over-threshold review comment\n%s", out)
	}
}

// TestMineArgs_CapsHighCardinalityValueAccumulation pins the fix for unbounded
// distinct-value accumulation: mineArgs must stop growing an argument's value
// set once it has collected maxValues+1 distinct values (enough to prove "too
// many to allowlist" at render) rather than retaining every distinct value for
// the whole tape, which would grow without bound for a high-cardinality
// argument (request IDs, paths, timestamps) over a large audit log.
func TestMineArgs_CapsHighCardinalityValueAccumulation(t *testing.T) {
	const maxValues = 3
	tgt := &observedTarget{namespace: "tool", name: "fetch", args: map[string]*observedArg{}}
	for i := 0; i < 1000; i++ {
		mineArgs(tgt, map[string]interface{}{"id": fmt.Sprintf("id-%d", i)}, true, maxValues)
	}

	a := tgt.args["id"]
	if a == nil {
		t.Fatal("id argument missing")
	}
	if !a.overflowed {
		t.Error("expected a.overflowed = true after exceeding maxValues+1 distinct values")
	}
	if got := len(a.values); got > maxValues+1 {
		t.Errorf("a.values retained %d entries; want at most maxValues+1 (%d) — collection must not grow unbounded", got, maxValues+1)
	}
	// calls must still count every observation regardless of overflow, so the
	// optional-argument check downstream is unaffected by the cap.
	if a.calls != 1000 {
		t.Errorf("a.calls = %d; want 1000 (overflow must not stop presence counting)", a.calls)
	}
}

// TestRenderSuggestedManifest_OverflowedArgumentReportsCountBound pins the
// render-side message emitted for a collection-time overflow: since the exact
// distinct-value count is no longer known once overflowed, the note must not
// claim a specific count and must still downgrade to a review comment (never
// render allowedValues, which would omit values the cap discarded).
func TestRenderSuggestedManifest_OverflowedArgumentReportsCountBound(t *testing.T) {
	const maxValues = 3
	var lines []string
	for i := 0; i < 1000; i++ {
		lines = append(lines, auditLine("allow", "tool", "fetch", map[string]any{"details": map[string]any{"id": fmt.Sprintf("id-%d", i)}}))
	}
	s, err := computeSuggestions(strings.NewReader(strings.Join(lines, "\n")), maxValues)
	if err != nil {
		t.Fatalf("computeSuggestions: %v", err)
	}
	out := renderSuggestedManifest(s, "m", maxValues)

	if strings.Contains(out, "allowedValues") {
		t.Errorf("expected no allowedValues for an overflowed argument\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprintf(`argument "id": more than %d distinct values observed`, maxValues)) {
		t.Errorf("expected an overflow review comment bounded by maxValues\n%s", out)
	}
}

// TestRenderSuggestedManifest_OverflowedArgumentAlsoNonStringReportsOverflow pins
// the overflow-vs-nonString case ordering: an argument that overflowed its
// string-value cap (a.values cleared to nil, len(vals)==0) AND also carried a
// non-string value on some other call must still report the overflow note, not
// "non-string values observed" — the latter would satisfy `a.nonString &&
// len(vals)==0` and misleadingly imply no string values were ever seen, when in
// fact more than maxValues were (collection only stopped because it overflowed).
func TestRenderSuggestedManifest_OverflowedArgumentAlsoNonStringReportsOverflow(t *testing.T) {
	const maxValues = 3
	var lines []string
	for i := 0; i < 1000; i++ {
		lines = append(lines, auditLine("allow", "tool", "fetch", map[string]any{"details": map[string]any{"id": fmt.Sprintf("id-%d", i)}}))
	}
	// One additional call where "id" is a non-string value.
	lines = append(lines, auditLine("allow", "tool", "fetch", map[string]any{"details": map[string]any{"id": 42}}))
	s, err := computeSuggestions(strings.NewReader(strings.Join(lines, "\n")), maxValues)
	if err != nil {
		t.Fatalf("computeSuggestions: %v", err)
	}
	out := renderSuggestedManifest(s, "m", maxValues)

	if strings.Contains(out, "allowedValues") {
		t.Errorf("expected no allowedValues for an overflowed argument\n%s", out)
	}
	if strings.Contains(out, "non-string values observed") {
		t.Errorf("overflow must take priority over the misleading non-string-only note\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprintf(`argument "id": more than %d distinct values observed`, maxValues)) {
		t.Errorf("expected the overflow review comment even with a stray non-string value\n%s", out)
	}
}

func TestRenderSuggestedManifest_SamplingAlwaysCommented(t *testing.T) {
	log := auditLine("allow", "system", "sampling/createMessage", map[string]any{"session_id": "s1"})
	s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	if !strings.Contains(out, `# - target: "system:sampling/createMessage"`) {
		t.Errorf("sampling opt-in must be emitted commented out\n%s", out)
	}
	// And there must be no active (uncommented) system entry.
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, `- target: "system:`) {
			t.Errorf("found active sampling entry; must stay commented: %q", line)
		}
	}
}

func TestRenderSuggestedManifest_EmptyLog(t *testing.T) {
	s, _ := computeSuggestions(strings.NewReader(""), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "empty", suggestMaxValuesDefault)
	if !strings.Contains(out, "capabilities: []") {
		t.Errorf("empty tape should produce empty capabilities\n%s", out)
	}
	// Even the empty draft must be a loadable manifest.
	path := filepath.Join(t.TempDir(), "empty.yaml")
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := config.LoadManifest(path); err != nil {
		t.Fatalf("empty draft failed to load: %v", err)
	}
}

// ─── cmdSuggest (CLI path) ────────────────────────────────────────────────────

func TestCmdSuggest_WritesLoadableManifest(t *testing.T) {
	tape := writeTempFile(t, auditLine("allow", "tool", "read_file", map[string]any{"session_id": "s1", "details": map[string]any{"path": "/reports/q3.pdf"}})+"\n"+
		auditLine("allow", "tool", "query_db", map[string]any{"session_id": "s1", "details": map[string]any{"sql": "SELECT 1"}}))
	out := filepath.Join(t.TempDir(), "draft.yaml")

	withArgs([]string{"eunox", "suggest", "--audit-log", tape, "--output", out}, func() {
		cmdSuggest()
	})

	if _, err := config.LoadManifest(out); err != nil {
		t.Fatalf("suggest output did not load as a valid manifest: %v", err)
	}
}

func TestCmdSuggest_EmptyLogToStdout(t *testing.T) {
	tape := writeTempFile(t, "")
	withArgs([]string{"eunox", "suggest", "--audit-log", tape}, func() {
		cmdSuggest()
	})
}

// ─── commonPrefixGlob ─────────────────────────────────────────────────────────

func TestCommonPrefixGlob(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"/reports/a.pdf", "/reports/b.pdf"}, "/reports/*"},
		// "/*" does not cross "/", so it cannot match the deeper observed values —
		// the candidate is validated against every value and suppressed.
		{[]string{"/a/x", "/b/y"}, ""},
		{[]string{"SELECT 1", "SELECT 2"}, ""}, // no "/" — no path glob
		{[]string{"/only/one.pdf"}, ""},        // single value: nothing to generalize
		{[]string{"/reports/a", "/other/b"}, ""},
	}
	for _, tc := range cases {
		if got := commonPrefixGlob(tc.in); got != tc.want {
			t.Errorf("commonPrefixGlob(%v) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

// TestCommonPrefixGlob_SuppressesNonMatchingCandidate pins the case where a "<dir>/*"
// candidate that fails to match an observed sub-directory value (because a single
// "*" does not cross "/") must be suppressed rather than proposed as a hint that
// would reject a call the tape showed as allowed.
func TestCommonPrefixGlob_SuppressesNonMatchingCandidate(t *testing.T) {
	// Common prefix is "/srv/data/", candidate "/srv/data/*", but the second
	// value lives a directory deeper, so "*" cannot match it.
	if got := commonPrefixGlob([]string{"/srv/data/a.pdf", "/srv/data/logs/b.pdf"}); got != "" {
		t.Errorf("commonPrefixGlob = %q; want \"\" (candidate must not be proposed when it fails to match a sub-directory value)", got)
	}
	// When every value sits directly under the shared directory, the candidate
	// matches all of them and is still proposed.
	if got := commonPrefixGlob([]string{"/srv/data/a.pdf", "/srv/data/b.pdf"}); got != "/srv/data/*" {
		t.Errorf("commonPrefixGlob = %q; want \"/srv/data/*\"", got)
	}
}

// TestRenderSuggestedManifest_YAMLHostileTargetNameRoundTrips pins the case where a tool
// (or resource) name carrying a YAML-significant character must be emitted as a
// quoted target token so the draft still loads and parses into the exact target
// the tape observed — rather than a misparsed or injected entry.
func TestRenderSuggestedManifest_YAMLHostileTargetNameRoundTrips(t *testing.T) {
	// A colon-space in the name would, unquoted, mis-parse the YAML mapping; a
	// leading "*" is a YAML alias sigil. Both must survive a quoted round-trip.
	const tool = "weird: tool *name"
	log := auditLine("allow", "tool", tool, map[string]any{"details": map[string]any{"path": "/x.txt"}})
	s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	if !strings.Contains(out, `- target: "tool:weird: tool *name"`) {
		t.Errorf("YAML-hostile target name must be emitted as a quoted token\n%s", out)
	}
	path := filepath.Join(t.TempDir(), "draft.yaml")
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	m, err := config.LoadManifest(path)
	if err != nil {
		t.Fatalf("draft with a YAML-hostile target name failed to load:\n%s\nerror: %v", out, err)
	}
	found := false
	for i := range m.Capabilities {
		if m.Capabilities[i].Target == "tool:"+tool {
			found = true
		}
	}
	if !found {
		t.Errorf("loaded manifest does not carry the exact target %q\n%s", "tool:"+tool, out)
	}
}

// TestRenderSuggestedManifest_NewlineTargetNameDoesNotEscapeDenyComment pins the
// worst case: a newline in a deny-only target name must not break out of
// the commented "seen only as denials" block and smuggle an active entry past a
// reviewer. With %q the newline is escaped, keeping the whole token on one
// commented line.
func TestRenderSuggestedManifest_NewlineTargetNameDoesNotEscapeDenyComment(t *testing.T) {
	const tool = "good\n  - target: tool:exfil"
	log := auditLine("deny", "tool", tool, map[string]any{"denial_code": "AUTHORIZATION_FAILED"})
	s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	// No line may carry an uncommented active target injected via the newline.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "- target:") {
			t.Errorf("newline in deny-only target name escaped the comment and produced an active entry: %q\n%s", line, out)
		}
	}
	// The draft must still load (the injected newline did not corrupt the YAML).
	path := filepath.Join(t.TempDir(), "draft.yaml")
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := config.LoadManifest(path); err != nil {
		t.Fatalf("draft with a newline-bearing target name failed to load:\n%s\nerror: %v", out, err)
	}
}

// TestRenderSuggestedManifest_WideningGlobValueNotConstrained pins the case where an
// observed literal value that is itself a self-matching-but-widening glob (e.g.
// "*") must NOT be emitted into an active allowedValues list, since allowedValues
// is matched only as a glob and "*" would widen access to every value — well
// beyond the single observed literal.
func TestRenderSuggestedManifest_WideningGlobValueNotConstrained(t *testing.T) {
	star := map[string]any{"q": "*"}
	mid := map[string]any{"q": "a*b"}
	log := auditLine("allow", "tool", "search", map[string]any{"details": star}) + "\n" +
		auditLine("allow", "tool", "search", map[string]any{"details": mid})
	s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	if strings.Contains(out, "- type: allowedValues") {
		t.Errorf("a widening glob value must not be emitted as an allowedValues condition\n%s", out)
	}
	if strings.Contains(out, `values: ["*"]`) || strings.Contains(out, `- "*"`) {
		t.Errorf("observed literal \"*\" must not appear in a values: list\n%s", out)
	}
	if !strings.Contains(out, `# argument "q"`) {
		t.Errorf("expected a review comment for the unconstrained widening-glob argument \"q\"\n%s", out)
	}
	// The observed calls must still be admitted by the generated manifest.
	assertManifestAllows(t, out, "search", star)
	assertManifestAllows(t, out, "search", mid)
}

// TestValuesGlobInert_BackslashIsGlobSignificant pins that valuesGlobInert
// treats backslash as a glob metacharacter, independent of any upstream guard.
// MatchValueGlob delegates to stdlib path.Match, where backslash is an escape on
// every platform, so a backslash-bearing value is not glob-inert. This also
// double-checks the documented relationship to valuesSelfMatch: such a value
// fails to self-match (escaping breaks its literal), so it is already excluded
// before valuesGlobInert is reached — but valuesGlobInert must still report it
// non-inert on its own.
func TestValuesGlobInert_BackslashIsGlobSignificant(t *testing.T) {
	tests := []struct {
		name      string
		values    []string
		wantInert bool
	}{
		{"plain literal", []string{"data/file.txt"}, true},
		{"backslash escape", []string{`data\file`}, false},
		{"backslash before metachar", []string{`a\*b`}, false},
		{"star widens", []string{"a*b"}, false},
		{"question widens", []string{"file?.txt"}, false},
		{"bracket class", []string{"report[2024]"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := valuesGlobInert(tt.values); got != tt.wantInert {
				t.Errorf("valuesGlobInert(%q) = %v, want %v", tt.values, got, tt.wantInert)
			}
			// For a backslash value, confirm the documented self-match exclusion
			// holds: escaping breaks the literal so it never self-matches.
			for _, v := range tt.values {
				if strings.Contains(v, `\`) && enforcement.MatchValueGlob(v, v) {
					t.Errorf("expected backslash value %q not to self-match under path.Match", v)
				}
			}
		})
	}
}

// TestMineArgs_PerValueTruncationFlagsTruncated pins the case where a per-value-truncated
// audit argument (placeholder prefixed "[eunox: omitted ") must set the
// per-argument truncated flag (NOT the tool-level wholeTruncated) and count the
// argument's PRESENCE (it WAS on the call) while NOT recording the placeholder as
// an observed value, so the argument-specific truncation note fires and the
// argument is not mislabeled "optional".
func TestMineArgs_PerValueTruncationFlagsTruncated(t *testing.T) {
	placeholder := "[eunox: omitted 600000-byte value exceeding the 524288-byte audit detail cap]"
	tgt := &observedTarget{namespace: "tool", name: "write_file", args: map[string]*observedArg{}}
	mineArgs(tgt, map[string]interface{}{"body": placeholder}, true, suggestMaxValuesDefault)

	if tgt.wholeTruncated {
		t.Error("per-value truncation must NOT set the tool-level wholeTruncated flag")
	}
	if !tgt.args["body"].truncated {
		t.Error("per-value truncation placeholder must set the per-argument a.truncated flag")
	}
	a, ok := tgt.args["body"]
	if !ok {
		t.Fatalf("per-value truncation must still count the argument's presence: %+v", tgt.args)
	}
	if a.calls != 1 {
		t.Errorf("argument presence count = %d, want 1 (present even though its value was truncated)", a.calls)
	}
	if len(a.values) != 0 {
		t.Errorf("the truncation placeholder must not be recorded as an observed value: %+v", a.values)
	}
}

// TestRenderSuggestedManifest_PerValueTruncationNote pins end-to-end: the
// draft for a tool whose argument value was truncated by the audit layer must
// carry the truncation NOTE, not the glob-metacharacter note, and must still
// admit the observed call.
func TestRenderSuggestedManifest_PerValueTruncationNote(t *testing.T) {
	placeholder := "[eunox: omitted 600000-byte value exceeding the 524288-byte audit detail cap]"
	log := auditLine("allow", "tool", "write_file", map[string]any{"details": map[string]any{"body": placeholder}})
	s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	if strings.Contains(out, "glob metacharacters") {
		t.Errorf("truncated value must not be reported as carrying glob metacharacters\n%s", out)
	}
	if !strings.Contains(out, "truncated in the audit log") {
		t.Errorf("draft missing per-value truncation review note\n%s", out)
	}
	assertManifestAllows(t, out, "write_file", map[string]any{"body": "anything"})
}

// TestRenderSuggestedManifest_AlwaysPresentTruncatedArgNotOptional pins the rule that an
// argument present on EVERY observed allowed call but value-truncated on at least
// one of them must NOT be reported as "optional" (present on K of N), and must NOT
// be constrained with a partial allowlist that would deny the truncated call.
func TestRenderSuggestedManifest_AlwaysPresentTruncatedArgNotOptional(t *testing.T) {
	placeholder := "[eunox: omitted 600000-byte value exceeding the 524288-byte audit detail cap]"
	// Two allowed calls to the same tool: the argument is present on both, but its
	// value was truncated on the first and small on the second.
	truncatedCall := auditLine("allow", "tool", "write_file", map[string]any{"details": map[string]any{"content": placeholder}})
	smallCall := auditLine("allow", "tool", "write_file", map[string]any{"details": map[string]any{"content": "small"}})
	logs := truncatedCall + "\n" + smallCall
	s, _ := computeSuggestions(strings.NewReader(logs), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	if strings.Contains(out, "of 2 observed call(s)") {
		t.Errorf("always-present-but-truncated argument must not be reported as optional\n%s", out)
	}
	if strings.Contains(out, "allowedValues") {
		t.Errorf("an argument with a truncated value must be left unconstrained, not given a partial allowlist\n%s", out)
	}
	if !strings.Contains(out, "truncated in the audit log") {
		t.Errorf("draft missing per-value truncation review note\n%s", out)
	}
	// Both the truncated-value call and the small-value call must still be admitted.
	assertManifestAllows(t, out, "write_file", map[string]any{"content": "anything"})
}

// TestMineArgs_NilDetailsIsNotADenominator pins that an enforce-mode allow (which
// carries no argument map at all: details == nil) is not counted as a denominator
// for the optional-argument check, so an argument genuinely present on every call
// WITH visible arguments is not mislabeled "optional" and keeps its allowedValues.
func TestMineArgs_NilDetailsIsNotADenominator(t *testing.T) {
	// One enforce-mode allow (no details) followed by one wiretap allow whose only
	// argument is present.
	enforceAllow := auditLine("allow", "tool", "read_file", nil)
	wiretapAllow := auditLine("allow", "tool", "read_file", map[string]any{"details": map[string]any{"path": "/reports/q3.pdf"}})
	logs := enforceAllow + "\n" + wiretapAllow
	s, _ := computeSuggestions(strings.NewReader(logs), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	// The nil-details call must not inflate the denominator: nonTruncatedAllow is 1,
	// so "path" (a.calls == 1) is always-present and must be constrained.
	tgt := s.targets["tool:read_file"]
	if tgt.nonTruncatedAllow != 1 {
		t.Errorf("nil-details enforce allow must not count as a denominator: nonTruncatedAllow = %d, want 1", tgt.nonTruncatedAllow)
	}
	if strings.Contains(out, "left unconstrained, since a condition would deny the calls that omit it") {
		t.Errorf("always-present argument must not be mislabeled optional by a nil-details enforce allow\n%s", out)
	}
	if !strings.Contains(out, `argument: "path"`) {
		t.Errorf("always-present argument \"path\" should be constrained, not suppressed\n%s", out)
	}
	assertManifestAllows(t, out, "read_file", map[string]any{"path": "/reports/q3.pdf"})
}

// TestMineArgs_ReservedUpstreamErrorCodeKey pins that the reserved, underscore-prefixed
// audit-only detail key audit.UpstreamErrorCodeKey (merged by the transport when an
// allowed call's upstream then errored) is never mined as a phantom tool argument, and
// that its reserved namespace means a real tool argument literally named
// "upstream_error_code" (bare, no prefix) is mined like any other argument since it can
// no longer collide with the reserved key.
func TestMineArgs_ReservedUpstreamErrorCodeKey(t *testing.T) {
	reserved := audit.UpstreamErrorCodeKey

	t.Run("flat shape skips the reserved key", func(t *testing.T) {
		tgt := &observedTarget{namespace: "tool", name: "fetch", args: map[string]*observedArg{}}
		mineArgs(tgt, map[string]interface{}{"url": "https://x", reserved: 500}, true, suggestMaxValuesDefault)
		if _, ok := tgt.args[reserved]; ok {
			t.Errorf("reserved key %q must not be mined as an argument", reserved)
		}
		if a := tgt.args["url"]; a == nil || a.calls != 1 {
			t.Errorf("real argument \"url\" should be mined once; got %+v", a)
		}
		if tgt.nonTruncatedAllow != 1 {
			t.Errorf("a call with a real argument must count as a denominator; nonTruncatedAllow = %d", tgt.nonTruncatedAllow)
		}
	})

	t.Run("reserved-only record is not an enforce-mode denominator", func(t *testing.T) {
		tgt := &observedTarget{namespace: "tool", name: "fetch", args: map[string]*observedArg{}}
		mineArgs(tgt, map[string]interface{}{reserved: 500}, false, suggestMaxValuesDefault)
		if len(tgt.args) != 0 {
			t.Errorf("a reserved-only enforce record must mine no arguments; got %v", tgt.args)
		}
		if tgt.nonTruncatedAllow != 0 {
			t.Errorf("a reserved-only enforce record has zero argument visibility and must not count; nonTruncatedAllow = %d", tgt.nonTruncatedAllow)
		}
	})

	t.Run("reserved-only record is a zero-arg observation in audit mode", func(t *testing.T) {
		tgt := &observedTarget{namespace: "tool", name: "fetch", args: map[string]*observedArg{}}
		mineArgs(tgt, map[string]interface{}{reserved: 500}, true, suggestMaxValuesDefault)
		if len(tgt.args) != 0 {
			t.Errorf("a reserved-only audit record must mine no arguments; got %v", tgt.args)
		}
		if tgt.nonTruncatedAllow != 1 {
			t.Errorf("a reserved-only audit record is a real zero-argument observation; nonTruncatedAllow = %d", tgt.nonTruncatedAllow)
		}
	})

	t.Run("real argument literally named upstream_error_code is mined like any other argument", func(t *testing.T) {
		// Previously ambiguous: a real tool argument named "upstream_error_code" (bare)
		// could collide with the injected reserved code. Now the injected code lives
		// under the underscore-prefixed audit.UpstreamErrorCodeKey, so the bare name is
		// ordinary caller data and is mined normally, whether or not the upstream errored.
		tgt := &observedTarget{namespace: "tool", name: "fetch", args: map[string]*observedArg{}}
		mineArgs(tgt, map[string]interface{}{
			"upstream_error_code": "user-value",
			reserved:              500,
		}, true, suggestMaxValuesDefault)
		if a := tgt.args["upstream_error_code"]; a == nil || a.calls != 1 {
			t.Errorf("the real bare-named argument must be mined; got %+v", a)
		}
		if _, ok := tgt.args[reserved]; ok {
			t.Errorf("the reserved key %q must not be mined as an argument", reserved)
		}
	})

	t.Run("nested collision shape mines the real inner arguments", func(t *testing.T) {
		// The residual rare collision: a real tool argument is literally named the
		// reserved key's own string, so the transport nests the caller's args under
		// "arguments" (dispatch.go's dispatchToolsCall collide branch).
		tgt := &observedTarget{namespace: "tool", name: "fetch", args: map[string]*observedArg{}}
		mineArgs(tgt, map[string]interface{}{
			"arguments": map[string]interface{}{reserved: "user-value"},
			reserved:    500,
		}, true, suggestMaxValuesDefault)
		if _, ok := tgt.args["arguments"]; ok {
			t.Errorf("the nested wrapper key \"arguments\" must not be mined as an argument")
		}
		if a := tgt.args[reserved]; a == nil || a.calls != 1 {
			t.Errorf("the genuine inner argument %q must be mined; got %+v", reserved, a)
		}
	})

	t.Run("flat merge over an object-valued argument named arguments is not misread as the nested wrapper", func(t *testing.T) {
		// NOT the nested-collision shape: the ORDINARY flat merge for a call whose one
		// real argument is a map named "arguments" and whose upstream then errored.
		// Structurally identical to the true nested wrapper EXCEPT the inner map does
		// not itself carry the reserved key — the fact that disambiguates the two.
		//
		// Mining must read it flat: "arguments" is the one real argument and the
		// reserved key is still the transport's injected code, not caller data. The
		// accepted cost of preferring this (far likelier) reading is that a call
		// genuinely carrying a top-level argument literally named the reserved key's
		// string drops that one argument — the vanishingly rare case.
		tgt := &observedTarget{namespace: "tool", name: "fetch", args: map[string]*observedArg{}}
		mineArgs(tgt, map[string]interface{}{
			"arguments": map[string]interface{}{"depth": float64(3)},
			reserved:    500,
		}, true, suggestMaxValuesDefault)

		if _, ok := tgt.args["depth"]; ok {
			t.Errorf("the inner object's field \"depth\" must NOT be mined as a top-level argument; got %v", tgt.args)
		}
		if a := tgt.args["arguments"]; a == nil || a.calls != 1 {
			t.Errorf("the real top-level argument \"arguments\" must be mined once; got %+v", a)
		}
		if _, ok := tgt.args[reserved]; ok {
			t.Errorf("the transport's injected reserved key %q must not be mined as a phantom argument; got %v", reserved, tgt.args)
		}
		if tgt.nonTruncatedAllow != 1 {
			t.Errorf("the call carries a real argument and must count as a denominator; nonTruncatedAllow = %d", tgt.nonTruncatedAllow)
		}
	})

	t.Run("flat merge over an object-valued argument named arguments does not skew presence accounting", func(t *testing.T) {
		// The regression the flat reading protects: the same tool called twice with its
		// one real map argument "arguments" — once cleanly, once with an upstream error.
		// Misreading the errored record as "two real top-level arguments" would leave
		// "arguments" at calls == 1 against nonTruncatedAllow == 2 and mislabel an
		// always-present argument as optional, suppressing its allowedValues condition.
		tgt := &observedTarget{namespace: "tool", name: "fetch", args: map[string]*observedArg{}}
		mineArgs(tgt, map[string]interface{}{
			"arguments": map[string]interface{}{"depth": float64(3)},
		}, true, suggestMaxValuesDefault)
		mineArgs(tgt, map[string]interface{}{
			"arguments": map[string]interface{}{"depth": float64(3)},
			reserved:    500,
		}, true, suggestMaxValuesDefault)

		a := tgt.args["arguments"]
		if a == nil || a.calls != 2 {
			t.Fatalf("the always-present argument \"arguments\" must be mined on both calls; got %+v", a)
		}
		if tgt.nonTruncatedAllow != 2 {
			t.Fatalf("both records carry a real argument; nonTruncatedAllow = %d, want 2", tgt.nonTruncatedAllow)
		}
		if a.calls != tgt.nonTruncatedAllow {
			t.Errorf("presence accounting skewed: calls = %d, nonTruncatedAllow = %d — the argument would be mislabeled optional", a.calls, tgt.nonTruncatedAllow)
		}
	})
}

// TestRenderSuggestedManifest_PerValueTruncationNoToolLevelNote pins that a single
// argument's value being truncated produces an ARGUMENT-SPECIFIC note (not the
// generic whole-tool NOTE) while OTHER arguments on the same call still get their
// allowedValues conditions.
func TestRenderSuggestedManifest_PerValueTruncationNoToolLevelNote(t *testing.T) {
	placeholder := "[eunox: omitted 600000-byte value exceeding the 524288-byte audit detail cap]"
	// "body" is value-truncated; "encoding" is a normal small string on the same call.
	log := auditLine("allow", "tool", "write_file", map[string]any{"details": map[string]any{"body": placeholder, "encoding": "utf8"}})
	s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	// The generic whole-tool NOTE ("values could not be mined") must NOT fire for a
	// per-value truncation.
	if strings.Contains(out, "values could not be mined") {
		t.Errorf("per-value truncation must not emit the whole-tool NOTE\n%s", out)
	}
	// An argument-specific truncation note must fire for "body".
	if !strings.Contains(out, `# argument "body": value(s) were truncated in the audit log`) {
		t.Errorf("draft missing argument-specific truncation note for \"body\"\n%s", out)
	}
	// The other argument must still be constrained.
	if !strings.Contains(out, `argument: "encoding"`) {
		t.Errorf("a per-value truncation of one argument must not suppress conditions for others\n%s", out)
	}
	assertManifestAllows(t, out, "write_file", map[string]any{"body": "anything", "encoding": "utf8"})
}

// TestRenderSuggestedManifest_ArgumentPathPrefixNoted pins that an argument whose
// NAME uses the reserved "$." nested-path prefix is flagged with its
// reserved-prefix note even when concrete values were observed (the prefix is a
// property of the name, not the values, so the check runs regardless of value count).
func TestRenderSuggestedManifest_ArgumentPathPrefixNoted(t *testing.T) {
	log := auditLine("allow", "tool", "patch", map[string]any{"details": map[string]any{"$.target": "main"}})
	s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	if strings.Contains(out, "allowedValues") {
		t.Errorf("a \"$.\"-prefixed argument with observed values must not be given an allowedValues condition\n%s", out)
	}
	if !strings.Contains(out, `reserved "$." nested-path prefix`) {
		t.Errorf("draft missing the reserved-prefix note for a \"$.\"-prefixed argument with observed values\n%s", out)
	}
	assertManifestAllows(t, out, "patch", map[string]any{"$.target": "main"})
}

// TestRenderSuggestedManifest_EscapedArgumentLiteralNoted pins that an argument
// whose NAME uses the reserved "$$." escape prefix (2+ leading '$' then '.') is
// left unconstrained with its escape-prefix note rather than given an
// allowedValues condition. The engine unescapes such a name to a different
// literal key (ArgumentLiteralKey: "$$.x" -> "$.x"), so an emitted condition
// would resolve a different argument and deny the very call the tape recorded as
// allowed. Like the "$." arm, the check is a property of the name and runs even
// though concrete values were observed.
func TestRenderSuggestedManifest_EscapedArgumentLiteralNoted(t *testing.T) {
	log := auditLine("allow", "tool", "foo", map[string]any{"details": map[string]any{"$$.x": "val"}})
	s, _ := computeSuggestions(strings.NewReader(log), suggestMaxValuesDefault)
	out := renderSuggestedManifest(s, "m", suggestMaxValuesDefault)

	if strings.Contains(out, "allowedValues") {
		t.Errorf("a \"$$.\"-escaped argument with observed values must not be given an allowedValues condition\n%s", out)
	}
	if !strings.Contains(out, `reserved "$$." escape prefix`) {
		t.Errorf("draft missing the escape-prefix note for a \"$$.\"-escaped argument with observed values\n%s", out)
	}
	// The grounded draft must still allow the exact observed call — the whole point
	// of leaving it unconstrained instead of emitting a self-denying condition.
	assertManifestAllows(t, out, "foo", map[string]any{"$$.x": "val"})
}
