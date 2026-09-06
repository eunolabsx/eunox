// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/pkg/capability"
)

var manifestSchemaPath = filepath.Join("..", "..", "schemas", "eunox-capability-manifest.schema.json")

func loadManifestSchema(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(manifestSchemaPath)
	if err != nil {
		t.Fatalf("read schema %s: %v", manifestSchemaPath, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	return doc
}

func TestManifestSchema_WellFormed(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)
	for _, key := range []string{"$schema", "$id", "title", "type", "properties", "$defs"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("schema missing top-level %q", key)
		}
	}
	if doc["type"] != "object" {
		t.Errorf(`schema "type" = %v, want "object"`, doc["type"])
	}
	if doc["additionalProperties"] != false {
		t.Errorf(`schema "additionalProperties" = %v, want false — an open manifest schema would accept the misspelled key the loader rejects`, doc["additionalProperties"])
	}
}

// TestManifestSchema_MatchesRootStruct guards the top-level object against drift from
// config.LocalManifest, the struct the loader actually parses. A field present in one and
// not the other is either an undocumented grammar token or a stale schema property that
// an author's editor would accept and the loader then refuses.
func TestManifestSchema_MatchesRootStruct(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)
	want := jsonTagSet(reflect.TypeOf(config.LocalManifest{}))
	got := schemaPropNames(t, doc)
	if missing := diffKeys(want, got); len(missing) > 0 {
		t.Errorf("LocalManifest fields missing from the schema root: %v", missing)
	}
	if extra := diffKeys(got, want); len(extra) > 0 {
		t.Errorf("schema root properties with no matching LocalManifest field: %v", extra)
	}
}

// TestManifestSchema_MatchesConstraintStruct does the same for one capability entry
// against capability.Constraint.
func TestManifestSchema_MatchesConstraintStruct(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)
	want := jsonTagSet(reflect.TypeOf(capability.Constraint{}))
	got := schemaPropNames(t, schemaObjectAt(t, doc, "$defs", "capability"))
	if missing := diffKeys(want, got); len(missing) > 0 {
		t.Errorf("Constraint fields missing from $defs.capability: %v", missing)
	}
	if extra := diffKeys(got, want); len(extra) > 0 {
		t.Errorf("$defs.capability properties with no matching Constraint field: %v", extra)
	}
}

// TestManifestSchema_CoversEveryConditionType is the strongest of the drift guards: it
// walks the condition PROTOTYPE REGISTRY — the one place a condition type is registered —
// and asserts the schema declares a branch for each, with exactly that type's JSON fields.
//
// Deriving the expectation from the registry rather than a hand-written list is the point.
// A hand-written mirror is a second table to update per new condition type, and one that
// fails silently: a type missing from it is simply not checked, so the grammar could grow
// a predicate the published schema never mentions.
func TestManifestSchema_CoversEveryConditionType(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)
	branches := schemaOneOfByConst(t, schemaObjectAt(t, doc, "$defs", "condition"))

	for _, condType := range capability.KnownConditionTypes() {
		proto, ok := capability.NewConditionPrototype(condType)
		if !ok {
			t.Fatalf("condition type %q is advertised but has no prototype", condType)
		}
		branch, declared := branches[condType]
		if !declared {
			t.Errorf("schema declares no branch for condition type %q (add one under $defs.condition.oneOf)", condType)
			continue
		}
		want := jsonTagSet(reflect.TypeOf(proto))
		want["type"] = true
		got := schemaPropNames(t, branch)
		if missing := diffKeys(want, got); len(missing) > 0 {
			t.Errorf("condition %q: struct fields missing from the schema branch: %v", condType, missing)
		}
		if extra := diffKeys(got, want); len(extra) > 0 {
			t.Errorf("condition %q: schema branch properties with no matching struct field: %v", condType, extra)
		}
		if branch["additionalProperties"] != false {
			t.Errorf("condition %q: branch must set additionalProperties:false", condType)
		}
	}
	if len(branches) != len(capability.KnownConditionTypes()) {
		t.Errorf("schema declares %d condition branches for %d known types — a branch names a type the grammar does not have",
			len(branches), len(capability.KnownConditionTypes()))
	}
}

// TestManifestSchema_CoversEveryDirectiveType mirrors the condition walk for directives,
// deriving its expectation from the directive registry for the same reason: a hand-written
// mirror is a second table to update per new directive, and one that fails silently.
func TestManifestSchema_CoversEveryDirectiveType(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)
	branches := schemaOneOfByConst(t, schemaObjectAt(t, doc, "$defs", "directive"))

	want := map[string]any{}
	for _, dirType := range capability.KnownDirectiveTypes() {
		proto, ok := capability.NewDirectivePrototype(dirType)
		if !ok {
			t.Fatalf("directive type %q is advertised but has no prototype", dirType)
		}
		want[dirType] = proto
	}
	for dirType, proto := range want {
		branch, declared := branches[dirType]
		if !declared {
			t.Errorf("schema declares no branch for directive type %q", dirType)
			continue
		}
		fields := jsonTagSet(reflect.TypeOf(proto))
		fields["type"] = true
		got := schemaPropNames(t, branch)
		if missing := diffKeys(fields, got); len(missing) > 0 {
			t.Errorf("directive %q: struct fields missing from the schema branch: %v", dirType, missing)
		}
		if extra := diffKeys(got, fields); len(extra) > 0 {
			t.Errorf("directive %q: schema branch properties with no matching struct field: %v", dirType, extra)
		}
	}
	if len(branches) != len(want) {
		t.Errorf("schema declares %d directive branches, want %d", len(branches), len(want))
	}
}

// TestManifestSchema_ClosedVocabularies pins the enum sets against the constants the
// engine enforces, so the published schema and the runtime cannot disagree about what the
// closed vocabularies contain. A schema that accepted a label the engine rejects would
// hand an author a manifest their proxy refuses to load.
func TestManifestSchema_ClosedVocabularies(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)

	// The NATIVE half only: the imported axis has no enum to pin, since its values are the
	// incumbent taxonomy's and eunox never enumerates them. Pinned through the dedicated
	// $def so widening #/$defs/flowLabel to the two-axis oneOf cannot quietly drop the one
	// vocabulary the schema and the engine must still agree on.
	if got, want := schemaEnum(t, schemaObjectAt(t, doc, "$defs", "nativeFlowLabel")), capability.NativeFlowLabelVocabulary(); !sameStrings(got, want) {
		t.Errorf("nativeFlowLabel enum = %v, want the native vocabulary %v", got, want)
	}
	if got, want := schemaEnum(t, schemaObjectAt(t, doc, "$defs", "effectClass")), capability.EffectClassVocabulary(); !sameStrings(got, want) {
		t.Errorf("effectClass enum = %v, want the closed reversibility set %v", got, want)
	}
	onExceed := schemaEnum(t, schemaObjectAt(t, doc, "$defs", "effectCeiling", "properties", "onExceed"))
	if !sameStrings(onExceed, []string{capability.OnExceedEscalate, capability.OnExceedDeny}) {
		t.Errorf("onExceed enum = %v, want [escalate deny]", onExceed)
	}
	enforcement := schemaEnum(t, schemaObjectAt(t, doc, "$defs", "capability", "properties", "enforcement"))
	if !sameStrings(enforcement, []string{capability.EnforcementEnforce, capability.EnforcementAudit}) {
		t.Errorf("enforcement enum = %v, want [enforce audit]", enforcement)
	}
	principal := schemaPropNames(t, schemaObjectAt(t, doc, "$defs", "capability", "properties", "principal"))
	wantPrincipal := map[string]bool{}
	for _, c := range capability.SupportedPrincipalClaimNames() {
		wantPrincipal[c] = true
	}
	if missing := diffKeys(wantPrincipal, principal); len(missing) > 0 {
		t.Errorf("principal claims missing from the schema: %v", missing)
	}
	if extra := diffKeys(principal, wantPrincipal); len(extra) > 0 {
		t.Errorf("schema principal claims the loader does not support: %v", extra)
	}
}

// TestManifestSchema_SchemaVersionEnum pins that the schema advertises exactly the
// grammar revisions this build parses — including that the retired draft string is NOT
// among them.
func TestManifestSchema_SchemaVersionEnum(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)
	got := schemaEnum(t, schemaObjectAt(t, doc, "properties", "schemaVersion"))
	// Derived, not restated: publishing a revision is an append to capability's ordered
	// sequence, which the loader's parse set is derived from — so a literal here would let
	// the loader accept a manifest the published schema's enum still rejects, with both
	// sides of this assertion frozen and the test green. Same reason the token expectations
	// below derive from the prototype registry.
	want := capability.PublishedSchemaVersions()
	if !sameStrings(got, want) {
		t.Fatalf("schemaVersion enum = %v, want %v", got, want)
	}
	for _, v := range got {
		if v == "0.2-draft" {
			t.Fatal("the retired draft version must not be advertised — it is removed, not aliased")
		}
	}
}

// TestManifestSchema_VersionPatternMatchesLoader exercises the semver pattern the schema
// publishes against the same accepted/rejected forms the loader enforces on `version`, so
// an author-time check and the runtime agree on what a valid version looks like. The
// loader runs no JSON-Schema validation, so this compiles the declared pattern and drives
// it directly rather than pulling in a json-schema dependency.
func TestManifestSchema_VersionPatternMatchesLoader(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)
	pat, ok := schemaObjectAt(t, doc, "properties", "version")["pattern"].(string)
	if !ok {
		t.Fatal("version has no string \"pattern\"")
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		t.Fatalf("version pattern is not a valid regexp: %v", err)
	}
	for _, v := range []string{"0.0.0", "0.1.0", "1.2.3", "10.20.30"} {
		if !re.MatchString(v) {
			t.Errorf("version pattern rejected valid version %q", v)
		}
	}
	for _, v := range []string{"1.2.3-rc", "1.2.3+build", "1.2", "1.2.3.4", "v1.2.3", "01.2.3", "1.2.03", " 1.2.3", "1.2.3 ", ""} {
		if re.MatchString(v) {
			t.Errorf("version pattern accepted invalid version %q", v)
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// jsonTagSet returns the JSON field names of a struct type, skipping "-" and
// unexported fields. Mirrors yamlTagSet in the gateway-config schema test.
func jsonTagSet(t reflect.Type) map[string]bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	out := map[string]bool{}
	for i := range t.NumField() {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		tag := f.Tag.Get("json")
		name, _, _ := cutComma(tag)
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = true
	}
	return out
}

func cutComma(s string) (before, after string, found bool) {
	for i := range len(s) {
		if s[i] == ',' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// schemaPropNames returns the property names declared on a schema object node.
func schemaPropNames(t *testing.T, node map[string]any) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	props, ok := node["properties"].(map[string]any)
	if !ok {
		return out
	}
	for k := range props {
		out[k] = true
	}
	return out
}

// schemaOneOfByConst indexes a discriminated-union node's oneOf branches by the const
// value of their "type" property, which is how every condition/directive branch is keyed.
func schemaOneOfByConst(t *testing.T, node map[string]any) map[string]map[string]any {
	t.Helper()
	branches, ok := node["oneOf"].([]any)
	if !ok {
		t.Fatal("node has no oneOf array")
	}
	out := make(map[string]map[string]any, len(branches))
	for i, b := range branches {
		branch, ok := b.(map[string]any)
		if !ok {
			t.Fatalf("oneOf[%d] is not an object", i)
		}
		props, ok := branch["properties"].(map[string]any)
		if !ok {
			t.Fatalf("oneOf[%d] has no properties", i)
		}
		typeNode, ok := props["type"].(map[string]any)
		if !ok {
			t.Fatalf("oneOf[%d] has no \"type\" property", i)
		}
		discriminator, ok := typeNode["const"].(string)
		if !ok {
			t.Fatalf("oneOf[%d].properties.type has no string const", i)
		}
		out[discriminator] = branch
	}
	return out
}

// schemaEnum returns a node's enum values as strings, sorted.
func schemaEnum(t *testing.T, node map[string]any) []string {
	t.Helper()
	raw, ok := node["enum"].([]any)
	if !ok {
		t.Fatal("node has no enum array")
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("enum member %v is not a string", v)
		}
		out = append(out, s)
	}
	return out
}

// sameStrings compares two string sets irrespective of order.
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// TestManifestSchema_GatesTheFlowEffectTokensByRevision is the correspondence test between
// the published schema and the loader on the one rule an author is most likely to trip:
// that "0.1" is a strict subset. It walks the same token list against BOTH — the schema
// must name each in its 0.1 exclusion, and the loader must refuse each under 0.1 — so the
// two cannot silently disagree about which revision admits a token.
//
// Without it, the schema's flat schemaVersion enum certified as valid exactly the manifest
// the proxy then refused to boot on: an authoring aid that green-lights the error it exists
// to catch is worse than none.
func TestManifestSchema_GatesTheFlowEffectTokensByRevision(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)
	all, ok := doc["allOf"].([]any)
	if !ok || len(all) != 1 {
		t.Fatal("schema has no single-entry allOf carrying the 0.1 subset rule")
	}
	gate, ok := all[0].(map[string]any)
	if !ok {
		t.Fatal("allOf[0] is not an object")
	}
	then, ok := gate["then"].(map[string]any)
	if !ok {
		t.Fatal("the 0.1 subset rule has no \"then\"")
	}
	item := schemaObjectAt(t, then, "properties", "capabilities", "items")

	// The root-level and per-capability structural exclusions.
	if req, _ := schemaObjectAt(t, then, "not")["required"].([]any); len(req) != 1 || req[0] != "effectCeiling" {
		t.Errorf("the 0.1 arm must exclude the top-level effectCeiling, got %v", req)
	}
	if req, _ := schemaObjectAt(t, item, "not")["required"].([]any); len(req) != 1 || req[0] != "effect" {
		t.Errorf("the 0.1 arm must exclude a capability's effect contract, got %v", req)
	}

	condExcluded := schemaNotEnum(t, schemaObjectAt(t, item, "properties", "conditions", "items", "properties", "type"))
	dirExcluded := schemaNotEnum(t, schemaObjectAt(t, item, "properties", "directives", "items", "properties", "type"))
	varExcluded := schemaNotEnum(t, schemaObjectAt(t, item, "properties", "conditions", "items", "properties", "values", "items"))

	// DERIVED from the prototype registry, not restated: every condition and directive the
	// registry classifies as introduced by the flow+effect revision must appear in the
	// schema's 0.1 exclusion. Written as literals, a fourth such token could be added to the
	// registry (which the loader then correctly refuses under 0.1) while the schema's
	// exclusion arm and this expectation were both left behind — and the test would pass
	// while the published authoring aid green-lit a manifest the proxy refuses to boot on.
	// The task-variable check below already derives its expectation the same way.
	wantCond := tokensIntroducedIn(capability.SchemaVersion02, capability.KnownConditionTypes())
	wantDir := tokensIntroducedIn(capability.SchemaVersion02, capability.KnownDirectiveTypes())
	var wantVar []string
	for _, n := range capability.TaskVarNames() {
		wantVar = append(wantVar, "${"+n+"}")
	}
	if !sameStrings(condExcluded, wantCond) {
		t.Errorf("0.1 condition exclusion = %v, want %v", condExcluded, wantCond)
	}
	if !sameStrings(dirExcluded, wantDir) {
		t.Errorf("0.1 directive exclusion = %v, want %v", dirExcluded, wantDir)
	}
	if !sameStrings(varExcluded, wantVar) {
		t.Errorf("0.1 task-variable exclusion = %v, want %v", varExcluded, wantVar)
	}

	// The other half of the correspondence: the LOADER refuses every one of them under
	// 0.1. A schema exclusion the loader does not enforce (or vice versa) is the drift
	// this test exists to catch.
	bodies := map[string]string{
		"effectCeiling":     "effectCeiling:\n  maxEffectClass: reversible\ncapabilities:\n  - target: tool:t\n    actions: [call]\n",
		"effect contract":   "capabilities:\n  - target: tool:t\n    actions: [call]\n    effect:\n      class: reversible\n",
		"flowLabel":         "capabilities:\n  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: flowLabel\n        allow: [public]\n",
		"effectClass":       "capabilities:\n  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: effectClass\n        allow: [reversible]\n",
		"blastRadius":       "capabilities:\n  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: blastRadius\n        max: 5\n",
		"labelOutput":       "capabilities:\n  - target: tool:t\n    actions: [call]\n    directives:\n      - type: labelOutput\n        labels: [pii]\n",
		"${task.id}":        "capabilities:\n  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: allowedValues\n        argument: a\n        values: [\"${task.id}\"]\n",
		"${task.agent}":     "capabilities:\n  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: allowedValues\n        argument: a\n        values: [\"${task.agent}\"]\n",
		"${task.principal}": "capabilities:\n  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: allowedValues\n        argument: a\n        values: [\"${task.principal}\"]\n",
	}
	for name, body := range bodies {
		t.Run("loader refuses "+name+" under 0.1", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "m.yaml")
			if err := os.WriteFile(path, []byte("schemaVersion: \"0.1\"\nname: m\nversion: \"1.0.0\"\n"+body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, err := config.LoadManifest(path)
			if err == nil {
				t.Fatalf("%s must be refused under the 0.1 grammar", name)
			}
			if !strings.Contains(err.Error(), "schemaVersion \"0.2\"") {
				t.Fatalf("%s: err = %v, want it to name the introducing revision", name, err)
			}
		})
	}
}

// schemaNotEnum returns the enum a node excludes via {"not": {"enum": [...]}}.
func schemaNotEnum(t *testing.T, node map[string]any) []string {
	t.Helper()
	return schemaEnum(t, schemaObjectAt(t, node, "not"))
}

// tokensIntroducedIn filters a prototype registry's discriminators down to those the registry
// says a given grammar revision introduced, through the one classification lookup
// (capability.TokenSince). It is what lets the schema-drift checks derive their expectations
// from the registry rather than from a literal list beside it.
func tokensIntroducedIn(revision string, tokens []string) []string {
	var out []string
	for _, tok := range tokens {
		// An unclassified token is deliberately not folded into any revision here: the loader
		// refuses it outright, and TestManifestSchema_CoversEveryConditionType is what fails
		// when a token is missing a Since.
		if since, ok := capability.TokenSince(tok); ok && since == revision {
			out = append(out, tok)
		}
	}
	return out
}

// TestComputeAuditStats_UnroutableIsCountedAndCalledOut pins the operator-facing half of the
// routing-refusal marker: it records AUTHORIZATION_FAILED, a genuine policy code, so on this
// summary a wiretap run's own refusals are otherwise indistinguishable from policy blocks — in a
// posture where policy blocks nothing. The banner tells the operator to read the tape with this
// tool, so this tool has to say which is which. The probe is derived from the producer's key.
func TestComputeAuditStats_UnroutableIsCountedAndCalledOut(t *testing.T) {
	t.Parallel()
	if string(unroutableProbe) != audit.UnroutableKey {
		t.Fatalf("the stats probe %q is not the producer's key %q", unroutableProbe, audit.UnroutableKey)
	}
	marker := func(reason string) string {
		return `{"` + audit.UnroutableKey + `":{"reason":"` + reason + `","revision":"2026-07-28"}}`
	}
	log := strings.Join([]string{
		`{"decision":"deny","method":"resources/subscribe","denial_code":"AUTHORIZATION_FAILED","details":` + marker(audit.UnroutableRemovedInRevision) + `}`,
		`{"decision":"deny","method":"agents/delegate","target":"agents/delegate","denial_code":"AUTHORIZATION_FAILED","details":` + marker(audit.UnroutableUnknownMethod) + `}`,
		`{"decision":"deny","method":"agents/delegate","target":"agents/delegate","denial_code":"AUTHORIZATION_FAILED","details":` + marker(audit.UnroutableUnknownMethod) + `}`,
		// A genuine policy denial, which must NOT be folded in.
		`{"decision":"deny","target_type":"tool","target":"read_file","denial_code":"AUTHORIZATION_FAILED"}`,
	}, "\n")
	got, err := computeAuditStats(strings.NewReader(log))
	if err != nil {
		t.Fatalf("computeAuditStats: %v", err)
	}
	if got.unroutableTotal != 3 {
		t.Errorf("unroutableTotal = %d, want 3", got.unroutableTotal)
	}
	if got.unroutable[audit.UnroutableUnknownMethod] != 2 || got.unroutable[audit.UnroutableRemovedInRevision] != 1 {
		t.Errorf("per-reason tally = %v, want 2 unknown_method and 1 removed_in_revision", got.unroutable)
	}
	// Still counted as blocked: they WERE refused, and the summary's arithmetic must reconcile.
	if got.blocked != 4 {
		t.Errorf("blocked = %d, want 4 — the note explains the refusals, it does not remove them", got.blocked)
	}

	var out strings.Builder
	printAuditStats(&out, got)
	for _, want := range []string{"eunox's own routing", audit.UnroutableUnknownMethod, audit.UnroutableRemovedInRevision} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("printAuditStats is missing %q:\n%s", want, out.String())
		}
	}

	// A tape with no routing refusals must raise nothing: a note an operator learns to ignore is
	// worse than none.
	clean, err := computeAuditStats(strings.NewReader(`{"decision":"deny","target_type":"tool","target":"read_file","denial_code":"AUTHORIZATION_FAILED"}`))
	if err != nil {
		t.Fatalf("computeAuditStats: %v", err)
	}
	var cleanOut strings.Builder
	printAuditStats(&cleanOut, clean)
	if strings.Contains(cleanOut.String(), "eunox's own routing") {
		t.Errorf("a clean tape must raise no routing note:\n%s", cleanOut.String())
	}
}

// TestComputeAuditStats_HandlerFaultIsCountedAndCalledOut pins the operator-facing half of the
// repaired-fault report. The repair leaves the record looking like any other allow — the call
// was decided exactly as a conforming handler's would have been — so if `eunox stats` does not
// name it, an observe run tolerates a broken plugin indefinitely and the budget the run existed
// to PREDICT is not being predicted. The probe is derived from the producer's own key for
// declassifyProbe's reason: a respelling would make every fault silently invisible.
func TestComputeAuditStats_HandlerFaultIsCountedAndCalledOut(t *testing.T) {
	t.Parallel()
	if string(handlerFaultProbe) != audit.HandlerFaultKey {
		t.Fatalf("the stats probe %q is not the producer's key %q", handlerFaultProbe, audit.HandlerFaultKey)
	}
	if !audit.IsReservedDetailKey(audit.HandlerFaultKey) {
		t.Errorf("key %q is not reserved, so `eunox suggest` would mine it as a tool argument", audit.HandlerFaultKey)
	}

	// Both records a fault can ride: the allow it was decided on, and the deny a route running
	// --audit forwards anyway (where the deny record is the one an operator reads).
	log := strings.Join([]string{
		`{"decision":"allow","target":"read_file","details":{"` + audit.HandlerFaultKey + `":[{"type":"maxCalls","contract":"quota_bucket_under_skip_quota"}]}}`,
		`{"decision":"deny","audit_only":true,"target":"read_file","denial_code":"CONDITION_FAILED","details":{"` + audit.HandlerFaultKey + `":[{"type":"maxCalls","contract":"quota_bucket_under_skip_quota"}]}}`,
		`{"decision":"allow","target":"read_file","details":{"path":"/tmp/x"}}`,
	}, "\n")
	got, err := computeAuditStats(strings.NewReader(log))
	if err != nil {
		t.Fatalf("computeAuditStats: %v", err)
	}
	if got.handlerFaults != 2 {
		t.Errorf("handlerFaults = %d, want 2 (the report rides whichever record the decision produced)", got.handlerFaults)
	}

	var out strings.Builder
	printAuditStats(&out, got)
	for _, want := range []string{"ATTENTION", "commit contract", audit.HandlerFaultKey} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("printAuditStats is missing %q:\n%s", want, out.String())
		}
	}

	// A clean log must raise nothing: an alert an operator learns to ignore is worse than none.
	clean, err := computeAuditStats(strings.NewReader(`{"decision":"allow","target":"read_file","details":{"path":"/tmp/x"}}`))
	if err != nil {
		t.Fatalf("computeAuditStats: %v", err)
	}
	var cleanOut strings.Builder
	printAuditStats(&cleanOut, clean)
	if strings.Contains(cleanOut.String(), "commit contract") {
		t.Errorf("a healthy run must raise no handler-fault line:\n%s", cleanOut.String())
	}
}

// TestManifestSchema_AuthoredFlowLabelCountBound pins the published maxItems on both
// flow-label lists against the loader's own constant, for TestManifestSchema_SchemaVersionEnum's
// reason: a literal here would let the two disagree with both sides frozen and the test
// green, handing an author a schema-valid manifest the proxy refuses at startup (or the
// reverse — an editor flagging a policy eunox loads happily), with nothing to say which
// is authoritative.
func TestManifestSchema_AuthoredFlowLabelCountBound(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)

	for _, tc := range []struct {
		node string
		list string
	}{
		{"condition", "allow"},
		{"directive", "labels"},
	} {
		branches := schemaOneOfByConst(t, schemaObjectAt(t, doc, "$defs", tc.node))
		branch, ok := branches[map[string]string{"allow": capability.ConditionTypeFlowLabel, "labels": capability.DirectiveTypeLabelOutput}[tc.list]]
		if !ok {
			t.Fatalf("schema declares no %s branch for the flow token carrying %q", tc.node, tc.list)
		}
		list := schemaObjectAt(t, branch, "properties", tc.list)
		got, ok := list["maxItems"].(float64)
		if !ok {
			t.Fatalf("%s.%s declares no maxItems; the loader bounds it at %d", tc.node, tc.list, capability.MaxAuthoredFlowLabels)
		}
		if int(got) != capability.MaxAuthoredFlowLabels {
			t.Errorf("%s.%s maxItems = %d, want capability.MaxAuthoredFlowLabels (%d)",
				tc.node, tc.list, int(got), capability.MaxAuthoredFlowLabels)
		}
	}
}
